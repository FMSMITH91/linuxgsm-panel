"""Part 183 of the unit suite: the scheduled world reset for Minecraft Java and Factorio.

Held here:
* The world's name read from server.properties is used only when it is a plain folder name: empty,
  `.`/`..`, a slash or backslash, a control character (NUL, newline), a leading `-`, blanks at
  either end and over 64 characters are refused, never guessed past. A missing key is `world`.
* Factorio's save is the one LinuxGSM's start parameters load (`--start-server-load-latest`: the
  newest in saves/; an older config's `--start-server ${serverfiles}/save1.zip`); anything else,
  or a non-default executable, is refused.
* The reset's one host command, run here by bash against a scratch tree: deletes exactly the world
  (and creates Factorio's new save with the binary's `--create`), keeps everything else, and
  refuses, deleting nothing, when serverfiles is missing, the server is still running by
  LinuxGSM's own tmux test, a world path or Factorio's saves folder is a symlink, or a path does not
  resolve to itself. A removal that fails is a failure; output that did not come back is "unread",
  never done.
* The card's route: `reset` is the only kind for these games, map/full stays Rust's, Paper is not
  offered; the page renders the game's own description and no map/full choice.
* The sweep, end to end with every host call stubbed: backup, players, stop, the delete (and
  create), start, in that order, under the wipe registration; and each way it stops short.

HOW IT RUNS. Routes and sweeps on part12's app with its transport tripwire armed and every host call
stubbed; the host command runs under local bash in a temp folder with tmux (and, once, realpath)
replaced by stand-ins. Times are fixed, never the wall clock. Nothing reaches a host or data/.
"""
import os as _os183
import shutil as _shutil183
import stat as _stat183
import subprocess as _sp183  # nosec B404 - bash over the script this part builds, in a temp folder
import tempfile as _tmp183

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core import panel_state as _ps183
from panel.routes import _shared as _sh183, server_detail as _sd183, server_files as _sf183
from panel.routes import wipe_schedule as _wr183
from panel.services import lgsm_players as _lgp183, monitoring as _mon183
from panel.services import wipe_schedule as _ws183, world_reset as _wwr183

_trips183 = len(_P9_TRIPPED)
_NOW183 = 1_800_000_000.0        # a fixed sweep time: nothing here reads the clock to decide


# ── 1. the world's name ─────────────────────────────────────────────────────────────────────────
_bad_names183 = {"empty": "", "dot": ".", "dotdot": "..", "slash": "a/b", "backslash": "w\\:x",
                 "NUL": "a\x00b", "newline": "a\nb", "leading dash": "-rf", "over 64": "w" * 65,
                 "trailing blank": "world ", "bidi override": "a\u202eb", "line separator": "a\u2028b",
                 "no-break space": "a\u00a0b"}
for _why183, _name183 in _bad_names183.items():
    check("world reset name: a level-name with %s is refused" % _why183,
          _wwr183.world_name_problem(_name183) is not None, repr(_name183))
check("world reset name: plain names are used as they are (64 characters, a blank inside, unicode)",
      all(_wwr183.world_name_problem(n) is None for n in ("w" * 64, "my world", "monde_été", "world")), "")
eq("world reset name: server.properties without level-name is Minecraft's default, `world`",
   _wwr183.level_name("#Minecraft server properties\nmotd=A server\nlevel-seed=42\n"), ("world", None))
eq("world reset name: the last level-name line wins, comments are skipped, `key : value` is read",
   [_wwr183.level_name("level-name=old\n#level-name=commented\nlevel-name=new\n")[0],
    _wwr183.level_name("! c\nlevel-name : spaced\n")[0]], ["new", "spaced"])
check("world reset name: an empty level-name, or one the server escaped (`\\:`), is refused, not defaulted",
      _wwr183.level_name("level-name=\n")[0] is None and _wwr183.level_name("level-name=a\\:b\n")[0] is None, "")
eq("world reset name: read as java.util.Properties: a blank ends the key, the whole rest is the value",
   [_wwr183.level_name("level-name old run\n")[0], _wwr183.level_name("level-name=old run\n")[0],
    _wwr183.level_name("level-name\t:\tw2\n")[0]], ["old run", "old run", "w2"])
eq("world reset name: lines end only at \\n, \\r or \\r\\n (a form feed or U+2028 does not end one)",
   [_wwr183.level_name("level-name=a\rmotd=x\r\nlevel-seed=1")[0], _wwr183.level_name("motd=x\u2028level-name=b\n")[0]],
   ["a", "world"])
eq("world reset name: a line ending in a backslash goes on (a level-name there is part of the line before); "
   "a comment line never goes on",
   [_wwr183.level_name("motd=hi \\\n  level-name=x\nlevel-name=y\n")[0],
    _wwr183.level_name("motd=hi \\\n  level-name=x\n")[0], _wwr183.level_name("# c \\\nlevel-name=z\n")[0]],
   ["y", "world", "z"])
check("world reset name: a key written with escapes that Java reads as level-name is refused, not skipped",
      _wwr183.level_name("level\\-name=elsewhere\n")[0] is None
      and _wwr183.level_name("level\\u002dname=elsewhere\n")[0] is None, "")

# ── 1b. Minecraft: what moves the world away from level-name ────────────────────────────────────
_MCV183 = {"startparameters": "nogui", "extraparams": "", "executabledir": "${serverfiles}"}
check("world reset mc: LinuxGSM's default start (nogui, in serverfiles) is read from server.properties",
      _wwr183.mc_start_problem(_MCV183) is None and _wwr183.mc_start_problem({"startparameters": "nogui"}) is None, "")
check("world reset mc: --world / --universe in the start parameters or extraparams, written in full, "
      "abbreviated, with = or one dash, are refused",
      all(_wwr183.mc_start_problem(dict(_MCV183, **{k: v})) is not None for k, v in (
          ("startparameters", "nogui --world survival"), ("startparameters", "nogui --universe worlds"),
          ("startparameters", "nogui --wor=x"), ("startparameters", "-World x nogui"),
          ("extraparams", "--universe=/srv/w"), ("extraparams", "-u w"))), "")
check("world reset mc: a server that does not run in serverfiles (executabledir changed) is refused",
      _wwr183.mc_start_problem(dict(_MCV183, executabledir="/srv/minecraft")) is not None, "")


# ── 2. Factorio: which save the server starts ───────────────────────────────────────────────────
_LATEST183 = ("--bind ${ip} --start-server-load-latest --server-settings ${servercfgfullpath} --port ${port} "
              "--rcon-port ${rconport} --rcon-password ${rconpassword}")
_OLD183 = _LATEST183.replace("--start-server-load-latest", "--start-server ${serverfiles}/save1.zip")
_EXE183 = {"executabledir": "${serverfiles}/bin/x64", "executable": "./factorio"}


def _layout183(start, extra="", **exe):
    return _wwr183.fctr_layout(dict(_EXE183, startparameters=start, extraparams=extra, **exe))[0]


eq("world reset fctr: LinuxGSM's current start (--start-server-load-latest) resets saves/save1.zip and the "
   "autosaves, and creates saves/save1",
   _layout183(_LATEST183), {"dir": "saves", "remove": ["save1.zip"], "globs": ["_autosave*.zip"], "create": "save1"})
eq("world reset fctr: an older instance config (--start-server ${serverfiles}/save1.zip) resets that file",
   _layout183(_OLD183), {"dir": "", "remove": ["save1.zip"], "globs": [], "create": "save1"})
check("world reset fctr: a save the panel did not make, a second start option in extraparams, a scenario, "
      "or no start option at all is refused",
      _layout183(_OLD183.replace("${serverfiles}/save1.zip", "/srv/mine.zip")) is None
      and _layout183(_LATEST183, "--start-server ${serverfiles}/save1.zip") is None
      and _layout183("--start-server-load-scenario base/freeplay") is None
      and _layout183("--port 34197") is None, "")
check("world reset fctr: a non-default executable is refused (the new save could not be made LinuxGSM's way)",
      _layout183(_LATEST183, executabledir="/opt/factorio/bin/x64") is None
      and _layout183(_LATEST183, executable="./factorio-other") is None, "")


# ── 3. the host command, run by bash against a scratch tree ─────────────────────────────────────
_MC_PLAN183 = {"dir": "", "remove": ["world", "world_nether", "world_the_end"], "globs": [], "create": None}
_FCTR_PLAN183 = _layout183(_LATEST183)
_FCTR_OLD_PLAN183 = _layout183(_OLD183)


def _write183(path, text="x"):
    _os183.makedirs(_os183.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _exe183(path, body):
    _write183(path, "#!/bin/sh\n" + body)
    _os183.chmod(path, 0o755)


def _tree183(tmp, files, links, uid):
    """The scratch home: `files`, `links` (@OUT = a folder outside it, holding keep.txt), the script's uid."""
    home, outside = _os183.path.join(tmp, "home"), _os183.path.join(tmp, "outside")
    for f in files:
        _write183(_os183.path.join(home, f))
    _write183(_os183.path.join(outside, "keep.txt"))
    for link, target in links:
        _os183.symlink(target.replace("@OUT", outside), _os183.path.join(home, link))
    if uid is not None:
        _write183(_os183.path.join(home, "lgsm", "data", "p183s.uid"), uid)
    return home


def _stubs183(tmp, home, up, realpath):
    """tmux (a session when `up`), realpath (when asked, one answering another path) and the factorio binary."""
    stubs = _os183.path.join(tmp, "stubs")
    _exe183(_os183.path.join(stubs, "tmux"), 'echo "$*" >> "%s/tmux.args"\n%s' % (tmp, "echo p183s\n" if up else ""))
    if realpath:
        # "elsewhere": every path resolves somewhere else; "same": every path resolves to itself (a host
        # where realpath does not follow the link), so only the script's own symlink test stands.
        _exe183(_os183.path.join(stubs, "realpath"), "echo /elsewhere/x\n" if realpath == "elsewhere" else 'echo "$3"\n')
    if _os183.path.isdir(_os183.path.join(home, "serverfiles")):
        _exe183(_os183.path.join(home, "serverfiles", "bin", "x64", "factorio"),
                'echo "$*" >> "%s/factorio.args"\nprintf new > "$2.zip"\n' % tmp)
    return dict(_os183.environ, PATH=stubs + ":" + _os183.environ.get("PATH", "/usr/bin:/bin"))


def _said183(tmp, name):
    path = _os183.path.join(tmp, name)
    if not _os183.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _left183(home):
    left = sorted(_os183.path.relpath(_os183.path.join(r, f), home) for r, _d, fs in _os183.walk(home) for f in fs)
    return [f for f in left if not f.startswith(("serverfiles/bin/", "lgsm/"))]


def _holder183(home, hold):
    """A stand-in process of this account using serverfiles: ("cwd", secs) sits in it, ("file", secs) holds a file open."""
    if not hold:
        return None
    how, secs = hold
    sf = _os183.path.join(home, "serverfiles")
    if how == "cwd":
        return _sp183.Popen(["sleep", str(secs)], cwd=sf)  # nosec B603 B607
    return _sp183.Popen(["bash", "-c", 'exec 3<"$1"; exec sleep "$2"', "x", _os183.path.join(sf, "server.properties"),  # nosec B603 B607
                         str(secs)], cwd="/")


def _host183(plan, files=(), links=(), up=False, uid=None, realpath=None, locked=None, **o):
    """Run the reset's script in a temp home.

    `o`: busy_polls (the script's wait), hold (_holder183), lock ("backup", "backup-old", "update", "update-dead"),
    status (run status_script instead). Returns (files left, stdout, rc, tmux args, factorio args, whether the
    outside folder's file is still there).
    """
    tmp = _tmp183.mkdtemp(prefix="p183-")
    home = _os183.path.join(tmp, "home")
    holder = None
    try:
        _tree183(tmp, files, links, uid)
        _lock183(home, o.get("lock"))
        env = _stubs183(tmp, home, up, realpath)
        if locked:
            _os183.chmod(_os183.path.join(home, locked), _stat183.S_IRUSR | _stat183.S_IXUSR)
        holder = _holder183(home, o.get("hold"))
        sh = (_wwr183.status_script("p183u", "p183s") if o.get("status")
              else _wwr183.script("p183u", "p183s", plan, busy_polls=o.get("busy_polls", 3)))
        res = _sp183.run(["bash", "-c", sh.replace("/home/p183u", home)], capture_output=True, text=True,  # nosec B603 B607
                         timeout=60, env=env, check=False)
        return (_left183(home), res.stdout, res.returncode, _said183(tmp, "tmux.args"), _said183(tmp, "factorio.args"),
                _os183.path.exists(_os183.path.join(tmp, "outside", "keep.txt")))
    finally:
        if holder is not None:
            holder.kill()
            holder.wait()
        if locked:
            _os183.chmod(_os183.path.join(home, locked), _stat183.S_IRWXU)
        _shutil183.rmtree(tmp, ignore_errors=True)


def _lock183(home, lock):
    """LinuxGSM's lock files as a backup or update leaves them (an old backup lock is stale; a dead PID too)."""
    if not lock:
        return
    path = _os183.path.join(home, "lgsm", "lock", "updating.lock" if lock.startswith("update") else "backup.lock")
    dead = _sp183.Popen(["true"])  # nosec B603 B607
    dead.wait()
    _write183(path, str(_os183.getpid() if lock == "update" else dead.pid) if lock.startswith("update") else "1800000000")
    if lock == "backup-old":
        _os183.utime(path, (1_700_000_000, 1_700_000_000))


_MC_FILES183 = ("serverfiles/world/level.dat", "serverfiles/world/region/r.0.0.mca", "serverfiles/world_nether/x",
                "serverfiles/world_the_end/x", "serverfiles/server.properties", "serverfiles/ops.json",
                "serverfiles/whitelist.json", "serverfiles/banned-players.json", "serverfiles/banned-ips.json",
                "serverfiles/usercache.json", "serverfiles/worldedit/x", "serverfiles/minecraft_server.jar")
_KEPT183 = ["serverfiles/banned-ips.json", "serverfiles/banned-players.json", "serverfiles/minecraft_server.jar",
            "serverfiles/ops.json", "serverfiles/server.properties", "serverfiles/usercache.json",
            "serverfiles/whitelist.json", "serverfiles/worldedit/x"]
_mc183 = _host183(_MC_PLAN183, _MC_FILES183, uid="u7")
eq("world reset host: Minecraft's world, nether and end folders go; ops, whitelist, bans, server.properties "
   "and every other file stay", _mc183[0], _KEPT183)
eq("world reset host: ...the run reports three removed and done", _wwr183.outcome(_mc183[1], _mc183[2], _MC_PLAN183),
   ("done", "world deleted (3 removed)"))
check("world reset host: the running test is LinuxGSM's own (tmux on the script's uid socket)",
      _mc183[3].split()[:2] == ["-L", "p183s-u7"] and "list-sessions" in _mc183[3], repr(_mc183[3]))

_up183 = _host183(_MC_PLAN183, _MC_FILES183, up=True)
check("world reset host: a server still running by LinuxGSM's test is refused and nothing is deleted",
      _wwr183.outcome(_up183[1], _up183[2], _MC_PLAN183)[0] == "refused" and "serverfiles/world/level.dat" in _up183[0]
      and "serverfiles/world_nether/x" in _up183[0], repr(_up183[:3]))

_link183 = _host183(_MC_PLAN183, [f for f in _MC_FILES183 if not f.startswith("serverfiles/world/")],
                    links=[("serverfiles/world", "@OUT")])
check("world reset host: a world folder that is a symlink is refused before anything is deleted (its target, "
      "and the nether and end beside it, are untouched)",
      _wwr183.outcome(_link183[1], _link183[2], _MC_PLAN183)[0] == "refused" and _link183[5]
      and "serverfiles/world_nether/x" in _link183[0], repr(_link183[:3]))

_samelink183 = _host183(_MC_PLAN183, [f for f in _MC_FILES183 if not f.startswith("serverfiles/world/")],
                        links=[("serverfiles/world", "@OUT")], realpath="same")
check("world reset host: ...refused by the symlink test itself, even where realpath would not catch it",
      "__WWR_LINK__" in _samelink183[1] and _samelink183[5] and "serverfiles/world_nether/x" in _samelink183[0],
      repr(_samelink183[:3]))

_elsewhere183 = _host183(_MC_PLAN183, _MC_FILES183, realpath="elsewhere")
check("world reset host: a world path that does not resolve to serverfiles/<name> is refused, nothing deleted",
      "__WWR_OUTSIDE__" in _elsewhere183[1] and "serverfiles/world/level.dat" in _elsewhere183[0]
      and "serverfiles/world_the_end/x" in _elsewhere183[0], repr(_elsewhere183[:3]))

_nosf183 = _host183(_MC_PLAN183, ("other/x",))
eq("world reset host: with no serverfiles folder nothing runs (refused)",
   _wwr183.outcome(_nosf183[1], _nosf183[2], _MC_PLAN183)[0], "refused")

_rmfail183 = _host183(_MC_PLAN183, _MC_FILES183 + ("serverfiles/world/locked/data",), locked="serverfiles/world/locked")
eq("world reset host: a world file that cannot be removed is a failure, not a reset",
   _wwr183.outcome(_rmfail183[1], _rmfail183[2], _MC_PLAN183)[0], "failed")

_FCTR_FILES183 = ("serverfiles/saves/save1.zip", "serverfiles/saves/_autosave1.zip", "serverfiles/saves/_autosave2.zip",
                  "serverfiles/saves/kept-by-hand.zip", "serverfiles/player-data.json", "serverfiles/mods/m.zip",
                  "serverfiles/data/server-settings.json")
_fctr183 = _host183(_FCTR_PLAN183, _FCTR_FILES183)
check("world reset host: Factorio's save1 and autosaves go, a new save1 is made by the binary's --create "
      "(LinuxGSM's install command); other saves, mods, player data and settings stay",
      _fctr183[0] == ["serverfiles/data/server-settings.json", "serverfiles/mods/m.zip", "serverfiles/player-data.json",
                      "serverfiles/saves/kept-by-hand.zip", "serverfiles/saves/save1.zip"]
      and _fctr183[4].split()[0] == "--create" and _fctr183[4].split()[1].endswith("/serverfiles/saves/save1")
      and _wwr183.outcome(_fctr183[1], _fctr183[2], _FCTR_PLAN183) == ("done", "world deleted (3 removed)"),
      repr(_fctr183))
_fold183 = _host183(_FCTR_OLD_PLAN183, ("serverfiles/save1.zip", "serverfiles/saves/_autosave1.zip"))
check("world reset host: the older layout's serverfiles/save1.zip is replaced the same way",
      _fold183[4].split()[1].endswith("/serverfiles/save1")
      and _fold183[0] == ["serverfiles/save1.zip", "serverfiles/saves/_autosave1.zip"]
      and _wwr183.outcome(_fold183[1], _fold183[2], _FCTR_OLD_PLAN183)[0] == "done", repr(_fold183))
_fsaves183 = _host183(_FCTR_PLAN183, ("serverfiles/player-data.json",), links=[("serverfiles/saves", "@OUT")])
check("world reset host: a Factorio saves folder that is a symlink is refused: nothing deleted, nothing created",
      _wwr183.outcome(_fsaves183[1], _fsaves183[2], _FCTR_PLAN183)[0] == "refused" and _fsaves183[4] == ""
      and _fsaves183[5], repr(_fsaves183))

_none183 = _host183(_MC_PLAN183, ("serverfiles/server.properties", "serverfiles/ops.json"))
check("world reset host: a serverfiles with none of the world's folders is 'nothing found', not a reset",
      _wwr183.outcome(_none183[1], _none183[2], _MC_PLAN183)[0] == "refused" and "__WWR_NOTHING__" in _none183[1]
      and "__WWR_DELETED__" not in _none183[1], repr(_none183[:3]))
_fnone183 = _host183(_FCTR_PLAN183, ("serverfiles/saves/kept-by-hand.zip", "serverfiles/player-data.json"))
check("world reset host: ...and for Factorio nothing is created then",
      "__WWR_NOTHING__" in _fnone183[1] and _fnone183[4] == "", repr(_fnone183[:5]))

_cwd183 = _host183(_MC_PLAN183, _MC_FILES183, hold=("cwd", 30), busy_polls=1)
_fd183 = _host183(_MC_PLAN183, _MC_FILES183, hold=("file", 30), busy_polls=1)
check("world reset host: a process of the account still in serverfiles (its cwd, or a file it holds open) "
      "after the wait is refused and nothing is deleted",
      "__WWR_BUSY__" in _cwd183[1] and "__WWR_BUSY__" in _fd183[1] and "serverfiles/world/level.dat" in _cwd183[0]
      and "serverfiles/world/level.dat" in _fd183[0]
      and _wwr183.outcome(_cwd183[1], _cwd183[2], _MC_PLAN183)[0] == "refused", repr((_cwd183[:3], _fd183[:3])))
_late183 = _host183(_MC_PLAN183, _MC_FILES183, hold=("cwd", 1), busy_polls=4)
check("world reset host: ...one that lets go within the wait does not stop the reset",
      _wwr183.outcome(_late183[1], _late183[2], _MC_PLAN183)[0] == "done", repr(_late183[:3]))

_locks183 = {k: _host183(_MC_PLAN183, _MC_FILES183, lock=k) for k in ("backup", "update", "backup-old", "update-dead")}
check("world reset host: a running LinuxGSM backup (backup.lock under an hour old) or update (updating.lock "
      "holding a live PID) is refused, nothing deleted",
      all("__WWR_LOCKED__" in _locks183[k][1] and "serverfiles/world/level.dat" in _locks183[k][0]
          for k in ("backup", "update")), repr({k: v[:3] for k, v in _locks183.items()}))
check("world reset host: ...a stale lock (a backup.lock older than an hour, a dead PID) does not stop it",
      all(_wwr183.outcome(_locks183[k][1], _locks183[k][2], _MC_PLAN183)[0] == "done" for k in ("backup-old", "update-dead")),
      repr({k: v[:3] for k, v in _locks183.items()}))

_st183 = {k: _host183(None, ("serverfiles/x",), status=True, **a) for k, a in (
    ("up", {"up": True}), ("down", {}), ("locked", {"lock": "backup"}))}
eq("world reset host: the state command reads up, down, or locked, by LinuxGSM's tmux test and locks",
   {k: _wwr183.status_of(v[1]) for k, v in _st183.items()}, {"up": "up", "down": "down", "locked": "locked"})
check("world reset host: a state command whose answer did not come back is unknown, never 'down'",
      _wwr183.status_of("") is None and _wwr183.status_of("bash: timed out") is None, "")

check("world reset host: output that did not come back (a timeout, a transport's '' with no raise), or stopped "
      "before its last line, is unread, never done",
      _wwr183.outcome("", -1, _MC_PLAN183)[0] == "unread"
      and _wwr183.outcome("__WWR_GONE__\n", 0, _MC_PLAN183)[0] == "unread", "")
check("world reset host: a Factorio run whose --create failed is a failure",
      _wwr183.outcome("__WWR_GONE__\n__WWR_DELETED__\nError: no space\n__WWR_CREATEFAIL__\n", 7,
                      _FCTR_PLAN183)[0] == "failed", "")
_odd183 = _wwr183.script("p183u", "p183s", dict(_MC_PLAN183, remove=["my $(id) world"]))
check("world reset host: names reach the shell quoted and are removed with `rm -rf --`",
      "set -- 'my $(id) world'" in _odd183 and 'rm -rf -- "$p"' in _odd183, _odd183)


# ── 4. the card's route and page ────────────────────────────────────────────────────────────────
_mc_sid183 = _p9_new_server(P9_HOST, "p183mc", "mc", 25565, name="p183-mc")
_fctr_sid183 = _p9_new_server(P9_HOST, "p183fctr", "fctr", 34197, name="p183-fctr")
_rust_sid183 = _p9_new_server(P9_HOST, "p183rust", "rust", 28015, name="p183-rust")
_pmc_sid183 = _p9_new_server(P9_HOST, "p183pmc", "pmc", 25566, name="p183-pmc")
_CRON183 = "0 3 * * *"
_BODY183 = {"enabled": True, "kind": "reset", "preset": "custom", "cron": _CRON183, "tz": "UTC"}
_r183 = {}
try:
    _p9_arm(who="part183")
    _A183 = _p9_client(P9_ADMIN)
    _u183 = "/api/server/%d/wipe-schedule"
    _r183["get"] = _A183.get(_u183 % _mc_sid183).get_json()
    _r183["save"] = _A183.post(_u183 % _mc_sid183, json=_BODY183)
    _r183["saved"] = dict(_ws183.get(_mc_sid183) or {})
    _r183["map_fctr"] = _A183.post(_u183 % _fctr_sid183, json=dict(_BODY183, kind="map"))
    _r183["reset_rust"] = _A183.post(_u183 % _rust_sid183, json=_BODY183)
    _r183["pmc"] = _A183.post(_u183 % _pmc_sid183, json=_BODY183)
    _p9_patch(_sd183, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd183, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_sf183, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("run_command", lambda *a, **k: ("", "", 1))
    _r183["pages"] = {g: _A183.get("/server/%d/files" % s).get_data(as_text=True)
                      for g, s in (("mc", _mc_sid183), ("fctr", _fctr_sid183), ("rust", _rust_sid183),
                                   ("pmc", _pmc_sid183))}
finally:
    _p9_restore_all()
    _ws183.put(_mc_sid183, None)
check("world reset route: a Minecraft server's card is a reset card, and saving `reset` stores it, described "
      "as a world reset",
      _r183["get"].get("reset") is True and _r183["get"].get("supported") is True
      and _r183["save"].status_code == 200 and _r183["saved"].get("kind") == "reset"
      and (_r183["save"].get_json() or {}).get("describe", "").startswith("World reset, cron '0 3 * * *'"),
      repr((_r183["get"], _r183["saved"])))
check("world reset route: map/full is refused for Factorio, `reset` for Rust, and Paper is not offered at all",
      _r183["map_fctr"].status_code == 400 and _r183["map_fctr"].get_json()["message"] == "kind must be reset."
      and _r183["reset_rust"].status_code == 400
      and _r183["reset_rust"].get_json()["message"] == "kind must be map or full."
      and _r183["pmc"].status_code == 400, repr([_r183[k].get_json() for k in ("map_fctr", "reset_rust", "pmc")]))
_pg183 = _r183["pages"]
check("world reset page: Minecraft and Factorio get their own description and a fixed `reset` kind, no map/full "
      "choice; Rust keeps its select; Paper has no card",
      'id="wipe-kind" value="reset"' in _pg183["mc"] and "ops, whitelist, bans and server.properties are kept"
      in _pg183["mc"] and '<option value="map">' not in _pg183["mc"]
      and 'id="wipe-kind" value="reset"' in _pg183["fctr"] and "deletes the map save and its autosaves" in _pg183["fctr"]
      and '<option value="map">Map wipe</option>' in _pg183["rust"] and 'id="wipe-card"' not in _pg183["pmc"]
      and 'id="wipe-card"' in _pg183["mc"], "")


# ── 5. the sweep, end to end ────────────────────────────────────────────────────────────────────
_PROPS183 = "motd=hi\nlevel-name=survival\nlevel-seed=\n"
_GONE183 = "__WWR_GONE__\n__WWR_GONE__\n__WWR_DELETED__\n"
_FCTR_GONE183 = "__WWR_GONE__\n__WWR_DELETED__\nInfo Saving map\n__WWR_CREATED__\n"
_STOPPED183 = "[  OK  ] Stopping mcserver: Minecraft Server\n"


class _Dropped183(Exception):
    """paramiko's drop as ssh_manager raises it: a ConnectionError whose command was sent, or not."""


def _sweep_case183(sid, **o):
    """One (or two) sweeps of a pending reset of server `sid`, every host call stubbed. Returns what happened."""
    got = {"sid": sid, "cmds": [], "jobs": [], "alerts": [], "backups": [], "players_asked": 0}
    with _p9.app_context():
        from panel.db.models import GameServer, db
        gs = db.session.get(GameServer, sid)
        entry = dict(_ws183.identity(gs), kind="reset", preset="custom", at="", cron=_CRON183, tz="UTC",
                     wait_empty=o.get("wait_empty", True), anchor=_NOW183 - 7200, pending_since=_NOW183 - 3600,
                     backed_up=o.get("backed_up", int(_NOW183 - 3500)), tried=0, wait="")
    _ws183.put(sid, entry)

    def _run(remote, user, action, **k):
        got["cmds"].append(action)
        got["jobs"].append(sorted(_ps183.r36j_route_jobs(sid)))
        return o.get(action, lambda: (_STOPPED183 if action == "stop" else "[  OK  ] Starting", "", 0))()

    def _shell(remote, user, sh, **k):
        status = "echo __WWR_UP__" in sh
        got["cmds"].append("status" if status else sh)
        got["jobs"].append(sorted(_ps183.r36j_route_jobs(sid)))
        if status:
            return o.get("status", lambda: ("__WWR_UP__\n", "", 0))()
        return o.get("delete", lambda: (_GONE183, "", 0))()

    def _players(*a, **k):
        got["players_asked"] += 1
        return o.get("players", 0)

    def _bk(*a, **k):
        got["backups"].append(a[2])
        return o.get("backup", (True, "Backed up", False))
    try:
        _p9_arm(who="part183")
        _p9_patch(_sh183, "_marked_backup", _bk)
        _p9_patch(_sh183, "_alert_backup", lambda *a, **k: got["alerts"].append(a[2]))
        _p9_patch(_sh183, "_reboot_holds", lambda gs: False)
        _p9_patch(_lgp183, "allowance_seconds", lambda *a, **k: 0)
        _p9_patch_sm("run_as_game_user", _run)
        _p9_patch_sm("shell_as_game_user", _shell)
        _p9_patch_sm("player_count", _players)
        _p9_patch_sm("read_file", lambda *a, **k: o.get("props", (_PROPS183, None)))
        _values = (dict(_EXE183, startparameters=_LATEST183, extraparams="") if sid == _fctr_sid183
                   else dict(_MCV183))
        _p9_patch_sm("lgsm_get_values", lambda *a, **k: o.get("values", _values))
        try:
            _wr183.sweep(_p9, now=_NOW183)
        except Exception as exc:  # noqa: BLE001 - recorded, and named by the check that reads it
            got["raised"] = repr(exc)
        got["entry"] = dict(_ws183.get(sid) or {})
        got["window"] = (_mon183._offline_expected(sid), _mon183._stop_expected(sid))
        got["audit"] = _p9_audit("wipe_server")
        if o.get("again"):
            n = len(got["cmds"])
            _wr183.sweep(_p9, now=_NOW183 + _wr183._RETRY_SECONDS + 5)
            got["again"] = got["cmds"][n:]
        return got
    finally:
        _p9_restore_all()
        _ws183.put(sid, None)
        _mon183._end_offline_window(sid)


def _last183(got):
    return (got.get("entry") or {}).get("last") or {}


def _is_delete183(c):
    return isinstance(c, str) and "rm -rf --" in c


def _raise183(started):
    def _r():
        exc = _Dropped183("Command failed: Socket is closed")
        exc.command_started = started
        raise exc
    return _r


_ok183 = _sweep_case183(_mc_sid183, backed_up=0)
_okc183 = _ok183["cmds"]
check("world reset sweep (mc): backup, the state, players, then stop, the delete of survival/_nether/_the_end, "
      "start, in that order, each under the wipe registration",
      _ok183["backups"] == ["p183mc"] and _ok183["players_asked"] == 1 and len(_okc183) == 4
      and _okc183[:2] == ["status", "stop"] and _is_delete183(_okc183[2])
      and "set -- survival survival_nether survival_the_end" in _okc183[2] and _okc183[3] == "start"
      and all("wipe" in j for j in _ok183["jobs"]), repr(_ok183))
check("world reset sweep (mc): the reset is recorded as done (audit, card's last result), no alert, and the "
      "monitor's window is a restart's (the server must come back), not a stop's",
      _ok183["audit"].success is True and "world reset: world deleted (2 removed)" in _ok183["audit"].detail
      and _last183(_ok183).get("ok") is True and not _ok183["entry"].get("pending_since")
      and _ok183["alerts"] == [] and _ok183["window"] == (True, False), repr(_ok183))

_fok183 = _sweep_case183(_fctr_sid183, delete=lambda: (_FCTR_GONE183, "", 0))
check("world reset sweep (fctr): stop, the delete with its --create of saves/save1, start; done",
      len(_fok183["cmds"]) == 4 and _fok183["cmds"][:2] == ["status", "stop"] and _is_delete183(_fok183["cmds"][2])
      and '--create "$d/save1"' in _fok183["cmds"][2] and _fok183["cmds"][3] == "start"
      and _last183(_fok183).get("ok") is True, repr(_fok183))

_stopfail183 = _sweep_case183(_mc_sid183, stop=lambda: ("[ FAIL ] Stopping mcserver", "", 1))
check("world reset sweep: a stop that exits non-zero deletes nothing, starts the server again, and ends the "
      "reset alerted as not done",
      _stopfail183["cmds"] == ["status", "stop", "start"] and _last183(_stopfail183).get("ok") is False
      and _stopfail183["alerts"] == ["Scheduled wipe did not run"] and _stopfail183["audit"].success is False,
      repr(_stopfail183))

_running183 = _sweep_case183(_mc_sid183, delete=lambda: ("__WWR_RUNNING__\n", "", 4))
check("world reset sweep: a server the delete command finds still running is not reset; start is still run "
      "and the failure alerted",
      _running183["cmds"][-1] == "start" and len(_running183["cmds"]) == 4
      and "still running" in (_last183(_running183).get("detail") or "")
      and _running183["alerts"] == ["Scheduled wipe did not run"], repr(_running183))

_unread183 = _sweep_case183(_mc_sid183, delete=lambda: ("", "timed out", -1))
check("world reset sweep: a delete whose output did not come back is never recorded as done; the server is "
      "started and the operator told to check it",
      _last183(_unread183).get("ok") is False and "may have deleted the world" in (_last183(_unread183).get("detail") or "")
      and _unread183["cmds"][-1] == "start", repr(_unread183))

_drop183 = _sweep_case183(_mc_sid183, delete=_raise183(True), again=True)
check("world reset sweep: a connection that drops after the delete was sent ends the reset (start still tried, "
      "alerted as 'may have been deleted'), and the next sweep does NOT run it again",
      _drop183["cmds"][-1] == "start" and _last183(_drop183).get("ok") is False
      and "may have been deleted" in (_last183(_drop183).get("detail") or "") and _drop183["again"] == []
      and _drop183["alerts"] == ["Scheduled wipe did not run"], repr(_drop183))
_unsent183 = _sweep_case183(_mc_sid183, delete=_raise183(False))
check("world reset sweep: a delete never sent starts the server again and stays pending with its backup",
      _unsent183["cmds"][-1] == "start" and _unsent183["entry"].get("pending_since")
      and _unsent183["entry"].get("backed_up") and _unsent183["alerts"] == [], repr(_unsent183))

_players183 = _sweep_case183(_mc_sid183, players=3)
_forced183 = _sweep_case183(_mc_sid183, players=3, wait_empty=False)
check("world reset sweep: with 'wait until empty' on, players online keep it waiting (nothing stopped, backup "
      "kept); off, the players are not asked and it runs",
      _players183["cmds"] == ["status"] and _players183["entry"].get("pending_since") and _players183["entry"].get("backed_up")
      and "3 player(s) online" in (_players183["entry"].get("wait") or "")
      and _forced183["players_asked"] == 0 and _last183(_forced183).get("ok") is True, repr((_players183, _forced183)))

_refused183 = _sweep_case183(_mc_sid183, stop=lambda: (
    "[ INFO ] Stopping mcserver: 2 players are on the server: stop prevented\n", "", 0))
check("world reset sweep: LinuxGSM's own players-online refusal of the stop keeps it waiting, deletes nothing, "
      "and ends the monitor's window",
      _refused183["cmds"] == ["status", "stop"] and _refused183["entry"].get("pending_since")
      and "2 player(s) online" in (_refused183["entry"].get("wait") or "") and _refused183["window"][0] is False,
      repr(_refused183))

_unreadprops183 = _sweep_case183(_mc_sid183, props=(None, "Could not read that file — the host did not answer."))
_badname183 = _sweep_case183(_mc_sid183, props=("level-name=../home\n", None))
_badcfg183 = _sweep_case183(_fctr_sid183, values=None)
_emptyprops183 = _sweep_case183(_mc_sid183, props=("", None))
check("world reset sweep: server.properties (or Factorio's config) that could not be read keeps the reset "
      "waiting with the server untouched, never guessing a name",
      _unreadprops183["cmds"] == [] and _unreadprops183["entry"].get("pending_since")
      and "could not be read" in (_unreadprops183["entry"].get("wait") or "")
      and _badcfg183["cmds"] == [] and _badcfg183["entry"].get("pending_since"), repr((_unreadprops183, _badcfg183)))
check("world reset sweep: an empty server.properties (read, but nothing in it) is refused, never read as `world`",
      _emptyprops183["cmds"] == [] and _last183(_emptyprops183).get("ok") is False
      and "server.properties is empty" in (_last183(_emptyprops183).get("detail") or ""), repr(_emptyprops183))
check("world reset sweep: a level-name the panel refuses ends the reset, alerted, with the server untouched",
      _badname183["cmds"] == [] and _last183(_badname183).get("ok") is False
      and "level-name in server.properties is not used" in (_last183(_badname183).get("detail") or "")
      and _badname183["alerts"] == ["Scheduled wipe did not run"], repr(_badname183))

_down183 = _sweep_case183(_mc_sid183, status=lambda: ("__WWR_DOWN__\n", "", 0))
check("world reset sweep: a server that was stopped is reset and left stopped (no stop, no start, no quiet "
      "window, no player count), as LinuxGSM's own wipe does",
      len(_down183["cmds"]) == 2 and _down183["cmds"][0] == "status" and _is_delete183(_down183["cmds"][1])
      and _down183["players_asked"] == 0 and _last183(_down183).get("ok") is True
      and "left stopped" in (_last183(_down183).get("detail") or "") and _down183["window"] == (False, False),
      repr(_down183))
_downbusy183 = _sweep_case183(_mc_sid183, status=lambda: ("__WWR_DOWN__\n", "", 0),
                              delete=lambda: ("__WWR_BUSY__\n", "", 4))
check("world reset sweep: ...and a stopped server whose reset is refused is not started either",
      "start" not in _downbusy183["cmds"] and _last183(_downbusy183).get("ok") is False
      and "left stopped" in (_last183(_downbusy183).get("detail") or ""), repr(_downbusy183))

_stopdrop183 = _sweep_case183(_mc_sid183, stop=_raise183(True))
check("world reset sweep: a connection that drops while LinuxGSM stops the server is followed by a start "
      "attempt, and the reset ends (nothing deleted)",
      _stopdrop183["cmds"] == ["status", "stop", "start"] and _last183(_stopdrop183).get("ok") is False
      and "nothing was deleted" in (_last183(_stopdrop183).get("detail") or ""), repr(_stopdrop183))

_uncounted183 = _sweep_case183(_mc_sid183, players=None)
check("world reset sweep: with 'wait until empty' on, players that cannot be counted keep it waiting (and "
      "the wait says why)",
      _uncounted183["cmds"] == ["status"] and _uncounted183["entry"].get("pending_since")
      and "could not be counted" in (_uncounted183["entry"].get("wait") or ""), repr(_uncounted183))

_stunread183 = _sweep_case183(_mc_sid183, status=lambda: ("", "timed out", -1))
_stlocked183 = _sweep_case183(_mc_sid183, status=lambda: ("__WWR_LOCKED__\n", "", 4))
check("world reset sweep: a state that did not come back, or a LinuxGSM backup/update running, waits with "
      "nothing stopped",
      _stunread183["cmds"] == ["status"] and _stunread183["entry"].get("pending_since")
      and _stlocked183["cmds"] == ["status"] and "backup or update" in (_stlocked183["entry"].get("wait") or ""),
      repr((_stunread183, _stlocked183)))

_busy183 = _sweep_case183(_mc_sid183, delete=lambda: ("__WWR_BUSY__\n", "", 4))
_nothing183 = _sweep_case183(_mc_sid183, delete=lambda: ("__WWR_NOTHING__\n", "", 8))
check("world reset sweep: a delete refused because serverfiles was still in use, or that found no world, is "
      "not a reset: the server is started again and the failure alerted",
      _busy183["cmds"][-1] == "start" and _last183(_busy183).get("ok") is False
      and _nothing183["cmds"][-1] == "start" and _last183(_nothing183).get("ok") is False
      and "no world was found" in (_last183(_nothing183).get("detail") or "")
      and _nothing183["alerts"] == ["Scheduled wipe did not run"], repr((_busy183, _nothing183)))

_firm183 = {e: _sweep_case183(_mc_sid183, props=(None, e)) for e in (
    "Invalid path", "Binary file — download/replace via upload instead", "File is too large to edit in the browser")}
check("world reset sweep: a server.properties the reader refuses for good (invalid path, binary, too large) "
      "ends the reset, alerted, instead of retrying for hours",
      all(g["cmds"] == [] and _last183(g).get("ok") is False and not g["entry"].get("pending_since")
          and g["alerts"] == ["Scheduled wipe did not run"] for g in _firm183.values()), repr(_firm183))

_world183 = _sweep_case183(_mc_sid183, values=dict(_MCV183, startparameters="nogui --world survival"))
check("world reset sweep: a Minecraft server started with --world is not reset (server untouched, alerted)",
      _world183["cmds"] == [] and _last183(_world183).get("ok") is False
      and "--world or --universe" in (_last183(_world183).get("detail") or ""), repr(_world183))

_bkfail183 = _sweep_case183(_mc_sid183, backed_up=0, backup=(False, "disk full", False))
check("world reset sweep: a backup that failed resets nothing (nothing stopped or deleted)",
      _bkfail183["cmds"] == [] and _last183(_bkfail183).get("ok") is False, repr(_bkfail183))

for _sid183 in (_mc_sid183, _fctr_sid183, _rust_sid183, _pmc_sid183):
    _p9_delete_server(_sid183)
eq("world reset: nothing this part drove reached a real transport (part12's tripwire, armed)",
   _P9_TRIPPED[_trips183:], [])
