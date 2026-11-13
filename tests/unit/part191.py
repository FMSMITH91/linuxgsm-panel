"""Part 191 of the unit suite: the scheduled world reset for Paper (pmc) and Bedrock (mcb).

Held here:
* Paper's start parameters: every option of Paper's that moves the world or the files that name it
  (-W/--world-dir/--universe/--world-container, -w/--world/--level-name, -c/--config,
  -b/--bukkit-settings, -P/--plugins), written in full, abbreviated, with one dash, `=`, an attached
  value or after a no-value option in a cluster, is refused; LinuxGSM's default and Paper's other
  options are not; shell quoting or expansion is refused (Minecraft Java's too).
* bukkit.yml: world-container anywhere outside a whole-line comment, or a backslash escape, refuses;
  a missing bukkit.yml is Paper's default; a bukkit.yml that could not be read waits.
* Bedrock's server.properties: only a plain `level-name=<name>` line is read (CRLF too); any other
  form, two different lines, no line, and a name Bedrock forbids or the panel will not guess about
  are refused.
* The host command against scratch trees: Paper's world folder goes (current layout and the older
  _nether/_the_end), plugins, config and a plugin's own world stay; Bedrock's worlds/<name> with a
  blank in it goes, the other worlds and the server's own files stay; a worlds folder that is a
  symlink is refused, nothing deleted.
* The card and the sweep, through the app: both games get a reset card with their own text; the
  player box is ticked for Paper (gamedig counts it) and unticked for Bedrock, whose current servers
  answer no player query the panel has (it waits for a count only when ticked). A due reset runs
  state, stop, backup, delete, start, or stops short as each refusal says.

HOW IT RUNS. part12's app with its transport tripwire armed and every host call stubbed (part183's
sweep helper); host commands run under local bash in a temp folder (part183's helper). Times are
fixed, never the wall clock. Nothing reaches a host or data/.
"""
import os as _os191top
import shutil as _shutil191
import subprocess as _sp191  # nosec B404 - bash over lgsm_cfg_texts' own command, in a temp folder
import tempfile as _tempfile191

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_client, _p9_delete_server, _p9_new_server,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part183 import _host183, _is_delete183, _last183, _sweep_case183
from panel.ops.ssh_manager import _core as _core191, files as _sm191
from panel.routes import server_detail as _sd191, server_files as _sf191
from panel.services import wipe_schedule as _ws191, world_reset as _wwr191

_trips191 = len(_P9_TRIPPED)

# ── 1. Paper: what moves the world away from server.properties ──────────────────────────────────
_PMCV191 = {"startparameters": "nogui", "extraparams": "", "executabledir": "${serverfiles}",
            "executable": "./paper.jar", "preexecutable": "java -Xmx${javaram}M -jar"}


def _pmc191(**kv):
    return _wwr191.pmc_start_problem(dict(_PMCV191, **kv))


check("world reset pmc: LinuxGSM's default start (nogui, paper.jar, in serverfiles) and Paper's other options "
      "(port, online mode, size, an exact -p / -s / --p / --s, bonusChest, server-name) are not refused",
      all(_pmc191(startparameters=s) is None for s in (
          "nogui", "nogui --port 25566", "-p 25566 -o false", "--nogui -s 20 --size 20", "--p 25566 --s 20",
          "--bonusChest --server-name lobby", "-port 25566", "--forceUpgrade")) and _pmc191(executable="") is None, "")
_PMC_MOVES191 = {
    "the world container (-W, --world-dir, --universe, --world-container, abbreviated)":
        ("-W w", "--world-dir w", "--universe=w", "--uni w", "--world-container /srv", "-Ww"),
    "the world name (-w, --world, --level-name, one dash, abbreviated)":
        ("-w x", "--world x", "-world x", "--level-name x", "--level x", "-l x", "--wor=x", "-wfoo"),
    "another server.properties (-c, --config)": ("-c other.properties", "--config o", "-cfoo", "--con o", "--c o"),
    "another bukkit.yml (-b, --bukkit-settings)": ("-b b.yml", "--bukkit-settings b.yml", "--bukk b", "--b b"),
    "another plugins folder (-P, --plugins)": ("-P world/plugins", "--plugins p", "-Pp", "--pl p", "--P p"),
    "a one-letter option after a no-value one in a cluster (-vW)": ("-vW w", "-vw x", "-vS s.yml"),
    "an extra plugin jar or folder (--add-plugin, --add-plugin-dir, abbreviated)":
        ("--add-plugin world/x.jar", "--add-extra-plugin-jar x", "--add-plugin-dir world/p", "--add-extra-plugin-dir p",
         "--add p", "-add-plugin-dir p"),
    "Paper's config folder or file (--paper-dir, --paper-settings, abbreviated)":
        ("--paper-dir world/cfg", "--paper-settings-directory c", "--paper x.yml", "--paper-settings x", "--pa x"),
    "spigot.yml or commands.yml elsewhere (-S, --spigot-settings, -C, --commands-settings)":
        ("-S world/spigot.yml", "--spigot-settings s", "--sp s", "-Sx", "-C world/commands.yml", "--C c",
         "--commands-settings c", "--comm c", "-Cx"),
}
for _why191, _words191 in _PMC_MOVES191.items():
    check("world reset pmc: a start parameter choosing %s is refused" % _why191,
          all(_pmc191(startparameters="nogui " + w) is not None for w in _words191),
          repr([w for w in _words191 if _pmc191(startparameters="nogui " + w) is None]))
check("world reset pmc: the same options in extraparams, or after the jar in `executable`, are refused too",
      _pmc191(extraparams="--world x") is not None and _pmc191(executable="./paper.jar --universe w") is not None, "")
_PRE_OK191 = ("java -Xmx${javaram}M -jar", "java -Xms2G -Xmx4G -XX:+UseG1GC -Dcom.mojang.eula.agree=true -jar",
              "/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx$javaram -jar")
_PRE_BAD191 = {"Paper options after -jar": "java -Xmx2G -jar ./paper.jar --world-dir /srv/w",
               "a wrapper before java": "env -C /srv java -jar", "another program": "python3 -jar", "an @argfile": "java @jvm.args -jar",
               "user.dir moved": "java -Duser.dir=/srv -jar", "a word that is not an option": "java -cp x.jar -jar",
               "no -jar": "java -Xmx2G", "shell syntax": "java -Xmx${heap} -jar", "nothing at all": ""}
check("world reset preexecutable: LinuxGSM's own (java -Xmx${javaram}M -jar), other JVM options and a full path "
      "to java are not refused",
      all(_wwr191.java_pre_problem(p, _wwr191.pmc_start_problem) is None for p in _PRE_OK191), "")
for _why191, _pre191 in _PRE_BAD191.items():
    check("world reset preexecutable: one with %s is refused" % _why191,
          _wwr191.java_pre_problem(_pre191, _wwr191.pmc_start_problem) is not None, repr(_pre191))
check("world reset preexecutable: shell syntax is refused by the preexecutable test itself, with no game scan "
      "given (a JVM option ${heap}, a quoted -jar)",
      _wwr191.java_pre_problem("java -Xmx${heap} -jar") is not None
      and _wwr191.java_pre_problem("java -Xmx2G '-jar'") is not None, "")
check("world reset preexecutable: LinuxGSM's ${javaram} (and $javaram) is the one expansion read, as a number",
      _wwr191.java_pre_problem("java -Xmx${javaram}M -jar") is None and _wwr191.java_pre_problem("java -Xmx$javaram -jar")
      is None and _wwr191.java_pre_problem("java -Xmx${javaramx} -jar") is not None, "")
check("world reset preexecutable: a JVM option the game's option scan refuses is refused too (-Wx for Paper)",
      _wwr191.java_pre_problem("java -Wx -jar", _wwr191.pmc_start_problem) is not None
      and _wwr191.java_pre_problem("java -Wx -jar") is None, "")
check("world reset mcb: a Bedrock preexecutable (LinuxGSM sets none) is refused",
      _wwr191.mcb_start_problem({"executabledir": "${serverfiles}", "preexecutable": "env -C /srv"}) is not None
      and _wwr191.mcb_start_problem({"executabledir": "${serverfiles}"}) is None, "")
check("world reset pmc: a server that does not run in serverfiles (executabledir changed) is refused",
      _pmc191(executabledir="/srv/paper") is not None, "")
_SHELL191 = ('"--world" x', "--wo''rld x", "$(printf -- --world) x", "${EXTRA}", "nogui; true", "-[w] x", "`w`",
             "--wo\\rld x", "nogui > log", "{a,b}")
check("world reset pmc: shell quoting, expansion, globbing or command syntax in the start parameters is refused "
      "(a shell could make a word the option test does not see)",
      all(_pmc191(startparameters=s) is not None for s in _SHELL191),
      repr([s for s in _SHELL191 if _pmc191(startparameters=s) is None]))
check("world reset mc: ...and Minecraft Java's start parameters with shell quoting are refused the same way",
      _wwr191.mc_start_problem({"startparameters": 'nogui "--world" x', "executabledir": "${serverfiles}"})
      is not None and _wwr191.mc_start_problem({"startparameters": "nogui", "extraparams": "--wo''rld x"}) is not None,
      "")

# ── 1c. the LinuxGSM config, read as LinuxGSM reads it ──────────────────────────────────────────
def _cfg191(default="", common="", inst="", secrets_inst=""):
    return [default, common, "", inst, secrets_inst]


_DEF191 = 'startparameters="nogui"\nexecutabledir="${serverfiles}"\npreexecutable="java -Xmx${javaram}M -jar"\n'
_K191 = ["startparameters", "executabledir", "preexecutable", "extraparams"]
eq("world reset cfg: plain lines are read with the last file in LinuxGSM's order winning (instance over "
   "_default, secrets-instance over instance), a key nowhere is empty",
   [_wwr191.cfg_values(_cfg191(_DEF191), _K191)[0],
    _wwr191.cfg_values(_cfg191(_DEF191, inst='startparameters="nogui -p 25566"\n'), ["startparameters"])[0],
    _wwr191.cfg_values(_cfg191(_DEF191, inst='startparameters="a"\n', secrets_inst='  startparameters="b"\n'),
                       ["startparameters"])[0]],
   [{"startparameters": "nogui", "executabledir": "${serverfiles}", "preexecutable": "java -Xmx${javaram}M -jar",
     "extraparams": ""}, {"startparameters": "nogui -p 25566"}, {"startparameters": "b"}])
_CFG_ODD191 = {
    "two lines in one file (LinuxGSM starts with the first, a merge reads the last)":
        'startparameters="nogui --world-dir /srv/w"\nstartparameters="nogui"\n',
    "a tab-indented line (grep finds it, LinuxGSM's sed does not)": '\tstartparameters="nogui --world x"\n',
    "blanks around `=` (bash and LinuxGSM ignore it)": 'startparameters = "nogui"\n',
    "a comment after the value": 'startparameters="nogui" # moved\n',
    "a CRLF line end": 'startparameters="nogui"\r\n',
    "single quotes": "startparameters='nogui'\n",
    "the key set inside a command": '[ -f x ] && startparameters="--world x"\n',
    "a backslash in the value": 'startparameters="nogui \\"\n',
}
for _why191, _txt191 in _CFG_ODD191.items():
    check("world reset cfg: startparameters with %s is refused" % _why191,
          _wwr191.cfg_values(_cfg191(_DEF191, inst=_txt191), ["startparameters"])[0] is None, repr(_txt191))
check("world reset cfg: executabledir and preexecutable are held to the same plain form",
      _wwr191.cfg_values(_cfg191(_DEF191, inst='executabledir="/srv"\nexecutabledir="${serverfiles}"\n'),
                         ["executabledir"])[0] is None
      and _wwr191.cfg_values(_cfg191(_DEF191, common='\tpreexecutable="java -jar x.jar --world w -jar"\n'),
                             ["preexecutable"])[0] is None, "")
check("world reset cfg: a config file that sources another file or runs eval is refused (whatever it sets is not "
      "in the files)",
      all(_wwr191.cfg_values(_cfg191(_DEF191, inst=t), ["executabledir"])[0] is None
          for t in ("source /home/x/more.cfg\n", ". ./more.cfg\n", "  eval \"$x\"\n")), "")
check("world reset cfg: comment lines naming the key, and LinuxGSM's own logdir line, are not refused",
      _wwr191.cfg_values(_cfg191(_DEF191 + '# startparameters="--world x"\n  #startparameters=1\n'
                                 '[ -n "${LGSM_LOGDIR}" ] && logdir="${LGSM_LOGDIR}" || logdir="${rootdir}/log"\n'),
                         _K191)[1] is None, "")


def _cfg_read191(tmp, files):
    """lgsm_cfg_texts against a scratch home: its own shell command run by bash, files as given."""
    d = _os191top.path.join(tmp, "lgsm", "config-lgsm", "p191s")
    _os191top.makedirs(d, exist_ok=True)
    for name, data in files.items():
        with open(_os191top.path.join(d, name), "wb") as fh:
            fh.write(data)

    def _shell(server, user, inner, **k):
        r = _sp191.run(["bash", "-c", inner.replace("/home/p191u", tmp)], capture_output=True, text=True,  # nosec B603 B607
                       timeout=30, check=False)
        return r.stdout.strip(), r.stderr, r.returncode
    try:
        _p9_patch_sm("shell_as_game_user", _shell)
        return _sm191.lgsm_cfg_texts(None, "p191u", "p191s")
    finally:
        _p9_restore_all()


_tmp191 = _tempfile191.mkdtemp(prefix="p191-")
try:
    _cfgread191 = _cfg_read191(_tmp191, {"_default.cfg": b'startparameters="nogui"\r\n', "p191s.cfg": b"x=1\n"})
finally:
    _shutil191.rmtree(_tmp191, ignore_errors=True)
eq("world reset cfg: lgsm_cfg_texts reads the five files in LinuxGSM's order in one command, byte for byte "
   "(a CRLF kept), a missing file as empty",
   _cfgread191, ['startparameters="nogui"\r\n', "", "", "x=1\n", ""])
_UNREAD_NAME191 = "world reset cfg: a config file that is there but cannot be read makes the whole read None (unread)"
if _os191top.geteuid() == 0:
    skip(_UNREAD_NAME191, "root reads a mode-000 file; held by the non-root run")
else:
    _tmp191 = _tempfile191.mkdtemp(prefix="p191-")
    try:
        _secret191 = _os191top.path.join(_tmp191, "lgsm", "config-lgsm", "p191s", "secrets-p191s.cfg")
        _cfg_read191(_tmp191, {"_default.cfg": b'startparameters="nogui"\n'})
        with open(_secret191, "w", encoding="utf-8") as _fh191:
            _fh191.write('startparameters="--world x"\n')
        _os191top.chmod(_secret191, 0)
        _unread191 = _cfg_read191(_tmp191, {})
    finally:
        _shutil191.rmtree(_tmp191, ignore_errors=True)
    check(_UNREAD_NAME191, _unread191 is None, repr(_unread191))


# ── 2. bukkit.yml ───────────────────────────────────────────────────────────────────────────────
_BUKKIT191 = ("# The main configuration file for Bukkit.\nsettings:\n  allow-end: true\n  warn-on-overload: true\n"
              "  permissions-file: permissions.yml\n  shutdown-message: Server closed\n  # world-container: x\n"
              "spawn-limits:\n  monsters: 70\n")
check("world reset pmc: a bukkit.yml without world-container (one only in a whole-line comment) is not refused",
      _wwr191.bukkit_problem(_BUKKIT191) is None and _wwr191.bukkit_problem(_BUKKIT191.replace("\n", "\r\n")) is None, "")
check("world reset pmc: bukkit.yml setting world-container (block, flow style, quoted, any case) is refused",
      all(_wwr191.bukkit_problem(_BUKKIT191 + t) is not None for t in (
          "settings:\n  world-container: worlds\n", "settings: {world-container: w}\n", "'world-container': w\n",
          "  World-Container: w\n", "settings:\n  world-container: w # moved\n")), "")
check("world reset pmc: a backslash escape in bukkit.yml (which could spell world-container) is refused",
      _wwr191.bukkit_problem(_BUKKIT191 + 'settings:\n  "world\\x2dcontainer": w\n') is not None, "")

# ── 3. Bedrock's server.properties ──────────────────────────────────────────────────────────────
_MCB_PROPS191 = ("server-name=Dedicated Server\n# Used as the server name\n# Allowed values: Any string without "
                 "semicolon symbol.\n\ngamemode=survival\nlevel-name=Bedrock level\n# Allowed values: Any string "
                 "without semicolon symbol or symbols illegal for file name.\nlevel-seed=\n")
eq("world reset mcb: a plain level-name line is read as it is, a blank inside kept (LF and CRLF files)",
   [_wwr191.bedrock_level_name(_MCB_PROPS191), _wwr191.bedrock_level_name(_MCB_PROPS191.replace("\n", "\r\n")),
    _wwr191.bedrock_level_name("level-name=Survival 2\nlevel-name=Survival 2\n")],
   [("Bedrock level", None), ("Bedrock level", None), ("Survival 2", None)])
_MCB_FORMS191 = {"a leading blank": " level-name=x\n", "a blank before =": "level-name =x\n",
                 "another case": "Level-Name=x\n", "`:` for `=`": "level-name: x\n", "no `=`": "level-name\n",
                 "a byte-order mark": "﻿level-name=x\n"}
for _why191, _text191 in _MCB_FORMS191.items():
    check("world reset mcb: a level-name line with %s is refused, not read, even beside a plain one" % _why191,
          _wwr191.bedrock_level_name("motd=x\n" + _text191)[0] is None
          and _wwr191.bedrock_level_name("level-name=plain\n" + _text191)[0] is None, repr(_text191))
check("world reset mcb: no level-name line at all is refused (the server's default is not assumed)",
      _wwr191.bedrock_level_name("server-name=x\n#level-name=commented\n") == (None, "server.properties has no "
                                                                               "level-name line"), "")
check("world reset mcb: two level-name lines naming different worlds are refused",
      _wwr191.bedrock_level_name("level-name=a\nlevel-name=b\n")[0] is None, "")
_MCB_BAD191 = {"a semicolon": "a;b", "a colon": "a:b", "a star": "w*", "a question mark": "w?", "a pipe": "a|b",
               "a double quote": 'a"b', "a backtick": "a`b", "angle brackets": "a<b>", "an equals sign": "a=b",
               "'..' inside": "a..b", "a non-ASCII letter": "monde été", "a slash": "a/b", "a backslash": "a\\b",
               "a tab": "a\tb", "a carriage return inside": "a\rb", "a leading dash": "-w", "a trailing blank": "w ",
               "an empty name": "", "over 64 characters": "w" * 65, "'..'": ".."}
for _why191, _name191 in _MCB_BAD191.items():
    check("world reset mcb: a level-name with %s is refused" % _why191,
          _wwr191.bedrock_level_name("level-name=%s\n" % _name191)[0] is None, repr(_name191))

# ── 4. the resolvers, as the sweep asks them ────────────────────────────────────────────────────
_MCBV191 = {"startparameters": "", "extraparams": "", "executabledir": "${serverfiles}"}
_pmc_sid191 = _p9_new_server(P9_HOST, "p191pmc", "pmc", 25566, name="p191-pmc")
_mcb_sid191 = _p9_new_server(P9_HOST, "p191mcb", "mcb", 19132, name="p191-mcb")


def _reads191(props, bukkit=(None, "File not found")):
    """A read_file stand-in: server.properties and bukkit.yml answer as given, and each path read is noted."""
    asked = []

    def _read(path):
        asked.append(path)
        return bukkit if path.endswith("bukkit.yml") else props
    _read.asked = asked
    return _read


_PROPS191 = "motd=hi\nlevel-name=survival\n"
_pmcread191 = _reads191((_PROPS191, None))
_pok191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191), read=_pmcread191)
check("world reset sweep (pmc): state, stop, backup, the delete of survival and the old layout's "
      "survival_nether / survival_the_end, start; done, with server.properties and bukkit.yml read first",
      _pok191["cmds"][:3] == ["status", "stop", "backup"] and len(_pok191["cmds"]) == 5
      and _is_delete183(_pok191["cmds"][3]) and "set -- survival survival_nether survival_the_end" in _pok191["cmds"][3]
      and _pok191["cmds"][4] == "start" and _last183(_pok191).get("ok") is True
      and _pmcread191.asked == ["serverfiles/server.properties", "serverfiles/bukkit.yml"], repr(_pok191))
_pcont191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191),
                           read=_reads191((_PROPS191, None), ("settings:\n  world-container: /srv/worlds\n", None)))
check("world reset sweep (pmc): a bukkit.yml with world-container ends the reset, alerted, the server untouched",
      _pcont191["cmds"] == [] and _last183(_pcont191).get("ok") is False
      and "world-container" in (_last183(_pcont191).get("detail") or "")
      and _pcont191["alerts"] == ["Scheduled wipe did not run"], repr(_pcont191))
_pbunread191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191),
                              read=_reads191((_PROPS191, None), (None, "Could not read that file — no answer.")))
_pbfirm191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191),
                            read=_reads191((_PROPS191, None), (None, "Invalid path")))
check("world reset sweep (pmc): a bukkit.yml that could not be read waits (server untouched); one the reader "
      "refuses for good ends the reset",
      _pbunread191["cmds"] == [] and _pbunread191["entry"].get("pending_since")
      and "bukkit.yml could not be read" in (_pbunread191["entry"].get("wait") or "")
      and _pbfirm191["cmds"] == [] and not _pbfirm191["entry"].get("pending_since")
      and _last183(_pbfirm191).get("ok") is False, repr((_pbunread191, _pbfirm191)))
_pwread191 = _reads191((_PROPS191, None))
_pworld191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191, startparameters="nogui --world-container /srv"),
                            read=_pwread191)
check("world reset sweep (pmc): a Paper started with --world-container is not reset, nothing read or stopped",
      _pworld191["cmds"] == [] and _pwread191.asked == [] and _last183(_pworld191).get("ok") is False
      and "--world-container" in (_last183(_pworld191).get("detail") or ""), repr(_pworld191))

_dupread191 = _reads191((_PROPS191, None))
_dup191 = _sweep_case183(_pmc_sid191, read=_dupread191, cfg=[
    'startparameters="nogui"\nexecutabledir="${serverfiles}"\nexecutable="./paper.jar"\n'
    'preexecutable="java -Xmx${javaram}M -jar"\n', "", "",
    'startparameters="nogui --world-dir /srv/w"\nstartparameters="nogui"\n', ""])
check("world reset sweep (pmc): an instance cfg with two startparameters lines (LinuxGSM starts with the first) "
      "is not reset, nothing read or stopped",
      _dup191["cmds"] == [] and _dupread191.asked == [] and _last183(_dup191).get("ok") is False
      and "more than once" in (_last183(_dup191).get("detail") or ""), repr(_dup191))
_pre191 = _sweep_case183(_pmc_sid191, read=_reads191((_PROPS191, None)),
                         values=dict(_PMCV191, preexecutable="java -Xmx2G -jar ./paper.jar --world-dir /srv/w"))
check("world reset sweep (pmc): a preexecutable passing Paper options after -jar is not reset, nothing stopped",
      _pre191["cmds"] == [] and "preexecutable" in (_last183(_pre191).get("detail") or ""), repr(_pre191))
_plug191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191), read=_reads191(("level-name=Plugins\n", None)))
_logs191 = _sweep_case183(_pmc_sid191, values=dict(_PMCV191), read=_reads191(("level-name=logs\n", None)))
check("world reset sweep (pmc): a level-name naming one of the server's own folders (plugins, logs, any case) is "
      "not reset, nothing stopped",
      all(g["cmds"] == [] and "server's own folders" in (_last183(g).get("detail") or "") for g in (_plug191, _logs191)),
      repr((_plug191, _logs191)))
check("world reset sweep (pmc): the delete command carries the level.dat test",
      len(_pok191["cmds"]) > 3 and "__WWR_NOTWORLD__" in _pok191["cmds"][3], "")

_mcbread191 = _reads191((_MCB_PROPS191, None))
_mok191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191), read=_mcbread191)
check("world reset sweep (mcb): state, stop, backup, the delete of worlds/'Bedrock level' (quoted, with the "
      "worlds folder's symlink test), start; done",
      _mok191["cmds"][:3] == ["status", "stop", "backup"] and len(_mok191["cmds"]) == 5
      and _is_delete183(_mok191["cmds"][3]) and "set -- 'Bedrock level'" in _mok191["cmds"][3]
      and 'if [ -L "$sf/worlds" ]' in _mok191["cmds"][3] and 'd="$sf/worlds"' in _mok191["cmds"][3]
      and "__WWR_NOTWORLD__" in _mok191["cmds"][3]
      and _mok191["cmds"][4] == "start" and _last183(_mok191).get("ok") is True
      and _mcbread191.asked == ["serverfiles/server.properties"], repr(_mok191))
_mparams191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191, startparameters="-x"), read=_reads191((_MCB_PROPS191, None)))
_mexedir191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191, executabledir="/opt/bedrock"),
                             read=_reads191((_MCB_PROPS191, None)))
_mnoname191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191), read=_reads191(("server-name=x\n", None)))
check("world reset sweep (mcb): start parameters, a non-default executabledir, or no level-name line end the "
      "reset, alerted, the server untouched",
      all(g["cmds"] == [] and _last183(g).get("ok") is False and g["alerts"] == ["Scheduled wipe did not run"]
          for g in (_mparams191, _mexedir191, _mnoname191)), repr((_mparams191, _mexedir191, _mnoname191)))
_munread191 = _sweep_case183(_mcb_sid191, values=None, read=_reads191((_MCB_PROPS191, None)))
check("world reset sweep (mcb): a LinuxGSM config that could not be read waits, nothing stopped",
      _munread191["cmds"] == [] and _munread191["entry"].get("pending_since"), repr(_munread191))
_mplayers191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191), read=_reads191((_MCB_PROPS191, None)), players=2)
check("world reset sweep (mcb): where Bedrock's players can be counted (a RakNet server gamedig reaches), with "
      "'wait until empty' on, players online keep it waiting with nothing stopped",
      _mplayers191["cmds"] == ["status"] and _mplayers191["players_asked"] == 1
      and "2 player(s) online" in (_mplayers191["entry"].get("wait") or "")
      and _core191.GAMEDIG_TYPE.get("mcb") == "mbe" and _core191.GAMEDIG_TYPE.get("pmc") == "minecraft",
      repr(_mplayers191))
_mnocount191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191), read=_reads191((_MCB_PROPS191, None)), players=None)
_mnowait191 = _sweep_case183(_mcb_sid191, values=dict(_MCBV191), read=_reads191((_MCB_PROPS191, None)), players=None,
                             wait_empty=False)
check("world reset sweep (mcb): players that cannot be counted wait only when 'wait until empty' is ticked; "
      "unticked (the card's default for Bedrock) the reset runs without asking",
      _mnocount191["cmds"] == ["status"] and "could not be counted" in (_mnocount191["entry"].get("wait") or "")
      and _mnowait191["players_asked"] == 0 and _last183(_mnowait191).get("ok") is True
      and len(_mnowait191["cmds"]) == 5, repr((_mnocount191, _mnowait191)))

# ── 5. the host command against scratch trees ───────────────────────────────────────────────────
_PMC_PLAN191 = {"dir": "", "remove": ["world", "world_nether", "world_the_end"], "globs": [], "create": None,
                "world": True}
_PMC_FILES191 = ("serverfiles/world/level.dat", "serverfiles/world/players/p.dat", "serverfiles/world/datapacks/d.zip",
                 "serverfiles/world/dimensions/minecraft/the_nether/region/r.0.0.mca",
                 "serverfiles/world/dimensions/minecraft/overworld/paper-world.yml",
                 "serverfiles/plugins/Essentials.jar", "serverfiles/plugins/Essentials/config.yml",
                 "serverfiles/config/paper-global.yml", "serverfiles/bukkit.yml", "serverfiles/spigot.yml",
                 "serverfiles/lobby/level.dat", "serverfiles/ops.json", "serverfiles/server.properties",
                 "serverfiles/paper.jar")
_pmchost191 = _host183(_PMC_PLAN191, _PMC_FILES191)
eq("world reset host (pmc): Paper's world folder goes whole (players, datapacks, dimensions, its own Paper "
   "settings); plugins, config, bukkit.yml, a plugin's own world (lobby) and the server's files stay",
   (_pmchost191[0], _wwr191.outcome(_pmchost191[1], _pmchost191[2], _PMC_PLAN191)),
   (["serverfiles/bukkit.yml", "serverfiles/config/paper-global.yml", "serverfiles/lobby/level.dat",
     "serverfiles/ops.json", "serverfiles/paper.jar", "serverfiles/plugins/Essentials.jar",
     "serverfiles/plugins/Essentials/config.yml", "serverfiles/server.properties", "serverfiles/spigot.yml"],
    ("done", "world deleted (1 removed)")))
_pmcold191 = _host183(_PMC_PLAN191, ("serverfiles/world/level.dat", "serverfiles/world_nether/level.dat",
                                     "serverfiles/world_nether/DIM-1/r", "serverfiles/world_the_end/level.dat",
                                     "serverfiles/world_the_end/DIM1/r", "serverfiles/plugins/p.jar"))
check("world reset host (pmc): an older Paper's world_nether and world_the_end beside the world go too",
      _pmcold191[0] == ["serverfiles/plugins/p.jar"]
      and _wwr191.outcome(_pmcold191[1], _pmcold191[2], _PMC_PLAN191) == ("done", "world deleted (3 removed)"),
      repr(_pmcold191[:3]))

_MCB_PLAN191 = {"dir": "worlds", "remove": ["Bedrock level"], "globs": [], "create": None, "world": True}
_MCB_FILES191 = ("serverfiles/worlds/Bedrock level/level.dat", "serverfiles/worlds/Bedrock level/levelname.txt",
                 "serverfiles/worlds/Bedrock level/db/CURRENT", "serverfiles/worlds/Bedrock level/world_behavior_packs.json",
                 "serverfiles/worlds/Bedrock/level.dat", "serverfiles/worlds/Other world/level.dat",
                 "serverfiles/permissions.json", "serverfiles/allowlist.json", "serverfiles/server.properties",
                 "serverfiles/behavior_packs/vanilla/manifest.json", "serverfiles/resource_packs/vanilla/manifest.json",
                 "serverfiles/bedrock_server")
_mcbhost191 = _host183(_MCB_PLAN191, _MCB_FILES191)
eq("world reset host (mcb): worlds/'Bedrock level' goes whole; worlds/Bedrock, the other worlds, permissions, "
   "allowlist, server.properties and the shared packs stay",
   (_mcbhost191[0], _wwr191.outcome(_mcbhost191[1], _mcbhost191[2], _MCB_PLAN191)),
   (["serverfiles/allowlist.json", "serverfiles/bedrock_server", "serverfiles/behavior_packs/vanilla/manifest.json",
     "serverfiles/permissions.json", "serverfiles/resource_packs/vanilla/manifest.json", "serverfiles/server.properties",
     "serverfiles/worlds/Bedrock/level.dat", "serverfiles/worlds/Other world/level.dat"],
    ("done", "world deleted (1 removed)")))
_mcblink191 = _host183(_MCB_PLAN191, ("serverfiles/server.properties",), links=[("serverfiles/worlds", "@OUT")])
check("world reset host (mcb): a worlds folder that is a symlink is refused, nothing deleted there",
      _wwr191.outcome(_mcblink191[1], _mcblink191[2], _MCB_PLAN191)[0] == "refused" and "__WWR_LINK__" in _mcblink191[1]
      and _mcblink191[5], repr(_mcblink191[:3]))
_mcbnone191 = _host183(_MCB_PLAN191, ("serverfiles/worlds/Other world/level.dat",))
check("world reset host (mcb): no folder of that name in worlds/ is 'nothing found', the other world kept",
      "__WWR_NOTHING__" in _mcbnone191[1] and _mcbnone191[0] == ["serverfiles/worlds/Other world/level.dat"],
      repr(_mcbnone191[:3]))

_NOTWORLD191 = {
    "a world folder without level.dat": (_PMC_PLAN191, ("serverfiles/world/region/r.0.0.mca", "serverfiles/plugins/p.jar")),
    "a _nether folder without level.dat": (_PMC_PLAN191, ("serverfiles/world/level.dat", "serverfiles/world_nether/x")),
    "a file where the world folder should be": (dict(_PMC_PLAN191, remove=["ops.json"]), ("serverfiles/ops.json",)),
    "a Bedrock world folder without level.dat": (_MCB_PLAN191, ("serverfiles/worlds/Bedrock level/db/CURRENT",)),
}
for _why191, (_plan191, _files191) in _NOTWORLD191.items():
    _nw191 = _host183(_plan191, _files191)
    check("world reset host: %s is refused as not a world, nothing deleted" % _why191,
          "__WWR_NOTWORLD__" in _nw191[1] and "__WWR_GONE__" not in _nw191[1]
          and sorted(_nw191[0]) == sorted(_files191)
          and _wwr191.outcome(_nw191[1], _nw191[2], _plan191)[0] == "refused", repr(_nw191[:3]))
_nomain191 = _host183(_PMC_PLAN191, ("serverfiles/world_nether/level.dat", "serverfiles/world_nether/DIM-1/r"))
check("world reset host: with no world folder, a _nether beside it is not deleted on its own ('nothing found')",
      "__WWR_NOTHING__" in _nomain191[1] and _nomain191[0] == ["serverfiles/world_nether/DIM-1/r",
                                                               "serverfiles/world_nether/level.dat"],
      repr(_nomain191[:3]))
_FPLAN191 = _wwr191.fctr_layout({"startparameters": "--start-server-load-latest",
                                  "executabledir": "${serverfiles}/bin/x64"})[0]
_fnolevel191 = _host183(_FPLAN191, ("serverfiles/saves/save1.zip",))
check("world reset host: Factorio's save files are not held to the level.dat test",
      _wwr191.outcome(_fnolevel191[1], _fnolevel191[2], _FPLAN191)[0] == "done", repr(_fnolevel191[:3]))

# ── 6. the card ─────────────────────────────────────────────────────────────────────────────────
_BODY191 = {"enabled": True, "kind": "reset", "preset": "custom", "cron": "0 4 * * *", "tz": "UTC"}
_r191 = {}
try:
    _p9_arm(who="part191")
    _A191 = _p9_client(P9_ADMIN)
    for _g191, _s191 in (("pmc", _pmc_sid191), ("mcb", _mcb_sid191)):
        _r191["get_" + _g191] = _A191.get("/api/server/%d/wipe-schedule" % _s191).get_json()
        _r191["save_" + _g191] = _A191.post("/api/server/%d/wipe-schedule" % _s191, json=_BODY191).status_code
        _r191["kind_" + _g191] = (_ws191.get(_s191) or {}).get("kind")
        _r191["map_" + _g191] = _A191.post("/api/server/%d/wipe-schedule" % _s191,
                                           json=dict(_BODY191, kind="map")).status_code
    _p9_patch(_sd191, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd191, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_sf191, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("run_command", lambda *a, **k: ("", "", 1))
    _r191["pages"] = {g: _A191.get("/server/%d/files" % s).get_data(as_text=True)
                      for g, s in (("pmc", _pmc_sid191), ("mcb", _mcb_sid191))}
finally:
    _p9_restore_all()
    _ws191.put(_pmc_sid191, None)
    _ws191.put(_mcb_sid191, None)
check("world reset route: Paper and Bedrock servers get a reset card; `reset` is saved, map/full refused",
      all(_r191["get_" + g].get("reset") is True and _r191["get_" + g].get("supported") is True
          and _r191["save_" + g] == 200 and _r191["kind_" + g] == "reset" and _r191["map_" + g] == 400
          for g in ("pmc", "mcb")), repr(_r191))
_pg191 = _r191.get("pages", {})
check("world reset page: Paper's card says its world folder goes and plugins and Paper's config stay; "
      "Bedrock's says worlds/ and the packs to add again; both a fixed `reset` kind",
      all('id="wipe-kind" value="reset"' in _pg191.get(g, "") for g in ("pmc", "mcb"))
      and "plugins, worlds a plugin created, Paper" in _pg191.get("pmc", "")
      and "s folder in worlds/ (the one level-name names" in _pg191.get("mcb", "")
      and "Packs the old world applied are not applied to the new one" in _pg191.get("mcb", ""), "")
check("world reset page: the player box is ticked for Paper and unticked for Bedrock, whose card says its players "
      "can't be counted and to leave the box unticked",
      'id="wipe-wait" checked' in _pg191.get("pmc", "") and 'id="wipe-wait">' in _pg191.get("mcb", "")
      and "Bedrock servers can't be asked for their player count" in _pg191.get("mcb", "")
      and "so leave it unticked" in _pg191.get("mcb", ""), "")

for _sid191 in (_pmc_sid191, _mcb_sid191):
    _p9_delete_server(_sid191)
eq("world reset (pmc, mcb): nothing this part drove reached a real transport (part12's tripwire, armed)",
   _P9_TRIPPED[_trips191:], [])
