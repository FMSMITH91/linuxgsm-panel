"""Scheduled world resets for games whose LinuxGSM script has no wipe command (Minecraft, Factorio).

LinuxGSM gives `wipe` / `full-wipe` to Rust alone (core_getopt.sh, checked on master 2026-11). For
the games here the panel does the reset itself, on the Wipe schedule card's schedule and after the
same backup (routes/wipe_schedule): LinuxGSM `stop`, then ONE command as the game account that
checks the server is really down and deletes the world (and, for Factorio, creates the new save),
then LinuxGSM `start`. This module holds the parts that need no Flask: which files make up a game's
world (a resolver per game, reading the instance's own config), the checks on a name read from that
config, the shell script, and how its output is read.

Adding a game is one entry in RESOLVERS plus its resolver: (plan, None) or (None, why refused).

THE WORLD, per game (LinuxGSM master, 2026-11; Minecraft Wiki "Server.properties"; Factorio Wiki
"Command line parameters" and "Multiplayer"):

* mc (mcserver): the server runs in serverfiles (executabledir="${serverfiles}") and reads
  server.properties there. Its world is the folder `level-name` names (default `world`), and a
  Bukkit-style server keeps the other dimensions beside it as <level-name>_nether and
  <level-name>_the_end (vanilla keeps them inside the world folder). With no folder of that name the
  server generates a new world on start, from `level-seed` when one is set. ops.json,
  whitelist.json, the ban lists and server.properties sit beside the world and are kept.
* fctr (fctrserver): LinuxGSM's install creates the save with
  `"${executabledir}"/factorio --create "${serverfiles}/saves/save1"` and starts the server with
  `--start-server-load-latest`, which loads the newest save in serverfiles/saves (since LinuxGSM's
  #4960; before it, the save was serverfiles/save1.zip, started with `--start-server
  ${serverfiles}/save1.zip`, and an instance config can still hold that). The world is LinuxGSM's
  save plus the server's autosaves (_autosave<N>.zip); a new save1 is created the same way, so it is
  the newest one and the one loaded. Other saves an operator put there are kept. Anything else in
  the start parameters is refused: the panel cannot tell which save the server starts.
* pmc (pmcserver, Paper): as mc (executabledir="${serverfiles}", server.properties there), with
  Paper's own ways of moving the world refused (CraftBukkit Main and Paper's patch of the server's
  Main, PaperMC/Paper main, 2026-11): the options -W/--world-dir/--universe/--world-container (the
  folder level-name is relative to), -w/--world/--level-name (overrides level-name), -c/--config
  (another properties file), -b/--bukkit-settings (another bukkit.yml), -P/--plugins (the plugins
  folder, which a reset must not reach), and bukkit.yml's settings.world-container, which Paper
  reads when no --universe is given. Current Paper keeps the nether and end inside the world folder
  (world/dimensions/minecraft/...); older ones had world_nether / world_the_end beside it, removed
  when present. plugins/ and config/ are kept.
* mcb (mcbserver, Bedrock): the server runs in serverfiles and keeps its world in
  worlds/<level-name> (Microsoft Learn, "Bedrock Dedicated Server Properties" and "Getting
  Started"), creating a new one there on start when the folder is missing. Its server.properties is
  key=value lines with `#` comments, not java.util.Properties, so only a plain `level-name=<name>`
  line is read (bedrock_level_name). permissions.json, allowlist.json, server.properties and the
  shared behavior_packs / resource_packs folders sit in serverfiles and are kept.
"""
import re

from panel.core import i18n, terminal
from panel.ops import ssh_manager as _sm

# The kind the schedule stores for these games (there is no map/full split here).
KIND = "reset"
# Longest level-name accepted. Minecraft takes longer, but a name this long is not one to guess about.
_WWR_NAME_MAX = 64
_WWR_PROPS = "serverfiles/server.properties"
_WWR_NO_FILE = "File not found"           # read_file's answer for a file that is not there
# Factorio's start options: exactly one of these must be in the start parameters.
_WWR_FCTR_START = ("--start-server", "--start-server-load-latest", "--start-server-load-scenario")
_WWR_FCTR_OLD_SAVE = ("${serverfiles}/save1.zip", "$serverfiles/save1.zip")
_WWR_FCTR_EXEDIR = ("", "${serverfiles}/bin/x64", "$serverfiles/bin/x64")
_WWR_FCTR_EXE = ("", "./factorio")
# What the script prints. Each starts a line; nothing the host prints can be mistaken for one, since a
# deleted name is never echoed.
_M_NOSF, _M_RUNNING, _M_LINK, _M_OUTSIDE = "__WWR_NOSF__", "__WWR_RUNNING__", "__WWR_LINK__", "__WWR_OUTSIDE__"
_M_RMFAIL, _M_GONE, _M_CREATED, _M_CREATEFAIL = "__WWR_RMFAIL__", "__WWR_GONE__", "__WWR_CREATED__", "__WWR_CREATEFAIL__"
_M_DELETED, _M_NOTHING, _M_BUSY, _M_LOCKED = "__WWR_DELETED__", "__WWR_NOTHING__", "__WWR_BUSY__", "__WWR_LOCKED__"
_M_UP, _M_DOWN = "__WWR_UP__", "__WWR_DOWN__"
# How long the delete waits, after LinuxGSM's stop, for the account's processes to let go of serverfiles:
# polls of 2 seconds. Minecraft goes on saving after LinuxGSM's tmux kill (its shutdown hook joins the
# server thread), and a Factorio still running holds its write-data lock.
_WWR_BUSY_POLLS = 30
# Minecraft's own options that move the world (--world overrides level-name, --universe is the folder
# level-name is relative to). The server's option parser takes an abbreviation and a single dash, so any
# word starting with -w / -u (either case) is read as one of them: no other option of the vanilla
# server starts with those letters.
_WWR_MC_WORLD_OPT = re.compile(r"-{1,2}[wu]", re.I)
_WWR_MC_EXEDIR = ("", "${serverfiles}", "$serverfiles")
# The start command is a string LinuxGSM hands tmux, which a shell runs: quoting, expansion, globbing
# and command syntax could make words the panel does not see, so a start parameter holding one is refused.
_WWR_SHELL_SYNTAX = frozenset("\"'`$\\;&|<>(){}*?[]")
_WWR_SHELL_SAID = i18n.Sentence("the start parameters use shell quoting, expansion or syntax, which the panel "
                                "does not read")


class Unread(i18n.Sentence):
    """A refusal because a read failed (not because of what it said): the reset is tried again later."""

    __slots__ = ()


def world_name_problem(name):
    """Why `name` (a level-name read from server.properties) is not used as a folder name, else None.

    Refused rather than guessed: an empty name, `.` or `..`, a path separator or backslash (Java
    properties escapes, which the server writes for some characters), NUL or any control character
    (a newline included), a leading `-` (read as an option), blanks at either end, and over 64
    characters.
    """
    if not isinstance(name, str) or not name:
        return i18n.Sentence("it is empty")
    return next((why for bad, why in _WWR_NAME_RULES if bad(name)), None)


# Each rule: (refuses, the sentence said). Asked in order, after the empty test.
_WWR_NAME_RULES = (
    (lambda n: n in (".", ".."), i18n.Sentence("it is '.' or '..'")),
    (lambda n: len(n) > _WWR_NAME_MAX, i18n.Sentence("it is longer than {max} characters", max=_WWR_NAME_MAX)),
    (lambda n: "/" in n or "\\" in n, i18n.Sentence("it contains a slash or backslash")),
    (lambda n: not all(c == " " or c.isprintable() for c in n),
     i18n.Sentence("it contains a control or non-printable character")),
    (lambda n: n.startswith("-"), i18n.Sentence("it starts with '-'")),
    (lambda n: n != n.strip(), i18n.Sentence("it starts or ends with a blank")),
)


_WWR_BLANK = " \t\f"      # what java.util.Properties skips between a key and its value


def _wwr_continues(line):
    """Whether a properties line goes on to the next: it ends in an odd number of backslashes."""
    return (len(line) - len(line.rstrip("\\"))) % 2 == 1


def _wwr_logical_lines(props):
    r"""server.properties as java.util.Properties reads it: logical lines, comments and blanks dropped.

    Lines end only at \\n, \\r or \\r\\n (not at the other characters str.splitlines() breaks on); a
    line ending in an odd number of backslashes goes on with the next line, its leading blanks dropped;
    a comment line (`#` or `!` first) never goes on.
    """
    phys = re.split(r"\r\n|\r|\n", props)
    out, i = [], 0
    while i < len(phys):
        line, i = phys[i].lstrip(_WWR_BLANK), i + 1
        if not line or line[0] in "#!":
            continue
        while _wwr_continues(line) and i < len(phys):
            line, i = line[:-1] + phys[i].lstrip(_WWR_BLANK), i + 1
        out.append(line)
    return out


def _wwr_key_value(line):
    """(raw key, raw value) of one logical line: the key ends at the first unescaped blank, `=` or `:`."""
    i = 0
    while i < len(line) and line[i] not in _WWR_BLANK + "=:":
        i += 2 if line[i] == "\\" else 1
    key, rest = line[:i], line[i:].lstrip(_WWR_BLANK)
    if rest[:1] in ("=", ":"):
        rest = rest[1:].lstrip(_WWR_BLANK)
    return key, rest


def _wwr_unescaped(key):
    r"""A key with its properties escapes undone (\uXXXX and \<char>)."""
    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)",
                  lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 5 else m.group(1), key)


def level_name(props):
    """`level-name` from server.properties text: (name, None), or (None, why) when it cannot be used.

    Read as java.util.Properties reads it (_wwr_logical_lines, _wwr_key_value); the last line for the key
    wins, and a file without it is Minecraft's default, `world`. A key or value written with a
    backslash escape is refused rather than decoded (world_name_problem), as is anything not printable.
    """
    found = None
    for line in _wwr_logical_lines(props):
        key, value = _wwr_key_value(line)
        if _wwr_unescaped(key) == "level-name":
            found = value if key == "level-name" else "\\" + value     # an escaped key: refused below
    name = "world" if found is None else found
    why = world_name_problem(name)
    return (None, why) if why else (name, None)


def mc_start_problem(values):
    """Why the instance's LinuxGSM values put the world somewhere server.properties does not say, else None.

    The jar runs in executabledir (LinuxGSM's default: serverfiles) and reads level-name from there,
    unless the start parameters pass --world or --universe (_WWR_MC_WORLD_OPT). Shell quoting or
    expansion there (_WWR_SHELL_SYNTAX) could spell one the word test does not see (`"--world" x`).
    """
    if (values.get("executabledir") or "") not in _WWR_MC_EXEDIR:
        return i18n.Sentence("the server does not run in serverfiles (executabledir is not LinuxGSM's default)")
    text = "%s %s" % (values.get("startparameters") or "", values.get("extraparams") or "")
    if any(c in _WWR_SHELL_SYNTAX for c in text):
        return _WWR_SHELL_SAID
    if any(_WWR_MC_WORLD_OPT.match(w) for w in text.split()):
        return i18n.Sentence("the start parameters choose the world folder themselves (--world or --universe)")
    return None


def _wwr_firm_read_errors():
    """read_file's answers that will not change on a retry: the file is not there, or cannot be used."""
    return frozenset(_sm.files._READ_REFUSALS.values()) | {_WWR_NO_FILE, "Invalid path"}


def _wwr_props(gs):
    """serverfiles/server.properties of `gs`: (text, None), or (None, why) — an Unread when the read failed."""
    content, err = _sm.read_file(gs.remote, gs.short_name, _WWR_PROPS)
    if err in _wwr_firm_read_errors():
        return None, i18n.Sentence("serverfiles/server.properties cannot be used: {error}", error=str(err))
    if err is not None or content is None:
        return None, Unread("server.properties could not be read: {error}", error=str(err or "no answer"))
    if not content.strip():
        return None, i18n.Sentence("server.properties is empty, so the world's name is not known")
    return content, None


def _wwr_values(gs, keys):
    """The instance's merged LinuxGSM values for `keys`: (values, None), or (None, Unread)."""
    values = _sm.lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, keys)
    if values is None:
        return None, Unread("the server's LinuxGSM config could not be read")
    return values, None


def _wwr_java_plan(gs, start_problem, extra_check=None):
    """The world of a Java edition server (mc, pmc): (plan, None), or (None, why it is not reset).

    `start_problem` judges the instance's LinuxGSM values; `extra_check(gs)`, when given, is asked
    after server.properties was read and answers None or why the reset is refused.
    """
    values, why = _wwr_values(gs, ["startparameters", "extraparams", "executabledir", "executable"])
    why = why or start_problem(values)
    if why is not None:
        return None, why
    content, why = _wwr_props(gs)
    if content is None:
        return None, why
    name, why = level_name(content)
    if name is None:
        return None, i18n.Sentence("level-name in server.properties is not used: {why}", why=why)
    why = extra_check(gs) if extra_check else None
    if why is not None:
        return None, why
    return {"dir": "", "remove": [name, name + "_nether", name + "_the_end"], "globs": [], "create": None}, None


def mc_plan(gs):
    """The world of Minecraft Java server `gs`: (plan, None), or (None, why it is not reset)."""
    return _wwr_java_plan(gs, mc_start_problem)


# Paper's options that move the world, or the files that say where it is (CraftBukkit Main on PaperMC/Paper
# main, 2026-11): W/world-dir/universe/world-container, w/world/level-name, c/config (server.properties),
# b/bukkit-settings (bukkit.yml, which can hold world-container) and P/plugins (a plugins folder inside the
# world would go with it). Paper's parser is jopt-simple with abbreviations on: a long option may be any
# unambiguous prefix, given with one dash or two, and its value after `=`; one-letter options cluster
# (`-vW x`), the rest of the word being the value of the first one that takes one.
_WWR_PMC_LONG = ("world-dir", "universe", "world-container", "world", "level-name", "config", "bukkit-settings",
                 "plugins")
_WWR_PMC_SHORT = "WwcbP"
# One-letter options that take no value (help, version), so a cluster reads on past them.
_WWR_PMC_NOARG = "?v"
# One-letter options whose letter starts a refused long name (port, commands settings): given exactly,
# jopt-simple takes the option of that name, not an abbreviation.
_WWR_PMC_EXACT_OK = ("p", "C")


def _wwr_pmc_word_moves(word):
    """Whether one word of Paper's start parameters is, or may be read as, an option in _WWR_PMC_LONG."""
    if not word.startswith("-") or word in ("-", "--"):
        return False
    body = word[2:] if word.startswith("--") else word[1:]
    name = body.split("=", 1)[0]
    if name in _WWR_PMC_EXACT_OK:
        return False
    if name and any(n.startswith(name.lower()) for n in _WWR_PMC_LONG):
        return True
    return not word.startswith("--") and body.lstrip(_WWR_PMC_NOARG)[:1] in tuple(_WWR_PMC_SHORT)


def pmc_start_problem(values):
    """Why the instance's LinuxGSM values may put a Paper world somewhere server.properties does not say, else None.

    LinuxGSM starts `${preexecutable} ${executable} ${startparameters}` in executabledir
    (command_start.sh); extraparams is added to startparameters. So the words after the jar in
    `executable`, the start parameters and extraparams are Paper's arguments.
    """
    if (values.get("executabledir") or "") not in _WWR_MC_EXEDIR:
        return i18n.Sentence("the server does not run in serverfiles (executabledir is not LinuxGSM's default)")
    text = "%s %s %s" % (" ".join((values.get("executable") or "").split()[1:]), values.get("startparameters") or "",
                         values.get("extraparams") or "")
    if any(c in _WWR_SHELL_SYNTAX for c in text):
        return _WWR_SHELL_SAID
    if any(_wwr_pmc_word_moves(w) for w in text.split()):
        return i18n.Sentence("the start parameters choose the world, its folder, or the files that name it "
                             "(--world, --universe, --world-container, --config, --bukkit-settings or --plugins)")
    return None


_WWR_BUKKIT = "serverfiles/bukkit.yml"


def bukkit_problem(text):
    r"""Why bukkit.yml (its text) may move Paper's worlds out of serverfiles, else None.

    Paper reads settings.world-container from it when no --universe is given (its patch of the
    server's Main). The panel does not parse YAML: any mention of world-container outside a
    whole-line comment is refused, and so is any backslash there, since a double-quoted YAML key can
    spell the name with escapes (`"world\x2dcontainer"`).
    """
    body = "\n".join(ln for ln in re.split(r"\r\n|\r|\n", text) if not ln.lstrip(" \t").startswith("#"))
    if "world-container" in body.lower():
        return i18n.Sentence("bukkit.yml sets world-container, which moves the worlds out of serverfiles")
    if "\\" in body:
        return i18n.Sentence("bukkit.yml holds a backslash escape, so whether it sets world-container cannot be read")
    return None


def _wwr_bukkit_check(gs):
    """bukkit.yml's answer for `gs`: None (no world-container; a missing file is Paper's default), or why."""
    content, err = _sm.read_file(gs.remote, gs.short_name, _WWR_BUKKIT)
    if err == _WWR_NO_FILE:
        return None
    if err in _wwr_firm_read_errors():
        return i18n.Sentence("serverfiles/bukkit.yml cannot be used: {error}", error=str(err))
    if err is not None or content is None:
        return Unread("bukkit.yml could not be read: {error}", error=str(err or "no answer"))
    return bukkit_problem(content)


def pmc_plan(gs):
    """The world of Paper server `gs`: (plan, None), or (None, why it is not reset)."""
    return _wwr_java_plan(gs, pmc_start_problem, _wwr_bukkit_check)


# Bedrock's own rule for level-name, from the comment its server.properties carries: "Any string without
# semicolon symbol or symbols illegal for file name: /\n\r\t\f`?*\\<>|\":". `=` is added: the panel does
# not know whether the server splits a line at its first `=` or its last.
_WWR_MCB_BAD = frozenset(";/\\`?*<>|\":=")
_WWR_MCB_KEY = "level-name="
_WWR_MCB_RULES = (
    (lambda n: not n.isascii(), i18n.Sentence("it is not plain ASCII")),
    (lambda n: any(c in _WWR_MCB_BAD for c in n),
     i18n.Sentence("it contains a character Bedrock does not allow in a world name")),
    (lambda n: ".." in n, i18n.Sentence("it contains '..'")),
)


def _wwr_mcb_names(props):
    r"""The names on the plain `level-name=` lines of Bedrock's server.properties: (names, None) or (None, why).

    Lines end at \n (a \r before it is dropped); a line starting with `#` is a comment. A line that
    names level-name in any other form (blanks, case, no `=`) is refused rather than guessed about.
    """
    found = set()
    for line in props.split("\n"):
        line = line[:-1] if line.endswith("\r") else line
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith(_WWR_MCB_KEY):
            found.add(line[len(_WWR_MCB_KEY):])
        elif "level-name" in line.lower():
            return None, i18n.Sentence("a level-name line in server.properties is not in the plain form "
                                       "level-name=<name>")
    return found, None


def bedrock_level_name(props):
    """`level-name` from Bedrock's server.properties text: (name, None), or (None, why).

    The file is key=value lines with `#` comments (Microsoft Learn, "Bedrock Dedicated Server
    Properties"). Only what is certain is read (_wwr_mcb_names): the name is everything after
    `level-name=` at the start of a line. Refused: a level-name line in any other form, two lines
    that differ, no line at all (the panel does not assume the server's default), and a name
    world_name_problem or _WWR_MCB_RULES refuses.
    """
    found, why = _wwr_mcb_names(props)
    if why is None and len(found) != 1:
        why = (i18n.Sentence("server.properties has no level-name line") if not found
               else i18n.Sentence("server.properties sets level-name more than once, to different names"))
    if why is not None:
        return None, why
    name = found.pop()
    why = world_name_problem(name) or next((w for bad, w in _WWR_MCB_RULES if bad(name)), None)
    if why is not None:
        return None, i18n.Sentence("level-name in server.properties is not used: {why}", why=why)
    return name, None


def mcb_start_problem(values):
    """Why the instance's LinuxGSM values may move a Bedrock world, else None.

    bedrock_server reads server.properties and worlds/ in the folder it runs in (executabledir:
    LinuxGSM's default is serverfiles) and has no documented options; LinuxGSM passes none
    (startparameters=""), so any start parameter is one the panel cannot judge.
    """
    if (values.get("executabledir") or "") not in _WWR_MC_EXEDIR:
        return i18n.Sentence("the server does not run in serverfiles (executabledir is not LinuxGSM's default)")
    if (values.get("startparameters") or "").strip() or (values.get("extraparams") or "").strip():
        return i18n.Sentence("the server has start parameters, and Bedrock documents none the panel could judge")
    return None


def mcb_plan(gs):
    """The world of Bedrock server `gs`: (plan, None), or (None, why it is not reset)."""
    values, why = _wwr_values(gs, ["startparameters", "extraparams", "executabledir"])
    why = why or mcb_start_problem(values)
    if why is not None:
        return None, why
    content, why = _wwr_props(gs)
    if content is None:
        return None, why
    name, why = bedrock_level_name(content)
    if name is None:
        return None, why
    return {"dir": "worlds", "remove": [name], "globs": [], "create": None}, None


_WWR_FCTR_NO_SAVE = i18n.Sentence("the start parameters do not name one save the panel knows how to reset")


def _wwr_fctr_start(values):
    """The start option and the word after it, ("--start-server…", next) — or None unless there is exactly one."""
    words = ("%s %s" % (values.get("startparameters") or "", values.get("extraparams") or "")).split() + [""]
    starts = [i for i, w in enumerate(words) if w.startswith("--start-server")]
    if len(starts) != 1 or words[starts[0]] not in _WWR_FCTR_START:
        return None
    return words[starts[0]], words[starts[0] + 1]


def fctr_layout(values):
    """Which save Factorio starts, from the instance's merged LinuxGSM values: (plan, None) or (None, why)."""
    start = _wwr_fctr_start(values)
    if start is None:
        return None, _WWR_FCTR_NO_SAVE
    if (values.get("executabledir") or "") not in _WWR_FCTR_EXEDIR or (values.get("executable") or "") not in _WWR_FCTR_EXE:
        return None, i18n.Sentence("the Factorio executable is not LinuxGSM's default, so the new save "
                                   "cannot be created the way LinuxGSM creates it")
    if start[0] == "--start-server-load-latest":
        return {"dir": "saves", "remove": ["save1.zip"], "globs": ["_autosave*.zip"], "create": "save1"}, None
    if start[0] == "--start-server" and start[1] in _WWR_FCTR_OLD_SAVE:
        return {"dir": "", "remove": ["save1.zip"], "globs": [], "create": "save1"}, None
    return None, _WWR_FCTR_NO_SAVE


def fctr_plan(gs):
    """The world of Factorio server `gs`: (plan, None), or (None, why it is not reset)."""
    values = _sm.lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name,
                                 ["startparameters", "extraparams", "executabledir", "executable"])
    if values is None:
        return None, Unread("the server's LinuxGSM config could not be read")
    if not (values.get("startparameters") or "").strip():
        return None, i18n.Sentence("the server's start parameters are empty")
    return fctr_layout(values)


# game type -> the resolver that finds its world. Only games with a real server to prove them on.
RESOLVERS = {"mc": mc_plan, "fctr": fctr_plan, "pmc": pmc_plan, "mcb": mcb_plan}
GAMES = frozenset(RESOLVERS)


def plan_for(gs):
    """(plan, None) for `gs`'s world, or (None, why). A game with no resolver is refused."""
    resolver = RESOLVERS.get(gs.game_type)
    if resolver is None:
        return None, i18n.Sentence("the panel cannot reset this game's world")
    return resolver(gs)


def _q(s):
    return _sm._quote(s)


def _wwr_head(user, selfname):
    """The lines both scripts open with: C locale, cd /, LinuxGSM's locks, and $s for its tmux socket.

    The locks are LinuxGSM's own (master, 2026-11): lgsm/lock/backup.lock while a backup runs (it calls
    one older than 60 minutes stale), and lgsm/lock/updating.lock holding the PID of a running update,
    validate or workshop update (check_update_lock.sh: stale once that PID is gone).
    """
    home = "/home/%s" % user
    lk = home + "/lgsm/lock"
    return [
        "export LC_ALL=C",
        "cd / || exit 3",
        'if [ -n "$(find %s -mmin -60 2>/dev/null)" ]; then echo %s; exit 4; fi' % (_q(lk + "/backup.lock"), _M_LOCKED),
        'u=$(cat %s 2>/dev/null); case "$u" in ""|*[!0-9]*) ;; *) if kill -0 "$u" 2>/dev/null; then echo %s; exit 4; fi;; '
        'esac' % (_q(lk + "/updating.lock"), _M_LOCKED),
        's=; [ -f {uid} ] && s={sn}-$(cat {uid})'.format(uid=_q("%s/lgsm/data/%s.uid" % (home, selfname)),
                                                         sn=_q(selfname)),
    ]


def _wwr_tmux_up(selfname):
    """The running test LinuxGSM itself uses (check_status.sh): a session named for the script on its socket."""
    return ('[ "$(TERM=screen tmux -L "$s" list-sessions -F "#{session_name}" 2>/dev/null | grep -Ecx %s)" != 0 ]'
            % _q("^" + selfname))


def status_script(user, selfname):
    """One command, as the game account: is a LinuxGSM update or backup running, else is the server up."""
    return "\n".join(_wwr_head(user, selfname) + [
        "if %s; then echo %s; else echo %s; fi" % (_wwr_tmux_up(selfname), _M_UP, _M_DOWN)]) + "\n"


def status_of(out):
    """status_script's answer: "up", "down", "locked", or None when it did not come back."""
    text = terminal.strip_escapes(out or "")
    for mark, state in ((_M_LOCKED, "locked"), (_M_UP, "up"), (_M_DOWN, "down")):
        if re.search("^" + mark, text, re.M):
            return state
    return None


def _wwr_busy_wait(polls):
    """Wait (up to `polls` x 2 s) until no process of the account has its cwd or an open file in serverfiles.

    /proc/<pid> belongs to the process's user, so `[ -O ]` keeps the account's own; the script itself
    (cwd /) is skipped. Still busy at the end: refused, nothing deleted.
    """
    return [
        'busy() { for p in /proc/[0-9]*; do [ -O "$p" ] || continue; [ "${p#/proc/}" = "$$" ] && continue; '
        'c=$(readlink "$p/cwd" 2>/dev/null) || continue; case "$c" in "$sf"|"$sf"/*) return 0;; esac; '
        'for f in "$p"/fd/*; do t=$(readlink "$f" 2>/dev/null) || continue; case "$t" in "$sf"/*) return 0;; esac; '
        'done; done; return 1; }',
        'i=0; while busy; do i=$((i+1)); if [ "$i" -ge %d ]; then echo %s; exit 4; fi; sleep 2; done'
        % (int(polls), _M_BUSY),
    ]


def script(user, selfname, plan, busy_polls=_WWR_BUSY_POLLS):
    """The one command, as the game account, that checks the server is down, deletes the world, creates a new one.

    In order, each refusal before anything is deleted:
    1. a LinuxGSM backup or update of the server is running (its lock files): refuses;
    2. serverfiles is resolved on the host (`cd -P`); unresolvable, or `/`, refuses;
    3. LinuxGSM's own running test (check_status.sh: a tmux session named for the script on its
       socket) finds the server still up: refuses;
    4. a process of the account still has its cwd or a file open in serverfiles after a bounded wait
       (_wwr_busy_wait): refuses;
    5. the save folder (Factorio's saves/) is a symlink: refuses;
    6. each path is collected (the fixed names, and the glob's matches), and one that is a symlink,
       or does not resolve to exactly <folder>/<name>, refuses;
    then each is removed with `rm -rf --` and checked gone; none there at all is "nothing found"
    (no world was reset); and the new save is created.
    """
    home = "/home/%s" % user
    names = " ".join(_q(n) for n in plan["remove"])
    globs = "".join('for g in "$d"/%s; do [ -e "$g" ] || [ -L "$g" ] || continue; set -- "$@" "${g##*/}"; done; ' % g
                    for g in plan["globs"])
    sub = plan["dir"]
    lines = _wwr_head(user, selfname) + [
        'sf=$(cd -P -- %s 2>/dev/null && pwd -P && printf x) && sf=${sf%%?x} || sf=' % _q(home + "/serverfiles"),
        'case "$sf" in ""|/) echo %s; exit 3;; esac' % _M_NOSF,
        "if %s; then echo %s; exit 4; fi" % (_wwr_tmux_up(selfname), _M_RUNNING),
    ] + _wwr_busy_wait(busy_polls) + ['d="$sf"']
    if sub:
        lines += ['if [ -L "$sf/%s" ]; then echo %s; exit 5; fi' % (sub, _M_LINK), 'd="$sf/%s"' % sub]
    lines += [
        "set -- " + names,
        globs + ":",
        'for n in "$@"; do p="$d/$n"; if [ -L "$p" ]; then echo %s; exit 5; fi; [ -e "$p" ] || continue; '
        'r=$(realpath -e -- "$p" 2>/dev/null && printf x) && r=${r%%?x} || r=; '
        'if [ "$r" != "$d/$n" ]; then echo %s; exit 5; fi; done' % (_M_LINK, _M_OUTSIDE),
        'g=0; for n in "$@"; do p="$d/$n"; [ -e "$p" ] || continue; rm -rf -- "$p"; '
        'if [ -e "$p" ] || [ -L "$p" ]; then echo %s; exit 6; fi; g=$((g+1)); echo %s; done' % (_M_RMFAIL, _M_GONE),
        'if [ "$g" = 0 ]; then echo %s; exit 8; fi' % _M_NOTHING,
        "echo " + _M_DELETED,
    ]
    if plan["create"]:
        lines += [
            '[ -d "$d" ] || mkdir -p -- "$d" || { echo %s; exit 7; }' % _M_CREATEFAIL,
            'cd -- "$sf" && "$sf/bin/x64/factorio" --create "$d/%s"; rc=$?' % plan["create"],
            'if [ "$rc" = 0 ] && [ -f "$d/%s.zip" ]; then echo %s; else echo %s; exit 7; fi'
            % (plan["create"], _M_CREATED, _M_CREATEFAIL),
        ]
    return "\n".join(lines) + "\n"


# The script's refusals, each printed before anything is deleted.
_WWR_REFUSALS = (
    (_M_NOSF, i18n.Sentence("the serverfiles folder could not be found")),
    (_M_RUNNING, i18n.Sentence("the server was still running after LinuxGSM's stop")),
    (_M_LINK, i18n.Sentence("part of the world is a symbolic link or outside serverfiles; nothing was deleted")),
    (_M_OUTSIDE, i18n.Sentence("part of the world is a symbolic link or outside serverfiles; nothing was deleted")),
    (_M_LOCKED, i18n.Sentence("a LinuxGSM backup or update of this server is running; nothing was deleted")),
    (_M_BUSY, i18n.Sentence("a process of the game account still had files open in serverfiles a minute after "
                            "the stop; nothing was deleted")),
)


def outcome(out, rc, plan):
    """How the script went: (state, sentence).

    "refused": nothing was deleted (no serverfiles, still running, a symlink or a path outside).
    "failed": a removal, or the new save, failed; some of the world may be gone.
    "done": the world is gone (and the new save made).
    "unread": none of its lines came back (a timeout, a transport that answered "" and did not raise):
    whether it ran is not known.
    """
    text = terminal.strip_escapes(out or "")
    marks = set(re.findall(r"^__WWR_[A-Z]+__", text, re.M))
    gone = len(re.findall(r"^" + _M_GONE, text, re.M))
    refused = next((why for mark, why in _WWR_REFUSALS if mark in marks), None)
    if refused is not None:
        return "refused", refused
    if _M_NOTHING in marks:
        return "refused", i18n.Sentence("no world was found in serverfiles (looked for: {names}); nothing was "
                                        "deleted", names=", ".join(plan["remove"] + plan["globs"]))
    return _wwr_past_checks(text, marks, gone, rc, plan)


def _wwr_past_checks(text, marks, gone, rc, plan):
    """outcome() for a run that refused nothing: failed, unread or done."""
    if _M_RMFAIL in marks:
        return "failed", i18n.Sentence("a world file could not be deleted ({count} removed before it)", count=gone)
    if _M_DELETED not in marks:
        return "unread", i18n.Sentence("the delete's result did not come back (exit {rc}); it may have deleted "
                                       "the world: check the server", rc=rc)
    if plan["create"] and _M_CREATED not in marks:
        return "failed", i18n.Sentence("the world was deleted, but the new save was not created: {last}",
                                       last=_wwr_last_line(text))
    return "done", i18n.Sentence("world deleted ({count} removed)", count=gone)


def _wwr_last_line(text):
    """The host's last line of its own (not one of the script's marks), for a failure's sentence."""
    last = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("__WWR_")]
    return (last[-1] if last else "no output")[:200]
