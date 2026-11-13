"""Scheduled world resets for games whose LinuxGSM script has no wipe command (Minecraft Java, Factorio).

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
_M_DELETED = "__WWR_DELETED__"


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
    if name in (".", ".."):
        return i18n.Sentence("it is '.' or '..'")
    if len(name) > _WWR_NAME_MAX:
        return i18n.Sentence("it is longer than {max} characters", max=_WWR_NAME_MAX)
    if "/" in name or "\\" in name:
        return i18n.Sentence("it contains a slash or backslash")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        return i18n.Sentence("it contains a control character")
    if name.startswith("-"):
        return i18n.Sentence("it starts with '-'")
    if name != name.strip():
        return i18n.Sentence("it starts or ends with a blank")
    return None


def level_name(props):
    """`level-name` from server.properties text: (name, None), or (None, why) when it cannot be used.

    Properties syntax: `#`/`!` comment lines, the key ends at the first `=` or `:`, blanks before the
    value are dropped, and the last line for a key wins. A file without the key is Minecraft's
    default, `world`.
    """
    found = None
    for line in props.splitlines():
        s = line.lstrip()
        if not s or s[0] in "#!":
            continue
        m = re.match(r"([^=:]*?)\s*[=:]", s)
        if m and m.group(1).strip() == "level-name":
            found = s[m.end():].lstrip(" \t\f")
    name = "world" if found is None else found
    why = world_name_problem(name)
    return (None, why) if why else (name, None)


def mc_plan(gs):
    """The world of Minecraft Java server `gs`: (plan, None), or (None, why it is not reset)."""
    content, err = _sm.read_file(gs.remote, gs.short_name, _WWR_PROPS)
    if err == _WWR_NO_FILE:
        return None, i18n.Sentence("serverfiles/server.properties is not there, so the world's name is not known")
    if err is not None or content is None:
        return None, Unread("server.properties could not be read: {error}", error=str(err or "no answer"))
    if not content.strip():
        return None, i18n.Sentence("server.properties is empty, so the world's name is not known")
    name, why = level_name(content)
    if name is None:
        return None, i18n.Sentence("level-name in server.properties is not used: {why}", why=why)
    return {"dir": "", "remove": [name, name + "_nether", name + "_the_end"], "globs": [], "create": None}, None


def fctr_layout(values):
    """Which save Factorio starts, from the instance's merged LinuxGSM values: (plan, None) or (None, why)."""
    words = ("%s %s" % (values.get("startparameters") or "", values.get("extraparams") or "")).split()
    starts = [i for i, w in enumerate(words) if w.startswith("--start-server")]
    if len(starts) != 1 or words[starts[0]] not in _WWR_FCTR_START:
        return None, i18n.Sentence("the start parameters do not name one save the panel knows how to reset")
    if (values.get("executabledir") or "") not in _WWR_FCTR_EXEDIR or (values.get("executable") or "") not in _WWR_FCTR_EXE:
        return None, i18n.Sentence("the Factorio executable is not LinuxGSM's default, so the new save "
                                   "cannot be created the way LinuxGSM creates it")
    i = starts[0]
    if words[i] == "--start-server-load-latest":
        return {"dir": "saves", "remove": ["save1.zip"], "globs": ["_autosave*.zip"], "create": "save1"}, None
    if words[i] == "--start-server" and words[i + 1:i + 2] and words[i + 1] in _WWR_FCTR_OLD_SAVE:
        return {"dir": "", "remove": ["save1.zip"], "globs": [], "create": "save1"}, None
    return None, i18n.Sentence("the start parameters do not name one save the panel knows how to reset")


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
RESOLVERS = {"mc": mc_plan, "fctr": fctr_plan}
GAMES = frozenset(RESOLVERS)


def plan_for(gs):
    """(plan, None) for `gs`'s world, or (None, why). A game with no resolver is refused."""
    resolver = RESOLVERS.get(gs.game_type)
    if resolver is None:
        return None, i18n.Sentence("the panel cannot reset this game's world")
    return resolver(gs)


def _q(s):
    return _sm._quote(s)


def script(user, selfname, plan):
    """The one command, as the game account, that checks the server is down, deletes the world, creates a new one.

    In order, each refusal before anything is deleted:
    1. serverfiles is resolved on the host (`cd -P`); unresolvable, or `/`, refuses;
    2. LinuxGSM's own running test (check_status.sh: a tmux session named for the script on its
       socket) finds the server still up: refuses;
    3. the save folder (Factorio's saves/) is a symlink: refuses;
    4. each path is collected (the fixed names, and the glob's matches), and one that is a symlink,
       or does not resolve to exactly <folder>/<name>, refuses;
    then each is removed with `rm -rf --` and checked gone, and the new save is created.
    """
    home = "/home/%s" % user
    names = " ".join(_q(n) for n in plan["remove"])
    globs = "".join('for g in "$d"/%s; do [ -e "$g" ] || [ -L "$g" ] || continue; set -- "$@" "${g##*/}"; done; ' % g
                    for g in plan["globs"])
    sub = plan["dir"]
    lines = [
        "cd / || exit 3",
        'sf=$(cd -P -- %s 2>/dev/null && pwd -P && printf x) && sf=${sf%%?x} || sf=' % _q(home + "/serverfiles"),
        'case "$sf" in ""|/) echo %s; exit 3;; esac' % _M_NOSF,
        's=; [ -f %s ] && s=%s-$(cat %s)' % (_q("%s/lgsm/data/%s.uid" % (home, selfname)), _q(selfname),
                                            _q("%s/lgsm/data/%s.uid" % (home, selfname))),
        'if [ "$(TERM=screen tmux -L "$s" list-sessions -F "#{session_name}" 2>/dev/null | grep -Ecx %s)" != 0 ]; '
        'then echo %s; exit 4; fi' % (_q("^" + selfname), _M_RUNNING),
        'd="$sf"',
    ]
    if sub:
        lines += ['if [ -L "$sf/%s" ]; then echo %s; exit 5; fi' % (sub, _M_LINK), 'd="$sf/%s"' % sub]
    lines += [
        "set -- " + names,
        globs + ":",
        'for n in "$@"; do p="$d/$n"; if [ -L "$p" ]; then echo %s; exit 5; fi; [ -e "$p" ] || continue; '
        'r=$(realpath -e -- "$p" 2>/dev/null && printf x) && r=${r%%?x} || r=; '
        'if [ "$r" != "$d/$n" ]; then echo %s; exit 5; fi; done' % (_M_LINK, _M_OUTSIDE),
        'for n in "$@"; do p="$d/$n"; [ -e "$p" ] || continue; rm -rf -- "$p"; '
        'if [ -e "$p" ] || [ -L "$p" ]; then echo %s; exit 6; fi; echo %s; done' % (_M_RMFAIL, _M_GONE),
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
    if _M_NOSF in marks:
        return "refused", i18n.Sentence("the serverfiles folder could not be found")
    if _M_RUNNING in marks:
        return "refused", i18n.Sentence("the server was still running after LinuxGSM's stop")
    if _M_LINK in marks or _M_OUTSIDE in marks:
        return "refused", i18n.Sentence("part of the world is a symbolic link or outside serverfiles; "
                                        "nothing was deleted")
    if _M_RMFAIL in marks:
        return "failed", i18n.Sentence("a world file could not be deleted ({count} removed before it)", count=gone)
    if _M_DELETED not in marks:
        return "unread", i18n.Sentence("the delete's result did not come back (exit {rc}); it may have deleted "
                                       "the world: check the server", rc=rc)
    if plan["create"] and _M_CREATED not in marks:
        last = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("__WWR_")]
        return "failed", i18n.Sentence("the world was deleted, but the new save was not created: {last}",
                                       last=(last[-1] if last else "no output")[:200])
    return "done", i18n.Sentence("world deleted ({count} removed)", count=gone)
