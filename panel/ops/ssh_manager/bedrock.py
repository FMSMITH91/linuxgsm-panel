"""Minecraft Bedrock's player count, read from the server's own console log.

Bedrock Dedicated Server 1.26 on NetherNet (WebRTC: TCP signalling on server-port, UDP per player)
answers no RakNet unconnected ping, and that ping is the only query gamedig's `mbe` type sends. On
the test host (BDS 1.26.63.1) nothing listens on UDP 19132 at all and `gamedig --type mbe` printed
{"error":"Failed all 2 attempts"}, so every Bedrock server's players read "unknown": the
dashboard, the bots, the backup and restart guards, "wait until empty" and the hourly
restart-when-empty check. LinuxGSM itself gives mcbserver querymode="5" (a TCP connect, no count).

The server writes every join and leave to its console, which LinuxGSM keeps in
log/console/<selfname>-console.log (tmux pipe-pane) and starts afresh on every `start` (it moves
the old one aside, command_start.sh). Each line carries BDS's own prefix:

    [2025-03-01 08:49:08:469 INFO] Player connected: Name, xuid: 2535412345678901
    [2025-03-01 08:52:10:002 INFO] Player disconnected: Name, xuid: 2535412345678901, pfid: ...

("Player Connected: Name, xuid: , pfid: ..." on a server without Xbox sign-in.) So the count is a
passive read: nothing is typed into the console the operator is watching. It is trusted only when
LinuxGSM's own running test sees the session AND the log holds this run's "Server started." line
(a log that was cleared, pruned by LinuxGSM's log cleanup or written with console logging off has
none, and a stale log would otherwise read as nobody on). A connect line that cannot be read makes
the whole count unread rather than one lower. Per player name the tally never drops below zero, so
a leave with no join before it cannot cancel someone else's join.

The tally runs on the host, in one awk pass over at most 256 bytes of each line that grep kept, so
what crosses the network is one short line whatever the log's size. It is ONE shell fragment,
used both by the panel's own reads and inside the hourly restart-when-empty cron line, so the two
cannot count differently.
"""
import re

from panel.ops.ssh_manager import _core  # noqa: E402,F401  (module object: resolves at CALL time)

BEDROCK_GAME = "mcb"
# LinuxGSM's script name for Bedrock: GameServer.lgsm_name is always "<game_type>server".
BEDROCK_SELFNAME = "mcbserver"

# The tally. POSIX awk only (Ubuntu's awk is mawk): no interval expressions, no gawk extensions, no
# `%` (cron reads one as a newline) and no single quote (it is single-quoted in the shell). Prints
# "OK <n>" for a counted run, "N" when this run's start line is missing, "B" when a join line could
# not be read. Lines are cut to 256 bytes before grep, so no line is ever held whole.
BEDROCK_TALLY_AWK = (
    '{sub(/\\r+$/,"");sub(/^NO LOG FILE! - /,"");if(!sub(/^\\[[^]]* INFO\\] /,""))next;d=0}'
    '/^Server started\\.$/{s=1;split("",n);next}'
    '/^Player [Cc]onnected: /{d=1}'
    '/^Player [Dd]isconnected: /{d=-1}'
    'd{r=substr($0,index($0,"onnected: ")+10);j=index(r,", xuid:");'
    'if(j<2||j>81){if(d>0)b=1;next}k=substr(r,1,j-1);if(d>0)n[k]++;else if(n[k]>0)n[k]--}'
    'END{for(k in n)c+=n[k];print(b?"B":s?"OK "c+0:"N")}'
)

# What the panel's own read prints before the tally, so a reply that did not run to it (a dropped
# connection, a refused account) is told from a tally.
_MARK = "mcbp:"
_TALLY_LINE = re.compile(r"mcbp:(?:OK ([0-9]{1,6})|(D)|(N)|(B))\Z")
_PROPS_LINE = re.compile(r"(max-players|server-name|level-name)=([^\r\n]{0,120})\r?\Z")


def is_bedrock(game_type):
    """Whether a server of `game_type` is counted from its console log (LinuxGSM's mcbserver)."""
    return (game_type or "").lower() == BEDROCK_GAME


def bedrock_count_sh(selfname):
    """Shell, run AS the game account in its home, that prints the tally (see BEDROCK_TALLY_AWK) or D.

    D: LinuxGSM's own running test (check_status.sh: a session named for the script on its
    `<selfname>-<uid>` socket, or the bare one of releases before the uid file) sees no server.
    `selfname` must already have passed game_idents_ok: it is a plain word, written unquoted.
    """
    uid = "lgsm/data/%s.uid" % selfname
    return (f"export LC_ALL=C;s={selfname};[ -f {uid} ]&&s={selfname}-$(head -c 40 {uid});"
            f"TERM=screen tmux -L \"$s\" ls -F '#{{session_name}}' 2>/dev/null|grep -Fqx {selfname}"
            "||{ echo D;exit;};"
            f"timeout 20 cut -b 1-256 -- log/console/{selfname}-console.log 2>/dev/null"
            f"|grep -aE 'INFO\\] (Player|Server started)'|awk {_core._quote(BEDROCK_TALLY_AWK)}")


def bedrock_read_sh(user, selfname):
    """The panel's read: the tally line, then server.properties' capacity, name and level."""
    return (f"cd /home/{user} || exit 3; P=$({bedrock_count_sh(selfname)}); echo \"{_MARK}$P\"; "
            "grep -aE '^(max-players|server-name|level-name)=' serverfiles/server.properties "
            "2>/dev/null | head -n 6 | cut -b 1-160")


def _props(lines):
    """{key: value} from server.properties lines (the first of each key), values whitespace-collapsed."""
    got = {}
    for ln in lines:
        m = _PROPS_LINE.match(ln.strip(" \t"))
        if m and m.group(1) not in got:
            got[m.group(1)] = " ".join(m.group(2).split())
    return got


def _capacity(text):
    """max-players as an int, or None when it is not a plain number."""
    return int(text) if text and text.isdecimal() and len(text) <= 6 else None


def _state(line):
    """(state, count) for the tally line: ok/down/unread, or (None, None) when it is not one."""
    m = _TALLY_LINE.match(line)
    if not m:
        return None, None
    if m.group(1) is not None:
        return "ok", int(m.group(1))
    return ("down" if m.group(2) else "unread"), None


def bedrock_slots(server, user, selfname=None):
    """(state, count, max, name, level) for a Bedrock server, from ONE command run as its account.

    state is "ok" (count is the int the log adds up to), "down" (LinuxGSM's running test sees no
    server: no count), "unread" (no start line in the log, or a join line it could not read: the
    caller may still try gamedig, which answers on a RakNet server) or "failed" (refused account,
    transport error, or a reply without the tally: unknown). max, name and level come from
    server.properties when it was read, else None. Never raises.
    """
    selfname = selfname or BEDROCK_SELFNAME
    none = ("failed", None, None, None, None)
    if not _core.game_idents_ok(user, selfname):
        return none
    try:
        out, _, _ = _core.shell_as_game_user(server, user, bedrock_read_sh(user, selfname),
                                             timeout=30, selfname=selfname)
    except Exception:
        return none
    lines = (out or "").splitlines()
    tally = [ln.strip() for ln in lines if ln.strip().startswith(_MARK)]
    state, count = _state(tally[0]) if len(tally) == 1 else (None, None)
    if state is None:
        return none
    props = _props(ln for ln in lines if not ln.strip().startswith(_MARK))
    return (state, count, _capacity(props.get("max-players")),
            props.get("server-name") or None, props.get("level-name"))
