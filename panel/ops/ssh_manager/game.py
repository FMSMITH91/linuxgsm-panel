"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
from panel.core import terminal
import time
from panel.ops.ssh_manager import (_core, cron, files, portscan)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── Engine families ──────────────────────────────────────────────────────────
# Moderation (kick/ban/say) and the way we read a player list are per game ENGINE, not per game, so
# one classifier covers every LinuxGSM game of a family instead of a per-game table. Source and
# GoldSrc share the SAME console syntax (`status`, `kick "<name>"`, `banid`, `say`) and both print
# SteamIDs in `status`, so they're one "valve" family here. Anything not classified has no console
# moderation — its player list still shows via gamedig where available, just with no kick/ban/say.
_ENG_VALVE = frozenset({
    # Source
    "gmod", "css", "cs2", "csgo", "tf2", "hl2dm", "hl2mp", "dods", "l4d", "l4d2",
    "ins", "insurgency", "nmrih", "zps", "fof", "gesource", "bb2", "ship", "doi", "nd", "bm",
    # GoldSrc
    "cs", "cscz", "tfc", "dmc", "ns", "ricochet", "hldm", "hldms", "ahl", "sfc", "dod", "og", "ag",
})
_ENG_IDTECH3 = frozenset({           # Quake3 / idTech3 — `status` gives slot numbers, kick/ban by slot
    "cod", "coduo", "cod2", "cod4", "codwaw", "q3", "quakelive", "et", "etl", "rtcw", "wet", "jamp",
})
_ENG_MINECRAFT = frozenset({         # Minecraft — `list` gives names, kick/ban by name
    "mc", "pmc", "spigot", "paper", "bukkit", "forge", "fabric", "purpur", "mcbe", "mcb", "pocketmine",
})


def game_engine(game_type):
    """The moderation/query engine family for a LinuxGSM game: 'valve', 'idtech3', 'minecraft',
    or '' when the game has no console-based moderation the panel understands."""
    gt = (game_type or "").lower()
    if gt in _ENG_VALVE:
        return "valve"
    if gt in _ENG_IDTECH3:
        return "idtech3"
    if gt in _ENG_MINECRAFT:
        return "minecraft"
    return ""


# A Steam ID in either legacy (STEAM_0:1:2) or modern ([U:1:5]) form — the only shape we accept as a
# ban target, so a hostile name in a `status` line can never smuggle anything else into `banid`.
_STEAMID_RE = re.compile(r"STEAM_[0-9]:[0-9]:[0-9]+|\[U:[0-9]:[0-9]+\]")


def _strip_q3_colors(s):
    return re.sub(r"\^[0-9]", "", s or "")


def _int_or_none(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def _sanitize_steamid(s):
    m = _STEAMID_RE.search(str(s or ""))
    return m.group(0) if m else ""


def _sanitize_slotnum(s):
    n = _int_or_none(s)
    return n if (n is not None and 0 <= n <= 128) else None


def capture_console(server, user, selfname=None, lines=180):
    """Read-only snapshot of the last `lines` of a LinuxGSM instance's live tmux console. Used to
    read a `status`/`list` reply back. rc 3 + NO_SESSION when the server isn't running.

    -J (join wrapped lines), because capture-pane otherwise returns the pane's VISUAL lines: every
    logical line is hard-wrapped at the pane width, mid-word, and both the console the user reads
    and the parsers below get the fragments. Measured against a live Minecraft server on a test
    host: 49 wrapped lines where there were 33 real ones, every one cut at exactly 80 columns
    ("...All dimensions are s" / "aved").

    The display is the visible half; the parsers are the damaging half. A vanilla `list` reply puts
    every online player on ONE line, so a 12-player server sends 160 characters and the panel
    received two 80-column fragments — _parse_minecraft_list then read ONE player, named "Ali",
    and eleven were gone. That count feeds the Players panel, the empty-server notification and
    reboot-when-empty, and the ids moderation acts on. Five players with ordinary names is enough
    to cross 80 columns."""
    selfname = selfname or user
    inner = _core._tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" capture-pane -p -J -t {selfname} -S -{int(lines)}'
    return _core.shell_as_game_user(server, user, inner, timeout=15, selfname=selfname)


# '#<userid> "<name>"' — the start of a Source/GoldSrc status row. Used to READ a row and, by
# negation, to tell the column header from a row: both carry the word "uniqueid" when a player
# picks the right name, and only one of them starts with a number.
_VALVE_ROW_RE = re.compile(r'\s*#\s*\d+\s+"([^"]*)"')


def _parse_valve_status(text):
    """Parse a Source/GoldSrc `status` reply into [{name, steamid, num, score, time}]. Player rows
    start with '#' and carry a quoted name + a STEAM_/[U:..] id; bots have no id. Only the MOST
    RECENT table is used (rows after the last 'uniqueid' header), so players who left don't linger.

    Both halves of that are things a PLAYER CONTROLS, because their name is on the line:

      * The header scan looked for "uniqueid" anywhere in a line. A player called "my uniqueid"
        made their own row the header, so parsing started after it — naming themselves that and
        sitting at the bottom of the table returned an empty list, and mid-table it hid them AND
        everyone above them. The Players panel goes blank and _resolve_from_console — the only
        source of SteamIDs for a gamedig-sourced list — answers None for everybody. A header is a
        line that is NOT a player row, and that is now what is required.
      * The SteamID was searched for across the WHOLE line, and in a status row the name column
        comes BEFORE the uniqueid column. A persona name of "STEAM_0:1:11111111" won the search,
        so the row carried a SteamID of the player's choosing rather than their own. The admin
        clicks Ban, the browser posts that id back, moderate() re-validates its SHAPE and bans it —
        fleet-wide with scope "all", and into GlobalBan for a superadmin, which re-applies to
        servers added later. An arbitrary third party, permanently, while the attacker stays
        connected. The id is read from the text AFTER the closing quote now, where the column is.
    """
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if "uniqueid" in ln.lower() and not _VALVE_ROW_RE.match(ln):
            start = i + 1
    players, seen = [], set()
    for ln in lines[start:]:
        # A real player row is '#<userid> "<name>" …'. Requiring the leading '#' + number rejects the
        # '# userid name uniqueid' header AND stray chat/console lines that merely contain quotes.
        m = _VALVE_ROW_RE.match(ln)
        if not m:
            continue
        name = m.group(1).strip()
        if not name:
            continue
        steamid = _sanitize_steamid(ln[m.end():])
        key = (name, steamid)
        if key in seen:
            continue
        seen.add(key)
        players.append({"name": name[:64], "steamid": steamid, "num": None,
                        "score": None, "time": None})
    return players


def _parse_idtech3_status(text):
    """Parse a Quake3/CoD `status` reply into [{name, num, guid, steamid, score, time}]. Rows are
    'num score ping guid name … address …'; the name can contain spaces + ^-colour codes. Only the
    most recent table (rows after the last 'num…score…ping' header) is kept."""
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        low = ln.lower()
        # ...and the header is a line that is NOT a player row. Every row begins with the slot
        # number and the header begins with the word "num", so the leading character separates
        # them. Without that, a player called "numscoreping" — twelve characters, well inside a
        # CoD name limit — made their own row the header: last in the table it returned an empty
        # list, mid-table it dropped them and everyone above them, and either way the slot numbers
        # moderation needs came back None for the whole server.
        if "num" in low and "score" in low and "ping" in low and not re.match(r"\s*\d", ln):
            start = i + 1
    players, seen = [], set()
    for ln in lines[start:]:
        # Preferred: name is everything between the guid and the trailing 'lastmsg address' columns.
        m = re.match(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s+\d+\s+\d{1,3}(?:\.\d{1,3}){3}:\d+", ln)
        if not m:
            # Fallback for formats without an address column: num score ping guid name(rest).
            m = re.match(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+([0-9A-Fa-f]{6,})\s+(.+)$", ln)
            if not m:
                continue
        num = _int_or_none(m.group(1))
        if num is None or num in seen:
            continue
        name = _strip_q3_colors(m.group(5)).strip()
        if not name:
            continue
        seen.add(num)
        players.append({"name": name[:64], "num": num, "guid": m.group(4), "steamid": "",
                        "score": _int_or_none(m.group(2)), "time": None})
    return players


# The `list` reply's OWN shape: the count prefix, anchored to the start of the line with nothing
# in front of it but the server's own bracketed log prefix ("[12:34:56] [Server thread/INFO]: ").
# A chat line carries the same prefix and then "<Steve> " or a plugin's tag before the message, so
# it cannot reach "There are". Both vanilla spellings of the count are accepted ("N of a max of M"
# and the older "N/M").
#
# The prefix is peeled off in a loop rather than written as `(?:\[[^\]]*\]\s*)*` inside the
# pattern. That form is a quantifier inside a quantifier, which is what ReDoS scanners look for.
# It happens to be linear — each repetition has to consume a literal `[`…`]`, so it cannot spin on
# an empty match — but this pattern is applied to a line a hostile player can write, and "I read
# the backtracking and it is fine" is a worse argument than not writing the shape at all. Each
# pass below removes at least two characters, so the loop is bounded by the line length.
_MC_LOG_PREFIX_RE = re.compile(r"^\s*\[[^\]]*\]\s*")
_MC_LIST_RE = re.compile(
    r"^:?\s*there are\s+(\d+)\s*(?:of a max of\s+\d+|/\s*\d+)\s+players online:",
    re.IGNORECASE)


def _mc_strip_log_prefix(line):
    """Strip the server's own bracketed log prefixes ('[12:34:56] [Server thread/INFO]: ')."""
    prev = None
    while prev != line:
        prev = line
        line = _MC_LOG_PREFIX_RE.sub("", line, count=1)
    return line.lstrip()


def _parse_minecraft_list(text):
    """Parse a Minecraft `list` reply ('There are N of M players online: Alice, Bob') into
    [{name, …}], or None when the capture holds no `list` reply at all.

    This kept the LAST line containing the bare substring "online:", and that is a line a PLAYER
    WRITES: a Minecraft server logs chat to the same stdout the tmux pane captures, so typing
    "online: Notch" in chat once a second lands an attacker-chosen line after the real reply, and
    the last match wins. The Players panel then showed exactly one connected player under the name
    the attacker picked — hiding everyone actually on, including them — and Kick on that row sent
    the admin's `kick` to that name. The two sibling parsers above were hardened against this same
    class (a player called "my uniqueid"; a player called "numscoreping") and now require a shape a
    chat line cannot forge; this one was the one left on a bare substring.

    And None, not [], when nothing matched. [] here means "confirmed empty", so a server that did
    not answer `list` inside the 0.8s capture window used to read as a server with nobody on it —
    or, with an older reply still in the pane, as the players who were on minutes ago. The count is
    cross-checked against the names for the same reason: a reply that arrived half-written (tmux
    wrapping, a capture taken mid-print) is unknown, never a short player list and never zero."""
    m, line = None, ""
    for ln in (text or "").splitlines():
        body = _mc_strip_log_prefix(ln)
        hit = _MC_LIST_RE.match(body)
        if hit:
            m, line = hit, body
    if m is None:
        return None
    after = line[m.end():]
    players, seen = [], set()
    for chunk in after.split(","):
        nm = re.sub(r"[^A-Za-z0-9_]", "", chunk)[:32]
        if nm and nm not in seen:
            seen.add(nm)
            players.append({"name": nm, "steamid": "", "num": None, "score": None, "time": None})
    if len(players) != int(m.group(1)):
        return None     # a truncated or partial reply is UNKNOWN — not a shorter list, not zero
    return players


def console_player_list(server, user, game_type, selfname=None):
    """Player list from the game's OWN console — the only source that yields the identifiers needed
    to kick/ban precisely (SteamIDs for valve, slot numbers for idTech3). Sends the list command,
    then captures + parses the pane. Returns a list (possibly empty), or None for a non-console
    game. Never raises."""
    eng = game_engine(game_type)
    if not eng:
        return None
    cmd = "list" if eng == "minecraft" else "status"
    # NONE for "could not read", [] only for a table that really had no rows in it. These both
    # answered [], and player_list's `or []` then turned a stopped server into a confirmed-empty
    # one: the bot's /players said "no players connected" about a server that was down. Its own
    # docstring already draws the distinction ("an empty list for a confirmed-empty server, or
    # None when it can't be read"); only the code did not.
    try:
        # The SEND's status, not just the capture's. send_console_command returns (out, err, rc)
        # like every other call here and rc is meaningful (3 + NO_SESSION for no live tmux session,
        # non-zero when `sudo -u` or the transport failed) — it was thrown away. On the tailscale
        # and local transports a failed send does not RAISE (_run_via_ssh_cli returns
        # ("", "SSH command timed out", -1)), so the `except` below never saw one; and the capture
        # is a SEPARATE round trip 0.8s later, which can perfectly well succeed after the send
        # failed. What came back then was whatever the pane already held — a PREVIOUS `status`
        # table — parsed and returned as the answer to a question the server was never asked:
        # players who had already disconnected, with their SteamIDs, on rows whose Ban fans out
        # fleet-wide and into GlobalBan. Same idiom moderate() and console_steamid_ban() use.
        _sent = _core.send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        if (_sent[2] if isinstance(_sent, tuple) and len(_sent) >= 3 else 1) != 0:
            return None
        time.sleep(0.8)   # let the server print its reply into the pane before we capture it
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return None
    if rc != 0 or not out or "NO_SESSION" in out:
        return None
    if eng == "idtech3":
        return _parse_idtech3_status(out)
    if eng == "minecraft":
        return _parse_minecraft_list(out)
    return _parse_valve_status(out)


_HOSTNAME_RE = re.compile(r"^\s*(?:hostname|sv_hostname)\s*:?\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)


def console_status(server, user, game_type, selfname=None):
    """One console `status`/`list` capture → (players, name): the parsed player list AND the server's
    advertised in-game name (the valve/idTech3 `hostname:` line), from a SINGLE round-trip. Used by
    the background poller so a server gamedig can't query (e.g. no GSLT) isn't hit with two separate
    `status` sends per pass — which would spam the very console an admin is watching.

    Returns (None, None) for a non-console game or on failure — NOT ([], None). An empty list is
    "confirmed empty", and this returned it for a send that never arrived, a capture that failed
    and a game with no console at all, which is the same conflation console_player_list's contract
    exists to avoid. Never raises."""
    eng = game_engine(game_type)
    if not eng:
        return None, None
    cmd = "list" if eng == "minecraft" else "status"
    try:
        # The send's status too — see console_player_list above for what dropping it cost: the
        # capture is a separate round trip and succeeds happily after a send that never landed,
        # so the pane's PREVIOUS table was returned as the current one.
        _sent = _core.send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        if (_sent[2] if isinstance(_sent, tuple) and len(_sent) >= 3 else 1) != 0:
            return None, None
        time.sleep(0.8)   # let the server print its reply into the pane
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return None, None
    if rc != 0 or not out:
        return None, None
    if eng == "idtech3":
        players = _parse_idtech3_status(out)
    elif eng == "minecraft":
        players = _parse_minecraft_list(out)
    else:
        players = _parse_valve_status(out)
    name = None
    if eng in ("valve", "idtech3"):
        m = _HOSTNAME_RE.search(out)
        if m:
            name = " ".join(_strip_q3_colors(m.group(1)).split())[:120] or None
    return players, name


def _gamedig_player_list(server, user, game_type=None, port=None, query_type=None):
    """Player list via gamedig — the PRIMARY source. Returns a list ([{name, …}], possibly empty
    for a confirmed-empty server) when gamedig could query the game, or None when it couldn't (no
    gamedig type, no port, or the query failed) so the caller can fall back to the console. Never
    raises. Names carry score/time where the game reports them; no kick/ban ids (those come from the
    console on demand)."""
    if not _core.game_idents_ok(user):
        return None      # refused, which is "could not query" — never an empty server
    gdtype = cron._gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None
    # Player fields are protocol-specific in gamedig: Source/valve exposes score + time (seconds
    # connected); Quake3/idTech3 (cod) exposes `frags` and no time. Pull score from score OR frags
    # so cod shows a score too; time stays null where the game doesn't report it.
    jqf = ('[.players[] | {name:(.name // ""), '
           'score:(.raw.score // .score // .raw.frags // .frags // null), '
           'time:(.raw.time // .time // null)}]')
    cmd = f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null | jq -c {_core._quote(jqf)} 2>/dev/null"
    try:
        out, _, _ = _core.shell_as_game_user(server, user, cmd, timeout=25)
    except Exception:
        return None
    line = next((ln.strip() for ln in (out or "").splitlines() if ln.strip().startswith("[")), "")
    if not line:
        return None
    try:
        import json as _json
        data = _json.loads(line)
    except (ValueError, TypeError):
        return None
    players = []
    for p in (data if isinstance(data, list) else []):
        if isinstance(p, dict):
            name = str(p.get("name") or "").strip()
            if name:
                players.append({"name": name[:64], "steamid": "", "num": None,
                                "score": p.get("score"), "time": p.get("time")})
    return players


def player_list(server, user, game_type=None, port=None, query_type=None, selfname=None,
                allow_console=False):
    """Connected players for the Players panel. gamedig is the PRIMARY source (names + score/time,
    and it never touches the game console). The game's own console (`status`/`list`) is only used
    when gamedig can't query the game AND the caller explicitly opts in with allow_console=True —
    so a background/timer poll never issues a console command; only an on-demand user action does.
    Returns [{name, steamid, num, score, time}] (steamid/num set only when the list came from the
    console), an empty list for a confirmed-empty server, or None when it can't be read over the
    network and the console wasn't allowed. Never raises."""
    pl = _gamedig_player_list(server, user, game_type, port, query_type)
    if pl is not None:
        return pl                       # gamedig answered (players, or a confirmed-empty server)
    if allow_console and game_engine(game_type):   # explicit, on-demand console read only
        # No `or []`: None here means the console could not be read, which is not the same
        # answer as "nobody is playing" and is the distinction this function's contract turns on.
        return console_player_list(server, user, game_type, selfname=selfname)
    return None                         # can't read over the network; console not requested


def is_player_queryable(game_type, query_type=None):
    """True if the panel can show a live player list: a console engine (valve/idTech3/Minecraft)
    or a gamedig type (built-in map or a per-server override)."""
    return bool(game_engine(game_type)) or bool(cron._gamedig_type(game_type, query_type))


# Bedrock Dedicated Server's console has NO `ban` command. Banning on Bedrock is the allowlist
# (`allowlist add/remove`, renamed from `whitelist` in 1.18.10); `/ban` is Java-only. PocketMine
# does implement `ban`, so it is deliberately not in here.
_MC_NO_BAN = frozenset({"mcbe", "mcb"})


def moderation_caps(game_type):
    """Which moderation actions this game's console supports: {kick, ban, say}. Driven by the engine
    family, so every game of a family is covered. Non-console games get nothing (view-only).

    `ban` is dropped for Bedrock: _ENG_MINECRAFT covers mcbe/mcb alongside the Java families, so
    this answered ban=True for a console with no ban command, the detail page rendered the button,
    and sending `ban <name>` into the pane got "Unknown command" while tmux send-keys exited 0 —
    "Done.", a success audit row, and the griefer still connected."""
    if game_engine(game_type):      # valve, idtech3 and minecraft all support kick + say
        return {"kick": True, "ban": (game_type or "").lower() not in _MC_NO_BAN, "say": True}
    return {"kick": False, "ban": False, "say": False}


# SECURITY: player names come FROM the game, so a hostile player can set a name containing console
# metacharacters. ';' chains commands (Source), quotes/backticks break arg parsing, and CR/LF would
# inject a whole new console line — strip them before the name/message goes into a console command.
_MOD_BAD_CHARS = str.maketrans({c: None for c in ';"`\r\n\t\x00'})


def _mod_sanitize(s, maxlen=64):
    return str(s or "").translate(_MOD_BAD_CHARS).strip()[:maxlen]


def _resolve_from_console(server, user, game_type, name, selfname):
    """Find a player by name in the game's console list and return their {name, num, steamid, …}.
    Used to resolve the kick/ban identifier (slot number / SteamID) when the list on screen came
    from gamedig, which doesn't carry those ids. Matches on the colour-code-stripped name; returns
    None if not found. Only runs when someone actually clicks kick/ban — no continuous polling."""
    want = _strip_q3_colors(name or "").strip()
    if not want:
        return None
    for p in (console_player_list(server, user, game_type, selfname=selfname) or []):
        if _strip_q3_colors(p.get("name") or "").strip() == want:
            return p
    return None


def moderate(server, user, game_type, action, target="", message="", selfname=None,
             steamid="", num=""):
    """Kick/ban a player or announce a message through the game's own console, dispatched by engine:
      • valve (Source/GoldSrc): kick by name, ban by SteamID, say
      • idTech3 (CoD/Quake3):   kick/ban by slot number, say
      • minecraft:              kick/ban by name, say
    Names/messages are sanitized (and the SteamID/slot re-validated) so a hostile name can't inject
    a console command. Returns (ok, msg)."""
    eng = game_engine(game_type)
    if action not in ("kick", "ban", "say") or not moderation_caps(game_type).get(action):
        # Bedrock gets its own reason, because "isn't supported" is not actionable: BDS has no ban
        # command at all (see _MC_NO_BAN), and banning there is the allowlist. Until moderation_caps
        # dropped it, this fell through to the minecraft branch, sent `ban <name>` into the pane,
        # and `tmux send-keys` exited 0 for a command the game answered with "Unknown command" — so
        # the panel flashed "Done.", wrote a success audit row, counted the Bedrock servers in
        # "Also banned on N other servers", and the griefer reconnected immediately. Same reasoning
        # as the space-in-name refusal further down: a ban that silently does nothing is worse than
        # a button that says why it stopped.
        if action == "ban" and eng == "minecraft" and (game_type or "").lower() in _MC_NO_BAN:
            return False, ("Bedrock servers have no ban command — remove the player from the "
                           "server's allowlist instead.")
        return False, "That action isn't supported for this game."

    if action == "say":
        msg = _mod_sanitize(message, 200)
        if not msg:
            return False, "Nothing to announce."
        cmd = "say %s" % msg
    elif eng == "valve":
        if action == "kick":
            nm = _mod_sanitize(target, 64)
            if not nm:
                return False, "No player selected."
            cmd = 'kick "%s"' % nm
        else:
            sid = _sanitize_steamid(steamid)
            if not sid:      # list came from gamedig (no SteamID) — resolve it on the console now
                p = _resolve_from_console(server, user, game_type, target, selfname)
                sid = _sanitize_steamid(p.get("steamid")) if p else ""
            if not sid:
                return False, "Couldn't find that player's SteamID to ban them."
            # banid <0=permanent> <id> kick — the `kick` keyword boots them if they're connected
            # right now (banid without it only blocks future joins); writeid persists to the ban file.
            cmd = "banid 0 %s kick; writeid" % sid
    elif eng == "idtech3":
        slot = _sanitize_slotnum(num)
        if slot is None:     # list came from gamedig (no slot number) — resolve it on the console now
            p = _resolve_from_console(server, user, game_type, target, selfname)
            slot = _sanitize_slotnum(p.get("num")) if p else None
        if slot is None:
            return False, "Couldn't find that player on the server."
        cmd = "%s %d" % ("clientkick" if action == "kick" else "banclient", slot)
    elif eng == "minecraft":
        nm = _mod_sanitize(target, 64)
        if not nm:
            return False, "No player selected."
        # `kick <player> [reason]` — the name and the reason are separated by a SPACE, and
        # _MOD_BAD_CHARS does not strip one. That is right for Source and idTech3, whose consoles
        # separate on ';' and newline only, and wrong here: _ENG_MINECRAFT covers mcbe/mcb/
        # pocketmine, Bedrock gamertags may contain spaces, and a gamedig-sourced list carries the
        # raw name (only _parse_minecraft_list sanitises, and that is the console path). So a
        # player named "<someone else> griefing" sends the admin's kick to that someone else.
        # There is no quoting that is correct across Java, Bedrock and PocketMine, so this refuses
        # rather than guessing — a misdirected ban is worse than a button that says why it stopped.
        if re.search(r"\s", nm):
            return False, ("That player's name contains a space, which this game's console reads "
                           "as the start of the reason — kick or ban them from the server "
                           "console directly.")
        cmd = "%s %s" % ("kick" if action == "kick" else "ban", nm)
    else:
        return False, "That action isn't supported for this game."

    out = _core.send_console_command(server, user, cmd, timeout=15, selfname=selfname)
    rc = out[2] if isinstance(out, tuple) and len(out) >= 3 else 1
    return (rc == 0), ("Done." if rc == 0 else "Console not reachable — is the server running?")


def console_steamid_ban(server, user, selfname, steamid, unban=False):
    """Ban (or unban) a SteamID on ONE Source/GoldSrc server via its console — `banid 0 <id>; writeid`
    to ban, `removeid <id>; writeid` to lift, using the game's native persistent ban list. The
    SteamID is re-validated to STEAM_x:y:z / [U:x:y] so nothing injectable reaches the console.
    Only affects a RUNNING server (needs a live console). (ok, reason) where reason is a fixed word:
    'banned' / 'unbanned' / 'invalid' / 'offline' / 'failed'."""
    sid = _sanitize_steamid(steamid)
    if not sid:
        return False, "invalid"
    # the `kick` keyword boots a connected player too (banid alone only blocks future joins); unban lifts it
    cmd = ("removeid %s; writeid" % sid) if unban else ("banid 0 %s kick; writeid" % sid)
    out = _core.send_console_command(server, user, cmd, timeout=15, selfname=selfname)
    rc = out[2] if isinstance(out, tuple) and len(out) >= 3 else 1
    if rc == 3:
        return False, "offline"
    return (rc == 0), ("unbanned" if unban and rc == 0 else "banned" if rc == 0 else "failed")


def ensure_persistent_bans(server, user, selfname):
    """Make a Source server RELOAD its ban list on every (re)start. `banid`/`writeid` persist a
    SteamID ban to cfg/banned_user.cfg, but the engine only loads that file if the server config
    execs it — without the exec line a ban is silently lost on the next map change / restart and the
    player can rejoin (exactly what bit us: a flapping server dropped every ban). Append the exec
    lines to the LinuxGSM servercfg (`${selfname}.cfg` in the game's cfg dir), idempotently. Best-
    effort; returns True when the line is present/added, False on any failure or non-Source layout."""
    try:
        _vals = files.lgsm_get_values(server, user, selfname, ["servercfg"])
        if _vals is None:
            return False     # config unreadable: do not guess a filename and append to it
        raw = (_vals.get("servercfg") or "").strip()
        fname = (raw.replace("${selfname}", selfname).replace("$selfname", selfname)
                 or "%s.cfg" % selfname)
        if not re.match(r"^[A-Za-z0-9_.-]+\.cfg\Z", fname):     # guard the value going into `find`
            fname = "%s.cfg" % selfname
        inner = (
            f"F=$(find ~/serverfiles -maxdepth 4 -path '*/cfg/{fname}' 2>/dev/null | head -1); "
            '[ -z "$F" ] && exit 1; '
            'grep -qiE "^[[:space:]]*exec[[:space:]]+banned_user" "$F" && exit 0; '
            'printf "\\n// panel: load persistent bans on every (re)start\\n'
            'exec banned_user.cfg\\nexec banned_ip.cfg\\n" >> "$F"'
        )
        _, _, rc = _core.shell_as_game_user(server, user, inner, timeout=15, selfname=selfname)
        return rc == 0
    except Exception:
        return False


def mod_restart_decision(status, players, force=False):
    """Decide how to handle the restart a mod change needs, given the server `status`
    ('online'/'offline'/'unresponsive'/'unknown'), the current player count (int, or None when
    unknown), and whether the admin forced it. Pure/side-effect-free so it can be tested directly:
      'idle'    — server is stopped; nothing to do (the change loads on next start)
      'restart' — restart now (server is confirmed empty, or the admin forced it)
      'pending' — defer: players are online, or we can't confirm it's empty.

    Only a status of 'offline' is idle, and only STOPPED means offline. 'unresponsive' — a
    session running but not serving — falls through to 'pending' and keeps the request queued,
    because clearing it would throw away something the operator asked for without doing it."""
    if status == "offline":
        return "idle"
    if force:
        return "restart"
    if status == "online" and players == 0:
        return "restart"
    return "pending"


def _stale_backup_lock_sweep(user, home=None):
    """The shell that clears an ORPHANED backup.lock before a backup starts, run as the game user.

    LinuxGSM writes the lock once, at the start, so its mtime is the backup's start time — and a
    lock older than five minutes was deleted on the strength of a comment saying the panel "only
    ever runs one game backup at a time (serialised by a lock in app.py)". Neither half held. The
    lock that exists is _full_backup_lock in panel/core/panel_state.py, and it covers only the
    panel's scheduled and manual backup runners: the control bar's and the chat bots' `backup`
    maintenance action runs LinuxGSM's backup directly, outside it, and so does a host cron or an
    operator in the terminal. Any of those still archiving after five minutes had its lock deleted
    and a second backup of the same server started beside it.

    So an old lock is orphaned only when no `tar` is running as this user: LinuxGSM's backup is a
    tar of the install, and a game server runs none of its own. The match is on the process NAME
    (-x), never the command line — this snippet's own `bash -c` line contains the word `backup`,
    and a -f match would always find itself and never clear a stale lock again. `home` exists for
    the test; the panel always passes the account's own."""
    home = home or "/home/%s" % user
    return (f"pgrep -u {user} -x tar >/dev/null 2>&1 || "
            f"find {home} -maxdepth 4 -name '*backup.lock' -mmin +5 -delete 2>/dev/null; ")


def run_game_backup(server, user, selfname=None, keep=3, game_type=None, port=None, force=False,
                    query_type=None):
    """Run LinuxGSM's own `backup` for a game instance (archives serverfiles into
    ~/lgsm/backup/), then prune to the newest `keep`. Runs AS THE GAME USER, non-interactively
    (like a cron backup). Long-running — archives can be large.

    LinuxGSM's `backup` STOPS a running server for the duration, which disconnects
    anyone playing. So unless `force=True`, we first check the live player count and,
    if anyone is on, SKIP rather than kick them. Returns (ok, message, skipped):
      - (True, note, False)   backup completed
      - (False, reason, False) backup attempted but failed
      - (False, "N player(s) online …", True) skipped because players were connected
    An unknown/unqueryable player count (None) is treated as empty, so games gamedig
    can't query still back up on schedule (matching the daily-restart behaviour) —
    which is exactly why `query_type` has to be threaded in (see below)."""
    selfname = selfname or user
    # Refused before the player query, the headroom prune and the listing, which would otherwise
    # each reach the host first: the backup itself is refused by shell_as_game_user anyway.
    if not _core.game_idents_ok(user, selfname):
        return False, _core.GAME_ACCOUNT_REFUSED[1], False
    keep = max(1, int(keep))
    if not force:
        # query_type, like every other player/version read in this file (_gamedig_player_list,
        # _queried_version, is_player_queryable) and like the on-screen count in server_detail.
        # This one call — the only one that decides whether to disconnect people — dropped it, so
        # player_count resolved the gamedig type from the 26-entry built-in map ALONE. A game the
        # map does not cover (Project Zomboid, ARK, Mordhau, Killing Floor) whose operator set the
        # per-server override precisely so the panel could query it resolved to "", answered None,
        # and the rule above reads None as empty — so the hourly ticker ran LinuxGSM's `backup`,
        # which STOPS the server, and disconnected everyone on it. The override exists for exactly
        # the servers this guard was blind on.
        pc = cron.player_count(server, user, game_type, port, query_type)
        if pc is not None and pc > 0:
            return (False,
                    f"{pc} player(s) online — backup skipped so nobody gets disconnected",
                    True)
    # Smart retention: if the disk is nearly full, delete old backups BEFORE creating the new one
    # so the backup succeeds instead of aborting for lack of space.
    headroom_note = cron._ensure_backup_headroom(server, user, keep)
    # Pre-flight space check: if there STILL isn't room for the archive after freeing what we can,
    # don't even start LinuxGSM's backup. A backup that runs out of space mid-write half-fills the
    # disk with a partial archive and can leave a stale lock behind — far worse than not starting.
    # We estimate the next archive from the largest existing one; with none to go by we let it try.
    try:
        # `or []`: this is only the ESTIMATE, and an unreadable listing means no estimate —
        # which the `_est and _total` guard below already treats as "let it try". It must
        # not BLOCK a backup, for the same reason a failed df must not.
        _bks = cron.list_game_backups(server, user) or []
        _est = max((b.get("size", 0) for b in _bks), default=0)
        _disk = cron.backup_disk_info(server, user)
        _free, _total = _disk.get("free", 0), _disk.get("total", 0)
        # Only enforce when we actually read the disk (total > 0); a failed df reads as 0/0 and must
        # NOT block an otherwise-fine backup.
        if _est and _total and _free < int(_est * 1.05):
            note = " after clearing what old backups it could" if headroom_note else ""
            return (False,
                    f"Not enough disk space to back up{note}: the archive needs about "
                    f"{cron._fmt_size(int(_est * 1.05))} but only {cron._fmt_size(_free)} is free on the host. "
                    f"Lower this server's 'keep' count, remove old backups, or free space on the disk.",
                    False)
    except Exception:
        _core._log.debug("backup pre-flight space check failed", exc_info=True)
    # A crashed/killed/timed-out earlier backup can leave LinuxGSM's backup.lock behind, after
    # which every backup refuses with "Lockfile found: Backup is currently running". See
    # _stale_backup_lock_sweep for when a lock counts as orphaned.
    precheck = _stale_backup_lock_sweep(user)
    # When the instance is running, LinuxGSM's `backup` warns + counts down, then STOPS the
    # server, archives it, and RESTARTS it (verified on a live box: ~1.5 min outage for a 6.5G
    # GMod install). It doesn't strictly need a y/N answer, but we feed a few harmless "y"s as a
    # safety net for any version that does prompt. The stream is bounded, so it can't hang.
    inner = precheck + f"cd /home/{user} && printf 'y\\ny\\ny\\n' | ./{selfname} backup"
    out, err, rc = _core.shell_as_game_user(server, user, inner, timeout=3600, selfname=selfname)
    ok = rc == 0
    # LinuxGSM can exit 0 while REFUSING to back up because a (possibly stale) lock exists —
    # "Lockfile found: Backup is currently running". No archive is created, so this is NOT a
    # success; reporting it as one is what makes the UI show "✓ Backed up" with no actual backup.
    _blob = ((out or "") + " " + (err or "")).lower()
    lock_refused = "lockfile found" in _blob or "backup is currently running" in _blob
    if lock_refused:
        ok = False
    try:
        cron.prune_game_backups(server, user, keep)
    except Exception:
        _core._log.debug("game backup prune failed", exc_info=True)
    if ok:
        return True, ("Backed up — " + headroom_note if headroom_note else "Backed up"), False
    if lock_refused:
        return False, ("A backup lock was in the way — a previous backup may still be running, or it "
                       "left a stale lock. Try again in a minute."), False
    # Surface the most relevant LinuxGSM line so the panel can show WHY it failed.
    clean = terminal.strip_escapes(((out or "") + "\n" + (err or ""))).strip()
    reason = ""
    for line in reversed(clean.splitlines()):
        low = line.lower()
        if any(k in low for k in ("fail", "error", "unable", "no space", "not enough", "denied", "cannot")):
            reason = line.strip()
            break
    if not reason and clean.splitlines():
        reason = clean.splitlines()[-1].strip()
    return False, (reason or "backup failed")[-200:], False


def list_server_commands(server, user, selfname=None):
    """Run the LinuxGSM instance script with no arguments to read its command list,
    which varies per game. Returns a list of {"cmd", "short", "desc"} dicts."""
    selfname = selfname or user
    out, err, _ = _core.shell_as_game_user(server, user, f"cd /home/{user} && ./{selfname}",
                                           timeout=30, selfname=selfname)
    text = terminal.strip_escapes((out or "") + "\n" + (err or ""))
    cmds, seen = [], set()
    for line in text.splitlines():
        # "start         st   | Start the server."
        m = re.match(r"^\s*([a-z][a-z0-9-]*)\s+([a-z]{1,4})\s+\|\s+(.+?)\s*$", line)
        if m:
            cmd, short, desc = m.group(1), m.group(2), m.group(3)
            if cmd not in seen:
                seen.add(cmd)
                cmds.append({"cmd": cmd, "short": short, "desc": desc})
    return cmds




# Port descriptions we DON'T open by default — only the ports players actually need
# to connect should be exposed. 'Client' is outbound (nothing listens). SourceTV is
# an optional spectator relay. RCON/telnet is remote admin and a security risk to
# expose to the internet (and on Source it rides the game port anyway). Users can
# still open any of these manually from the firewall page if they want them.
_NONESSENTIAL_PORT_DESCS = ("client", "sourcetv", "source tv", "rcon", "telnet")


def detect_game_ports(server, user, selfname=None):
    """Parse LinuxGSM `details` for a server's ports and decide which to open.

    We open only what a player needs to reach the server: the Game port and, if the
    game lists a separate Query port (for server-browser visibility). Optional/admin/
    outbound ports (SourceTV, RCON/telnet, Client) are deliberately left CLOSED — e.g.
    Garry's Mod lists Game 27015 + SourceTV 27020, but only 27015 is needed. Returns:
      {"game_port": int|None, "open_ports": [ports to open], "ports": [all parsed]}.
    """
    out, _, _ = _core.run_as_game_user(server, user, "details", timeout=45, selfname=selfname)
    text = terminal.strip_escapes(out or "")
    ports, game_port, in_table = [], None, False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"DESCRIPTION\s+PORT\s+PROTOCOL", s, re.I):
            in_table = True
            continue
        if in_table:
            m = re.match(r"([A-Za-z][A-Za-z0-9/+ .-]*?)\s+(\d{2,5})\s+(tcp|udp|both|raw)\b", s, re.I)
            if m:
                desc, port, proto = m.group(1).strip(), int(m.group(2)), m.group(3).lower()
                ports.append({"desc": desc, "port": port, "protocol": proto})
                if game_port is None and desc.lower().startswith("game"):
                    game_port = port
            else:
                in_table = False  # blank/other line → table ended
    # Open only the essential inbound ports: Game + Query. Everything else (SourceTV,
    # RCON, Client, …) is left closed so we don't expose more than the game needs.
    open_ports = sorted({
        p["port"] for p in ports
        if not p["desc"].lower().startswith(_NONESSENTIAL_PORT_DESCS)
        and (p["desc"].lower().startswith(("game", "query")))
    })
    if game_port is None:
        m = re.search(r"(?:server|internet)\s+ip:.*?:(\d{2,5})", text, re.I)
        game_port = int(m.group(1)) if m else (open_ports[0] if open_ports else None)
    # Always ensure the game port itself is opened, even if the details table used an
    # unexpected description for it.
    if game_port and game_port not in open_ports:
        open_ports = sorted(set(open_ports) | {game_port})
    return {"game_port": game_port, "open_ports": open_ports, "ports": ports}


def get_server_status(server, game_server, distinguish_unresponsive=False):
    """Get the status of a LinuxGSM game server: 'online', 'offline' or 'unknown'.

    LinuxGSM has no `status` command; `details` prints a "Status: STARTED/STOPPED"
    line, so we run that and parse it.

    STARTED is a weaker claim than it reads. LinuxGSM's check is "is there a tmux session
    with this name" (check_status.sh counts `tmux list-sessions`), and for most of the games
    here what runs inside that session is a WRAPPER — srcds_run, hlds_run, the Java launcher
    — which outlives the game binary and relaunches it in a loop. A server that crashed, or
    one whose config stops it booting at all, therefore reports STARTED indefinitely while
    nobody can connect to it. Seen on the test box: the tmux session and `./srcds_run` alive,
    no game process, `details` cheerfully STARTED.

    So STARTED is confirmed against the only signal that means what a player means by online:
    is the server's port actually listening. That is already what /api/servers and the monitor
    report from, so this makes the panel's answers agree instead of the detail page
    contradicting the dashboard and overwriting it in the database.

    Two things this deliberately does NOT do:

      * downgrade on a failed scan. _remote_listening_ports answers None when it could not
        read the host, and None is not "nothing is listening" — see empty-is-not-a-measurement.
      * downgrade a server with no port on record. There is nothing to confirm against, so
        LinuxGSM's answer stands.

    STOPPED is left authoritative as it always was: no session means no server, whatever else
    happens to be holding the port.

    `distinguish_unresponsive` separates the two things this otherwise folds into "offline":
    STOPPED, where nothing is running at all, and STARTED-but-not-serving, where a session is
    very much running. Callers that only care whether players can connect want them folded, and
    get that by default. A caller deciding whether there is anything to act ON must not: the
    deferred restart/stop sweep read "offline" as "already stopped", cleared the operator's
    queued request and did nothing — so a "stop when empty" issued against a crashed server (the
    exact state this port check was added to detect) was silently dropped, as was one that
    happened to land in the seconds between a restart and the port binding."""
    out, err, rc = _core.run_as_game_user(
        server, game_server.short_name, "details", timeout=30,
        selfname=game_server.lgsm_name,
    )
    text = (out or "") + "\n" + (err or "")
    # Strip ANSI color codes, then read the "Status:" line specifically. (Scanning
    # the whole blob is unsafe: the details output includes a query-check URL
    # containing "ismygameserver.online", which collides with a naive "online" check.)
    clean = terminal.strip_escapes(text)
    for line in clean.splitlines():
        low = line.lower()
        if "status:" in low:
            if "started" in low:
                if _really_serving(server, game_server):
                    return "online"
                # A session IS running; it is just not serving anyone. For most callers that is
                # the same thing as offline and always has been. For a caller deciding whether
                # there is something to ACT on it is not: see distinguish_unresponsive.
                return "unresponsive" if distinguish_unresponsive else "offline"
            if "stopped" in low:
                return "offline"
    return "unknown"


def _really_serving(server, game_server):
    """Is the game's own port listening on the host? True unless we can prove otherwise.

    Split out from get_server_status so the cross-check has one place to be stubbed and
    tested. Returns True for "we could not tell" as well as for "yes", because the caller
    uses it to DOWNGRADE LinuxGSM's answer and an unreadable host must never do that."""
    port = getattr(game_server, "port", None)
    if not port:
        return True
    try:
        ports = portscan._remote_listening_ports(server)
    except Exception:
        return True
    if ports is None:          # the scan failed; that is not an empty set
        return True
    return port in ports


# ── Which build of the game is actually installed ─────────────────────────────────────────────
# Two independent answers, because no single one covers the games this panel manages:
#
#   ON DISK   SteamCMD records the installed build in serverfiles/steamapps/appmanifest_<appid>.acf
#             — the same "buildid" LinuxGSM's own `update` compares against Steam. It is a build
#             number rather than a marketing version, but it is exact, it is there whether or not
#             the server is running, and it moves every time an update lands.
#
#   REPORTED  The running game answers a query with the version string players see (Source's
#             A2S_INFO, idTech3's getstatus \shortversion\, Minecraft's handshake). That is the
#             friendlier number, and for the NON-SteamCMD games — the whole Call of Duty family,
#             which has no `update` command at all — it is the only one that exists.
#
# So read both, prefer the reported string for display, and keep the build alongside it. Neither
# read is on a render path: the detail page fetches this once, asynchronously, after it has drawn.
_version_cache = _core.register_remote_cache({})
_VERSION_TTL = 600        # a build only changes when an update runs, and that invalidates it anyway


def _steam_build(server, user, selfname=None):
    """{appid, build, updated} from the SteamCMD app manifest on disk, or {} for a game that has
    none (non-Steam games, or files not downloaded yet). One SSH round trip. Never raises.

    The appid comes from LinuxGSM's own config rather than from whichever manifest happens to
    sort first: serverfiles/steamapps/ can hold several (a game plus a dependency), and picking
    the wrong one reports a build number that never moves when the game updates."""
    selfname = selfname or user
    sh = (
        f"cd /home/{user} 2>/dev/null || exit 0; "
        # appid="740" in _default.cfg (quoted or not) — keep only the digits.
        f"a=$(grep -hoE '^[[:space:]]*appid=[\"'\"'\"']?[0-9]+' "
        f"lgsm/config-lgsm/{selfname}/_default.cfg 2>/dev/null | head -1 | tr -dc 0-9); "
        "m=\"\"; "
        "if [ -n \"$a\" ] && [ -f \"serverfiles/steamapps/appmanifest_$a.acf\" ]; then "
        "m=\"serverfiles/steamapps/appmanifest_$a.acf\"; fi; "
        # Fall back to the only manifest there is, for a game whose config names no appid.
        "if [ -z \"$m\" ]; then for f in serverfiles/steamapps/appmanifest_*.acf; do "
        "if [ -f \"$f\" ]; then m=\"$f\"; break; fi; done; fi; "
        "if [ -n \"$m\" ]; then awk -F'\"' "
        "'$2==\"appid\"{print \"appid=\" $4} $2==\"buildid\"{print \"build=\" $4} "
        "$2==\"LastUpdated\"{print \"updated=\" $4}' \"$m\"; fi; "
        # Paper/Purpur/Spigot write the build they are running to this file, which is the only
        # on-disk version a Minecraft server has — its jar carries it inside the archive.
        "if [ -f serverfiles/version_history.json ]; then sed -n "
        "'s/.*\"currentVersion\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/reported=\\1/p' "
        "serverfiles/version_history.json | head -1; fi"
    )
    try:
        out, _, _ = _core.shell_as_game_user(server, user, sh, timeout=20, selfname=selfname)
    except Exception:
        return {}
    got = {}
    for line in (out or "").splitlines():
        key, _, val = line.strip().partition("=")
        if key in ("appid", "build", "updated", "reported") and val:
            got[key] = val[:64]
    if "updated" in got:
        got["updated"] = _int_or_none(got["updated"])
    return got


def _queried_version(server, user, game_type=None, port=None, query_type=None):
    """The version string the RUNNING game reports, via gamedig, or "" if it can't be read.

    Several protocols spell it differently and some report it as a number, so take the first of
    the known fields that has a value and stringify it — rather than trusting one path and showing
    nothing for every game that uses another."""
    if not _core.game_idents_ok(user):
        return ""
    gdtype = cron._gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return ""
    jqf = ('[.version, .raw.version, .raw.shortversion, .raw.gamever, '
           '.raw.vanilla.raw.version.name] | map(select(. != null and . != "") | tostring) '
           '| .[0] // empty')
    cmd = (f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -r {_core._quote(jqf)} 2>/dev/null")
    try:
        out, _, _ = _core.shell_as_game_user(server, user, cmd, timeout=25)
    except Exception:
        return ""
    # A version is a short token; anything longer is gamedig noise that got past the redirect.
    val = (out or "").strip().splitlines()
    return val[0].strip()[:48] if val and val[0].strip() != "null" else ""


def _version_detail(info):
    """The long form of a version, for the hover text — "where did this number come from".

    Built here rather than in the browser because it is prose assembled from several optional
    parts, and the panel's UI strings are translated by matching whole text nodes against a
    catalog: a sentence stitched together in JavaScript from three dynamic pieces could never
    match one. One string, one place, and the page only has to display it."""
    bits = []
    if info.get("reported"):
        bits.append("reported by the running server")
    if info.get("build"):
        bits.append("Steam build %s" % info["build"])
    if info.get("appid"):
        bits.append("app %s" % info["appid"])
    if info.get("updated"):
        # Date only: the hour Steam happened to push a build is noise next to which build it is.
        # UTC, not localtime: the panel process's timezone has no business deciding what date a
        # build carries, and the browser reading it is frequently in a different one anyway.
        bits.append("files updated %s (UTC)"
                    % time.strftime("%Y-%m-%d", time.gmtime(info["updated"])))
    return " \u00b7 ".join(bits)


def game_version(server, user, game_type=None, port=None, query_type=None, selfname=None,
                 force=False):
    """What's installed for one game server: {reported, build, appid, updated, label}.

    `reported` is the version the game itself answers with (empty when it's offline or doesn't
    answer), `build` the SteamCMD build id on disk (empty for a non-Steam game), `updated` the
    epoch Steam last updated those files, and `label` the single string to show — which is why
    it's built here and not in a template: "unknown" is a real answer for a game that is neither
    SteamCMD-based nor currently running, and the caller shouldn't have to re-derive that.

    Cached for _VERSION_TTL, because nothing but an update moves any of it. Never raises."""
    key = getattr(server, "id", None), user
    now = time.time()
    if not force:
        hit = _version_cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    info = _steam_build(server, user, selfname=selfname)
    reported = _queried_version(server, user, game_type, port, query_type) or info.get("reported", "")
    out = {"reported": reported, "build": info.get("build", ""),
           "appid": info.get("appid", ""), "updated": info.get("updated")}
    if reported:
        out["label"] = reported
    elif out["build"]:
        out["label"] = f"build {out['build']}"
    else:
        out["label"] = ""
    out["detail"] = _version_detail(out)
    # Don't cache a total miss: it's what an unreachable host and a mid-install server both look
    # like, and pinning "unknown" for ten minutes outlasts either.
    if out["label"]:
        _version_cache[key] = (now + _VERSION_TTL, out)
    return out


def _register_version_invalidation():
    """Forget a host's cached versions when its row is DELETED.

    SQLite hands a deleted row's id straight to the next INSERT — plain INTEGER PRIMARY KEY is the
    rowid, no AUTOINCREMENT — so a newly added host inherits whatever the deleted one left in any
    map keyed by host id. panel_state's note on that says it has already bitten this codebase
    twice, both times showing a new server the previous one's state. Here it would take a recycled
    host id AND a game user of the same name to surface, but the whole point of a version readout
    is that the number is right, so it gets closed rather than reasoned about.

    An event rather than a call in the delete route, for the reason the SSH pool's twin above
    gives: the invariant belongs where the row goes away, not at each of the places that remove
    one. Never raises — a cache that failed to prune must not turn into a failed commit."""
    from sqlalchemy import event
    from panel.db.models import RemoteServer

    @event.listens_for(RemoteServer, "after_delete")
    def _forget_versions(_mapper, _connection, target):
        try:
            invalidate_game_version(target.id)
        except Exception:
            _core._log.debug("version-cache prune failed for a deleted remote", exc_info=True)


def invalidate_game_version(remote_id=None, user=None):
    """Forget cached versions so the next read is fresh — call after an update/validate, which is
    the one thing that changes the answer.

    The cache is keyed by (host id, game user), which is what the instance actually is: the same
    short_name can exist on two different hosts. Called with neither argument it clears everything,
    which is the right blast radius for a host-wide change."""
    if remote_id is None and user is None:
        _version_cache.clear()
        return
    for k in [k for k in _version_cache
              if (remote_id is None or k[0] == remote_id) and (user is None or k[1] == user)]:
        _version_cache.pop(k, None)


_register_version_invalidation()
