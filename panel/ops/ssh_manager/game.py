"""Engine families, player queries, the console, moderation and per-game backups.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).
"""
import re
import threading
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
    """The moderation/query engine family for a LinuxGSM game.

    One of 'valve', 'idtech3', 'minecraft', or '' when the game has no console-based moderation the
    panel understands.
    """
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
    """Read-only snapshot of the last `lines` of a LinuxGSM instance's live tmux console.

    Used to read a `status`/`list` reply back. rc 3 + NO_SESSION when the server isn't running.

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
    to cross 80 columns.
    """
    selfname = selfname or user
    inner = _core._tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" capture-pane -p -J -t {selfname} -S -{int(lines)}'
    return _core.shell_as_game_user(server, user, inner, timeout=15, selfname=selfname)


# '#<userid> "<name>"' — the start of a Source/GoldSrc status row. Used to READ a row and, by
# negation, to tell the column header from a row: both carry the word "uniqueid" when a player
# picks the right name, and only one of them starts with a number.
_VALVE_ROW_RE = re.compile(r'\s*#\s*\d+\s+"([^"]*)"')


def _parse_valve_status(text):
    """Parse a Source/GoldSrc `status` reply into [{name, steamid, num, score, time}].

    Player rows start with '#' and carry a quoted name + a STEAM_/[U:..] id; bots have no id. Only
    the MOST RECENT table is used (rows after the last 'uniqueid' header), so players who left
    don't linger.

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


def _idtech3_table_start(lines):
    """Index of the first row after the LAST 'num…score…ping' header (0 when there is none)."""
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
    return start


# An idTech3 `status` row: "num score ping guid name … lastmsg address …". The name may hold
# spaces, so it is whatever lies between the guid and the first "<lastmsg> <a.b.c.d:port>" after
# it. That was one pattern, `\s+(.+?)\s+\d+\s+<address>`, and the lazy name re-walked every run
# of blanks in the row at each character it grew by: quadratic in a row's blanks. The row is now
# read in the same order the pattern read it — each run of blanks is tried ONCE, as the gap in
# front of the lastmsg column — so the answers are the pattern's, in linear time.
_IDT3_ROW_HEAD_RE = re.compile(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+(\S+)(\s+)")
_IDT3_ADDR_RE = re.compile(r"\d+\s+\d{1,3}(?:\.\d{1,3}){3}:\d+")
_BLANKS_RE = re.compile(r"\s+")
# The fallback for rows with no address column: num score ping guid name(rest). The name starts on
# a non-blank (`\S.*`, not `.+`): a `.+` after `\s+` could split the blanks between them every way.
# Only the case where the row ENDS in blanks after the guid answers differently — there `.+` took
# one blank as the name — and the caller strips a name and skips an empty one, as it does a miss.
_IDT3_ROW_NOADDR_RE = re.compile(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+([0-9A-Fa-f]{6,})\s+(\S.*)$")


def _idtech3_row_with_address(ln):
    """Return (num, score, ping, guid, name) for a row that has the address column, else None."""
    head = _IDT3_ROW_HEAD_RE.match(ln)
    if not head or head.end() >= len(ln):
        return None
    name_at = head.end()
    for gap in _BLANKS_RE.finditer(ln, name_at + 1):
        if _IDT3_ADDR_RE.match(ln, gap.end()):
            return head.groups()[:4] + (ln[name_at:gap.start()],)
    # The pattern's last resort: it gave the name a blank of the gap before it. So a row with NO
    # name (the guid, three or more blanks, then lastmsg and address) matched with a one-blank name,
    # which the caller skips. Returning None instead would hand that row to the fallback below,
    # and it would come back as a player named after its own lastmsg and address.
    if len(head.group(5)) >= 3 and _IDT3_ADDR_RE.match(ln, name_at):
        return head.groups()[:4] + (ln[name_at - 2],)
    return None


def _match_idtech3_row(ln):
    """Match one idTech3 status row, with or without the trailing address column (else None).

    The answer is (num, score, ping, guid, name).
    """
    row = _idtech3_row_with_address(ln)
    if row is None:
        m = _IDT3_ROW_NOADDR_RE.match(ln)
        row = m.groups() if m else None
    return row


def _parse_idtech3_status(text):
    """Parse a Quake3/CoD `status` reply into [{name, num, guid, steamid, score, time}].

    Rows are 'num score ping guid name … address …'; the name can contain spaces + ^-colour codes.
    Only the most recent table (rows after the last 'num…score…ping' header) is kept.
    """
    lines = (text or "").splitlines()
    start = _idtech3_table_start(lines)
    players, seen = [], set()
    for ln in lines[start:]:
        row = _match_idtech3_row(ln)
        if not row:
            continue
        num = _int_or_none(row[0])
        if num is None or num in seen:
            continue
        name = _strip_q3_colors(row[4]).strip()
        if not name:
            continue
        seen.add(num)
        players.append({"name": name[:64], "num": num, "guid": row[3], "steamid": "",
                        "score": _int_or_none(row[1]), "time": None})
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
    """Parse a Minecraft `list` reply into [{name, …}], or None when there is no reply at all.

    The reply reads 'There are N of M players online: Alice, Bob'; None when the capture holds no
    `list` reply at all.

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
    wrapping, a capture taken mid-print) is unknown, never a short player list and never zero.
    """
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


def _send_rc(result):
    """The rc of a send_console_command result, or 1 when it is not an (out, err, rc) tuple."""
    return result[2] if isinstance(result, tuple) and len(result) >= 3 else 1


def _send_and_capture(server, user, eng, selfname):
    """Send the engine's player-list command and capture the reply: (out, rc), or None.

    None when the send itself failed or anything raised — the capture is never trusted then.
    """
    cmd = "list" if eng == "minecraft" else "status"
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
        if _send_rc(_sent) != 0:
            return None
        time.sleep(0.8)   # let the server print its reply into the pane before we capture it
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return None
    return out, rc


def _parse_player_reply(eng, out):
    """Parse a captured player-list reply with the engine's own parser."""
    if eng == "idtech3":
        return _parse_idtech3_status(out)
    if eng == "minecraft":
        return _parse_minecraft_list(out)
    return _parse_valve_status(out)


def console_player_list(server, user, game_type, selfname=None):
    """Player list from the game's OWN console.

    The only source that yields the identifiers needed to kick/ban precisely (SteamIDs for valve,
    slot numbers for idTech3). Sends the list command, then captures + parses the pane. Returns a
    list (possibly empty), or None for a non-console game. Never raises.
    """
    eng = game_engine(game_type)
    if not eng:
        return None
    # NONE for "could not read", [] only for a table that really had no rows in it. These both
    # answered [], and player_list's `or []` then turned a stopped server into a confirmed-empty
    # one: the bot's /players said "no players connected" about a server that was down. Its own
    # docstring already draws the distinction ("an empty list for a confirmed-empty server, or
    # None when it can't be read"); only the code did not.
    got = _send_and_capture(server, user, eng, selfname)
    if got is None:
        return None
    out, rc = got
    if rc != 0 or not out or "NO_SESSION" in out:
        return None
    return _parse_player_reply(eng, out)


# The `hostname:` line of a valve/idTech3 `status` reply. The keyword must be the first thing on
# its line, blanks aside, and it is looked for line by line: the old pattern's `^\s*` in front of it
# crossed newlines and re-walked every blank line below each line start, quadratic in a run of
# empty lines.
_HOSTNAME_KEY_RE = re.compile(r"(?:hostname|sv_hostname)", re.IGNORECASE)


def _hostname_key_end(out):
    """Return where the keyword ends on the first line that starts with it, or -1 for none."""
    at = 0
    for line in out.split("\n"):
        m = _HOSTNAME_KEY_RE.match(line, len(line) - len(line.lstrip()))
        if m:
            return at + m.end()
        at += len(line) + 1
    return -1


def _status_hostname(out):
    r"""Return the server name a console `status` reply advertises, as its line holds it, or None.

    It answers what `^\s*(?:hostname|sv_hostname)\s*:?\s*(.+?)\s*$` (MULTILINE, IGNORECASE)
    captured, wherever console_status can tell the difference. That pattern's `(.+?)\s*$` retried
    the whole tail of the line at each character of the name: quadratic in a name holding a long run
    of blanks. What it captured is the first non-blank after the keyword (and after a colon, if
    one comes first), to the end of that line, and blanks before the name may span lines. After a
    colon with nothing but blanks to the end of the reply it captured a blank, which console_status
    reads as no name, or the colon itself when those blanks were all newlines.
    """
    end = _hostname_key_end(out)
    if end < 0:
        return None
    value = out[end:].lstrip()
    if value.startswith(":"):
        after = value[1:].lstrip()
        if not after:
            return None if value[1:].strip("\n") else ":"
        value = after
    return value.split("\n", 1)[0].rstrip()


def console_status(server, user, game_type, selfname=None):
    """One console `status`/`list` capture → (players, name), from a SINGLE round-trip.

    The parsed player list AND the server's advertised in-game name (the valve/idTech3 `hostname:`
    line). Used by the background poller so a server gamedig can't query (e.g. no GSLT) isn't hit
    with two separate `status` sends per pass — which would spam the very console an admin is
    watching.

    Returns (None, None) for a non-console game or on failure — NOT ([], None). An empty list is
    "confirmed empty", and this returned it for a send that never arrived, a capture that failed
    and a game with no console at all, which is the same conflation console_player_list's contract
    exists to avoid. Never raises.
    """
    eng = game_engine(game_type)
    if not eng:
        return None, None
    # The send's status too — see _send_and_capture for what dropping it cost: the capture is a
    # separate round trip and succeeds happily after a send that never landed, so the pane's
    # PREVIOUS table was returned as the current one.
    got = _send_and_capture(server, user, eng, selfname)
    if got is None:
        return None, None
    out, rc = got
    if rc != 0 or not out:
        return None, None
    players = _parse_player_reply(eng, out)
    name = None
    if eng in ("valve", "idtech3"):
        advertised = _status_hostname(out)
        if advertised:
            name = " ".join(_strip_q3_colors(advertised).split())[:120] or None
    return players, name


def _gamedig_player_list(server, user, game_type=None, port=None, query_type=None):
    """Player list via gamedig — the PRIMARY source.

    Returns a list ([{name, …}], possibly empty for a confirmed-empty server) when gamedig could
    query the game, or None when it couldn't (no gamedig type, no port, or the query failed) so the
    caller can fall back to the console. Never raises. Names carry score/time where the game
    reports them; no kick/ban ids (those come from the console on demand).
    """
    if not _core.game_idents_ok(user):
        return None      # refused, which is "could not query" — never an empty server
    gdtype = cron._gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None
    # Player fields are protocol-specific in gamedig: Source/valve exposes score + time (seconds
    # connected); Quake3/idTech3 (cod) exposes `frags` and no time. Pull score from score OR frags
    # so cod shows a score too; time stays null where the game doesn't report it. `c` is the
    # reply's own head count (_core.GAMEDIG_HUMANS_JQ), so an empty list can be told from an empty
    # server: see _gamedig_players_from_output.
    jqf = ('{p:[.players[] | {name:(.name // ""), '
           'score:(.raw.score // .score // .raw.frags // .frags // null), '
           'time:(.raw.time // .time // null)}], c:%s}' % _core.GAMEDIG_HUMANS_JQ)
    cmd = f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null | jq -c {_core._quote(jqf)} 2>/dev/null"
    try:
        out, _, _ = _core.shell_as_game_user(server, user, cmd, timeout=25)
    except Exception:
        return None
    return _gamedig_players_from_output(out)


def _gamedig_players_from_output(out):
    """The player list from the jq-reduced gamedig output ({p: list, c: head count}), or None.

    None when there is nothing to read — and when the list has no names while the reply's own count
    says someone is on. A Minecraft Bedrock reply never carries a list (numplayers is all its ping
    returns), nor does a Java server hiding its players or a Source server that does not answer
    A2S_PLAYER, and an empty list was read as a confirmed-empty server: the Players panel and the
    chat bot's /players said "no players connected" with people on. Unknown lets the on-demand
    console fallback answer instead.
    """
    line = next((ln.strip() for ln in reversed((out or "").splitlines())
                 if ln.strip().startswith("{")), "")
    if not line:
        return None
    try:
        import json as _json
        data = _json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    rows = _gamedig_player_rows(data.get("p"))
    if not rows and data.get("c") != 0:
        return None      # nobody named, and the count is not a counted 0: unknown, not empty
    return rows


def _gamedig_player_rows(data):
    """Player rows from the decoded gamedig list (`p`): named entries only, name capped at 64."""
    players = []
    for p in (data if isinstance(data, list) else []):
        if isinstance(p, dict):
            name = str(p.get("name") or "").strip()
            if name:
                players.append({"name": name[:64], "steamid": "", "num": None,
                                "score": p.get("score"), "time": p.get("time")})
    return players


# The server page's Players card polls /playerlist every 15 s per open page, and each poll was its
# own `sudo -u <account> gamedig` run: two viewers of one server, or one viewer and a quick re-poll,
# paid twice for one answer. A list gamedig READ is kept this long, keyed by what was queried, and
# a second caller that arrives while a query is running waits for it instead of starting another.
# Shorter than the page's own period, so a lone viewer always sees a fresh list.
_PLAYERLIST_TTL = 10
_playerlist_cache = _core.register_remote_cache({})   # {(remote_id, port, gdtype): (expiry, list)}
_playerlist_locks = _core.register_remote_cache({})
_playerlist_guard = threading.Lock()


def _playerlist_lock(key):
    with _playerlist_guard:
        lock = _playerlist_locks.get(key)
        if lock is None:
            lock = _playerlist_locks[key] = threading.Lock()
        return lock


def _playerlist_hit(key):
    hit = _playerlist_cache.get(key)
    if hit and hit[0] > time.time():
        return [dict(p) for p in hit[1]]
    return None


def _gamedig_player_list_shared(server, user, game_type, port, query_type):
    """_gamedig_player_list through the short shared cache. Only a list gamedig read is stored."""
    gdtype = cron._gamedig_type(game_type, query_type)
    if not _core.game_idents_ok(user) or not gdtype or not port:
        return _gamedig_player_list(server, user, game_type, port, query_type)
    try:
        key = (getattr(server, "id", None), int(port), gdtype)
    except (TypeError, ValueError):
        return _gamedig_player_list(server, user, game_type, port, query_type)
    hit = _playerlist_hit(key)
    if hit is not None:
        return hit
    with _playerlist_lock(key):
        hit = _playerlist_hit(key)
        if hit is not None:
            return hit
        pl = _gamedig_player_list(server, user, game_type, port, query_type)
        if pl is not None:
            _playerlist_cache[key] = (time.time() + _PLAYERLIST_TTL, [dict(p) for p in pl])
        return pl


def player_list(server, user, game_type=None, port=None, query_type=None, selfname=None,
                allow_console=False, shared=False):
    """Connected players for the Players panel.

    gamedig is the PRIMARY source (names + score/time, and it never touches the game console). The
    game's own console (`status`/`list`) is only used when gamedig can't query the game AND the
    caller explicitly opts in with allow_console=True — so a background/timer poll never issues a
    console command; only an on-demand user action does.
    Returns [{name, steamid, num, score, time}] (steamid/num set only when the list came from the
    console), an empty list for a confirmed-empty server, or None when it can't be read over the
    network and the console wasn't allowed. Never raises.

    `shared=True` is for the page's timed poll: it may be answered by a list gamedig read in the
    last _PLAYERLIST_TTL seconds. An explicit refresh (after a kick, say) passes False and asks.
    """
    if shared:
        pl = _gamedig_player_list_shared(server, user, game_type, port, query_type)
    else:
        pl = _gamedig_player_list(server, user, game_type, port, query_type)
    if pl is not None:
        return pl                       # gamedig answered (players, or a confirmed-empty server)
    if allow_console and game_engine(game_type):   # explicit, on-demand console read only
        # No `or []`: None here means the console could not be read, which is not the same
        # answer as "nobody is playing" and is the distinction this function's contract turns on.
        return console_player_list(server, user, game_type, selfname=selfname)
    return None                         # can't read over the network; console not requested


def is_player_queryable(game_type, query_type=None):
    """True if the panel can show a live player list.

    That takes a console engine (valve/idTech3/Minecraft) or a gamedig type (built-in map or a
    per-server override).
    """
    return bool(game_engine(game_type)) or bool(cron._gamedig_type(game_type, query_type))


# Bedrock Dedicated Server's console has NO `ban` command. Banning on Bedrock is the allowlist
# (`allowlist add/remove`, renamed from `whitelist` in 1.18.10); `/ban` is Java-only. PocketMine
# does implement `ban`, so it is deliberately not in here.
_MC_NO_BAN = frozenset({"mcbe", "mcb"})


def moderation_caps(game_type):
    """Which moderation actions this game's console supports: {kick, ban, say}.

    Driven by the engine family, so every game of a family is covered. Non-console games get
    nothing (view-only).

    `ban` is dropped for Bedrock: _ENG_MINECRAFT covers mcbe/mcb alongside the Java families, so
    this answered ban=True for a console with no ban command, the detail page rendered the button,
    and sending `ban <name>` into the pane got "Unknown command" while tmux send-keys exited 0 —
    "Done.", a success audit row, and the griefer still connected.
    """
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
    None if not found. Only runs when someone actually clicks kick/ban — no continuous polling.
    """
    want = _strip_q3_colors(name or "").strip()
    if not want:
        return None
    for p in (console_player_list(server, user, game_type, selfname=selfname) or []):
        if _strip_q3_colors(p.get("name") or "").strip() == want:
            return p
    return None


_MOD_IDENT_KEYS = ("steamid", "num")


def _moderation_ident(ident):
    """The (steamid, num) a moderate() call was given, refusing any other keyword.

    They arrive as keywords only; an unknown one is the same TypeError a misspelled parameter
    always raised, so a typo cannot silently turn into a ban with no identifier.
    """
    unknown = sorted(set(ident) - set(_MOD_IDENT_KEYS))
    if unknown:
        raise TypeError("moderate() got an unexpected keyword argument %r" % unknown[0])
    return ident.get("steamid", ""), ident.get("num", "")


def _mod_unsupported_reason(game_type, eng, action):
    """Why an action this game's console cannot take was refused.

    Bedrock gets its own reason, because "isn't supported" is not actionable: BDS has no ban
    command at all (see _MC_NO_BAN), and banning there is the allowlist. Until moderation_caps
    dropped it, this fell through to the minecraft branch, sent `ban <name>` into the pane,
    and `tmux send-keys` exited 0 for a command the game answered with "Unknown command" — so
    the panel flashed "Done.", wrote a success audit row, counted the Bedrock servers in
    "Also banned on N other servers", and the griefer reconnected immediately. Same reasoning
    as the space-in-name refusal in _mod_minecraft_cmd: a ban that silently does nothing is worse
    than a button that says why it stopped.
    """
    if action == "ban" and eng == "minecraft" and (game_type or "").lower() in _MC_NO_BAN:
        return ("Bedrock servers have no ban command — remove the player from the "
                "server's allowlist instead.")
    return "That action isn't supported for this game."


def _mod_say_cmd(message):
    """(console command, None) for an announcement, or (None, why) when there is nothing to say."""
    msg = _mod_sanitize(message, 200)
    if not msg:
        return None, "Nothing to announce."
    return "say %s" % msg, None


def _mod_valve_cmd(action, target, steamid, resolve):
    """(console command, None) for a Source/GoldSrc kick or ban, or (None, why) when refused.

    Kick by name, ban by SteamID; `resolve()` looks the player up on the console when the list on
    screen came from gamedig and carries no SteamID.
    """
    if action == "kick":
        nm = _mod_sanitize(target, 64)
        if not nm:
            return None, "No player selected."
        return 'kick "%s"' % nm, None
    sid = _sanitize_steamid(steamid)
    if not sid:      # list came from gamedig (no SteamID) — resolve it on the console now
        p = resolve()
        sid = _sanitize_steamid(p.get("steamid")) if p else ""
    if not sid:
        return None, "Couldn't find that player's SteamID to ban them."
    # banid <0=permanent> <id> kick — the `kick` keyword boots them if they're connected
    # right now (banid without it only blocks future joins); writeid persists to the ban file.
    return "banid 0 %s kick; writeid" % sid, None


def _mod_idtech3_cmd(action, num, resolve):
    """(console command, None) for an idTech3 kick or ban by slot number, or (None, why)."""
    slot = _sanitize_slotnum(num)
    if slot is None:     # list came from gamedig (no slot number) — resolve it on the console now
        p = resolve()
        slot = _sanitize_slotnum(p.get("num")) if p else None
    if slot is None:
        return None, "Couldn't find that player on the server."
    return "%s %d" % ("clientkick" if action == "kick" else "banclient", slot), None


def _mod_minecraft_cmd(action, target):
    """(console command, None) for a Minecraft kick or ban by name, or (None, why) when refused."""
    nm = _mod_sanitize(target, 64)
    if not nm:
        return None, "No player selected."
    # `kick <player> [reason]` — the name and the reason are separated by a SPACE, and
    # _MOD_BAD_CHARS does not strip one. That is right for Source and idTech3, whose consoles
    # separate on ';' and newline only, and wrong here: _ENG_MINECRAFT covers mcbe/mcb/
    # pocketmine, Bedrock gamertags may contain spaces, and a gamedig-sourced list carries the
    # raw name (only _parse_minecraft_list sanitises, and that is the console path). So a
    # player named "<someone else> griefing" sends the admin's kick to that someone else.
    # There is no quoting that is correct across Java, Bedrock and PocketMine, so this refuses
    # rather than guessing — a misdirected ban is worse than a button that says why it stopped.
    if re.search(r"\s", nm):
        return None, ("That player's name contains a space, which this game's console reads "
                      "as the start of the reason — kick or ban them from the server "
                      "console directly.")
    return "%s %s" % ("kick" if action == "kick" else "ban", nm), None


def moderate(server, user, game_type, action, target="", message="", selfname=None, **ident):
    """Kick/ban a player or announce a message through the game's own console.

    Dispatched by engine:
      • valve (Source/GoldSrc): kick by name, ban by SteamID, say
      • idTech3 (CoD/Quake3):   kick/ban by slot number, say
      • minecraft:              kick/ban by name, say
    Names/messages are sanitized (and the SteamID/slot re-validated) so a hostile name can't inject
    a console command. Returns (ok, msg).

    The player's console identifiers come as keywords only — `steamid=` (valve) and `num=`
    (idTech3 slot) — and any other keyword is refused with a TypeError (see _moderation_ident).
    """
    steamid, num = _moderation_ident(ident)
    eng = game_engine(game_type)
    if action not in ("kick", "ban", "say") or not moderation_caps(game_type).get(action):
        return False, _mod_unsupported_reason(game_type, eng, action)

    def resolve():
        return _resolve_from_console(server, user, game_type, target, selfname)

    if action == "say":
        cmd, why = _mod_say_cmd(message)
    elif eng == "valve":
        cmd, why = _mod_valve_cmd(action, target, steamid, resolve)
    elif eng == "idtech3":
        cmd, why = _mod_idtech3_cmd(action, num, resolve)
    elif eng == "minecraft":
        cmd, why = _mod_minecraft_cmd(action, target)
    else:
        return False, "That action isn't supported for this game."
    if why:
        return False, why

    out = _core.send_console_command(server, user, cmd, timeout=15, selfname=selfname)
    rc = _send_rc(out)
    return (rc == 0), ("Done." if rc == 0 else "Console not reachable — is the server running?")


def console_steamid_ban(server, user, selfname, steamid, unban=False):
    """Ban (or unban) a SteamID on ONE Source/GoldSrc server via its console.

    `banid 0 <id>; writeid` to ban, `removeid <id>; writeid` to lift, using the game's native
    persistent ban list. The SteamID is re-validated to STEAM_x:y:z / [U:x:y] so nothing
    injectable reaches the console.
    Only affects a RUNNING server (needs a live console). (ok, reason) where reason is a fixed word:
    'banned' / 'unbanned' / 'invalid' / 'offline' / 'failed'.
    """
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
    """Make a Source server RELOAD its ban list on every (re)start.

    `banid`/`writeid` persist a SteamID ban to cfg/banned_user.cfg, but the engine only loads that
    file if the server config execs it — without the exec line a ban is silently lost on the next
    map change / restart and the player can rejoin (exactly what bit us: a flapping server dropped
    every ban). Append the exec lines to the LinuxGSM servercfg (`${selfname}.cfg` in the game's
    cfg dir), idempotently. Best-effort; returns True when the line is present/added, False on any
    failure or non-Source layout.
    """
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
    """Decide how to handle the restart a mod change needs.

    Given the server `status` ('online'/'offline'/'unresponsive'/'unknown'), the current player
    count (int, or None when unknown), and whether the admin forced it. Pure/side-effect-free so it
    can be tested directly:
      'idle'    — server is stopped; nothing to do (the change loads on next start)
      'restart' — restart now (server is confirmed empty, or the admin forced it)
      'pending' — defer: players are online, or we can't confirm it's empty.

    Only a status of 'offline' is idle, and only STOPPED means offline. 'unresponsive' — a
    session running but not serving — falls through to 'pending' and keeps the request queued,
    because clearing it would throw away something the operator asked for without doing it.
    """
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
    the test; the panel always passes the account's own.
    """
    home = home or "/home/%s" % user
    return (f"pgrep -u {user} -x tar >/dev/null 2>&1 || "
            f"find {home} -maxdepth 4 -name '*backup.lock' -mmin +5 -delete 2>/dev/null; ")


def _backup_players_online(server, user, game_type, port, query_type):
    """The skip message when players are connected (a backup would disconnect them), else None.

    An unknown count (None) is treated as empty — see run_game_backup.

    query_type, like every other player/version read in this file (_gamedig_player_list,
    _queried_version, is_player_queryable) and like the on-screen count in server_detail.
    This one call — the only one that decides whether to disconnect people — dropped it, so
    player_count resolved the gamedig type from the 26-entry built-in map ALONE. A game the
    map does not cover (Project Zomboid, ARK, Mordhau, Killing Floor) whose operator set the
    per-server override precisely so the panel could query it resolved to "", answered None,
    and the rule above reads None as empty — so the hourly ticker ran LinuxGSM's `backup`,
    which STOPS the server, and disconnected everyone on it. The override exists for exactly
    the servers this guard was blind on.
    """
    pc = cron.player_count(server, user, game_type, port, query_type)
    if pc is not None and pc > 0:
        return f"{pc} player(s) online — backup skipped so nobody gets disconnected"
    return None


def _backup_space_refusal(server, user, headroom_note):
    """The refusal message when the next archive will not fit on the disk, else None.

    Pre-flight space check: if there STILL isn't room for the archive after freeing what we can,
    don't even start LinuxGSM's backup. A backup that runs out of space mid-write half-fills the
    disk with a partial archive and can leave a stale lock behind — far worse than not starting.
    We estimate the next archive from the largest existing one; with none to go by we let it try.
    """
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
            return (f"Not enough disk space to back up{note}: the archive needs about "
                    f"{cron._fmt_size(int(_est * 1.05))} but only {cron._fmt_size(_free)} is free on the host. "
                    f"Lower this server's 'keep' count, remove old backups, or free space on the disk.")
    except Exception:
        _core._log.debug("backup pre-flight space check failed", exc_info=True)
    return None


def _backup_failure_reason(out, err):
    """The most relevant LinuxGSM line from a failed backup, so the panel can show WHY it failed."""
    clean = terminal.strip_escapes(((out or "") + "\n" + (err or ""))).strip()
    reason = ""
    for line in reversed(clean.splitlines()):
        low = line.lower()
        if any(k in low for k in ("fail", "error", "unable", "no space", "not enough", "denied", "cannot")):
            reason = line.strip()
            break
    if not reason and clean.splitlines():
        reason = clean.splitlines()[-1].strip()
    return (reason or "backup failed")[-200:]


def _run_linuxgsm_backup(server, user, selfname):
    """Run LinuxGSM's `backup` as the game user: (ok, lock_refused, out, err)."""
    # A crashed/killed/timed-out earlier backup can leave LinuxGSM's backup.lock behind, after
    # which every backup refuses with "Lockfile found: Backup is currently running". See
    # _stale_backup_lock_sweep for when a lock counts as orphaned.
    _core.shell_as_game_user(server, user, _stale_backup_lock_sweep(user) + "true", timeout=60)
    # When the instance is running, LinuxGSM's `backup` warns + counts down, then STOPS the
    # server, archives it, and RESTARTS it (verified on a live box: ~1.5 min outage for a 6.5G
    # GMod install). It doesn't strictly need a y/N answer, but we feed a few harmless "y"s as a
    # safety net for any version that does prompt. The stream is bounded, so it can't hang.
    #
    # Through run_as_game_user, the one path every other LinuxGSM action takes. This was its own
    # `sudo -u <account> … ./<script> backup`, and the server LinuxGSM restarts at the end of a
    # backup was started from the panel's cgroup with it: on a system install the next panel
    # restart ended it. On the panel's own host the helper's lgsm-command gives the action a scope
    # of its own before it drops to the account; on a remote it is the same shell form as before.
    out, err, rc = _core.run_as_game_user(server, user, "backup", timeout=3600, selfname=selfname,
                                          answers=["y", "y", "y"])
    ok = rc == 0
    # LinuxGSM can exit 0 while REFUSING to back up because a (possibly stale) lock exists —
    # "Lockfile found: Backup is currently running". No archive is created, so this is NOT a
    # success; reporting it as one is what makes the UI show "✓ Backed up" with no actual backup.
    _blob = ((out or "") + " " + (err or "")).lower()
    lock_refused = "lockfile found" in _blob or "backup is currently running" in _blob
    if lock_refused:
        ok = False
    return ok, lock_refused, out, err


def run_game_backup(server, user, selfname=None, keep=3, game_type=None, port=None, force=False,
                    query_type=None):
    """Run LinuxGSM's own `backup` for a game instance, then prune to the newest `keep`.

    The backup archives serverfiles into ~/lgsm/backup/. Runs AS THE GAME USER, non-interactively
    (like a cron backup). Long-running — archives can be large.

    LinuxGSM's `backup` STOPS a running server for the duration, which disconnects
    anyone playing. So unless `force=True`, we first check the live player count and,
    if anyone is on, SKIP rather than kick them. Returns (ok, message, skipped):
      - (True, note, False)   backup completed
      - (False, reason, False) backup attempted but failed
      - (False, "N player(s) online …", True) skipped because players were connected
    An unknown/unqueryable player count (None) is treated as empty, so games gamedig
    can't query still back up on schedule (matching the daily-restart behaviour) —
    which is exactly why `query_type` has to be threaded in (see below).
    """
    selfname = selfname or user
    # Refused before the player query, the headroom prune and the listing, which would otherwise
    # each reach the host first: the backup itself is refused by shell_as_game_user anyway.
    if not _core.game_idents_ok(user, selfname):
        return False, _core.GAME_ACCOUNT_REFUSED[1], False
    keep = max(1, int(keep))
    if not force:
        skip = _backup_players_online(server, user, game_type, port, query_type)
        if skip:
            return False, skip, True
    # Smart retention: if the disk is nearly full, delete old backups BEFORE creating the new one
    # so the backup succeeds instead of aborting for lack of space.
    headroom_note = cron._ensure_backup_headroom(server, user, keep)
    refusal = _backup_space_refusal(server, user, headroom_note)
    if refusal:
        return False, refusal, False
    ok, lock_refused, out, err = _run_linuxgsm_backup(server, user, selfname)
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
    return False, _backup_failure_reason(out, err), False


# One row of the command table the instance script prints with no arguments:
# "start         st   | Start the server.". The description is read after the pattern, not by
# it: `\|\s+(.+?)\s*$` retried its trailing `\s*$` at every character of the description, which
# is quadratic in a description holding a long run of blanks.
_CMD_ROW_HEAD_RE = re.compile(r"\s*([a-z][a-z0-9-]*)\s+([a-z]{1,4})\s+\|(?=\s)")


def _command_table_row(line):
    r"""Return (cmd, short, desc) for one command-table row, or None.

    It answers what `^\s*([a-z][a-z0-9-]*)\s+([a-z]{1,4})\s+\|\s+(.+?)\s*$` answered on one
    line: the description is the text after the bar with its blanks trimmed. When there is only
    blank after the bar, that pattern needed two blanks and captured the last one, so it still does.
    """
    m = _CMD_ROW_HEAD_RE.match(line)
    if not m:
        return None
    rest = line[m.end():]
    desc = rest.strip()
    if not desc:
        if len(rest) < 2:
            return None
        desc = rest[-1]
    return m.group(1), m.group(2), desc


def list_server_commands(server, user, selfname=None):
    """Run the LinuxGSM instance script with no arguments to read its command list.

    The list varies per game. Returns a list of {"cmd", "short", "desc"} dicts.
    """
    selfname = selfname or user
    out, err, _ = _core.shell_as_game_user(server, user, f"cd /home/{user} && ./{selfname}",
                                           timeout=30, selfname=selfname)
    text = terminal.strip_escapes((out or "") + "\n" + (err or ""))
    cmds, seen = [], set()
    for line in text.splitlines():
        row = _command_table_row(line)
        if row:
            cmd, short, desc = row
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


# One row of `details`' DESCRIPTION / PORT / PROTOCOL table: "Game  27015  udp". The description
# may hold spaces, so it runs to the first gap followed by a 2-5 digit port and a protocol. That was
# `([A-Za-z][A-Za-z0-9/+ .-]*?)\s+(\d{2,5})\s+(tcp|udp|both|raw)\b`, whose lazy description re-walked
# every later run of blanks at each character it grew by: quadratic in a row's blanks.
_PORT_ROW_DESC_RE = re.compile(r"[A-Za-z][A-Za-z0-9/+ .-]*", re.I)
_PORT_ROW_TAIL_RE = re.compile(r"\s+(\d{2,5})\s+(tcp|udp|both|raw)\b", re.I)


def _port_table_row(s):
    """Return (desc, port, protocol) as the old row pattern captured them, or None.

    Each gap inside the longest description the charset allows is tried once, in order, which is
    exactly the order the lazy description tried them in; within a gap every position answered the
    same, so its first is the one it took.
    """
    head = _PORT_ROW_DESC_RE.match(s)
    if not head:
        return None
    for gap in _BLANKS_RE.finditer(s, 1, head.end() + 1):
        tail = _PORT_ROW_TAIL_RE.match(s, gap.start())
        if tail:
            return s[:gap.start()], tail.group(1), tail.group(2)
    return None


def _parse_details_port_table(text):
    """The DESCRIPTION/PORT/PROTOCOL table from `details`: (ports, the first "Game" port or None)."""
    ports, game_port, in_table = [], None, False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"DESCRIPTION\s+PORT\s+PROTOCOL", s, re.I):
            in_table = True
            continue
        if not in_table:
            continue
        row = _port_table_row(s)
        if not row:
            in_table = False  # blank/other line → table ended
            continue
        desc, port, proto = row[0].strip(), int(row[1]), row[2].lower()
        ports.append({"desc": desc, "port": port, "protocol": proto})
        if game_port is None and desc.lower().startswith("game"):
            game_port = port
    return ports, game_port


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
    ports, game_port = _parse_details_port_table(text)
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
    happened to land in the seconds between a restart and the port binding.
    """
    out, err, _ = _core.run_as_game_user(
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
    uses it to DOWNGRADE LinuxGSM's answer and an unreadable host must never do that.
    """
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
    """{appid, build, updated} from the SteamCMD app manifest on disk, or {} when there is none.

    {} for a game that has none (non-Steam games, or files not downloaded yet). One SSH round trip.
    Never raises.

    The appid comes from LinuxGSM's own config rather than from whichever manifest happens to
    sort first: serverfiles/steamapps/ can hold several (a game plus a dependency), and picking
    the wrong one reports a build number that never moves when the game updates.
    """
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
    nothing for every game that uses another.
    """
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
    match one. One string, one place, and the page only has to display it.
    """
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

    Cached for _VERSION_TTL, because nothing but an update moves any of it. Never raises.
    """
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
    one. Never raises — a cache that failed to prune must not turn into a failed commit.
    """
    from sqlalchemy import event
    from panel.db.models import RemoteServer

    @event.listens_for(RemoteServer, "after_delete")
    def _forget_versions(_mapper, _connection, target):
        try:
            invalidate_game_version(target.id)
        except Exception:
            _core._log.debug("version-cache prune failed for a deleted remote", exc_info=True)


def invalidate_game_version(remote_id=None, user=None):
    """Forget cached versions so the next read is fresh.

    Call after an update/validate, which is the one thing that changes the answer.

    The cache is keyed by (host id, game user), which is what the instance actually is: the same
    short_name can exist on two different hosts. Called with neither argument it clears everything,
    which is the right blast radius for a host-wide change.
    """
    if remote_id is None and user is None:
        _version_cache.clear()
        return
    for k in [k for k in _version_cache
              if (remote_id is None or k[0] == remote_id) and (user is None or k[1] == user)]:
        _version_cache.pop(k, None)


_register_version_invalidation()
