"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
from panel.core import terminal
import time
from panel.ops.ssh_manager import (_core, cron, files)  # noqa: E402,F401  (module objects: the
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
    read a `status`/`list` reply back. rc 3 + NO_SESSION when the server isn't running."""
    selfname = selfname or user
    inner = _core._tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" capture-pane -p -t {selfname} -S -{int(lines)}'
    cmd = f"sudo -u {user} bash -c {_core._quote(inner)}"
    return _core.run_command(server, cmd, timeout=15, sudo=False)


def _parse_valve_status(text):
    """Parse a Source/GoldSrc `status` reply into [{name, steamid, num, score, time}]. Player rows
    start with '#' and carry a quoted name + a STEAM_/[U:..] id; bots have no id. Only the MOST
    RECENT table is used (rows after the last 'uniqueid' header), so players who left don't linger."""
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if "uniqueid" in ln.lower():
            start = i + 1
    players, seen = [], set()
    for ln in lines[start:]:
        # A real player row is '#<userid> "<name>" …'. Requiring the leading '#' + number rejects the
        # '# userid name uniqueid' header AND stray chat/console lines that merely contain quotes.
        m = re.match(r'\s*#\s*\d+\s+"([^"]*)"', ln)
        if not m:
            continue
        name = m.group(1).strip()
        if not name:
            continue
        steamid = _sanitize_steamid(ln)
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
        if "num" in low and "score" in low and "ping" in low:
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


def _parse_minecraft_list(text):
    """Parse a Minecraft `list` reply ('There are N of M players online: Alice, Bob') into
    [{name, …}]. Splits on the last 'online:' so a log-line timestamp prefix can't confuse it."""
    line = ""
    for ln in (text or "").splitlines():
        if "online:" in ln.lower():
            line = ln
    idx = line.lower().rfind("online:")
    if idx == -1:
        return []
    after = line[idx + len("online:"):]
    players, seen = [], set()
    for chunk in after.split(","):
        nm = re.sub(r"[^A-Za-z0-9_]", "", chunk)[:32]
        if nm and nm not in seen:
            seen.add(nm)
            players.append({"name": nm, "steamid": "", "num": None, "score": None, "time": None})
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
    try:
        _core.send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        time.sleep(0.8)   # let the server print its reply into the pane before we capture it
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return []
    if rc != 0 or not out:
        return []
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
    `status` sends per pass — which would spam the very console an admin is watching. Returns
    ([], None) for a non-console game or on failure. Never raises."""
    eng = game_engine(game_type)
    if not eng:
        return [], None
    cmd = "list" if eng == "minecraft" else "status"
    try:
        _core.send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        time.sleep(0.8)   # let the server print its reply into the pane
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return [], None
    if rc != 0 or not out:
        return [], None
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
        out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=25, sudo=False)
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
        return console_player_list(server, user, game_type, selfname=selfname) or []
    return None                         # can't read over the network; console not requested


def is_player_queryable(game_type, query_type=None):
    """True if the panel can show a live player list: a console engine (valve/idTech3/Minecraft)
    or a gamedig type (built-in map or a per-server override)."""
    return bool(game_engine(game_type)) or bool(cron._gamedig_type(game_type, query_type))


def moderation_caps(game_type):
    """Which moderation actions this game's console supports: {kick, ban, say}. Driven by the engine
    family, so every game of a family is covered. Non-console games get nothing (view-only)."""
    if game_engine(game_type):      # valve, idtech3 and minecraft all support all three
        return {"kick": True, "ban": True, "say": True}
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
        raw = (files.lgsm_get_values(server, user, selfname, ["servercfg"]).get("servercfg") or "").strip()
        fname = (raw.replace("${selfname}", selfname).replace("$selfname", selfname)
                 or "%s.cfg" % selfname)
        if not re.match(r"^[A-Za-z0-9_.-]+\.cfg$", fname):     # guard the value going into `find`
            fname = "%s.cfg" % selfname
        inner = (
            f"F=$(find ~/serverfiles -maxdepth 4 -path '*/cfg/{fname}' 2>/dev/null | head -1); "
            '[ -z "$F" ] && exit 1; '
            'grep -qiE "^[[:space:]]*exec[[:space:]]+banned_user" "$F" && exit 0; '
            'printf "\\n// panel: load persistent bans on every (re)start\\n'
            'exec banned_user.cfg\\nexec banned_ip.cfg\\n" >> "$F"'
        )
        _, _, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}", timeout=15, sudo=False)
        return rc == 0
    except Exception:
        return False


def mod_restart_decision(status, players, force=False):
    """Decide how to handle the restart a mod change needs, given the server `status`
    ('online'/'offline'/'unknown'), the current player count (int, or None when unknown),
    and whether the admin forced it. Pure/side-effect-free so it can be tested directly:
      'idle'    — server is stopped; nothing to do (the change loads on next start)
      'restart' — restart now (server is confirmed empty, or the admin forced it)
      'pending' — defer: players are online, or we can't confirm it's empty."""
    if status == "offline":
        return "idle"
    if force:
        return "restart"
    if status == "online" and players == 0:
        return "restart"
    return "pending"


def run_game_backup(server, user, selfname=None, keep=3, game_type=None, port=None, force=False):
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
    can't query still back up on schedule (matching the daily-restart behaviour)."""
    selfname = selfname or user
    keep = max(1, int(keep))
    if not force:
        pc = cron.player_count(server, user, game_type, port)
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
        _bks = cron.list_game_backups(server, user)
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
    # which every backup refuses with "Lockfile found: Backup is currently running". The panel
    # only ever runs one game backup at a time (serialised by a lock in app.py), so if we're here
    # and a backup.lock exists that hasn't been touched in >5 min, it's orphaned — delete it.
    # LinuxGSM writes the lock once at start and removes it on completion, so its mtime is the
    # backup's start time; a real, freshly-started backup (<5 min) is left untouched.
    precheck = (
        f"find /home/{user} -maxdepth 4 -name '*backup.lock' -mmin +5 -delete 2>/dev/null; "
    )
    # When the instance is running, LinuxGSM's `backup` warns + counts down, then STOPS the
    # server, archives it, and RESTARTS it (verified on a live box: ~1.5 min outage for a 6.5G
    # GMod install). It doesn't strictly need a y/N answer, but we feed a few harmless "y"s as a
    # safety net for any version that does prompt. The stream is bounded, so it can't hang.
    inner = precheck + f"cd /home/{user} && printf 'y\\ny\\ny\\n' | ./{selfname} backup"
    out, err, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}",
                               timeout=3600, sudo=False)
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
    out, err, rc = _core.run_command(
        server,
        f"sudo -u {user} bash -c {_core._quote(f'cd /home/{user} && ./{selfname}')}",
        timeout=30, sudo=False,
    )
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
    out, _, _ = _core.run_as_game_user(server, user, "details 2>&1", timeout=45, selfname=selfname)
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


def get_server_status(server, game_server):
    """Get the status of a LinuxGSM game server.

    LinuxGSM has no `status` command; `details` prints a "Status: STARTED/STOPPED"
    line, so we run that and parse it."""
    out, err, rc = _core.run_as_game_user(
        server, game_server.short_name, "details 2>&1", timeout=30,
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
                return "online"
            if "stopped" in low:
                return "offline"
    return "unknown"
