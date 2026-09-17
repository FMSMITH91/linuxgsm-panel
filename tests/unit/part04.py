"""Part 4 of the unit suite. Imported for its side effects."""
from unit.part01 import (N, NS, SO, _Path, _command_arg, _parse_tg_command, _sm_core, _sm_cron, _sm_files, _sm_game, _sm_gmod, _sm_hosts, _valid_ip_or_cidr, _whitelisted, check, config, eq, os)  # noqa: F401,E402
from unit.part02 import (_pre)  # noqa: F401,E402
from unit.part03 import (_GS, _app, _orig_disc_rc, _so)  # noqa: F401,E402
from unit import REPO_ROOT as _UNIT_ROOT  # noqa: E402
try:
    _sm_core.run_command = lambda *a, **k: (
        "FOUND|gmodserver|gmodserver|27015|3|2|4|1\n"
        "FOUND|myrust|rustserver|28015|0|0|0|0\n"
        "some unrelated line\n"
        "FOUND|shortline|gmodserver|0\n"          # missing the count fields -> skipped
        "FOUND|zeroport|csgoserver|0|0|0|0|0\n", "", 0)
    _disc = _sm_core.discover_linuxgsm_servers(None)
    eq("discover: keeps only well-formed (8-field) FOUND lines", len(_disc), 3)
    check("discover: parses user / lgsm_name / port + backup/mod/cron counts + autostart",
          _disc[0] == {"user": "gmodserver", "lgsm_name": "gmodserver", "port": 27015,
                       "backups": 3, "mods": 2, "cron": 4, "autostart": True})
    check("discover: a 0/blank port becomes None and autostart is False",
          _disc[2]["user"] == "zeroport" and _disc[2]["port"] is None
          and _disc[2]["autostart"] is False)
    _sm_core.run_command = lambda *a, **k: ("", "err", 1)
    check("discover: returns [] when the scan command fails", _sm_core.discover_linuxgsm_servers(None) == [])
finally:
    _sm_core.run_command = _orig_disc_rc

# ── content_box_users: telling a GMod content box from real servers ──────────────────────────
# A content box installs each mountable game through LinuxGSM, so every one of them carries the
# exact signature discovery looks for. Seven of them under one account filled the import table with
# seven "servers" that were nothing of the kind — and could not have been imported anyway, since a
# host's servers are keyed on the Linux user. Classified by SHAPE, never by username: the content
# user is whatever the host already had.
_cb = _sm_gmod.content_box_users


def _f(user, name):
    return {"user": user, "lgsm_name": name}


_box = [_f("srcds", n) for n in ("cssserver", "dodsserver", "hl2dmserver", "hldmsserver",
                                 "l4dserver", "l4d2server", "tf2server")]
check("content box: an account holding several mountable games is content, not servers",
      _cb(_box) == {"srcds"}, repr(_cb(_box)))
check("content box: ...whatever it is called — the name is never the test",
      _cb([_f("steam", "cssserver"), _f("steam", "tf2server")]) == {"steam"})
check("content box: a lone real server under its own user is NOT a content box",
      _cb([_f("cssbox", "cssserver")]) == set())
check("content box: ...so a one-game host still offers its server for import",
      _cb([_f("mygmod", "gmodserver")]) == set())
check("content box: the panel's own content account counts even with one game",
      _cb([_f("gmodcontent", "cssserver")]) == {"gmodcontent"})
check("content box: an account mixing content with a real server is left alone",
      _cb([_f("mixed", "cssserver"), _f("mixed", "rustserver")]) == set())
check("content box: a GMod server is not content, however many sit beside it",
      _cb([_f("g", "gmodserver"), _f("g", "cssserver")]) == set())
check("content box: several accounts are judged independently",
      _cb(_box + [_f("realtf2", "tf2server")]) == {"srcds"})
check("content box: empty / malformed scan output yields nothing",
      _cb([]) == set() and _cb([{"user": "", "lgsm_name": ""}]) == set() and _cb(None) == set())
check("content box: every installable content game is recognised",
      _sm_gmod.CONTENT_LGSM_NAMES >= {"cssserver", "tf2server", "l4d2server"}
      and "gmodserver" not in _sm_gmod.CONTENT_LGSM_NAMES)

# ── LinuxGSM's data files: fetched and cached, not vendored ───────────────────────────────────
# serverlist.csv and ubuntu-24.04.csv are LinuxGSM's. They used to be committed here, which froze
# the panel's game list at whatever upstream shipped that day — it was two games behind by the time
# this replaced it. Everything below points the cache at a TEMP DIRECTORY and seeds it, so this
# suite never touches the network and the assertions are about the panel's parsing rather than
# about whatever upstream happens to contain today.
from panel.services import lgsm_data as _lgd
import tempfile as _lgd_tempfile
_lgd_dir = _lgd_tempfile.mkdtemp()
_lgd._CACHE_DIR = _Path(_lgd_dir)   # pathlib via this file, not reached through the module
_lgd._mem.clear()
(_lgd._CACHE_DIR).mkdir(parents=True, exist_ok=True)
_SERVERLIST_FIXTURE = ("shortname,gameservername,gamename,os\n"
                       "gmod,gmodserver,Garry's Mod,ubuntu-24.04\n"
                       "rust,rustserver,Rust,ubuntu-24.04\n"
                       "cod,codserver,Call of Duty,ubuntu-24.04\n")
_DEPS_FIXTURE = "all,bc,binutils,curl\nsteamcmd,lib32gcc-s1,steamcmd\ngmod,lib32tinfo6\n"
(_lgd._CACHE_DIR / _lgd.SERVERLIST).write_text(_SERVERLIST_FIXTURE, encoding="utf-8")
(_lgd._CACHE_DIR / _lgd.DEPS).write_text(_DEPS_FIXTURE, encoding="utf-8")
# Reading must NOT reach the network when a fresh cache is on disk.
_lgd_fetches = []
_lgd_real_fetch = _lgd._fetch          # the tests below put this back to exercise it for real
_lgd._fetch = lambda name: (_lgd_fetches.append(name), None)[1]
_lgd._mem.clear()
eq("lgsm data: a fresh cache is read without fetching", len(_lgd.serverlist()), 3)
eq("lgsm data: ...and no network call was made", _lgd_fetches, [])
eq("lgsm data: the deps csv parses into {key: [packages]}", _lgd.deps().get("steamcmd"),
   ["lib32gcc-s1", "steamcmd"])

# A fetch that "succeeds" but returns something else — a captive portal, an error page, a truncated
# body — must never be cached. Replacing the game list with an HTML login page would leave the
# panel with no games and no clue why.
_html = "<!doctype html><html><head><title>Sign in</title></head><body>" + ("x" * 400) + "</body></html>"
check("lgsm data: an HTML page is not accepted as the serverlist",
      _lgd._looks_like(_lgd.SERVERLIST, _html) is False)
check("lgsm data: a truncated body is not accepted", _lgd._looks_like(_lgd.SERVERLIST, "shortname,") is False)
check("lgsm data: the real shape IS accepted",
      _lgd._looks_like(_lgd.SERVERLIST, "shortname,gameservername,gamename,os\n" + ("a,b,c,d\n" * 30)) is True)
# 200 bytes minimum, so the fixture has to be a realistic size — a few short lines would be
# rejected by the length check before the shape check ever ran.
check("lgsm data: the deps file has its own shape check",
      _lgd._looks_like(_lgd.DEPS, "all,bc,binutils,curl,file,tar\n" + ("gameserver,libfoo,libbar\n" * 30)) is True
      and _lgd._looks_like(_lgd.DEPS, _html) is False)

# The shape check has to be WIRED IN, not merely correct. Testing _looks_like on its own passed
# happily with the call removed from _fetch, which would have cached a captive portal's login page
# as the game list.
_lgd._mem.clear()
_lgd._fetch = _lgd_real_fetch          # the stub above would make both checks below meaningless
_orig_urlopen_lgd = _lgd.urllib.request.urlopen


class _FakeResp:
    def __init__(self, body):
        self._b = body.encode()
        self.status = 200
    def read(self, _n=None):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


_lgd.urllib.request.urlopen = lambda req, timeout=None: _FakeResp(_html)
check("lgsm data: _fetch REJECTS a body that is not the file it asked for",
      _lgd._fetch(_lgd.SERVERLIST) is None)
_good_csv = "shortname,gameservername,gamename,os\n" + ("a%d,a%dserver,Game %d,ubuntu-24.04\n" % (1, 1, 1)) * 40
_lgd.urllib.request.urlopen = lambda req, timeout=None: _FakeResp(_good_csv)
check("lgsm data: ...and accepts a real one", _lgd._fetch(_lgd.SERVERLIST) is not None)
_lgd.urllib.request.urlopen = _orig_urlopen_lgd
_lgd._fetch = lambda name: (_lgd_fetches.append(name), None)[1]   # back to "the network is down"

# A failed fetch must stay retryable. Memoising [] would make one bad moment permanent for the
# life of the process, so the Retry button and the background warm could never recover.
_app._GAME_LIST_CACHE["games"] = None
_app._LGSM_NAME_MAP["data"] = None
_lgd._mem.clear()
_lgd_saved = _lgd.serverlist
_lgd.serverlist = lambda *a, **k: []
eq("lgsm data: a failed fetch yields an empty game list", _app.load_game_list(), [])
check("lgsm data: ...and is NOT memoised, so a retry can still succeed",
      _app._GAME_LIST_CACHE["games"] is None)
_lgd.serverlist = _lgd_saved
_lgd._mem.clear()
_app._GAME_LIST_CACHE["games"] = None
check("lgsm data: ...and the retry does succeed once the data is back",
      len(_app.load_game_list()) == 3, len(_app.load_game_list()))

# ── the package list is PER DISTRO ────────────────────────────────────────────────────────────
# LinuxGSM publishes ubuntu-22.04.csv, ubuntu-26.04.csv, debian-12.csv and twenty more. The panel
# used to hard-code ubuntu-24.04 for every host, so a 22.04 box was handed 24.04's packages — and
# one package that does not exist on that release takes the whole apt transaction down with it.
# This panel officially supports 22.04, 24.04 and 26.04, so that was not hypothetical.
eq("deps: a host's own distro picks its own file", _lgd.deps_name("ubuntu-22.04"), "ubuntu-22.04.csv")
eq("deps: another distro entirely", _lgd.deps_name("debian-12"), "debian-12.csv")
eq("deps: no slug falls back to the default", _lgd.deps_name(None), "ubuntu-24.04.csv")
# The slug comes from the REMOTE host's /etc/os-release and is interpolated into a URL, so a
# compromised host must not be able to steer that request anywhere.
for _bad in ("../../etc/passwd", "ubuntu-24.04/../x", "http://evil.example/x", "UBUNTU-24.04",
             "a" * 40 + "-1", "ubuntu-24.04;id", "", "/absolute-1"):
    eq("deps: %r cannot steer the fetch" % _bad[:18], _lgd.deps_name(_bad), "ubuntu-24.04.csv")
# Per-distro results must not collide in the cache.
_lgd._mem.clear()
(_lgd._CACHE_DIR / "ubuntu-22.04.csv").write_text(
    "all,bc,jammy-only-pkg\n" + ("g%d,p%d\n" % (1, 1)) * 30, encoding="utf-8")
eq("deps: the 22.04 list is its own, not the default one",
   _lgd.deps("ubuntu-22.04").get("all"), ["bc", "jammy-only-pkg"])
eq("deps: ...and the default is still the default",
   _lgd.deps(None).get("all"), ["bc", "binutils", "curl"])

# A stale cache with no network beats no list at all.
import os as _os_lgd
_os_lgd.utime(_lgd._CACHE_DIR / _lgd.SERVERLIST, (0, 0))   # ancient
_lgd._mem.clear(); _lgd_fetches.clear()
eq("lgsm data: a stale cache is still served when the refetch fails", len(_lgd.serverlist()), 3)
check("lgsm data: ...and it did try to refresh first", _lgd_fetches == [_lgd.SERVERLIST], _lgd_fetches)

# ── lgsm_name_to_game_type: gameservername -> panel game_type, from LinuxGSM's serverlist ──
_app._LGSM_NAME_MAP["data"] = None
_app._GAME_LIST_CACHE["games"] = None
check("lgsm-name map: gmodserver -> gmod", _app.lgsm_name_to_game_type("gmodserver") == "gmod")
check("lgsm-name map: rustserver -> rust", _app.lgsm_name_to_game_type("rustserver") == "rust")
check("lgsm-name map: an unknown script -> None", _app.lgsm_name_to_game_type("notagameserver") is None)

# ── GameServer.supports_update: drives the (bulk) Update button + backend skip per game ──
check("supports_update: fetched list exposing 'update' -> True",
      _GS(commands='[{"cmd":"update"},{"cmd":"start"}]').supports_update is True)
check("supports_update: fetched list with no 'update' -> False",
      _GS(commands='[{"cmd":"start"},{"cmd":"stop"}]').supports_update is False)
check("supports_update: empty list + known no-update game (cod) -> False",
      _GS(commands='[]', game_type='cod').supports_update is False)
check("supports_update: empty list + SteamCMD game -> True (fail open)",
      _GS(commands='[]', game_type='csgo').supports_update is True)

# ── list_server_commands: parse LinuxGSM's command menu. This is what populates the
#    "Supported Commands" panel; import now auto-caches it in the background, so lock in
#    that a realistic menu (with ANSI colour + non-menu noise lines) parses correctly. ──
_LGSM_MENU = (
    "\x1b[0m./gmodserver [option]\n"
    "start         st   | Start the server.\n"
    "stop          sp   | Stop the server.\n"
    "update        u    | Check and apply any updates.\n"
    "some banner line without a pipe here\n"
    "details       dt   | Display server information.\n"
)
_saved_run = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: (_LGSM_MENU, "", 0)
    _parsed = _sm_game.list_server_commands(NS(), "gmodserver")
finally:
    _sm_core.run_command = _saved_run
_pc = {c["cmd"]: c for c in _parsed}
check("list_server_commands: parses start (with short code)",
      _pc.get("start", {}).get("short") == "st")
check("list_server_commands: parses update", "update" in _pc)
eq("list_server_commands: captures description", _pc.get("details", {}).get("desc"),
   "Display server information.")
check("list_server_commands: ignores the ./script header + no-pipe banner lines",
      "some" not in _pc and "gmodserver" not in _pc and len(_pc) == 4)

# ── player moderation: engine-aware caps, status/list parsers + injection-safe commands ──
check("moderation: gmod (valve) supports kick + ban + say",
      _sm_game.moderation_caps("gmod") == {"kick": True, "ban": True, "say": True})
check("moderation: minecraft supports kick + ban + say",
      _sm_game.moderation_caps("mc") == {"kick": True, "ban": True, "say": True})
check("moderation: cod (idTech3) supports kick + ban + say",
      _sm_game.moderation_caps("cod") == {"kick": True, "ban": True, "say": True})
check("moderation: a non-console game (rust) supports nothing",
      _sm_game.moderation_caps("rust") == {"kick": False, "ban": False, "say": False})
check("engine: gmod->valve, cod->idtech3, mc->minecraft, rust->''",
      (_sm_game.game_engine("gmod"), _sm_game.game_engine("cod"), _sm_game.game_engine("mc"), _sm_game.game_engine("rust"))
      == ("valve", "idtech3", "minecraft", ""))
check("moderation: cod is now queryable (via console); a game with neither engine nor gamedig is not",
      _sm_game.is_player_queryable("cod") is True and _sm_game.is_player_queryable("nosuchgame") is False)
check("moderation: console metacharacters are stripped from a name (no injection)",
      _sm_game._mod_sanitize('a;b"c`d\ne') == "abcde")

# per-engine status/list parsers (sample output — I can't live-fire each engine)
_SRC = ('# userid name uniqueid connected ping loss state adr\n'
        '#  2 "Alice" STEAM_0:1:12345 15:30 45 0 active 5.6.7.8:27005\n'
        '#  5 "Bob ^S" [U:1:99] 02:11 67 0 active 9.9.9.9:27005\n'
        '#  7 "aBot" BOT 00:00 0 0 active\n')
check("parser(valve): names + steamids (legacy / modern / bot-empty)",
      [(p["name"], p["steamid"]) for p in _sm_game._parse_valve_status(_SRC)]
      == [("Alice", "STEAM_0:1:12345"), ("Bob ^S", "[U:1:99]"), ("aBot", "")])
_COD = ('num score ping guid                             name            lastmsg address       qport rate\n'
        '--- ----- ---- -------------------------------- --------------- ------- ------------- ----- ----\n'
        '  0     5   45 1100001aaaaaaaaaaaaaaaaaaaaaaaaa ^1Alice^7             0 5.6.7.8:28960 12345 25000\n'
        '  1     0   67 1100001bbbbbbbbbbbbbbbbbbbbbbbbb Bob Smith            50 9.9.9.9:28961 54321 25000\n')
check("parser(idtech3): slot numbers + names (colours stripped, spaces kept)",
      [(p["num"], p["name"]) for p in _sm_game._parse_idtech3_status(_COD)] == [(0, "Alice"), (1, "Bob Smith")])
_MC = "[12:34:56] [Server thread/INFO]: There are 2 of a max of 20 players online: Alice, Bob_1"
check("parser(minecraft): names from a prefixed log line",
      [p["name"] for p in _sm_game._parse_minecraft_list(_MC)] == ["Alice", "Bob_1"])
check("parser(minecraft): empty server -> no players",
      _sm_game._parse_minecraft_list("There are 0 of a max of 20 players online: ") == [])

# _gamedig_host: Source servers reply to A2S from the host's real IP, so a 127.0.0.1 query is
# silently dropped — the panel must query the host's primary IP. (run_command runs the awk pipeline
# remotely, so the stub returns what awk WOULD emit: just the IP, or nothing.)
class _FakeRemote:
    def __init__(self, rid): self.id = rid
_orig_rc = _sm_core.run_command
try:
    _sm_core._gamedig_host_cache.clear()
    _sm_core.run_command = lambda *a, **k: ("45.76.63.211\n", "", 0)
    check("gamedig-host: uses the host's primary IP, not 127.0.0.1",
          _sm_core._gamedig_host(_FakeRemote(9001)) == "45.76.63.211")
    _sm_core._gamedig_host_cache.clear()
    _sm_core.run_command = lambda *a, **k: ("", "", 0)          # no default route / no output
    check("gamedig-host: falls back to 127.0.0.1 when the IP can't be resolved",
          _sm_core._gamedig_host(_FakeRemote(9002)) == "127.0.0.1")
    _sm_core._gamedig_host_cache.clear()
    _calls = {"n": 0}
    def _counting_rc(*a, **k):
        _calls["n"] += 1
        return ("10.0.0.5\n", "", 0)
    _sm_core.run_command = _counting_rc
    _r = _FakeRemote(9003)
    _sm_core._gamedig_host(_r); _sm_core._gamedig_host(_r)
    check("gamedig-host: caches per remote (one lookup, not one per query)", _calls["n"] == 1)
finally:
    _sm_core.run_command = _orig_rc
    _sm_core._gamedig_host_cache.clear()

# _tmux_live_socket_sh: LinuxGSM leaves a stale <selfname>-<random> socket behind on every restart,
# so the console targeting must pick the socket with a LIVE session (via has-session) rather than the
# first match — otherwise send-keys/capture-pane hit a dead socket and kick/ban/say/status all no-op.
_snip = _sm_core._tmux_live_socket_sh("gmodserver")
check("tmux-socket: verifies a live session instead of grabbing the first socket",
      "has-session -t gmodserver" in _snip and "grep -m1" not in _snip)
check("tmux-socket: still signals NO_SESSION when nothing is live",
      "NO_SESSION" in _snip and "exit 3" in _snip)

# ensure_persistent_bans: a banid ban only survives a restart if the server config execs
# banned_user.cfg — this appends that (idempotently) to the resolved servercfg (${selfname}.cfg).
_orig_lgv2, _orig_rc3 = _sm_files.lgsm_get_values, _sm_core.run_command
try:
    _sm_files.lgsm_get_values = lambda *a, **k: {"servercfg": "${selfname}.cfg"}
    _pb = {}
    _sm_core.run_command = lambda server, cmd, timeout=15, sudo=False: (_pb.__setitem__("cmd", cmd), ("", "", 0))[1]
    _ok_pb = _sm_game.ensure_persistent_bans(object(), "gmodserver2", "gmodserver")
    check("persistent-bans: targets the resolved servercfg, adds the exec, guards duplicates",
          _ok_pb is True and "*/cfg/gmodserver.cfg" in _pb["cmd"]
          and "exec banned_user.cfg" in _pb["cmd"] and "grep -qiE" in _pb["cmd"])
finally:
    _sm_files.lgsm_get_values, _sm_core.run_command = _orig_lgv2, _orig_rc3

# game_map: a separate cached gamedig read for the current map, kept out of the player-count path.
_orig_rc5 = _sm_core.run_command
try:
    _sm_cron._game_map_cache.clear(); _sm_core.run_command = lambda *a, **k: ("de_dust2\n", "", 0)
    check("game-map: parses the map name from gamedig", _sm_cron.game_map(object(), "u", "css", 27015) == "de_dust2")
    _sm_cron._game_map_cache.clear(); _sm_core.run_command = lambda *a, **k: ("null\n", "", 0)
    check("game-map: 'null'/empty gamedig output -> ''", _sm_cron.game_map(object(), "u", "css", 27015) == "")
    _sm_cron._game_map_cache.clear(); _sm_core.run_command = lambda *a, **k: ("<b>gm_x\n", "", 0)
    check("game-map: strips angle brackets from game-supplied text",
          "<" not in _sm_cron.game_map(object(), "u", "css", 27015) and ">" not in _sm_cron.game_map(object(), "u", "css", 27015))
    check("game-map: no gamedig type/port -> '' (no query)", _sm_cron.game_map(object(), "u", "css", None) == "")
finally:
    _sm_core.run_command = _orig_rc5; _sm_cron._game_map_cache.clear()

# player_list: gamedig is PRIMARY (no console spam). The console is a backup used ONLY when the
# caller explicitly passes allow_console=True (a user action) — the automatic path (default) never
# touches the console: it returns None ('unknown') so the UI shows a GSLT hint instead of querying.
_orig_cpl, _orig_gpl = _sm_game.console_player_list, _sm_game._gamedig_player_list
try:
    _sm_game.console_player_list = lambda *a, **k: [{"name": "Ace"}]
    _sm_game._gamedig_player_list = lambda *a, **k: [{"name": "Zed", "steamid": "", "num": None,
                                                "score": None, "time": None}]
    check("player_list: gamedig is primary — the console isn't touched when gamedig answers",
          [p["name"] for p in _sm_game.player_list(None, "u", "cod", 28960, None, "codserver")] == ["Zed"])
    _sm_game._gamedig_player_list = lambda *a, **k: []   # gamedig says the server is empty
    check("player_list: a gamedig-confirmed empty server does NOT fall back to the console",
          _sm_game.player_list(None, "u", "cod", 28960, None, "codserver") == [])
    _sm_game._gamedig_player_list = lambda *a, **k: None  # gamedig couldn't query at all
    check("player_list: the automatic path is gamedig-only — no console, returns None when unread",
          _sm_game.player_list(None, "u", "cod", 28960, None, "codserver") is None)
    check("player_list: the console backup runs ONLY when allow_console=True (an explicit action)",
          [p["name"] for p in _sm_game.player_list(None, "u", "cod", 28960, None, "codserver",
                                             allow_console=True)] == ["Ace"])
finally:
    _sm_game.console_player_list, _sm_game._gamedig_player_list = _orig_cpl, _orig_gpl

# injection-safe command building, dispatched by engine
_msent = {}
_orig_scc = _sm_core.send_console_command
_orig_cpl_m = _sm_game.console_player_list
try:
    _sm_core.send_console_command = lambda *a, **k: (_msent.__setitem__("cmd", a[2]), ("", "", 0))[1]
    _sm_game.moderate(None, "u", "gmod", "kick", target='Bad;Guy"x')
    check("moderation: valve kick quotes the sanitized name (injection neutralised)",
          _msent.get("cmd") == 'kick "BadGuyx"')
    _sm_game.moderate(None, "u", "gmod", "ban", steamid="STEAM_0:1:5; rcon x")
    check("moderation: valve ban bans + kicks the re-validated SteamID only (injection stripped)",
          _msent.get("cmd") == "banid 0 STEAM_0:1:5 kick; writeid")
    check("moderation: valve ban with no SteamID and no name is refused",
          _sm_game.moderate(None, "u", "gmod", "ban", steamid="")[0] is False)
    _sm_game.moderate(None, "u", "cod", "kick", num="3")
    check("moderation: idTech3 kick is clientkick <slot>", _msent.get("cmd") == "clientkick 3")
    _sm_game.moderate(None, "u", "cod", "ban", num="3")
    check("moderation: idTech3 ban is banclient <slot>", _msent.get("cmd") == "banclient 3")
    check("moderation: idTech3 with a junk slot and no name is refused",
          _sm_game.moderate(None, "u", "cod", "ban", num="3; quit")[0] is False)
    _sm_game.moderate(None, "u", "mc", "ban", target="Steve")
    check("moderation: minecraft ban is a bare name command", _msent.get("cmd") == "ban Steve")
    check("moderation: a non-console game (rust) refuses moderation",
          _sm_game.moderate(None, "u", "rust", "ban", target="x")[0] is False)
    # on-demand id resolution: a gamedig-sourced list carries no ids, so kick/ban looks the player
    # up on the console by name and uses the slot / SteamID it finds there.
    _sm_game.console_player_list = lambda *a, **k: [{"name": "Ace", "num": 4, "steamid": "STEAM_0:1:9"}]
    _msent.clear()
    _sm_game.moderate(None, "u", "cod", "kick", target="Ace")   # no num supplied
    check("moderation: idTech3 kick resolves the slot from the console when given only a name",
          _msent.get("cmd") == "clientkick 4")
    _msent.clear()
    _sm_game.moderate(None, "u", "gmod", "ban", target="Ace")   # no steamid supplied
    check("moderation: valve ban resolves the SteamID from the console when given only a name",
          _msent.get("cmd") == "banid 0 STEAM_0:1:9 kick; writeid")
finally:
    _sm_core.send_console_command = _orig_scc
    _sm_game.console_player_list = _orig_cpl_m

# ── gamedig query type: per-server override wins over the built-in map, sanitized ──
check("query-type: an explicit override wins over the built-in map",
      _sm_cron._gamedig_type("gmod", "customtype") == "customtype")
check("query-type: unmapped game with no override -> '' (no gamedig type)",
      _sm_cron._gamedig_type("noquerygame", None) == "")
check("query-type: a mapped game with no override uses the map",
      _sm_cron._gamedig_type("gmod", None) == "garrysmod")
check("query-type: the override is sanitized to a gamedig-safe charset",
      _sm_cron._gamedig_type("cod", "co d;rm -rf") == "codrm-rf")
check("query-type: the Call of Duty family is mapped, so its player count (restart/backup) works",
      _sm_cron._gamedig_type("cod", None) == "cod" and _sm_cron._gamedig_type("cod4", None) == "cod4")
check("query-type: a game with neither engine nor map becomes queryable once an override is set",
      _sm_game.is_player_queryable("nosuchgame", None) is False
      and _sm_game.is_player_queryable("nosuchgame", "quake3") is True)

# ── change_ssh_port: input validation rejects bad ports BEFORE touching the host ──
check("ssh-port: non-numeric rejected", _sm_hosts.change_ssh_port(None, "abc")[0] is False)
check("ssh-port: port 0 rejected", _sm_hosts.change_ssh_port(None, 0)[0] is False)
check("ssh-port: port 70000 (out of range) rejected", _sm_hosts.change_ssh_port(None, 70000)[0] is False)
check("ssh-port: negative port rejected", _sm_hosts.change_ssh_port(None, -5)[0] is False)
check("ssh-port: invalid bind IP rejected", _sm_hosts.change_ssh_port(None, 2222, "not-an-ip")[0] is False)
check("valid-ip: accepts IPv4", _sm_hosts._valid_ip("192.168.1.5") is True)
check("valid-ip: accepts IPv6", _sm_hosts._valid_ip("::1") is True)
check("valid-ip: rejects junk", _sm_hosts._valid_ip("nope") is False)
check("valid-ip: rejects host:port form", _sm_hosts._valid_ip("1.2.3.4:22") is False)

# ── db_maintenance: offline SQLite check / repair / optimize (updater + health card) ──
import db_maintenance as _dbm
import sqlite3 as _sq3
import tempfile as _tf
import shutil as _sh

_dbm_dir = _tf.mkdtemp(prefix="dbm-")


def _mk_db(p, rows=40):
    c = _sq3.connect(p)
    try:
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany("INSERT INTO t (v) VALUES (?)", [("x" * 80,) for _ in range(rows)])
        c.commit()
    finally:
        c.close()


def _garbage(p, n=9000):
    with open(p, "wb") as f:
        f.write(os.urandom(n))


try:
    _good = os.path.join(_dbm_dir, "good.db")
    _mk_db(_good)
    check("db-maint: a healthy DB passes integrity_check", _dbm.integrity_check(_good)[0] is True)
    check("db-maint: a missing DB counts as healthy (fresh install)",
          _dbm.integrity_check(os.path.join(_dbm_dir, "nope.db"))[0] is True)
    _garbage(os.path.join(_dbm_dir, "bad.db"))
    check("db-maint: a non-database file is flagged as unhealthy",
          _dbm.integrity_check(os.path.join(_dbm_dir, "bad.db"))[0] is False)
    check("db-maint: optimize a healthy DB succeeds", _dbm.optimize(_good)[0] is True)

    # repair a healthy DB → rebuilds it, and it stays healthy
    _rep_ok, _ = _dbm.repair(_good, None)
    check("db-maint: repair rebuilds a DB that verifies healthy",
          _rep_ok is True and _dbm.integrity_check(_good)[0] is True)

    # corrupt DB + healthy backup → restores the backup, keeps the corrupt copy aside
    _main = os.path.join(_dbm_dir, "main.db")
    _garbage(_main)
    _bkp = _main + ".backup"
    _mk_db(_bkp, rows=8)
    _r2_ok, _ = _dbm.repair(_main, _bkp)
    _aside = any(f.startswith("main.db.corrupt-") for f in os.listdir(_dbm_dir))
    check("db-maint: repair restores a healthy backup when a rebuild can't salvage",
          _r2_ok is True and _dbm.integrity_check(_main)[0] is True and _aside)

    # unsalvageable + no backup → fails safely, original never deleted
    _m2 = os.path.join(_dbm_dir, "m2.db")
    _garbage(_m2)
    _r3_ok, _ = _dbm.repair(_m2, os.path.join(_dbm_dir, "absent.backup"))
    check("db-maint: repair fails safely (keeps the original) when nothing is salvageable",
          _r3_ok is False and os.path.exists(_m2))
finally:
    _sh.rmtree(_dbm_dir, ignore_errors=True)

# ── granular moderation permissions + custom-command scope/argument safety ──
import re as _re
from types import SimpleNamespace as _NS
from panel.security.auth import can_moderate_action, _custom_command_scope_matches
from panel.db.models import CUSTOM_ARG_DEFAULT_PATTERN


class _FakeGroup:
    def __init__(self, perms):
        self._p = set(perms)

    def get_permissions(self):
        return self._p


def _u(perms=(), superadmin=False):
    return _NS(is_superadmin=superadmin, groups=[_FakeGroup(perms)])


# A mod granted ONLY kick can kick, but not ban or announce.
_kicker = _u(["kick_player"])
check("mod perm: kick_player -> can kick", can_moderate_action(_kicker, "kick"))
check("mod perm: kick_player -> can NOT ban", not can_moderate_action(_kicker, "ban"))
check("mod perm: kick_player -> can NOT say", not can_moderate_action(_kicker, "say"))
# The umbrella moderate_server (legacy groups) still grants all three.
_umb = _u(["moderate_server"])
check("mod perm: umbrella grants kick+ban+say",
      can_moderate_action(_umb, "kick") and can_moderate_action(_umb, "ban")
      and can_moderate_action(_umb, "say"))
# Full console access implies moderation; no perms implies none; superadmin gets all.
check("mod perm: send_command implies ban", can_moderate_action(_u(["send_command"]), "ban"))
check("mod perm: no perms -> cannot kick", not can_moderate_action(_u([]), "kick"))
check("mod perm: superadmin can do everything",
      can_moderate_action(_u(superadmin=True), "ban"))

# Custom-command scope matching (all / by engine / by game).
_cod2 = _NS(game_type="cod2")
_gmod = _NS(game_type="gmod")
check("cmd scope all -> matches any game",
      _custom_command_scope_matches(_NS(scope_type="all", scope_value=""), _cod2))
check("cmd scope game=cod2 -> matches cod2",
      _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _cod2))
check("cmd scope game=cod2 -> does NOT match gmod",
      not _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _gmod))
check("cmd scope engine=idtech3 -> matches cod2 (idTech3)",
      _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _cod2))
check("cmd scope engine=idtech3 -> does NOT match gmod (valve)",
      not _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _gmod))

# Argument charset: real map/entity names pass; anything that could break out of the console
# line (metacharacters, spaces, command substitution, empty) is rejected.
_arg_ok = lambda v: _re.fullmatch(CUSTOM_ARG_DEFAULT_PATTERN, v) is not None
check("custom arg: map name accepted", _arg_ok("mp_toujane"))
check("custom arg: dotted/dashed accepted", _arg_ok("de_dust2-v2.1"))
check("custom arg: rejects ; injection", not _arg_ok("a;rm -rf /"))
check("custom arg: rejects command substitution", not _arg_ok("$(reboot)"))
check("custom arg: rejects backtick", not _arg_ok("`id`"))
check("custom arg: rejects spaces", not _arg_ok("mp toujane"))
check("custom arg: rejects newline", not _arg_ok("a\nb"))
check("custom arg: rejects empty", not _arg_ok(""))

# ── panel branch-switch: git-ref name validation (fed to git + the root installer) ──
# _so is the `import system_ops as _so` from the integrity-tests section above.
check("branch: main valid", _so._valid_branch("main"))
check("branch: feature/x valid", _so._valid_branch("feature/moderation-permissions"))
check("branch: release/v1.2.3 valid", _so._valid_branch("release/v1.2.3"))
check("branch: rejects leading dash (option injection)", not _so._valid_branch("-oProxyCommand=x"))
check("branch: rejects traversal", not _so._valid_branch("a..b"))
check("branch: rejects space", not _so._valid_branch("a b"))
check("branch: rejects ; metachar", not _so._valid_branch("a;reboot"))
check("branch: rejects command substitution", not _so._valid_branch("$(id)"))
check("branch: rejects empty", not _so._valid_branch(""))

# ── cleanup: remove key/config files this run created ─────────
for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE):
    if p not in _pre and os.path.exists(p):
        try:
            p.unlink()
        except OSError:
            pass

# ── Notifications: SSRF guards, provider validation, and event-key wiring ──
import pathlib as _pl   # noqa: E402

# Discord webhook is rebuilt onto a CONSTANT host from a validated id/token (no user-controlled host).
check("notify: valid discord webhook is accepted + kept on discord.com",
      N._discord_api_url("https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
      == "https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
check("notify: discordapp.com webhook is canonicalised to discord.com",
      N._discord_api_url("https://discordapp.com/api/webhooks/123456789012/tok_ABCdef")
      == "https://discord.com/api/webhooks/123456789012/tok_ABCdef")
check("notify: SSRF - an internal host is rejected",
      N._discord_api_url("https://169.254.169.254/api/webhooks/123456789012/x") is None)
check("notify: SSRF - a non-webhook discord path is rejected",
      N._discord_api_url("https://discord.com/evil") is None)
check("notify: SSRF - _post refuses a non-allow-listed host",
      N._post("https://evil.example.com/x", b"", {}) == (False, "blocked"))
check("notify: SSRF - _post refuses a non-https URL",
      N._post("http://api.telegram.org/botX/sendMessage", b"", {})[0] is False)
# Telegram token/chat validation short-circuits before any network call.
check("notify: telegram rejects a malformed bot token",
      N.send_telegram("not-a-real-token", "123456", "hi")[0] is False)
check("notify: telegram rejects an empty chat id",
      N.send_telegram("123456:AAABBBCCCDDDEEEFFF_gg-hh", "", "hi")[0] is False)
# EVENTS registry shape, and every notify() call in app.py uses a registered key (a typo'd key would
# silently never fire — like a data-action with no handler).
check("notify: EVENTS entries are (label:str, default:bool)",
      all(isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], bool)
          for v in N.EVENTS.values()))
_app_src = (_pl.Path(_UNIT_ROOT) / "app.py").read_text(encoding="utf-8")
_used_keys = set(_re.findall(r'notifications\.notify\(\s*"(\w+)"', _app_src))
check("notify: every notify() key in app.py is registered in EVENTS",
      _used_keys and _used_keys <= set(N.EVENTS), "unregistered: %s" % sorted(_used_keys - set(N.EVENTS)))

# The global 'enabled' master switch was removed (a channel's own toggle is the on/off). The one-time
# migration must PRESERVE a previously-muted state: master off -> disable both channels, then drop the
# key — otherwise removing the gate would silently start sending to still-enabled channels.
_m_off = {"enabled": False, "telegram": {"enabled": True}, "discord": {"enabled": True}}
check("master-switch drop: was off -> both channels disabled + key removed",
      N._drop_master_switch(_m_off) is True and "enabled" not in _m_off
      and _m_off["telegram"]["enabled"] is False and _m_off["discord"]["enabled"] is False)
_m_on = {"enabled": True, "telegram": {"enabled": True}, "discord": {"enabled": False}}
check("master-switch drop: was on -> channels untouched, key removed",
      N._drop_master_switch(_m_on) is True and "enabled" not in _m_on
      and _m_on["telegram"]["enabled"] is True and _m_on["discord"]["enabled"] is False)
_m_none = {"telegram": {"enabled": True}}
check("master-switch drop: already migrated (no key) -> no change",
      N._drop_master_switch(_m_none) is False and _m_none == {"telegram": {"enabled": True}})

# Alert thresholds: disk %/mem % are real percents (<=99); CPU 'load' is a per-core loadavg % that can
# exceed 100; load_mins is the sustained window. Each is clamped to its own range with defaults.
_orig_thr_cfg = N._cfg
try:
    N._cfg = lambda: {}
    check("thresholds: sensible defaults when unset",
          N.get_thresholds() == {"disk_pct": 90, "load_pct": 200, "mem_pct": 90, "load_mins": 5})
    N._cfg = lambda: {"thresholds": {"disk_pct": 250, "mem_pct": 250, "load_pct": 250, "load_mins": 999}}
    _thi = N.get_thresholds()
    check("thresholds: disk % and mem % are capped at 99 (real percentages)",
          _thi["disk_pct"] == 99 and _thi["mem_pct"] == 99)
    check("thresholds: CPU load may exceed 100% (loadavg-based, ceiling 800)", _thi["load_pct"] == 250)
    check("thresholds: the sustained-minutes window is capped at 120", _thi["load_mins"] == 120)
    N._cfg = lambda: {"thresholds": {"load_pct": 5, "load_mins": 0}}
    _thlo = N.get_thresholds()
    check("thresholds: values below the floor clamp up (load>=50, mins>=1)",
          _thlo["load_pct"] == 50 and _thlo["load_mins"] == 1)
finally:
    N._cfg = _orig_thr_cfg
# The monitor's sustained window maps minutes -> consecutive passes at the 60s monitor cadence.
import app as _app_thr  # noqa: E402
check("thresholds: 60s monitor cadence means load_mins == required consecutive passes",
      _app_thr._MONITOR_SECONDS == 60 and max(1, round(10 * 60 / _app_thr._MONITOR_SECONDS)) == 10)

# ── Login-security whitelist + auto-block threshold ──
import ipaddress as _ipaddr  # noqa: E402

check("whitelist: a bare IP is accepted + canonicalised", _valid_ip_or_cidr("  1.2.3.4 ") == "1.2.3.4")
check("whitelist: a CIDR is accepted + canonicalised to its network", _valid_ip_or_cidr("10.0.0.5/24") == "10.0.0.0/24")
check("whitelist: junk / empty is rejected", _valid_ip_or_cidr("not-an-ip") is None and _valid_ip_or_cidr("") is None)
check("whitelist: an out-of-range octet is rejected", _valid_ip_or_cidr("999.1.1.1") is None)
_wl_nets = [_ipaddr.ip_network("10.0.0.0/8"), _ipaddr.ip_network("203.0.113.7")]
check("whitelist: a CIDR entry covers an address inside it", _whitelisted("10.1.2.3", _wl_nets) is True)
check("whitelist: an exact-IP entry matches that IP", _whitelisted("203.0.113.7", _wl_nets) is True)
check("whitelist: an address outside every entry does not match", _whitelisted("8.8.8.8", _wl_nets) is False)
check("whitelist: a non-IP string never matches", _whitelisted("garbage", _wl_nets) is False)

# The fail2ban ignoreip line is built ONLY from entries that re-parse as an IP/CIDR — defence-in-depth
# so no attacker-influenced token can ever be written into the root-owned jail file.
_ign = SO._f2b_ignoreip_line(["1.2.3.4", "10.0.0.0/8", "evil; rm -rf /", "$(whoami)", "not-an-ip"])
check("f2b: ignoreip always includes localhost", "127.0.0.1/8" in _ign and "::1" in _ign)
check("f2b: ignoreip keeps the valid IP + CIDR entries", "1.2.3.4" in _ign and "10.0.0.0/8" in _ign)
check("f2b: ignoreip drops every non-IP token (no shell metachars reach the jail file)",
      not any(bad in _ign for bad in (";", "$", "rm", "whoami", "not-an-ip")))
_jail = SO._panel_f2b_jail_body("/data/auth.log", 5000, ["1.2.3.4", "junk"])
check("f2b: the jail body carries an ignoreip line with the valid entry only",
      "\nignoreip = " in _jail and "1.2.3.4" in _jail and "junk" not in _jail)

# top-offenders parsing: the counting pipeline emits "<attempts>\t<bans>\t<ip>\t<jail,jail>"; each row
# must surface which fail2ban jail(s) caught the IP. Old 3-field lines (no jail) parse with jails=[].
_top = SO._parse_top_ips("9\t3\t1.2.3.4\tsshd,recidive\n5\t0\t5.6.7.8\tpanel-login\n2\t0\t9.9.9.9",
                         banned_now={"1.2.3.4"}, blocked={"5.6.7.8": "panel-block"})
check("f2b top: attempts/bans/ip parse in order",
      [(r["ip"], r["attempts"], r["bans"]) for r in _top]
      == [("1.2.3.4", 9, 3), ("5.6.7.8", 5, 0), ("9.9.9.9", 2, 0)])
check("f2b top: the jail column surfaces every jail that caught the IP",
      _top[0]["jails"] == ["sshd", "recidive"] and _top[1]["jails"] == ["panel-login"])
check("f2b top: a legacy 3-field line (no jail) parses with an empty jail list",
      _top[2]["jails"] == [])
check("f2b top: banned_now / blocked flags still track the passed-in sets",
      _top[0]["banned_now"] is True and _top[1]["blocked"] is True and _top[2]["blocked"] is False)

# Telegram command parsing: normalise '/Cmd@Bot arg' to a bare lowercase verb; non-commands -> ''.
check("telegram: /update parses to 'update'", _parse_tg_command("/update") == "update")
check("telegram: a bot-mention + args is stripped", _parse_tg_command("/Update@MyBot now") == "update")
check("telegram: /STATUS is lowercased", _parse_tg_command("/STATUS") == "status")
check("telegram: a non-command is empty", _parse_tg_command("hello there") == "" and _parse_tg_command("") == "")
check("telegram: /restart <name> extracts the argument", _command_arg("/restart my server") == "my server")
check("telegram: a bare command has no argument", _command_arg("/status") == "")

# ── The one-line summary a completion message carries ─────────────────────────────────────────
# A backgrounded action now reports back when it lands, and what it reports is one line of
# LinuxGSM's output. LinuxGSM prints its logo first and its verdict last, so the head is always
# the banner and the tail is always the answer.
from panel.routes.server_detail import _summarise_action_output as _sao  # noqa: E402
check("bots: an action summary keeps LinuxGSM's verdict, which is its LAST line",
      _sao("[ LinuxGSM ] csgoserver\nStarting csgoserver\nFailed to start\n") == "Failed to start",
      _sao("[ LinuxGSM ] csgoserver\nStarting csgoserver\nFailed to start\n"))
check("bots: trailing blank lines don't become the summary",
      _sao("Server started\n\n   \n") == "Server started", repr(_sao("Server started\n\n   \n")))
check("bots: no output summarises to nothing, not to a placeholder",
      _sao("") == "" and _sao(None) == "")
# A chat message is capped; an action that spews one enormous line must not blow past it.
check("bots: a runaway line is truncated for the chat message",
      len(_sao("x" * 5000)) == 200, len(_sao("x" * 5000)))

# Both bots share ONE ack-wording table, so the two can't drift into saying different things for
# the same command.
from panel.services.bots.commands import (_ACTION_ACK as _AACK, _WORKING_ACK as _WACK,  # noqa: E402
                                          action_ack as _aack, working_ack as _wack)
check("bots: every action ack has a slot for the server name",
      all(v.count("%s") == 1 for v in _AACK.values()), _AACK)
check("bots: the slow read commands are acked and the database-only ones are not",
      set(_WACK) == {"players", "console", "say"}, sorted(_WACK))
# Both routers ask these two rather than indexing the tables, so which commands announce
# themselves is decided once, for both bots, instead of per transport.
check("bots: working_ack names a slow command", _wack("console") == _WACK["console"])
check("bots: working_ack stays silent for a command that answers from the database",
      _wack("status") is None and _wack("servers") is None and _wack("connect") is None)
check("bots: working_ack shrugs off a command it has never heard of", _wack("nonsense") is None)
check("bots: action_ack fills in the server name",
      _aack("restart", "codserver") == "🔄 codserver — restarting…", _aack("restart", "codserver"))
# The fallback is the point: an unknown action still has to say SOMETHING, because the ack is all
# that stands between the user and a silent minute.
check("bots: an action with no wording still acks rather than going quiet",
      "codserver" in _aack("validate", "codserver"), _aack("validate", "codserver"))

# telegram_set_commands registers the '/' autocomplete menu via setMyCommands (through _post).
import json as _json_tg  # noqa: E402
_tg_posts = []
_orig_post = N._post
try:
    N._post = lambda url, data, headers: (_tg_posts.append((url, data)), (True, "sent"))[1]
    check("telegram: set_commands posts to setMyCommands with the registered command set",
          N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh")
          and _tg_posts[-1][0].endswith("/setMyCommands")
          and {c["command"] for c in _json_tg.loads(_tg_posts[-1][1].decode())["commands"]}
          == {c for c, _ in N.TG_COMMANDS})
    N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh", clear=True)
    check("telegram: set_commands(clear=True) sends an empty command list",
          _json_tg.loads(_tg_posts[-1][1].decode())["commands"] == [])
    check("telegram: set_commands rejects a malformed token", N.telegram_set_commands("nope") is False)
finally:
    N._post = _orig_post

# ── Discord command bot (Gateway): parsing, SSRF-safe reply path, and the message pump ──
from panel.services.bots.discord import _parse_dc_command  # noqa: E402

# Command parsing accepts either '!' (types cleanly — Discord reserves '/') or '/'; mention + args stripped.
check("discord: !status parses to 'status'", _parse_dc_command("!status") == "status")
check("discord: a '/' prefix also parses", _parse_dc_command("/restart foo") == "restart")
check("discord: a bot-mention + args is stripped + lowercased", _parse_dc_command("!Restart@bot Now") == "restart")
check("discord: a non-command / bare prefix is empty",
      _parse_dc_command("hello") == "" and _parse_dc_command("! ") == "" and _parse_dc_command("") == "")

# The bot reply URL is rebuilt onto the CONSTANT discord.com host with a digits-only channel id, and the
# same _ALLOWED_PREFIXES barrier that guards the webhook sender now also covers the /channels/ API.
check("discord: bot message URL is built on the constant host from a snowflake channel id",
      N._discord_bot_message_url("112233445566778899")
      == "https://discord.com/api/v10/channels/112233445566778899/messages")
check("discord: SSRF - a non-numeric / traversal channel id is rejected",
      N._discord_bot_message_url("../evil") is None and N._discord_bot_message_url("") is None)
check("discord: SSRF - the bot channels URL sits on an allow-listed prefix",
      "https://discord.com/api/v10/channels/1/messages".startswith(N._ALLOWED_PREFIXES))
check("discord: SSRF - a discord.com look-alike host is not allow-listed",
      not "https://discord.com.evil.example/api/x".startswith(N._ALLOWED_PREFIXES))

# The bot token only ever rides in an Authorization header — the charset forbids whitespace/newlines so
# it can't inject one, and it's loose on the internal '.'-separated shape so future formats still pass.
# A dotted, real-shaped fixture that is deliberately NOT a valid Discord token layout (lowercase, wrong
# segment lengths) so GitHub push-protection doesn't flag it — it only needs to exercise the charset.
check("discord: a plausible bot token validates",
      N._valid_discord_bot_token("panel.fixture.not_a_real_token_" + "a" * 30))
check("discord: a bot token with a space is rejected", not N._valid_discord_bot_token("has a space " + "x" * 40))
check("discord: a bot token with a newline (header injection) is rejected",
      not N._valid_discord_bot_token("tok\nX-Evil: 1 " + "x" * 40))

# discord_bot_send validates BEFORE any network call, and posts to the constant host with a Bot header.
_dc_posts = []
_orig_post2 = N._post
try:
    N._post = lambda url, data, headers: (_dc_posts.append((url, headers)), (True, "sent"))[1]
    _ok_send, _ = N.discord_bot_send("A" * 50, "112233445566778899", "hi")
    check("discord: a bot reply posts to the constant discord.com channels API",
          _ok_send and _dc_posts[-1][0] == "https://discord.com/api/v10/channels/112233445566778899/messages")
    check("discord: a bot reply carries an 'Authorization: Bot' header",
          _dc_posts[-1][1].get("Authorization", "").startswith("Bot "))
    check("discord: bot send rejects a malformed channel id without a network call",
          N.discord_bot_send("A" * 50, "../evil", "hi")[0] is False)
    check("discord: bot send rejects a malformed token without a network call",
          N.discord_bot_send("bad token", "112233445566778899", "hi")[0] is False)
finally:
    N._post = _orig_post2


# The Gateway pump: HELLO -> IDENTIFY (with the message-content intent) -> deliver MESSAGE_CREATE to the
# handler -> return on EOF. A fake socket stands in for the WebSocket so no network is touched.
class _FakeWS:
    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []
    def recv(self):
        return self._frames.pop(0) if self._frames else ""   # "" == EOF -> the loop breaks
    def send(self, s):
        self.sent.append(s)
    def close(self):
        pass


_dc_seen = []
_fake_ws = _FakeWS([
    '{"op":10,"d":{"heartbeat_interval":600000}}',
    '{"op":0,"s":1,"t":"MESSAGE_CREATE","d":{"channel_id":"999","author":{"bot":false},"content":"!status"}}',
])
N.discord_gateway_run("A" * 50, lambda ch, is_bot, content, author=None: _dc_seen.append((ch, is_bot, content)),
                      _connect=lambda: _fake_ws)
check("discord: the gateway IDENTIFYs with the message-content intent",
      any('"op": 2' in s and str(N._DISCORD_INTENTS) in s for s in _fake_ws.sent))
check("discord: a MESSAGE_CREATE is delivered to the handler with (channel, is_bot, content)",
      _dc_seen == [("999", False, "!status")])
check("discord: the message-content intent bit (1<<15) is set", N._DISCORD_INTENTS & (1 << 15))

# player_slots parses gamedig's compact JSON into (count, max, name); a name with spaces/quotes
# round-trips and junk output is rejected. run_command is stubbed so no SSH/gamedig is needed.
_orig_rc = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ('{"c":7,"m":24,"n":"[EU] Bob\'s \\"Fun\\" Server","ok":true}', "", 0)
    check("player_slots: parses count/max/name from gamedig JSON",
          _sm_cron.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo")
          == (7, 24, "[EU] Bob's \"Fun\" Server"))
    _sm_core.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":true}', "", 0)
    check("player_slots: null max + empty name -> (0, None, None)",
          _sm_cron.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (0, None, None))
    # A gamedig FAILURE ({"error":...} -> ok=false) is 'unknown', NOT 0 players, so the caller can
    # fall back to the console instead of showing a bogus 0.
    _sm_core.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":false}', "", 0)
    check("player_slots: a failed query (ok=false) -> (None, None, None), not a fake 0",
          _sm_cron.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
    _sm_core.run_command = lambda *a, **k: ("not json", "", 0)
    check("player_slots: junk output -> (None, None, None)",
          _sm_cron.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
finally:
    _sm_core.run_command = _orig_rc

# Global ban: console_steamid_ban builds the right native ban/unban command from a VALIDATED SteamID,
# and refuses junk before anything reaches the console (send_console_command is stubbed to record it).
_gb_cmds = []
_orig_scc = _sm_core.send_console_command
try:
    _sm_core.send_console_command = lambda server, user, command, timeout=20, selfname=None: (_gb_cmds.append(command), ("", "", 0))[1]
    _ok, _reason = _sm_game.console_steamid_ban(object(), "u", "csgoserver", "STEAM_0:1:5")
    check("global-ban: ban builds 'banid 0 <id> kick; writeid'",
          _ok and _gb_cmds[-1] == "banid 0 STEAM_0:1:5 kick; writeid")
    _sm_game.console_steamid_ban(object(), "u", "csgoserver", "[U:1:11]", unban=True)
    check("global-ban: unban builds 'removeid <id>; writeid'", _gb_cmds[-1] == "removeid [U:1:11]; writeid")
    check("global-ban: an invalid SteamID is rejected before the console",
          _sm_game.console_steamid_ban(object(), "u", "s", "garbage; rm -rf") == (False, "invalid"))
finally:
    _sm_core.send_console_command = _orig_scc

# The REMOTE ignoreip drop-in (pushed to remotes over SSH) is built from the same validated entries.
_dropin = _sm_hosts._f2b_dropin_ignoreip_body(["9.9.9.9", "10.0.0.0/8", "bad; rm -rf /"])
check("remote-f2b: drop-in is a [DEFAULT] ignoreip block including localhost",
      "[DEFAULT]" in _dropin and "ignoreip = " in _dropin and "127.0.0.1/8" in _dropin)
check("remote-f2b: drop-in keeps the valid IP + CIDR entries", "9.9.9.9" in _dropin and "10.0.0.0/8" in _dropin)
check("remote-f2b: drop-in drops non-IP tokens (no shell metachars in the file)",
      not any(bad in _dropin for bad in (";", "$", "rm", "bad")))

# ── The maintenance probe that keeps a scheduled LinuxGSM update from reading as a crash. The
# monitor tests stub this function out wholesale, so the shell command it builds — the one place a
# real bug can hide — is only ever asserted here.
# Patch the module the function actually RESOLVES run_command from. _lgsm_maintenance_running
# used to live in app.py, so patching app.run_command intercepted it; it lives in monitoring now
# and looks the name up in monitoring's namespace, so patching app's would silently no-op and the
# stub would never be called. (That is exactly how this test failed during the move.)
from panel.services import monitoring as _mapp
from panel.services.monitoring import _lgsm_maintenance_running as _lmr

_sent = []


def _fake_run(remote, cmd, timeout=None):
    _sent.append(cmd)
    return ("BUSY\n", "", 0)


_GS = lambda **kw: NS(**dict(dict(short_name="gmodserver", game_type="gmod", name="Gmod",
                                  lgsm_name="gmodserver"), **kw))
_orig_rc = _mapp.run_command
try:
    _mapp.run_command = _fake_run
    check("maintenance probe: a running force-update reads as busy", _lmr(object(), _GS()) is True)
    _cmd = _sent[-1]
    check("maintenance probe: pgrep is scoped to that server's OWN unix user",
          "pgrep -u gmodserver " in _cmd or "pgrep -u 'gmodserver' " in _cmd, _cmd)
    check("maintenance probe: it matches the lgsm script name followed by a maintenance command",
          "gmodserver (update|force-update|" in _cmd, _cmd)
    check("maintenance probe: monitor is NOT a maintenance command (it would mute every alert)",
          "|monitor" not in _cmd and "(monitor" not in _cmd, _cmd)
    check("maintenance probe: update-lgsm is NOT one either — it never stops the server",
          "update-lgsm" not in _cmd, _cmd)

    _mapp.run_command = lambda remote, cmd, timeout=None: ("IDLE\n", "", 0)
    check("maintenance probe: nothing running reads as idle", _lmr(object(), _GS()) is False)

    # The command text itself contains the word BUSY, so a substring test would latch on forever.
    _mapp.run_command = lambda remote, cmd, timeout=None: ("echo BUSYIDLE\nIDLE\n", "", 0)
    check("maintenance probe: an echoed command line is not mistaken for a busy answer",
          _lmr(object(), _GS()) is False)

    def _boom(remote, cmd, timeout=None):
        raise OSError("host unreachable")

    _mapp.run_command = _boom
    check("maintenance probe: a probe that cannot answer must NOT hide a real outage",
          _lmr(object(), _GS()) is False)

    _mapp.run_command = _fake_run
    check("maintenance probe: no unix user -> no probe at all",
          _lmr(object(), _GS(short_name="")) is False)
    check("maintenance probe: no game type -> no probe (a bare 'server' pattern would over-match)",
          _lmr(object(), _GS(game_type="", lgsm_name="server")) is False)
    _sent.clear()
    _lmr(object(), _GS(short_name="", game_type=""))
    check("maintenance probe: the guards short-circuit before any SSH round trip", not _sent)

    # short_name/game_type are pinned to [A-Za-z0-9._-]; "." is the one ERE metacharacter that fits.
    _sent.clear()
    _lmr(object(), _GS(game_type="cs.source", lgsm_name="cs.sourceserver"))
    check("maintenance probe: a dot in the name is matched literally, not as 'any character'",
          "cs[.]sourceserver" in _sent[-1], _sent[-1])
finally:
    _mapp.run_command = _orig_rc

# ── API tokens: only a HASH is ever stored ────────────────────────────────────────────────────
# Bearer tokens authenticate scripts as their owner and inherit that user's full RBAC, and app.py
# exempts Bearer requests from CSRF — yet nothing exercised any of it. These are the pure half; the
# lookup half (a disabled owner, a replayed hash) is asserted against the real DB in smoke_test.
import hashlib as _hl
from panel.db.models import User as _U, RemoteServer as _RS

_tu = _U(username="tok", password_hash="x")
_plain = _tu.generate_api_token()
check("api token: the minted token is handed back in plaintext, once",
      isinstance(_plain, str) and _plain.startswith("lgsm_") and len(_plain) >= 32, _plain[:12])
check("api token: the plaintext is NOT what gets stored", _tu.api_token != _plain)
check("api token: what IS stored is its sha256 — a leaked DB yields no usable token",
      _tu.api_token == _hl.sha256(_plain.encode()).hexdigest())
_plain2 = _tu.generate_api_token()
check("api token: minting again replaces the old one", _plain2 != _plain and
      _tu.api_token == _hl.sha256(_plain2.encode()).hexdigest())
check("api token: has_api_token reports the stored state", _tu.has_api_token is True)
_tu.revoke_api_token()
check("api token: revoking clears it", _tu.api_token is None and _tu.has_api_token is False)

# ── Pinned SSH host key: the fingerprint an operator eyeballs before trusting a host ───────────
import base64 as _b64
_blob = b"\x00\x00\x00\x07ssh-rsa" + bytes(range(256)) * 2
_key = "ssh-rsa " + _b64.b64encode(_blob).decode()
_want = "ssh-rsa SHA256:" + _b64.b64encode(_hl.sha256(_blob).digest()).decode().rstrip("=")
eq("host key: the fingerprint is sha256 of the DECODED key, in OpenSSH form",
   _RS(host_key=_key).host_key_fingerprint, _want)
check("host key: it is the base64 digest, not hex, and unpadded",
      ":" in _want and "=" not in _want.split(":")[1] and len(_want.split(":")[1]) == 43, _want)
eq("host key: nothing pinned yet reads as empty, not as an error",
   _RS(host_key="").host_key_fingerprint, "")
for _bad in ("not base64 !!!", "ssh-rsa", "ssh-rsa ***", "\x00\xff"):
    eq("host key: malformed pin %r degrades to empty rather than raising" % _bad[:14],
       _RS(host_key=_bad).host_key_fingerprint, "")

# ── File manager: the protected-path guard on `rm -rf` ────────────────────────────────────────
# delete_path deletes the RESOLVED absolute path, so the guard has to judge the resolved path too.
# It used to read the raw string: "./lgsm" and "x/../serverfiles" looked like ordinary sub-paths
# while resolving onto the LinuxGSM control tree and the entire game install.
_SELF = "csgoserver"
for _p in ("lgsm", "lgsm/data", "/lgsm", "lgsm/", "serverfiles", "linuxgsm.sh", _SELF,
           ".ssh", ".bashrc", "", "/", ".", "..", "../..", "a/../.."):
    check("file guard: %r is protected from deletion" % _p,
          _sm_files._is_protected_path(_p, _SELF) is True)
# The bypasses. Each of these resolves onto something whose loss is unrecoverable.
for _p, _what in (("./lgsm", "the LinuxGSM control tree"),
                  (".//lgsm", "the LinuxGSM control tree"),
                  ("./serverfiles", "the game install"),
                  ("x/../serverfiles", "the game install"),
                  ("a/b/../../.ssh", "the host's SSH keys"),
                  ("./linuxgsm.sh", "the LinuxGSM launcher"),
                  ("./%s" % _SELF, "the server's own script")):
    check("file guard: %r cannot sneak past and take %s" % (_p, _what),
          _sm_files._is_protected_path(_p, _SELF) is True)
