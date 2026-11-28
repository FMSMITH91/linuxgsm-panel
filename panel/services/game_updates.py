"""A game server's own updates: whether a newer build of the game is out, read with LinuxGSM's check-update.

ONE SOURCE OF TRUTH. note_output() takes every check-update output the panel sees (the server page's
check-update, the daily check below, Check now on the Updates page) and after_run() every update's; seen() is what
the Updates page, its count and the nightly window read. So the server page's check-update and the Updates row
always say the same thing.

WHAT LINUXGSM PRINTS (v26.6.0, every updater: core_steamcmd.sh for Steam games, update_<game>.sh for the rest).
After "Checking for update" comes "Update available" or "No update available", then "* Local build: <x>",
"* Remote build: <y>", and on Steam "* Branch: <b>" and the game's SteamDB history link. Nothing it prints marks a
build as a security fix, so a game row is never marked as a security update.

WHAT AN UPDATE COSTS. command_update.sh's fn_update_apply runs only when the two builds differ: it stops a running
server, downloads, and starts it again only if it was running. A stopped server stays stopped. check-update reads
the builds only and never stops the server.

THE DAILY CHECK (check_pass, from the nightly window's loop every 5 minutes): at most one server per pass, the one
checked longest ago, each about once a day (CHECK_EVERY; a check that got no answer again after CHECK_RETRY), never
while the panel runs another action on it (busy_reason: the same holds every action path asks). Each check makes the
host ask Steam or the game's own source, so it has its own Outside services switch (GAME_UPDATE_CHECK). What it
read is kept in memory: after a panel restart every server is read again, one per pass.

AUTOMATIC UPDATES IN THE NIGHTLY WINDOW, by family (default_auto; the reason is shown beside the switch):
    Steam games: on. Players' Steam clients update themselves, and a server behind them refuses them.
    Minecraft (Java, Bedrock, and LinuxGSM's Paper, Velocity and Waterfall), OpenRA, Vintage Story: off. Players
        need the same release: a new one locks out players who have not updated, and can break plugins and mods.
    The other games LinuxGSM updates from their own releases: on, as OWASP recommends.
OWASP Top 10 2025 A03 Software Supply Chain Failures asks for timely patching and a patch management process; the
recommended value (on) is shown beside every switch, and off is a note, never a block.
"""
import re
import threading
import time

from panel.core import terminal

CHECK_EVERY = 24 * 3600
CHECK_RETRY = 6 * 3600
_SEEN = {}                # server id -> {"at", "state", "local", "remote", "branch", "appid"}
_SECS = {}                # server id -> how long its last applied update took, in seconds
_LOCK = threading.Lock()

# LinuxGSM's own updaters (command_update.sh): every other game is updated through SteamCMD.
OWN_UPDATERS = frozenset(("ts3", "mc", "mcb", "pmc", "vpmc", "wmc", "fctr", "fivem", "hyt", "mta", "jk2", "jk3",
                          "luanti", "orar", "vints", "bfe", "bb", "ut99", "xnt", "qw", "etl"))
MINECRAFT = frozenset(("mc", "mcb", "pmc", "vpmc", "wmc"))
SAME_RELEASE = frozenset(("orar", "vints"))
WHY_STEAM = "On by default: players' Steam clients update themselves, and a server behind them refuses them."
WHY_MINECRAFT = ("Off by default: a new Minecraft release can lock out players whose game is older, and break plugins "
                 "and mods. Update it when you are ready.")
WHY_SAME = ("Off by default: players need the same release as the server, so a new one locks out players who have "
            "not updated yet, and can break mods. Update it when you are ready.")
WHY_OTHER = ("On by default, as OWASP recommends: LinuxGSM installs this game's new releases from its own "
             "project. Switch it off if a release ever breaks your mods.")

_STATE_RE = re.compile(r"^\s*(No update|Update) available\s*$", re.M)
_BUILD_WORD = r"([A-Za-z0-9][A-Za-z0-9._+:-]{0,63})\s*$"
_LOCAL_RE = re.compile(r"^\s*\*\s*Local build:\s*" + _BUILD_WORD, re.M)
_REMOTE_RE = re.compile(r"^\s*\*\s*Remote build:\s*" + _BUILD_WORD, re.M)
_BRANCH_RE = re.compile(r"^\s*\*\s*Branch:\s*" + _BUILD_WORD, re.M)
_STEAMDB_RE = re.compile(r"https://steamdb\.info/app/([0-9]{1,10})/history")


def family(game_type):
    """Return the update family: "steam", "minecraft", "same" (players need the same release) or "own" (LinuxGSM's updater)."""
    gt = (game_type or "").lower()
    if gt in MINECRAFT:
        return "minecraft"
    if gt in SAME_RELEASE:
        return "same"
    return "own" if gt in OWN_UPDATERS else "steam"


def default_auto(game_type):
    """(on, why): automatic game updates' default for the game's family and the sentence that says why."""
    return {"steam": (True, WHY_STEAM), "minecraft": (False, WHY_MINECRAFT), "same": (False, WHY_SAME),
            "own": (True, WHY_OTHER)}[family(game_type)]


def parse(out):
    """{"state": "available" | "none" | "unknown", "local", "remote", "branch", "appid"} from LinuxGSM's output."""
    text = terminal.strip_escapes(out or "").replace("\r", "\n")
    found = _STATE_RE.findall(text)
    got = {"state": "unknown", "local": "", "remote": "", "branch": "", "appid": ""}
    if not found:
        return got
    for key, rx in (("local", _LOCAL_RE), ("remote", _REMOTE_RE), ("branch", _BRANCH_RE), ("appid", _STEAMDB_RE)):
        m = rx.search(text)
        got[key] = m.group(1) if m else ""
    got["state"] = "available" if found[-1] == "Update" else "none"
    return got


def note_output(gs_id, out, now=None):
    """Remember what a check-update's output says for server `gs_id`. -> the parsed result."""
    got = parse(out)
    with _LOCK:
        old = _SEEN.get(gs_id) or {}
        if got["state"] == "unknown" and old.get("state") in ("available", "none"):
            # A check that got no answer keeps what was known, and is tried again sooner.
            _SEEN[gs_id] = dict(old, at=time.time() if now is None else now, failed=True)
        else:
            _SEEN[gs_id] = dict(got, at=time.time() if now is None else now, failed=got["state"] == "unknown")
    return got


def after_run(gs_id, action, out, rc, done, secs=None):
    """After an update ran (`done`: LinuxGSM did not postpone it): the server is on the build it printed.

    An update prints the same lines as check-update before it applies them; one that exited 0 is on the remote build
    now, so its row goes. A failed one keeps its row. `secs` (an applied update's run time) prices the next one.
    Returns the build an applied update installed ("" when none was applied, or its build was not printed).
    """
    if action not in ("update", "force-update") or not done or rc != 0:
        return ""
    got = parse(out)
    if got["state"] == "unknown":
        return ""
    if got["state"] == "available" and secs:
        with _LOCK:
            _SECS[gs_id] = max(1, int(secs))
    with _LOCK:
        _SEEN[gs_id] = dict(got, state="none", local=got["remote"] or got["local"], at=time.time(), failed=False)
    return got["remote"] if got["state"] == "available" else ""


def seen(gs_id):
    """What the last check-update or update of `gs_id` said ({} when the panel has not read it yet)."""
    with _LOCK:
        return dict(_SEEN.get(gs_id) or {})


def update_minutes(gs_id):
    """How many minutes the server's last applied update took (rounded up), or None when not measured yet."""
    with _LOCK:
        secs = _SECS.get(gs_id)
    return None if not secs else max(1, -(-secs // 60))


def forget(gs_id):
    """Drop what was read for a server (it was removed, or its id may be handed out again)."""
    with _LOCK:
        _SEEN.pop(gs_id, None)
        _SECS.pop(gs_id, None)


def due_for_check(gs_id, now=None):
    """Whether the daily check should read `gs_id` now: never read, read a day ago, or its last read failed."""
    got = seen(gs_id)
    if not got:
        return True
    age = (time.time() if now is None else now) - got.get("at", 0)
    return age >= (CHECK_RETRY if got.get("failed") else CHECK_EVERY)


def check_order(ids, now=None):
    """The servers in `ids` whose daily check is due, the one read longest ago first (never-read ones first)."""
    due = [i for i in ids if due_for_check(i, now)]
    return sorted(due, key=lambda i: (seen(i).get("at", 0), i))


# ── reading a server: the busy gate, then LinuxGSM's check-update as the game account ──────────
def busy_reason(gs):
    """Why no LinuxGSM command may run on `gs` now ("" when it may): the holds every action path asks first.

    Installing or not installed, its host's clean reboot, a scheduled wipe or a restore, an uninstall (all
    server_detail._r40_action_blocked), any action the panel registered on it (an update, a backup, a queued stop),
    a backup the panel's runners hold, a queued update; then the account's write refusal (it runs LinuxGSM as the
    game account).
    """
    from panel.core.panel_state import r36j_route_jobs
    from panel.routes._shared import _backup_in_progress, game_account_write_refusal
    from panel.routes.server_detail import _r40_action_blocked
    blocked = _r40_action_blocked(gs, gs.remote, "check-update")
    if blocked:
        return str(blocked)
    if r36j_route_jobs(gs.id) or _backup_in_progress(gs.id) or getattr(gs, "update_pending", False):
        return "another action of the panel is running on it"
    why = game_account_write_refusal(gs.remote, gs.short_name)
    return str(why) if why else ""


def check_server(gs):
    """Run check-update on `gs` (never stops it) and note what it said. -> the parsed result, or None when busy."""
    from panel.ops import ssh_manager as _sm
    if busy_reason(gs):
        return None
    try:
        out, err, _rc = _sm.run_as_game_user(gs.remote, gs.short_name, "check-update", timeout=110,
                                             selfname=gs.lgsm_name)
    except Exception:  # noqa: BLE001 - a host that did not answer is tried again later
        out, err = "", ""
    return note_output(gs.id, (out or "") + "\n" + (err or ""))


def _installed_ids():
    from panel.db.models import GameServer
    return [i for (i,) in GameServer.query.with_entities(GameServer.id).filter(GameServer.installed.is_(True)).all()]


def check_pass(now=None):
    """The daily check: read the one installed server whose check is most overdue and not busy. -> its id or None.

    Each host then asks Steam or the game's own source: Settings -> Outside services can switch it off.
    """
    from panel.core import outside_services as _outside
    from panel.db.models import GameServer, db
    if not _outside.enabled(_outside.GAME_UPDATE_CHECK):
        return None
    for gs_id in check_order(_installed_ids(), now):
        gs = db.session.get(GameServer, gs_id)
        if gs is not None and gs.remote is not None and check_server(gs) is not None:
            return gs_id
    return None
