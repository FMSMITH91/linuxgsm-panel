"""LinuxGSM v26.4.0's player protection, as the panel meets it: warnings, refusals, postponements.

Read from LinuxGSM's own v26.4.0 source (lgsm/modules/command_stop.sh, command_restart.sh,
command_update.sh, command_backup.sh, command_monitor.sh) and measured on the test host:

* `warnplayerstimer="N"` (minutes, 0 = off) makes every stop, restart, update and backup that stops
  a running server count down in-game first: N, then 60 30 15 10 5 3 1 below N, the stop coming N
  minutes after the first warning. It ends early only when a player COUNT reads zero; a count that
  cannot be read (querymode 1, no gamedig) warns for the whole N minutes. A forced update skips it.
  Measured with a one-minute timer: 7.9 s to stop an empty server, 66.3 s with two players on.
* `stoponlyifnoplayers="on"` with players online: `stop` prints "N players are on the server: stop
  prevented" and does nothing; `restart` prints "...: restart postponed" and leaves a
  restart-request lock that LinuxGSM's `monitor` acts on once the server is empty; `update` and
  `backup` print "Update/Backup postponed until the server is empty" and leave a request lock the
  same way; `workshop-update` is only "stop prevented" and is not retried. EVERY one of them exits
  0 (measured), so an exit code says nothing here: the output does.

LinuxGSM's messages are fixed English in its scripts (it has no translations), so they are matched
as LinuxGSM writes them; the panel's own words for each outcome are i18n Sentences.
"""
import logging
import re
import threading
import time

from panel.core import i18n, terminal
from panel.core.validation import _int_or
from panel.ops import ssh_manager as _sm

# The games whose console takes a chat command LinuxGSM can warn with: consoleinteract="yes" in the
# game's _default.cfg AND a warn command in command_stop.sh's fn_stop_warn_players_command (the
# Source, Source 2 and GoldSrc engines, plus its named games). Computed from v26.4.0's
# lgsm/data/serverlist.csv and lgsm/config-default/config-lgsm/*/_default.cfg: 82 of 144. For any
# other game LinuxGSM prints "Warning players: not supported by <game>: skipped".
WARN_GAMES = frozenset((
    "ahl", "ahl2", "av", "bb", "bb2", "bd", "bmdm", "bs", "bt", "cc", "cod", "cod2", "cod4", "coduo",
    "codwaw", "cs", "cs2", "cscz", "csgo", "css", "ct", "dab", "dmc", "dod", "dods", "doi", "dst",
    "dys", "em", "etl", "fctr", "fof", "gmod", "hl2dm", "hldm", "hldms", "hyt", "ins", "ios", "jbep3",
    "jk2", "l4d", "l4d2", "mc", "mcb", "mcv", "mohaa", "mta", "nd", "nec", "nmrih", "ns", "opfor",
    "pmc", "pvkii", "pz", "q2", "q3", "q4", "ql", "qw", "ricochet", "rtcw", "rw", "scpsl", "sfc",
    "sof2", "sven", "terraria", "tf2", "tf2c", "tfc", "ts", "unt", "vints", "vs", "wet", "wf", "wmc",
    "xnt", "zmr", "zps"))

# The games whose player LIST LinuxGSM cannot rely on. LinuxGSM counts players as the length of
# gamedig's `players` list (query_gamedig.sh: `jq -re '.players | length'`), and for these games
# that list can be empty with players on (_core.GAMEDIG_HUMANS_JQ has the measurements): Minecraft
# Bedrock's ping never carries one (mbe), a Java server hiding its players sends none (mc, pmc, wmc:
# gamedig "minecraft"), and a Source 2 / CS:GO server that does not answer A2S_PLAYER leaves it
# empty. Then LinuxGSM reads 0: "Warning players: no players on the server", and it stops at once —
# no warning — and stoponlyifnoplayers never holds anything back. So for these the panel keeps its
# own 60 s countdown before a forced reboot, and never says LinuxGSM's warning is the one.
LIST_UNRELIABLE_GAMES = frozenset(("mcb", "mc", "pmc", "wmc", "cs2", "csgo"))

# The panel's editor offers 0-60 minutes: LinuxGSM's own countdown steps start at 60.
WARN_MAX_MINUTES = 60
# A hand-written timer beyond the editor's range still gets its time, up to a day.
_LG264_ALLOWANCE_CAP_MIN = 24 * 60
# Each warning step also asks gamedig for the count and checks the session every 10 s.
_LG264_WARN_SLACK = 60
# The actions whose stop LinuxGSM warns before (fn_stop_warn_players): validate and force-update
# never warn, a start never stops.
_LG264_WARNING_ACTIONS = frozenset(("stop", "restart", "update", "backup", "workshop-update"))

_log = logging.getLogger("panel.lgsm_players")
_LG264_TTL = 600
_lg264_cache = _sm.register_remote_cache({})
_lg264_lock = threading.Lock()


def _lg264_key(server, user, selfname):
    return (getattr(server, "id", None), user, selfname or user)


def warn_minutes_value(raw):
    """Read a warnplayerstimer value as LinuxGSM does: digits are minutes, anything else is off (0).

    A hand-written run of digits too long for int() (over 4300) is not off — LinuxGSM would warn —
    so it reads as the longest the panel allows for (_LG264_ALLOWANCE_CAP_MIN), never a raise:
    the editor's read and every reboot of the host go through here.
    """
    s = str(raw or "").strip().strip("\"'")
    return _int_or(s, _LG264_ALLOWANCE_CAP_MIN) if s.isascii() and s.isdecimal() else 0


# A key every v26.4.0 _default.cfg has and no earlier release knows (v26.1.0 has none of the three):
# its presence is the release, read in the same config read. A warnplayerstimer written by hand on
# an older LinuxGSM does nothing there, so it is read as off.
_LG264_RELEASE_KEY = "stoponlyifnoplayersallcommands"


def settings(server, user, selfname, fresh=False):
    """The server's LinuxGSM player settings, cached.

    {"minutes": warnplayerstimer, "stop_only": stoponlyifnoplayers is on, "supported": its
    LinuxGSM is v26.4.0 or later}. None when its config could not be read: unknown, never "off". Before v26.4.0 both are off
    whatever the config says: that LinuxGSM has neither.
    """
    key = _lg264_key(server, user, selfname)
    now = time.time()
    with _lg264_lock:
        hit = _lg264_cache.get(key)
    if hit and hit[0] > now and not fresh:
        return dict(hit[1])
    try:
        vals = _sm.lgsm_get_values(server, user, selfname or user,
                                   ["warnplayerstimer", "stoponlyifnoplayers", _LG264_RELEASE_KEY])
    except Exception:  # noqa: BLE001 - unread is answered as unknown, never as "off"
        vals = None
    if vals is None:
        return None
    if not str(vals.get(_LG264_RELEASE_KEY) or "").strip():
        vals = {}                       # an older LinuxGSM: neither setting exists there
    return remember(server, user, selfname, vals.get("warnplayerstimer"),
                    vals.get("stoponlyifnoplayers"), supported=bool(vals))


def warn_minutes(server, user, selfname, fresh=False):
    """Return the server's warnplayerstimer in minutes, cached; None when its config was not read."""
    got = settings(server, user, selfname, fresh)
    return None if got is None else got["minutes"]


def stop_only_if_empty(server, user, selfname):
    """Whether the server's stoponlyifnoplayers is on, cached; None when its config was not read."""
    got = settings(server, user, selfname)
    return None if got is None else got["stop_only"]


def forget(server, user, selfname):
    """Drop the cached settings of one server: its config was just written."""
    with _lg264_lock:
        _lg264_cache.pop(_lg264_key(server, user, selfname), None)


def remember(server, user, selfname, raw_timer, raw_stop, supported=True):
    """Cache the two settings a config read in hand already holds (the editor's read): settings()'s dict."""
    got = {"minutes": warn_minutes_value(raw_timer) if supported else 0,
           "stop_only": supported and str(raw_stop or "").strip() == "on", "supported": supported}
    with _lg264_lock:
        _lg264_cache[_lg264_key(server, user, selfname)] = (time.time() + _LG264_TTL, got)
    return dict(got)


def allowance_seconds(server, user, selfname, action="stop"):
    """The seconds a LinuxGSM `action` may spend warning players before it stops the server.

    0 for an action that never warns, a timer that is off, and a config that could not be read:
    unknown keeps the caller's own budget, it never shortens it.
    """
    if action not in _LG264_WARNING_ACTIONS:
        return 0
    minutes = warn_minutes(server, user, selfname)
    if not minutes:
        return 0
    return min(minutes, _LG264_ALLOWANCE_CAP_MIN) * 60 + _LG264_WARN_SLACK


def timeout_for(server, user, selfname, action, base):
    """`base` seconds plus this server's warning allowance for `action`."""
    return base + allowance_seconds(server, user, selfname, action)


# ── LinuxGSM's outcome lines ────────────────────────────────────────────────────────────────────
# Each is an INFO line ("[ INFO ] Stopping codserver: 2 players are on the server: stop prevented");
# the bracket keeps a game's own text, which never comes through these commands, from matching.
_LG264_INFO = r"\[\s*INFO\s*\][^\n\r]*?"
_LG264_PLAYERS_RE = re.compile(_LG264_INFO + r"\b(\d{1,6}) players are on the server: "
                               r"(stop prevented|restart postponed)\b")
_LG264_REQUEST_RE = re.compile(_LG264_INFO + r"\b(Update|Backup) postponed until the server is empty\b")


def outcome(out):
    """What LinuxGSM's output says it did instead of the action, or None when it did the action.

    {"code": "lgsm_postponed" | "lgsm_refused", "kind": "update" | "backup" | "restart" | "stop",
     "players": int}. Postponed: LinuxGSM recorded a request its monitor acts on. Refused: nothing
    was recorded, so nothing happens unless it is asked again.
    """
    text = terminal.strip_escapes(out or "")
    m = _LG264_PLAYERS_RE.search(text)
    if m is None:
        return None
    players = int(m.group(1))
    req = _LG264_REQUEST_RE.search(text)
    if req is not None:
        return {"code": "lgsm_postponed", "kind": req.group(1).lower(), "players": players}
    if m.group(2) == "restart postponed":
        return {"code": "lgsm_postponed", "kind": "restart", "players": players}
    return {"code": "lgsm_refused", "kind": "stop", "players": players}


def outcome_of(out, rc):
    """outcome(out) for a command that exited `rc`: only an exit 0 can be one (LinuxGSM's own)."""
    return outcome(out) if rc == 0 else None


# The panel's words. A postponement is only run later by LinuxGSM's `monitor`, which is the
# server's Autostart cron (ssh_manager set_autostart): with Autostart off, nothing ever runs it.
_LG264_POSTPONED = {
    "update": i18n.Sentence("Update postponed: players are online. LinuxGSM runs it when the "
                            "server is empty."),
    "backup": i18n.Sentence("Backup postponed: players are online. LinuxGSM runs it when the "
                            "server is empty."),
    "restart": i18n.Sentence("Restart postponed: players are online. LinuxGSM restarts it when "
                             "the server is empty."),
}
_LG264_POSTPONED_NO_MONITOR = {
    "update": i18n.Sentence("Update postponed: players are online. Autostart is off for this "
                            "server, so LinuxGSM's monitor will not run it later — run it again "
                            "when the server is empty."),
    "backup": i18n.Sentence("Backup postponed: players are online. Autostart is off for this "
                            "server, so LinuxGSM's monitor will not run it later — run it again "
                            "when the server is empty."),
    "restart": i18n.Sentence("Restart postponed: players are online. Autostart is off for this "
                             "server, so LinuxGSM's monitor will not restart it later — run it "
                             "again when the server is empty."),
}
_LG264_REFUSED = {
    "stop": i18n.Sentence("Stop refused: players are online and this server's LinuxGSM setting "
                          "\"Only stop when empty\" (stoponlyifnoplayers) is on. Nothing was "
                          "stopped."),
    "workshop-update": i18n.Sentence("Workshop update not applied: players are online and "
                                     "stoponlyifnoplayers is on. Run it again when the server is "
                                     "empty."),
}
_LG264_REFUSED_OTHER = i18n.Sentence("'{action}' not run: players are online and "
                                     "stoponlyifnoplayers is on. Run it again when the server is "
                                     "empty.")


# Whether the server's Autostart is on could not be read: neither "LinuxGSM runs it" nor "nothing
# will" is known, so the sentence says what it depends on.
_LG264_POSTPONED_UNREAD = i18n.Sentence("Postponed by LinuxGSM: players are online. LinuxGSM runs it "
                                        "once the server is empty if the server's Autostart is on.")


def outcome_message(oc, action, monitor=True):
    """The panel's sentence for outcome `oc` of `action`.

    `monitor`: the server's Autostart is on (True), off (False), or could not be read (None).
    """
    if oc["code"] == "lgsm_postponed":
        if monitor is None:
            return _LG264_POSTPONED_UNREAD
        table = _LG264_POSTPONED if monitor else _LG264_POSTPONED_NO_MONITOR
        return table[oc["kind"]]
    return _LG264_REFUSED.get(action) or i18n.Sentence(_LG264_REFUSED_OTHER.template, action=action)



# ── a backup answer that knows about LinuxGSM's request ─────────────────────────────────────────
class Note(i18n.Sentence):
    """A run_game_backup message that also says what LinuxGSM's own backup request held.

    An i18n.Sentence, so every recorder keeps it as English. `code` ("lgsm_postponed": LinuxGSM holds the backup,
    "lgsm_done": LinuxGSM's monitor took it), `requested` (the host epoch of LinuxGSM's request, or
    None) and `alerted` (LinuxGSM has sent its own backup-postponed alert).
    """

    __slots__ = ("code", "requested", "alerted")


def note(sentence, code, requested=None, alerted=False):
    """`sentence` as a Note carrying `code`, `requested` and `alerted`."""
    n = Note(sentence.template, **sentence.vals)
    n.code, n.requested, n.alerted = code, requested, alerted
    return n


def note_code(msg):
    """The Note code of a backup message, or None for any other message."""
    return getattr(msg, "code", None)


# Said whenever LinuxGSM's backup request is there and its monitor is armed: that is also while
# the monitor's own backup of it runs, and after one that failed (the request goes only when an
# archive is written), so it does not claim players are on now.
BACKUP_QUEUED = i18n.Sentence("LinuxGSM holds a postponed backup of this server: its monitor runs it "
                              "once the server is empty.")
BACKUP_DONE_BY_LGSM = i18n.Sentence("Backed up by LinuxGSM once the server was empty.")


# ── the config editor's two controls (Files & Config → LinuxGSM Settings) ───────────────────────
def config_view(gs, d):
    """lgsm_read_config's answer `d` as the editor shows it: the player settings as their own controls.

    Offered only where they do something: LinuxGSM v26.4.0 or later (its `players.supported`), and
    the warning timer only on a game in WARN_GAMES. Both keys then leave the generic list, so each
    is edited in one place — except a timer already set on a game LinuxGSM cannot warn on, which
    stays there so it can be cleared. `can_count`: LinuxGSM counts players only with querymode 2 or
    3; with any other it skips its check and stops anyway (check_players_online.sh), said on the page.
    `list_unreliable`: a game whose player list LinuxGSM's count can find empty with players on
    (LIST_UNRELIABLE_GAMES), said on the page too.
    """
    pl = d.pop("players", None) or {}
    if not pl.get("supported") or d.get("error"):
        d["players"] = {"supported": False}
        return d
    warn_ok = (gs.game_type or "") in WARN_GAMES
    minutes = warn_minutes_value(pl.get("warnplayerstimer"))
    remember(gs.remote, gs.short_name, gs.lgsm_name, pl.get("warnplayerstimer"),
             pl.get("stoponlyifnoplayers"))
    _lg264_hide_keys(d, {"stoponlyifnoplayers"} | ({"warnplayerstimer"} if warn_ok or not minutes else set()))
    d["players"] = {"supported": True, "stop_only_if_empty": pl.get("stoponlyifnoplayers") == "on",
                    "warn_supported": warn_ok, "warn_minutes": minutes, "warn_max": WARN_MAX_MINUTES,
                    "can_count": pl.get("querymode") in ("2", "3"),
                    "list_unreliable": (gs.game_type or "") in LIST_UNRELIABLE_GAMES}
    d["tf2_norestart"] = _lg264_tf2_needs_norestart(gs, pl)
    return d


def _lg264_hide_keys(d, hidden):
    """Drop `hidden` keys from the editor's generic groups, and any group left empty."""
    for grp in d.get("groups") or ():
        grp["settings"] = [x for x in grp["settings"] if x.get("key") not in hidden]
    d["groups"] = [g for g in d.get("groups") or () if g["settings"]]


def _lg264_tf2_needs_norestart(gs, pl):
    """TF2 with its own startparameters lacking -norestart (v26.4.0 starts the 64-bit server).

    Without it a stop falls back to killing the session after 60 s (the v26.4.0 release notes).
    """
    return (gs.game_type == "tf2" and bool(pl.get("startparameters_set"))
            and "-norestart" not in (pl.get("startparameters") or "").split())


def bad_setting(settings):
    """Why a posted stoponlyifnoplayers / warnplayerstimer value is refused, or None.

    A good timer is written back as LinuxGSM reads it ("005" -> "5").
    """
    if settings.get("stoponlyifnoplayers", "on") not in ("on", "off"):
        return i18n.Sentence("stoponlyifnoplayers must be on or off.")
    if "warnplayerstimer" not in settings:
        return None
    minutes = _lg264_minutes(settings["warnplayerstimer"])
    if minutes is None:
        return i18n.Sentence("The warning time must be a whole number of minutes from 0 to {max}.",
                             max=WARN_MAX_MINUTES)
    settings["warnplayerstimer"] = str(minutes)
    return None


def _lg264_minutes(v):
    """A posted timer as whole minutes 0..WARN_MAX_MINUTES, or None. A JSON int counts; a bool does not.

    A JSON true/false is an int to isinstance, and its str() is "True"/"False", which the
    isdecimal() test refuses.
    """
    if isinstance(v, int):
        v = str(v)
    if not (isinstance(v, str) and v.isascii() and v.isdecimal() and len(v) <= 3):
        return None
    return int(v) if int(v) <= WARN_MAX_MINUTES else None


# ── the clean reboot (host_reboot) ──────────────────────────────────────────────────────────────
def reboot_warn_fields(remote, gs, probe):
    """What a forced reboot's stop of server `gs` tells its players first (the dialog's lines).

    Only for a running one (probe session 1), else {}. warn_minutes: LinuxGSM's warnplayerstimer
    (None: unread); stop_only_if_empty: its stoponlyifnoplayers, which makes LinuxGSM refuse a
    plain stop while players are on — a forced reboot sets it aside for its stop (reboot_stop), so
    the server is still stopped cleanly; warn_supported: its game is in WARN_GAMES; lgsm_supported:
    its LinuxGSM is v26.4.0 or later (False: it has no warning setting to point to); lgsm_counts:
    LinuxGSM can count its players (not LIST_UNRELIABLE_GAMES), without which its warning may not
    run; say: the panel's own 60 s countdown (host_reboot COUNTDOWN) reaches it.
    """
    if (probe or {}).get("session") != 1:
        return {}
    got = settings(remote, gs.short_name, gs.lgsm_name)
    return {"warn_minutes": None if got is None else got["minutes"],
            "stop_only_if_empty": None if got is None else got["stop_only"],
            "warn_supported": (gs.game_type or "") in WARN_GAMES,
            "lgsm_supported": None if got is None else got.get("supported", True),
            "lgsm_counts": (gs.game_type or "") not in LIST_UNRELIABLE_GAMES,
            "say": bool(_sm.moderation_caps(gs.game_type).get("say"))}


def refused(out):
    """Whether LinuxGSM's output says it refused a stop (players on, stoponlyifnoplayers on)."""
    oc = outcome(out)
    return bool(oc and oc["code"] == "lgsm_refused")


def stop_word(e):
    """A reboot plan entry's stop outcome, for the audit row."""
    if e.get("lgsm_refused"):
        return "refused by LinuxGSM (players online, stoponlyifnoplayers on)"
    return e.get("stop") or "not stopped"


def refused_stops_note(entries):
    """The reboot announcement's note on stops LinuxGSM refused, or "" when there were none."""
    n = sum(1 for e in entries if e.get("lgsm_refused"))
    if not n:
        return ""
    return (" LinuxGSM refused to stop %d (players online and its stoponlyifnoplayers is on), so "
            "the shutdown ended %s." % (n, "it" if n == 1 else "them"))


def reboot_allowance(remote, e, base):
    """The seconds a reboot's stop of plan entry `e` may take beyond `base`, for warnings.

    Its own countdown (allowance_seconds), and before it room for ONE other LinuxGSM command already
    warning the same server: fn_stop_warn_players_wait (command_stop.sh) waits while another
    command's <self>-warning.lock pid lives — a cron `restart` fired in the reboot's minute — and
    then warns again, so that command's countdown and its own stop and start come first. The census
    refuses a reboot while such a warning runs (host_reboot's WARN probe); this covers one that
    begins after it. 0 with no timer: then LinuxGSM neither warns nor waits on another's warning.
    """
    own = allowance_seconds(remote, e["user"], e["selfname"])
    return 2 * own + base if own else 0


def schedule_seconds(durations, workers):
    """How long `durations` take, in this order, on `workers` side by side: each taken by the first free.

    ThreadPoolExecutor's queue does exactly that with the reboot's account groups.
    """
    free = [0] * max(1, min(workers, len(durations)))
    for d in durations:
        i = free.index(min(free))
        free[i] += d
    return max(free)


def reboot_warn_budget(remote, passes, workers, base_for):
    """The seconds a reboot's stop phase adds for warnings, as its pool runs the stops.

    `passes`: stop_passes(); each a list of account groups. One account's servers stop one after
    another, `workers` accounts at a time, each next account taken by the first worker free; a pass
    starts when the one before has ended. `base_for(e)`: the entry's own stop budget. The longest
    account alone undercounted it: nine accounts with players and a 60-minute timer started their
    third batch after the deadline, so those servers were never stopped and the shutdown ended them.
    """
    return sum(schedule_seconds([sum(reboot_allowance(remote, e, base_for(e)) for e in grp)
                                 for grp in groups], workers) for groups in passes)


def census_blockers(running, probes, blocker):
    """The host census's blockers from its probes: LinuxGSM maintenance, or its warning countdown.

    `running`: the rows read running; `blocker(kind, name)`: host_reboot's. A countdown (the probe's
    WARN: <self>-warning.lock's pid alive) is LinuxGSM about to stop or restart that server after
    its warning, and a reboot's stop would wait it out and then warn again (reboot_allowance).
    """
    return [blocker("lgsm_warning" if probes[gs.id].get("warn") else "maintenance", gs.name)
            for gs in running if probes[gs.id].get("maint") or probes[gs.id].get("warn")]


def stop_passes(remote, entries):
    """A reboot's stops as passes of account groups: first every server LinuxGSM does not warn, then the rest.

    A forced reboot's own 60 s countdown (panel_warned) runs BEFORE the stop phase, so the servers
    it warned are stopped first, in a pass of their own; queued behind a LinuxGSM countdown in the
    same account or a later batch, one was stopped up to that many minutes after its players were
    told "60 seconds". Within an account the servers still stop one after another.
    """
    passes = ({}, {})
    for e in entries:
        passes[_lg264_warns(remote, e.get("game_type"), e["user"], e["selfname"])].setdefault(
            e["user"], []).append(e)
    return [list(p.values()) for p in passes if p]


def run_stop_passes(passes, stop_group, workers, cancelled, on_cancel):
    """Run each pass's account groups through `stop_group`, `workers` at a time, a pass after the last.

    Watched a second at a time, so a Cancel is acted on while a stop runs: `on_cancel()` once, when
    `cancelled()` first says so (it calls LinuxGSM's countdowns off: interrupt_countdowns). A raise
    in a group is the caller's, as the pool's map gave it.
    """
    import concurrent.futures as _cf
    called = False
    for groups in passes:
        with _cf.ThreadPoolExecutor(max_workers=min(workers, len(groups))) as ex:
            futs = [ex.submit(stop_group, g) for g in groups]
            pending = futs
            while pending:
                pending = _cf.wait(futs, timeout=1)[1]
                if not called and cancelled():
                    called = True
                    on_cancel()
            for f in futs:
                f.result()


# Cancel during a reboot's stop. LinuxGSM's own way to call a countdown off is Ctrl-C: core_trap.sh
# traps INT, and fn_stop_warn_players_cancel tells the players "Server stopping cancelled", removes
# its warning lock and ends the command without stopping. The countdown's pid is the first line of
# lgsm/lock/<self>-warning.lock; it is signalled only while it is a `stop` of this very server (the
# reboot's own, in either shape: `./<self> stop` or the forced `source ./<self> stop`) — another
# command's countdown there, a cron restart, is not the reboot's to call off. Bash runs the trap
# when its current 10 s sleep ends.
_LG264_INTERRUPT = ('cd %s || exit 3; p=$(head -n 1 %s 2>/dev/null); case "$p" in ""|*[!0-9]*) '
                    'exit 0;; esac; tr "\\000" " " < "/proc/$p/cmdline" 2>/dev/null | grep -qE %s '
                    '&& kill -INT "$p" && echo LG264_INTERRUPTED')


def interrupt_sh(user, selfname):
    """The shell, run as the account, that calls off the reboot's own countdown of `selfname`."""
    s = selfname.replace(".", "[.]")
    return _LG264_INTERRUPT % (_sm._quote("/home/" + user),
                               _sm._quote("lgsm/lock/%s-warning.lock" % selfname),
                               _sm._quote("/[%s]%s stop( |$)" % (s[0], s[1:])))


def interrupt_countdowns(remote, entries, account_shell):
    """Call off LinuxGSM's warning countdown of every reboot stop still running (`in_stop`).

    `account_shell(remote, user, sh, timeout=, selfname=)`: host_reboot's, which reads the panel's
    own account on its own host directly. Best effort: a stop it cannot reach ends as LinuxGSM ends
    it, and the job's Cancel is acted on after it. -> the names whose countdown was called off.
    """
    off = []
    for e in list(entries):
        if not e.get("in_stop"):
            continue
        try:
            out, _err, _rc = account_shell(remote, e["user"], interrupt_sh(e["user"], e["selfname"]),
                                           timeout=20, selfname=e["selfname"])
        except Exception:  # noqa: BLE001 - best effort: the stop then runs to its end
            _log.debug("could not call off the countdown of %s", e.get("id"), exc_info=True)
            continue
        if "LG264_INTERRUPTED" in (out or ""):
            off.append(e.get("name"))
    return off


# A forced reboot's stop with stoponlyifnoplayers set aside for that one run. LinuxGSM has no option
# for it (v26.4.0: no flag or variable; the setting is read from the cfg files linuxgsm.sh sources
# after the environment), so the instance script is sourced in a shell where the variable is
# READONLY: the cfg's own assignment is refused ("readonly variable", not fatal without set -e,
# which LinuxGSM does not use), and LinuxGSM's own stop then runs as it always does — its warning,
# its graceful stop mode for the game (quit, CTRL+c, telnet...), its locks. Measured on the test
# host with two stand-in players: the plain stop was "stop prevented", this one "Graceful: sending
# "quit" ... OK" in 6 s. Only a forced reboot uses it: a Stop from the panel keeps the setting.
# TERM exported as run_as_game_user's shell form does, or LinuxGSM's tput prints errors.
_LG264_FORCED_STOP = "cd %s && export TERM=xterm && readonly %s && source ./%s stop 2>&1"


def _lg264_forced_sh(user, selfname, aside="stoponlyifnoplayers=off"):
    return _LG264_FORCED_STOP % (_sm._quote("/home/" + user), aside, _sm._quote(selfname))


def reboot_stop(remote, e, base, force=False):
    """A reboot's `stop` of plan entry `e`, given `base` seconds plus its warnings: its output.

    The ordinary LinuxGSM stop first (through the helper's lgsm-command on the panel's host, as
    every action). `force` (the reboot was asked for with players on, "now"): a stop LinuxGSM
    refused for stoponlyifnoplayers is run again with the setting set aside (_LG264_FORCED_STOP),
    so the server still gets its clean stop rather than the shutdown. LinuxGSM refuses before it
    warns or stops anything, so the second run is the only one that does. The output is both runs'
    — a forced run that answered nothing (a sudo refusal, a transport timeout) keeps the first's
    refusal for refused(). `in_stop` is set on `e` while it runs (interrupt_countdowns). Never
    raises: the caller reads the server's state to decide, never the call.
    """
    timeout = base + reboot_allowance(remote, e, base)
    out = ""
    e["in_stop"] = True
    try:
        out, _err, _rc = _sm.run_as_game_user(remote, e["user"], "stop", timeout=timeout,
                                              selfname=e["selfname"])
        out = out or ""
        if force and refused(out):
            forced, _err, _rc = _sm.shell_as_game_user(remote, e["user"],
                                                       _lg264_forced_sh(e["user"], e["selfname"]),
                                                       timeout=timeout, selfname=e["selfname"])
            out = out + "\n" + (forced or "")
    except Exception:  # noqa: BLE001 - the state read decides, never the call
        _log.debug("stop of %s raised", e.get("id"), exc_info=True)
    finally:
        e["in_stop"] = False
    return out


def stop_now(remote, user, selfname, timeout=60):
    """Stop as an uninstall does: LinuxGSM's own graceful stop with no warning and no players check.

    An uninstall runs inside the request, and a server it is removing is not coming back, so its
    stop must not count down for warnplayerstimer minutes (the request would hang for up to an
    hour) nor be refused for players. Both settings are set aside for this one run as the forced
    reboot does (_LG264_FORCED_STOP); on a LinuxGSM before v26.4.0 the two names mean nothing. A
    shell it cannot run falls back to the plain stop, as the uninstall did before. -> (out, err, rc).
    """
    sh = _lg264_forced_sh(user, selfname, "stoponlyifnoplayers=off warnplayerstimer=0")
    got = _sm.shell_as_game_user(remote, user, sh, timeout=timeout, selfname=selfname)
    if got[2] in (0, None) or (got[0] or "").strip():
        return got
    return _sm.run_as_game_user(remote, user, "stop", timeout=timeout, selfname=selfname)


def _lg264_warns(remote, game_type, user, selfname):
    """Whether LinuxGSM itself warns this server's players before its stop.

    A timer, on a game it can warn on, whose players it can count: on LIST_UNRELIABLE_GAMES its
    count can read 0 with players on, and then it stops at once without a word.
    """
    gt = game_type or ""
    return gt in WARN_GAMES and gt not in LIST_UNRELIABLE_GAMES and bool(warn_minutes(remote, user, selfname))


def lgsm_warns(remote, gs):
    """Whether LinuxGSM itself warns server `gs`'s players before its stop (_lg264_warns)."""
    return _lg264_warns(remote, gs.game_type, gs.short_name, gs.lgsm_name)


def panel_warned(remote, rows):
    """The rows ([{id, name}]) a forced reboot's own 60 s countdown still warns: not LinuxGSM's.

    Players are told once. Where LinuxGSM warns (lgsm_warns) the reboot waits for that countdown
    (its stop budget, reboot_allowance) and the panel says nothing; elsewhere — no timer, a game
    LinuxGSM cannot warn on or cannot count, a timer that could not be read — the panel's countdown
    is the warning.
    """
    from panel.db.models import GameServer
    ids = [r["id"] for r in rows or ()]
    if not ids:
        return []
    lgsm = {gs.id for gs in GameServer.query.filter(GameServer.id.in_(ids)).all() if lgsm_warns(remote, gs)}
    return [r for r in rows if r["id"] not in lgsm]
