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
    """Read a warnplayerstimer value as LinuxGSM does: digits are minutes, anything else is off (0)."""
    s = str(raw or "").strip().strip("\"'")
    return int(s, 10) if s.isascii() and s.isdecimal() else 0


def settings(server, user, selfname, fresh=False):
    """The server's {"minutes": warnplayerstimer, "stop_only": stoponlyifnoplayers is on}, cached.

    None when its config could not be read: unknown, never "off".
    """
    key = _lg264_key(server, user, selfname)
    now = time.time()
    with _lg264_lock:
        hit = _lg264_cache.get(key)
    if hit and hit[0] > now and not fresh:
        return dict(hit[1])
    try:
        vals = _sm.lgsm_get_values(server, user, selfname or user,
                                   ["warnplayerstimer", "stoponlyifnoplayers"])
    except Exception:  # noqa: BLE001 - unread is answered as unknown, never as "off"
        vals = None
    if vals is None:
        return None
    remember(server, user, selfname, vals.get("warnplayerstimer"), vals.get("stoponlyifnoplayers"))
    return {"minutes": warn_minutes_value(vals.get("warnplayerstimer")),
            "stop_only": str(vals.get("stoponlyifnoplayers") or "").strip() == "on"}


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


def remember(server, user, selfname, raw_timer, raw_stop):
    """Cache the two settings a config read in hand already holds (the editor's read)."""
    with _lg264_lock:
        _lg264_cache[_lg264_key(server, user, selfname)] = (
            time.time() + _LG264_TTL, {"minutes": warn_minutes_value(raw_timer),
                                       "stop_only": str(raw_stop or "").strip() == "on"})


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


def outcome_message(oc, action, monitor=True):
    """The panel's sentence for outcome `oc` of `action`; `monitor`: the server's Autostart is on."""
    if oc["code"] == "lgsm_postponed":
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


BACKUP_QUEUED = i18n.Sentence("Backup postponed by LinuxGSM: players are online. LinuxGSM runs it "
                              "when the server is empty.")
BACKUP_DONE_BY_LGSM = i18n.Sentence("Backed up by LinuxGSM once the server was empty.")


# ── the config editor's two controls (Files & Config → LinuxGSM Settings) ───────────────────────
def config_view(gs, d):
    """lgsm_read_config's answer `d` as the editor shows it: the player settings as their own controls.

    Offered only where they do something: LinuxGSM v26.4.0 or later (its `players.supported`), and
    the warning timer only on a game in WARN_GAMES. Both keys then leave the generic list, so each
    is edited in one place — except a timer already set on a game LinuxGSM cannot warn on, which
    stays there so it can be cleared. `can_count`: LinuxGSM counts players only with querymode 2 or
    3; with any other it skips its check and stops anyway (check_players_online.sh), said on the page.
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
                    "can_count": pl.get("querymode") in ("2", "3")}
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
    (None: unread); stop_only_if_empty: its stoponlyifnoplayers, which makes LinuxGSM REFUSE the
    reboot's stop while players are on — the panel cannot override it, so the shutdown ends that
    server; warn_supported: its game is in WARN_GAMES; say: the panel's own 60 s countdown
    (host_reboot COUNTDOWN) reaches it.
    """
    if (probe or {}).get("session") != 1:
        return {}
    return {"warn_minutes": warn_minutes(remote, gs.short_name, gs.lgsm_name),
            "stop_only_if_empty": stop_only_if_empty(remote, gs.short_name, gs.lgsm_name),
            "warn_supported": (gs.game_type or "") in WARN_GAMES,
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


def reboot_warn_budget(remote, groups):
    """The seconds a reboot's stop phase adds for warnings: the longest account's sum.

    `groups`: {account: [plan entries]}. One account's servers stop one after another, each after
    its own countdown; the accounts stop side by side.
    """
    return max((sum(allowance_seconds(remote, e["user"], e["selfname"]) for e in grp)
                for grp in groups.values()), default=0)


# A forced reboot's stop with stoponlyifnoplayers set aside for that one run. LinuxGSM has no option
# for it (v26.4.0: no flag or variable; the setting is read from the cfg files linuxgsm.sh sources
# after the environment), so the instance script is sourced in a shell where the variable is
# READONLY: the cfg's own assignment is refused ("readonly variable", not fatal without set -e,
# which LinuxGSM does not use), and LinuxGSM's own stop then runs as it always does — its warning,
# its graceful stop mode for the game (quit, CTRL+c, telnet...), its locks. Measured on the test
# host with two stand-in players: the plain stop was "stop prevented", this one "Graceful: sending
# "quit" ... OK" in 6 s. Only a forced reboot uses it: a Stop from the panel keeps the setting.
_LG264_FORCED_STOP = "cd %s && readonly stoponlyifnoplayers=off && source ./%s stop 2>&1"


def reboot_stop(remote, e, base, force=False):
    """A reboot's `stop` of plan entry `e`, given `base` seconds plus its warning: its output.

    The ordinary LinuxGSM stop first (through the helper's lgsm-command on the panel's host, as
    every action). `force` (the reboot was asked for with players on, "now"): a stop LinuxGSM
    refused for stoponlyifnoplayers is run again with the setting set aside (_LG264_FORCED_STOP),
    so the server still gets its clean stop rather than the shutdown. LinuxGSM refuses before it
    warns or stops anything, so the second run is the only one that does. Never raises: the caller
    reads the server's state to decide, never the call ("" on a raise).
    """
    timeout = timeout_for(remote, e["user"], e["selfname"], "stop", base)
    try:
        out, _err, _rc = _sm.run_as_game_user(remote, e["user"], "stop", timeout=timeout,
                                              selfname=e["selfname"])
        if force and refused(out):
            sh = _LG264_FORCED_STOP % (_sm._quote("/home/" + e["user"]), _sm._quote(e["selfname"]))
            out, _err, _rc = _sm.shell_as_game_user(remote, e["user"], sh, timeout=timeout,
                                                    selfname=e["selfname"])
        return out or ""
    except Exception:  # noqa: BLE001 - the state read decides, never the call
        _log.debug("stop of %s raised", e.get("id"), exc_info=True)
        return ""


def lgsm_warns(remote, gs):
    """Whether LinuxGSM itself warns server `gs`'s players before its stop: a timer, on its game."""
    return (gs.game_type or "") in WARN_GAMES and bool(warn_minutes(remote, gs.short_name, gs.lgsm_name))


def panel_warned(remote, rows):
    """The rows ([{id, name}]) a forced reboot's own 60 s countdown still warns: not LinuxGSM's.

    Players are told once. Where LinuxGSM has a warning timer the reboot waits for that countdown
    (its stop budget, allowance_seconds) and the panel says nothing; elsewhere — no timer, a game
    LinuxGSM cannot warn on, a timer that could not be read — the panel's countdown is the warning.
    """
    from panel.db.models import GameServer
    ids = [r["id"] for r in rows or ()]
    if not ids:
        return []
    lgsm = {gs.id for gs in GameServer.query.filter(GameServer.id.in_(ids)).all() if lgsm_warns(remote, gs)}
    return [r for r in rows if r["id"] not in lgsm]
