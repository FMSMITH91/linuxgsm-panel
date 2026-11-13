"""Scheduled wipes for Rust, and world resets for Minecraft Java and Factorio.

Rust uses LinuxGSM's map / full wipe (`wipe` / `full-wipe`). The games in services/world_reset.py
(Minecraft Java, Factorio) get a world reset instead, which LinuxGSM has no command for.

What LinuxGSM does (lgsm/modules/command_wipe.sh, core_getopt.sh, v26.5.0): only `rust` gets the
two commands. `wipe` (map-wipe) deletes the server identity's *.map and *.sav* files and keeps
blueprints; `full-wipe` also deletes its *.db files except player.tokens.db (Rust+ pairing). A
running server is stopped, wiped and started again; a stopped one is wiped and left stopped. With
nothing to delete it prints "Wipe not required". It never prompts.

The panel runs it on a schedule the operator sets, and only after a LinuxGSM backup of the server
worked: the backup is the only way back from a wipe nobody meant. This module holds the parts that
need no Flask: the schedule (a 5-field cron line, or the "first Thursday" preset Rust's monthly
forced wipe uses), when it is next due, where it is stored, and how a wipe's output is judged.
"""
import datetime
import re
import time
import zoneinfo

from panel.core import i18n, terminal
from panel.core.config import load_config, update_config
from panel.services import lgsm_players as _lgp, world_reset

# Games whose LinuxGSM script offers wipe/full-wipe (core_getopt.sh: `[ "${shortname}" == "rust" ]`).
LGSM_WIPE_GAMES = frozenset(("rust",))
# Every game the schedule card is offered for: LinuxGSM's wipe, or the panel's world reset.
WIPE_GAMES = LGSM_WIPE_GAMES | world_reset.GAMES
# The panel's kind -> LinuxGSM's command.
WIPE_COMMANDS = {"map": "wipe", "full": "full-wipe"}


def kinds_for(game_type):
    """The kinds a schedule may hold for `game_type` (a frozenset): map/full for Rust, the reset for the others."""
    if game_type in LGSM_WIPE_GAMES:
        return frozenset(WIPE_COMMANDS)
    return frozenset((world_reset.KIND,)) if game_type in world_reset.GAMES else frozenset()


def kind_refusal(game_type):
    """The card's refusal of a kind `game_type` does not take."""
    return "kind must be reset." if game_type in world_reset.GAMES else "kind must be map or full."


PRESETS = ("first-thursday", "weekly-thursday", "custom")
# A due wipe the panel could not start within this long (it was not running at the time) is skipped,
# not run late: a wipe days after the announced time is a surprise to everyone on the server.
GRACE_SECONDS = 6 * 3600
# How long a due wipe may wait for an empty server, a running backup or a host reboot.
MAX_WAIT_SECONDS = 12 * 3600
_CFG_KEY = "wipe_schedules"

# Names only where cron takes them (cronie's entry.c passes MonthNames and DowNames to those two
# fields' get_list, NULL to the rest): `0 mon * * *` is not minute 0, hour 1.
_R37B_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
                "sep": 9, "oct": 10, "nov": 11, "dec": 12}
_R37B_DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
_BOUNDS = ((0, 59, {}), (0, 23, {}), (1, 31, {}), (1, 12, _R37B_MONTHS), (0, 7, _R37B_DAYS))
_ITEM_RE = re.compile(r"(\*|[0-9a-z]{1,3}(?:-[0-9a-z]{1,3})?)(?:/([0-9]{1,2}))?")


def _cmpd_value(tok, lo, hi, names):
    """One field value (a number, or one of this field's `names`) inside [lo, hi], else ValueError."""
    v = names[tok] if tok in names else int(tok)
    if not lo <= v <= hi:
        raise ValueError("out of range")
    return v


def _cmpd_field(text, lo, hi, names):
    """The set of values one cron field means (`*`, `a-b`, lists, `/step`, this field's names)."""
    out = set()
    for item in text.split(","):
        m = _ITEM_RE.fullmatch(item)
        if m is None:
            raise ValueError("bad field")
        rng, step = m.group(1), int(m.group(2) or 1)
        if step < 1:
            raise ValueError("bad step")
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            a, b = (_cmpd_value(t, lo, hi, names) for t in rng.split("-"))
        else:
            a = b = _cmpd_value(rng, lo, hi, names)
        if a > b:
            raise ValueError("bad range")
        out.update(range(a, b + 1, step))
    return out


def parse_cron(line):
    """A 5-field cron line as a dict of value sets, or None when it is not one.

    Vixie semantics, as the host's cron reads it: with BOTH day-of-month and weekday restricted, a
    day matching either one fires. Weekday 7 is Sunday, like 0. No @macros: a wipe needs a time.
    "Restricted" is cron's own test, not the field's meaning: cronie's (and Debian's) entry.c sets
    DOM_STAR / DOW_STAR when the field's FIRST character is `*`, so `*/2` counts as a star and
    `0 18 */2 * 4` is odd days that are Thursdays, never every odd day plus every Thursday.
    """
    parts = str(line or "").strip().lower().split()
    if len(parts) != 5 or len(str(line)) > 120:
        return None
    try:
        sets = [_cmpd_field(p, lo, hi, names) for p, (lo, hi, names) in zip(parts, _BOUNDS)]
    except (ValueError, KeyError):
        return None
    dow = {d % 7 for d in sets[4]}
    return {"minute": sets[0], "hour": sets[1], "dom": sets[2], "month": sets[3], "dow": dow,
            "dom_star": parts[2].startswith("*"), "dow_star": parts[4].startswith("*"), "both": False}


def spec_for(preset, at, cron):
    """(spec, cron line) for a preset at "HH:MM", or for a custom cron line; (None, why) if invalid."""
    if preset == "custom":
        spec = parse_cron(cron)
        return (spec, " ".join(str(cron).split())) if spec else (None, "not a 5-field cron schedule")
    m = re.fullmatch(r"([01]?[0-9]|2[0-3]):([0-5][0-9])", str(at or ""))
    if preset not in PRESETS or m is None:
        return None, "time must be HH:MM"
    hour, minute = int(m.group(1)), int(m.group(2))
    line = "%d %d %s * 4" % (minute, hour, "1-7" if preset == "first-thursday" else "*")
    spec = parse_cron(line)
    spec["both"] = preset == "first-thursday"      # the 1st-7th AND a Thursday: the first one
    return spec, line


def _cmpd_day_matches(spec, day):
    """Whether date `day` is a day the schedule fires on."""
    if day.month not in spec["month"]:
        return False
    dom_ok = day.day in spec["dom"]
    dow_ok = (day.weekday() + 1) % 7 in spec["dow"]
    if spec["both"]:
        return dom_ok and dow_ok
    if spec["dom_star"] or spec["dow_star"]:
        return dom_ok and dow_ok
    return dom_ok or dow_ok


def next_after(spec, after, tz_name):
    """The first fire time strictly after epoch `after`, as an epoch, in zone `tz_name`; None if none.

    Walked a day at a time (at most 400 days, so an impossible date such as 31 February ends), and
    within a matching day only the listed hours and minutes. A wall time that does not exist on a
    DST day is taken as zoneinfo resolves it.
    """
    try:
        tz = zoneinfo.ZoneInfo(tz_name) if tz_name else datetime.timezone.utc
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        tz = datetime.timezone.utc
    start = datetime.datetime.fromtimestamp(after, tz)
    for offset in range(400):
        day = start.date() + datetime.timedelta(days=offset)
        if not _cmpd_day_matches(spec, day):
            continue
        for hour in sorted(spec["hour"]):
            for minute in sorted(spec["minute"]):
                at = datetime.datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz).timestamp()
                if at > after:
                    return at
    return None


def describe(entry):
    """A short English line for the page and the audit row: kind, schedule, zone."""
    what = {"full": "Full wipe", world_reset.KIND: "World reset"}.get(entry.get("kind"), "Map wipe")
    return "%s, cron '%s'%s (%s)" % (what, entry.get("cron", ""),
                                     " (first Thursday)" if entry.get("preset") == "first-thursday" else "",
                                     entry.get("tz") or "UTC")


# ── storage: config.json["wipe_schedules"][str(server id)] ─────────────────────────────────────
def _cmpd_all(cfg):
    got = cfg.get(_CFG_KEY)
    return got if isinstance(got, dict) else {}


def get(sid):
    """The stored entry for server `sid`, or None."""
    entry = _cmpd_all(load_config()).get(str(sid))
    return entry if isinstance(entry, dict) else None


def all_entries():
    """{server id (int): entry} for every stored schedule."""
    out = {}
    for k, v in _cmpd_all(load_config()).items():
        if isinstance(v, dict) and str(k).isdecimal():
            out[int(k)] = v
    return out


def put(sid, entry):
    """Store (or, with None, remove) server `sid`'s entry."""
    def _mut(cfg):
        allw = _cmpd_all(cfg)
        cfg[_CFG_KEY] = allw
        if entry is None:
            allw.pop(str(sid), None)
        else:
            allw[str(sid)] = entry
    update_config(_mut)


def patch(sid, **fields):
    """Merge `fields` into server `sid`'s stored entry (nothing when there is none)."""
    def _mut(cfg):
        cur = _cmpd_all(cfg).get(str(sid))
        if isinstance(cur, dict):
            cur.update(fields)
    update_config(_mut)


def identity(gs):
    """What an entry is pinned to: SQLite hands a deleted server's id to the next one created."""
    return {"short_name": gs.short_name, "remote_id": gs.remote_id, "born": str(gs.created_at)}


def same_server(entry, gs):
    """Whether `entry` was made for the server row `gs` (not an earlier one that held its id)."""
    return all(entry.get(k) == v for k, v in identity(gs).items())


def due(entry, now=None):
    """Return (state, fire epoch): whether the wipe is due now.

    ("run", t) when it is due, ("missed", t) when its time passed more than GRACE_SECONDS ago,
    else (None, the next fire time or None). Measured from the entry's `anchor`: when it was
    saved, or the last fire time already handled.
    """
    now = time.time() if now is None else now
    spec = parse_cron(entry.get("cron"))
    if not spec:
        return None, None
    spec["both"] = entry.get("preset") == "first-thursday"
    nxt = next_after(spec, float(entry.get("anchor") or now), entry.get("tz"))
    if nxt is None or nxt > now:
        return None, nxt
    return ("missed" if now - nxt > GRACE_SECONDS else "run"), nxt


# ── judging LinuxGSM's output ───────────────────────────────────────────────────────────────────
_WIPED_RE = re.compile(r"Success!\s+(Full|Map) wipe\b")
_NOT_REQUIRED_RE = re.compile(r"\[\s*OK\s*\][^\n\r]*\bWipe not required\b")
_FAIL_RE = re.compile(r"\[\s*FAIL\s*\]|\.\.\.\s*FAIL\b|\bFailure!")
# The wipe's own start line (command_wipe.sh fn_wipe_files: fn_print_start_nl "${wipetype}"), and the
# stop's last word when even the tmux kill left the server running (command_stop.sh fn_stop_tmux).
_R39A_START_RE = re.compile(r"\[\s*START\s*\][^\n\r]*\b(?:Full|Map) wipe\b")
_R39A_UNSTOPPED_RE = re.compile(r"\[\s*FAIL\s*\][^\n\r]*\bUnable to stop\b")


def judge(out, rc, command):
    """("wiped" | "nothing" | "refused" | "failed", sentence) for one wipe run's output and exit.

    Refused: LinuxGSM's own players-online refusal (stoponlyifnoplayersallcommands) ended the run
    before anything was deleted. Only LinuxGSM's own success line, with no failed removal or stop
    before it (_r39a_failed_before), is a wipe; an exit 0 with neither line is NOT read as one, since
    it says nothing about what was deleted.
    The sentence is an i18n.Sentence: English in the audit row, the viewer's language on the card.
    """
    text = terminal.strip_escapes(out or "")
    oc = _lgp.outcome_of(text, rc, command)
    if oc is not None:
        return "refused", i18n.Sentence("LinuxGSM did not wipe: {players} player(s) online",
                                        players=oc.get("players", "?"))
    done = _cmpd_done(text, rc)
    if done is not None:
        return done
    last = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return "failed", i18n.Sentence("wipe exited {rc}: {last}", rc=rc,
                                   last=(last[-1] if last else "no output")[:200])


def _cmpd_done(text, rc):
    """("wiped" | "nothing", sentence) for a wipe's output and exit, or None when it says neither."""
    wiped = _WIPED_RE.search(text)
    if wiped and not _r39a_failed_before(text, wiped.start()):
        # command_wipe.sh prints its success line after the files are gone and only then starts a
        # server it stopped (exitbypass=1; command_start.sh). A FAIL after that line is the start's:
        # the wipe happened, and was read as one that did not ("Scheduled wipe did not run"). The
        # server left down is the monitor's to page (the wipe marks a restart, which must come back).
        # Whatever the exit code: a start that fails there logs FAIL (exitcode=1), its own core_exit.sh
        # only unsets exitbypass, and command_start.sh's last core_exit.sh exits 1 from inside the
        # wipe (LinuxGSM v26.5.0) — so this shape comes with exit 1, not 0.
        late = _FAIL_RE.search(text, wiped.end())
        line = text[late.start():].splitlines()[0].strip()[:200] if late else None
        return "wiped", _r38b_wiped_said(wiped.group(1) == "Full", line, rc)
    if rc == 0 and _NOT_REQUIRED_RE.search(text):
        return "nothing", i18n.Sentence("LinuxGSM found nothing to wipe")
    return None


def _r39a_failed_before(text, end):
    """Whether the output before the success line (at `end`) says the wipe, or the stop before it, failed.

    Only the FAILs from the wipe's own start line on (a removal's " ... FAIL": fn_wipe_exit_code), and
    the stop's "Unable to stop" (the files went from under a running server). Not any FAIL before the
    line: a running server that ignores `quit` for its whole timeout (Rust's stopmode 4: 120 s) prints
    the graceful step's "[ ERROR ] ... Graceful: sending "quit": ... FAIL", then LinuxGSM kills its tmux
    session ("[  OK  ]"), wipes and prints "Success!" (exitbypass, LinuxGSM v26.5.0). That wipe was
    recorded as one that did not run and alerted so, and the operator told to run it by hand would
    wipe the fresh map again. Output with no start line (an older LinuxGSM) is judged as before.
    """
    starts = [m.start() for m in _R39A_START_RE.finditer(text, 0, end)]
    return bool(_FAIL_RE.search(text, starts[-1] if starts else 0, end)
                or _R39A_UNSTOPPED_RE.search(text, 0, end))


def _r38b_wiped_said(full, late, rc):
    """The sentence for a wipe that happened: plain, or with the FAIL line after it (`late`), or its exit code."""
    if late is not None:
        if full:
            return i18n.Sentence("Full wipe done, but LinuxGSM reported a failure after it: {line}", line=late)
        return i18n.Sentence("Map wipe done, but LinuxGSM reported a failure after it: {line}", line=late)
    if rc != 0:
        # A non-zero exit with no FAIL line after the files went (a failed alert, a start cut off by
        # the timeout): still a wipe, said with the exit code.
        if full:
            return i18n.Sentence("Full wipe done, but LinuxGSM exited {rc} after it", rc=rc)
        return i18n.Sentence("Map wipe done, but LinuxGSM exited {rc} after it", rc=rc)
    return i18n.Sentence("Full wipe done") if full else i18n.Sentence("Map wipe done")
