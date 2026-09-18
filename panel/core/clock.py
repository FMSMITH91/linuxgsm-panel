"""Time, with one definition of "now".

Everything the panel stores is **naive UTC**: fourteen `db.Column(db.DateTime)` defaults in
`models.py` insert it, and every comparison and retention cutoff reads it back. SQLite keeps no
timezone, so a single aware value written into one of those columns would come back naive anyway
and silently compare as if it were UTC — right only by accident.

`datetime.utcnow()` produced exactly that naive-UTC value and was the obvious way to write it. It is
deprecated since Python 3.12 and **scheduled for removal**, so it cannot stay; the panel had 22 calls
to it. The replacement has to keep the naive-UTC contract rather than quietly switch the codebase to
aware datetimes, because mixing the two raises `TypeError: can't compare offset-naive and
offset-aware datetimes` at whichever comparison runs first — which here is inside a request.

So there are two functions, and which one you want depends on where the value is going:

  * `utcnow()`   — naive UTC. For anything that touches the database.
  * `aware_utcnow()` — timezone-aware UTC. For APIs that want an aware datetime, notably
    `cryptography`, whose naive-datetime certificate properties are themselves deprecated.

No imports beyond the standard library, so anything in the codebase can use it.
"""
from datetime import datetime, timezone


def utcnow():
    """The current UTC time as a **naive** datetime — what `datetime.utcnow()` returned.

    Use for every value that is stored in, or compared against, a `db.DateTime` column."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def aware_utcnow():
    """The current UTC time as a **timezone-aware** datetime.

    Use only where a library asks for one. Never store it: it would land in a naive column."""
    return datetime.now(timezone.utc)


# ── Wall-clock schedules across two different zones ───────────────────────────────────────────
# A cron entry fires on the HOST's clock. The person setting it is reading their own. Those are
# usually different, and on a VPS bootstrapped to UTC — which is this panel's own default — the
# gap is the whole working day: "daily at 05:00" set by someone in US Central meant 23:00 for
# them, in peak hours, with nothing on screen saying so.
#
# So a schedule is ENTERED in the viewer's zone and STORED in the host's, converted here.
import re as _re

_HHMM_RE = _re.compile(r"^([01]?[0-9]|2[0-3]):([0-5][0-9])$")


def parse_hhmm(value, default=(5, 0)):
    """"HH:MM" -> (hour, minute), or `default` for anything that is not one. Never raises: this
    parses a value that reached us from a form."""
    m = _HHMM_RE.match((value or "").strip())
    return (int(m.group(1)), int(m.group(2))) if m else default


def valid_timezone(name):
    """`name` if it is an IANA zone this machine knows, else "". Never raises.

    Checked rather than trusted: it arrives from the browser and from a remote host's
    `timedatectl`, and it goes on to index the zone database, into a stored column, and onto the
    page.

    The shape check below is a CHEAP BOUND, not the thing that stops path traversal — `zoneinfo`
    refuses an absolute path or a `..` component itself (ValueError, verified on 3.14). Measured
    rather than assumed, because a comment claiming otherwise would be a security control that
    only appears to exist. What it genuinely buys: obviously-invalid input never reaches a
    filesystem-backed lookup on a browser-reachable path, and the value that can be stored and
    rendered is held to a known charset and length."""
    name = (name or "").strip()
    if not name or len(name) > 64 or not _re.match(r"^[A-Za-z0-9+_/-]+$", name) or ".." in name:
        return ""
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(name)
        return name
    except Exception:
        return ""


def convert_wall_time(hour, minute, from_tz, to_tz, on=None):
    """A recurring wall-clock time moved from one zone to another: (hour, minute).

    Returns the input unchanged when either zone is unknown or they are the same — an unreadable
    host must leave the schedule where the operator put it, not silently shift it.

    THE DST CAVEAT, WHICH IS REAL AND CANNOT BE ENGINEERED AWAY HERE. A crontab line is a fixed
    wall time on the host. Two zones whose daylight-saving rules differ are 60 minutes further
    apart for part of the year, so a schedule converted today is an hour out after the next
    changeover — 05:00 America/Chicago is 11:00 UTC in January and 10:00 UTC in July. Nothing
    short of a DST-aware scheduler on the host fixes that, so the conversion is anchored to a
    reference date (now, by default) and the UI says which host time it actually wrote."""
    from_tz, to_tz = valid_timezone(from_tz), valid_timezone(to_tz)
    if not from_tz or not to_tz or from_tz == to_tz:
        return hour, minute
    try:
        from zoneinfo import ZoneInfo
        ref = (on or datetime.now()).replace(hour=int(hour), minute=int(minute), second=0,
                                             microsecond=0, tzinfo=ZoneInfo(from_tz))
        moved = ref.astimezone(ZoneInfo(to_tz))
        return moved.hour, moved.minute
    except Exception:
        return hour, minute
