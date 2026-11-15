"""How long a sign-in lasts: the idle timeout, the absolute limit and "remember me", from config.json.

OWASP Session Management Cheat Sheet, "Session Expiration" (read 2026-11-15): "Common idle timeouts
ranges are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications", and
for an office day "an appropriate absolute timeout range could be between 4 and 8 hours". The page
gives no number for a persistent ("remember me") login; its "Expire and Max-Age Attributes" section
only advises non-persistent cookies where a login need not outlive the browser. Every value stays
editable: the Settings page shows these ranges beside the fields and notes a value past them.

Config keys: `session_idle_minutes` (new installs: 30) and `session_absolute_hours` (8). An install
from before they existed carries `session_lifetime_hours`, read as that many hours of idle time, and
an absolute limit of the longer of 8 hours and that idle time (the rule it already had), so an upgrade
changes no one's effective sign-in length.
"""
import math
from datetime import timedelta

IDLE_DEFAULT_MINUTES = 30
IDLE_MIN_MINUTES = 5
IDLE_MAX_MINUTES = 7 * 24 * 60          # the old idle field's own maximum (168 hours)
ABSOLUTE_DEFAULT_HOURS = 8
ABSOLUTE_MIN_HOURS = 1
# 168, not OWASP's 8: an install upgraded with a 7-day idle timeout has to be able to keep it, and an
# idle timeout longer than the absolute limit would mean nothing.
ABSOLUTE_MAX_HOURS = 168
REMEMBER_DEFAULT_DAYS = 3
REMEMBER_MIN_DAYS = 1
REMEMBER_MAX_DAYS = 90
# OWASP's upper bounds (Session Management Cheat Sheet, "Session Expiration"): past these the
# Settings page says "Longer than OWASP recommends", and saves anyway.
OWASP_IDLE_MAX_MINUTES = 30
OWASP_ABSOLUTE_MAX_HOURS = 8


def _num(value, default, lo, hi):
    """`value` as an int held to lo..hi; `default` when it is not a finite number."""
    try:
        n = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default
    return max(lo, min(n, hi))


def _set(cfg, key):
    """Whether config.json holds a usable value for `key` (None and "" are not one)."""
    return cfg.get(key) not in (None, "")


def idle_minutes(cfg):
    """The idle timeout in minutes; an older install's `session_lifetime_hours` converted."""
    if _set(cfg, "session_idle_minutes"):
        return _num(cfg["session_idle_minutes"], IDLE_DEFAULT_MINUTES, IDLE_MIN_MINUTES, IDLE_MAX_MINUTES)
    if _set(cfg, "session_lifetime_hours"):
        return _num(cfg["session_lifetime_hours"], 8, 1, 168) * 60
    return IDLE_DEFAULT_MINUTES


def absolute_hours(cfg):
    """The absolute limit in hours; unset, the longer of 8 hours and the idle timeout (the old rule)."""
    if _set(cfg, "session_absolute_hours"):
        return _num(cfg["session_absolute_hours"], ABSOLUTE_DEFAULT_HOURS, ABSOLUTE_MIN_HOURS,
                    ABSOLUTE_MAX_HOURS)
    return max(ABSOLUTE_DEFAULT_HOURS, int(math.ceil(idle_minutes(cfg) / 60.0)))


def remember_days(cfg):
    """How many days a "remember me" login lasts from its sign-in."""
    return _num(cfg.get("remember_days", REMEMBER_DEFAULT_DAYS), REMEMBER_DEFAULT_DAYS,
                REMEMBER_MIN_DAYS, REMEMBER_MAX_DAYS)


def lifetimes(cfg):
    """(idle seconds, absolute seconds, remember timedelta) for `cfg`."""
    return idle_minutes(cfg) * 60, absolute_hours(cfg) * 3600, timedelta(days=remember_days(cfg))


def apply(app, cfg):
    """Put `cfg`'s lifetimes in force on `app`: the cookies' lifetimes and the absolute limit."""
    idle, absolute, remember = lifetimes(cfg)
    app.config["PERMANENT_SESSION_LIFETIME"] = idle
    app.config["SESSION_ABSOLUTE_SECONDS"] = absolute
    app.config["REMEMBER_COOKIE_DURATION"] = remember


def form_values(cfg):
    """The three Settings fields, with whether each is past OWASP's range."""
    idle, absolute = idle_minutes(cfg), absolute_hours(cfg)
    return {"session_idle_minutes": idle, "session_absolute_hours": absolute,
            "remember_days": remember_days(cfg),
            "idle_past_owasp": idle > OWASP_IDLE_MAX_MINUTES,
            "absolute_past_owasp": absolute > OWASP_ABSOLUTE_MAX_HOURS}


def parse_form(form):
    """(cfg changes, None) from the Settings form, or (None, the reason it cannot be saved)."""
    idle = _num(form.get("session_idle_minutes"), IDLE_DEFAULT_MINUTES, IDLE_MIN_MINUTES, IDLE_MAX_MINUTES)
    absolute = _num(form.get("session_absolute_hours"), ABSOLUTE_DEFAULT_HOURS, ABSOLUTE_MIN_HOURS,
                    ABSOLUTE_MAX_HOURS)
    days = _num(form.get("remember_days"), REMEMBER_DEFAULT_DAYS, REMEMBER_MIN_DAYS, REMEMBER_MAX_DAYS)
    if idle > absolute * 60:
        return None, ("The idle timeout cannot be longer than the absolute session limit. Shorten the "
                      "idle timeout or lengthen the limit.")
    return {"session_idle_minutes": idle, "session_absolute_hours": absolute, "remember_days": days}, None
