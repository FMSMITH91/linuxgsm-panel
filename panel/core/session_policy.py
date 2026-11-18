"""How long a sign-in lasts: the idle timeout, the absolute limit and "remember me", from config.json.

OWASP Session Management Cheat Sheet, "Session Expiration" (read 2026-11-15): "Common idle timeouts
ranges are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications", and
for an office day "an appropriate absolute timeout range could be between 4 and 8 hours". The page
gives no number for a persistent ("remember me") login; its "Expire and Max-Age Attributes" section
only advises non-persistent cookies where a login need not outlive the browser. Every value stays
editable: the Settings page shows these ranges beside the fields and notes a value past them.

Step-up (`step_up_minutes`, default 10, 0 = off): how long a sign-in or password confirmation lets the
holder open a terminal or make another high-risk change (users and groups, hosts, the firewall,
updates, certificates, databases, backups, Settings, Notifications) before the password is asked for
again (panel/security/account_guard.py, step_up_required). No OWASP page gives a number: the
Session Management and Authentication Cheat Sheets ("Reauthentication After Risk Events") and the
Transaction Authorization Cheat Sheet (2.9, "a limited time period") name none, and ASVS 5.0 V7.1.1
points at NIST SP 800-63B for re-authentication. NIST SP 800-63B-4, 2.3.3 (AAL3, read 2026-11-15):
"The inactivity timeout SHOULD be no more than 15 minutes", the strictest freshness it sets, used here
for the high-risk actions; past it Settings notes the value, and saves it.

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
STEP_UP_DEFAULT_MINUTES = 10
STEP_UP_MAX_MINUTES = 1440              # 0 (off) .. one day
NIST_STEP_UP_MAX_MINUTES = 15           # SP 800-63B-4 2.3.3; OWASP gives no number (docstring above)


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


def step_up_minutes(cfg):
    """Minutes a sign-in or confirmation covers the high-risk actions (0 switches step-up off)."""
    return _num(cfg.get("step_up_minutes", STEP_UP_DEFAULT_MINUTES), STEP_UP_DEFAULT_MINUTES, 0,
                STEP_UP_MAX_MINUTES)


def lifetimes(cfg):
    """(idle seconds, absolute seconds, remember timedelta) for `cfg`."""
    return idle_minutes(cfg) * 60, absolute_hours(cfg) * 3600, timedelta(days=remember_days(cfg))


def apply(app, cfg):
    """Put `cfg`'s lifetimes in force on `app`: the cookies' lifetimes and the absolute limit."""
    idle, absolute, remember = lifetimes(cfg)
    app.config["PERMANENT_SESSION_LIFETIME"] = idle
    app.config["SESSION_ABSOLUTE_SECONDS"] = absolute
    app.config["REMEMBER_COOKIE_DURATION"] = remember
    if "step_up_minutes" in cfg:        # a save without the field leaves the window as it was
        app.config["STEP_UP_MINUTES"] = step_up_minutes(cfg)


def form_values(cfg):
    """The four Settings fields, with whether each is outside its recommended range."""
    idle, absolute, step_up = idle_minutes(cfg), absolute_hours(cfg), step_up_minutes(cfg)
    return {"session_idle_minutes": idle, "session_absolute_hours": absolute,
            "remember_days": remember_days(cfg), "step_up_minutes": step_up,
            "idle_past_owasp": idle > OWASP_IDLE_MAX_MINUTES,
            "absolute_past_owasp": absolute > OWASP_ABSOLUTE_MAX_HOURS,
            "step_up_past_nist": step_up > NIST_STEP_UP_MAX_MINUTES, "step_up_off": step_up == 0}


def parse_form(form):
    """(cfg changes, None) from the Settings form, or (None, the reason it cannot be saved)."""
    idle = _num(form.get("session_idle_minutes"), IDLE_DEFAULT_MINUTES, IDLE_MIN_MINUTES, IDLE_MAX_MINUTES)
    absolute = _num(form.get("session_absolute_hours"), ABSOLUTE_DEFAULT_HOURS, ABSOLUTE_MIN_HOURS,
                    ABSOLUTE_MAX_HOURS)
    days = _num(form.get("remember_days"), REMEMBER_DEFAULT_DAYS, REMEMBER_MIN_DAYS, REMEMBER_MAX_DAYS)
    if idle > absolute * 60:
        return None, ("The idle timeout cannot be longer than the absolute session limit. Shorten the "
                      "idle timeout or lengthen the limit.")
    out = {"session_idle_minutes": idle, "session_absolute_hours": absolute, "remember_days": days}
    if "step_up_minutes" in form:       # absent (an older form): the stored window is kept
        out["step_up_minutes"] = step_up_minutes(form)
    return out, None


_AUDITED = (("session_idle_minutes", "idle timeout %s min"), ("session_absolute_hours", "absolute limit %s h"),
            ("remember_days", "remember me %s d"), ("step_up_minutes", "step-up %s min"))


def switch_note(cfg, require_2fa, protection):
    """The audit detail for Settings' two security switches: each one this save changes, old -> new.

    "Require 2FA" and session binding (strong or basic) sit on the same form as the lifetimes, and a
    change to either is a change of security configuration the audit trail must name (OWASP Logging
    Cheat Sheet, "Which events to log"). "" when neither changes.
    """
    was_2fa = bool(cfg.get("require_2fa"))
    was_bind = cfg.get("session_protection", "strong")
    notes = []
    if bool(require_2fa) != was_2fa:
        notes.append("require 2FA %s -> %s" % ("on" if was_2fa else "off", "on" if require_2fa else "off"))
    if protection != was_bind:
        notes.append("session protection %s -> %s" % (was_bind, protection))
    return "; ".join(notes)


def change_note(cfg, saved):
    """The audit detail for a save: each session value `saved` changes, old -> new ("" if none)."""
    before = form_values(cfg)
    return "; ".join(label % ("%s -> %s" % (before[key], saved[key])) for key, label in _AUDITED
                     if key in saved and saved[key] != before[key])
