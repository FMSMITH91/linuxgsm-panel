"""Every update the panel knows is waiting, in one list, and the settings of the nightly window.

WHAT IS LISTED (collect), each from what the panel already holds, so opening the page asks no host anything:
    Panel      its own update status as the update-check ticker last cached it (system_ops), superadmins only.
    Host system  each host's OS packages from the daily check (routes/remote_vps.os_update_hosts, the banner's own
               read and scoping), security packages counted apart.
    Game servers  a server whose LinuxGSM is behind its latest release, as the server page last read it
               (note_lgsm), with that release's notes. The game itself is updated by LinuxGSM's own daily job.
    Add-ons    an installed add-on whose image differs from the catalog's, as its card or the nightly window last
               read it (note_addons).
    Websites   a site whose image or site files differ from the catalog's (routes/websites.update_available).
Each row says what the update changes, what it costs, whether it is a security update, when it happens by
itself and how to start it now: the row's action is the item's own route (the page aggregates them, it never
does an update its own way).

THE NIGHTLY WINDOW (services/updates_auto.py) applies website and add-on updates between `start` and `end`
on each host's own clock (default 04:00-05:00, before LinuxGSM's own jobs at 05:00 and 05:15), one at a time.
Automatic updates are on for every item by default; an item can be switched off (`off`, by its ref). A
security update (the signed catalog's `security` section: catalog_security.py) is applied in the window even
for an item switched off, and the page keeps a warning on such an item. OWASP Top 10 2025 A03 Software Supply
Chain Failures (the successor of A06:2021 Vulnerable and Outdated Components) counts not upgrading "in a
risk-based, timely fashion" as the weakness, and its "How to prevent" asks for a patch management process and
staged rollouts ("Avoid deploying updates to all systems simultaneously"): automatic on, one item at a time.
So the recommended value of each switch is on, shown beside it, and off is a note, never a block.
"""
import re
import threading
import time
from datetime import datetime, timedelta

from panel.core import clock, i18n
from panel.core.config import config_value, update_config
from panel.services import catalog_security as _cs

CFG = "auto_updates"
DEFAULT_START, DEFAULT_END = "04:00", "05:00"
OWASP_AUTO = True
_HHMM = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]\Z")
REF_RE = re.compile(r"(?:website:[1-9][0-9]{0,9}|addon:[1-9][0-9]{0,9}:[a-z][a-z0-9-]{0,31})\Z")
_OFF_MAX = 5000
# What each kind of update costs, in the words the rows show.
COST_SITE = "A few seconds offline. Its files, databases and settings stay."
COST_SITE_BUILD = ("A few seconds offline (building its new image can take a few minutes first). Its files, databases and "
                   "settings stay.")
COST_ADDON = "The add-on restarts: about a minute without it. Players stay on the game server."
COST_LGSM = "No restart: players stay on. Only LinuxGSM's own scripts change."
COST_OS = "Services on the host may restart, and a kernel update needs a reboot to take effect."
COST_PANEL = "The panel restarts: a few seconds. Game servers and websites keep running."
S_BAD_WINDOW = "Give the window's start and end as HH:MM (24-hour), and different from each other."
S_BAD_REF = "That is not an update the panel lists."
S_AUTO_OFF_NOTE = ("OWASP recommends installing updates promptly: with automatic updates off, this one waits for "
                   "someone to press Update now. Security updates still install in the nightly window.")
# The pages read the lists below at most this often per viewer (the nav's count is on every page).
COUNT_TTL = 60.0

_ADDONS_SEEN = {}         # server id -> {"at": epoch, "rows": {addon id: {"reason", "version", "new"}}}
_LGSM_SEEN = {}           # server id -> {"at": epoch, "release", "latest", "behind"}
_LGSM_CRON = {}           # server id -> {"at": epoch, "schedule": the update-lgsm task's cron schedule, "" when none}
# An update-lgsm in a crontab line's command: LinuxGSM's own command or its short form, after the server's script.
_LGSM_CRON_RE = re.compile(r"(?:^|\s)(?:update-lgsm|ul)(?:\s|$)")
_COUNTS = {}              # user id -> (epoch, count)
_SEEN_LOCK = threading.Lock()


# ── settings ───────────────────────────────────────────────────────────────────────────────────
def _hhmm(value, default):
    return value if isinstance(value, str) and _HHMM.match(value) else default


def settings():
    """{"start", "end", "off": [refs]} as config.json holds them, each falling back to its default."""
    raw = config_value(CFG, {})
    raw = raw if isinstance(raw, dict) else {}
    start, end = _hhmm(raw.get("start"), DEFAULT_START), _hhmm(raw.get("end"), DEFAULT_END)
    if start == end:
        start, end = DEFAULT_START, DEFAULT_END
    off = raw.get("off") if isinstance(raw.get("off"), list) else []
    return {"start": start, "end": end, "off": sorted({r for r in off if isinstance(r, str) and REF_RE.match(r)})}


def save_window(start, end):
    """Store the window: None, or the sentence that refuses it (not HH:MM, or start equal to end)."""
    if not (isinstance(start, str) and _HHMM.match(start) and isinstance(end, str) and _HHMM.match(end)) \
            or start == end:
        return S_BAD_WINDOW
    update_config(lambda cfg: cfg.update({CFG: dict(_raw(cfg), start=start, end=end)}))
    return None


def _raw(cfg):
    got = cfg.get(CFG)
    return dict(got) if isinstance(got, dict) else {}


def set_auto(ref, on):
    """Switch automatic updates on or off for the item `ref` ("website:<id>", "addon:<server id>:<add-on>")."""
    if not isinstance(ref, str) or not REF_RE.match(ref):
        return S_BAD_REF

    def _mutate(cfg):
        raw = _raw(cfg)
        off = {r for r in (raw.get("off") or []) if isinstance(r, str) and REF_RE.match(r)}
        off = (off - {ref}) if on else (off | {ref})
        raw["off"] = sorted(off)[:_OFF_MAX]
        cfg[CFG] = raw
    update_config(_mutate)
    return None


def auto_on(ref, cfg=None):
    """Whether automatic updates are on for the item `ref` (on unless switched off)."""
    return ref not in (cfg or settings())["off"]


# ── the window on a host's clock ───────────────────────────────────────────────────────────────
def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def host_zone(remote):
    """The IANA zone of `remote`'s clock (RemoteServer.timezone), "UTC" when it is not known."""
    return clock.valid_timezone(getattr(remote, "timezone", "") or "") or "UTC"


def host_now(remote, now=None):
    """The wall time now on `remote`'s clock, as a naive datetime. `now` (epoch seconds) is for tests."""
    from zoneinfo import ZoneInfo
    return datetime.fromtimestamp(time.time() if now is None else now, ZoneInfo(host_zone(remote))).replace(tzinfo=None)


def window_key(wall, cfg):
    """The date (YYYY-MM-DD) the window holding the wall time `wall` began, or None when `wall` is outside it.

    A window that runs past midnight (23:30-00:30) began the day before for the part after midnight.
    """
    s, e, t = _minutes(cfg["start"]), _minutes(cfg["end"]), wall.hour * 60 + wall.minute
    if s < e:
        return wall.date().isoformat() if s <= t < e else None
    if t >= s:
        return wall.date().isoformat()
    return (wall.date() - timedelta(days=1)).isoformat() if t < e else None


def next_start(remote, cfg, now=None):
    """The next time the window opens on `remote`'s clock, as "HH:MM" and whether that is today or tomorrow."""
    wall = host_now(remote, now)
    s = _minutes(cfg["start"])
    today = wall.hour * 60 + wall.minute < s
    return {"at": cfg["start"], "end": cfg["end"], "zone": host_zone(remote), "today": today}


# ── the signed catalog's security marks ────────────────────────────────────────────────────────
def security():
    """{"addons", "sites", "note"} from the signed catalog's `security` section (the floor's when it has none)."""
    from panel.services import addons_catalog as _cat
    try:
        floor, signed, _src = _cat.section("security")
    except Exception:
        return _cs.parsed(None)
    return _cs.parsed(signed if signed is not None else floor)


def site_part(site):
    """The `sites` section part `site`'s image comes from (catalog_security.SITE_PARTS)."""
    return {"static": "static", "wordpress": "wordpress", "app": "runtimes"}.get(site.kind, "php")


# ── what the pages last read: add-ons and LinuxGSM ─────────────────────────────────────────────
def note_addons(gs_id, found):
    """Remember which of a server's installed add-ons have an update (`found`: addons.parse_status()["addons"])."""
    from panel.routes import addons_change as _ch
    rows = {}
    for k, got in (found or {}).items():
        meta = (got or {}).get("meta") or {}
        try:
            reason = _ch.update_reason(k, meta)
            version, new = _ch.shown_version(k, meta, True)
        except KeyError:
            continue
        rows[k] = {"reason": reason, "version": version, "new": new}
    with _SEEN_LOCK:
        _ADDONS_SEEN[gs_id] = {"at": time.time(), "rows": rows}


def note_lgsm(gs_id, info):
    """Remember a server's LinuxGSM state ({"release", "latest", "behind"}) as the server page read it."""
    if not isinstance(info, dict):
        return
    with _SEEN_LOCK:
        _LGSM_SEEN[gs_id] = {"at": time.time(), "release": info.get("release") or "",
                             "latest": info.get("latest") or "", "behind": bool(info.get("behind"))}


def note_lgsm_cron(gs_id, jobs):
    """Remember whether a server's crontab runs update-lgsm, as its Scheduled tasks card last read it (`jobs`).

    `jobs` is ssh_manager.list_cron_jobs' list; None (the crontab could not be read) keeps what was known.
    """
    if not isinstance(jobs, list):
        return
    found = [j for j in jobs if isinstance(j, dict) and _LGSM_CRON_RE.search(str(j.get("command") or ""))]
    with _SEEN_LOCK:
        _LGSM_CRON[gs_id] = {"at": time.time(), "schedule": str(found[0].get("schedule") or "")[:60] if found else ""}


def lgsm_cron_seen(gs_id):
    """{"at", "schedule"} of a server's update-lgsm task as last read, or None when its crontab was not read yet."""
    with _SEEN_LOCK:
        got = _LGSM_CRON.get(gs_id)
        return dict(got) if got else None


def forget_server(gs_id):
    """Drop what was read for a server (it was removed, or its id may be handed out again)."""
    with _SEEN_LOCK:
        _ADDONS_SEEN.pop(gs_id, None)
        _LGSM_SEEN.pop(gs_id, None)
        _LGSM_CRON.pop(gs_id, None)


def addons_seen(gs_id):
    with _SEEN_LOCK:
        return dict((_ADDONS_SEEN.get(gs_id) or {}).get("rows") or {})


def lgsm_seen(gs_id):
    with _SEEN_LOCK:
        return dict(_LGSM_SEEN.get(gs_id) or {})


def tr(sentence, **vals):
    """A row's words in the viewer's language."""
    return i18n.tr(i18n.Sentence(sentence, **vals)) if vals else i18n.tr(sentence)


def count_cached(user_id, compute):
    """The nav's count for a viewer: `compute()` at most once per COUNT_TTL seconds."""
    now = time.time()
    with _SEEN_LOCK:
        got = _COUNTS.get(user_id)
    if got and now - got[0] < COUNT_TTL:
        return got[1]
    n = compute()
    with _SEEN_LOCK:
        if len(_COUNTS) > 500:
            _COUNTS.clear()
        _COUNTS[user_id] = (now, n)
    return n


def forget_counts():
    """Recount on the next page: an update ran, or a setting changed."""
    with _SEEN_LOCK:
        _COUNTS.clear()
