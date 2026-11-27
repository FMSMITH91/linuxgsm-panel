"""B3's offline country database, refreshed by itself every month (services/geoip.py fetches and checks it).

THE PANEL'S DOWNLOAD (fetch). The update-check thread (routes/os_updates.py) calls tick() every 30
minutes. geoip.latest downloads a month's file once and keeps it in data/geoip/; fetch asks it only
while the file kept is older than this month and Settings -> Outside services has DB-IP on (off: no
download, every B3 keeps the file it has, and its card says so). Between two asks it waits: after a
page that still shows last month (DB-IP publishes early on the 1st, UTC) UNPUBLISHED_WAIT, and after a
failure FIRST_BACKOFF, doubling up to MAX_BACKOFF. The wait is kept in data/geoip/refresh.json, so a
restart of the panel does not ask early. A failed download or check keeps the last good file.

EACH B3 (visit). For every server of a game B3 is offered for, once per month of the panel's file (and on
each tick while a restart is waiting): one read of the account's add-on records. A B3 set to offline
whose record names an older month gets the file (stdin, base64, written beside and renamed), its
record the month, and B3 loads it without a restart: its geolocation plugin opens the database again
whenever its settings are reloaded, which B3 does since v2.0.2 on SIGHUP or the control socket's
reload_plugins (b3_control.reload_core_sh), no player disconnected. A B3 built from an earlier commit
(NO_RELOAD: to it SIGHUP is the end of the process), or one whose reload got no answer, is restarted
instead, and only once the game reads 0 players (monitoring._server_slots: unread is not empty); until
then its record keeps RESTART_KEY, so the wait survives a restart of the panel, and its card says so.
A B3 that is not running reads the new file at its next start.

Every write to the account comes after game_account_write_refusal, under the add-on's job slot
(routes/addons.claim_job: no Apply, Update or Remove runs beside it), and is audited (addon_geoip) with
the month and what B3 did. Reads of the account are bounded by status_sh's own caps.
"""
import base64
import json
import logging
import os
import threading
import time

from panel.core import i18n
from panel.db.models import GameServer, row_birth
from panel.ops import ssh_manager as _sm
from panel.routes._shared import game_account_write_refusal
from panel.security.auth import log_action
from panel.services import addons as _ad, b3_control as _b3c, geoip as _geoip

_log = logging.getLogger("panel.addons_geoip")

STATE_FILE = "refresh.json"
UNPUBLISHED_WAIT = 6 * 3600     # the page still shows last month: ask again in six hours
FIRST_BACKOFF = 3600            # a failed download: an hour, then 2, 4, 8 ... up to MAX_BACKOFF
MAX_BACKOFF = 24 * 3600
# B3 commits the panel once pinned that have no plugin reload (it came in v2.0.2, bc482bf7): a SIGHUP ends them.
NO_RELOAD = frozenset({"b8e98400c51bb329e026f5b1c5e6f3b50f65518c", "920d736648e2544714ee58a74e556fbbb3881892"})
RESTART_KEY = "geoip_restart"   # addon.json: the month B3 still has to restart for
ACTOR = "country-database-refresh"   # B3 logs the socket's reload as asked by "panel:" + this (b3_control.actor)
JOB = "geoip"

S_PUSH_FAILED = "Couldn't put this month's country database in B3's folder. The panel tries again later."
S_WAITING = ("B3 still uses its earlier country database: the panel restarts it with the {month} one once the "
             "server is empty.")
S_KEPT_OFF = "No monthly refresh while the download is off: B3 keeps the country database it has."
S_FAILED = ("The monthly download of the country database didn't work: {why} B3 keeps the one it has, and the panel "
            "tries again later.")

_DONE = {}                      # server id -> (its row's birth, the month it was read for with nothing to do)
_DONE_LOCK = threading.Lock()


# ── the panel's one download a month ──────────────────────────────────────────────────────────
def _state_path():
    return _geoip.CACHE_DIR / STATE_FILE


def state():
    """The wait between asks: {"next": epoch, "fails": n, "why": the last failure or ""}; empty when unreadable."""
    try:
        with open(_state_path(), encoding="utf-8") as fh:
            got = json.load(fh)
    except (OSError, ValueError):
        got = {}
    got = got if isinstance(got, dict) else {}
    nxt, fails, why = got.get("next"), got.get("fails"), got.get("why")
    return {"next": float(nxt) if isinstance(nxt, (int, float)) and not isinstance(nxt, bool) else 0.0,
            "fails": min(fails, 30) if isinstance(fails, int) and not isinstance(fails, bool) and fails > 0 else 0,
            "why": why if why in (_geoip.UNREACHABLE, _geoip.UNREADABLE, _geoip.BAD_FILE) else ""}


def _save(st):
    """Write the wait, 0600, beside the file (atomically). Best effort: unsaved, the next tick asks again."""
    try:
        _geoip.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _geoip.CACHE_DIR / (STATE_FILE + ".new")
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fh:
            json.dump(st, fh)
        os.replace(tmp, _state_path())
    except OSError:
        _log.warning("couldn't record the country database's next download time", exc_info=True)


def fetch(now=None):
    """The panel's file for the month, downloaded at most once a month: (path or None, month, why or "")."""
    now = time.time() if now is None else now
    path, month = _geoip._cached()
    if path is not None and month >= _geoip.month_now():
        return path, month, ""
    if not _geoip.download_allowed():
        return path, month, _geoip.OFF
    st = state()
    if now < st["next"]:
        return path, month, st["why"]
    path, month, why = _geoip.latest()
    if why:
        fails = min(st["fails"] + 1, 30)
        _save({"next": now + min(FIRST_BACKOFF * 2 ** (fails - 1), MAX_BACKOFF), "fails": fails, "why": why})
    else:
        _save({"next": now + UNPUBLISHED_WAIT if month < _geoip.month_now() else 0, "fails": 0, "why": ""})
    return path, month, why


# ── each B3 ───────────────────────────────────────────────────────────────────────────────────
def tick(app):
    """One pass from the update-check thread. Never raises.

    Each B3 first gets the file the panel already has (no outside request); only when an offline B3
    was found and that file is older than this month is DB-IP asked (fetch), and a newer file found
    there is then taken to each B3 the same way. With no offline B3, nothing is downloaded.
    """
    try:
        with app.app_context():
            path, month = _geoip._cached()
            servers = [gs for gs in GameServer.query.all() if _ad.B3 in _ad.offered(gs.game_type)]
            offline = [visit(gs, path, month) for gs in servers]
            if any(offline) and month < _geoip.month_now():
                new_path, new_month, _why = fetch()
                if new_path is not None and new_month > month:
                    for gs in servers:
                        visit(gs, new_path, new_month)
    except Exception:  # noqa: BLE001 - a background pass: the next one tries again
        _log.warning("country database refresh failed", exc_info=True)


def visit(gs, path, month):
    """Bring server `gs`'s offline B3 to the panel's file (`path`, of `month`) when it needs it. Never raises.

    -> whether the server has a B3 set to offline geolocation (False when it could not be read).
    """
    born = row_birth(gs)
    with _DONE_LOCK:
        done = _DONE.get(gs.id)
    if done is not None and done[:2] == (born, month):
        return done[2]
    if game_account_write_refusal(gs.remote, gs.short_name):
        return False
    from panel.routes import addons as _ra   # it imports the routes that import this module: read at call time
    key = (gs.id, _ad.B3)
    with _ra._JOBS_LOCK:
        before = _ra._JOBS.get(key)
        if _ra.claim_job(gs.id, _ad.B3, JOB) is not None:
            return False                    # an install, change or remove is running: the next tick comes back
    why, done, offline = "", False, False
    try:
        why, done, offline = _step(gs, path, month)
    except Exception:  # noqa: BLE001 - an unreachable host is the next tick's
        _log.debug("country database refresh: server %s not done", gs.id, exc_info=True)
    finally:
        _release(_ra, key, before, why)
    if done:
        with _DONE_LOCK:
            _DONE[gs.id] = (born, month, offline)
    return offline


def _release(_ra, key, before, why):
    """Free the job slot: this refresh's failure on the card, else what the card showed before it."""
    with _ra._JOBS_LOCK:
        if why:
            _ra._JOBS[key] = {"running": False, "why": why, "tail": "", "kind": JOB}
        elif before is not None and before.get("kind") != JOB:
            _ra._JOBS[key] = before
        else:
            _ra._JOBS.pop(key, None)


def _step(gs, path, month):
    """(why not or "", done for the month, offline B3 or not) for one server, its job slot held."""
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
    if rc != 0:
        return "", False, False              # no read is no measurement: the next tick reads again
    found = _ad.parse_status(out)["addons"].get(_ad.B3)
    if found is None or _ad.geo_mode(found["meta"].get("geolocation")) != _ad.GEO_OFFLINE:
        return "", True, False
    meta = found["meta"]
    if path is not None and str(meta.get("geoip") or "") < month:
        return _push(gs, meta, path, month) + (True,)
    if meta.get(RESTART_KEY):
        return _restart_when_empty(gs, meta) + (True,)
    return "", True, True


def reloadable(meta):
    """Whether the installed B3 reloads its plugins without a restart: built from a commit that has the reload."""
    commit = meta.get("commit")
    return isinstance(commit, str) and bool(commit) and commit not in NO_RELOAD


def push_sh(user, rec, reload):
    """Shell, as the account: the file from stdin, the record, then B3 told (or not) to load it.

    Prints GEOIP_RECORDED once the file and the record are in place, then GEOIP_IDLE (B3 not running),
    GEOIP_RUNNING (running, no reload asked) or GEOIP_RELOADED and reload.b64= (the answer, "" when none).
    """
    told = (_b3c.reload_core_sh(user, ACTOR) + "echo GEOIP_RELOADED; " + _b3c.RELOAD_PRINT_SH + "echo; "
            if reload else "echo GEOIP_RUNNING; ")
    return ("%s || { echo GEOIP_PUT_FAILED; exit 21; }; %s || { echo GEOIP_PUT_FAILED; exit 21; }; "
            "echo GEOIP_RECORDED; if systemctl --user is-active -q %s.service; then %selse echo GEOIP_IDLE; fi"
            % (_ad.geoip_put_sh(user, _ad.B3), _meta_put_sh(user, rec), _ad.unit_name(_ad.B3), told))


def _meta_put_sh(user, rec):
    """Shell writing B3's record (addon.json, no secret in it) atomically."""
    return _ad._put_sh("%s/%s" % (_ad.addon_dir(user, _ad.B3), _ad.META_FILE), json.dumps(rec) + "\n")


def restart_sh(user, rec):
    """Shell, as the account: a running B3 restarted (its start limit cleared first), then the record without the wait.

    Prints GEOIP_RESTARTED or GEOIP_IDLE (not running: its next start reads the file), then GEOIP_RECORDED.
    No settle watch: a B3 that fails to come back is left to its unit's Restart=, as after any restart.
    """
    return ("%sumask 077; if systemctl --user is-active -q %s.service; then { %s; } "
            "|| { echo GEOIP_RESTART_FAILED; exit 25; }; echo GEOIP_RESTARTED; else echo GEOIP_IDLE; fi; "
            "%s || { echo GEOIP_PUT_FAILED; exit 21; }; echo GEOIP_RECORDED"
            % (_ad._ENV, _ad.unit_name(_ad.B3), _ad._fresh_start_sh(_ad.B3, "restart"), _meta_put_sh(user, rec)))


def _audit(gs, ok, detail):
    log_action(None, "addon_geoip", target=gs.name, server=gs, success=ok, detail="b3 country database " + detail)


def _push(gs, meta, path, month):
    """Put the panel's file in B3's folder and have B3 load it: (why not or "", done)."""
    reload = reloadable(meta)
    rec = dict(meta, geoip=month, **{RESTART_KEY: month})     # pending until B3 is known to have loaded it
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")   # the panel's own data/geoip file (geoip._cached)
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, push_sh(gs.short_name, rec, reload),
                                           timeout=300, stdin_text=b64)
    out = out or ""
    if rc != 0 or "GEOIP_RECORDED" not in out:
        _audit(gs, False, "%s: not put in place" % month)
        return S_PUSH_FAILED, False
    answer = _ad._unb64(_ad.kv_lines(out).get("reload.b64", ""))
    if "GEOIP_IDLE" in out or ("GEOIP_RELOADED" in out and _b3c.reload_answered(answer)):
        how = "B3 isn't running: it reads it at its next start" if "GEOIP_IDLE" in out else "B3 reloaded it"
        _audit(gs, True, "%s: %s" % (month, how))
        return _record(gs, rec)
    _audit(gs, True, "%s: in place; B3 restarts with it once the server is empty" % month)
    return _restart_when_empty(gs, rec)


def _record(gs, rec):
    """Drop RESTART_KEY from the record: (why not or "", done). Unwritten, the wait stays (one restart too many)."""
    clean = {k: v for k, v in rec.items() if k != RESTART_KEY}
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, "%sumask 077; %s && echo GEOIP_RECORDED"
                                           % (_ad._ENV, _meta_put_sh(gs.short_name, clean)), timeout=30)
    return "", rc == 0 and "GEOIP_RECORDED" in (out or "")


def _players(gs):
    """The game's player count now (0 for a stopped server), or None when it can't be read."""
    from panel.services import monitoring as _mon    # it imports much of the panel: read at call time
    try:
        return _mon._server_slots(gs)[0]
    except Exception:  # noqa: BLE001 - an unread count is not an empty server
        return None


def _restart_when_empty(gs, rec):
    """Restart B3 with the new file once the game is empty: (why not or "", done). Players on: wait."""
    if _players(gs) != 0:
        return "", False
    clean = {k: v for k, v in rec.items() if k != RESTART_KEY}
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, restart_sh(gs.short_name, clean), timeout=120)
    out = out or ""
    month = str(rec.get(RESTART_KEY) or rec.get("geoip") or "")
    if rc != 0 or "GEOIP_RECORDED" not in out:
        _audit(gs, False, "%s: B3's restart with it didn't finish" % month)
        return "", False
    how = ("B3 restarted with it, the server empty" if "GEOIP_RESTARTED" in out
           else "B3 isn't running: it reads it at its next start")
    _audit(gs, True, "%s: %s" % (month, how))
    return "", True


# ── the card ──────────────────────────────────────────────────────────────────────────────────
def card_note(meta):
    """The card's line on the monthly refresh for an offline B3's record `meta` (translated), or ""."""
    if _ad.geo_mode(meta.get("geolocation")) != _ad.GEO_OFFLINE:
        return ""
    if meta.get(RESTART_KEY):
        return i18n.tr(S_WAITING, month=str(meta.get(RESTART_KEY))[:7])
    if not _geoip.download_allowed():
        return i18n.tr(S_KEPT_OFF)
    why = state()["why"]
    if why and str(meta.get("geoip") or "") < _geoip.month_now():
        return i18n.tr(S_FAILED, why=i18n.tr(why))
    return ""
