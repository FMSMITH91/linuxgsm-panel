"""The nightly window: website and add-on updates applied by themselves, so none waits on someone pressing Update.

WHEN. Every TICK seconds the loop asks, for each website and each game server with add-ons, whether its host's
clock is inside the window (services/updates.settings: 04:00-05:00 by default). Each item is tried once per
window (_DONE): one that is busy, or that fails, waits for the next night.

WHAT. A website whose image or site files changed (routes/websites.update_available) and an installed add-on
whose image differs from the catalog's (routes/addons_change.update_reason), when automatic updates are on for
it or the update is a security one (the signed catalog's `security` section): security updates are applied
even where an item's automatic updates are off. Panel, host packages and LinuxGSM keep their own settings
(the update check, unattended-upgrades on each host, LinuxGSM's own cron jobs).

ONE AT A TIME. The loop runs one update, waits for its end, then takes the next (OWASP Top 10 2025 A03,
"How to prevent": avoid updating everything at once; staged rollouts).

BUSY. A website with open connections from the web proxy (it answered a visitor in the last minutes:
ssh_manager.websites.recent_requests), or whose host did not say, waits; an add-on whose game server has
players on (the player poll's last count) waits. A skip is recorded in the history (update_skipped).

FAILURE. The update's own code runs (the website's Update, the add-on's Update with the account's write
refusal first). When it fails, the item is put back on what it ran before: the website installed again from
its previous image (services/websites.pinned_image), the add-on's previous record and unit restored and
started (services/addons.rollback_sh). The history says so, and the auto_update_failed alert is sent.
"""
import logging
import threading
import time

from panel.core import i18n, runtime_stats
from panel.services import updates as U

_log = logging.getLogger("panel.updates.auto")

TICK = 300
ACTOR = "automatic"
_DONE = {}                 # item ref -> the window key it was tried in
RUN_LOCK = threading.Lock()
SITE_STATES = ("running", "stopped", "failed")


def loop(app):
    """The supervised loop ("auto-updates"): a tick every TICK seconds. Never raises."""
    runtime_stats.loop_started("auto-updates", TICK)
    time.sleep(90)            # let the start settle (the player poll's first counts)
    while True:
        t0 = time.time()
        try:
            tick(app)
        except Exception:
            runtime_stats.bump("loopfail", "auto-updates")
            _log.debug("automatic updates tick failed", exc_info=True)
        runtime_stats.beat("auto-updates", TICK, time.time() - t0)
        time.sleep(TICK)


def tick(app, now=None):
    """One pass: every website, then every game server's add-ons, whose host is inside the window now."""
    if not RUN_LOCK.acquire(blocking=False):
        return                # the last pass (or Update everything safe now) is still running
    try:
        with app.app_context():
            for site_id in _site_ids():
                _site_pass(app, site_id, now)
            for gs_id in _server_ids():
                _server_pass(app, gs_id, now)
    finally:
        RUN_LOCK.release()


def _site_ids():
    from panel.db.models import Website
    return [i for (i,) in Website.query.with_entities(Website.id).filter(Website.state.in_(SITE_STATES)).all()]


def _server_ids():
    from panel.db.models import GameServer
    return [i for (i,) in GameServer.query.with_entities(GameServer.id).filter(GameServer.installed.is_(True)).all()]


def _due(ref, remote, cfg, now):
    """The window key when `ref` may be tried now (its host inside the window, not tried in it yet), else None."""
    key = U.window_key(U.host_now(remote, now), cfg)
    return key if key is not None and _DONE.get(ref) != key else None


def wanted(ref, security, cfg):
    """Whether the window applies an item's update: automatic updates on for it, or a security update."""
    return bool(security) or U.auto_on(ref, cfg)


# ── websites ───────────────────────────────────────────────────────────────────────────────────
def _site_pass(app, site_id, now):
    from panel.db.models import Website, db
    from panel.routes import websites as _w
    site = db.session.get(Website, site_id)
    if site is None or site.remote is None or not _w.update_available(site):
        return
    cfg, ref = U.settings(), "website:%d" % site.id
    security = U.site_part(site) in U.security()["sites"]
    key = _due(ref, site.remote, cfg, now)
    if key is None or not wanted(ref, security, cfg):
        return
    _DONE[ref] = key
    busy = _site_busy(site)
    if busy:
        _site_audit(site, "update_skipped", busy, True)
        return
    update_site(app, site, ACTOR)


def _site_busy(site):
    """Why `site` waits for the next window ("" when it may be updated now)."""
    from panel.ops.ssh_manager import websites as _sw
    open_now = _sw.recent_requests(site.remote, site)
    if open_now is None:
        return "automatic: not updated, its host did not say whether it is busy; the next window tries again"
    if open_now:
        return "automatic: not updated, it answered visitors in the last minutes; the next window tries again"
    return ""


def _site_audit(site, action, detail, ok, who=ACTOR, user=None):
    from panel.security.auth import log_website_action
    log_website_action(user, site, action, detail=detail, success=ok, actor=who)


def update_site(app, site, who, user=None):
    """Update `site` with its own Update (routes/websites.install_site); on failure put it back. -> (ok, sentence)."""
    from panel.routes import websites as _w
    prev = site.image_digest or ""
    ok, said = _w.install_site(site)
    _w.forget_status(site.id)
    if ok:
        _w.note_run_state(site, ok, said)
        _site_audit(site, "website_update", "%s: image updated" % who, True, who, user)
        U.forget_counts()
        return True, said
    back, back_said = rollback_site(site, prev)
    words = "%s: failed: %s; %s" % (who, i18n.tr(said), "put back on its previous image" if back
                                     else "could not be put back: %s" % i18n.tr(back_said))
    _site_audit(site, "website_update", words, False, who, user)
    _alert(site.name, back)
    return False, said


def rollback_site(site, prev):
    """Install `site` again from its previous image `prev` (still on the host). -> (ok, sentence)."""
    from panel.routes import websites as _w
    if not prev:
        return False, "the panel had not recorded its previous image"
    site.rollback_image = prev
    try:
        ok, said = _w.install_site(site)
    finally:
        site.rollback_image = ""
    _w.forget_status(site.id)
    if ok:
        _w.note_run_state(site, ok, said)
    return ok, said


def _alert(name, back):
    from panel.services import notifications
    try:
        notifications.notify(
            "auto_update_failed", "Automatic update failed: %s" % name,
            "The automatic update of %s failed. %s See Updates in the panel." % (
                name, "It was put back on what it ran before." if back else "It could not be put back: check it now."))
    except Exception:
        _log.debug("auto_update_failed alert not sent", exc_info=True)


# ── add-ons ────────────────────────────────────────────────────────────────────────────────────
def _server_pass(app, gs_id, now):
    from panel.db.models import GameServer, db
    gs = db.session.get(GameServer, gs_id)
    if gs is None or gs.remote is None:
        return
    cfg = U.settings()
    from panel.services import addons as _ad
    # The server's add-ons are read from its host once per window: every later pass finds it done.
    key = _due("server:%d" % gs.id, gs.remote, cfg, now)
    if key is None or not _ad.offered(gs.game_type):
        return
    _DONE["server:%d" % gs.id] = key
    for addon_id, security in _pending_addons(gs, cfg):
        ref = "addon:%d:%s" % (gs.id, addon_id)
        key = _due(ref, gs.remote, cfg, now)
        if key is None or not wanted(ref, security, cfg):
            continue
        _DONE[ref] = key
        _addon_once(app, gs, addon_id)


def _pending_addons(gs, cfg):
    """[(add-on id, security)] of the server's installed add-ons with an image update, read from its host now."""
    from panel.ops import ssh_manager as _sm
    from panel.routes._shared import game_account_write_refusal
    from panel.services import addons as _ad
    if game_account_write_refusal(gs.remote, gs.short_name, reading=True):
        return []
    try:
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
    except Exception:
        return []
    if rc != 0:
        return []
    U.note_addons(gs.id, _ad.parse_status(out)["addons"])
    sec = U.security()["addons"]
    return [(k, k in sec) for k, row in sorted(U.addons_seen(gs.id).items()) if row.get("reason") == "image"]


def _addon_once(app, gs, addon_id):
    """Update one add-on unless its game server has players on (update_addon refuses the rest)."""
    from panel.services.monitoring import _cached_player_count
    players = _cached_player_count(gs.id)
    if isinstance(players, int) and players > 0:
        _addon_skipped(gs, addon_id, "it has players on", ACTOR)
        return
    update_addon(app, gs, addon_id, ACTOR)


def _addon_skipped(gs, addon_id, why, who):
    from panel.security.auth import log_action
    log_action(None, "update_skipped", target=gs.name, actor=who, server=gs,
               detail="%s: %s not updated, %s; the next window tries again" % (who, addon_id, why))


def _addon_refusal(gs):
    """Why the server's add-ons may not be changed now ("" when they may): its account, or a reboot of its host.

    The card's own checks (routes/addons._guarded): the root-capable-account refusal before anything runs as the
    game account, and a clean reboot whose plan holds the server.
    """
    from panel.routes._shared import _reboot_holds, game_account_write_refusal
    why = game_account_write_refusal(gs.remote, gs.short_name)
    if why:
        return str(why)
    return "its host is being rebooted" if _reboot_holds(gs) else ""


def update_addon(app, gs, addon_id, who):
    """Update the add-on with its card's Update, in this thread; put it back when it fails. -> (ok, why)."""
    from panel.db.models import row_birth
    from panel.routes import addons as _ra, addons_change as _ch
    from panel.security.auth import log_action
    from panel.services import addon_web as _aw
    refused = _addon_refusal(gs)
    if refused:
        _addon_skipped(gs, addon_id, refused, who)
        return False, refused
    with _ra._JOBS_LOCK:
        job = _ra.claim_job(gs.id, addon_id, "update")
    if job is not None:
        return False, _ra.busy_sentence(job)
    _aw.revoke_server(gs.id, addon_id)
    _ch._worker(app, gs.id, row_birth(gs), addon_id, who, "update", None)
    with _ra._JOBS_LOCK:
        why = (_ra._JOBS.get((gs.id, addon_id)) or {}).get("why") or ""
    U.forget_counts()
    if not why:
        return True, ""
    back = rollback_addon(gs, addon_id)
    log_action(None, "addon_update", target=gs.name, actor=who, server=gs, success=False,
               detail="%s: %s" % (addon_id, "put back on its previous version" if back else "could not be put back"))
    _alert("%s (%s)" % (addon_id, gs.name), back)
    return False, why


def rollback_addon(gs, addon_id):
    """Put the add-on back on the record and unit it had before the update (addons.rollback_sh): whether it runs."""
    from panel.ops import ssh_manager as _sm
    from panel.routes._shared import game_account_write_refusal
    from panel.services import addons as _ad
    if game_account_write_refusal(gs.remote, gs.short_name):
        return False
    try:
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.rollback_sh(gs.short_name, addon_id),
                                               timeout=_ad.INSTALL_TIMEOUT, selfname=gs.lgsm_name)
    except Exception:
        return False
    return rc == 0 and "ADDON_ROLLED_BACK" in (out or "")
