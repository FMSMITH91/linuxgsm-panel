"""Running a game's update: Update now (players warned first), Update when empty, and the nightly window's.

Every update goes through the server's own action path (routes/server_detail._run_action): the same holds (an
install, a clean reboot, a wipe), the same console output, audit rows and version refresh as the server page's
Update, and LinuxGSM's own player rules (stoponlyifnoplayers postpones it). Each of these paths runs LinuxGSM as
the game account, so each asks the account's write refusal first (routes/_shared.game_account_write_refusal).

UPDATE NOW with players on: on a game whose console has a chat command (schedule_chains.say_verb: the warning
chain's own table) and where LinuxGSM does not warn them itself (lgsm_players.lgsm_warns), the panel says
WARN_TEXT in the console, waits WARN_SECS, then runs the update. Players are told once.

UPDATE WHEN EMPTY sets the server's update_pending; the due-actions sweep (routes/_shared._settle_queued_action,
every 90 seconds) runs it once the server is read online with no players, or stopped (settle_queued).

THE NIGHTLY WINDOW (services/updates_auto) runs update_game: one server at a time, only with nobody on. With the
server's "Back up first" switch on it stops a running server, backs it up, updates it and starts it again:
LinuxGSM's backup stops and starts a running server itself, and an update straight after would stop one that is
still starting.
"""
import logging
import threading
import time

from panel.core import i18n

_log = logging.getLogger("panel.updates.games")

WARN_SECS = 60
WARN_TEXT = "The server restarts in 1 minute to install a game update."
STEP_TIMEOUT = {"stop": 300, "start": 300, "backup": 3 * 3600, "update": 3 * 3600}
S_WARNED = "Players were warned in the game; the update starts in 1 minute."
S_QUEUED = "Queued: {name} updates its game once no players are on."
S_UNQUEUED = "No longer queued: {name} does not wait to update."


def _sd():
    from panel.routes import server_detail
    return server_detail


def _refusal(gs):
    from panel.routes._shared import game_account_write_refusal
    return game_account_write_refusal(gs.remote, gs.short_name)


def _warns_itself(gs):
    """Whether LinuxGSM warns this server's players before its update (its timer), so the panel says nothing."""
    from panel.services import lgsm_players as _lgp
    try:
        return _lgp.lgsm_warns(gs.remote, gs)
    except Exception:  # noqa: BLE001 - unread: the panel warns (players told at least once)
        return False


def update_now(app, gs, user):
    """Update `gs`'s game now for `user`. -> (ok, sentence). Players on are warned first where the panel can."""
    from panel.db.models import row_birth
    from panel.services import schedule_chains as _sch
    from panel.services.monitoring import _cached_player_count
    why = _refusal(gs)
    if why:
        return False, why
    verb = _sch.say_verb(gs.game_type)
    players = _cached_player_count(gs.id)
    if verb and isinstance(players, int) and players > 0 and not _warns_itself(gs):
        threading.Thread(target=_warn_then_update, args=(app, gs.id, row_birth(gs), user.id, verb),
                         daemon=True).start()
        return True, i18n.Sentence(S_WARNED)
    return _sd()._run_action(app, gs, gs.remote, "update", user)


def _warn_then_update(app, gs_id, born, user_id, verb):
    """Say WARN_TEXT in the server's console, wait WARN_SECS, then run the update (still the same server)."""
    from panel.db.models import GameServer, User, claim_row, db
    from panel.ops.ssh_manager import send_console_command
    from panel.security.auth import log_action
    with app.app_context():
        gs, user = claim_row(GameServer, gs_id, born), db.session.get(User, user_id)
        if gs is None or user is None:
            return
        try:
            send_console_command(gs.remote, gs.short_name, "%s %s" % (verb, WARN_TEXT), timeout=10,
                                 selfname=gs.lgsm_name)
        except Exception:  # noqa: BLE001 - a warning that did not go out does not stop the update asked for
            app.logger.debug("update warning not sent", exc_info=True)
        log_action(user, "update_warned", target=gs.name, server=gs, detail="%s; the update starts in %d s"
                   % (WARN_TEXT, WARN_SECS))
        name = gs.name
    time.sleep(WARN_SECS)
    with app.app_context():
        gs, user = claim_row(GameServer, gs_id, born), db.session.get(User, user_id)
        if gs is None or user is None:
            app.logger.info("update of %s not run: the server is gone", name)
            return
        _sd()._run_action(app, gs, gs.remote, "update", user)


def queue_when_empty(gs, user, on):
    """Queue (or un-queue) `gs`'s update for once no players are on. -> (ok, sentence)."""
    from panel.db.models import db
    from panel.security.auth import log_action
    if on:
        why = _refusal(gs)
        if why:
            return False, why
    gs.update_pending = bool(on)
    db.session.commit()
    log_action(user, "update_when_empty", target=gs.name, server=gs, detail="queued" if on else "no longer queued")
    return True, i18n.Sentence(S_QUEUED if on else S_UNQUEUED, name=gs.name)


def only_update_queued(gs):
    """Whether `gs`'s only queued action is its update (a queued stop or restart is settled first)."""
    return bool(gs.update_pending) and not (gs.restart_pending or gs.stop_pending)


def settle_queued(app, gs, decision):
    """Run `gs`'s queued update when the due-actions sweep read it empty or stopped (`decision` not "pending").

    Called by routes/_shared._settle_queued_action. The update starts through _run_action and the queue clears;
    a hold (a wipe, a backup, any action the panel runs on it, a clean reboot) leaves it queued for the next sweep.
    An account the panel may not run code as is never updated: the queue clears and the history says why.
    """
    from panel.core.panel_state import r36j_route_jobs
    from panel.db.models import db
    from panel.routes._shared import _backup_in_progress, _r39a_wipe_running, uninstall_running
    from panel.security.auth import log_action
    if decision == "pending":
        return False
    if (_r39a_wipe_running(gs.id) or _backup_in_progress(gs.id) or uninstall_running(gs.id)
            or r36j_route_jobs(gs.id)):
        return False
    why = _refusal(gs)
    if why:
        gs.update_pending = False
        db.session.commit()
        log_action(None, "update_skipped", target=gs.name, actor="when empty", server=gs, success=False,
                   detail="queued update not run: %s" % i18n.tr(why))
        return False
    ok, _msg = _sd()._run_action(app, gs, gs.remote, "update", None, origin="when empty")
    if ok:
        gs.update_pending = False
        db.session.commit()
    return ok


# ── the nightly window ─────────────────────────────────────────────────────────────────────────
def _run_wait(app, gs, action, origin):
    """Run `action` through _run_action and wait for its end. -> (ok, detail); ok None: LinuxGSM postponed it."""
    done, got = threading.Event(), {}

    def _on_done(ok, detail):
        got.update(ok=ok, detail=detail)
        done.set()
    ok, msg = _sd()._run_action(app, gs, gs.remote, action, None, origin=origin, on_done=_on_done)
    if not ok:
        return False, i18n.tr(msg)
    if not done.wait(STEP_TIMEOUT[action]):
        return False, "%s did not finish within %d minutes" % (action, STEP_TIMEOUT[action] // 60)
    return got.get("ok"), got.get("detail") or ""


def _steps(backup, online):
    if not backup:
        return ("update",)
    return (("stop",) if online else ()) + ("backup", "update") + (("start",) if online else ())


def update_game(app, gs, who, backup):
    """The nightly window's update of `gs`'s game, backed up first when `backup`. -> whether it updated.

    A step that fails stops the run; a server it stopped is started again. The history has each step's rows
    (_run_action's own); a failure also sends the auto_update_failed alert.
    """
    from panel.routes._shared import get_server_status
    why = _refusal(gs)
    if why:
        _skipped(gs, i18n.tr(why), who)
        return False
    online = bool(backup) and get_server_status(gs.remote, gs) == "online"
    for action in _steps(backup, online):
        ok, said = _run_wait(app, gs, action, who)
        if ok:
            continue
        if online and action in ("backup", "update"):
            _run_wait(app, gs, "start", who)       # it was running before the run stopped it
        if ok is None:
            _skipped(gs, "LinuxGSM postponed its %s: %s" % (action, said), who)
        else:
            _alert(gs.name, action, said)
        return False
    return True


def _skipped(gs, why, who):
    from panel.security.auth import log_action
    log_action(None, "update_skipped", target=gs.name, actor=who, server=gs,
               detail="%s: game not updated, %s; the next window tries again" % (who, why))


def _alert(name, action, said):
    from panel.services import notifications
    try:
        notifications.notify(
            "auto_update_failed", "Automatic update failed: %s" % name,
            "The automatic game update of %s failed at its %s: %s. See Updates in the panel."
            % (name, action, said[:200]))
    except Exception:  # noqa: BLE001 - an alert channel that failed never stops the window
        _log.debug("auto_update_failed alert not sent", exc_info=True)
