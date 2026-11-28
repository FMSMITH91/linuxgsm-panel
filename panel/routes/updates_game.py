"""The Updates page's game rows: a newer build of a server's game, and how to install it.

Registered from routes/updates.register. Rows come from services/game_updates (what the last check-update or update
of each server said), so opening the page asks no host anything. Who sees a row and its buttons: whoever may run
the server's Update (the server page's own permission, UPDATE_SERVER, on a server they can reach).

POST /api/updates/game/<id>         {"when": "now"}    Update now (game_updates_run.update_now: players warned first)
                                    {"when": "empty"}  Update when empty (queued; the due-actions sweep runs it)
                                    {"when": "cancel"} no longer queued
POST /api/updates/game/<id>/backup  {"on": bool}       the nightly window backs it up first
POST /api/updates/games/check       check-update on every server the viewer may read (VIEW_CONSOLE, the server
                                    page's check-update), one at a time in the background, the busy ones skipped
"""
import threading
from datetime import datetime, timezone

from flask import jsonify, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.http import _json_body
from panel.db.models import GameServer, db
from panel.security.auth import (VIEW_CONSOLE, _perm_for_action, get_game, get_user_servers, has_permission,
                                 log_action, server_access_required)
from panel.services import game_updates as _gu, game_updates_run as _gur, updates as U, updates_auto as UA

S_DENIED = "You can't change that."
S_NO_UPDATE = "This server has no game update to install."
S_CHECKING = "Checking {n} game server(s) one at a time. The list fills in as each answers."
S_NOTHING_TO_CHECK = "No game server here is yours to check."
S_GAME_OFF_NOTE = ("OWASP recommends installing updates promptly: with automatic updates off, this game waits for "
                   "someone to press Update now.")
COST_STOPPED = "Nobody is kicked: the server is stopped, and stays stopped."
COST_MEASURED = "Players are kicked: the server restarts (about {n} min, as its last update took)."
COST_UNMEASURED = "Players are kicked: the server restarts while it updates (how long depends on the download)."
_CHECKING = {"n": 0}
_CHECK_LOCK = threading.Lock()


def may_update(user):
    """Whether `user` may run a game server's Update at all (each server is checked again by its access)."""
    return bool(user.is_superadmin or has_permission(user, _perm_for_action("update")))


def checking():
    """How many game servers the page's Check now still has to read."""
    with _CHECK_LOCK:
        return _CHECKING["n"]


def cost(gs):
    """What a game update costs, in the viewer's words: who is kicked and for how long, as far as the panel knows."""
    if gs.status not in ("online", "starting", "unresponsive"):
        return U.tr(COST_STOPPED)
    mins = _gu.update_minutes(gs.id)
    return U.tr(COST_MEASURED, n=mins) if mins else U.tr(COST_UNMEASURED)


# The nightly window's words for a game, by where its host's clock is (services/updates.window_phase).
WHEN_WINDOW = {"now": "By itself now, in tonight's window (until {end}, the host's clock), if no players are on.",
               "tonight": "By itself tonight at {at} (the host's clock), if no players are on.",
               "next": "By itself the next night at {at} (the host's clock), if no players are on."}


def when(gs, auto, cfg):
    """(when, link) of a game update: the queue a person asked for, its own scheduled update task, or the window.

    The queue first: Update when empty runs it as soon as nobody is on, before any task or window would.
    """
    if gs.update_pending:
        return U.tr("Queued: it updates as soon as no players are on."), None
    cron = (U.lgsm_cron_seen(gs.id) or {}).get("game")
    if cron:
        return U.tr("By itself: its scheduled task runs update ({schedule}, the host's clock).", schedule=cron), None
    if not auto:
        return U.tr("Automatic updates are off for it: it waits for Update now."), None
    if UA.tried_now("game:%d" % gs.id, gs.remote, cfg):
        return U.tr("Tried in tonight's window, it waits: by itself the next night at {at} (the host's clock).",
                    at=cfg["start"]), None
    return U.tr(WHEN_WINDOW[U.window_phase(gs.remote, cfg)], at=cfg["start"], end=cfg["end"]), None


S_CONFIRM_TITLE = "Update {name} now?"
S_WARNED_FIRST = ("The {n} player(s) on now are warned in the game first: by the panel 1 minute before the update, or "
                  "by LinuxGSM's own countdown where its warning timer is set.")
S_NOT_WARNED = "The {n} player(s) on now are not warned first: this game's console has no chat command the panel uses."


def confirm(gs):
    """(title, body) of Update now's question: the server by name, what it costs, and whether players are warned.

    The player count is the one the panel last read (monitoring's cache); the page asks no host anything.
    """
    from panel.services import schedule_chains as _sch
    from panel.services.monitoring import _cached_player_count
    body = [cost(gs)]
    players = _cached_player_count(gs.id)
    if isinstance(players, int) and players > 0 and gs.status in ("online", "starting", "unresponsive"):
        body.append(U.tr(S_WARNED_FIRST if _sch.say_verb(gs.game_type) else S_NOT_WARNED, n=players))
    return U.tr(S_CONFIRM_TITLE, name=gs.name), " ".join(body)


def _checked_at(gs, at):
    """When the panel last read the server's builds, on its host's clock."""
    from panel.routes.updates import host_time
    stamp = datetime.fromtimestamp(at, timezone.utc).replace(tzinfo=None)
    return host_time(stamp, U.host_zone(gs.remote))


def game_row(gs, got, cfg):
    """The row of server `gs`, whose last check found a newer build (`got`: game_updates.seen)."""
    from panel.routes.updates import _row
    auto = U.game_auto_on(gs, cfg)
    old, new = got.get("local") or "?", got.get("remote") or "?"
    what = [U.tr("{old} to {new} (branch {branch}).", old=old, new=new, branch=got["branch"]) if got.get("branch")
            else U.tr("{old} to {new}.", old=old, new=new)]
    what.append(U.tr("LinuxGSM's check, {at} (the host's clock).", at=_checked_at(gs, got.get("at") or 0)))
    notes = ([{"title": "SteamDB", "url": "https://steamdb.info/app/%s/history" % got["appid"]}]
             if got.get("appid") else [])
    said, link = when(gs, auto, cfg)
    post = url_for("api_updates_game", server_id=gs.id)
    title, body = confirm(gs)
    return _row("game", "game:%d" % gs.id, gs.name, host=gs.remote.display_name if gs.remote else "", what=what,
                notes=notes, cost=cost(gs), auto=auto, auto_editable=True, when=said, when_link=link,
                auto_why=U.tr(_gu.default_auto(gs.game_type)[1]), backup=str(gs.id) in cfg["backup"],
                action={"post": post, "body": {"when": "now"}, "confirm": body, "confirm_title": title},
                later={"post": post, "queued": bool(gs.update_pending)},
                backup_post=url_for("api_updates_game_backup", server_id=gs.id),
                link=url_for("server_detail", server_id=gs.id))


def game_rows(user, servers, cfg):
    """The game rows `user` may see: servers they can reach and update, whose last check found a newer build."""
    if not may_update(user):
        return []
    return [game_row(gs, got, cfg) for gs in servers
            for got in (_gu.seen(gs.id),) if got.get("state") == "available" and gs.supports_update]


def _check_all(app, ids):
    """Check now: check-update on each server in `ids`, one at a time (game_updates.check_server skips busy ones)."""
    try:
        with app.app_context():
            for gs_id in ids:
                try:
                    gs = db.session.get(GameServer, gs_id)
                    if gs is not None and gs.remote is not None:
                        _gu.check_server(gs)
                except Exception:  # noqa: BLE001 - one server failing never stops the next
                    db.session.rollback()
                    app.logger.debug("game update check of %s failed", gs_id, exc_info=True)
                finally:
                    with _CHECK_LOCK:
                        _CHECKING["n"] = max(0, _CHECKING["n"] - 1)
            U.forget_counts()
    finally:
        with _CHECK_LOCK:
            _CHECKING["n"] = 0


def _refused(msg, code):
    return jsonify({"success": False, "message": i18n.tr(msg)}), code


def _game_target(server_id):
    """(the server, None) when it has a game update to install, else (None, the reply). The route checks who first."""
    gs = get_game(server_id)
    if not gs.installed or not gs.supports_update:
        return None, _refused(S_NO_UPDATE, 400)
    return gs, None


def register(app):
    """The game rows' routes."""
    @app.route("/api/updates/game/<int:server_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_updates_game(server_id):
        if not (current_user.is_superadmin or has_permission(current_user, _perm_for_action("update"))):
            return _refused(S_DENIED, 403)     # the server page's Update permission (UPDATE_SERVER)
        gs, refused = _game_target(server_id)
        if refused:
            return refused
        mode = _json_body().get("when")
        if mode == "now":
            ok, msg = _gur.update_now(app, gs, current_user)
        elif mode in ("empty", "cancel"):
            ok, msg = _gur.queue_when_empty(gs, current_user, mode == "empty")
        else:
            return _refused(S_DENIED, 400)
        U.forget_counts()
        # Said as the server page says its own actions' answers (Sentences, translated whole). `when`: the row's line
        # as it reads now (a queued update says so before any task or window).
        from panel.routes.server_detail import _r15e_said
        cfg = U.settings()
        return jsonify({"success": bool(ok), "message": _r15e_said(msg), "queued": bool(gs.update_pending),
                        "when": when(gs, U.game_auto_on(gs, cfg), cfg)[0]})

    @app.route("/api/updates/game/<int:server_id>/backup", methods=["POST"])
    @login_required
    @server_access_required
    def api_updates_game_backup(server_id):
        if not (current_user.is_superadmin or has_permission(current_user, _perm_for_action("update"))):
            return _refused(S_DENIED, 403)     # the server page's Update permission (UPDATE_SERVER)
        gs, refused = _game_target(server_id)
        if refused:
            return refused
        on = _json_body().get("on")
        if not isinstance(on, bool):
            return _refused(S_DENIED, 400)
        U.set_backup_first(gs.id, on)
        log_action(current_user, "updates_auto", target=gs.name, server=gs,
                   detail="game:%d back up first %s" % (gs.id, "on" if on else "off"))
        return jsonify({"success": True, "backup": on})

    @app.route("/api/updates/games/check", methods=["POST"])
    @login_required
    def api_updates_games_check():
        if not (current_user.is_superadmin or has_permission(current_user, VIEW_CONSOLE)):
            return _refused(S_DENIED, 403)
        ids = [gs.id for gs in get_user_servers(current_user) if gs.installed and gs.supports_update]
        if not ids:
            return jsonify({"success": True, "started": 0, "message": i18n.tr(S_NOTHING_TO_CHECK)})
        with _CHECK_LOCK:
            if _CHECKING["n"]:
                return jsonify({"success": True, "started": 0, "message": i18n.tr(S_CHECKING, n=_CHECKING["n"])})
            _CHECKING["n"] = len(ids)
        log_action(current_user, "game_update_check", target="game servers", detail="%d server(s)" % len(ids))
        threading.Thread(target=_check_all, args=(app, ids), daemon=True).start()
        return jsonify({"success": True, "started": len(ids), "message": i18n.tr(S_CHECKING, n=len(ids))}), 202
