"""The B3 players section's actions: unban, kick and warn, done by B3 itself over its control socket.

PERMISSION (Authorization Cheat Sheet: "Deny by Default", "Validate the Permissions on Every Request",
"Enforce Least Privileges"). Each action takes Manage add-ons (the section's own permission) and the
moderation permission it is: Ban players for an unban, Kick players for a kick or a warning (B3's
warnings add up to its own kicks and temporary bans). Both are granted to no group by default, and both
are checked in the route on every request. A sign-in older than the confirmation window confirms the
password first (step-up), as an add-on's install does. B3's Panel actions setting must be on: without it
B3 opens no socket and the panel has nothing to send to.

HOW. The request is one JSON line on stdin to a client inside B3's own container (services/b3_control,
`podman exec`, as the game account: the root-capable-account guard runs first). The panel sends
`actor` "panel:<username>", which B3 writes to b3.log and events.jsonl beside the command; who may act
is decided here, never by that label. A kick or a warning needs the player's slot: it is found by the
name B3 stored for that B3 id in the game's own player list (one console read, the moderation buttons'
own lookup), and only a name that one listed player has is used. B3 then answers which player it acted
on; another one (the slot changed hands in between) is said and audited.

AUDIT (Logging Cheat Sheet, "Which events to log"; "Data to exclude"). Every action and every refusal
past the permission check writes an audit row with the server: what, the player's B3 id, the slot, and
how B3 answered. Never the reason's text or the player's name: both are what people typed and can name
someone; B3's own events.jsonl keeps the reason.
"""
from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.http import _json_body
from panel.db.models import db
from panel.ops import ssh_manager as _sm
from panel.routes import addons as _ra, addons_b3 as _r3
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.security.auth import (MANAGE_ADDONS, can_moderate_action, get_game, has_permission, log_action,
                                 server_access_required)
from panel.services import addons as _ad, b3_control as _b3c, b3_players as _b3

# The section's action -> the moderation permission it takes (security/auth.can_moderate_action).
NEEDS = {"unban": "ban", "kick": "kick", "warn": "kick"}
S_ACTIONS_OFF = "Panel actions are off for this B3: turn them on in its B3 settings, then try again."
S_B3_DOWN = "B3 isn't running, or didn't answer, so it can't take the command. Start it on its card, then try again."
S_BAD_REASON = "A reason is at most 100 characters, with no line break, control character or colour code (^)."
S_NEED_REASON = "A warning needs a reason."
S_NOT_ONLINE = ("That player isn't on the game server now, or another player there has the same name, so B3 can't "
                "be told which slot to act on.")
S_NO_ID = "B3 has no player with that B3 id."
S_NO_SLOT = "B3 sees no player on that slot now."
S_REFUSED = "B3 refused it ({code}): {message}"
S_DONE = {"unban": "B3 lifted the player's bans ({n}).", "kick": "B3 kicked the player.",
          "warn": "B3 warned the player."}
S_OTHER = ("B3 acted on slot {slot}, whose player is B3 id @{got}, not @{want}: the player on that slot changed in "
           "between.")
S_BAD_FLAG = "Send enabled: true or false."
S_ALERTS = {True: "Alerts for B3's bans and kicks on this server are on.",
            False: "Alerts for B3's bans and kicks on this server are off."}


def offered(gs):
    """What the player view may offer this viewer: {"on": Panel actions on, and each action this viewer may take}."""
    return {"on": _b3.actions_on(gs.id) is True,
            "unban": can_moderate_action(current_user, "ban"), "kick": can_moderate_action(current_user, "kick"),
            "warn": can_moderate_action(current_user, "kick")}


def _audit(gs, action, ok, detail):
    """One audit row for an action (each written with its own literal name, which the audit backfill knows)."""
    if action == "unban":
        log_action(current_user, "b3_unban", target=gs.name, server=gs, success=ok, detail=detail)
    elif action == "kick":
        log_action(current_user, "b3_kick", target=gs.name, server=gs, success=ok, detail=detail)
    else:
        log_action(current_user, "b3_warn", target=gs.name, server=gs, success=ok, detail=detail)


def _send(gs, cmd, args):
    """Send one command to B3's control socket: b3_control.reply's (state, value)."""
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _b3c.socket_sh(), timeout=30,
                                           selfname=gs.lgsm_name,
                                           stdin_text=_b3c.request(cmd, args, current_user.username))
    return _b3c.reply(out, rc)


def _slot_of(gs, client_id):
    """(the slot of B3 player `client_id` in the game's own list, None) or (None, (status, sentence))."""
    got, bad = _r3._read(gs, [_b3.name_statement(client_id)], 1)
    if bad:
        return None, bad
    rows = _b3.records(got[0])
    if not rows:
        return None, (404, _r3.S_NO_PLAYER)
    name = _b3.plain(rows[0].get("name")).strip()
    hit = _sm._resolve_from_console(gs.remote, gs.short_name, gs.game_type, name, gs.lgsm_name) if name else None
    num = _b3c.slot((hit or {}).get("num"))
    return (num, None) if num else (None, (409, S_NOT_ONLINE))


def _said(action, state, got):
    """(HTTP status, sentence, audited outcome) for B3's answer to anything but a success."""
    if state == "off":
        return 409, S_ACTIONS_OFF, "the control socket is off"
    if state == "down":
        return 502, S_B3_DOWN, "B3 did not answer"
    code, message = got
    if code == "not_found":
        return 404, (S_NO_ID if action == "unban" else S_NO_SLOT), "B3: not_found"
    return 502, i18n.Sentence(S_REFUSED, code=code, message=message), "B3 refused: %s" % code


def _answer(gs, action, client_id, num, sent):
    """The route's answer to B3's reply `sent`, audited."""
    state, got = sent
    where = (", slot %s" % num) if num else ""
    if state != "ok":
        status, sentence, outcome = _said(action, state, got)
        _audit(gs, action, False, "B3 player @%d%s: %s" % (client_id, where, outcome))
        return _r3._say(status, sentence)
    acted = got.get("client_id")
    if action != "unban" and acted != client_id:
        _audit(gs, action, True, "B3 player @%d%s: B3 acted on @%s instead" % (client_id, where, acted))
        said = i18n.tr(i18n.Sentence(S_OTHER, slot=num, got=acted if isinstance(acted, int) else "?", want=client_id))
        return jsonify({"success": True, "warning": True, "message": said})
    n = got.get("bans_lifted") if isinstance(got.get("bans_lifted"), int) else 0
    _audit(gs, action, True, "B3 player @%d%s: done%s" % (client_id, where, ", %d bans lifted" % n if action == "unban"
                                                          else ""))
    return jsonify({"success": True, "message": i18n.tr(i18n.Sentence(S_DONE[action], n=n))})


def _act(gs, action, client_id):
    reason = _b3c.clean_reason(_json_body().get("reason"), required=action == "warn")
    if reason is None:
        return _r3._say(400, S_NEED_REASON if action == "warn" and not _json_body().get("reason") else S_BAD_REASON)
    if client_id > _b3c.CLIENT_ID_MAX or client_id < 1:
        return _r3._say(404, _r3.S_NO_PLAYER)
    extra = {"reason": reason} if reason else {}
    if action == "unban":
        return _answer(gs, action, client_id, None, _send(gs, "unban", dict(extra, client_id=client_id)))
    num, bad = _slot_of(gs, client_id)
    if bad:
        _audit(gs, action, False, "B3 player @%d: no slot (%s)" % (client_id, "not listed" if bad[0] == 409 else
                                                                   "not read"))
        return _r3._say(*bad)
    return _answer(gs, action, client_id, num, _send(gs, action, dict(extra, cid=num)))


def _alerts_answer(server_id):
    enabled = _json_body().get("enabled")
    if not isinstance(enabled, bool):
        return _r3._say(400, S_BAD_FLAG)
    gs = get_game(server_id)
    if _ad.B3 not in _ad.offered(gs.game_type):
        return _r3._say(404, _ra._UNKNOWN)
    gs.b3_alerts = enabled
    db.session.commit()
    from panel.services import b3_events   # it reads the database at sweep time
    b3_events.forget(gs.id)                # turned on again: only what B3 writes from now on
    log_action(current_user, "b3_alerts_set", target=gs.name, server=gs,
               detail="alerts for B3's bans and kicks %s" % ("on" if enabled else "off"))
    return jsonify({"success": True, "enabled": enabled, "message": i18n.tr(S_ALERTS[enabled])})


def register(app):
    """Register the actions' routes (called by routes/addons_b3.py's register)."""

    # One route per action, each written out (a page's fetch names the whole path the step-up gate reads).
    @app.route("/api/server/<int:server_id>/addons/b3/players/<int:client_id>/unban", methods=["POST"],
               defaults={"action": "unban"})
    @app.route("/api/server/<int:server_id>/addons/b3/players/<int:client_id>/kick", methods=["POST"],
               defaults={"action": "kick"})
    @app.route("/api/server/<int:server_id>/addons/b3/players/<int:client_id>/warn", methods=["POST"],
               defaults={"action": "warn"})
    @login_required
    @server_access_required
    def api_server_b3_player_action(server_id, client_id, action):
        """Unban, kick or warn one of B3's players, through B3 (its control socket)."""
        if action not in NEEDS:
            return _r3._say(404, _ra._UNKNOWN)
        if not (has_permission(current_user, MANAGE_ADDONS) and can_moderate_action(current_user, NEEDS[action])):
            return _r3._say(403, _r3._DENIED)
        if step_up_needed():          # an action on a player through the game account: confirm first
            return step_up_refusal()
        return _ra._guarded(server_id, _ad.B3, lambda gs: _act(gs, action, client_id))

    @app.route("/api/server/<int:server_id>/addons/b3/alerts", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_b3_alerts(server_id):
        """Turn this server's alerts for B3's bans, temporary bans and kicks on or off."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _r3._say(403, _r3._DENIED)
        return _alerts_answer(server_id)
