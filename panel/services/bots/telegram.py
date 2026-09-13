"""The Telegram bot: transport, the long-poll watch, and self-update reporting.

Moved out of app.py verbatim — see panel/services/bots/__init__.py.
"""
from panel.core.config import (decrypt_secret, load_config, update_config)
from panel.ops import system_ops as so
from panel.services import (notifications)
from panel.services.bots.commands import (_bot_origin, _panel_ver_label,
    _command_arg, _connect_text, _console_text, _find_server,
    _hosts_text, _reply_header, _players_text, _say_text,
    _servers_text, _status_text)
import logging
import time

# Same logger name app.py used, so existing log filters and greps keep working.
_log = logging.getLogger("panel.app")
# ── Telegram command bot ───────────────────────────────────────────────────────────────────────
# Drive the panel from the configured Telegram chat: /update, /status, /servers, /help. Opt-in
# (Notifications → Telegram → "Accept commands") and locked to the saved chat_id — no other chat is
# honoured. Discord webhooks are send-only, so this is Telegram-only. Long-polls getUpdates.
_TG_CMD_BACKOFF = 15


def _tg_reply(token, chat_id, text):
    notifications.send_telegram(token, chat_id, "%s\n%s" % (_reply_header(), text))


def _parse_tg_command(text):
    """Normalise a Telegram command: '/Update@MyBot foo' -> 'update'. '' if it isn't a command."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return ""
    return text.split()[0].split("@")[0].lstrip("/").lower()


def _telegram_command_watch(app):
    """Long-poll loop: honour commands from the authorised chat only. Skips any backlog on (re)start
    so a command sent while we were down — including the /update that caused our own restart — is
    never replayed."""
    offset, primed, registered = None, False, False
    while True:
        try:
            cfg = notifications._cfg()
            tg = cfg.get("telegram") or {}
            token = decrypt_secret(tg.get("token") or "")
            if not (tg.get("enabled") and tg.get("accept_commands")):
                if registered and token:
                    notifications.telegram_set_commands(token, clear=True)   # drop the '/' menu
                    registered = False
                time.sleep(_TG_CMD_BACKOFF)
                offset, primed = None, False   # re-prime (skip backlog) when it's re-enabled
                continue
            authorized = (tg.get("chat_id") or "").strip()
            if not token or not authorized:
                time.sleep(_TG_CMD_BACKOFF)
                continue
            if not registered:
                # Populate Telegram's '/' autocomplete menu with the bot's commands.
                registered = bool(notifications.telegram_set_commands(token))
            if not primed:
                latest = notifications.telegram_get_updates(token, offset=-1, timeout=0)
                if latest:
                    offset = latest[-1].get("update_id", 0) + 1
                primed = True
                continue
            updates = notifications.telegram_get_updates(token, offset=offset, timeout=25)
            if updates is None:
                time.sleep(_TG_CMD_BACKOFF)   # error / 409 conflict (a second poller) → back off
                continue
            for upd in updates:
                offset = upd.get("update_id", 0) + 1
                msg = upd.get("message") or upd.get("edited_message") or {}
                text = (msg.get("text") or "").strip()
                chat = str((msg.get("chat") or {}).get("id") or "")
                if not text.startswith("/"):
                    continue
                if chat != authorized:
                    _log.info("telegram: ignoring a command from unauthorised chat %s", chat[:32])
                    continue
                _handle_telegram_command(app, token, authorized, text, msg.get("from"))
        except Exception:
            _log.debug("telegram command-watch tick failed", exc_info=True)
            time.sleep(_TG_CMD_BACKOFF)


def _tg_help_text():
    return ("Commands:\n"
            "/status — panel version + server counts\n"
            "/servers — servers with player counts\n"
            "/hosts — hosts and their status\n"
            "/players <name> — who's on a server\n"
            "/console <name> — the last 20 console lines\n"
            "/connect <name> — the address to give players\n"
            "/say <name> <message> — announce it in-game\n"
            "/start <name> — start a server\n"
            "/stop <name> — stop a server\n"
            "/restart <name> — restart a server\n"
            "/backup <name> — back a server up\n"
            "/update — update the panel itself\n"
            "/update <name> — update that ONE game server instead\n"
            "/help — this message")


def _tg_server_action(app, token, chat_id, action, arg, sender=None):
    run_action = getattr(app, "_run_action", None)
    with app.app_context():
        gs, err = _find_server(arg)
        if err:
            _tg_reply(token, chat_id, err)
            return
        if not run_action:
            _tg_reply(token, chat_id, "That action isn't available right now.")
            return
        try:
            # origin, not actor=None: this is attributable to a chat message, and the audit
            # log should say so rather than filing it under "system".
            ok, msg = run_action(gs, gs.remote, action, None,
                                 origin=_bot_origin("telegram", sender))
        except Exception:
            _log.debug("telegram server action failed", exc_info=True)
            ok, msg = False, "the action failed"
        _tg_reply(token, chat_id, "%s %s — %s" % ("✅" if ok else "⚠️", gs.name, msg))


def _handle_telegram_command(app, token, chat_id, text, sender=None):
    cmd = _parse_tg_command(text)
    arg = _command_arg(text)
    # A BARE /start is Telegram's own "open the chat" command and should answer with help — but
    # `/start <server>` is the documented way to start a server (it is in TG_COMMANDS, so Telegram
    # puts it in the '/' menu, and _tg_help_text lists it). Matching on the word alone swallowed
    # every one of those: the branch below never saw "start", so the bot answered a start request
    # with its help text. Discord's equivalent matches "help" only and has always worked.
    if cmd == "help" or (cmd == "start" and not arg):
        _tg_reply(token, chat_id, _tg_help_text())
    elif cmd == "status":
        _tg_reply(token, chat_id, _status_text(app))
    elif cmd == "servers":
        _tg_reply(token, chat_id, _servers_text(app))
    elif cmd == "hosts":
        _tg_reply(token, chat_id, _hosts_text(app))
    elif cmd == "players":
        _tg_reply(token, chat_id, _players_text(app, arg))
    elif cmd == "console":
        _tg_reply(token, chat_id, _console_text(app, arg))
    elif cmd == "say":
        _tg_reply(token, chat_id, _say_text(app, arg))
    elif cmd == "connect":
        _tg_reply(token, chat_id, _connect_text(app, arg))
    elif cmd in ("restart", "start", "stop", "backup"):
        _tg_server_action(app, token, chat_id, cmd, arg, sender)
    elif cmd in ("update", "upgrade"):
        # An argument names a SERVER here, the way it does for every other command that takes one
        # (/start, /stop, /restart, /players). The argument used to be parsed and then dropped, so
        # "/update codserver" — asking for a LinuxGSM update of one game server — silently updated
        # the panel itself and restarted it instead.
        if arg:
            _tg_server_action(app, token, chat_id, "update", arg, sender)
        else:
            _telegram_do_update(app, token, chat_id)
    else:
        _tg_reply(token, chat_id, "Unknown command '%s'. Send /help." % cmd[:24])


def _telegram_do_update(app, token, chat_id):
    try:
        st = so.panel_update_status(force=True)
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _tg_reply(token, chat_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    if not ok:
        _tg_reply(token, chat_id, "⚠️ Update not started: %s" % msg)
        return
    # Store the COMMIT (not the VERSION string, which rarely changes) so the post-restart check can
    # tell whether the update actually landed.
    _set_tg_pending_update(chat_id, so.panel_commit())
    target = (st.get("target_sha") or "")[:7] or "the newest verified commit"
    _tg_reply(token, chat_id, "🔄 Update started: %s → %s. I'll message you here once I'm back."
              % (_panel_ver_label(), target))


def _set_tg_pending_update(chat_id, from_commit):
    # update_config: this runs in the Telegram poller thread, so a plain load+save could clobber a
    # concurrent whitelist/threshold write from an HTTP handler.
    update_config(lambda cfg: cfg.update(
        {"telegram_pending_update": {"chat_id": chat_id, "from_commit": from_commit, "ts": time.time()}}))


def _report_tg_pending_update():
    """After a restart, if a Telegram-triggered update was pending, tell the chat how it went — by
    comparing the git commit before/after (the VERSION string usually doesn't move between commits)."""
    cfg = load_config()
    pend = cfg.get("telegram_pending_update")
    if not pend:
        return
    update_config(lambda c: c.pop("telegram_pending_update", None))   # clear the marker atomically
    tg = (cfg.get("notifications") or {}).get("telegram") or {}
    token = decrypt_secret(tg.get("token") or "")
    chat = pend.get("chat_id") or ""
    if not (token and chat):
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or pend.get("from_version")   # from_version: older pending markers
    if now and frm and now != frm:
        _tg_reply(token, chat, "✅ Update complete — now on %s (was %s). Back online." % (_panel_ver_label(), frm))
    else:
        _tg_reply(token, chat, "ℹ️ Update finished — no new commit landed (already current, or it "
                               "rolled back). Still on %s." % _panel_ver_label())
