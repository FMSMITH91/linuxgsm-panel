"""The Discord bot: Gateway transport, the socket watch, and self-update reporting.

Moved out of app.py verbatim — see panel/services/bots/__init__.py.
"""
from panel.core.config import (decrypt_secret, load_config, update_config)
from panel.ops import system_ops as so
from panel.services import (notifications)
from panel.services.bots.commands import (BUSY_REPLY, CommandWorker, _bot_origin,
    _panel_ver_label, _command_arg, _connect_text, _console_text, _find_server,
    _hosts_text, _reply_header, _players_text, _say_text,
    _servers_text, _status_text, action_ack, working_ack)
import logging
import time

# Same logger name app.py used, so existing log filters and greps keep working.
_log = logging.getLogger("panel.app")


# ── Discord command bot (Gateway) ──────────────────────────────
# Two-way control over Discord. Unlike Telegram (outbound long-poll), Discord needs a persistent Gateway
# WebSocket, so this keeps one open in a background greenlet and posts replies over the bot REST API. The
# command SET, auth model (only the configured channel), and per-command text are shared with the
# Telegram bot — only the transport (reply send / update-pending marker) differs.
_DC_CMD_BACKOFF = 15
# Commands run here, not on the Gateway socket thread. More than a latency fix on this transport:
# the socket that is not being read is the same one that has to answer Discord's heartbeats, so a
# command that blocked it could get the session dropped and reconnected mid-answer.
_DC_WORKER = CommandWorker("discord-commands")


def _dc_reply(bot_token, channel_id, text):
    notifications.discord_bot_send(bot_token, channel_id, "%s\n%s" % (_reply_header(), text))


def _dc_ack(bot_token, channel_id, text):
    """The immediate "working on it" line — see telegram._tg_ack for the reasoning; this is its
    twin, and the two bots deliberately behave the same way. No _reply_header(), because the ack
    lands right under the command that caused it."""
    notifications.discord_bot_send(bot_token, channel_id, text)


def _parse_dc_command(text):
    """Normalise a Discord command word: '!Restart foo' or '/status' -> 'restart'/'status'. Accepts a
    '!' or '/' prefix — Discord reserves '/' for its own slash-command picker, so '!' is the one that
    types cleanly. '' if it isn't a command."""
    text = (text or "").strip()
    if not text or text[0] not in "!/":
        return ""
    parts = text[1:].split()
    return parts[0].split("@")[0].lower() if parts else ""


def _discord_command_watch(app):
    """Keep a Discord Gateway session open and honour commands from the authorised channel only.
    Mirrors _telegram_command_watch: reconnect-with-backoff, each command routed to the same
    channel-agnostic text builders the Telegram bot uses. A dropped socket just reconnects (a fresh
    IDENTIFY skips any backlog, so the /update that restarted us is never replayed)."""
    while True:
        try:
            cfg = notifications._cfg()
            dc = cfg.get("discord") or {}
            bot_token = decrypt_secret(dc.get("bot_token") or "")
            channel = (dc.get("channel_id") or "").strip()
            if not (dc.get("enabled") and dc.get("accept_commands") and bot_token and channel):
                time.sleep(_DC_CMD_BACKOFF)
                continue

            def _on_message(msg_channel, author_is_bot, content, author=None, _tok=bot_token):
                # Ignore our own (and every other bot's) messages.
                if author_is_bot:
                    return
                # RE-READ the gate on every message, the way the Telegram twin re-reads it on every
                # poll. It used to be frozen into this closure's default args at IDENTIFY time, and
                # a Gateway session is deliberately long-lived — heartbeat every ~41s, reconnect
                # only on op 7/9 or a dropped socket. So unticking "Accept commands from this
                # channel" (or moving the bot to a locked-down channel) changed the settings page
                # and nothing else: the old channel kept control, and the next `!stop codserver`
                # posted there still stopped the server, for minutes or for days, with no bound the
                # panel could put on it. Revocation has to take effect at the next message, not at
                # the next socket drop.
                _dc = notifications._cfg().get("discord") or {}
                if not (_dc.get("enabled") and _dc.get("accept_commands")):
                    return
                _chan = (_dc.get("channel_id") or "").strip()
                if not _chan or msg_channel != _chan:
                    return
                if (content or "")[:1] not in ("!", "/"):
                    return
                _dc_dispatch(app, _tok, _chan, content.strip(), author)

            notifications.discord_gateway_run(bot_token, _on_message)   # returns when the socket drops
        except Exception:
            _log.debug("discord command-watch tick failed", exc_info=True)
        time.sleep(_DC_CMD_BACKOFF)


def _dc_help_text():
    return ("Commands (type `!cmd`, or `/cmd`):\n"
            "`!status` — panel version + server counts\n"
            "`!servers` — servers with player counts\n"
            "`!hosts` — hosts and their status\n"
            "`!players <name>` — who's on a server\n"
            "`!console <name>` — the last 20 console lines\n"
            "`!connect <name>` — the address to give players\n"
            "`!say <name> <message>` — announce it in-game\n"
            "`!start <name>` — start a server\n"
            "`!stop <name>` — stop a server\n"
            "`!restart <name>` — restart a server\n"
            "`!backup <name>` — back a server up\n"
            "`!update` — update the panel itself\n"
            "`!update <name>` — update that ONE game server instead\n"
            "`!help` — this message")


def _dc_dispatch(app, bot_token, channel_id, text, sender=None):
    """Ack on the socket thread, run the command on the worker — Telegram's twin, see _tg_dispatch
    for why the ack cannot be queued along with the work."""
    ack = working_ack(_parse_dc_command(text))
    if ack:
        _dc_ack(bot_token, channel_id, ack)
    if not _DC_WORKER.submit(
            lambda: _handle_discord_command(app, bot_token, channel_id, text, sender)):
        _dc_reply(bot_token, channel_id, BUSY_REPLY)


def _dc_server_action(app, bot_token, channel_id, action, arg, sender=None):
    run_action = getattr(app, "_run_action", None)
    with app.app_context():
        gs, err = _find_server(arg)
        if err:
            _dc_reply(bot_token, channel_id, err)
            return
        if not run_action:
            _dc_reply(bot_token, channel_id, "That action isn't available right now.")
            return
        # A plain string: _done runs on a worker thread once this app context has closed, where
        # `gs` is detached and reading gs.name would raise.
        name = gs.name

        def _done(ok, detail):
            if ok:
                _dc_reply(bot_token, channel_id, "✅ %s — %s finished." % (name, action))
            else:
                _dc_reply(bot_token, channel_id, "⚠️ %s — %s failed%s"
                          % (name, action, (": " + detail) if detail else "."))

        _dc_ack(bot_token, channel_id, action_ack(action, name))
        try:
            # origin, not actor=None: this is attributable to a chat message, and the audit
            # log should say so rather than filing it under "system".
            ok, msg = run_action(gs, gs.remote, action, None,
                                 origin=_bot_origin("discord", sender), on_done=_done)
        except Exception:
            _log.debug("discord server action failed", exc_info=True)
            ok, msg = False, "the action failed"
        # Silent on success: the ack said it started and _done will say how it ended. Only a
        # refusal needs a word here, because then nothing was backgrounded and _done never runs.
        if not ok:
            _dc_reply(bot_token, channel_id, "⚠️ %s — %s" % (name, msg))


def _handle_discord_command(app, bot_token, channel_id, text, sender=None):
    cmd = _parse_dc_command(text)
    arg = _command_arg(text)
    if cmd == "help":
        _dc_reply(bot_token, channel_id, _dc_help_text())
    elif cmd == "status":
        _dc_reply(bot_token, channel_id, _status_text(app))
    elif cmd == "servers":
        _dc_reply(bot_token, channel_id, _servers_text(app))
    elif cmd == "hosts":
        _dc_reply(bot_token, channel_id, _hosts_text(app))
    elif cmd == "players":
        _dc_reply(bot_token, channel_id, _players_text(app, arg))
    elif cmd == "console":
        _dc_reply(bot_token, channel_id, _console_text(app, arg))
    elif cmd == "say":
        _dc_reply(bot_token, channel_id, _say_text(app, arg))
    elif cmd == "connect":
        _dc_reply(bot_token, channel_id, _connect_text(app, arg))
    elif cmd in ("restart", "start", "stop", "backup"):
        _dc_server_action(app, bot_token, channel_id, cmd, arg, sender)
    elif cmd in ("update", "upgrade"):
        # Same rule as Telegram: an argument names a server, not the panel. (See the note there.)
        if arg:
            _dc_server_action(app, bot_token, channel_id, "update", arg, sender)
        else:
            _discord_do_update(app, bot_token, channel_id)
    elif cmd:
        _dc_reply(bot_token, channel_id, "Unknown command '%s'. Send !help." % cmd[:24])


def _discord_do_update(app, bot_token, channel_id):
    try:
        st = so.panel_update_status(force=True)
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _dc_reply(bot_token, channel_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    if not ok:
        _dc_reply(bot_token, channel_id, "⚠️ Update not started: %s" % msg)
        return
    _set_dc_pending_update(channel_id, so.panel_commit())
    target = (st.get("target_sha") or "")[:7] or "the newest verified commit"
    _dc_reply(bot_token, channel_id, "🔄 Update started: %s → %s. I'll message you here once I'm back."
              % (_panel_ver_label(), target))


def _set_dc_pending_update(channel_id, from_commit):
    # update_config: runs in the Discord watcher greenlet, so use the atomic mutator (not load+save) to
    # avoid clobbering a concurrent config write from an HTTP handler.
    update_config(lambda cfg: cfg.update(
        {"discord_pending_update": {"channel_id": channel_id, "from_commit": from_commit, "ts": time.time()}}))


def _report_dc_pending_update():
    """After a restart, if a Discord-triggered update was pending, tell the channel how it went — by
    comparing the git commit before/after."""
    cfg = load_config()
    pend = cfg.get("discord_pending_update")
    if not pend:
        return
    update_config(lambda c: c.pop("discord_pending_update", None))   # clear the marker atomically
    dc = (cfg.get("notifications") or {}).get("discord") or {}
    bot_token = decrypt_secret(dc.get("bot_token") or "")
    channel = pend.get("channel_id") or ""
    if not (bot_token and channel):
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or ""
    if now and frm and now != frm:
        _dc_reply(bot_token, channel, "✅ Update complete — now on %s (was %s). Back online."
                  % (_panel_ver_label(), frm))
    else:
        _dc_reply(bot_token, channel, "ℹ️ Update finished — no new commit landed (already current, or "
                                      "it rolled back). Still on %s." % _panel_ver_label())
