"""The Discord bot: Gateway transport, the socket watch, and self-update reporting.

Moved out of app.py verbatim — see panel/services/bots/__init__.py.
"""
from panel.core.config import (decrypt_secret, load_config, update_config)
from panel.ops import system_ops as so
from panel.services import (notifications)
from panel.services.bots.commands import (BUSY_REPLY, CommandWorker, _bot_origin,
    _panel_ver_label, _command_arg, _connect_text, _console_text, _find_server,
    _hosts_text, _reply_header, _players_text, _say_text,
    _servers_text, _status_text, action_ack, update_outcome_text, working_ack,
    UPDATE_RUNNING_REPLY, audit_bot_action, bot_update_status, command_refusal,
    panel_update_requested, queue_panel_update, sender_id, spend_update_check,
    update_rate_reply)
from panel.db.models import (LOCAL_HOST_LABEL)
import functools
import logging
import time

# Same logger name app.py used, so existing log filters and greps keep working.
_log = logging.getLogger("panel.app")
# This bot's name in audit rows and refusals — a constant, so the command routers carry no
# platform literal of their own (smoke_test compares the quoted words in the two routers).
_PLATFORM = "discord"
# Bound at import, not looked up as time.monotonic at the call: tests stand in for `time` with an
# object that only sleeps, and the session timing below must still read a real clock.
_clock = time.monotonic


# ── Discord command bot (Gateway) ──────────────────────────────
# Two-way control over Discord. Unlike Telegram (outbound long-poll), Discord needs a persistent Gateway
# WebSocket, so this keeps one open in a background greenlet and posts replies over the bot REST API. The
# command SET, auth model (only the configured channel, and only allowed user ids for anything that
# changes state), and per-command text are shared with the Telegram bot — only the transport (reply
# send / update-pending marker) differs.
_DC_CMD_BACKOFF = 15
# ── How often the Gateway may be dialled ───────────────────────────────────────────────────────
# Every session start is an IDENTIFY, and Discord allows a bot 1,000 of those a day; past that it
# resets the bot's token. The watcher used to reconnect 15 s after EVERY session end, whatever
# ended it — including the close codes that mean "this will never work": 4004 (the token is
# wrong or was reset) and 4014 (the Message Content intent is not enabled, the commonest setup
# mistake). A session refused at IDENTIFY ends in about a second, so that was an IDENTIFY every
# ~16 s — about 5,400 a day, five times the limit, for a bot that could not have worked anyway.
#
# Now: a fatal close code stops the bot, says why once in the log and on the Notifications page,
# and it stays stopped until the token or the "Accept commands" setting changes (or, in case the
# fix was made in the Developer Portal, once every _DC_FATAL_RETRY). Any other end backs off
# exponentially, doubling from _DC_CMD_BACKOFF to _DC_BACKOFF_MAX, and only a session that lasted
# _DC_SESSION_HEALTHY resets it — so a session that keeps dying young cannot cost more than one
# IDENTIFY per _DC_BACKOFF_MAX, and a long-lived one that drops reconnects promptly as before.
_DC_BACKOFF_MAX = 900
_DC_SESSION_HEALTHY = 300
_DC_FATAL_RETRY = 6 * 3600
_DC_FATAL_CLOSE = {
    4004: "Discord rejected the bot token (close code 4004). Paste a fresh token from the "
          "Developer Portal and save.",
    4010: "Discord refused the session: invalid shard (close code 4010).",
    4011: "Discord refused the session: this bot is in too many servers to run unsharded "
          "(close code 4011).",
    4012: "Discord refused the session: invalid Gateway API version (close code 4012).",
    4013: "Discord refused the session: invalid intents (close code 4013).",
    4014: "Discord refused the bot's intents (close code 4014). In the Developer Portal, under "
          "Bot → Privileged Gateway Intents, turn on Message Content Intent, then untick and "
          "re-tick \"Accept commands\" here and save.",
}
# Commands run here, not on the Gateway socket thread. More than a latency fix on this transport:
# the socket that is not being read is the same one that has to answer Discord's heartbeats, so a
# command that blocked it could get the session dropped and reconnected mid-answer.
_DC_WORKER = CommandWorker("discord-commands")


def _dc_reply(bot_token, channel_id, text):
    notifications.discord_bot_send(bot_token, channel_id, "%s\n%s" % (_reply_header(), text))


def _dc_literal(body):
    """Show `body` exactly as written: in a code block, with no backtick left to close it.

    For the text a player controls: their names (!players) and the console tail (!console), which on
    most engines carries in-game chat. allowed_mentions stops that pinging anyone, but Discord still
    rendered the rest of its markdown in the bot's own message, so a player named
    `[Panel login expired](https://evil.example/login)`, or one saying `# Re-authenticate at ...` in
    chat, had the operator's bot post a clickable masked link or a headline in the admin channel.
    Nothing in a code block is rendered or linked; U+02CB stands in for each backtick so the block
    cannot be ended from inside it.
    """
    return "```\n%s\n```" % (body or "").replace("`", "\u02cb")


def _dc_ack(bot_token, channel_id, text):
    """The immediate "working on it" line — the twin of telegram._tg_ack.

    See telegram._tg_ack for the reasoning; the two bots deliberately behave the same way. No
    _reply_header(), because the ack lands right under the command that caused it.
    """
    notifications.discord_bot_send(bot_token, channel_id, text)


def _parse_dc_command(text):
    """Normalise a Discord command word: '!Restart foo' or '/status' -> 'restart'/'status'.

    Accepts a '!' or '/' prefix — Discord reserves '/' for its own slash-command picker, so '!' is
    the one that types cleanly. '' if it isn't a command.
    """
    text = (text or "").strip()
    if not text or text[0] not in "!/":
        return ""
    parts = text[1:].split()
    return parts[0].split("@")[0].lower() if parts else ""


def _dc_on_message(app, _tok, msg_channel, author_is_bot, content, author=None):
    """Handle one Gateway message for the session opened with bot token `_tok`."""
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
    _chan = _dc_gate_channel(_dc, msg_channel, content)
    if not _chan:
        return
    text = content.strip()
    # ...and the SENDER, for anything that changes state: everyone who can post in the
    # channel is "the authorised channel". author.id is Discord's, not the sender's to
    # choose. Re-read per message like the rest of the gate. See _tg_route_update.
    refusal = command_refusal("discord", _parse_dc_command(text), _command_arg(text),
                              author, notifications.command_users(_dc))
    if refusal:
        _log.info("discord: refused a command from user %s, who is not on the allowed "
                  "list", sender_id(author) or "?")
        _dc_reply(_tok, _chan, refusal)
        return
    _dc_dispatch(app, _tok, _chan, text, author)


def _dc_gate_channel(_dc, msg_channel, content):
    """The authorised channel id when this message passes the channel gate, else ''."""
    if not (_dc.get("enabled") and _dc.get("accept_commands")):
        return ""
    _chan = (_dc.get("channel_id") or "").strip()
    if not _chan or msg_channel != _chan:
        return ""
    if (content or "")[:1] not in ("!", "/"):
        return ""
    return _chan


def _dc_watch_token():
    """The bot token when commands are switched on and fully configured, else ''."""
    cfg = notifications._cfg()
    dc = cfg.get("discord") or {}
    bot_token = decrypt_secret(dc.get("bot_token") or "")
    channel = (dc.get("channel_id") or "").strip()
    if not (dc.get("enabled") and dc.get("accept_commands") and bot_token and channel):
        return ""
    return bot_token


def _dc_fatal_holds(fatal, fatal_gen, bot_token):
    """True while the last fatal close still holds for this token and settings generation."""
    return bool(fatal and fatal[0] == bot_token and _clock() - fatal[1] < _DC_FATAL_RETRY
                and fatal_gen == notifications.discord_settings_generation())


def _discord_command_watch(app):
    """Keep a Discord Gateway session open and honour commands from the authorised channel only.

    Mirrors _telegram_command_watch: reconnect-with-backoff, each command routed to the same
    channel-agnostic text builders the Telegram bot uses. A dropped socket reconnects after a
    backoff (a fresh IDENTIFY skips any backlog, so the /update that restarted us is never
    replayed); a session Discord closed for good does not — see _DC_FATAL_CLOSE.
    """
    backoff = _DC_CMD_BACKOFF
    fatal = None      # (bot token, when) of the last fatal close, while it still holds
    fatal_gen = None  # the settings generation at that close: any save since lifts the hold
    while True:
        wait = backoff
        try:
            bot_token = _dc_watch_token()
            if not bot_token:
                # Switched off: forget a fatal close and the backoff, so switching it back on (the
                # page's advice after fixing the intent in the Portal) connects at once.
                if fatal:
                    notifications.set_discord_gateway_problem("")
                fatal, backoff = None, _DC_CMD_BACKOFF
                time.sleep(_DC_CMD_BACKOFF)
                continue
            if _dc_fatal_holds(fatal, fatal_gen, bot_token):
                time.sleep(_DC_CMD_BACKOFF)       # a config read, no IDENTIFY: cheap to repeat
                continue
            if fatal:
                fatal = None                      # a new token, or time to try the old one again
                notifications.set_discord_gateway_problem("")
            started = _clock()
            code = notifications.discord_gateway_run(   # returns when the socket drops
                bot_token, functools.partial(_dc_on_message, app, bot_token))
            fatal, backoff = _dc_after_session(bot_token, code, _clock() - started, backoff)
            fatal_gen = notifications.discord_settings_generation()
            wait = backoff
        except Exception:
            _log.debug("discord command-watch tick failed", exc_info=True)
        time.sleep(wait)


def _dc_after_session(bot_token, code, lasted, backoff):
    """Decide what follows a Gateway session that ended with `code` after `lasted` seconds.

    Returns (fatal, backoff): `fatal` is (bot_token, now) when Discord closed the session for a
    reason retrying cannot fix, else None; `backoff` is the wait before the next IDENTIFY.
    """
    if code in _DC_FATAL_CLOSE:
        why = _DC_FATAL_CLOSE[code]
        # Once per fatal close — which, with the hold below, is once per _DC_FATAL_RETRY at most.
        _log.warning("discord command bot stopped: %s It stays off until the bot token or "
                     "\"Accept commands\" changes.", why)
        notifications.set_discord_gateway_problem(why)
        return (bot_token, _clock()), _DC_CMD_BACKOFF
    if lasted >= _DC_SESSION_HEALTHY:
        return None, _DC_CMD_BACKOFF
    return None, min(_DC_BACKOFF_MAX, backoff * 2)


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
            "`!help` — this message\n"
            "Anyone here can use `!status`, `!servers`, `!hosts`, `!connect` and `!help`; the "
            "rest need your user ID on the panel's allowed list.")


def _dc_dispatch(app, bot_token, channel_id, text, sender=None):
    """Ack on the socket thread, run the command on the worker — Telegram's twin.

    See _tg_dispatch for why the ack cannot be queued along with the work.
    """
    cmd = _parse_dc_command(text)
    ack = working_ack(cmd)
    if ack:
        _dc_ack(bot_token, channel_id, ack)

    def job():
        _handle_discord_command(app, bot_token, channel_id, text, sender)

    if panel_update_requested(cmd, _command_arg(text)):
        # One panel !update in flight at a time — see _tg_dispatch (Aikido 745379272).
        outcome = queue_panel_update(_DC_WORKER, "discord", job)
        if outcome != "queued":
            _dc_reply(bot_token, channel_id,
                      UPDATE_RUNNING_REPLY if outcome == "running" else BUSY_REPLY)
        return
    if not _DC_WORKER.submit(job):
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
    """Run one command from the authorised channel and answer it there."""
    cmd = _parse_dc_command(text)
    arg = _command_arg(text)
    # The commands that only answer: one reply each, built by a shared text helper. Built per call
    # and resolved by name when it runs, so each helper is still looked up as a module attribute.
    replies = {
        "help": _dc_help_text,
        "status": lambda: _status_text(app),
        "servers": lambda: _servers_text(app),
        "hosts": lambda: _hosts_text(app),
        "players": lambda: _players_text(app, arg, fence=_dc_literal),
        "console": lambda: _console_text(app, arg, fence=_dc_literal),
        "say": lambda: _say_text(app, arg, origin=_bot_origin(_PLATFORM, sender)),
        "connect": lambda: _connect_text(app, arg),
    }
    if cmd in replies:
        _dc_reply(bot_token, channel_id, replies[cmd]())
    elif cmd in ("restart", "start", "stop", "backup"):
        _dc_server_action(app, bot_token, channel_id, cmd, arg, sender)
    elif cmd in ("update", "upgrade"):
        # Same rule as Telegram: an argument names a server, not the panel. (See the note there.)
        if arg:
            _dc_server_action(app, bot_token, channel_id, "update", arg, sender)
        else:
            _discord_do_update(app, bot_token, channel_id, sender)
    elif cmd:
        _dc_reply(bot_token, channel_id, "Unknown command '%s'. Send !help." % cmd[:24])


def _discord_do_update(app, bot_token, channel_id, sender=None):
    # Not force=True, and the self-update's own forced check is metered — see _telegram_do_update.
    try:
        st = bot_update_status()
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _dc_reply(bot_token, channel_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    if not spend_update_check():
        _dc_reply(bot_token, channel_id, update_rate_reply())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    audit_bot_action(app, _bot_origin("discord", sender), "panel_self_update", LOCAL_HOST_LABEL,
                     detail=msg, success=ok)
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


def _dc_channel_still_authorised(dc, channel):
    """Whether the Discord settings `dc` still take commands from `channel` — the watcher's gate."""
    return bool(dc.get("enabled") and dc.get("accept_commands")
                and (dc.get("channel_id") or "").strip() == str(channel).strip())


def _report_dc_pending_update():
    """After a restart, tell the channel how a Discord-triggered update went, if one was pending.

    It compares the git commit before/after; commands.update_outcome_text words the answer for
    both bots.
    """
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
    # The channel was authorised when it sent !update, which is not the same as being authorised
    # now: the marker outlives the restart, and the admin may have switched the bot off, turned
    # commands off, or moved it to another channel in between. The watcher re-reads that gate on
    # every message; this report went to the marker's channel whatever the settings said.
    if not _dc_channel_still_authorised(dc, channel):
        _log.info("discord: the pending update report was dropped; its channel is no longer the "
                  "authorised one")
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or ""
    # The same split as telegram.py's twin, now one shared wording: an EMPTY commit means git could
    # not be read — panel_commit() returns "" when `git rev-parse` fails or times out, in the busy
    # seconds after a restart — and that is not "no new commit landed". Reporting it as one, with
    # "already current, or it rolled back" as the causes, sent the admin to !update a second time.
    _dc_reply(bot_token, channel, update_outcome_text(now, frm))
