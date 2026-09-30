"""The Telegram bot: transport, the long-poll watch, and self-update reporting.

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
import logging
import time

# Same logger name app.py used, so existing log filters and greps keep working.
_log = logging.getLogger("panel.app")
# This bot's name in audit rows and refusals — a constant, so the command routers carry no
# platform literal of their own (smoke_test compares the quoted words in the two routers).
_PLATFORM = "telegram"
# ── Telegram command bot ───────────────────────────────────────────────────────────────────────
# Drive the panel from the configured Telegram chat: /update, /status, /servers, /help. Opt-in
# (Notifications → Telegram → "Accept commands") and locked to the saved chat_id — no other chat is
# honoured — and every command that changes anything to the allowed user ids beside it
# (commands.OPEN_COMMANDS). Long-polls getUpdates.
_TG_CMD_BACKOFF = 15
# Commands run here, not on the long-poll thread — see commands.CommandWorker.
_TG_WORKER = CommandWorker("telegram-commands")


def _tg_reply(token, chat_id, text):
    notifications.send_telegram(token, chat_id, "%s\n%s" % (_reply_header(), text))


def _tg_ack(token, chat_id, text):
    """The immediate "I heard you, I'm working on it" line for a command that cannot answer at once.

    Telegram shows nothing of its own while a bot thinks, so a command that has to reach a host
    over SSH — or hand work to a background thread that takes minutes — left the chat completely
    silent until it was over. Tens of seconds of nothing reads as a dead bot, and the usual
    response is to send the command again.

    No _reply_header(): this lands directly under the message you just sent, so which panel
    answered is not in question. The ANSWER keeps the header, because it can arrive long after,
    with other chatter in between.
    """
    notifications.send_telegram(token, chat_id, text)


def _parse_tg_command(text):
    """Normalise a Telegram command: '/Update@MyBot foo' -> 'update'. '' if it isn't a command."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return ""
    return text.split()[0].split("@")[0].lstrip("/").lower()


def _tg_addressed_elsewhere(text, bot_username):
    """True when a command names a bot with '@' and that bot is not this one ('/update@OtherBot').

    _parse_tg_command drops the '@target' — right for '/status@ThisBot', which Telegram clients
    append in groups — so a command addressed to ANOTHER bot in the authorised group ran here too:
    with privacy mode off, or this bot a group admin (admins receive every message),
    '/update@MinecraftBot' self-updated and restarted the panel. An '@' naming a bot this one cannot
    identify (getMe has not answered yet) is not assumed to be this one.
    """
    first = (text or "").strip().split()[0] if (text or "").strip() else ""
    if "@" not in first:
        return False
    target = first.split("@", 1)[1]
    return not (bot_username and target.lower() == bot_username.lower())


def _tg_settings():
    """Read the bot's settings for one tick of the watch: (token, authorised chat id, state).

    `state` is "off" when the bot or its commands are switched off, "unconfigured" when they are on
    but the token or the chat id is missing, and "on" otherwise. The chat id is only read once
    commands are on, and is "" when they are not.
    """
    tg = notifications._cfg().get("telegram") or {}
    token = decrypt_secret(tg.get("token") or "")
    if not (tg.get("enabled") and tg.get("accept_commands")):
        return token, "", "off"
    authorized = (tg.get("chat_id") or "").strip()
    if not token or not authorized:
        return token, authorized, "unconfigured"
    return token, authorized, "on"


def _tg_drop_menu(token, registered):
    """Clear the '/' menu this loop registered, if it did; returns the new `registered`."""
    if registered and token:
        notifications.telegram_set_commands(token, clear=True)   # drop the '/' menu
        return False
    return registered


def _tg_register_menu(token, registered):
    """Register the '/' menu unless it already is; returns the new `registered`."""
    if registered:
        return registered
    # Populate Telegram's '/' autocomplete menu with the bot's commands.
    return bool(notifications.telegram_set_commands(token))


def _tg_bot_username(token, bot_username):
    """Return this bot's @username, asking getMe only while it is still unknown."""
    if bot_username is not None:
        return bot_username
    return notifications.telegram_get_me(token)   # None: asked again next tick


def _tg_offset_after(updates, offset):
    """Return the offset that confirms every update in `updates`, or `offset` when there are none."""
    return updates[-1].get("update_id", 0) + 1 if updates else offset


def _tg_route_update(app, token, authorized, bot_username, upd):
    """Dispatch one polled update when it is a command, from the authorised chat, for THIS bot."""
    # "message" only. An edit arrives as a NEW update carrying the old message, so dispatching
    # "edited_message" ran the command again: fixing a typo in last week's `/stop codserver`, or
    # anyone editing an old `/update`, stopped the server or restarted the panel a second time.
    msg = upd.get("message") or {}
    text = (msg.get("text") or "").strip()
    chat = str((msg.get("chat") or {}).get("id") or "")
    if not text.startswith("/"):
        return
    if chat != authorized:
        _log.info("telegram: ignoring a command from unauthorised chat %s", chat[:32])
        return
    if _tg_addressed_elsewhere(text, bot_username):
        return          # '/update@OtherBot' in the group is that bot's command
    # The chat is not the whole gate: in a group every member is "the authorised chat". A command
    # that changes anything also needs the SENDER's numeric id on the allowed list — see
    # commands.OPEN_COMMANDS. Checked here, beside the chat check, so nothing that fails it ever
    # reaches the worker or acks "working on it". `from` is Telegram's, not the sender's to set.
    # (An anonymous group admin arrives as Telegram's shared GroupAnonymousBot id, so allowing that
    # id would allow every anonymous admin — the settings page says so.)
    sender = msg.get("from")
    refusal = command_refusal("telegram", _parse_tg_command(text), _command_arg(text), sender,
                              _tg_command_users())
    if refusal:
        _log.info("telegram: refused a command from user %s, who is not on the allowed list",
                  sender_id(sender) or "?")
        _tg_reply(token, authorized, refusal)
        return
    _tg_dispatch(app, token, authorized, text, sender)


def _tg_command_users():
    """The Telegram bot's allowed user ids, read afresh (a revocation bites at the next message)."""
    return notifications.command_users(notifications._cfg().get("telegram") or {})


def _telegram_command_watch(app):
    """Long-poll loop: honour commands from the authorised chat only.

    Skips any backlog on (re)start so a command sent while we were down — including the /update
    that caused our own restart — is never replayed.

    The offset is advanced HERE, one update at a time and before that update is routed, so an
    update that makes routing raise is confirmed and skipped by the next poll instead of replaying
    the ones already dispatched ahead of it.
    """
    offset, primed, registered = None, False, False
    state_token = None     # the bot the three values above belong to
    bot_username = None    # this bot's @username (getMe), so '/cmd@OtherBot' is not run here
    while True:
        try:
            token, authorized, state = _tg_settings()
            if token != state_token:
                # A DIFFERENT BOT. update_id sequences are per bot and unrelated, so the old bot's
                # offset either sat above every id the new one had — each poll then confirmed and
                # discarded all of its commands, with no answer and no error, until a restart — or
                # below them, skipping the priming read and replaying up to 24h of the new bot's
                # backlog. `registered` stayed True too, so the new bot never got its '/' menu.
                offset, primed, registered = None, False, False
                state_token, bot_username = token, None
            if state == "off":
                registered = _tg_drop_menu(token, registered)
                time.sleep(_TG_CMD_BACKOFF)
                offset, primed = None, False   # re-prime (skip backlog) when it's re-enabled
                continue
            if state == "unconfigured":
                time.sleep(_TG_CMD_BACKOFF)
                continue
            registered = _tg_register_menu(token, registered)
            bot_username = _tg_bot_username(token, bot_username)
            if not primed:
                # PRIMED ONLY IF THE POLL ANSWERED. telegram_get_updates returns None on a network
                # error, on a 409 (a second poller) and on ok:false — and `primed = True` used to
                # run regardless, leaving offset=None, so the next poll asked Telegram for every
                # unconfirmed update. Telegram holds those for 24 hours, and the window this runs
                # in is the one most likely to fail: the process has just restarted from a
                # self-update. A `/stop codserver` sent hours earlier then stops a running server.
                latest = notifications.telegram_get_updates(token, offset=-1, timeout=0)
                if latest is None:
                    time.sleep(_TG_CMD_BACKOFF)
                    continue          # try again; do NOT mark primed on an answer we never got
                offset = _tg_offset_after(latest, offset)
                primed = True
                continue
            updates = notifications.telegram_get_updates(token, offset=offset, timeout=25)
            if updates is None:
                time.sleep(_TG_CMD_BACKOFF)   # error / 409 conflict (a second poller) → back off
                continue
            for upd in updates:
                offset = upd.get("update_id", 0) + 1
                _tg_route_update(app, token, authorized, bot_username, upd)
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
            "/help — this message\n"
            "Anyone here can use /status, /servers, /hosts, /connect and /help; the rest need "
            "your user ID on the panel's allowed list.")


def _tg_dispatch(app, token, chat_id, text, sender=None):
    """Acknowledge on the POLL thread, then run the command on the worker.

    The ack has to happen here rather than inside the handler. Queueing the whole handler would
    queue its ack too, so a command sent while a slow one was running would stay silent until the
    slow one finished — the silence this is meant to remove, moved rather than fixed. Acking first
    and queueing second means the poll loop is reading again within milliseconds, whatever the
    command turns out to cost.

    /players, /console and /say have to leave the box — a live query to the game, an SSH console
    capture, an in-game announcement. /status, /servers, /hosts and /connect answer from the
    database in the same breath and are deliberately absent from the table: acking an instant
    answer is two notifications for one reply. The table decides, not this router, so Discord
    cannot end up acking a different set. Server actions ack separately, in _tg_server_action,
    because theirs names the server it is acting on.
    """
    cmd = _parse_tg_command(text)
    ack = working_ack(cmd)
    if ack:
        _tg_ack(token, chat_id, ack)

    def job():
        _handle_telegram_command(app, token, chat_id, text, sender)

    if panel_update_requested(cmd, _command_arg(text)):
        # One panel /update in flight at a time: a second one while the first is queued or running
        # is answered, not queued behind it to run the same check again (Aikido 745379272).
        outcome = queue_panel_update(_TG_WORKER, "telegram", job)
        if outcome != "queued":
            _tg_reply(token, chat_id, UPDATE_RUNNING_REPLY if outcome == "running" else BUSY_REPLY)
        return
    if not _TG_WORKER.submit(job):
        _tg_reply(token, chat_id, BUSY_REPLY)


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
        # Captured as a plain string, deliberately: _done runs on a worker thread after this app
        # context has closed, where `gs` is a detached instance and touching gs.name would raise.
        name = gs.name

        def _done(ok, detail):
            # The second half of the exchange. Every action the bot can send runs in the
            # background (see the gate: they are all in LONG_ACTIONS or are power actions), so
            # run_action returns "started", never "finished" — without this the chat heard that a
            # restart began and never heard whether it worked.
            if ok:
                _tg_reply(token, chat_id, "✅ %s — %s finished." % (name, action))
            else:
                _tg_reply(token, chat_id, "⚠️ %s — %s failed%s"
                          % (name, action, (": " + detail) if detail else "."))

        # Ack BEFORE run_action, not after: start/stop probe the host for a live run-state before
        # they will commit to anything, which is an SSH round trip — on an unreachable host, the
        # full connect timeout — and that delay is exactly the silence this is here to remove.
        _tg_ack(token, chat_id, action_ack(action, name))
        try:
            # origin, not actor=None: this is attributable to a chat message, and the audit
            # log should say so rather than filing it under "system".
            ok, msg = run_action(gs, gs.remote, action, None,
                                 origin=_bot_origin("telegram", sender), on_done=_done)
        except Exception:
            _log.debug("telegram server action failed", exc_info=True)
            ok, msg = False, "the action failed"
        # On success say nothing here. run_action's own message is "'restart' issued — status
        # updates in a few seconds", which the ack above already conveyed and _done is about to
        # supersede; relaying it too would make one restart three messages. A refusal
        # ("already running") is different: no background work started, so nothing else will
        # ever speak, and the ack needs correcting.
        if not ok:
            _tg_reply(token, chat_id, "⚠️ %s — %s" % (name, msg))


def _handle_telegram_command(app, token, chat_id, text, sender=None):
    """Run one command from the authorised chat and answer it there."""
    cmd = _parse_tg_command(text)
    arg = _command_arg(text)
    # A BARE /start is Telegram's own "open the chat" command and should answer with help — but
    # `/start <server>` is the documented way to start a server (it is in TG_COMMANDS, so Telegram
    # puts it in the '/' menu, and _tg_help_text lists it). Matching on the word alone swallowed
    # every one of those: the branch below never saw "start", so the bot answered a start request
    # with its help text. Discord's equivalent matches "help" only and has always worked.
    #
    # The commands that only answer: one reply each, built by a shared text helper. Built per call
    # and resolved by name when it runs, so each helper is still looked up as a module attribute.
    replies = {
        "status": lambda: _status_text(app),
        "servers": lambda: _servers_text(app),
        "hosts": lambda: _hosts_text(app),
        "players": lambda: _players_text(app, arg),
        "console": lambda: _console_text(app, arg),
        "say": lambda: _say_text(app, arg, origin=_bot_origin(_PLATFORM, sender)),
        "connect": lambda: _connect_text(app, arg),
    }
    if cmd == "help" or (cmd == "start" and not arg):
        _tg_reply(token, chat_id, _tg_help_text())
    elif cmd in replies:
        _tg_reply(token, chat_id, replies[cmd]())
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
            _telegram_do_update(app, token, chat_id, sender)
    else:
        _tg_reply(token, chat_id, "Unknown command '%s'. Send /help." % cmd[:24])


def _telegram_do_update(app, token, chat_id, sender=None):
    # NOT force=True: a status seconds old is reused, and a forced check is spent from an hourly
    # allowance both bots share — each one can cost a GitHub request (see bot_update_status).
    try:
        st = bot_update_status()
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _tg_reply(token, chat_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    # panel_self_update keeps its own forced re-check (its CI gate), so it spends one too.
    if not spend_update_check():
        _tg_reply(token, chat_id, update_rate_reply())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    # Audited as the web button's own update is — see commands.audit_bot_action.
    audit_bot_action(app, _bot_origin("telegram", sender), "panel_self_update", LOCAL_HOST_LABEL,
                     detail=msg, success=ok)
    if not ok:
        _tg_reply(token, chat_id, "⚠️ Update not started: %s" % msg)
        return
    # Store the COMMIT (not the version, a date every commit of that day shares) so the post-restart
    # check can tell whether the update actually landed.
    _set_tg_pending_update(chat_id, so.panel_commit())
    target = (st.get("target_sha") or "")[:7] or "the newest verified commit"
    _tg_reply(token, chat_id, "🔄 Update started: %s → %s. I'll message you here once I'm back."
              % (_panel_ver_label(), target))


def _set_tg_pending_update(chat_id, from_commit):
    # update_config: this runs in the Telegram poller thread, so a plain load+save could clobber a
    # concurrent whitelist/threshold write from an HTTP handler.
    update_config(lambda cfg: cfg.update(
        {"telegram_pending_update": {"chat_id": chat_id, "from_commit": from_commit, "ts": time.time()}}))


def _tg_chat_still_authorised(tg, chat):
    """Whether the Telegram settings `tg` still take commands from `chat` — the poller's gate."""
    return bool(tg.get("enabled") and tg.get("accept_commands")
                and (tg.get("chat_id") or "").strip() == str(chat).strip())


def _report_tg_pending_update():
    """After a restart, tell the chat how a Telegram-triggered update went, if one was pending.

    It compares the git commit before and after, because the version is a date that a day's
    commits share; commands.update_outcome_text words the answer for both bots.
    """
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
    # Authorised when it sent /update is not authorised now: the marker outlives the restart, and
    # the bot may have been switched off, or its commands, or moved to another chat in between.
    # The same gate the poller applies to every update (_tg_settings / _tg_route_update).
    if not _tg_chat_still_authorised(tg, chat):
        _log.info("telegram: the pending update report was dropped; its chat is no longer the "
                  "authorised one")
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or pend.get("from_version")   # from_version: older pending markers
    # An empty commit on either side is one git never gave — see update_outcome_text, which is
    # where the split between "couldn't read" and "no new commit landed" lives. Same split as
    # _telegram_do_update above, which already refuses to conclude anything from `st` unless
    # st["git"] is true.
    _tg_reply(token, chat, update_outcome_text(now, frm))
