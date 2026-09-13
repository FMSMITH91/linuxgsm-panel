"""The command layer both chat bots run on.

Moved out of app.py verbatim — see panel/services/bots/__init__.py for why, and for why these
are still named `_tg_*` despite serving Discord equally.
"""
from panel.core import (terminal)
from panel.core.config import (load_config)
from panel.core.panel_state import (_player_counts)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import ssh_manager as _sm
from panel.ops import system_ops as so
from panel.ops.ssh_manager import (player_list)
import logging

# Same logger name app.py used, so existing log filters and greps keep working.
_log = logging.getLogger("panel.app")


def _reply_header():
    """A short identifier for THIS panel so replies are unambiguous when someone runs several panels:
    '<site title> (<hostname>)'."""
    import socket
    title = (load_config().get("site_title") or "LinuxGSM Panel").strip()
    try:
        host = socket.gethostname()
    except Exception:
        host = ""
    return "🎮 %s (%s)" % (title, host) if host else "🎮 %s" % title


def _command_arg(text):
    """The text after the command word: '/restart my server' -> 'my server'."""
    parts = (text or "").strip().split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def _find_server(arg):
    """Resolve a GameServer from a name/short_name argument (case-insensitive). Returns (gs, error):
    an exact short_name/name match wins, else a unique partial name match, else (None, message)."""
    arg = (arg or "").strip()
    if not arg:
        return None, "Which server? Send /servers to see the names."
    servers = GameServer.query.filter_by(installed=True).all()
    low = arg.lower()
    exact = [g for g in servers if g.short_name.lower() == low or g.name.lower() == low]
    if len(exact) == 1:
        return exact[0], None
    if len(exact) > 1:
        return None, "That matches several — use the exact short name: %s" % ", ".join(g.short_name for g in exact)
    partial = [g for g in servers if low in g.name.lower() or low in g.short_name.lower()]
    if len(partial) == 1:
        return partial[0], None
    if len(partial) > 1:
        return None, "Matches several: %s — be more specific." % ", ".join(g.name for g in partial[:8])
    return None, "No server matches '%s'. Send /servers for the list." % arg[:40]


def _players_text(app, arg):
    with app.app_context():
        gs, err = _find_server(arg)
        if err:
            return err
        try:
            # An explicit /players you typed — allowed to fall back to one console `status` if the
            # server can't be read over the network (unlike the panel's automatic polling).
            players = player_list(gs.remote, gs.short_name, gs.game_type, port=gs.port,
                                  query_type=gs.query_type, selfname=gs.lgsm_name, allow_console=True)
        except Exception:
            players = None
        if players is None:
            return "%s — couldn't read the player list (is it running?)." % gs.name
        if not players:
            return "%s — no players connected." % gs.name
        names = [str(p.get("name") or "?") for p in players]
        return "%s — %d player(s):\n%s" % (gs.name, len(names), "\n".join("• " + n for n in names[:40]))


# A chat reply has to fit in one message on BOTH transports — Telegram truncates at 4000 chars,
# Discord's bot REST send at 1900. Cap the variable-length bodies below that so the label and the
# last line of a console tail are never the part that gets cut.
_BOT_BODY_MAX = 1500


def _console_text(app, arg, lines=20):
    """The tail of a server's live console.

    The missing half of the power commands: start/stop/restart run in the background and their
    output is discarded, so when a start fails the bot can say that it failed but never why. This
    is that answer, without opening the panel."""
    with app.app_context():
        gs, err = _find_server(arg)
        if err:
            return err
        try:
            out, _, rc = _sm.capture_console(gs.remote, gs.short_name, selfname=gs.lgsm_name, lines=lines)
        except Exception:
            _log.debug("telegram console tail failed", exc_info=True)
            return "%s — couldn't read the console." % gs.name
        # rc 3 + NO_SESSION is capture_console's "the server isn't running", not an error.
        text = terminal.strip_escapes(out or "")
        rows = [r.rstrip() for r in text.splitlines() if r.strip()][-lines:]
        if not rows:
            return "%s — no console output (is it running?)." % gs.name
        body = "\n".join(rows)
        if len(body) > _BOT_BODY_MAX:      # keep the END: the newest lines are the useful ones
            body = "…" + body[-_BOT_BODY_MAX:]
        return "%s — last %d console line(s):\n%s" % (gs.name, len(rows), body)


def _say_text(app, arg):
    """Announce a message in a server's chat: '<server> <message>'.

    The server is the FIRST word (a short name never contains a space), everything after it is the
    message — otherwise there is no way to tell where one ends and the other begins. _sm.moderate()
    sanitizes the text, so a message can't smuggle a second console command."""
    name, _, message = (arg or "").strip().partition(" ")
    if not name:
        return "Usage: say <server> <message>"
    with app.app_context():
        gs, err = _find_server(name)
        if err:
            return err
        if not message.strip():
            return "%s — what should I announce? Usage: say <server> <message>" % gs.name
        try:
            ok, msg = _sm.moderate(gs.remote, gs.short_name, gs.game_type, "say",
                               message=message, selfname=gs.lgsm_name)
        except Exception:
            _log.debug("telegram say failed", exc_info=True)
            ok, msg = False, "the announcement failed"
        return "%s %s — %s" % ("✅" if ok else "⚠️", gs.name, msg or ("announced" if ok else "failed"))


def _connect_text(app, arg):
    """A server's joinable address, ready to paste to players."""
    with app.app_context():
        gs, err = _find_server(arg)
        if err:
            return err
        r = gs.remote
        host = (r.public_ip if r else "") or (r.host if (r and not r.is_local) else "")
        if not host:
            return ("%s — no public address known for its host yet. Open the panel once so it can "
                    "resolve one." % gs.name)
        uri = gs.connect_uri(host)
        return "%s\n%s:%s%s" % (gs.name, host, gs.port, ("\n" + uri) if uri else "")


def _hosts_text(app):
    with app.app_context():
        rows = []
        # One grouped COUNT for every host, rather than one COUNT per host inside the loop. The
        # /hosts command is not hot, but the shape was N+1 and the fix is a single query.
        _counts = dict(db.session.query(GameServer.remote_id, db.func.count(GameServer.id))
                       .filter_by(installed=True).group_by(GameServer.remote_id).all())
        for r in RemoteServer.query.order_by(RemoteServer.name).all():
            n_srv = _counts.get(r.id, 0)
            dot = "🟢" if r.is_online else "🔴"
            local = " (this panel)" if r.is_local else ""
            rows.append("%s %s%s — %d server%s" % (dot, r.display_name, local, n_srv, "" if n_srv == 1 else "s"))
    return "\n".join(rows) if rows else "No hosts configured."


def _bot_origin(platform, sender):
    """Audit-log actor string for a command that arrived over a chat bot.

    A bot command can stop a game server or update the panel, and until now every one was recorded
    with actor=None — i.e. as "system". The log showed that a server restarted but not that a chat
    message caused it, let alone which account sent it. Chat bots have no panel identity to map to,
    so the next best thing is to record the origin verbatim and let a human follow it up.
    """
    sender = sender or {}
    who = str(sender.get("username") or sender.get("id") or "unknown")
    return ("%s:%s" % (platform, who))[:64]


def _status_text(app):
    with app.app_context():
        installed = GameServer.query.filter_by(installed=True).all()
        online = sum(1 for gs in installed if gs.status == "online")
        players = sum((_player_counts.get(gs.id) or {}).get("count") or 0
                      for gs in installed if isinstance((_player_counts.get(gs.id) or {}).get("count"), int))
    return ("Version %s\nServers: %d online / %d installed\nPlayers online: %d"
            % (_panel_ver_label(), online, len(installed), players))


def _servers_text(app):
    with app.app_context():
        rows = []
        for gs in GameServer.query.filter_by(installed=True).order_by(GameServer.name).all():
            slot = _player_counts.get(gs.id) or {}
            count = slot.get("count")
            pc = ("%s/%s" % (count, slot.get("max"))) if isinstance(count, int) else "?"
            rows.append("%s %s — %s (%s players)"
                        % ("🟢" if gs.status == "online" else "⚪", gs.name, gs.status, pc))
    return "\n".join(rows) if rows else "No servers installed."


def _panel_ver_label():
    """Human-friendly version for messages: '<VERSION> (<short-commit>)'. The VERSION file rarely
    changes between commits, so the commit is what tells you an update actually landed."""
    ver = so.panel_version()
    commit = so.panel_commit()
    return "%s (%s)" % (ver, commit) if commit else ver
