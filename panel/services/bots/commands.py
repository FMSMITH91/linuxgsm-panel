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
import queue
import threading

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


def _players_text(app, arg, fence=None):
    """`fence`, when given, wraps the player names — the part a player chose — for a transport
    that renders markup in them (see discord._dc_literal)."""
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
        # Was `names[:40]` — a fixed slice that dropped the rest with nothing said, and still
        # overflowed the transport when forty clan-tagged names ran past 1900 characters. The
        # length cap subsumes it and reports what it left out.
        body = _join_capped(["• " + n for n in names])
        return "%s — %d player(s):\n%s" % (gs.name, len(names), fence(body) if fence else body)


# A chat reply has to fit in one message on BOTH transports — Telegram truncates at 4000 chars,
# Discord's bot REST send at 1900. Cap the variable-length bodies below that so the label and the
# last line of a console tail are never the part that gets cut.
_BOT_BODY_MAX = 1500


def _join_capped(rows):
    """Join `rows` into one body, dropping WHOLE rows off the end once the total passes
    _BOT_BODY_MAX and saying how many went.

    The cap above was written for all four variable-length builders and applied to exactly one of
    them (_console_text). The other three built unbounded bodies, and on Discord the end of that
    is discord_bot_send's bare `text[:1900]` — a hard slice, no ellipsis, mid-word, mid-row. A
    panel with ~45 servers answered `!servers` with a list that stopped part-way through a name and
    was missing roughly the last ten, with nothing saying so; an admin scanning it for a server
    that was down read that as "not installed".

    Truncated FORWARD, unlike _console_text: the newest lines are the point of a console tail,
    while the head is the useful end of a server/host/player list. The first row is always kept,
    so a single over-long row still produces a body rather than nothing."""
    out, used = [], 0
    for i, row in enumerate(rows):
        row = str(row)
        if out and used + len(row) + 1 > _BOT_BODY_MAX:
            out.append("… and %d more" % (len(rows) - i))
            break
        out.append(row)
        used += len(row) + 1
    return "\n".join(out)


def _console_text(app, arg, lines=20, fence=None):
    """The tail of a server's live console. `fence` is as for _players_text: the tail carries
    in-game chat.

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
        # rc 3 + NO_SESSION is capture_console's "the server isn't running", not an error — and
        # it was unpacked and never read, so the sentinel was rendered to the user as if it were
        # game output: "CoD Server — last 1 console line(s): NO_SESSION". `echo NO_SESSION` goes
        # to STDOUT, so the `if not rows` guard below could never fire. The command that exists to
        # answer "why did the start fail?" answered NO_SESSION. Both other callers of
        # capture_console guard on rc (game.py:205 and :232).
        #
        # ...and ONLY that sentinel says so. Any other non-zero rc is the panel failing to reach the
        # console: the local and tailscale transports return ("", "…timed out", -1) without
        # raising, and a `sudo -u` refusal is rc 1. Those were answered "the server isn't running",
        # a confident fact about a server the panel never observed — to an admin asking because a
        # start had failed.
        if rc == 3 and "NO_SESSION" in (out or ""):
            return "%s — the server isn't running, so there's no console to read." % gs.name
        if rc != 0:
            return "%s — couldn't read the console (the host didn't answer)." % gs.name
        text = terminal.strip_escapes(out or "")
        rows = [r.rstrip() for r in text.splitlines() if r.strip()][-lines:]
        if not rows:
            return "%s — no console output (is it running?)." % gs.name
        body = "\n".join(rows)
        if len(body) > _BOT_BODY_MAX:      # keep the END: the newest lines are the useful ones
            body = "…" + body[-_BOT_BODY_MAX:]
        return "%s — last %d console line(s):\n%s" % (gs.name, len(rows), fence(body) if fence else body)


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
    return _join_capped(rows) if rows else "No hosts configured."


# ── "I'm working on it" wording, shared by both bots ───────────────────────────────────────────
# Telegram and Discord run the same command set through the same helpers, so a user on one has no
# reason to see different words from a user on the other. Kept here rather than in either bot for
# that reason: two copies of a string is two copies that drift.

# What an action is called while it is still running. The COMPLETION message is built from the
# action name itself, so adding an action here is the only thing a new verb needs.
_ACTION_ACK = {
    "start": "🔄 %s — starting…",
    "stop": "🔄 %s — stopping…",
    "restart": "🔄 %s — restarting…",
    "backup": "🔄 %s — backing up. This can take a few minutes; I'll tell you when it's done.",
    "update": "🔄 %s — updating. This can take a few minutes; I'll tell you when it's done.",
}

# The read commands that have to leave the box before they can answer — a live query to the game
# server, an SSH console capture, an in-game announcement. status/servers/hosts/connect answer
# from the database and are already instant, so they are deliberately absent: acking an answer
# that arrives in the same breath is just noise.
_WORKING_ACK = {
    "players": "🔎 Asking the server who's on…",
    "console": "🔎 Fetching the console…",
    "say": "📣 Sending it in-game…",
}


# ── Running commands off the poll/socket thread ────────────────────────────────────────────────
# Both bots read their commands on ONE thread — Telegram long-polls getUpdates, Discord holds a
# Gateway socket — and used to run them on that same thread. A command that reaches a host costs an
# SSH round trip, so while one was running the reader was not reading: everything sent behind it
# sat untouched at the transport until the slow one returned. A single /console on an unreachable
# host stalled every command after it for the whole connect timeout. On Discord it is worse than
# slow — the socket that is not being read is also the one that must answer heartbeats, so a long
# command can get the session dropped and reconnected underneath you.
#
# ONE worker, not a pool: order is part of what a command bot promises. `/stop x` then `/start x`
# has to happen in that order, and a pool would let them race into "stopped" — the opposite of what
# was asked. Serial execution costs nothing here, because the slow actions were already handed to
# their own background threads by run_action; what is left on this queue is short.
#
# The queue is BOUNDED and full is reported, not swallowed. An unbounded queue turns a wedged host
# into unbounded memory and a chat that answers questions from ten minutes ago; saying "still
# working through earlier commands" is the honest answer to a bot that is genuinely behind.
_CMD_QUEUE_MAX = 32


class CommandWorker:
    """A single daemon thread that runs queued bot commands in arrival order.

    Started lazily on first use and restarted if it ever dies, so an unconfigured bot costs no
    thread and a crashed one does not silently stop answering for the life of the process."""

    def __init__(self, name):
        self.name = name
        self._q = queue.Queue(maxsize=_CMD_QUEUE_MAX)
        self._thread = None
        self._lock = threading.Lock()

    def submit(self, fn):
        """Queue `fn` to run on the worker. False when the queue is full — the caller answers."""
        self._ensure_running()
        try:
            self._q.put_nowait(fn)
            return True
        except queue.Full:
            _log.warning("%s: command queue is full (%d deep); refusing new commands",
                         self.name, _CMD_QUEUE_MAX)
            return False

    def _ensure_running(self):
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name=self.name, daemon=True)
                self._thread.start()

    def _run(self):
        while True:
            fn = self._q.get()
            try:
                fn()
            except Exception:
                # Never let one command take the worker down with it: the next command in the
                # queue is unrelated and still deserves to run.
                _log.debug("%s: a queued command failed", self.name, exc_info=True)
            finally:
                self._q.task_done()


# What to say when a bot is genuinely behind. Shared, like the rest of the wording. Worded as a
# REFUSAL, not a delay: a submit that returns False means the command was not queued and will
# never run, so "I'll get to it shortly" would be a promise the bot cannot keep.
BUSY_REPLY = ("⏳ I'm still working through earlier commands, so that one didn't make the queue. "
              "Send it again in a moment.")


def working_ack(cmd):
    """The "working on it" line for a command, or None when it answers instantly.

    The routers ask this instead of each indexing the table: WHICH commands ack is a property of
    the command set, not of a transport, and a branch added to one router and not the other is
    precisely the drift that produced the /start and /update bugs. Asking here means a new slow
    command starts acking on both bots the moment it is added to the table above, with no way for
    one of them to be forgotten."""
    return _WORKING_ACK.get(cmd)


def action_ack(action, name):
    """The "starting…" line for a server action, with the server's name already filled in.

    The fallback matters: an action with no wording still has to say SOMETHING, because the ack is
    the only thing standing between the user and a silent minute."""
    return _ACTION_ACK.get(action, "🔄 %s — working on it…") % name


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
        counts = [(_player_counts.get(gs.id) or {}).get("count") for gs in installed]
    known = [c for c in counts if isinstance(c, int)]
    unknown = len(counts) - len(known)
    # The isinstance filter used to be the ONLY handling of the unknown case: a server the panel
    # could not ask contributed nothing and the total was then printed as a fact. Both ways in are
    # ordinary — right after a restart the poller has not completed a pass, so _player_counts is
    # empty and six busy servers read as "Players online: 0"; steady-state a server whose game
    # query fails keeps count None (monitoring._refresh_player_counts: "an offline server is 0
    # players without a query; a running one the panel can't read stays None", so an offline
    # server is a real zero and is never counted here as unknown). An admin sent /status to check
    # the box came back and was told nobody was playing by a panel that had not asked.
    #
    # Render the unknowns instead of folding them into the total, the way /servers already prints
    # "?" for the same state six lines below.
    if unknown:
        players = "%s (%d server%s couldn't be queried)" % (
            sum(known) if known else "?", unknown, "" if unknown == 1 else "s")
    else:
        players = "%d" % sum(known)
    return ("Version %s\nServers: %d online / %d installed\nPlayers online: %s"
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
    return _join_capped(rows) if rows else "No servers installed."


def _panel_ver_label():
    """Human-friendly version for messages: '<VERSION> (<short-commit>)'. The VERSION file rarely
    changes between commits, so the commit is what tells you an update actually landed."""
    ver = so.panel_version()
    commit = so.panel_commit()
    return "%s (%s)" % (ver, commit) if commit else ver
