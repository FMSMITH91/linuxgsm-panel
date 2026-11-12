"""Is a stopped server's port free before the panel starts it, and a port saved on the Settings tab.

THE START CHECK. A game that cannot bind its port does not always say so: LinuxGSM can report it
started while the process failed to bind, and the panel then reads the server as up because
something else answers on that port. So a panel Start of a stopped server (and a Restart of one
that is not running) first looks:

1. another server on the same host, set to the same game or query port, that reads online: the
   start is refused naming it. Two servers may be configured on one port; only one may run.
2. a listener on the server's game port on the host (TCP or UDP), from one unprivileged
   `ss -H -lntu` (ssh_manager._remote_listening_ports, which every dashboard poll already runs and
   caches for a few seconds; `-n` prints numbers only, so the locale changes nothing it reads):
   the start is refused as a port in use by something the panel does not know.

Either refusal is a PortBusy, which the page offers to send again with `force` ("Start anyway").
The check fails OPEN: a read that fails, raises, times out or comes back empty starts the server
exactly as before. A server whose port is unknown (0 or unset) is not checked. Stop, a running
server's Restart, and LinuxGSM's own cron and autostart starts never come through here.

THE SAVED PORT. GameServer.port is what the monitor, the dashboard, the firewall and this check read.
A port saved on the Settings tab is LinuxGSM's `port=` key, which takes effect when the game next
starts. Saved while the server is stopped, the stored port moves at once; saved while it runs, the
running process still holds the old port, so the stored port stays and the new one waits in
pending_port until the next panel Start or Restart, which checks it and, once that start has run and
exited 0 with no LinuxGSM outcome (a postponed or refused Restart leaves the old process on the old
port), moves to it. Only games
whose port IS the cfg `port=` key follow here (94 of LinuxGSM's games: the Settings form offers
`port` only when the game's _default.cfg has it). The others keep their port in the game's own
config and still follow at the next panel start's re-read or the Firewall page's Sync ports, as
does SA-MP, whose cfg has a `port=` its start line never uses. A server restarted outside the panel
is healed by that same re-read.
"""
import logging
import re

from panel.core import i18n
from panel.db.models import GameServer, db
from panel.ops import ssh_manager as _sm
from panel.services import game_ports as _gp

_log = logging.getLogger("panel")

# SA-MP's cfg has `port=`, but its start line never passes it: the real port is in server.cfg.
_PCK_CFG_PORT_UNUSED = frozenset({"samp"})
_PCK_PORT_TEXT = re.compile(r"[0-9]{1,5}")
_PCK_FROM_SETTINGS = "saved on the Settings tab"
_PCK_FROM_PENDING = "saved on the Settings tab while it ran; moved at a panel start"


# manage_servers' two port rules as game_ports' mover takes them (the routes hand them in).
move_rules = _gp.move_rules


class PortBusy(i18n.Sentence):
    """A start refused because its port is in use: the page offers "Start anyway" for it."""

    __slots__ = ()


def wants_check(gs, action):
    """Whether a panel `action` on `gs` gets the port check: Start, and Restart of a server not online."""
    return action == "start" or (action == "restart" and gs.status != "online")


def _pck_port(value):
    """`value` as a port number, or None for anything else (0, None, a bool, out of range)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 65535 else None


def held_ports(row, span):
    """Every port server `row` holds on its host.

    That is `span` ports from its stored port, and as many from a port saved while it ran (pending_port),
    which its next start binds. A port that is not one adds none.
    """
    held = set()
    for base in (_pck_port(row.port), _pck_port(getattr(row, "pending_port", None))):
        if base is not None:
            held.update(range(base, base + span))
    return held


def start_port(gs):
    """The game port a start of `gs` binds: a port saved while it ran, else the stored one."""
    return _pck_port(gs.pending_port) or _pck_port(gs.port)


def _pck_running_claimant(gs, ports):
    """(name, port) of another server on gs's host that reads online and is set to one of `ports`."""
    others = (GameServer.query.filter(GameServer.remote_id == gs.remote_id, GameServer.id != gs.id,
                                      GameServer.status == "online")
              .order_by(GameServer.name, GameServer.id).all())
    for other in others:
        theirs = {other.port, other.query_port}
        hit = next((p for p in ports if p in theirs), None)
        if hit is not None:
            return other.name, hit
    return None


def _pck_listening(remote):
    """The host's listening ports, or None when they could not be read (a raise included)."""
    try:
        return _sm._remote_listening_ports(remote)
    except Exception:  # noqa: BLE001 - paramiko raises where the other transports return ""
        _log.info("port check: the host's listening ports could not be read", exc_info=True)
        return None


def start_refusal(gs, remote):
    """Why starting `gs` now would collide on its port (a PortBusy), or None to go ahead.

    Fails open: anything that cannot be read, or raises, is None.
    """
    try:
        return _pck_refusal(gs, remote)
    except Exception:  # noqa: BLE001 - never make Start less reliable than it was
        db.session.rollback()
        _log.warning("port check before a start failed; starting anyway", exc_info=True)
        return None


def _pck_refusal(gs, remote):
    """start_refusal's body."""
    port = start_port(gs)
    if port is None:
        return None
    ports = [port] + [p for p in (_pck_port(gs.query_port),) if p and p != port]
    hit = _pck_running_claimant(gs, ports)
    if hit:
        return PortBusy("Port {port} is in use by {name}, which is running. Stop it first, or start anyway.",
                        port=hit[1], name=hit[0])
    live = _pck_listening(remote)
    if not live:
        if live is None:
            _log.info("port check: no listening ports read for %s; starting without the check",
                      gs.name)
        return None
    if port in live:
        return PortBusy("Port {port} is already in use on this host (not by a server the panel knows). "
                        "Start anyway?", port=port)
    return None


def follow_pending(gs, remote, rules):
    """After a panel Start or Restart that ran cleanly, move the stored port to a port saved while it ran.

    Logged, never raised: the start has already run, and the next panel start's re-read
    still follows the port. A move refused by the re-read's rules leaves it pending.
    """
    port = _pck_port(gs.pending_port)
    if port is None:
        return
    try:
        if port == gs.port:
            gs.pending_port = None
            db.session.commit()
            return
        why = _gp.move_stored_port(remote, gs, port, rules, _PCK_FROM_PENDING)
        if why:
            _log.warning("%s: the port saved while it ran (%s) was not stored (%s)", gs.name, port, why)
    except Exception:  # noqa: BLE001 - the start goes ahead; the re-read follows the port later
        db.session.rollback()
        _log.warning("%s: the port saved while it ran could not be stored", gs.name, exc_info=True)


def saved_port(gs, settings):
    """The game port a Settings-tab save sets for `gs`, or None when it sets none this follows."""
    if not isinstance(settings, dict) or "port" not in settings or gs.game_type in _PCK_CFG_PORT_UNUSED:
        return None
    raw = settings["port"]
    text = raw.strip() if isinstance(raw, str) else ""
    return _pck_port(int(text)) if _PCK_PORT_TEXT.fullmatch(text) else None


def after_settings_save(gs, settings, running, rules):
    """Follow a game port saved on the Settings tab. -> a note for the save's reply, or None.

    `running`: _live_run_state's answer (True, False, None for unknown). Stopped, the stored port
    moves now; running or unknown, it waits in pending_port for the next panel Start or Restart.
    A port the re-read's rules refuse is neither stored nor pending, and the save stands as it is.
    """
    port = saved_port(gs, settings)
    if port is None:
        return None
    if port == gs.port:
        if gs.pending_port is not None:
            gs.pending_port = None
            db.session.commit()
        return None
    why = _gp.saved_port_refusal(gs.remote, gs, port, rules)
    if why:
        _log.warning("%s: port %s saved on the Settings tab is not followed (%s)", gs.name, port, why)
        return None
    if running is False:
        if _gp.move_stored_port(gs.remote, gs, port, rules, _PCK_FROM_SETTINGS) is None:
            return i18n.Sentence("The panel now watches port {port} for this server.", port=port)
        return None
    old = gs.port
    gs.pending_port = port
    db.session.commit()
    return i18n.Sentence("Port {port} takes effect at the next restart. Until then the panel keeps "
                         "watching port {old}, which the running server still uses.", port=port, old=old)
