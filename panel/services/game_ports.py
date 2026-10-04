"""A game server's port, READ on its host: never a default, never what a client sent.

Every consumer of GameServer.port treats it as a fact. The monitor and the dashboard call a server
up when something listens on it, the power guard refuses Start while it is held, gamedig asks it
for players, the host's crontab checks it, and the firewall and the port reservations act on it. So
a port nobody read is not a harmless placeholder: an imported Minecraft server stored on 27015 —
the import's old fallback for "no port", and Garry's Mod's port on the test box — read as up
whenever Garry's Mod was, and its crash never paged.

The reader is LinuxGSM's own `details` (detect_game_ports). It is the one reader that knows every
game: 46 of the 140 games LinuxGSM lists keep their port in the game's own config, in a dozen
formats, and its info_game.sh reads each of them. Install step 6 and the Firewall page's "Open all
ports" already trust it.
"""
import collections
import concurrent.futures
import functools
import logging

from panel.db.models import GameServer, db
from panel.ops import ssh_manager as _sm
from panel.security.auth import log_action

_log = logging.getLogger("panel")

# `details` takes 7-15 s on the test VPS; at most this many run at once.
PORT_READ_WORKERS = 4
# One reading: the game port (None when LinuxGSM gave none), whether `details` answered at all, and
# its Status line (True STARTED, False STOPPED, None neither).
Reading = collections.namedtuple("Reading", "port answered started")
NO_READING = Reading(None, False, None)


def read_reported_port(remote, user, selfname):
    """One server's game port as LinuxGSM's `details` reads it, as a Reading.

    "Answered" separates the two ways of getting no port, which call for different things: a
    `details` that never came back (a timeout, a refused account — try again), and one that came
    back with port 0 (a game whose own config does not exist yet, because the game writes it the
    first time it starts — start it once). Never raises.
    """
    try:
        info = _sm.detect_game_ports(remote, user, selfname)
    except Exception:  # noqa: BLE001 - a read that failed is no reading, never a 500
        _log.debug("details for %s could not be read", user, exc_info=True)
        return NO_READING
    game_port = info.get("game_port")
    return Reading(game_port or None, bool(info.get("answered") or info.get("ports") or game_port),
                   info.get("started"))


def _columns_loaded(obj):
    """`obj` with every column read HERE: a pool thread has no app context to load it in."""
    from sqlalchemy import inspect as _sa_inspect
    try:
        for key in _sa_inspect(obj).mapper.column_attrs.keys():
            getattr(obj, key)
    except Exception:  # noqa: BLE001 - not a mapped row; nothing to load
        _log.debug("could not load %r before handing it to a pool thread", obj, exc_info=True)
    return obj


def read_reported_ports(remote, wanted):
    """{key: read_reported_port(...)} for each (key, account, script name) in `wanted`, in parallel."""
    if not wanted:
        return {}
    _columns_loaded(remote)

    def _one(entry):
        key, user, selfname = entry
        return key, read_reported_port(remote, user, selfname)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(PORT_READ_WORKERS, len(wanted))) as ex:
        return dict(ex.map(_one, list(wanted)))


def port_refusal(port, protected):
    """Why `port` may not be stored as a game server's port, or None when it may.

    `protected` is hosts.protected_host_ports: SSH and the panel. Every reading here comes from a
    config the game account (and anyone with Manage Servers, through the file manager) can write,
    and "port 22" makes the monitor read that server as up for as long as SSH is.
    """
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return "%s is not a port" % (port,)
    if port in protected:
        return "port %d is this host's SSH or the panel itself" % port
    return None


def reconcile_stored_ports(app, withheld_game_ports):
    """Re-read every installed server's port from LinuxGSM, and store the reading where it differs.

    Run once per panel start, in the background. It heals what no reading ever produced: a server
    imported before the import read ports stored the port the browser sent, and 27015 when it sent
    none — for every game whose port LinuxGSM keeps outside its own config, and for any import
    made without the UI. It also follows a port changed in the game's config since. A server whose
    `details` does not answer keeps its port and is read again at the next start.

    A reading is stored only when it is a port (1-65535) that `withheld_game_ports`
    (manage_servers', handed in so this package imports nothing from the routes) allows: never SSH
    or the panel, and never a port in another server's block — the same rule as the Firewall
    page's "Open all ports", which this is without the firewall: no rule is opened or closed. And
    not a port something is listening on while LinuxGSM says this server is stopped: that socket
    is someone else's — an install keeps its own port, and says so, when the game reports one a
    process outside the panel already has, and this must not undo that.
    """
    with app.app_context():
        try:
            by_remote = {}
            for gs in GameServer.query.filter_by(installed=True).all():
                by_remote.setdefault(gs.remote_id, []).append(gs)
            for rows in by_remote.values():
                _reconcile_host(rows[0].remote, rows, withheld_game_ports)
        except Exception:  # noqa: BLE001 - background pass; the next start tries again
            _log.warning("the port re-read at startup failed", exc_info=True)
        finally:
            db.session.remove()


def _reconcile_host(remote, rows, withheld_game_ports):
    """reconcile_stored_ports for one host's installed servers."""
    if remote is None:
        return
    readings = read_reported_ports(remote, [(gs.id, gs.short_name, gs.lgsm_name) for gs in rows])
    if not any(r.port for r in readings.values()):
        return        # nothing answered: no reason to ask the host for its SSH ports either
    protected = _sm.protected_host_ports(remote)
    # Read once, and only when a port is about to move.
    listening = functools.lru_cache(maxsize=1)(lambda: _sm._remote_listening_ports(remote))
    for gs in rows:
        r = readings.get(gs.id, NO_READING)
        if r.port is None or r.port == gs.port:
            continue
        why = _reconcile_refusal(r, protected, withheld_game_ports(rows, gs, protected), listening)
        if why:
            _log.warning("%s: LinuxGSM reports port %s; not stored (%s) — keeping %s",
                         gs.name, r.port, why, gs.port)
        else:
            _store_read_port(gs, r.port)


def _store_read_port(gs, port):
    """Store the port LinuxGSM reports on `gs`, and audit the move."""
    old, gs.port = gs.port, port
    db.session.commit()
    log_action(None, "port_resync", target=gs.name, server=gs,
               detail="%s -> %s (read from LinuxGSM details at panel start)" % (old, port))
    _log.info("%s: stored port %s -> %s, as LinuxGSM reports", gs.name, old, port)


def _reconcile_refusal(reading, protected, held, listening):
    """Why the reported port is not stored, or None. `listening()` reads the host's ports."""
    return (port_refusal(reading.port, protected) or _held_by(reading.port, held)
            or _someone_elses(reading, listening()))


def _held_by(port, held):
    """Why `port` is not this server's to take, from withheld_game_ports' {port: who}; else None."""
    return "port %d is held by %s" % (port, held[port]) if port in held else None


def _someone_elses(reading, live):
    """Why the reported port may be another process's (`live`: the host's listening ports); else None."""
    if live is None:
        return "the host's listening ports could not be read"
    if reading.port in live and reading.started is not True:
        return "something is listening on it while this server is not running"
    return None
