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

from panel.db.models import GameServer, RemoteServer, db
from panel.ops import ssh_manager as _sm
from panel.security.auth import log_action
from panel.services import monitoring as _mon

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
    back with port 0. That second one says only that LinuxGSM found no port in the game's own
    config: the file is missing, or does not set the port. Most games get a default one at install
    (Minecraft's server.properties already says 25565), and a few write theirs the first time they
    start. Never raises.
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


def shared_port_note(names, port):
    """What it means that the servers `names` (two or more, on one host) are all set to `port`.

    Storing that port is right: it IS their configured port (Minecraft and PaperMC both default to
    25565). But every up/down read here is by port, so the panel cannot tell them apart. Said by the
    import's reply and the startup re-read's audit. A server bound to a single address of its own
    can share the port with one bound to another, so "only one" is not said without that exception.
    """
    names = list(names)
    who = names[0] if len(names) < 2 else "%s and %s" % (", ".join(names[:-1]), names[-1])
    return ("%s are set to the same port, %d. Only one of them can run at a time, unless each is "
            "bound to its own IP address. While one runs, the panel cannot tell them apart by "
            "port, so a stopped one may read online." % (who, port))


# One game server row as the re-read found it: plain values. A commit expires every row the session
# has loaded, and touching an expired row that a request deleted meanwhile raises — so with the rows
# held as models, one row deleted while the pass ran ended the pass for every row and host after it.
_Row = collections.namedtuple("_Row", "id remote_id name short_name lgsm_name game_type port installed")
# One host, as its pass knows it: the row, its SSH and panel ports, a callable answering its
# listening ports (read on first use, at most once), and its rows as the pass began.
_Host = collections.namedtuple("_Host", "remote protected listening rows")
# manage_servers' two port rules, handed in so this package imports nothing from the routes:
# withheld_game_ports(rows, gs, protected) and sibling_port_blocks(rows, gs).
_Rules = collections.namedtuple("_Rules", "withheld siblings")


def _row(gs):
    """`gs` as a _Row."""
    return _Row(gs.id, gs.remote_id, gs.name, gs.short_name, gs.lgsm_name, gs.game_type, gs.port,
                bool(gs.installed))


def _host_rows(remote_id):
    """Every server row on the host as it is now, installed or not, as _Rows in id order.

    Not only the installed ones: a server whose install failed still holds its block, and the
    install, its post-start read and "Open all ports" all count it.
    """
    return [_row(gs) for gs in GameServer.query.filter_by(remote_id=remote_id)
            .order_by(GameServer.id).all()]


def reconcile_stored_ports(app, withheld_game_ports, sibling_port_blocks):
    """Re-read every installed server's port from LinuxGSM, and store the reading where it differs.

    Run once per panel start, in the background. It heals what no reading ever produced: a server
    imported before the import read ports stored the port the browser sent, and 27015 when it sent
    none — for every game whose port LinuxGSM keeps outside its own config, and for any import
    made without the UI. It also follows a port changed in the game's config since, while that
    server is stopped. A server whose `details` does not answer keeps its port and is read again
    at the next start. Each host, and each row, is on its own: one that fails is logged and the
    pass goes on.

    What is stored is decided by _reconcile_refusal. Never SSH's or the panel's port. And when the
    port stored now is certainly not this server's — another server's, SSH's, or one something
    listens on while LinuxGSM says this server is stopped — the reading is stored on the import's
    own rule, even when another server shares it: Minecraft and PaperMC both default to 25565,
    and a row kept on Garry's Mod's 27015 reads as up whenever Garry's Mod is. Otherwise the stored
    port may be this server's own (an install keeps the port it allocated, and says so, when the
    game reports one another process already has), and the reading must be free: in no other
    server's block, and not listened on at all — LinuxGSM says STARTED for a game whose tmux
    session lives on after it failed to bind, so STARTED does not make a listener this server.

    A move resets the monitor's up/down for that server (it was read on the old port), rewrites
    its restart-when-empty cron check for the new one, and closes this server's own firewall rule
    on the old port when no other server can need it. It opens no rule: "Open all ports" on the
    host's Firewall page does that, as it always has. Each move is audited as `port_resync`.
    """
    rules = _Rules(withheld_game_ports, sibling_port_blocks)
    with app.app_context():
        try:
            for remote_id in _hosts_to_read():
                _reconcile_host_alone(remote_id, rules)
        finally:
            db.session.remove()


def _hosts_to_read():
    """The ids of the hosts with an installed server, in order; [] when they cannot be listed."""
    try:
        return sorted({rid for (rid,) in db.session.query(GameServer.remote_id)
                       .filter(GameServer.installed.is_(True)).distinct()})
    except Exception:  # noqa: BLE001 - background pass; the next start tries again
        _log.warning("the port re-read at startup could not list the servers", exc_info=True)
        return []


def _reconcile_host_alone(remote_id, rules):
    """_reconcile_host, with whatever it raises logged: one host never stops the pass for the rest."""
    try:
        _reconcile_host(remote_id, rules)
    except Exception:  # noqa: BLE001 - background pass; the next start reads this host again
        db.session.rollback()
        _log.warning("the port re-read at startup failed for host %s", remote_id, exc_info=True)


def _reconcile_host(remote_id, rules):
    """reconcile_stored_ports for one host's installed servers."""
    remote = db.session.get(RemoteServer, remote_id)
    if remote is None:
        return
    rows = _host_rows(remote_id)
    mine = [r for r in rows if r.installed]
    readings = read_reported_ports(remote, [(r.id, r.short_name, r.lgsm_name) for r in mine])
    moving = [(r, readings[r.id]) for r in mine
              if readings.get(r.id, NO_READING).port not in (None, r.port)]
    if not moving:
        return        # nothing answered with another port: no reason to ask the host anything else
    host = _Host(remote, _sm.protected_host_ports(remote),
                 functools.lru_cache(maxsize=1)(lambda: _sm._remote_listening_ports(remote)), rows)
    for row, reading in moving:
        try:
            _reconcile_row(host, row, reading, rules)
        except Exception:  # noqa: BLE001 - one row never stops the rest of its host
            db.session.rollback()
            _log.warning("%s: the port re-read at startup failed", row.name, exc_info=True)


def _reconcile_row(host, row, reading, rules):
    """Store the port LinuxGSM reports for one server, or log why it is not stored."""
    now = _host_rows(row.remote_id)
    cur = next((r for r in now if r.id == row.id), None)
    if cur is None or cur.port != row.port:
        return        # deleted, or moved by something else, since this pass read it
    why = _reconcile_refusal(host, cur, reading, now, rules)
    if why:
        _log.warning("%s: LinuxGSM reports port %s; not stored (%s) — keeping %s",
                     row.name, reading.port, why, row.port)
        return
    _store_read_port(host, cur, reading.port, now, rules)


def _reconcile_refusal(host, row, reading, now, rules):
    """Why the reported port is not stored for `row`, or None. `now`: the host's rows now."""
    refused = port_refusal(reading.port, host.protected)
    if refused or _stored_not_its(host, row, reading, rules):
        return refused
    return (_held_by(reading.port, rules.withheld(now, row, host.protected))
            or _someone_elses(reading.port, host.listening()))


def _stored_not_its(host, row, reading, rules):
    """Why the port stored for `row` is certainly not its own, or None when it may be.

    Not a port this server may have at all (SSH's, the panel's); inside another server's block as
    the pass began — the old import's 27015 beside Garry's Mod, or two old imports on one guess;
    or listened on while LinuxGSM says this server is stopped, which STOPPED (no tmux session)
    does prove. Any of them, and keeping it is the bug the re-read exists to heal.
    """
    if port_refusal(row.port, host.protected):
        return "the stored port is not one this server may have"
    holder = rules.siblings(host.rows, row).get(row.port)
    if holder:
        return "the stored port is in the block of %s" % holder
    if reading.started is False:
        live = host.listening()
        if live is not None and row.port in live:
            return "something listens on the stored port while this server is stopped"
    return None


def _store_read_port(host, row, port, now, rules):
    """Store `port` on the row, then move what was set up on the old one, and audit the move."""
    gs = db.session.get(GameServer, row.id)
    if gs is None:
        return
    gs.port = port
    db.session.commit()
    _mon.forget_updown(row.id)
    shared = _sharing_note(row, port, now)
    notes = [n for n in (_cron_follows(host.remote, row, port),
                         _close_old_rule(host, row, now, rules, port), shared) if n]
    log_action(None, "port_resync", target=row.name, server=gs,
               detail="%s -> %s (read from LinuxGSM details at panel start; %s)"
               % (row.port, port, "; ".join(notes)))
    _log.info("%s: stored port %s -> %s, as LinuxGSM reports", row.name, row.port, port)
    if shared:
        _log.warning("%s", shared)


def _sharing_note(row, port, now):
    """shared_port_note for `row` moved to `port`, when another of the host's rows (`now`) is on it; else ""."""
    names = [r.name for r in now if r.port == port or r.id == row.id]
    return shared_port_note(names, port) if len(names) > 1 else ""


def _cron_follows(remote, row, port):
    """Point the server's restart-when-empty cron check at `port`. -> a note for the audit, or "".

    The check asks gamedig at the stored port, and the boot's own cron upgrade (app.py's
    node-tools pass) has usually rewritten it from the OLD port before this pass runs, and then
    not again for a day: the line asked the neighbour, and acted on its player count.
    """
    try:
        changed = _sm.upgrade_managed_cron_tracking(remote, row.short_name, row.lgsm_name,
                                                    game_type=row.game_type, port=port)
    except Exception:  # noqa: BLE001 - the move stands; the daily pass rewrites the line
        _log.warning("%s: its cron could not be pointed at port %s", row.name, port,
                     exc_info=True)
        return "its restart-when-empty check could not be updated"
    return "its restart-when-empty check now asks port %s" % port if changed else ""


def _close_old_rule(host, row, now, rules, new_port):
    """Close THIS server's own firewall rule on its old port when nothing else can need it. -> a note.

    Only its tagged rule (remote_ufw_close_game_port without legacy), and only when the old port is
    in no other server's block — an imported server opens no rule of its own, so a neighbour can be
    relying on this one — and nothing listens on it. The new port is not opened: an unattended
    pass at start does not open the firewall on a reading from a config the game account writes.
    "Open all ports" on the host's Firewall page does, as it always has.
    """
    closed = _close_own_rule(host, row, now, rules)
    return (("closed this server's firewall rule on %s; " % row.port) if closed else "") + (
        "the firewall is not opened on %s: 'Open all ports' on the host's Firewall page opens it"
        % new_port)


def _close_own_rule(host, row, now, rules):
    """_close_old_rule's close, when it may be made. -> how many rules it removed."""
    old = row.port
    if old in host.protected or old in rules.siblings(now, row):
        return 0
    try:
        live = host.listening()
        if live is None or old in live:
            return 0
        return _sm.remote_ufw_close_game_port(host.remote, old, row.short_name)[0]
    except Exception:  # noqa: BLE001 - the move stands; the rule is left as it was
        _log.warning("%s: its firewall rule on %s could not be closed", row.name, old,
                     exc_info=True)
        return 0


def _held_by(port, held):
    """Why `port` is not this server's to take, from withheld_game_ports' {port: who}; else None."""
    return "port %d is held by %s" % (port, held[port]) if port in held else None


def _someone_elses(port, live):
    """Why the reported port may be another process's (`live`: the host's listening ports); else None."""
    if live is None:
        return "the host's listening ports could not be read"
    if port in live:
        return ("something is listening on it, and LinuxGSM's STARTED does not say that is this "
                "server: a game that failed to bind keeps its tmux session")
    return None
