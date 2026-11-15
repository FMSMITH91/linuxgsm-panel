"""Databases on a server on another machine, reached over Tailscale; and the Databases overview page.

A game host's new databases can live on a MariaDB/MySQL server elsewhere (a DatabaseEndpoint):
another host the panel manages ('managed': the accounts are made there, as root over its socket or
with its stored login) or a server the panel does not manage ('external': the accounts are made from
the game host, with an admin login a superadmin gave). Either way the server is reached at a tailnet
address only, and each database's account is made for the one address the game host reaches it from
(never '%'). The panel changes nothing about the server's network: a server that only listens on
loopback is reported, with what to change, and left alone.

What runs where (`admin_target` and `game_view`): creating, re-keying and deleting a database run
where the accounts are made; a backup's dump and a restore run on the game host, as its game
account, signed in as the database's own account, so the game's files are only ever written by
the game account.

PERMISSION. Choosing the server a host's databases go to is superadmin only; using the databases
follows the Databases tab's rules (MANAGE_DATABASES and access to the server). The overview page
lists the databases of the servers the viewer can see (VIEW_SERVERS or MANAGE_DATABASES).
"""
import ipaddress
import json
import time
from datetime import datetime, timezone

from flask import jsonify, render_template
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.config import encrypt_secret
from panel.core.http import _json_body, _json_str, _log_and_generic
from panel.db.models import DatabaseEndpoint, EndpointClient, GameDatabase, HostDatabaseServer, RemoteServer, db
from panel.ops.ssh_manager import databases as _dbs
from panel.security.auth import (MANAGE_DATABASES, VIEW_SERVERS, get_remote, get_user_servers, has_permission,
                                 log_action, superadmin_required)

_TS_FRESH = 600            # a host's tailnet address is read again after 10 minutes
_TS_IPS = {}               # remote id -> (monotonic time, tailnet IPv4 or "")
_ADMIN_USER_LEN, _ADMIN_PW_LEN = 32, 128
_TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")

S_NO_TAILNET = "{host} has no Tailscale address, so it can't reach a database server on another machine."
S_ONLY_TAILNET = "Only a Tailscale address (100.x.y.z) can be used for now."
S_DB_HOST_NOT_SET_UP = "{host} has no database server the panel uses. Set up databases on that host first."
S_NOT_LISTENING = ("The database server on {host} only listens on that machine, so {game} can't reach it. On {host}, "
                   "add a file in /etc/mysql/mariadb.conf.d/ (or mysql.conf.d/) named so it sorts after the others, with "
                   "bind-address = 127.0.0.1,{address} (MariaDB 10.11 and later, MySQL 8.0.13 and later; older ones take "
                   "one address), restart it, and allow its port from {game}'s Tailscale address only. Keep it off the "
                   "internet. The panel won't change it.")
S_NO_CLIENT = "The database client could not be installed on {host}."
_VERDICTS = {
    "denied": "The database server refused that user and password.",
    "lacks_grants": "That login works but can't create users and grant them rights (it needs CREATE USER and GRANT "
                    "OPTION).",
    "partial_revokes": "That login has the narrow grant, but this MySQL server has partial_revokes on, which reads gs% "
                       "literally, so it can't make the databases. Use a login with every privilege WITH GRANT OPTION "
                       "instead.",
    "unreachable": "{host} can't reach the database server at {address}, port {port}. Check that it listens on that "
                   "address and that its firewall lets {host} in over Tailscale; the panel changes neither.",
    "tls": "This database server only accepts TLS connections; the panel can use it over Tailscale only without TLS.",
    "noclient": "{host} has no database client.",
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _say(status, sentence, **vals):
    said = i18n.tr(i18n.Sentence(sentence, **vals) if vals else sentence)
    return jsonify({"success": False, "error": said, "message": said}), status


# ── where a database's statements run ───────────────────────────────────────────────────────────
def endpoint_for_host(remote_id):
    """The DatabaseEndpoint a game host's new databases go to, or None (its own server)."""
    cl = EndpointClient.query.filter_by(remote_id=remote_id).first()
    return db.session.get(DatabaseEndpoint, cl.endpoint_id) if cl is not None else None


def client_of(remote_id):
    """The game host's EndpointClient row, or None."""
    return EndpointClient.query.filter_by(remote_id=remote_id).first()


def _ep_admin(gs_remote, ep, client):
    """(remote the statements run on, verb target) for endpoint `ep`, accounts made for `client`."""
    if ep.kind == "managed":
        hd = HostDatabaseServer.query.filter_by(remote_id=ep.remote_id).first()
        host = db.session.get(RemoteServer, ep.remote_id) if ep.remote_id else None
        return (host, _dbs.target_view(hd, client=client)) if hd is not None and host is not None else (None, None)
    return gs_remote, _dbs.target_view(ep, client=client)


def admin_target(gs_remote, local_hd, row):
    """(remote, verb target) where database `row`'s accounts are made, or (None, None) when that is gone.

    A database on the game host's own server: the game host and its HostDatabaseServer row.
    """
    if row.endpoint_id is None:
        return (gs_remote, local_hd) if local_hd is not None else (None, None)
    ep = db.session.get(DatabaseEndpoint, row.endpoint_id)
    return _ep_admin(gs_remote, ep, row.account_host) if ep is not None else (None, None)


def new_target(gs_remote, ep):
    """(remote, verb target, the game host's address) for a new database on endpoint `ep`."""
    cl = client_of(gs_remote.id)
    client = cl.seen_addr if cl is not None else ""
    remote, view = _ep_admin(gs_remote, ep, client) if client else (None, None)
    return remote, view, client


def game_view(row):
    """The target a dump or a restore of endpoint database `row` runs with on its game host, or None.

    Signed in as the database's own account, at the server's tailnet address.
    """
    ep = db.session.get(DatabaseEndpoint, row.endpoint_id) if row.endpoint_id is not None else None
    if ep is None:
        return None
    return _dbs.target_view(ep, login=(row.name, row.secret), address=ep.address)


def row_endpoint(row):
    """(address, port, flavor) the game connects to for an endpoint database, or None for a local one."""
    ep = db.session.get(DatabaseEndpoint, row.endpoint_id) if row.endpoint_id is not None else None
    return (ep.address, ep.port or 3306, ep.flavor) if ep is not None else None


def endpoint_info(ep):
    """What the tab says about the server a host's databases go to (None for none)."""
    if ep is None:
        return None
    try:
        warnings = [w for w in json.loads(ep.warnings or "[]") if isinstance(w, str)]
    except ValueError:
        warnings = []
    return {"id": ep.id, "label": ep.label, "kind": ep.kind, "address": ep.address, "port": ep.port or 3306,
            "flavor": ep.flavor, "version": ep.version or "", "warnings": warnings}


# ── a host's tailnet address ────────────────────────────────────────────────────────────────────
def tailnet_ip(remote, force=False):
    """`remote`'s Tailscale IPv4 address, or "" (not on Tailscale, or it did not answer); cached 10 minutes."""
    hit = _TS_IPS.get(remote.id)
    if hit and not force and time.monotonic() - hit[0] < _TS_FRESH:
        return hit[1]
    from panel.ops.ssh_manager import hosts as _hosts
    try:
        got = _hosts.remote_check_tailscale(remote) or {}
    except Exception:
        got = {}
    ip = _first_tailnet_v4(got.get("tailscale_ip"))
    if ip or not got.get("unreachable"):
        _TS_IPS[remote.id] = (time.monotonic(), ip)
    return ip


def _first_tailnet_v4(text):
    """The first Tailscale IPv4 address in a comma-separated list, or ""."""
    return next((w.strip() for w in str(text or "").split(",") if _is_tailnet_v4(w.strip())), "")


def moved_to(gs_remote, rows):
    """The game host's tailnet address now, when an endpoint database's account was made for another one."""
    if not any(r.endpoint_id is not None and r.account_host for r in rows):
        return ""
    now = tailnet_ip(gs_remote)
    return now if now and any(r.endpoint_id is not None and r.account_host and r.account_host != now
                              for r in rows) else ""


# ── choosing the server a host's databases go to (superadmin) ──────────────────────────────────
def _listens_on(p, address):
    """Whether a probe's listeners or bind address reach `address` (the address itself, or every one)."""
    hosts = [a.rsplit(":", 1)[0].strip("[]") for a in p.get("listeners") or []]
    return any(h in (address, "*") or _unspecified(h) for h in hosts)


def _unspecified(host):
    """Whether `host` is the any-address (0.0.0.0 or ::): a listener there answers on every address."""
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def _ensure_client(remote, flavor):
    """True when `remote` has a database client, installing it from Ubuntu when it has none."""
    p = _dbs.probe(remote) or {}
    if p.get("socket_root") != "noclient":
        return p.get("state") != "unreadable"
    return _dbs.install_client(remote, flavor)


def _managed_endpoint(game, db_remote_id):
    """(endpoint, None) for a managed host's server, made or found; or (None, refusal response)."""
    host = db.session.get(RemoteServer, db_remote_id) if isinstance(db_remote_id, int) else None
    if host is None or host.id == game.id:
        return None, _say(400, "Choose another host the panel manages.")
    hd = HostDatabaseServer.query.filter_by(remote_id=host.id).first()
    if hd is None:
        return None, _say(409, S_DB_HOST_NOT_SET_UP, host=host.name)
    address, refused = _managed_address(game, host)
    if refused is not None:
        return None, refused
    ep = DatabaseEndpoint.query.filter_by(kind="managed", remote_id=host.id).first()
    if ep is None:
        ep = DatabaseEndpoint(kind="managed", remote_id=host.id, label=host.name[:80],
                              created_by=current_user.username[:80])
        db.session.add(ep)
    ep.address, ep.port, ep.flavor, ep.version = address, hd.port or 3306, hd.flavor, hd.version or ""
    ep.native_ok, ep.warnings, ep.checked_at = hd.native_ok, hd.warnings or "", _now()
    return ep, None


def _managed_address(game, host):
    """(the database host's tailnet address, None), or ("", refusal) when it has none or its server is not there.

    The server must listen on that address (or on every one): the panel never changes where it listens.
    """
    address = tailnet_ip(host, force=True)
    if not address:
        return "", _say(409, S_NO_TAILNET, host=host.name)
    p = _dbs.probe(host) or {}
    if p.get("state") == "unreadable":
        return "", _say(502, _dbs.S_UNREADABLE)
    if not _listens_on(p, address):
        return "", _say(409, S_NOT_LISTENING, host=host.name, game=game.name, address=address)
    return address, None


def _external_fields(data):
    """(address, port, user, password, label) from the form, or None when one is not acceptable."""
    address, user = _json_str(data, "address"), _json_str(data, "user")
    pw = data.get("password") if isinstance(data.get("password"), str) else ""
    port = data.get("port", 3306)
    if not (_is_tailnet_v4(address) and _ok_port(port) and 0 < len(user) <= _ADMIN_USER_LEN
            and 0 < len(pw) <= _ADMIN_PW_LEN):
        return None
    a = str(ipaddress.ip_address(address))
    return a, port, user, pw, _json_str(data, "label")[:80] or a


def _ok_port(port):
    """Whether `port` is a TCP port number (an int, not a bool)."""
    return not isinstance(port, bool) and isinstance(port, int) and 1 <= port <= 65535


def _check_external(game, address, port, user, pw):
    """(verdict, server variables) for an external server's admin login, signed in from `game`.

    A game host with no database client gets one (from Ubuntu), and is asked again once.
    """
    verdict, v = _dbs.endpoint_check(game, address, port, user, pw)
    if verdict == "noclient" and _dbs.install_client(game, "mariadb"):
        verdict, v = _dbs.endpoint_check(game, address, port, user, pw)
    return verdict, v


def _external_endpoint(game, data):
    """(endpoint, the address the server saw, None), or (None, "", refusal response)."""
    fields = _external_fields(data)
    if fields is None:
        return None, "", _say(400, S_ONLY_TAILNET + " " + i18n.tr("Enter the server's port, admin user and password."))
    address, port, user, pw, label = fields
    verdict, v = _check_external(game, address, port, user, pw)
    if verdict != "ok":
        return None, "", _say(400, _VERDICTS.get(verdict, _dbs.S_UNREADABLE), host=game.name, address=address,
                              port=port)
    facts = _dbs.with_login_facts({"listeners": [], "port": port}, v)
    ep = DatabaseEndpoint.query.filter_by(kind="external", address=address, port=port).first()
    if ep is None:
        ep = DatabaseEndpoint(kind="external", address=address, port=port, created_by=current_user.username[:80])
        db.session.add(ep)
    ep.label, ep.flavor, ep.version, ep.native_ok = label, facts["flavor"], facts["version"], facts["native_ok"]
    ep.warnings = json.dumps([w for w in facts["warnings"] if w in ("tls_required", "old_logins_only")])
    ep.admin_user, ep.admin_secret, ep.checked_at = user, encrypt_secret(pw), _now()
    seen = v.get("seen", "")
    return ep, (seen if _is_tailnet_v4(seen) else ""), None


def _is_tailnet_v4(text):
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return False
    return a.version == 4 and a in _TAILNET_V4


def _choose_answer(game):
    """POST: send this host's new databases to a server on another machine (or back to its own)."""
    data = _json_body()
    if data.get("clear") is True:
        EndpointClient.query.filter_by(remote_id=game.id).delete()
        db.session.commit()
        log_action(current_user, "db_endpoint_allow", target=game.name, detail="own server again", remote=game)
        return jsonify({"success": True, "message": i18n.tr("New databases on this host go to its own server again.")})
    mine = tailnet_ip(game, force=True)
    if not mine:
        return _say(409, S_NO_TAILNET, host=game.name)
    if data.get("kind") == "managed":
        ep, refused = _managed_endpoint(game, data.get("db_remote_id"))
        seen = ""
    else:
        ep, seen, refused = _external_endpoint(game, data)
    if refused is not None:
        db.session.rollback()
        return refused
    if ep.kind == "managed" and not _ensure_client(game, ep.flavor):
        db.session.rollback()
        return _say(502, S_NO_CLIENT, host=game.name)
    return _finish_reuse(game, ep, seen)


def _choices_answer(game):
    """GET: the server this host's databases go to, and what a superadmin may choose instead."""
    ep = endpoint_for_host(game.id)
    hosts = [{"id": r.id, "name": r.name} for r in RemoteServer.query.order_by(RemoteServer.name).all()
             if r.id != game.id and HostDatabaseServer.query.filter_by(remote_id=r.id).first() is not None]
    return jsonify({"current": endpoint_info(ep) if ep is not None else None, "hosts": hosts,
                    "external": [endpoint_info(e) for e in DatabaseEndpoint.query.filter_by(kind="external")
                                 .order_by(DatabaseEndpoint.id).all()]})


def _reuse_external(game, ep_id):
    """The stored admin login of external endpoint `ep_id`, as the form's fields, or None."""
    from panel.core.config import decrypt_secret
    ep = db.session.get(DatabaseEndpoint, ep_id) if isinstance(ep_id, int) else None
    if ep is None or ep.kind != "external":
        return None
    return {"address": ep.address, "port": ep.port, "user": ep.admin_user or "",
            "password": decrypt_secret(ep.admin_secret or "") or "", "label": ep.label}


# ── the overview page ───────────────────────────────────────────────────────────────────────────
def _host_word(hd, ep, refused):
    """How the panel uses a host's database server, in a few words."""
    if ep is not None:
        return i18n.Sentence("Uses {label} ({address}) over Tailscale", label=ep.label, address=ep.address)
    if hd is None:
        return i18n.Sentence("No database server set up")
    if hd.auth_mode == "login":
        return (i18n.Sentence("Existing server; its stored admin login is refused") if refused
                else i18n.Sentence("Existing server, signed in with a stored admin login"))
    return (i18n.Sentence("Installed by the panel") if hd.installed_by_panel
            else i18n.Sentence("Existing server"))


def overview_rows(user):
    """(hosts, databases) the overview lists for `user`: only the servers they can see, and their hosts."""
    servers = {gs.id: gs for gs in get_user_servers(user)}
    rows = (GameDatabase.query.filter(GameDatabase.game_server_id.in_(list(servers)))
            .order_by(GameDatabase.game_server_id, GameDatabase.id).all() if servers else [])
    remote_ids = sorted({gs.remote_id for gs in servers.values()})
    eps = {e.id: e for e in DatabaseEndpoint.query.all()} if remote_ids else {}
    names = {gs.remote_id: gs.remote.name for gs in servers.values()}
    hosts = _overview_hosts(remote_ids, names, eps)
    dbs = []
    for r in rows:
        gs, ep = servers[r.game_server_id], eps.get(r.endpoint_id)
        dbs.append({"name": r.name, "server_id": gs.id, "server": gs.name, "host": names.get(gs.remote_id, ""),
                    "where": ep.label if ep is not None else "", "size": r.size_bytes})
    return hosts, dbs


def _overview_hosts(remote_ids, names, eps):
    """One line per host in `remote_ids`: its name, how the panel uses its database server, and which one."""
    hds = {h.remote_id: h for h in HostDatabaseServer.query.filter(HostDatabaseServer.remote_id.in_(remote_ids))}
    cls = {c.remote_id: c for c in EndpointClient.query.filter(EndpointClient.remote_id.in_(remote_ids))}
    hosts = []
    for rid in remote_ids:
        hd, cl = hds.get(rid), cls.get(rid)
        ep = eps.get(cl.endpoint_id) if cl is not None else None
        hosts.append({"name": names.get(rid, ""), "state": i18n.tr(_host_word(hd, ep, _dbs.LOGIN_REFUSED.get(rid))),
                      "server": _server_name(hd)})
    return hosts


def _server_name(hd):
    """The server's name and version ('MariaDB 10.11.14', 'MySQL 8.4.11') from a host's row, or "" with none."""
    if hd is None:
        return ""
    return ("MySQL" if hd.flavor == "mysql" else "MariaDB") + " " + (hd.version or "")[:8]


def _size_text(b):
    if not isinstance(b, int):
        return ""
    for unit, n in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if b >= n:
            return "≈ %s %s" % (round(b / n, 1) if unit == "GB" else round(b / n), unit)
    return "%d B" % b


def overview_access():
    """Whether the viewer gets the Databases page (and its sidebar link)."""
    if not getattr(current_user, "is_authenticated", False):
        return False
    return has_permission(current_user, VIEW_SERVERS) or has_permission(current_user, MANAGE_DATABASES)


# ── routes ──────────────────────────────────────────────────────────────────────────────────────
def register(app):
    """The overview page, and the superadmin's choice of the server a host's databases go to."""
    app.jinja_env.globals["db_overview"] = overview_access

    @app.route("/databases")
    @login_required
    def databases_overview():
        """Every database the viewer may see, by server, and each host's database server (read only)."""
        if not overview_access():
            return _say(403, "Permission denied")
        hosts, dbs = overview_rows(current_user)
        for d in dbs:
            d["size_text"] = _size_text(d["size"])
        return render_template("databases_overview.html", hosts=hosts, databases=dbs)

    @app.route("/api/remote/<int:remote_id>/databases/endpoint", methods=["GET", "POST"])
    @login_required
    @superadmin_required
    def api_remote_databases_endpoint(remote_id):
        """Return (GET) or choose (POST) the server this host's new databases go to."""
        from flask import request
        game = get_remote(remote_id)
        try:
            if request.method == "GET":
                return _choices_answer(game)
            data = _json_body()
            if isinstance(data.get("endpoint_id"), int):
                fields = _reuse_external(game, data["endpoint_id"])
                if fields is None:
                    return _say(404, "No such database server.")
                ep, seen, refused = _external_endpoint(game, fields)
                if refused is not None:
                    return refused
                return _finish_reuse(game, ep, seen)
            return _choose_answer(game)
        except Exception:
            db.session.rollback()
            return _say(500, _log_and_generic("choosing a database server failed"))


def _finish_reuse(game, ep, seen):
    """Point `game` at an external endpoint that was checked again from it."""
    mine = tailnet_ip(game, force=True)
    if not mine:
        db.session.rollback()
        return _say(409, S_NO_TAILNET, host=game.name)
    db.session.flush()
    cl = client_of(game.id) or EndpointClient(remote_id=game.id, endpoint_id=ep.id)
    cl.endpoint_id, cl.seen_addr, cl.checked_at = ep.id, seen or mine, _now()
    db.session.add(cl)
    db.session.commit()
    log_action(current_user, "db_endpoint_allow", target=game.name, remote=game,
               detail="new databases go to %s (%s:%d), accounts for %s" % (ep.label, ep.address, ep.port, cl.seen_addr))
    return jsonify({"success": True, "message": i18n.tr(i18n.Sentence(
        "New databases on this host go to {label} ({address}), with accounts for {client} only.",
        label=ep.label, address=ep.address, client=cl.seen_addr))})
