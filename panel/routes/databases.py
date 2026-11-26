"""The Databases tab: MariaDB / MySQL databases for a game server's plugins.

A game's plugins (LuckPerms, CoreProtect, SourceBans++, oxmysql...) keep their data in a database on
the server's own host. The tab adds one with a single name, shows its host, port, name, user and
password with a copy button each and a ready-to-paste config for the game's plugins
(services/db_snippets), resets its password, restores it from the dump a backup put in the game's
files, and deletes it (an archive dump first). The first database on a host with no database server
offers one click to install MariaDB from Ubuntu, listening on this machine only; a server that is
already there is used as it is and never reconfigured. Everything on the host goes through
ssh_manager.databases.

PERMISSION. Seeing the list (no passwords) takes the server's view permission (VIEW_SERVERS) and
access to the server; every change and every password takes MANAGE_DATABASES too. Installing MariaDB
is a host-level root action: MANAGE_DATABASES and MANAGE_REMOTES (or superadmin), through
get_host_remote. A server's own admin login, and the password of the account the panel made on a
server it installed, are superadmin only. Passwords leave the panel only through the reveal routes
(POST, no-store, audited); never in a list, an audit row or a log line.

ROWS. GameDatabase (one per database; game_server_id None once its server was removed from the panel
and the database kept) and HostDatabaseServer (one per host the panel signs in to), in
panel/db/models.py.
"""
import contextlib
import functools
import json
import re
import threading
import time
from datetime import datetime, timezone

from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.config import decrypt_secret, encrypt_secret, load_config
from panel.core.http import _json_body, _json_str, _log_and_generic, _unreachable
from panel.db.models import GameDatabase, HostDatabaseServer, RemoteServer, claim_row, db, row_birth
from panel.ops.ssh_manager import databases as _dbs
from panel.routes._shared import _r20b_audit_on_raise, _r42r_audit_after, game_account_write_refusal
from panel.security.auth import (MANAGE_DATABASES, MANAGE_REMOTES, VIEW_SERVERS, get_game, get_host_remote, get_remote,
                                 has_permission, log_action, server_access_required, superadmin_required)
from panel.routes import addons, databases_net as _net
from panel.security.account_guard import step_up_needed, step_up_refusal, step_up_required
from panel.services import db_snippets as _snip

_SLUG_RE = re.compile(r"[a-z0-9]{1,16}\Z")
_ADMIN_USER_RE = re.compile(r"[A-Za-z0-9_.@-]{1,32}\Z")
_ADMIN_PW_RE = re.compile(r"[\x20-\x7e]{1,128}\Z")
PW_MARK = "•" * 8          # what a snippet shows where the password goes, until it is revealed
GRANT_PW_MARK = "<PASSWORD>"    # where the dedicated login's statements take the password the page makes
_PROBE_FRESH = 600              # a host's probe is reused for 10 minutes
_SIZE_FRESH = 60                # sizes are asked of the host at most once a minute
_SHA2 = "caching_sha2_password"

_DENIED = "Permission denied"
_NO_SUCH = "No such database on this server."
_NOT_READY = ("This host has no database server the panel can use yet. Set up databases on this host "
              "first.")
_UNREAD = "Couldn't read the database server on this host: it did not answer. Try again."

# remote id -> (monotonic time, probe dict) for a host with no HostDatabaseServer row yet.
_PROBES = {}
# remote id -> {"running": bool, "why": str}: "Set up databases on this host" in the background.
_SETUP = {}
_SETUP_LOCK = threading.Lock()
# Database row id -> what is being done to it now ("dump", "restore" or "delete"). One at a time per
# database: two imports into one database interleave each other's DROP, CREATE and INSERT, and an import
# reading the dump a dump is rewriting loads half a file, each answered as success. A second request is
# refused (409), as a game backup restore and an add-on removal are.
_BUSY = {}
_BUSY_LOCK = threading.Lock()
_BUSY_SAID = {
    "dump": "This database is being dumped right now. Try again when that has finished.",
    "restore": "This database is being restored right now. Try again when that has finished.",
    "delete": "This database is being deleted right now.",
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _can_manage():
    return has_permission(current_user, MANAGE_DATABASES)


def _can_setup():
    return _can_manage() and has_permission(current_user, MANAGE_REMOTES)


def tab_access():
    """For the Files & Config page (`db_tab()`): whether the viewer gets the tab, and may change it."""
    if not getattr(current_user, "is_authenticated", False):
        return {"view": False, "manage": False}
    manage = _can_manage()
    return {"view": manage or has_permission(current_user, VIEW_SERVERS), "manage": manage}


def _say(status, sentence, **extra):
    """A JSON refusal: `sentence` translated, with the same text in error and message."""
    said = i18n.tr(sentence)
    return jsonify(dict({"success": False, "error": said, "message": said}, **extra)), status


def _cfg_int(v, default, low, high):
    """A config.json value as a whole number in low..high, else `default`."""
    if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
        return default
    return v


def _cap():
    """How many databases one game server may have (config.json db_max_per_server, 1-50)."""
    return _cfg_int(load_config().get("db_max_per_server"), 5, 1, 50)


def _maxconn():
    """Connections each database's user may hold at once (config.json db_max_user_connections, 1-500)."""
    return _cfg_int(load_config().get("db_max_user_connections"), 30, 1, 500)


# ── the host's database server ──────────────────────────────────────────────────────────────────
def _host_row(remote_id):
    return HostDatabaseServer.query.filter_by(remote_id=remote_id).first()


def _warnings(hd):
    try:
        got = json.loads(hd.warnings or "[]")
    except ValueError:
        return []
    return [w for w in got if isinstance(w, str)] if isinstance(got, list) else []


def _store_probe(hd, p):
    """Copy what a probe read onto the host's row."""
    for key in ("flavor", "version"):
        if p.get(key):
            setattr(hd, key, str(p[key])[:40])
    if isinstance(p.get("port"), int):
        hd.port = p["port"]
    if isinstance(p.get("native_ok"), bool):
        hd.native_ok = p["native_ok"]
    hd.warnings = json.dumps([w for w in (p.get("warnings") or []) if isinstance(w, str)])
    hd.checked_at = _now()


def _probe(remote, force=False):
    """The host's probe, from the 10-minute cache unless `force`."""
    hit = _PROBES.get(remote.id)
    if hit and not force and time.monotonic() - hit[0] < _PROBE_FRESH:
        return hit[1]
    p = _dbs.probe(remote)
    p = p if isinstance(p, dict) else {"state": "unreadable"}
    # A host that did not answer is asked again next time, not reported down for ten minutes.
    if p.get("state") == "unreadable":
        _PROBES.pop(remote.id, None)
    else:
        _PROBES[remote.id] = (time.monotonic(), p)
    return p


def _new_host_row(remote, p, **fields):
    hd = HostDatabaseServer(remote_id=remote.id, flavor=p.get("flavor") or "mariadb", **fields)
    _store_probe(hd, p)
    db.session.add(hd)
    return hd


def _recheck(remote, hd):
    """A row older than 10 minutes, probed again: the state it is in now."""
    p = _probe(remote, force=True)
    state = p.get("state")
    if state == "needs_login" and hd.auth_mode == "login":
        state = "ready"          # the socket is refused, and the panel signs in with the stored login
        p = _login_probe(remote, hd, p)
    if state == "ready":
        _store_probe(hd, p)
        db.session.commit()
    return state or "unreadable"


def _login_probe(remote, hd, p):
    """`p` completed through the stored admin login: the version and native logins the socket can't read.

    A refused or unreadable login leaves `p` as it was (its refusal is the next write's to report).
    """
    user, secret = _dbs._secrets_for(hd)["admin"]
    verdict, v = _dbs.admin_check(remote, hd.port or 3306, user, secret)
    return _dbs.with_login_facts(p, v) if verdict in ("ok", "lacks_grants", "partial_revokes") else p


def _probe_again(hd, may_probe):
    """Whether a host with a row is probed now: on Refresh, or once the row is 10 minutes old."""
    return may_probe == "force" or (bool(may_probe) and not _fresh(hd.checked_at, _PROBE_FRESH))


def _probe_mode(manage):
    """How far the list looks at the host: only what is stored (a viewer), when stale, or now (Refresh)."""
    if not manage:
        return False
    return "force" if request.args.get("refresh") else True


def host_state(remote, may_probe):
    """(state, HostDatabaseServer row or None, probe dict) for `remote`.

    A host with a row was found ready before: it is probed again once its row is 10 minutes old.
    A host without one is probed (cached 10 minutes); found ready, it gets its row (an existing
    server, used as it is). `may_probe` False reads only what is stored; "force" (the tab's Refresh)
    probes now whatever is stored.
    """
    hd = _host_row(remote.id)
    if _SETUP.get(remote.id, {}).get("running"):
        return "setting_up", hd, {}
    if hd is not None:
        return (_recheck(remote, hd) if _probe_again(hd, may_probe) else "ready"), hd, {}
    if not may_probe:
        hit = _PROBES.get(remote.id)
        return ((hit[1].get("state") or "unreadable") if hit else "unknown"), None, {}
    p = _probe(remote, force=may_probe == "force")
    if p.get("state") == "ready":
        hd = _new_host_row(remote, p, installed_by_panel=False, auth_mode="socket")
        db.session.commit()
    return p.get("state") or "unreadable", hd, p


def _host_info(hd):
    if hd is None:
        return None
    login = hd.auth_mode == "login"
    return {"flavor": hd.flavor, "version": hd.version or "", "port": hd.port or 3306,
            "installed_by_panel": bool(hd.installed_by_panel), "login": login,
            "login_refused": login and bool(_dbs.LOGIN_REFUSED.get(hd.remote_id)),
            "warnings": _warnings(hd)}


# ── the databases ───────────────────────────────────────────────────────────────────────────────
def _server_rows(server_id):
    return GameDatabase.query.filter_by(game_server_id=server_id).order_by(GameDatabase.id).all()


def _fresh(when, seconds):
    """Whether `when` (a naive UTC time, or None) is less than `seconds` ago."""
    return bool(when) and (_now() - when).total_seconds() < seconds


def _refresh_sizes(gs, hd, rows):
    """Ask the host for the sizes of `rows` when any is older than a minute (one call for all).

    The same call says which of them have a dump in the server's files, and when it was written:
    that is `dumped_at`, so the tab offers Restore only for a database there is a dump of.
    """
    now = _now()
    if all(_fresh(r.size_at, _SIZE_FRESH) for r in rows):
        return
    # One call per server the databases are on (in practice one): where their accounts are made.
    for ep_id in sorted({r.endpoint_id for r in rows}, key=lambda x: (x is not None, x or 0)):
        _sizes_of(gs, hd, [r for r in rows if r.endpoint_id == ep_id], now)


def _sizes_of(gs, hd, group, now):
    """One sizes call for `group` (databases on one server), where their accounts are made."""
    remote, target = _net.admin_target(gs.remote, hd, group[0])
    if remote is None:
        return
    # The game host's files are read for its dumps only where the call runs on the game host.
    account = gs.short_name if remote is gs.remote else "-"
    try:
        got = _dbs.sizes(remote, target, account, [r.name for r in group])
    except Exception:
        got = None
    if isinstance(got, dict):
        _store_sizes(group, got.get("sizes") or {}, got.get("dumps") or {}, now, account != "-")


def _store_sizes(rows, sizes, dumps, now, read_dumps=True):
    """Store what one sizes call read: each row's size, and when its dump in the files was written.

    `read_dumps` False: the call ran where the game's files are not (another machine), so the dump
    times the backups recorded are kept.
    """
    for r in rows:
        if isinstance(sizes.get(r.name), int):
            r.size_bytes, r.size_at = sizes[r.name], now
            if read_dumps:
                r.dumped_at = _from_unix(dumps.get(r.name))
    db.session.commit()


def _from_unix(t):
    """A Unix time as a naive UTC datetime, or None."""
    if isinstance(t, bool) or not isinstance(t, int) or t < 0:
        return None
    return datetime.fromtimestamp(t, timezone.utc).replace(tzinfo=None)


def _iso(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat() if dt else None


def _row_json(gs, hd, r, moved=""):
    port = (hd.port if hd is not None else None) or 3306
    flavor = hd.flavor if hd is not None else "mariadb"
    host = _snip.HOST
    far = _net.row_endpoint(r)
    if far is not None:
        host, port, flavor = far
    return {"id": r.id, "name": r.name, "user": r.name, "host": host, "port": port,
            "account_host": r.account_host or "",
            "moved": bool(moved and r.endpoint_id is not None and r.account_host and r.account_host != moved),
            "size": r.size_bytes, "dumped_at": _iso(r.dumped_at),
            "old_logins": r.auth_plugin == _SHA2,
            "snippets": [{"kind": k, "label": label, "text": text} for k, label, text
                         in _snip.render_all(gs.game_type, flavor, port, r.name, PW_MARK, host)]}


def _list_answer(gs):
    """GET: the host's state and this server's databases (never a password)."""
    manage = _can_manage()
    ep, (state, hd, p) = _list_host(gs, manage)
    rows = _server_rows(gs.id)
    _refresh_sizes(gs, hd, rows)
    taken = [r.name.split("_", 1)[1] for r in rows if "_" in r.name]
    setup = _SETUP.get(gs.remote_id) or {}
    moved = _net.moved_to(gs.remote, rows) if manage else ""
    return jsonify({
        "state": state, "remote_id": gs.remote_id, "host": _host_info(hd),
        "endpoint": _net.endpoint_info(ep), "moved_to": moved,
        "probe_warnings": [w for w in (p.get("warnings") or []) if isinstance(w, str)],
        "setup_error": i18n.tr(setup["why"]) if setup.get("why") else "",
        "can": {"manage": manage, "setup": _can_setup(), "su": bool(current_user.is_superadmin)},
        "prefix": "gs%d_" % gs.id, "suggest": _snip.suggest_slug(gs.game_type, taken),
        "cap": _cap(), "used": len(rows), "pw_mark": PW_MARK,
        # The dedicated login's statements, for a superadmin's admin login form (its password is made
        # on the viewer's page, where GRANT_PW_MARK stands).
        "grant": _grant_offer(),
        "databases": [_row_json(gs, hd, r, moved) for r in rows]})


def _list_host(gs, manage):
    """(endpoint or None, (state, host row, probe)) for the list.

    With an endpoint, new databases go to a server on another machine: the host's own is not looked at.
    """
    ep = _net.endpoint_for_host(gs.remote_id)
    if ep is not None:
        return ep, ("ready", _host_row(gs.remote_id), {})
    return None, host_state(gs.remote, may_probe=_probe_mode(manage))


def _grant_offer():
    """The dedicated login's statements, for a superadmin's admin login form, else None.

    The password is made on the viewer's page, where GRANT_PW_MARK stands.
    """
    if not current_user.is_superadmin:
        return None
    return {"user": _dbs.SCOPED_USER, "mark": GRANT_PW_MARK, "sql": _dbs.scoped_grant_sql(GRANT_PW_MARK)}


def _names_answer(gs):
    """GET ?names=1: only this server's database names, for the uninstall dialog (nothing asked of the host)."""
    return jsonify({"names": [r.name for r in _server_rows(gs.id)]})


def _add_refusal(gs, slug, rows):
    """Why a new database `slug` can't be added to `gs` now (status, sentence), or None."""
    if not _SLUG_RE.match(slug):
        return 400, i18n.Sentence("A name is 1 to 16 lower-case letters and digits.")
    if len(rows) >= _cap():
        return 409, i18n.Sentence("This server already has {n} databases, the most it may have.", n=len(rows))
    if GameDatabase.query.filter_by(remote_id=gs.remote_id, name="gs%d_%s" % (gs.id, slug)).first() is not None:
        return 409, i18n.Sentence("This server already has a database with that name.")
    return None


def _add_answer(gs):
    """POST {"name"}: a new database and its own user, with a new password."""
    slug = _json_str(_json_body(), "name").lower()
    refused = _add_refusal(gs, slug, _server_rows(gs.id))
    if refused:
        return _say(*refused)
    ep, remote, hd, client, state = _add_target(gs)
    if state != "ready":
        return _say(409, _NOT_READY if state != "unreadable" else _UNREAD, state=state)
    name, secret = _dbs.db_name(gs.id, slug), _dbs.new_password()
    plugin, maxconn = _dbs.auth_plugin_name(_dbs.plugin_for(hd)), _maxconn()
    with _r20b_audit_on_raise("db_create", target=gs.name, detail=name, server=gs):
        ok, said = _create_proved(gs, (ep, remote, hd, client), name, secret, maxconn)
    if ok:
        db.session.add(GameDatabase(remote_id=gs.remote_id, game_server_id=gs.id, name=name,
                                    secret=encrypt_secret(secret), auth_plugin=plugin,
                                    max_conn=maxconn, created_by=current_user.username[:80],
                                    endpoint_id=getattr(ep, "id", None), account_host=client))
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(said or ("Database added." if ok else "Failed"))}
    where = " on %s for %s" % (ep.label, client) if ep is not None else ""
    with _r42r_audit_after(reply):
        log_action(current_user, "db_create", target=gs.name, detail="created database %s%s" % (name, where)
                   if ok else "database %s not created: %s" % (name, said), success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _add_target(gs):
    """(endpoint or None, remote, verb target, account host or None, state) for a new database of `gs`."""
    ep = _net.endpoint_for_host(gs.remote_id)
    if ep is not None:
        remote, hd, client = _net.new_target(gs.remote, ep)
        return ep, remote, hd, client, ("ready" if remote is not None else "gone")
    state, hd, _p = host_state(gs.remote, may_probe=True)
    return None, gs.remote, hd, None, state


def _create_proved(gs, where, name, secret, maxconn):
    """Create the database where `where` (endpoint, remote, target, client) says; an endpoint's must sign in."""
    ep, remote, hd, client = where
    ok, said = _dbs.create(remote, hd, name, secret, maxconn)
    if ok and ep is not None:
        ok, said = _proved(gs, ep, remote, hd, name, secret, client)
    return ok, said


def _proved(gs, ep, remote, target, name, secret, client):
    """(ok, sentence) after a new endpoint database's account signs in from the game host.

    Nothing is kept until it does: a failed sign-in drops what was just made and says why (the host
    can't reach the server, or the server sees the game host at another address than `client`).
    """
    kind, seen = _dbs.sign_in_check(gs.remote, ep, name, secret)
    if kind == "ok":
        return True, ""
    _dbs.drop(remote, target, None, name)
    vals = {"host": gs.remote.name, "address": ep.address, "port": ep.port or 3306}
    if kind == "denied" and seen and seen != client:
        return False, i18n.Sentence(_dbs.S_NET_SEEN, host=gs.remote.name, seen=seen, client=client)
    text = {"unreachable": _dbs.S_NET_UNREACHABLE, "denied": _dbs.S_NET_DENIED, "tls": _dbs.S_NET_TLS,
            "keyauth": _dbs.S_NET_KEY,
            "noclient": _dbs.S_NO_CLIENT}.get(kind, _dbs.S_NET_ERROR)
    return False, i18n.Sentence(text, **vals) if "{" in text else text


def _own_row(gs, db_id):
    """Return the server's own database `db_id`, or None (another server's is None too)."""
    r = db.session.get(GameDatabase, db_id)
    return r if r is not None and r.game_server_id == gs.id and r.remote_id == gs.remote_id else None


def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _reveal_answer(gs, r):
    """POST: the database's password, for the viewer's own screen or clipboard; audited, never logged."""
    secret = decrypt_secret(r.secret)
    if not secret:
        return _say(500, "The stored password can't be read on this panel.")
    log_action(current_user, "db_reveal", target=gs.name, detail="revealed the password of database %s" % r.name,
               server=gs)
    return _no_store(jsonify({"success": True, "password": secret}))


_ADDON_RESET = ("{addon} uses this database, and its own settings hold the current password. Remove the add-on on "
                "the Add-ons tab first, then reset the password.")
_ADDON_DELETE = "{addon} uses this database. Remove the add-on on the Add-ons tab first, then delete the database."


def _addon_refusal(gs, r, sentence):
    """The refusal when an add-on uses database `r` (its name in `sentence`), or one is being set up, or None.

    An install or settings change still running has chosen its database but written no record yet,
    so the record read alone would let a reset or a delete cut it off before it ever starts.
    """
    if addons.job_running(gs.id):
        return _say(409, addons.ADDON_BUSY)
    addon = addons.addon_using_database(gs, r.name)
    return _say(409, i18n.Sentence(sentence, addon=addon)) if addon else None


def _reset_answer(gs, r):
    """POST: a new password for the database's user (both of its host entries)."""
    remote, hd = _net.admin_target(gs.remote, _host_row(gs.remote_id), r)
    if remote is None:
        return _say(409, _NOT_READY)
    held = _addon_refusal(gs, r, _ADDON_RESET)
    if held is not None:
        return held
    secret = _dbs.new_password()
    with _r20b_audit_on_raise("db_password", target=gs.name, detail=r.name, server=gs):
        ok, said = _dbs.set_password(remote, hd, r.name, secret)
    if ok:
        r.secret = encrypt_secret(secret)
        r.auth_plugin = _dbs.auth_plugin_name(_dbs.plugin_for(hd))
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(
        said or ("New password set. Update it in the game's config, then restart the server." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_password", target=gs.name, detail=_done_or_not(
            ok, "new password for database %s" % r.name, "database %s password not changed" % r.name, said),
            success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _done_or_not(ok, done, not_done, said):
    """An audit row's detail: what was done, or what was not and why (never the success wording)."""
    return done if ok else "%s: %s" % (not_done, said or "failed")


def _confirmed(r):
    return _json_str(_json_body(), "confirm") == r.name


@contextlib.contextmanager
def database_claim(db_id, what):
    """Hold database `db_id` for `what` (a _BUSY_SAID key) while the block runs.

    Yields None when it is now held, or what another request is already doing to it (and then it is
    not held, and nothing is released after).
    """
    with _BUSY_LOCK:
        running = _BUSY.get(db_id)
        if running is None:
            _BUSY[db_id] = what
    try:
        yield running
    finally:
        if running is None:
            with _BUSY_LOCK:
                _BUSY.pop(db_id, None)


def one_at_a_time(what, action):
    """Make answer(gs, r, ...) hold database r for `what`; a request meanwhile is refused and audited as `action`."""
    def wrap(answer):
        @functools.wraps(answer)
        def held(gs, r, *args):
            with database_claim(r.id, what) as running:
                if running is not None:
                    said = _BUSY_SAID[running]
                    log_action(current_user, action, target=gs.name, server=gs, success=False,
                               detail="%s (refused: %s)" % (r.name, said))
                    return _say(409, said)
                return answer(gs, r, *args)
        return held
    return wrap


@one_at_a_time("delete", "db_delete")
def _delete_answer(gs, r):
    """POST {"confirm": name}: the database and its user dropped (a dump kept on the host first)."""
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    local = _host_row(gs.remote_id)
    if _net.admin_target(gs.remote, local, r)[0] is None:
        return _say(409, _NOT_READY)
    held = _addon_refusal(gs, r, _ADDON_DELETE)
    if held is not None:
        return held
    name = r.name
    with _r20b_audit_on_raise("db_delete", target=gs.name, detail=name, server=gs):
        ok, said = drop_row(gs.remote, local, r, gs.short_name)
    if ok:
        _forget_data(r.id)
        db.session.delete(r)
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(
        said or ("Database deleted. A copy is kept on the host for 30 days." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_delete", target=gs.name, detail=_done_or_not(
            ok, "deleted database %s" % name, "database %s not deleted" % name, said), success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


@one_at_a_time("restore", "db_restore")
def _restore_answer(gs, r):
    """POST {"confirm": name}: the database loaded from panel-db-dumps/<name>.sql.gz in the game's files."""
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    hd = _restore_target(gs, r)
    if hd is None:
        return _say(409, _NOT_READY)
    # The dump is the game's file and the import runs as the game account.
    refused = game_account_write_refusal(gs.remote, gs.short_name)
    if refused is not None:
        log_action(current_user, "db_restore", target=gs.name, detail="%s (refused: %s)" % (r.name, refused),
                   success=False, server=gs)
        return _say(409, refused)
    with _r20b_audit_on_raise("db_restore", target=gs.name, detail=r.name, server=gs):
        ok, said = _dbs.restore(gs.remote, hd, gs.short_name, r.name, decrypt_secret(r.secret))
    _forget_data(r.id)
    if ok is None:
        # No dump of it in the server's files: nothing was touched, and the tab stops offering it.
        r.dumped_at = None
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(said or ("Database restored." if ok else "Failed"))}
    if ok is None:
        reply["no_dump"] = True
    with _r42r_audit_after(reply):
        log_action(current_user, "db_restore", target=gs.name, detail=_done_or_not(
            ok, "restored database %s from its dump" % r.name, "database %s not restored" % r.name, said),
            success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else (409 if ok is None else 502)


def _forget_data(db_id):
    """The manager's cached structure of a database that was restored or deleted."""
    from panel.routes import databases_data
    databases_data.forget(db_id)


def _restore_target(gs, r):
    """What a restore of `r` signs in to: the host's own server, or one on another machine at its tailnet address.

    Either way the import runs on the game host, as its game account.
    """
    return _net.game_view(r) if r.endpoint_id is not None else _host_row(gs.remote_id)


def _move_answer(gs, r):
    """POST: move an endpoint database's account to the game host's tailnet address now.

    Its account was made for the address the host had then; RENAME USER keeps the password and
    grants. The new account must sign in from the host, or it is moved back.
    """
    new = _net.tailnet_ip(gs.remote, force=True)
    old = r.account_host or ""
    if _nothing_to_move(r, old, new):
        return _say(409, "This database's account already signs in from this host's address.")
    ep = db.session.get(_net.DatabaseEndpoint, r.endpoint_id)
    remote, target = _net.admin_target(gs.remote, _host_row(gs.remote_id), r)
    if remote is None or ep is None:
        return _say(409, _NOT_READY)
    with _r20b_audit_on_raise("db_rehost", target=gs.name, detail=r.name, server=gs):
        ok, said = _rehost_proved(gs, ep, (remote, target), r, (old, new))
    if ok:
        _moved_rows(gs, r, new)
    reply = {"success": bool(ok), "message": i18n.tr(said or "Failed")}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_rehost", target=gs.name, detail=_done_or_not(
            ok, "account of %s moved from %s to %s" % (r.name, old, new), "account of %s not moved" % r.name, said),
            success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _nothing_to_move(r, old, new):
    """Whether `r` has no account on another machine to move, or it already signs in from `new`."""
    return r.endpoint_id is None or not old or not new or new == old


def _rehost_proved(gs, ep, where, r, move):
    """Rename `r`'s account (old, new) where its accounts are made; moved back unless it signs in from the host."""
    (remote, target), (old, new) = where, move
    ok, said = _dbs.rehost(remote, target, r.name, old, new)
    if ok and _dbs.sign_in_check(gs.remote, ep, r.name, decrypt_secret(r.secret))[0] != "ok":
        _dbs.rehost(remote, target, r.name, new, old)
        return False, i18n.Sentence(_dbs.S_NET_ERROR, host=gs.remote.name)
    return ok, said


def _moved_rows(gs, r, new):
    """Record that `r`'s account now signs in from `new`, and the host's own choice says so too."""
    r.account_host = new
    cl = _net.client_of(gs.remote_id)
    if cl is not None and cl.endpoint_id == r.endpoint_id:
        cl.seen_addr = new
    db.session.commit()


# ── setting up a host ───────────────────────────────────────────────────────────────────────────
def _setup_worker(app, remote_id, born, who):
    """Install MariaDB on a host that has no database server, then record it. Runs in a thread."""
    with app.app_context():
        why = ""
        try:
            why = _setup_steps(remote_id, born, who)
        except Exception:
            why = _log_and_generic("database setup failed")
        finally:
            with _SETUP_LOCK:
                _SETUP[remote_id] = {"running": False, "why": why}
            _PROBES.pop(remote_id, None)


def _setup_steps(remote_id, born, who):
    """The setup itself: '' when MariaDB is installed and recorded, else why not."""
    remote = claim_row(RemoteServer, remote_id, born)
    if remote is None:
        return ""
    # Never over a server that is already there: the probe must find none.
    if (_dbs.probe(remote) or {}).get("state") != "none":
        why = i18n.Sentence("A database server is already on this host, so nothing was installed.")
    else:
        why = _install(remote)
    log_action(None, "db_setup", target=remote.name, actor=who, success=not why, remote=remote,
               detail="MariaDB installed" if not why else "not installed: %s" % why)
    return why


def _install(remote):
    """Install MariaDB and record the host's row: '' when it worked, else why not."""
    ok, said, admin_pw = _dbs.install_mariadb(remote)
    if not ok:
        return said or i18n.Sentence("The install failed.")
    p = _dbs.probe(remote) or {}
    hd = _host_row(remote.id) or _new_host_row(remote, p)
    _store_probe(hd, p)
    hd.flavor, hd.installed_by_panel, hd.auth_mode = "mariadb", True, "socket"
    hd.panel_admin_secret = encrypt_secret(admin_pw or "")
    db.session.commit()
    return ""


def _setup_answer(app, remote):
    """POST: start installing MariaDB on `remote` in the background (202); the tab's GET says how it went."""
    if _host_row(remote.id) is not None:
        return _say(409, "This host's database server is already set up.")
    with _SETUP_LOCK:
        if _SETUP.get(remote.id, {}).get("running"):
            return _say(409, "Databases are already being set up on this host.")
        _SETUP[remote.id] = {"running": True, "why": ""}
    log_action(current_user, "db_setup", target=remote.name, detail="started", remote=remote)
    threading.Thread(target=_setup_worker, args=(app, remote.id, row_birth(remote), current_user.username),
                     daemon=True).start()
    return jsonify({"success": True, "started": True,
                    "message": i18n.tr("Setting up databases on this host. This takes a minute or two.")}), 202


def _admin_clear_answer(remote):
    """POST {"clear": true}: drop the stored admin login, once root signs in over the socket again."""
    hd = _host_row(remote.id)
    if hd is None or hd.auth_mode != "login":
        return _say(409, "There is no stored admin login for this host's database server.")
    p = _probe(remote, force=True)
    if p.get("state") == "unreadable":
        return _say(502, _UNREAD)
    if p.get("socket_root") != "ok":
        log_action(current_user, "db_admin_login", target=remote.name, success=False, remote=remote,
                   detail="stored login kept: root can't sign in over the socket")
        return _say(409, "The panel can't sign in as root over the socket on this host, so the stored login was "
                         "kept. Enter a new one to replace it.")
    hd.auth_mode, hd.admin_user, hd.admin_secret = "socket", "", ""
    if p.get("state") == "ready":
        _store_probe(hd, p)
    db.session.commit()
    _dbs.LOGIN_REFUSED.pop(remote.id, None)
    log_action(current_user, "db_admin_login", target=remote.name, detail="stored login cleared", remote=remote)
    return jsonify({"success": True, "message": i18n.tr("Cleared. The panel signs in as root over the socket again.")})


def _admin_login_answer(remote):
    """POST {"user", "password"}: an existing server's admin login, stored only once it is shown to work.

    {"clear": true} instead drops a stored login (_admin_clear_answer).
    """
    data = _json_body()
    if data.get("clear") is True:
        return _admin_clear_answer(remote)
    user, secret = _json_str(data, "user"), data.get("password") if isinstance(data.get("password"), str) else ""
    if not _ADMIN_USER_RE.match(user) or not _ADMIN_PW_RE.match(secret):
        return _say(400, "Enter the database server's admin user and password.")
    p = _probe(remote)
    port = p.get("port") if isinstance(p.get("port"), int) else 3306
    with _r20b_audit_on_raise("db_admin_login", target=remote.name, detail=user, remote=remote):
        verdict, v = _dbs.admin_check(remote, port, user, secret)
    if verdict == "ok":
        hd = _host_row(remote.id) or _new_host_row(remote, p, installed_by_panel=False)
        _store_probe(hd, _dbs.with_login_facts(p, v))    # the version and native logins, read through it
        hd.auth_mode, hd.port, hd.admin_user, hd.admin_secret = "login", port, user, encrypt_secret(secret)
        db.session.commit()
        _dbs.LOGIN_REFUSED.pop(remote.id, None)
    said = {"ok": "Saved. The panel signs in to this database server with that login.",
            "denied": "The database server refused that user and password.",
            "lacks_grants": "That login works but can't create users and grant them rights (it needs CREATE "
                            "USER and GRANT OPTION).",
            "partial_revokes": "That login has the narrow grant, but this MySQL server has partial_revokes on, "
                               "which reads gs% literally, so it can't make the databases. Use a login with "
                               "every privilege WITH GRANT OPTION instead."}.get(verdict, _UNREAD)
    log_action(current_user, "db_admin_login", target=remote.name, detail="%s: %s" % (user, verdict),
               success=verdict == "ok", remote=remote)
    return jsonify({"success": verdict == "ok", "message": i18n.tr(said)}), 200 if verdict == "ok" else 400


def _admin_reveal_answer(remote):
    """POST: the password of the admin account the panel made on a server it installed."""
    hd = _host_row(remote.id)
    secret = decrypt_secret(hd.panel_admin_secret) if hd is not None else ""
    if not secret:
        return _say(404, "The panel has no admin password for this host's database server.")
    log_action(current_user, "db_admin_reveal", target=remote.name,
               detail="revealed the password of linuxgsm_panel_admin", remote=remote)
    return _no_store(jsonify({"success": True, "user": "linuxgsm_panel_admin", "password": secret}))


# ── databases kept after their server was removed from the panel ────────────────────────────────
def _orphans(remote_id):
    return GameDatabase.query.filter_by(remote_id=remote_id, game_server_id=None).order_by(GameDatabase.id).all()


def _orphan_delete_answer(remote, db_id):
    """POST {"confirm": name}: drop a database whose server is gone from the panel."""
    r = next((o for o in _orphans(remote.id) if o.id == db_id), None)
    if r is None:
        return _say(404, _NO_SUCH)
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    local = _host_row(remote.id)
    if _net.admin_target(remote, local, r)[0] is None:
        return _say(409, _NOT_READY)
    name = r.name
    with _r20b_audit_on_raise("db_delete", target=remote.name, detail=name, remote=remote):
        ok, said = drop_row(remote, local, r, None)
    if ok:
        db.session.delete(r)
        db.session.commit()
    log_action(current_user, "db_delete", target=remote.name, detail=_done_or_not(
        ok, "deleted database %s" % name, "database %s not deleted" % name, said), success=bool(ok), remote=remote)
    return jsonify({"success": bool(ok), "message": i18n.tr(
        said or ("Database deleted. A copy is kept on the host for 30 days." if ok else "Failed"))}), \
        200 if ok else 502


# ── hooks into other flows ──────────────────────────────────────────────────────────────────────
def _note(why):
    # "Not every": a dump that failed for one database still saved the others (db-dump goes on).
    return i18n.Sentence("Not every database is in this backup: {why}", why=why)


def dump_for_backup(sid, remote, account):
    """Before a backup: this server's databases dumped into its files (panel-db-dumps/), in one call.

    None when it has none or the dump worked, else a sentence for the backup's outcome. Never
    raises, and never stops the backup. The dump is written as the game account, so a root-capable
    account gets no dump.
    """
    try:
        rows = _server_rows(sid)
        hd = _host_row(rows[0].remote_id) if rows else None
    except Exception:
        return None          # nothing readable to dump; the backup goes on as it always did
    if not rows:
        return None
    # Each database is held for "dump" as the Databases tab's own dump is (one_at_a_time): a restore,
    # delete or other dump of it running now would interleave with this one on the same
    # panel-db-dumps/<name>.sql.gz, and a backup could archive a half-written file. A held one is
    # left out and said; the rest are dumped.
    with contextlib.ExitStack() as stack:
        free, busy = [], []
        for r in rows:
            (free if stack.enter_context(database_claim(r.id, "dump")) is None else busy).append(r)
        why = [i18n.Sentence("{name} is being dumped, restored or deleted right now.", name=r.name) for r in busy]
        try:
            why.append(_dump_rows(remote, account, hd, free) if free else "")
        except Exception:
            why.append(i18n.Sentence("the dump failed ({error}).", error=_log_and_generic("database dump failed")))
    why = [w for w in why if w]
    return _note(why[0] if len(why) == 1 else i18n.Sentences(*why)) if why else None


def _dump_rows(remote, account, hd, rows):
    """Dump `rows` into the game's files as `account`: '' when done, else why not.

    The game host's own databases in one call; each one on another machine in a call of its own,
    signed in as its own account (each has its own password). Every dump is written by the account.
    """
    if hd is None and any(r.endpoint_id is None for r in rows):
        return i18n.Sentence("the host's database server is not set up in the panel.")
    refused = game_account_write_refusal(remote, account)
    if refused is not None:
        return refused
    why = [w for w in (_dump_group(remote, account, target, group) for target, group in _dump_calls(hd, rows)) if w]
    db.session.commit()
    return i18n.Sentences(*why) if why else ""


def _dump_calls(hd, rows):
    """(target, rows) per dump call.

    Root over the socket dumps the host's own databases together; with a stored admin login each is
    dumped alone, signed in as its own account (a narrow login can't read another account's stored
    routines), and so is each one on another machine.
    """
    local = [r for r in rows if r.endpoint_id is None]
    if hd is not None and hd.auth_mode == "login":
        mine = [(_dbs.target_view(hd, login=(r.name, r.secret)), [r]) for r in local]
    else:
        mine = [(hd, local)] if local else []
    return mine + [(_net.game_view(r), [r]) for r in rows if r.endpoint_id is not None]


def own_view(local_hd, r):
    """The target a dump of `r` signs in with as its own account on its game host; None where root's socket can."""
    if r.endpoint_id is not None:
        return _net.game_view(r)
    if local_hd is not None and local_hd.auth_mode == "login":
        return _dbs.target_view(local_hd, login=(r.name, r.secret))
    return None


def drop_row(gs_remote, local_hd, r, account):
    """Delete database `r` where its accounts are made, its archive copy kept first: (ok, sentence).

    With root over the socket the drop keeps the copy itself. Otherwise the copy is dumped on the
    game host by the database's own account (least privilege: an admin login with fewer rights than
    root can't read the stored routines of another account), and the drop is told it was kept.
    """
    remote, target = _net.admin_target(gs_remote, local_hd, r)
    if remote is None:
        return False, i18n.Sentence("no database server")
    own = own_view(local_hd, r)
    if own is not None:
        ok, _said = _dbs.dump(gs_remote, own, "archive", None, [r.name])
        if ok:
            target = _dbs.copy_kept(target)
        # Otherwise (the account signs in from an address the game host no longer has, say) the drop
        # keeps its own copy, signed in where the accounts are made, and deletes only an empty
        # database when that copy fails too: never a database with no copy kept.
    return _dbs.drop(remote, target, account, r.name)


def _dump_group(remote, account, target, group):
    """Dump `group` (databases on one server, signed in to as `target`) into the game's files: '' or why not."""
    if target is None:
        return i18n.Sentence("the database server it is on is no longer set up.")
    ok, said = _dbs.dump(remote, target, "game", account, [r.name for r in group])
    if not ok:
        return said or i18n.Sentence("the dump failed.")
    for r in group:
        r.dumped_at = _now()
    return ""


def with_note(result, note):
    """A backup's (ok, reason, skipped) with `note` said after its reason."""
    if not note or not isinstance(result, tuple) or len(result) != 3:
        return result
    ok, reason, skipped = result
    return ok, i18n.Sentences(reason or (i18n.Sentence("Backed up") if ok else ""), note), skipped


def drop_for_uninstall(remote, server_id):
    """At uninstall: each of the server's databases dropped (a dump kept on the host), its row deleted.

    -> sentences for the uninstall's answer about any that could not be. A database that failed stays,
    listed on its host as one whose server is gone. Never raises.
    """
    notes = []
    try:
        rows = _server_rows(server_id)
        hd = _host_row(remote.id) if rows else None
    except Exception:
        return notes
    for r in rows:
        name = r.name
        try:
            ok, said = drop_row(remote, hd, r, None)
        except Exception:
            ok, said = False, _log_and_generic("database drop failed")
        if ok:
            db.session.delete(r)
            db.session.commit()
        else:
            notes.append(i18n.Sentence("Database {name} was not deleted ({why}); it is listed on the host's "
                                       "page.", name=name, why=said or i18n.Sentence("no database server")))
    return notes


def orphan_rows(server_id):
    """A server's database rows kept with no server: it was removed from the panel, not its databases."""
    try:
        GameDatabase.query.filter_by(game_server_id=server_id).update({"game_server_id": None})
        db.session.commit()
    except Exception:
        db.session.rollback()
        _log_and_generic("orphaning database rows failed")


def forget_remote(remote_id):
    """A deleted host's database rows, removed in the caller's transaction (its id goes to the next host).

    Also the server on it other hosts' databases went to: those rows go with it (the databases stay
    on that machine), and so does each host's choice of it.
    """
    for ep in _net.DatabaseEndpoint.query.filter_by(kind="managed", remote_id=remote_id).all():
        GameDatabase.query.filter_by(endpoint_id=ep.id).delete()
        _net.EndpointClient.query.filter_by(endpoint_id=ep.id).delete()
        db.session.delete(ep)
    _net.EndpointClient.query.filter_by(remote_id=remote_id).delete()
    GameDatabase.query.filter_by(remote_id=remote_id).delete()
    HostDatabaseServer.query.filter_by(remote_id=remote_id).delete()
    _PROBES.pop(remote_id, None)
    _dbs.LOGIN_REFUSED.pop(remote_id, None)


# ── routes ──────────────────────────────────────────────────────────────────────────────────────
def _failed(exc, what):
    """The answer for a route whose work raised: a host that did not answer, or a logged fault."""
    if isinstance(exc, ConnectionError):
        return _unreachable("reach the database server")
    return _say(500, _log_and_generic("database %s failed" % what))


def _row_route(server_id, db_id):
    """(server, its database `db_id` or None) for a database route."""
    gs = get_game(server_id)
    return gs, _own_row(gs, db_id)


def _list_or_add(server_id):
    """GET: the server's databases and the host's database server; POST: a new database (permission checked by the route)."""
    gs = get_game(server_id)
    try:
        if request.method == "GET":
            return _names_answer(gs) if request.args.get("names") else _list_answer(gs)
        return _add_answer(gs)
    except Exception as exc:
        return _failed(exc, "list" if request.method == "GET" else "create")


def _row_action(server_id, db_id, answer, what):
    """One change to one of the server's own databases (the route has checked MANAGE_DATABASES): `answer(gs, row)`."""
    gs, r = _row_route(server_id, db_id)
    if r is None:
        return _say(404, _NO_SUCH)
    try:
        return answer(gs, r)
    except Exception as exc:
        return _failed(exc, what)


def _server_routes(app):
    @app.route("/api/server/<int:server_id>/databases", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_databases(server_id):
        """Return the server's databases and the host's database server (GET), or add one (POST)."""
        need = VIEW_SERVERS if request.method == "GET" else MANAGE_DATABASES
        if not (has_permission(current_user, need) or has_permission(current_user, MANAGE_DATABASES)):
            return _say(403, _DENIED)
        return _list_or_add(server_id)

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/reveal", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_reveal(server_id, db_id):
        """The database's password, for the viewer's screen or clipboard (audited, not stored)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _row_action(server_id, db_id, _reveal_answer, "reveal")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/reset-password", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_reset(server_id, db_id):
        """A new password for the database's user."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        if step_up_needed():
            return step_up_refusal()
        return _row_action(server_id, db_id, _reset_answer, "password reset")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/delete", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_delete(server_id, db_id):
        """Delete the database and its user, a dump kept on the host first."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        if step_up_needed():
            return step_up_refusal()
        return _row_action(server_id, db_id, _delete_answer, "delete")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/restore", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_restore(server_id, db_id):
        """Load the database from the dump in the server's files (panel-db-dumps/<name>.sql.gz)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        if step_up_needed():
            return step_up_refusal()
        return _row_action(server_id, db_id, _restore_answer, "restore")


def _move_route(app):
    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/move", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_move(server_id, db_id):
        """Move the database's account to the address its game host reaches the server from now."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _row_action(server_id, db_id, _move_answer, "move")


def _remote_routes(app):
    @app.route("/api/remote/<int:remote_id>/databases/setup", methods=["POST"])
    @login_required
    def api_remote_databases_setup(remote_id):
        """Install MariaDB on this host, listening on this machine only (in the background)."""
        if not (has_permission(current_user, MANAGE_DATABASES) and has_permission(current_user, MANAGE_REMOTES)):
            return _say(403, _DENIED)
        if step_up_needed():          # a root install on the host: the password again past the window
            return step_up_refusal()
        return _setup_answer(app, get_host_remote(remote_id))

    @app.route("/api/remote/<int:remote_id>/databases/admin-login", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required
    def api_remote_databases_admin_login(remote_id):
        """An existing database server's admin login, checked and then stored encrypted (or cleared)."""
        remote = get_remote(remote_id)
        try:
            return _admin_login_answer(remote)
        except Exception as exc:
            return _failed(exc, "admin login")

    @app.route("/api/remote/<int:remote_id>/databases/admin-reveal", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required
    def api_remote_databases_admin_reveal(remote_id):
        """The password of the admin account the panel made on a database server it installed."""
        return _admin_reveal_answer(get_remote(remote_id))

    @app.route("/api/remote/<int:remote_id>/databases")
    @login_required
    def api_remote_databases(remote_id):
        """Return the host's databases whose game server was removed from the panel."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        remote = get_remote(remote_id)
        return jsonify({"databases": [{"id": r.id, "name": r.name, "size": r.size_bytes,
                                       "created_at": _iso(r.created_at)} for r in _orphans(remote.id)]})

    @app.route("/api/remote/<int:remote_id>/databases/<int:db_id>/delete", methods=["POST"])
    @login_required
    def api_remote_database_delete(remote_id, db_id):
        """Delete a database whose game server was removed from the panel (a dump is kept first)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        if step_up_needed():          # a delete, as the per-server one asks: the password again past the window
            return step_up_refusal()
        remote = get_remote(remote_id)
        try:
            return _orphan_delete_answer(remote, db_id)
        except Exception as exc:
            return _failed(exc, "delete")


def register(app):
    """The Databases tab's routes, the manager's (browse, edit, SQL, dumps), and the template's `db_tab()`."""
    from panel.routes import databases_data, databases_files
    app.jinja_env.globals["db_tab"] = tab_access
    _server_routes(app)
    _move_route(app)
    _remote_routes(app)
    _net.register(app)
    addons.register(app)          # the Add-ons card: its add-ons each use one of these databases
    databases_data.register(app)
    databases_files.register(app)
