"""The Databases tab: MariaDB / MySQL databases for a game server's plugins.

A game's plugins (LuckPerms, CoreProtect, SourceBans++, oxmysql...) keep their data in a database on
the server's own host. The tab adds one with a single name, shows its host, port, name, user and
password with a copy button each and a ready-to-paste config for the game's plugins
(services/db_snippets), resets its password, restores it from the dump a backup put in the game's
files, and deletes it (an archive dump first). The first database on a host with no database server
offers one click to install MariaDB from Ubuntu, listening on this machine only; a server that is
already there is used as it is and never reconfigured. Everything on the host goes through
ssh_manager.databases, imported when first used.

PERMISSION. Seeing the list (no passwords) takes the server's view permission (VIEW_SERVERS) and
access to the server; every change and every password takes MANAGE_DATABASES too. Installing MariaDB
is a host-level root action: MANAGE_DATABASES and MANAGE_REMOTES (or superadmin), through
get_host_remote. A server's own admin login, and the password of the account the panel made on a
server it installed, are superadmin only. Passwords leave the panel only through the reveal routes
(POST, no-store, audited); never in a list, an audit row or a log line.

ROWS. GameDatabase (one per database; game_server_id None once its server was removed from the panel
and the database kept) and HostDatabaseServer (one per host the panel signs in to), in
panel/db/models.py. This build reads them by name from that module (_tables), so a build without
them answers as a host with no databases.
"""
import importlib
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
from panel.db import models as _models
from panel.db.models import RemoteServer, claim_row, db, row_birth
from panel.routes._shared import _r20b_audit_on_raise, _r42r_audit_after, game_account_write_refusal
from panel.security import auth as _auth
from panel.security.auth import (MANAGE_REMOTES, VIEW_SERVERS, get_game, get_host_remote, get_remote,
                                 has_permission, log_action, server_access_required, superadmin_required)
from panel.services import db_snippets as _snip

# The permission (security/auth.py). Read off the module so this file and the tables can land apart.
MANAGE_DATABASES = getattr(_auth, "MANAGE_DATABASES", "manage_databases")

_SLUG_RE = re.compile(r"[a-z0-9]{1,16}\Z")
_ADMIN_USER_RE = re.compile(r"[A-Za-z0-9_.@-]{1,32}\Z")
_ADMIN_PW_RE = re.compile(r"[\x20-\x7e]{1,128}\Z")
PW_MARK = "•" * 8          # what a snippet shows where the password goes, until it is revealed
_PROBE_FRESH = 600              # a host's probe is reused for 10 minutes
_SIZE_FRESH = 60                # sizes are asked of the host at most once a minute
_PLUGIN_NAME = {"native": "mysql_native_password", "sha2": "caching_sha2_password"}

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


def _svc():
    """The host side (panel/ops/ssh_manager/databases.py)."""
    return importlib.import_module("panel.ops.ssh_manager.databases")


def _tables():
    """(GameDatabase, HostDatabaseServer), or None on a build without the tables."""
    gd = getattr(_models, "GameDatabase", None)
    hd = getattr(_models, "HostDatabaseServer", None)
    return None if gd is None or hd is None else (gd, hd)


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
    t = _tables()
    return None if t is None else t[1].query.filter_by(remote_id=remote_id).first()


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
    p = _svc().probe(remote)
    p = p if isinstance(p, dict) else {"state": "unreadable"}
    # A host that did not answer is asked again next time, not reported down for ten minutes.
    if p.get("state") == "unreadable":
        _PROBES.pop(remote.id, None)
    else:
        _PROBES[remote.id] = (time.monotonic(), p)
    return p


def _new_host_row(remote, p, **fields):
    t = _tables()
    hd = t[1](remote_id=remote.id, flavor=p.get("flavor") or "mariadb", **fields)
    _store_probe(hd, p)
    db.session.add(hd)
    return hd


def _recheck(remote, hd):
    """A row older than 10 minutes, probed again: the state it is in now."""
    p = _probe(remote, force=True)
    state = p.get("state")
    if state == "needs_login" and hd.auth_mode == "login":
        state = "ready"          # the socket is refused, and the panel signs in with the stored login
    if state == "ready":
        _store_probe(hd, p)
        db.session.commit()
    return state or "unreadable"


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
    return {"flavor": hd.flavor, "version": hd.version or "", "port": hd.port or 3306,
            "installed_by_panel": bool(hd.installed_by_panel), "login": hd.auth_mode == "login",
            "warnings": _warnings(hd)}


# ── the databases ───────────────────────────────────────────────────────────────────────────────
def _server_rows(server_id):
    t = _tables()
    if t is None:
        return []
    return t[0].query.filter_by(game_server_id=server_id).order_by(t[0].id).all()


def _fresh(when, seconds):
    """Whether `when` (a naive UTC time, or None) is less than `seconds` ago."""
    return bool(when) and (_now() - when).total_seconds() < seconds


def _refresh_sizes(remote, hd, rows):
    """Ask the host for the sizes of `rows` when any is older than a minute (one call for all)."""
    now = _now()
    if hd is None or all(_fresh(r.size_at, _SIZE_FRESH) for r in rows):
        return
    try:
        got = _svc().sizes(remote, hd, [r.name for r in rows])
    except Exception:
        got = None
    if not isinstance(got, dict):
        return
    for r in rows:
        if isinstance(got.get(r.name), int):
            r.size_bytes, r.size_at = got[r.name], now
    db.session.commit()


def _iso(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat() if dt else None


def _row_json(gs, hd, r):
    port = (hd.port if hd is not None else None) or 3306
    flavor = hd.flavor if hd is not None else "mariadb"
    return {"id": r.id, "name": r.name, "user": r.name, "host": _snip.HOST, "port": port,
            "size": r.size_bytes, "dumped_at": _iso(r.dumped_at),
            "old_logins": r.auth_plugin == _PLUGIN_NAME["sha2"],
            "snippets": [{"kind": k, "label": label, "text": text} for k, label, text
                         in _snip.render_all(gs.game_type, flavor, port, r.name, PW_MARK)]}


def _list_answer(gs):
    """GET: the host's state and this server's databases (never a password)."""
    manage = _can_manage()
    state, hd, p = host_state(gs.remote, may_probe=_probe_mode(manage))
    rows = _server_rows(gs.id)
    _refresh_sizes(gs.remote, hd, rows)
    taken = [r.name.split("_", 1)[1] for r in rows if "_" in r.name]
    setup = _SETUP.get(gs.remote_id) or {}
    return jsonify({
        "state": state, "remote_id": gs.remote_id, "host": _host_info(hd),
        "probe_warnings": [w for w in (p.get("warnings") or []) if isinstance(w, str)],
        "setup_error": i18n.tr(setup["why"]) if setup.get("why") else "",
        "can": {"manage": manage, "setup": _can_setup(), "su": bool(current_user.is_superadmin)},
        "prefix": "gs%d_" % gs.id, "suggest": _snip.suggest_slug(gs.game_type, taken),
        "cap": _cap(), "used": len(rows), "pw_mark": PW_MARK,
        "databases": [_row_json(gs, hd, r) for r in rows]})


def _names_answer(gs):
    """GET ?names=1: only this server's database names, for the uninstall dialog (nothing asked of the host)."""
    return jsonify({"names": [r.name for r in _server_rows(gs.id)]})


def _add_refusal(gs, slug, rows):
    """Why a new database `slug` can't be added to `gs` now (status, sentence), or None."""
    if not _SLUG_RE.match(slug):
        return 400, i18n.Sentence("A name is 1 to 16 lower-case letters and digits.")
    if len(rows) >= _cap():
        return 409, i18n.Sentence("This server already has {n} databases, the most it may have.", n=len(rows))
    t = _tables()
    if t[0].query.filter_by(remote_id=gs.remote_id, name="gs%d_%s" % (gs.id, slug)).first() is not None:
        return 409, i18n.Sentence("This server already has a database with that name.")
    return None


def _add_answer(gs):
    """POST {"name"}: a new database and its own user, with a new password."""
    slug = _json_str(_json_body(), "name").lower()
    if _tables() is None:
        return _say(409, _NOT_READY)
    refused = _add_refusal(gs, slug, _server_rows(gs.id))
    if refused:
        return _say(*refused)
    state, hd, _p = host_state(gs.remote, may_probe=True)
    if state != "ready":
        return _say(409, _NOT_READY if state != "unreadable" else _UNREAD, state=state)
    svc = _svc()
    name, secret = svc.db_name(gs.id, slug), svc.new_password()
    plugin, maxconn = svc.plugin_for(hd), _maxconn()
    with _r20b_audit_on_raise("db_create", target=gs.name, detail=name, server=gs):
        ok, said = svc.create(gs.remote, hd, name, secret, maxconn)
    if ok:
        db.session.add(_tables()[0](remote_id=gs.remote_id, game_server_id=gs.id, name=name,
                                    secret=encrypt_secret(secret), auth_plugin=_PLUGIN_NAME.get(plugin, plugin),
                                    max_conn=maxconn, created_by=current_user.username[:80]))
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(said or ("Database added." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_create", target=gs.name, detail="created database %s" % name
                   if ok else "database %s not created: %s" % (name, said), success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _own_row(gs, db_id):
    """This server's database `db_id`, or None (another server's is None too)."""
    t = _tables()
    r = db.session.get(t[0], db_id) if t is not None else None
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


def _reset_answer(gs, r):
    """POST: a new password for the database's user (both of its host entries)."""
    hd = _host_row(gs.remote_id)
    if hd is None:
        return _say(409, _NOT_READY)
    svc = _svc()
    secret = svc.new_password()
    with _r20b_audit_on_raise("db_password", target=gs.name, detail=r.name, server=gs):
        ok, said = svc.set_password(gs.remote, hd, r.name, secret)
    if ok:
        r.secret = encrypt_secret(secret)
        r.auth_plugin = _PLUGIN_NAME.get(svc.plugin_for(hd), r.auth_plugin)
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(
        said or ("New password set. Update it in the game's config, then restart the server." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_password", target=gs.name, detail="new password for database %s" % r.name,
                   success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _confirmed(r):
    return _json_str(_json_body(), "confirm") == r.name


def _delete_answer(gs, r):
    """POST {"confirm": name}: the database and its user dropped (a dump kept on the host first)."""
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    hd = _host_row(gs.remote_id)
    if hd is None:
        return _say(409, _NOT_READY)
    name = r.name
    with _r20b_audit_on_raise("db_delete", target=gs.name, detail=name, server=gs):
        ok, said = _svc().drop(gs.remote, hd, gs.short_name, name)
    if ok:
        db.session.delete(r)
        db.session.commit()
    reply = {"success": bool(ok), "message": i18n.tr(
        said or ("Database deleted. A copy is kept on the host for 30 days." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_delete", target=gs.name, detail="deleted database %s" % name,
                   success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


def _restore_answer(gs, r):
    """POST {"confirm": name}: the database loaded from panel-db-dumps/<name>.sql.gz in the game's files."""
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    hd = _host_row(gs.remote_id)
    if hd is None:
        return _say(409, _NOT_READY)
    # The dump is the game's file and the import runs as the game account.
    refused = game_account_write_refusal(gs.remote, gs.short_name)
    if refused is not None:
        log_action(current_user, "db_restore", target=gs.name, detail="%s (refused: %s)" % (r.name, refused),
                   success=False, server=gs)
        return _say(409, refused)
    with _r20b_audit_on_raise("db_restore", target=gs.name, detail=r.name, server=gs):
        ok, said = _svc().restore(gs.remote, hd, gs.short_name, r.name, decrypt_secret(r.secret))
    reply = {"success": bool(ok), "message": i18n.tr(said or ("Database restored." if ok else "Failed"))}
    with _r42r_audit_after(reply):
        log_action(current_user, "db_restore", target=gs.name, detail="restored database %s from its dump" % r.name,
                   success=bool(ok), server=gs)
    return jsonify(reply), 200 if ok else 502


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
    if (_svc().probe(remote) or {}).get("state") != "none":
        why = i18n.Sentence("A database server is already on this host, so nothing was installed.")
    else:
        why = _install(remote)
    log_action(None, "db_setup", target=remote.name, actor=who, success=not why, remote=remote,
               detail="MariaDB installed" if not why else "not installed: %s" % why)
    return why


def _install(remote):
    """Install MariaDB and record the host's row: '' when it worked, else why not."""
    svc = _svc()
    ok, said, admin_pw = svc.install_mariadb(remote)
    if not ok:
        return said or i18n.Sentence("The install failed.")
    p = svc.probe(remote) or {}
    hd = _host_row(remote.id) or _new_host_row(remote, p)
    _store_probe(hd, p)
    hd.flavor, hd.installed_by_panel, hd.auth_mode = "mariadb", True, "socket"
    hd.panel_admin_secret = encrypt_secret(admin_pw or "")
    db.session.commit()
    return ""


def _setup_answer(app, remote):
    """POST: start installing MariaDB on `remote` in the background (202); the tab's GET says how it went."""
    if _tables() is None:
        return _say(409, _NOT_READY)
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


def _admin_login_answer(remote):
    """POST {"user", "password"}: an existing server's admin login, stored only once it is shown to work."""
    data = _json_body()
    user, secret = _json_str(data, "user"), data.get("password") if isinstance(data.get("password"), str) else ""
    if not _ADMIN_USER_RE.match(user) or not _ADMIN_PW_RE.match(secret) or _tables() is None:
        return _say(400, "Enter the database server's admin user and password.")
    p = _probe(remote)
    port = p.get("port") if isinstance(p.get("port"), int) else 3306
    with _r20b_audit_on_raise("db_admin_login", target=remote.name, detail=user, remote=remote):
        verdict = _svc().check_admin_login(remote, port, user, secret)
    if verdict == "ok":
        hd = _host_row(remote.id) or _new_host_row(remote, p, installed_by_panel=False)
        hd.auth_mode, hd.port, hd.admin_user, hd.admin_secret = "login", port, user, encrypt_secret(secret)
        hd.checked_at = _now()
        db.session.commit()
    said = {"ok": "Saved. The panel signs in to this database server with that login.",
            "denied": "The database server refused that user and password.",
            "lacks_grants": "That login works but can't create users and grant them rights (it needs CREATE "
                            "USER and GRANT OPTION)."}.get(verdict, _UNREAD)
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
    t = _tables()
    if t is None:
        return []
    return t[0].query.filter_by(remote_id=remote_id, game_server_id=None).order_by(t[0].id).all()


def _orphan_delete_answer(remote, db_id):
    """POST {"confirm": name}: drop a database whose server is gone from the panel."""
    r = next((o for o in _orphans(remote.id) if o.id == db_id), None)
    if r is None:
        return _say(404, _NO_SUCH)
    if not _confirmed(r):
        return _say(400, "Type the database's name to confirm.")
    hd = _host_row(remote.id)
    if hd is None:
        return _say(409, _NOT_READY)
    name = r.name
    with _r20b_audit_on_raise("db_delete", target=remote.name, detail=name, remote=remote):
        ok, said = _svc().drop(remote, hd, None, name)
    if ok:
        db.session.delete(r)
        db.session.commit()
    log_action(current_user, "db_delete", target=remote.name, detail="deleted database %s" % name,
               success=bool(ok), remote=remote)
    return jsonify({"success": bool(ok), "message": i18n.tr(
        said or ("Database deleted. A copy is kept on the host for 30 days." if ok else "Failed"))}), \
        200 if ok else 502


# ── hooks into other flows ──────────────────────────────────────────────────────────────────────
def _note(why):
    return i18n.Sentence("Databases were not included: {why}", why=why)


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
    try:
        why = _dump_rows(remote, account, hd, rows)
    except Exception:
        why = i18n.Sentence("the dump failed ({error}).", error=_log_and_generic("database dump failed"))
    return _note(why) if why else None


def _dump_rows(remote, account, hd, rows):
    """Dump `rows` into the game's files as `account`: '' when done, else why not."""
    if hd is None:
        return i18n.Sentence("the host's database server is not set up in the panel.")
    refused = game_account_write_refusal(remote, account)
    if refused is not None:
        return refused
    ok, said = _svc().dump(remote, hd, "game", account, [r.name for r in rows])
    if not ok:
        return said or i18n.Sentence("the dump failed.")
    for r in rows:
        r.dumped_at = _now()
    db.session.commit()
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
            ok, said = _svc().drop(remote, hd, None, name) if hd is not None else (False, "")
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
    t = _tables()
    if t is None:
        return
    try:
        t[0].query.filter_by(game_server_id=server_id).update({"game_server_id": None})
        db.session.commit()
    except Exception:
        db.session.rollback()
        _log_and_generic("orphaning database rows failed")


def forget_remote(remote_id):
    """A deleted host's database rows, removed in the caller's transaction (its id goes to the next host)."""
    t = _tables()
    if t is None:
        return
    t[0].query.filter_by(remote_id=remote_id).delete()
    t[1].query.filter_by(remote_id=remote_id).delete()
    _PROBES.pop(remote_id, None)


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


def _server_routes(app):
    @app.route("/api/server/<int:server_id>/databases", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_databases(server_id):
        """This server's databases and the host's database server (GET), or a new database (POST)."""
        gs = get_game(server_id)
        need = VIEW_SERVERS if request.method == "GET" else MANAGE_DATABASES
        if not (has_permission(current_user, need) or has_permission(current_user, MANAGE_DATABASES)):
            return _say(403, _DENIED)
        try:
            if request.method == "GET":
                return _names_answer(gs) if request.args.get("names") else _list_answer(gs)
            return _add_answer(gs)
        except Exception as exc:
            return _failed(exc, "list" if request.method == "GET" else "create")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/reveal", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_reveal(server_id, db_id):
        """The database's password, for the viewer's screen or clipboard (audited, not stored)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        gs, r = _row_route(server_id, db_id)
        if r is None:
            return _say(404, _NO_SUCH)
        try:
            return _reveal_answer(gs, r)
        except Exception as exc:
            return _failed(exc, "reveal")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/reset-password", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_reset(server_id, db_id):
        """A new password for the database's user."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        gs, r = _row_route(server_id, db_id)
        if r is None:
            return _say(404, _NO_SUCH)
        try:
            return _reset_answer(gs, r)
        except Exception as exc:
            return _failed(exc, "password reset")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/delete", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_delete(server_id, db_id):
        """Delete the database and its user, a dump kept on the host first."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        gs, r = _row_route(server_id, db_id)
        if r is None:
            return _say(404, _NO_SUCH)
        try:
            return _delete_answer(gs, r)
        except Exception as exc:
            return _failed(exc, "delete")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/restore", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_restore(server_id, db_id):
        """Load the database from the dump in the server's files (panel-db-dumps/<name>.sql.gz)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        gs, r = _row_route(server_id, db_id)
        if r is None:
            return _say(404, _NO_SUCH)
        try:
            return _restore_answer(gs, r)
        except Exception as exc:
            return _failed(exc, "restore")


def _remote_routes(app):
    @app.route("/api/remote/<int:remote_id>/databases/setup", methods=["POST"])
    @login_required
    def api_remote_databases_setup(remote_id):
        """Install MariaDB on this host, listening on this machine only (in the background)."""
        if not (has_permission(current_user, MANAGE_DATABASES) and has_permission(current_user, MANAGE_REMOTES)):
            return _say(403, _DENIED)
        return _setup_answer(app, get_host_remote(remote_id))

    @app.route("/api/remote/<int:remote_id>/databases/admin-login", methods=["POST"])
    @login_required
    @superadmin_required
    def api_remote_databases_admin_login(remote_id):
        """An existing database server's admin login, checked and then stored encrypted."""
        remote = get_remote(remote_id)
        try:
            return _admin_login_answer(remote)
        except Exception as exc:
            return _failed(exc, "admin login")

    @app.route("/api/remote/<int:remote_id>/databases/admin-reveal", methods=["POST"])
    @login_required
    @superadmin_required
    def api_remote_databases_admin_reveal(remote_id):
        """The password of the admin account the panel made on a database server it installed."""
        return _admin_reveal_answer(get_remote(remote_id))

    @app.route("/api/remote/<int:remote_id>/databases")
    @login_required
    def api_remote_databases(remote_id):
        """This host's databases whose game server was removed from the panel."""
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
        remote = get_remote(remote_id)
        try:
            return _orphan_delete_answer(remote, db_id)
        except Exception as exc:
            return _failed(exc, "delete")


def register(app):
    """The Databases tab's routes, and the template's `db_tab()`."""
    app.jinja_env.globals["db_tab"] = tab_access
    _server_routes(app)
    _remote_routes(app)
