"""A website's databases: the Databases tab's own code, for databases named ws<site id>_<name>.

MANAGE_WEBSITE on the site (site_for, 404 otherwise) lists, adds, reveals and resets the site's
databases; deleting one is MANAGE_WEBSITES. A site's database is a GameDatabase row with website_id
set and game_server_id NULL, made on the site's host by the same verbs as a game server's
(ssh_manager.databases.create, set_password, dump, restore, drop), with its own account and a
generated password stored encrypted (encrypt_secret; OWASP Secrets Management Cheat Sheet, "2.7.1
Creation", "Encryption"; Password Storage is not the question here, as the panel must hand the
password to the site). The password leaves the panel only through the reveal route: POST, no-store,
audited, never in a list, an audit row or a log line (OWASP Logging Cheat Sheet, "Data to exclude").
The name prefix ws<id>_ is what the host helper's database allow-list accepts for a site.
"""
from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import decrypt_secret, encrypt_secret, load_config
from panel.db.models import GameDatabase, db
from panel.ops.ssh_manager import databases as _dbs
from panel.routes import databases as _d
from panel.routes import websites as _w
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.security.auth import MANAGE_WEBSITE, MANAGE_WEBSITES
from panel.services import websites_access as _wa

S_CAP = "This website already has {n} databases, the most it may have."
S_EXISTS = "This website already has a database with that name."
S_NO_SUCH = "No such database on this website."


def _cap():
    """How many databases one website may have (config.json websites_db_max, 1-20)."""
    return _d._cfg_int(load_config().get("websites_db_max"), 3, 1, 20)


def site_rows(site):
    """The site's database rows, oldest first."""
    return GameDatabase.query.filter_by(website_id=site.id, remote_id=site.remote_id).order_by(GameDatabase.id).all()


def _row(site, db_id):
    r = db.session.get(GameDatabase, db_id)
    return r if r is not None and r.website_id == site.id and r.remote_id == site.remote_id else None


def row_json(site, r, hd):
    """A database as the site's Database tab shows it: never its password."""
    return {"id": r.id, "name": r.name, "user": r.name, "host": "127.0.0.1",
            "port": int(getattr(hd, "port", None) or 3306), "created_by": r.created_by or "",
            "website": site.name}


def create_for(site, slug):
    """Make database ws<id>_<slug> for `site`: (ok, sentence, row or None, password or "")."""
    name = _dbs.site_db_name(site.id, slug)
    if len(site_rows(site)) >= _cap():
        return False, i18n.Sentence(S_CAP, n=_cap()), None, ""
    if GameDatabase.query.filter_by(remote_id=site.remote_id, name=name).first() is not None:
        return False, S_EXISTS, None, ""
    state, hd, _p = _d.host_state(site.remote, may_probe=True)
    if state != "ready":
        return False, _d._NOT_READY if state != "unreadable" else _d._UNREAD, None, ""
    secret, maxconn = _dbs.new_password(), _d._maxconn()
    ok, said = _dbs.create(site.remote, hd, name, secret, maxconn)
    if not ok:
        return False, said, None, ""
    row = GameDatabase(remote_id=site.remote_id, game_server_id=None, website_id=site.id, name=name,
                       secret=encrypt_secret(secret), auth_plugin=_dbs.auth_plugin_name(_dbs.plugin_for(hd)),
                       max_conn=maxconn, created_by=(getattr(current_user, "username", "") or "panel")[:80])
    db.session.add(row)
    db.session.commit()
    return True, said, row, secret


def drop(site, r):
    """Delete database `r` of `site` on its host (an archive copy kept first) and its row: (ok, sentence)."""
    hd = _d._host_row(site.remote_id)
    ok, said = _d.drop_row(site.remote, hd, r, site.account)
    if ok:
        db.session.delete(r)
        db.session.commit()
    return ok, said


def dump_for_backup(site):
    """Dump the site's databases into its ~/panel-db-dumps before a backup: (ok, sentence)."""
    rows = site_rows(site)
    if not rows:
        return True, ""
    why = _d._dump_rows(site.remote, site.account, _d._host_row(site.remote_id), rows)
    return (False, why) if why else (True, "")


def restore_after_backup(site):
    """Load each of the site's databases from its dump in ~/panel-db-dumps: (ok, sentence)."""
    hd = _d._host_row(site.remote_id)
    for r in site_rows(site):
        ok, said = _dbs.restore(site.remote, hd, site.account, r.name, decrypt_secret(r.secret))
        if ok is False:
            return False, said
    return True, "Backup restored."


def _reveal(site, r):
    secret = decrypt_secret(r.secret)
    if not secret:
        return _w.say(500, "The stored password can't be read on this panel.")
    _w.audit(site, "website_db_reveal", "revealed the password of database %s" % r.name)
    return _d._no_store(jsonify({"success": True, "password": secret}))


def _reset(site, r):
    remote, hd = site.remote, _d._host_row(site.remote_id)
    if hd is None:
        return _w.say(409, _d._NOT_READY)
    secret = _dbs.new_password()
    ok, said = _dbs.set_password(remote, hd, r.name, secret)
    if ok:
        r.secret = encrypt_secret(secret)
        db.session.commit()
    return _w.acted(site, "website_db_password", ok, said, "new password for database %s" % r.name)


def register(app):
    """The site database routes."""
    @app.route("/websites/<int:site_id>/databases")
    @login_required
    def website_databases(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        hd = _d._host_row(site.remote_id)
        return jsonify({"databases": [row_json(site, r, hd) for r in site_rows(site)], "max": _cap(),
                        "prefix": "ws%d_" % site.id})

    @app.route("/websites/<int:site_id>/databases/add", methods=["POST"])
    @login_required
    def website_database_add(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        slug = _w.field(_w.body(), "name").lower()
        try:
            _dbs.site_db_name(site.id, slug)
        except ValueError:
            return _w.say(400, "A name is 1 to 16 lower-case letters and digits.")
        ok, said, row, _secret = create_for(site, slug)
        name = _dbs.site_db_name(site.id, slug)
        _w.audit(site, "website_db_create", "created database %s" % name if ok else "database %s not created: %s"
                 % (name, i18n.tr(said)), ok)
        return _w.done(ok, said or "Database added.", id=row.id if row else None)

    @app.route("/websites/<int:site_id>/databases/<int:db_id>/reveal", methods=["POST"])
    @login_required
    def website_database_reveal(site_id, db_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        r = _row(site, db_id)
        return _reveal(site, r) if r is not None else _w.say(404, S_NO_SUCH)

    @app.route("/websites/<int:site_id>/databases/<int:db_id>/reset-password", methods=["POST"])
    @login_required
    def website_database_reset(site_id, db_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        r = _row(site, db_id)
        if r is None:
            return _w.say(404, S_NO_SUCH)
        return step_up_refusal() if step_up_needed() else _reset(site, r)

    @app.route("/websites/<int:site_id>/databases/<int:db_id>/delete", methods=["POST"])
    @login_required
    def website_database_delete(site_id, db_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        r = _row(site, db_id)
        if r is None:
            return _w.say(404, S_NO_SUCH)
        if _w.field(_w.body(), "confirm") != r.name:
            return _w.say(400, "Type the database's name to confirm.")
        if step_up_needed():
            return step_up_refusal()
        name = r.name
        ok, said = drop(site, r)
        return _w.acted(site, "website_db_delete", ok, said, "deleted database %s" % name)
