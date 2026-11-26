"""A website's backups: list, back up now, download, restore, delete.

Taking and deleting backups is MANAGE_WEBSITE; downloading and restoring one is EDIT_WEBSITE_FILES
(a backup is the site's files, and a restore writes them), each through site_for (404 otherwise). The
work is services/website_backup, as the site's account; a backup's databases are dumped first with
the Databases tab's own verb (routes/databases_sites). A backup counts toward the site's disk, so
none is made when the site has no room left. A restore stops the site, takes a safety backup, checks
the archive, unpacks it, restores the databases' dumps, and starts the site again.
"""
from flask import Response, jsonify, request
from flask_login import current_user, login_required
from werkzeug.exceptions import NotFound

from panel.core import i18n
from panel.core.validation import _attachment_header
from panel.ops.ssh_manager import files as _files
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.routes._shared import game_account_write_refusal
from panel.security.auth import EDIT_WEBSITE_FILES, MANAGE_WEBSITE
from panel.services import website_backup as _wb
from panel.services import website_files as _wf
from panel.services import websites_access as _wa


def _refused(site, reading=False):
    why = game_account_write_refusal(site.remote, site.account, reading=reading)
    return _w.say(409, why) if why else None


def _name(data):
    name = _w.field(data, "name")
    return name if _wb.NAME_RE.match(name) else None


def make_backup(site):
    """Dump the site's databases, then back up its files: (ok, sentence, file name)."""
    from panel.routes import databases_sites
    ok, said = databases_sites.dump_for_backup(site)
    if not ok:
        return False, said, ""
    return _wb.create(site.remote, site.account, site.backup_keep)


def _restore(site, name):
    why = _wb.check_archive(site.remote, site.account, name)
    if why:
        sentence = why if why == _wb.S_BAD_NAME else i18n.Sentence(_wb.S_REFUSED, name=repr(why))
        _w.audit(site, "website_restore", "refused %s: %s" % (name, i18n.tr(sentence)), False)
        return _w.say(422, sentence)
    _w.host_call(_sw.stop, site.remote, site)
    ok, said, safety = make_backup(site)
    if not ok:
        _w.host_call(_sw.start, site.remote, site)
        return _w.acted(site, "website_restore", False, said, "no safety backup, nothing restored")
    ok, said = _wb.restore(site.remote, site.account, name)
    if ok:
        from panel.routes import databases_sites
        ok, said = databases_sites.restore_after_backup(site)
    _w.host_call(_sw.start, site.remote, site)
    _w.forget_status(site.id)
    return _w.acted(site, "website_restore", ok, said, "restored %s (safety backup %s)" % (name, safety))


def register(app):
    """The backup routes."""
    @app.route("/websites/<int:site_id>/backups/list")
    @login_required
    def website_backups_list(site_id):
        try:
            site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        except NotFound:
            site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rows = _wb.listing(site.remote, site.account)
        if rows is None:
            return _w.say(502, _w.S_UNREACHABLE)
        return jsonify({"backups": rows, "keep": site.backup_keep})

    @app.route("/websites/<int:site_id>/backups/create", methods=["POST"])
    @login_required
    def website_backups_create(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        refused = _refused(site)
        if refused:
            return refused
        _room, why = _wf.room_bytes(site.remote, site)
        if why:
            return _w.say(507, why)
        ok, said, name = make_backup(site)
        return _w.acted(site, "website_backup", ok, said, "backup %s" % name if ok else "")

    @app.route("/websites/<int:site_id>/backups/download")
    @login_required
    def website_backups_download(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        name = _name(request.args)
        refused = _w.say(404, _wb.S_BAD_NAME) if name is None else _refused(site, reading=True)
        if refused:
            return refused
        rel = "%s/%s" % (_wf.BACKUPS, name)
        info = _files.stat_path(site.remote, site.account, rel)
        if not info or info["type"] != "f":
            return _w.say(404, _wb.S_BAD_NAME)
        _w.audit(site, "website_backup_download", name)
        resp = Response(_files.stream_path(site.remote, site.account, rel, limit=info["size"]),
                        mimetype="application/gzip")
        resp.headers["Content-Length"] = str(info["size"])
        resp.headers["Content-Disposition"] = _attachment_header("%s-%s" % (site.name, name))
        return resp

    @app.route("/websites/<int:site_id>/backups/restore", methods=["POST"])
    @login_required
    def website_backups_restore(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        name = _name(_w.body())
        refused = _w.say(404, _wb.S_BAD_NAME) if name is None else _refused(site)
        return refused or _restore(site, name)

    @app.route("/websites/<int:site_id>/backups/delete", methods=["POST"])
    @login_required
    def website_backups_delete(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        name = _name(_w.body())
        refused = _w.say(404, _wb.S_BAD_NAME) if name is None else _refused(site)
        if refused:
            return refused
        ok, said = _wb.delete(site.remote, site.account, name)
        return _w.acted(site, "website_backup_delete", ok, said, "deleted backup %s" % name)
