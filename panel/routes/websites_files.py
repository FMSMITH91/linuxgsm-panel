"""A website's file manager: list, read, download, upload, save, new folder, rename, delete, unpack an archive.

EDIT_WEBSITE_FILES on the site (site_for, 404 otherwise): changing a PHP site's files runs code as
that site, which is why it is its own permission. Every operation runs as the site's account (never
root, never the panel's) through the game servers' file primitives held to the document root
(ssh_manager/files.confined_to): a path outside it by its text or by where it resolves on the host is
refused, sign-in paths are refused, names follow the same rules (OWASP File Upload Cheat Sheet,
"Filename Safety", "User Permissions", "Filesystem Permissions"). Before any of it the account is
asked whether it can become root (routes/_shared.game_account_write_refusal), as for a game server.

Uploads are an allow-list of OPERATIONS, not of file types: PHP files are what a PHP site is made of,
and what they can do is confined by the site's container. Every write is counted against the site's
disk limit first (an upload or an archive larger than what is left is refused), and the request size
is capped by the panel's own upload limit (OWASP File Upload Cheat Sheet, "Upload and Download
Limits"). Archives are checked and repacked by services/website_files before the host sees them.
Audit rows name the path, never the contents (OWASP Logging Cheat Sheet, "Data to exclude").
"""
from flask import Response, jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.validation import _attachment_header
from panel.ops.ssh_manager import files as _files
from panel.routes import websites as _w
from panel.routes._shared import game_account_write_refusal
from panel.security.auth import EDIT_WEBSITE_FILES
from panel.services import website_files as _wf
from panel.services import websites_access as _wa

S_BAD_PATH = "That path is not inside this website's files."
S_NO_FILE = "Choose a file to upload."
S_TOO_LARGE = "The file is larger than the {mb} MB this website has free."
_EDITABLE_MAX = 1024 * 1024         # what the editor opens (files.read_file's own limit)


def _account_refusal(site, reading=False):
    why = game_account_write_refusal(site.remote, site.account, reading=reading)
    return _w.say(409, why) if why else None


def _rel(text):
    """The page's path as a home-relative path inside the document root, or None."""
    return _wf.docroot_rel(text if isinstance(text, str) else "")


def _upload_bytes(fs, room):
    """The uploaded file's bytes, or (None, refusal) when it is larger than `room`."""
    data = fs.stream.read(room + 1)
    if len(data) > room:
        return None, _w.say(413, i18n.Sentence(S_TOO_LARGE, mb=room // _wf.MIB))
    return data, None


def _write_answer(site, action, ok, said, detail):
    _w.audit(site, action, detail if ok else "%s: %s" % (detail, i18n.tr(said)), ok)
    return _w.done(ok, said)


def _read_routes(app):
    @app.route("/websites/<int:site_id>/files/list")
    @login_required
    def website_files_list(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel = _rel(request.args.get("path", ""))
        refused = _account_refusal(site, reading=True) if rel else _w.say(400, S_BAD_PATH)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            got = _files.browse_dir(site.remote, site.account, rel)
        if got is None or got.get("outside_home"):
            return _w.say(400, S_BAD_PATH)
        entries = [{"name": e["name"], "dir": e["is_dir"], "size": e["size"],
                    "editable": not e["is_dir"] and e["size"] <= _EDITABLE_MAX} for e in got.get("entries", [])]
        return jsonify({"success": True, "path": _wf.page_rel(rel), "entries": entries,
                        "unreadable": bool(got.get("unreadable"))})

    @app.route("/websites/<int:site_id>/files/read")
    @login_required
    def website_files_read(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel = _rel(request.args.get("path", ""))
        refused = _account_refusal(site, reading=True) if rel else _w.say(400, S_BAD_PATH)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            content, err = _files.read_file(site.remote, site.account, rel)
        if content is None:
            return _w.say(400, err or S_BAD_PATH)
        return jsonify({"success": True, "path": _wf.page_rel(rel), "content": content})

    @app.route("/websites/<int:site_id>/files/download")
    @login_required
    def website_files_download(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel = _rel(request.args.get("path", ""))
        refused = _account_refusal(site, reading=True) if rel and rel != _wf.DOCROOT else _w.say(400, S_BAD_PATH)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            info = _files.stat_path(site.remote, site.account, rel)
        if not info:
            return _w.say(404, "That file is not there, or the host did not answer.")
        is_dir = info["type"] == "d"
        _w.audit(site, "website_files_download", _wf.page_rel(rel) + (" (as .tar.gz)" if is_dir else ""))
        resp = Response(_files.stream_path(site.remote, site.account, info["rel"], as_tar=is_dir,
                                           limit=None if is_dir else info["size"]),
                        mimetype="application/gzip" if is_dir else "application/octet-stream")
        if not is_dir:
            resp.headers["Content-Length"] = str(info["size"])
        resp.headers["Content-Disposition"] = _attachment_header(info["name"] + (".tar.gz" if is_dir else ""))
        return resp


def _write_routes(app):
    @app.route("/websites/<int:site_id>/files/upload", methods=["POST"])
    @login_required
    def website_files_upload(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel, fs = _rel(request.form.get("path", "")), request.files.get("file")
        refused = (_w.say(400, S_BAD_PATH) if not rel else _w.say(400, S_NO_FILE) if fs is None or not fs.filename
                   else _account_refusal(site))
        if refused:
            return refused
        room, why = _wf.room_bytes(site.remote, site)
        if why:
            return _w.say(507, why)
        data, refused = _upload_bytes(fs, room)
        if refused:
            return refused
        overwrite = _w.flag(request.form, "overwrite")
        with _files.confined_to(_wf.DOCROOT):
            ok, said = _files.upload_file(site.remote, site.account, rel, fs.filename, data, overwrite=overwrite)
        if said == _files.UPLOAD_EXISTS:
            return _w.say(409, "A file with that name is already there.", exists=True)
        return _write_answer(site, "website_files_upload", ok, said, "%s/%s (%d bytes)" % (_wf.page_rel(rel), fs.filename, len(data)))

    @app.route("/websites/<int:site_id>/files/save", methods=["POST"])
    @login_required
    def website_files_save(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        data = _w.body()
        rel, content = _rel(_w.field(data, "path")), data.get("content")
        refused = (_w.say(400, S_BAD_PATH) if not rel or rel == _wf.DOCROOT or not isinstance(content, str)
                   else _account_refusal(site))
        if refused:
            return refused
        room, why = _wf.room_bytes(site.remote, site)
        if why or len(content.encode("utf-8", "surrogatepass")) > room:
            return _w.say(507, why or i18n.Sentence(S_TOO_LARGE, mb=room // _wf.MIB))
        with _files.confined_to(_wf.DOCROOT):
            ok, said = _files.write_file(site.remote, site.account, rel, content)
        return _write_answer(site, "website_files_save", ok, said, _wf.page_rel(rel))


def _path_routes(app):
    @app.route("/websites/<int:site_id>/files/mkdir", methods=["POST"])
    @login_required
    def website_files_mkdir(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        data = _w.body()
        rel, name = _rel(_w.field(data, "path")), _w.field(data, "name")
        refused = _w.say(400, S_BAD_PATH) if not rel else _account_refusal(site)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            ok, said = _files.create_path(site.remote, site.account, rel, name, "folder")
        return _write_answer(site, "website_files_mkdir", ok, said, "%s/%s" % (_wf.page_rel(rel), name))

    @app.route("/websites/<int:site_id>/files/rename", methods=["POST"])
    @login_required
    def website_files_rename(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        data = _w.body()
        rel, name = _rel(_w.field(data, "path")), _w.field(data, "new_name") or _w.field(data, "name")
        refused = _w.say(400, S_BAD_PATH) if not rel or rel == _wf.DOCROOT else _account_refusal(site)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            ok, said = _files.rename_path(site.remote, site.account, rel, name)
        return _write_answer(site, "website_files_rename", ok, said, "%s -> %s" % (_wf.page_rel(rel), name))

    @app.route("/websites/<int:site_id>/files/delete", methods=["POST"])
    @login_required
    def website_files_delete(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel = _rel(_w.field(_w.body(), "path"))
        refused = _w.say(400, S_BAD_PATH) if not rel or rel == _wf.DOCROOT else _account_refusal(site)
        if refused:
            return refused
        with _files.confined_to(_wf.DOCROOT):
            ok, said = _files.delete_path(site.remote, site.account, rel)
        return _write_answer(site, "website_files_delete", ok, said, _wf.page_rel(rel))


def _extract_routes(app):
    @app.route("/websites/<int:site_id>/files/extract", methods=["POST"])
    @login_required
    def website_files_extract(site_id):
        site = _wa.site_for(current_user, site_id, EDIT_WEBSITE_FILES)
        rel, fs = _rel(request.form.get("path", "")), request.files.get("archive") or request.files.get("file")
        refused = (_w.say(400, S_BAD_PATH) if not rel else _w.say(400, S_NO_FILE) if fs is None or not fs.filename
                   else _account_refusal(site))
        if refused:
            return refused
        return _extract(site, rel, fs)


def _extract(site, rel, fs):
    """Check, repack and unpack the uploaded archive `fs` into `rel`, counted against the site's free disk."""
    room, why = _wf.room_bytes(site.remote, site)
    if why:
        return _w.say(507, why)
    detail = "%s into %s" % (fs.filename, _wf.page_rel(rel) or "/")
    try:
        clean, size = _wf.repack(fs.stream, room)
    except _wf.ArchiveRefused as exc:
        # Only the refusal's own sentence is shown, never an exception's text (OWASP Error Handling).
        _w.audit(site, "website_files_extract", "refused %s: %s" % (detail, exc.sentence), False)
        return _w.say(422, exc.sentence)
    with clean, _files.confined_to(_wf.DOCROOT):
        ok, said = _wf.extract(site.remote, site.account, rel, clean)
    return _write_answer(site, "website_files_extract", ok, said, "%s (%d bytes unpacked)" % (detail, size))


def register(app):
    """The file manager routes."""
    _read_routes(app)
    _write_routes(app)
    _path_routes(app)
    _extract_routes(app)
