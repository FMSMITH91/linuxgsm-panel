"""Uploading a backup archive from the browser: a game server's (to restore it) and the panel's own.

The panel's app-wide request cap (MAX_CONTENT_LENGTH, app.py: 50 MB and its envelope) stays as it
is, and so does the hook that reads a signed-in request's whole body before anything authorizes it
(auth.authorize_after_body): a backup goes up in pieces of UPLOAD_CHUNK bytes, each its own POST of
raw bytes (CSRF in the X-CSRFToken header, as every fetch sends it), held in memory one piece at a
time. Three requests per upload: start (the size, checked against the cap and the free space),
each piece (at the offset the stored part file has reached, so a piece whose answer was lost is
not appended twice), and finish (the whole file checked as a restore checks it, then listed under
a name the panel makes).

A game server's: RESTORE_BACKUP and EDIT_FILES on that server (server_access_required), and a plain game
account (_shared.game_account_write_refusal): an uploaded archive is any content the uploader chose, and
restoring it writes the LinuxGSM script and config that run as the game account. Written as the game account
into its own LinuxGSM backup dir (services/game_restore's upload commands, the transport every
other game-account command takes), and checked by the same member check a restore runs before it
is listed. The panel's: superadmin only, written by the panel into its own backup dir and checked
as backup.restore_backup checks an archive (ops/backup.upload_finish).
"""
import base64
import secrets
import threading
import time

from flask import jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.http import _json_body, _log_and_generic
from panel.db.models import LOCAL_HOST_LABEL
from panel.ops import backup as bk
from panel.ops import ssh_manager as _sm
from panel.core.stdin_chunks import StdinChunks
from panel.routes import _shared
from panel.security.auth import (EDIT_FILES, RESTORE_BACKUP, get_game, has_permission, log_action,
                                 permission_required, server_access_required, superadmin_required)
from panel.services import game_restore as grs

# upload id -> {"kind", "sid", "user", "size", "got", "ts"}. An upload untouched this long is forgotten.
_uploads = {}
_uploads_lock = threading.Lock()
_UPLOAD_IDLE = 2 * 3600
_GAME_PIECE_TIMEOUT = 300
_GAME_FINISH_TIMEOUT = 4 * 3600     # a large archive read to its end (the command prints a heartbeat)


def _bup_new(kind, sid, size):
    """Register a new upload; its id. One upload per server (or for the panel) at a time."""
    now = time.time()
    with _uploads_lock:
        for uid in [u for u, e in _uploads.items() if now - e["ts"] > _UPLOAD_IDLE]:
            _uploads.pop(uid, None)
        if any(e["kind"] == kind and e["sid"] == sid for e in _uploads.values()):
            return None
        uid = secrets.token_hex(16)
        _uploads[uid] = {"kind": kind, "sid": sid, "user": current_user.id, "size": size, "got": 0, "ts": now}
        return uid


def _bup_get(uid, kind, sid):
    """The upload `uid` when it is this user's, of this kind, for this server; else None."""
    with _uploads_lock:
        e = _uploads.get(uid)
        if e is None or e["kind"] != kind or e["sid"] != sid or e["user"] != current_user.id:
            return None
        e["ts"] = time.time()
        return e


def _bup_drop(uid):
    with _uploads_lock:
        _uploads.pop(uid, None)


def _bup_size(limit):
    """The size the start request declares, when it is a whole number from 1 to `limit`; else None."""
    size = _json_body().get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= limit:
        return None
    return size


def _bup_piece(entry, chunk):
    """(offset, bytes) of a piece request that fits its upload, or (None, refusal response)."""
    try:
        offset = int(request.args.get("offset", ""))
    except ValueError:
        offset = -1
    data = request.get_data(cache=True)
    if not data or len(data) > chunk:
        return None, (jsonify({"success": False, "message": i18n.tr("Each piece must be 1 byte to 4 MB.")}), 413)
    if offset < 0 or offset + len(data) > entry["size"]:
        return None, (jsonify({"success": False, "message": i18n.tr("That piece does not fit the upload.")}), 400)
    return offset, data


def _bup_too_big(limit):
    return jsonify({"success": False, "message": i18n.tr(
        "Give the archive's size: a whole number of bytes, at most {limit}.", limit=_sm._fmt_size(limit))}), 400


def _bup_no_edit():
    """The 403 for a game upload without EDIT_FILES (RESTORE_BACKUP is the route's decorator), else None."""
    if current_user.is_superadmin or has_permission(current_user, EDIT_FILES):
        return None
    return jsonify({"success": False, "message": i18n.tr(
        "Uploading a backup also needs the permission to change the server's files.")}), 403


def register(app):
    """The upload routes: four for a game server's backup, four for the panel's (start, piece, finish, cancel)."""
    _register_game(app)
    _register_game_cancel(app)
    _register_panel(app)


def _register_game(app):
    """A game server's backup: start, each piece, finish."""
    @app.route("/api/panel/backup/game/<int:server_id>/upload", methods=["POST"])
    @login_required
    @permission_required(RESTORE_BACKUP)
    @server_access_required
    def api_panel_backup_game_upload(server_id):
        """Start an upload: check the size against the cap and the host's free space, make the part file."""
        gs = get_game(server_id)
        refused = _bup_no_edit()
        if refused is not None:
            return refused
        if not gs.installed or not gs.remote_id:
            return jsonify({"success": False, "message": i18n.tr("Server is not installed.")}), 400
        why = _shared.game_account_write_refusal(gs.remote, gs.short_name)
        if why is not None:
            log_action(current_user, "game_backup_upload", target=gs.name, success=False, server=gs,
                       detail="refused: %s" % why)
            return jsonify({"success": False, "message": i18n.tr(why)}), 409
        size = _bup_size(grs.UPLOAD_MAX)
        if size is None:
            return _bup_too_big(grs.UPLOAD_MAX)
        uid = _bup_new("game", gs.id, size)
        if uid is None:
            return jsonify({"success": False, "message": i18n.tr("An upload to this server is already running.")}), 409
        state, val = _bup_game_run(gs, grs.upload_start_script(gs.short_name, uid, size), 60)
        if state != "ok":
            _bup_drop(uid)
            log_action(current_user, "game_backup_upload", target=gs.name, success=False, server=gs,
                       detail="refused: %s" % val)
            return jsonify({"success": False, "message": i18n.tr(val)}), 200
        return jsonify({"success": True, "id": uid, "chunk": grs.UPLOAD_CHUNK})

    @app.route("/api/panel/backup/game/<int:server_id>/upload/<uid>", methods=["POST"])
    @login_required
    @permission_required(RESTORE_BACKUP)
    @server_access_required
    def api_panel_backup_game_upload_piece(server_id, uid):
        """Append one piece at its offset; answers how much the host holds now."""
        gs = get_game(server_id)
        entry = None if _bup_no_edit() else _bup_get(uid, "game", gs.id)
        if entry is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        offset, data = _bup_piece(entry, grs.UPLOAD_CHUNK)
        if offset is None:
            return data
        state, val = _bup_game_run(gs, grs.upload_chunk_script(gs.short_name, uid, offset), _GAME_PIECE_TIMEOUT,
                                   stdin=_bup_b64_chunks(data))
        if state == "ok" and str(val).isdecimal():
            entry["got"] = int(val)
            return jsonify({"success": True, "received": entry["got"]})
        if state == "offset":
            entry["got"] = val
            return jsonify({"success": False, "received": val, "resume": True}), 409
        return jsonify({"success": False, "message": i18n.tr(val)}), 200

    @app.route("/api/panel/backup/game/<int:server_id>/upload/<uid>/finish", methods=["POST"])
    @login_required
    @permission_required(RESTORE_BACKUP)
    @server_access_required
    def api_panel_backup_game_upload_finish(server_id, uid):
        """Check the whole archive as a restore does and list it under a LinuxGSM backup's name.

        A finish whose answer did not come back keeps the upload, so the page can ask again (the part
        file is still there unless the check refused it).
        """
        gs = get_game(server_id)
        entry = None if _bup_no_edit() else _bup_get(uid, "game", gs.id)
        if entry is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        state, val = _bup_game_run(gs, grs.upload_finish_script(gs.short_name, gs.lgsm_name or gs.short_name, uid,
                                                                entry["size"], time.time()), _GAME_FINISH_TIMEOUT)
        if state == "unread":
            return jsonify({"success": False, "retry": True, "message": i18n.tr(val)}), 200
        _bup_drop(uid)
        ok = state == "ok"
        detail = ("%s (%d bytes)" % (val, entry["size"])) if ok else ("refused: %s" % val)
        log_action(current_user, "game_backup_upload", target=gs.name, success=ok, server=gs, detail=detail[:500])
        if not ok:
            return jsonify({"success": False, "message": i18n.tr(
                "The upload was not kept: {why}.", why=val if state == "refused" else i18n.Sentence(
                    "it is not all on the host"))}), 200
        return jsonify({"success": True, "name": val, "message": i18n.tr(
            "Uploaded as {name}. Restore it from the list.", name=val)})


def _register_game_cancel(app):
    """A game server's upload, cancelled: its part file removed and the upload forgotten."""
    @app.route("/api/panel/backup/game/<int:server_id>/upload/<uid>/cancel", methods=["POST"])
    @login_required
    @permission_required(RESTORE_BACKUP)
    @server_access_required
    def api_panel_backup_game_upload_cancel(server_id, uid):
        """Cancel an upload: its part file (and a staged piece) removed, the upload forgotten."""
        gs = get_game(server_id)
        entry = None if _bup_no_edit() else _bup_get(uid, "game", gs.id)
        if entry is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        _bup_drop(uid)
        state, _val = _bup_game_run(gs, grs.upload_cancel_script(gs.short_name, uid), 60)
        return jsonify({"success": state == "ok"})


_BUP_B64_STEP = 49152      # a multiple of 3, so each slice's base64 joins the next without padding


def _bup_b64_chunks(data):
    """A piece's bytes as base64, 64 KB at a time (the transport writes them as they come)."""
    view = memoryview(data)
    return StdinChunks(base64.b64encode(view[i:i + _BUP_B64_STEP]) for i in range(0, len(view), _BUP_B64_STEP))


def _bup_game_run(gs, script, timeout, stdin=None):
    """One upload command as the game account: (state, value) as services/game_restore.upload_outcome reads it."""
    try:
        cmd = _sm.game_user_cmd(gs.short_name, script)
        out, err, _rc = _sm.run_command(gs.remote, cmd, timeout=timeout, sudo=False,
                                        **({"stdin_text": stdin} if stdin is not None else {}))
    except Exception:
        _log_and_generic("game backup upload command failed")
        return "unread", i18n.Sentence("the host could not be reached")
    return grs.upload_outcome((out or "") + "\n" + (err or ""))


def _register_panel(app):
    """The panel's own backup: start, each piece, finish (superadmin only)."""
    @app.route("/api/panel/backup/upload", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_upload():
        """Start an upload of a panel backup: the size checked, the part file made."""
        size = _bup_size(bk.UPLOAD_MAX)
        if size is None:
            return _bup_too_big(bk.UPLOAD_MAX)
        uid = _bup_new("panel", 0, size)
        if uid is None:
            return jsonify({"success": False, "message": i18n.tr("A panel backup upload is already running.")}), 409
        refusal = bk.upload_begin(uid, size)
        if refusal:
            _bup_drop(uid)
            return jsonify({"success": False, "message": i18n.tr(refusal)}), 200
        return jsonify({"success": True, "id": uid, "chunk": bk.UPLOAD_CHUNK})

    @app.route("/api/panel/backup/upload/<uid>", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_upload_piece(uid):
        """Append one piece at its offset."""
        entry = _bup_get(uid, "panel", 0)
        if entry is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        offset, data = _bup_piece(entry, bk.UPLOAD_CHUNK)
        if offset is None:
            return data
        ok, now = bk.upload_append(uid, offset, data)
        entry["got"] = max(now, 0)
        if ok:
            return jsonify({"success": True, "received": now})
        if now < 0:
            _bup_drop(uid)
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        return jsonify({"success": False, "received": now, "resume": True}), 409

    @app.route("/api/panel/backup/upload/<uid>/cancel", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_upload_cancel(uid):
        """Cancel a panel backup upload: its part file removed, the upload forgotten."""
        if _bup_get(uid, "panel", 0) is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        _bup_drop(uid)
        bk.upload_discard(uid)
        return jsonify({"success": True})

    @app.route("/api/panel/backup/upload/<uid>/finish", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_upload_finish(uid):
        """Check the archive as a restore would and list it under a generated name."""
        entry = _bup_get(uid, "panel", 0)
        if entry is None:
            return jsonify({"success": False, "message": i18n.tr("No such upload.")}), 404
        _bup_drop(uid)
        try:
            ok, res = bk.upload_finish(uid, entry["size"])
        except Exception:
            bk.upload_discard(uid)
            return jsonify({"success": False, "message": _log_and_generic("panel backup upload failed")}), 200
        log_action(current_user, "panel_backup_upload", target=LOCAL_HOST_LABEL, success=ok,
                   detail=(("%s (%d bytes)" % (res, entry["size"])) if ok else "refused: %s" % res)[:500])
        if not ok:
            why = res if isinstance(res, i18n.Sentence) else i18n.Sentence(res)
            return jsonify({"success": False, "message": i18n.tr("The upload was not kept: {why}", why=why)}), 200
        return jsonify({"success": True, "name": res, "message": i18n.tr("Uploaded as {name}.", name=res)})
