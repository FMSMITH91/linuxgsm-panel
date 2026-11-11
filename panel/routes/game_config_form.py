"""The Form view of the game's own config file, beside its raw editor on Files & Config.

The fields come from panel/services/game_config_form.py. The game-config read (server_files'
api_server_game_config) carries the form for the file it found; this module adds:

* GET  /api/server/<id>/game-config/form?path=<rel> - the file read again with its form, for the page
  to rebuild the form after the raw editor saved it.
* POST /api/server/<id>/game-config/form - {path, hash, changes: {field id: value}}: only the changed
  values written, every other byte kept.

The same permission, refusals and writer as the raw editor's /file route: the Settings tab's
permission (_can_manage_files), the file browser's refusals of a root-capable account
(_read_refused, _write_refused), read_file/write_file as the game account. The path comes from the
page exactly as the raw editor's does, and write_file applies the same path rules to both. Each save
is audited as the raw editor's is (edit_file), naming the changed keys; a secret key's values never
go in the row.
"""
from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.http import _json_body, _log_and_generic, _unreachable
from panel.ops import ssh_manager as _sm
from panel.routes._shared import _r20b_audit_on_raise
from panel.security.auth import _can_manage_files, get_game, log_action, server_access_required
from panel.services import game_config_form as _gcf

_GCF_SAVED = "Saved. Restart the server to apply."
_GCF_NOTHING = "Nothing changed."
_GCF_AUDIT_ROOM = 900


def form_for(found):
    """The form for a game-config read's result ({rel, content, exists, ...}), or None."""
    if not isinstance(found, dict) or not found.get("rel") or not found.get("exists"):
        return None
    return _gcf.build(found["rel"], found.get("content") or "")


def _gcf_refusal(message, status=400):
    said = i18n.tr(message)
    return jsonify({"success": False, "message": said, "error": said}), status


def _gcf_read_answer(gs):
    """GET: the file read again, with its form."""
    from panel.routes import server_files as _sf
    rel = request.args.get("path", "")
    refused = _sf._read_refused(gs, "read_file", rel)
    if refused is not None:
        return refused
    try:
        content, err = _sm.read_file(gs.remote, gs.short_name, rel)
    except ConnectionError:
        return _unreachable("read the game config")
    except Exception:
        return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500
    if err:
        return _gcf_refusal(err)
    return jsonify({"success": True, "path": rel, "content": content,
                    "form": _gcf.build(rel, content or "")})


def _gcf_audit(gs, rel, detail, ok, reason=None):
    from panel.routes import server_files as _sf
    text = _sf._audit_safe("%s (form): %s" % (_sf._audit_name(rel), detail), limit=_GCF_AUDIT_ROOM)
    log_action(current_user, "edit_file", target=gs.name, detail=_sf._failed_detail(text, ok, reason),
               success=ok, server=gs)


def _gcf_save(gs, rel, data):
    """Re-read the file, check it is the text the form was built from, write the changed values."""
    from panel.routes import server_files as _sf
    content, err = _sm.read_file(gs.remote, gs.short_name, rel)
    if err:
        return _gcf_refusal(err, 409)
    new, changed, why = _gcf.apply(rel, content, data.get("hash"), data.get("changes"))
    if why:
        log_action(current_user, "edit_file", target=gs.name,
                   detail=_sf._r14b_refused(_sf._audit_name(rel), why), success=False, server=gs)
        return _gcf_refusal(why, 409 if why == _gcf.CHANGED else 400)
    if not changed:
        return jsonify({"success": True, "message": i18n.tr(_GCF_NOTHING), "content": content,
                        "form": _gcf.build(rel, content)})
    detail = _gcf.audit_detail(changed)
    with _r20b_audit_on_raise("edit_file", detail=_sf._audit_safe(_sf._audit_name(rel)), target=gs.name,
                              server=gs):
        ok, msg = _sm.write_file(gs.remote, gs.short_name, rel, new, selfname=gs.lgsm_name)
    reason = _sm.write_failure_reason(msg)
    _gcf_audit(gs, rel, detail, ok, reason)
    if not ok:
        return jsonify({"success": False, "message": i18n.tr(reason or "Failed")})
    return jsonify({"success": True, "message": i18n.tr(_GCF_SAVED), "content": new,
                    "form": _gcf.build(rel, new)})


def _gcf_save_answer(gs):
    """POST: the save, once the permission has passed."""
    from panel.routes import server_files as _sf
    data = _json_body()
    if not isinstance(data, dict):
        data = {}
    rel = data.get("path")
    if not isinstance(rel, str) or not rel:
        return _gcf_refusal("The file path must be text.")
    refused = _sf._write_refused(gs, "edit_file", rel)
    if refused is not None:
        return refused
    try:
        return _gcf_save(gs, rel, data)
    except ConnectionError:
        return _unreachable("save the game config")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def register(app):
    """The form route. Its view asks the Settings tab's permission itself (rbac_test reads it)."""
    @app.route("/api/server/<int:server_id>/game-config/form", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_game_config_form(server_id):
        """The game config file's form (GET), or its changed values written (POST)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"success": False, "error": "Permission denied", "message": "Permission denied"}), 403
        return _gcf_read_answer(gs) if request.method == "GET" else _gcf_save_answer(gs)
