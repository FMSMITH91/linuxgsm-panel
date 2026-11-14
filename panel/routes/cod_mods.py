"""The Mods tab of a Call of Duty server: its mod folders, the one it starts with, and switching it.

What a CoD mod is to the server, and why the switch is one token of `startparameters`, is in
panel/services/cod_mods.py. PERMISSION: the Mods tab's (MANAGE_SERVERS) to read; switching writes
the instance cfg, so it also needs the config editor's EDIT_FILES, and asks the file browser's refusal
of a root-capable account first (_write_refused), as reading asks _read_refused. Every switch is
audited with the folder before and after, against the server. A switch takes effect at the next
start: the answer says so, and nothing is restarted.
"""
from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.http import _json_body, _json_str, _log_and_generic, _unreachable
from panel.routes._shared import _r20b_audit_on_raise, _r42r_audit_after
from panel.security.auth import (_can_manage_files, _fpm_can_edit, get_game, log_action,
                                 server_access_required)
from panel.services import cod_mods as _cm

_AUDIT = "mods_select"


def _read_answer(gs):
    """GET: the card's state, or why there is none."""
    from panel.routes import server_files as _sf
    refused = _sf._read_refused(gs, "mods_read")
    if refused is not None:
        return refused
    try:
        state = _cm.read(gs.remote, gs.short_name, gs.lgsm_name, gs.game_type)
    except ConnectionError:
        return _unreachable("read the mod folders")
    except Exception:
        return jsonify({"error": _log_and_generic("cod mods read failed")}), 500
    if state is None:
        return jsonify({"error": i18n.tr(_cm.UNREAD)})
    state["upload_dir"] = _cm.upload_dir(gs.game_type)
    return jsonify(state)


def _switched(gs, value, result):
    """The answer and audit row of a switch the host was asked to make (`result`: cod_mods.switch's)."""
    ok, why, changed, before = result
    known = why in _cm.REASONS
    detail = "%s -> %s" % (before or "(none)", value or "(none)")
    if not ok:
        detail += "; " + (why if known else "the write failed")
        reply = {"success": False, "message": i18n.tr(why if known else "Couldn't save the config.")}
    elif not changed:
        reply = {"success": True, "changed": False, "active": value, "message": i18n.tr("Nothing to change.")}
    else:
        reply = {"success": True, "changed": True, "active": value,
                 "message": (i18n.tr("Saved. Restart the server to start it with {mod}.", mod=value) if value
                             else i18n.tr("Saved. Restart the server to start it without a mod."))}
    with _r42r_audit_after(reply):      # the cfg is written by now (_r42r_audit_after)
        log_action(current_user, _AUDIT, target=gs.name, detail=detail, success=ok, server=gs)
    return jsonify(reply)


def _switch_answer(gs):
    """POST: start the server with another mod folder (or none) from its next start."""
    from panel.routes import server_files as _sf
    value = _json_str(_json_body(), "mod")
    refused = _sf._write_refused(gs, _AUDIT, value)
    if refused is not None:
        return refused
    try:
        with _r20b_audit_on_raise(_AUDIT, target=gs.name, detail=value or "(none)", server=gs):
            result = _cm.switch(gs.remote, gs.short_name, gs.lgsm_name, gs.game_type, value)
    except ConnectionError:
        return _unreachable("change the mod")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("cod mods switch failed")}), 500
    return _switched(gs, value, result)


def register(app):
    """The CoD mods routes, and the template's `mods_kind` (which Mods card a game gets, if any)."""
    app.jinja_env.globals["mods_kind"] = _cm.mods_kind

    @app.route("/api/server/<int:server_id>/cod-mods", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_cod_mods(server_id):
        """A Call of Duty server's mod folders and active mod (GET), or a switch to another (POST)."""
        gs = get_game(server_id)
        if not _can_manage_files() or (request.method == "POST" and not _fpm_can_edit()):
            return jsonify({"success": False, "error": "Permission denied", "message": "Permission denied"}), 403
        if _cm.mods_kind(gs.game_type) != "cod":
            said = i18n.tr("Not a Call of Duty server.")
            return jsonify({"success": False, "error": said, "message": said}), 404
        return _read_answer(gs) if request.method == "GET" else _switch_answer(gs)
