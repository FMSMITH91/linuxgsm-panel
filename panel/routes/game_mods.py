"""The Mods tab's cards for games with no LinuxGSM installer: Arma 3 / DayZ folders, Factorio, Minecraft packs.

What each card edits, and why, is in its service module (panel/services/arma_mods.py, fctr_mods.py,
mc_packs.py). A Java Minecraft server's datapacks install from Modrinth through the plugin browser's
service (panel/services/modrinth.py, its datapack kind) with the same checks: the API's own file URL
on Modrinth's CDN, a size cap, and the sha512 compared before anything reaches the server.
PERMISSION: the Mods tab's (MANAGE_SERVERS) to read, as the CoD card (routes/cod_mods.py); a
change writes as the game account, so it also needs the config editor's EDIT_FILES and asks the
file browser's refusal of a root-capable account first (_write_refused), as reading asks
_read_refused. Every change is audited against the server with what it was and what it became.
Changes apply at the server's next start: the answers say so, and nothing is restarted.
"""
from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.http import _json_body, _json_str, _log_and_generic, _unreachable
from panel.routes._shared import _r20b_audit_on_raise, _r42r_audit_after
from panel.security.auth import (_can_manage_files, _fpm_can_edit, get_game, log_action,
                                 server_access_required)
from panel.ops import ssh_manager as _sm
from panel.services import arma_mods as _am, cod_mods as _cm, fctr_mods as _fm, mc_packs as _mp, modrinth as _mr

_DENIED = "Permission denied"
_SAVED_RESTART = "Saved. Restart the server to load the change."
_SAVED_RESTART_REMOVED = "Removed. The world stops loading it when the server next starts."


def _denied():
    return jsonify({"success": False, "error": _DENIED, "message": _DENIED}), 403


def _not_this_game(said):
    said = i18n.tr(said)
    return jsonify({"success": False, "error": said, "message": said}), 404


# ── Arma 3 / DayZ mod folders ───────────────────────────────────────────────────────────────────
def _am_read_answer(gs):
    """GET: the folders, and the two lists in load order."""
    from panel.routes import server_files as _sf
    refused = _sf._read_refused(gs, "mod_folders_read")
    if refused is not None:
        return refused
    try:
        state = _am.read_state(gs.remote, gs.short_name, gs.lgsm_name)
    except ConnectionError:
        return _unreachable("read the mod folders")
    except Exception:
        return jsonify({"error": _log_and_generic("mod folders read failed")}), 500
    if state is None:
        return jsonify({"error": i18n.tr(_am.UNREAD)})
    return jsonify(state)


def _am_detail(before, after):
    """`mods: @a;@b -> @a; servermods: (none) -> (none)` for the audit row."""
    return "; ".join("%s: %s -> %s" % (k, ";".join(before.get(k) or []) or "(none)",
                                       ";".join(after.get(k) or []) or "(none)") for k in _am.KEYS)


def _am_saved(gs, result):
    """The answer and audit row of a save the host was asked to make (`result`: arma_mods.save's)."""
    ok, why, before, after = result
    known = why in _am.REASONS
    detail = _am_detail(before, after)
    if not ok:
        detail += "; " + (why if known else "the write failed")
        reply = {"success": False, "message": i18n.tr(why if known else "Couldn't save the config.")}
    elif before == after:
        reply = {"success": True, "changed": False, "message": i18n.tr("Nothing to change.")}
    else:
        reply = {"success": True, "changed": True, "message": i18n.tr(_SAVED_RESTART)}
    with _r42r_audit_after(reply):      # the cfg is written by now (_r42r_audit_after)
        log_action(current_user, "mod_folders_save", target=gs.name, detail=detail, success=ok, server=gs)
    return jsonify(reply)


def _am_save_answer(gs):
    """POST {"mods": [...], "servermods": [...]}: the new lists, written into the instance cfg."""
    from panel.routes import server_files as _sf
    posted = _json_body()
    refused = _sf._write_refused(gs, "mod_folders_save")
    if refused is not None:
        return refused
    try:
        with _r20b_audit_on_raise("mod_folders_save", target=gs.name, detail="mods/servermods", server=gs):
            result = _am.save(gs.remote, gs.short_name, gs.lgsm_name, posted if isinstance(posted, dict) else {})
    except ConnectionError:
        return _unreachable("save the mod folders")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("mod folders save failed")}), 500
    return _am_saved(gs, result)


# ── Factorio ────────────────────────────────────────────────────────────────────────────────────
def _fm_read_answer(gs):
    """GET: the mods in the server's mods folder and mod-list.json."""
    from panel.routes import server_files as _sf
    refused = _sf._read_refused(gs, "factorio_mods_read")
    if refused is not None:
        return refused
    try:
        state = _fm.read(gs.remote, gs.short_name, gs.lgsm_name)
    except ConnectionError:
        return _unreachable("read the mods folder")
    except Exception:
        return jsonify({"error": _log_and_generic("factorio mods read failed")}), 500
    if state is None:
        return jsonify({"error": i18n.tr(_fm.UNREAD)})
    return jsonify(state)


def _fm_audit(gs, enabled, detail, ok):
    """One audit row for a Factorio mod turned on or off, its action spelled out at the call."""
    if enabled:
        log_action(current_user, "factorio_mod_enable", target=gs.name, detail=detail, success=ok, server=gs)
    else:
        log_action(current_user, "factorio_mod_disable", target=gs.name, detail=detail, success=ok, server=gs)


def _fm_changed(gs, name, enabled, result):
    """The answer and audit row of a change the host was asked to make (`result`: fctr_mods.set_enabled's)."""
    ok, why, changed, _before = result
    known = why in _fm.REASONS
    detail = "%s: %s" % (name, "on" if enabled else "off")
    if not ok:
        detail += "; " + (why if known else "the write failed")
        reply = {"success": False, "message": i18n.tr(why if known else "Couldn't save mod-list.json.")}
    elif not changed:
        reply = {"success": True, "changed": False, "message": i18n.tr("Nothing to change.")}
    else:
        reply = {"success": True, "changed": True, "message": i18n.tr(_SAVED_RESTART)}
    with _r42r_audit_after(reply):      # mod-list.json is written by now (_r42r_audit_after)
        _fm_audit(gs, enabled, detail, ok)
    return jsonify(reply)


def _fm_change_answer(gs):
    """POST {"name", "enabled"}: one mod turned on or off in mod-list.json."""
    from panel.routes import server_files as _sf
    data = _json_body()
    name = _json_str(data, "name")
    enabled = isinstance(data, dict) and data.get("enabled") is True
    refused = _sf._write_refused(gs, "factorio_mod_enable" if enabled else "factorio_mod_disable", _fm.MOD_LIST)
    if refused is not None:
        return refused
    try:
        with _r20b_audit_on_raise("factorio_mod_enable" if enabled else "factorio_mod_disable", target=gs.name,
                                  detail=_sf._audit_safe(name, 120), server=gs):
            result = _fm.set_enabled(gs.remote, gs.short_name, gs.lgsm_name, name, enabled)
    except ConnectionError:
        return _unreachable("change mod-list.json")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("factorio mod change failed")}), 500
    return _fm_changed(gs, _sf._audit_safe(name, 120), enabled, result)


# ── Minecraft: Java datapacks, Bedrock packs ────────────────────────────────────────────────────
def _mp_read_answer(gs):
    """GET: a Java server's datapacks, or a Bedrock server's packs."""
    from panel.routes import server_files as _sf
    refused = _sf._read_refused(gs, "mc_packs_read")
    if refused is not None:
        return refused
    try:
        if _mp.kind(gs.game_type) == "java":
            state = _mp.read_java(gs.remote, gs.short_name, gs.lgsm_name, gs.game_type)
        else:
            state = _mp.read_bedrock(gs.remote, gs.short_name, gs.lgsm_name)
    except ConnectionError:
        return _unreachable("read the packs")
    except Exception:
        return jsonify({"error": _log_and_generic("mc packs read failed")}), 500
    if state is None:
        return jsonify({"error": i18n.tr(_mp.UNREAD)})
    state["kind"] = _mp.kind(gs.game_type)
    return jsonify(state)


def _mp_refuse(gs, action, detail, why, status=400):
    """Audit a change refused before the server was written, and answer it."""
    log_action(current_user, action, target=gs.name, detail="%s (refused: %s)" % (detail, why), success=False,
               server=gs)
    return jsonify({"success": False, "message": i18n.tr(why)}), status


def _mp_remove(gs, name):
    """Delete one datapack from the server's world: the change route's answer for a Java server."""
    from panel.routes import server_files as _sf
    detail = _sf._audit_safe(name, 140)
    state = _mp.read_java(gs.remote, gs.short_name, gs.lgsm_name, gs.game_type)
    if state is None:
        return _mp_refuse(gs, "datapack_remove", detail, _mp.UNREAD, 409)
    rel = _mp.remove_target(state, name)
    if rel is None:
        return _mp_refuse(gs, "datapack_remove", detail, _mp.NOT_A_PACK)
    with _r20b_audit_on_raise("datapack_remove", detail=detail, target=gs.name, server=gs):
        ok, msg = _sm.delete_path(gs.remote, gs.short_name, rel, selfname=gs.lgsm_name)
    reply = ({"success": True, "message": i18n.tr(_SAVED_RESTART_REMOVED)} if ok
             else {"success": False, "message": i18n.tr(_sm.delete_failure_reason(msg) or "Failed")})
    with _r42r_audit_after(reply):      # the datapack is gone by now (_r42r_audit_after)
        log_action(current_user, "datapack_remove", target=gs.name, detail="%s/%s" % (state["world"], detail),
                   success=ok, server=gs)
    return jsonify(reply)


def _mp_pack_audit(gs, enabled, detail, ok):
    """One audit row for a Bedrock pack turned on or off, its action spelled out at the call."""
    if enabled:
        log_action(current_user, "bedrock_pack_enable", target=gs.name, detail=detail, success=ok, server=gs)
    else:
        log_action(current_user, "bedrock_pack_disable", target=gs.name, detail=detail, success=ok, server=gs)


def _mp_toggle(gs, data):
    """Turn one Bedrock pack on or off for the world: the change route's answer for a Bedrock server."""
    from panel.routes import server_files as _sf
    pack_type, uuid = _json_str(data, "type"), _json_str(data, "uuid")
    enabled = data.get("enabled") is True
    with _r20b_audit_on_raise("bedrock_pack_enable" if enabled else "bedrock_pack_disable", target=gs.name,
                              detail=_sf._audit_safe(uuid, 60), server=gs):
        ok, why, changed, label = _mp.set_pack(gs.remote, gs.short_name, gs.lgsm_name, pack_type, uuid, enabled)
    known = why in _mp.REASONS or isinstance(why, i18n.Sentence)
    detail = "%s: %s" % (label or _sf._audit_safe(uuid, 60), "on" if enabled else "off")
    if not ok:
        detail += "; " + (str(why) if known else "the write failed")
        reply = {"success": False, "message": i18n.tr(why) if known else i18n.tr("Couldn't save the world's pack list.")}
    elif not changed:
        reply = {"success": True, "changed": False, "message": i18n.tr("Nothing to change.")}
    else:
        reply = {"success": True, "changed": True, "message": i18n.tr(_SAVED_RESTART)}
    with _r42r_audit_after(reply):      # the world's list is written by now (_r42r_audit_after)
        _mp_pack_audit(gs, enabled, detail, ok)
    return jsonify(reply)


def _mp_change_answer(gs):
    """POST: remove a datapack (Java) or turn a pack on or off (Bedrock)."""
    from panel.routes import server_files as _sf
    data = _json_body()
    data = data if isinstance(data, dict) else {}
    java = _mp.kind(gs.game_type) == "java"
    action = "datapack_remove" if java else ("bedrock_pack_enable" if data.get("enabled") is True
                                             else "bedrock_pack_disable")
    refused = _sf._write_refused(gs, action)
    if refused is not None:
        return refused
    try:
        if java and data.get("action") != "remove":
            return _mp_refuse(gs, "datapack_remove", "?", _mp.NOT_A_PACK)
        return _mp_remove(gs, _json_str(data, "name")) if java else _mp_toggle(gs, data)
    except ConnectionError:
        return _unreachable("change the packs")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("mc packs change failed")}), 500


def _mp_search_answer(gs):
    """GET ?q=&mc=: Modrinth's datapacks matching q, on version mc when it reads as one."""
    mcv = request.args.get("mc", "")
    if mcv and not _mr.valid_mc_version(mcv):
        mcv = ""
    hits, why = _mr.search(request.args.get("q", ""), mcv or None, kind="datapack")
    if why:
        return jsonify({"success": False, "error": i18n.tr(why)}), 400 if why == _mr.BAD_QUERY else 502
    return jsonify({"success": True, "hits": hits, "verified": bool(mcv)})


def _mp_install(gs, project_id):
    """Resolve, download, verify and write one datapack into the world's datapacks folder."""
    from panel.routes import server_files as _sf
    state = _mp.read_java(gs.remote, gs.short_name, gs.lgsm_name, gs.game_type)
    if state is None:
        return _mp_refuse(gs, "datapack_install", project_id, _mp.UNREAD, 409)
    if not state["world"]:
        return _mp_refuse(gs, "datapack_install", project_id, i18n.Sentence(_mp.NO_WORLD, why=state["why"]), 409)
    info, why = _mr.resolve(project_id, state["mc_version"], kind="datapack")
    if why:
        return _mp_refuse(gs, "datapack_install", project_id, why, 502 if why == _mr.UNAVAILABLE else 400)
    plan = info["plan"]
    detail = _sf._audit_safe("%s %s (%s, %s/%s) -> %s" % (info["title"], info["version_number"], plan["filename"],
                                                          project_id, info["version_id"], state["world"]), 300)
    data, why = _mr.download(plan, kind="datapack")
    if why:
        return _mp_refuse(gs, "datapack_install", detail, why, 502)
    with _r20b_audit_on_raise("datapack_install", detail=detail, target=gs.name, server=gs):
        ok, msg = _sm.upload_file(gs.remote, gs.short_name, state["dir"], plan["filename"], data,
                                  overwrite=False, selfname=gs.lgsm_name)
    if not ok and msg == _sm.UPLOAD_EXISTS:
        return _mp_refuse(gs, "datapack_install", detail + " (name taken)",
                          i18n.Sentence(_mp.EXISTS, name=plan["filename"]), 409)
    reply = ({"success": True, "name": plan["filename"],
              "message": i18n.tr("Installed {name}. It loads when the server next starts.", name=plan["filename"])}
             if ok else {"success": False, "message": i18n.tr(_sm.write_failure_reason(msg) or "Failed")})
    with _r42r_audit_after(reply):      # the datapack is on the server by now (_r42r_audit_after)
        log_action(current_user, "datapack_install", target=gs.name, detail=detail, success=ok, server=gs)
    return jsonify(reply)


def _mp_install_answer(gs):
    """POST {"project_id"}: one Modrinth datapack installed into the server's world."""
    from panel.routes import server_files as _sf
    project_id = _json_str(_json_body(), "project_id")
    if not _mr.valid_id(project_id):
        return _mp_refuse(gs, "datapack_install", "?", _mr.BAD_ID)
    refused = _sf._write_refused(gs, "datapack_install")
    if refused is not None:
        return refused
    try:
        return _mp_install(gs, project_id)
    except ConnectionError:
        return _unreachable("install a datapack")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("datapack install failed")}), 500


def _mp_gate(gs, java_only=False):
    """A refusal for a server that is not Minecraft (or not Java, when `java_only`), else None."""
    kind = _cm.mods_kind(gs.game_type)
    if kind != "mc" and (java_only or kind != "mcb"):
        return _not_this_game("Not a Minecraft Java server." if java_only else "Not a Minecraft server.")
    return None


def register(app):
    """The Mods tab's routes for Arma 3 / DayZ, Factorio and Minecraft."""

    @app.route("/api/server/<int:server_id>/mod-folders", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_mod_folders(server_id):
        """An Arma 3 / DayZ server's mod folders and its mods / servermods lists (GET), or new lists (POST)."""
        gs = get_game(server_id)
        if not _can_manage_files() or (request.method == "POST" and not _fpm_can_edit()):
            return _denied()
        if _cm.mods_kind(gs.game_type) != "arma":
            return _not_this_game("Not an Arma 3 or DayZ server.")
        return _am_read_answer(gs) if request.method == "GET" else _am_save_answer(gs)

    @app.route("/api/server/<int:server_id>/factorio-mods", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_factorio_mods(server_id):
        """A Factorio server's mods and whether each is on (GET), or one turned on or off (POST)."""
        gs = get_game(server_id)
        if not _can_manage_files() or (request.method == "POST" and not _fpm_can_edit()):
            return _denied()
        if _cm.mods_kind(gs.game_type) != "fctr":
            return _not_this_game("Not a Factorio server.")
        return _fm_read_answer(gs) if request.method == "GET" else _fm_change_answer(gs)

    @app.route("/api/server/<int:server_id>/mc-packs", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_mc_packs(server_id):
        """A Minecraft server's datapacks or packs (GET), or one removed or turned on or off (POST)."""
        gs = get_game(server_id)
        if not _can_manage_files() or (request.method == "POST" and not _fpm_can_edit()):
            return _denied()
        bad = _mp_gate(gs)
        if bad is not None:
            return bad
        return _mp_read_answer(gs) if request.method == "GET" else _mp_change_answer(gs)

    @app.route("/api/server/<int:server_id>/mc-packs/search")
    @login_required
    @server_access_required
    def api_server_mc_packs_search(server_id):
        """Modrinth's datapacks matching `q`, on Minecraft version `mc` when given."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return _denied()
        return _mp_gate(gs, java_only=True) or _mp_search_answer(gs)

    @app.route("/api/server/<int:server_id>/mc-packs/install", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_mc_packs_install(server_id):
        """Download one Modrinth datapack on the panel host, check its sha512, write it into the world."""
        gs = get_game(server_id)
        if not _can_manage_files() or not _fpm_can_edit():
            return _denied()
        return _mp_gate(gs, java_only=True) or _mp_install_answer(gs)
