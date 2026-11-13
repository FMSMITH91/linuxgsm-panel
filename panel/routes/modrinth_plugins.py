"""A PaperMC server's plugins, on its server page: search Modrinth, install, enable, disable, remove.

Which games: LinuxGSM's pmcserver (pmc, PaperMC) only. A vanilla server (mcserver) cannot load
plugins, and the proxies (Velocity, Waterfall) load plugins of their own kind, not Paper's.

PERMISSION: the file manager's: VIEW_FILES to list and search, EDIT_FILES to install, enable,
disable or remove (_fpm_can_view, _fpm_can_edit). Installing a plugin puts code on the server,
exactly as uploading a jar through the file browser does, and every write here goes through the
file browser's own helpers with its own refusals: _write_refused (a root-capable game account is
never written as), then ssh_manager.upload_file / rename_path / delete_path as the game account.
Nothing here runs as root or adds a privileged path.

INSTALL: the panel host asks Modrinth for the newest release of the project for Paper, Spigot or
Bukkit on the server's Minecraft version, downloads its primary file from Modrinth's CDN and checks
its sha512 against the API's (panel/services/modrinth.py); only then is the .jar written into
serverfiles/plugins/, never over a file already there. The Minecraft version is read from the
server's own serverfiles/version_history.json (Paper writes it); when it cannot be told, the
search covers every version and the card marks the results as unverified for this server.

INSTALLED: the .jar files in serverfiles/plugins/, from the file browser's listing. Disable renames
X.jar to X.jar.disabled (Paper loads only .jar files), Enable renames it back, Remove deletes it.
Each takes effect when the server next starts. Every install, enable, disable and remove is
audited with the plugin's name and version, against the server.
"""
import re

from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.http import _json_body, _json_str, _log_and_generic, _unreachable
from panel.ops import ssh_manager as _sm
from panel.routes._shared import _r20b_audit_on_raise, _r42r_audit_after
from panel.security.auth import _fpm_can_edit, _fpm_can_view, get_game, log_action, server_access_required
from panel.services import modrinth as _mr

PLUGIN_GAMES = frozenset({"pmc"})
_MDR_DIR = "serverfiles/plugins"
_MDR_VERSION_FILE = "serverfiles/version_history.json"
_MDR_DISABLED = ".disabled"
# A plugin file the card can act on: the names an install writes, enabled or disabled.
_MDR_FILE = re.compile(r"[A-Za-z0-9_+-][A-Za-z0-9._+-]{0,127}\.jar(?:\.disabled)?")
_MDR_LIST_MAX = 500
_MDR_ACTIONS = ("enable", "disable", "remove")

NOT_PAPER = "Plugins can be installed on a PaperMC server only."
UNREADABLE = "The plugins folder could not be read from the server, so it is not shown."
EXISTS = ("A file named {name} is already in the plugins folder. Remove it first to install this "
          "build in its place.")
_MDR_BAD_FILE = "That is not a plugin file in this server's plugins folder."
_MDR_BAD_ACTION = "That change does not fit this plugin file."
_MDR_INSTALLED = "Installed {name}. It loads when the server next starts."
_MDR_CHANGED = "Done. The change takes effect when the server next starts."


def plugins_supported(game_type):
    """Does this LinuxGSM game load Paper plugins (a PaperMC server)?"""
    return (game_type or "").lower() in PLUGIN_GAMES


def mc_version(gs):
    """The server's Minecraft version from Paper's version_history.json, or None when it cannot be told."""
    content, err = _sm.read_file(gs.remote, gs.short_name, _MDR_VERSION_FILE)
    return None if err else _mr.paper_mc_version(content)


def _mdr_entry(e):
    """One listed file as the card's row, or None for a folder or a file that is not a plugin jar."""
    name = e.get("name") or ""
    if e.get("is_dir") or not (name.endswith(".jar") or name.endswith(".jar" + _MDR_DISABLED)):
        return None
    return {"name": name, "enabled": name.endswith(".jar"), "size": e.get("size") or 0,
            "managed": bool(_MDR_FILE.fullmatch(name))}


def _mdr_listing(gs, rel):
    """browse_dir's answer for `rel`, or None when it could not be read."""
    out = _sm.browse_dir(gs.remote, gs.short_name, rel, gs.lgsm_name)
    if not out or out.get("unreadable") or out.get("outside_home"):
        return None
    return out.get("entries") or []


def installed(gs):
    """(rows, None) for the plugin jars in serverfiles/plugins/, or (None, why).

    The folder is made by the server's first start: when it is not there but serverfiles is, the
    list is empty, not unreadable.
    """
    entries = _mdr_listing(gs, _MDR_DIR)
    if entries is None:
        parent = _mdr_listing(gs, "serverfiles")
        if parent is None or any(e.get("name") == "plugins" for e in parent):
            return None, UNREADABLE
        entries = []
    rows = [r for r in (_mdr_entry(e) for e in entries) if r is not None]
    return rows[:_MDR_LIST_MAX], None


def _mdr_audit(gs, verb, detail, success):
    """One audit row against the server for `verb` (install, enable, disable or remove).

    The action is spelled out at the call, not looked up, so the audit-id gate can read each name.
    """
    log_action(current_user, ("plugin_enable" if verb == "enable" else "plugin_disable" if verb == "disable"
                              else "plugin_remove" if verb == "remove" else "plugin_install"),
               target=gs.name, detail=detail, success=success, server=gs)


def _mdr_refuse(gs, verb, detail, why, status=400):
    """Audit an attempt refused before the server was touched, and answer it."""
    _mdr_audit(gs, verb, "%s (refused: %s)" % (detail, why), False)
    return jsonify({"success": False, "message": i18n.tr(why)}), status


def _mdr_install(gs, project_id):
    """Resolve, download, verify and write one plugin: the install route's answer."""
    from panel.routes import server_files as _sf
    info, why = _mr.resolve(project_id, mc_version(gs))
    if why:
        return _mdr_refuse(gs, "install", project_id, why, 502 if why == _mr.UNAVAILABLE else 400)
    plan = info["plan"]
    detail = _sf._audit_safe("%s %s (%s, %s/%s)" % (info["title"], info["version_number"], plan["filename"],
                                                    project_id, info["version_id"]), 300)
    data, why = _mr.download(plan)
    if why:
        return _mdr_refuse(gs, "install", detail, why, 502)
    with _r20b_audit_on_raise("plugin_install", detail=detail, target=gs.name, server=gs):
        ok, msg = _sm.upload_file(gs.remote, gs.short_name, _MDR_DIR, plan["filename"], data,
                                  overwrite=False, selfname=gs.lgsm_name)
    if not ok and msg == _sm.UPLOAD_EXISTS:
        return _mdr_refuse(gs, "install", detail + " (name taken)", EXISTS, 409)
    reply = ({"success": True, "name": plan["filename"], "message": i18n.tr(_MDR_INSTALLED, name=plan["filename"])}
             if ok else {"success": False, "message": _sm.write_failure_reason(msg) or "Failed"})
    with _r42r_audit_after(reply):      # the plugin is on the server by now (_r42r_audit_after)
        _mdr_audit(gs, "install", detail, ok)
    return jsonify(reply)


def change_target(action, name):
    """(new name or None for a removal, None), or (None, why) when the action does not fit the file."""
    if action not in _MDR_ACTIONS:
        return None, _MDR_BAD_ACTION
    if not isinstance(name, str) or not _MDR_FILE.fullmatch(name):
        return None, _MDR_BAD_FILE
    disabled = name.endswith(_MDR_DISABLED)
    if action == "enable":
        return (name[:-len(_MDR_DISABLED)], None) if disabled else (None, _MDR_BAD_ACTION)
    if action == "disable":
        return (None, _MDR_BAD_ACTION) if disabled else (name + _MDR_DISABLED, None)
    return None, None


def _mdr_change(gs, action, name, new_name):
    """Rename or delete one plugin file as the game account and audit it: the change route's answer."""
    rel = "%s/%s" % (_MDR_DIR, name)
    with _r20b_audit_on_raise("plugin_" + action, detail=name, target=gs.name, server=gs):
        if action == "remove":
            ok, msg = _sm.delete_path(gs.remote, gs.short_name, rel, selfname=gs.lgsm_name)
        else:
            ok, msg = _sm.rename_path(gs.remote, gs.short_name, rel, new_name, selfname=gs.lgsm_name)
    detail = name if new_name is None else "%s -> %s" % (name, new_name)
    reply = {"success": True, "message": i18n.tr(_MDR_CHANGED)}
    if not ok:
        # delete_path can answer with the host's own output; only its fixed refusals are shown.
        said = _sm.delete_failure_reason(msg) if action == "remove" else msg
        reply = {"success": False, "message": i18n.tr(said or "Failed")}
    with _r42r_audit_after(reply):      # the file is renamed or gone by now (_r42r_audit_after)
        _mdr_audit(gs, action, detail, ok)
    return jsonify(reply)


def _mdr_change_refused(gs, action, name, why):
    """A refusal for a change that failed its checks (`why`) or may not be written as, else None."""
    from panel.routes import server_files as _sf
    if why:
        # The action, never the refused name: it is what failed the checks. An unknown action is
        # audited as a removal attempt, the most destructive it could have been.
        verb = action if action in _MDR_ACTIONS else "remove"
        return _mdr_refuse(gs, verb, action if action in _MDR_ACTIONS else "?", why)
    return _sf._write_refused(gs, ("plugin_enable" if action == "enable" else "plugin_disable"
                                   if action == "disable" else "plugin_remove"),
                              "%s/%s" % (_MDR_DIR, name))


def _mdr_gate(gs):
    """A refusal for a server that is not PaperMC, else None (the permission is asked inline)."""
    if not plugins_supported(gs.game_type):
        return jsonify({"success": False, "error": i18n.tr(NOT_PAPER), "message": i18n.tr(NOT_PAPER)}), 400
    return None


def _mdr_list_answer(gs):
    """The list route's answer once its permission has passed."""
    from panel.routes import server_files as _sf
    bad = _mdr_gate(gs) or _sf._read_refused(gs, "plugin_list", _MDR_DIR)
    if bad is not None:
        return bad
    try:
        rows, why = installed(gs)
        if why:
            return jsonify({"success": False, "error": i18n.tr(why)})
        return jsonify({"success": True, "plugins": rows, "mc_version": mc_version(gs)})
    except ConnectionError:
        return _unreachable("list plugins")
    except Exception:
        return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500


def _mdr_search_answer(gs):
    """The search route's answer once its permission has passed; `mc` is dropped unless N.N[.N]."""
    bad = _mdr_gate(gs)
    if bad is not None:
        return bad
    mcv = request.args.get("mc", "")
    if mcv and not _mr.valid_mc_version(mcv):
        mcv = ""
    hits, why = _mr.search(request.args.get("q", ""), mcv or None)
    if why:
        return jsonify({"success": False, "error": i18n.tr(why)}), 400 if why == _mr.BAD_QUERY else 502
    return jsonify({"success": True, "hits": hits, "verified": bool(mcv)})


def _mdr_install_answer(gs):
    """The install route's answer once its permission has passed."""
    from panel.routes import server_files as _sf
    bad = _mdr_gate(gs)
    if bad is not None:
        return bad
    project_id = _json_str(_json_body(), "project_id")
    if not _mr.valid_id(project_id):
        return _mdr_refuse(gs, "install", "?", _mr.BAD_ID)
    refused = _sf._write_refused(gs, "plugin_install", _MDR_DIR)
    if refused is not None:
        return refused
    try:
        return _mdr_install(gs, project_id)
    except ConnectionError:
        return _unreachable("install a plugin")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def _mdr_change_answer(gs):
    """The change route's answer once its permission has passed."""
    bad = _mdr_gate(gs)
    if bad is not None:
        return bad
    data = _json_body()
    action, name = _json_str(data, "action"), _json_str(data, "name")
    new_name, why = change_target(action, name)
    refused = _mdr_change_refused(gs, action, name, why)
    if refused is not None:
        return refused
    try:
        return _mdr_change(gs, action, name, new_name)
    except ConnectionError:
        return _unreachable("change a plugin")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def register(app):
    """The plugin list, search, install and change routes, and the template's `plugins_supported`.

    Each view asks the file manager's permission itself (rbac_test reads each view's own gate), then
    hands the rest to its module-level answer.
    """
    app.jinja_env.globals["plugins_supported"] = plugins_supported

    @app.route("/api/server/<int:server_id>/plugins")
    @login_required
    @server_access_required
    def api_server_plugins(server_id):
        """The installed plugin jars and the server's Minecraft version (None when it cannot be told)."""
        gs = get_game(server_id)
        if not _fpm_can_view():
            return jsonify({"error": "Permission denied"}), 403
        return _mdr_list_answer(gs)

    @app.route("/api/server/<int:server_id>/plugins/search")
    @login_required
    @server_access_required
    def api_server_plugins_search(server_id):
        """Modrinth's plugins for Paper, Spigot or Bukkit matching `q`, on version `mc` when given."""
        gs = get_game(server_id)
        if not _fpm_can_view():
            return jsonify({"error": "Permission denied"}), 403
        return _mdr_search_answer(gs)

    @app.route("/api/server/<int:server_id>/plugins/install", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_plugins_install(server_id):
        """Download one Modrinth plugin on the panel host, check its sha512, write it into plugins/."""
        gs = get_game(server_id)
        if not _fpm_can_edit():
            return jsonify({"success": False, "message": "Permission denied"}), 403
        return _mdr_install_answer(gs)

    @app.route("/api/server/<int:server_id>/plugins/change", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_plugins_change(server_id):
        """Enable, disable or remove one plugin jar in serverfiles/plugins/."""
        gs = get_game(server_id)
        if not _fpm_can_edit():
            return jsonify({"success": False, "message": "Permission denied"}), 403
        return _mdr_change_answer(gs)
