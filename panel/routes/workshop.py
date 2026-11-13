"""A server's Steam Workshop content, on its server page: the ids its config lists, with their titles.

Three kinds of game, by where the list lives:

* WORKSHOPMODS (LinuxGSM's `workshopmods` setting): arma3, dayz, squad, squad44, ohd, bt, hw, col,
  st, l4d2, sb and sol. An ordered list of Workshop item or collection ids, in load order;
  `./<server> workshop-update` (lgsm/modules/workshop_core.sh) downloads them and expands each
  collection through Steam's API. The card offers that command as it is offered elsewhere: the
  existing server action, with its own permission (UPDATE_SERVER).
* WSCOLLECTIONID (LinuxGSM's `wscollectionid`): gmod and csgo. One collection id, which the game
  itself downloads when it starts (+host_workshop_collection). csgo's `wsapikey` is a secret and
  is never read, shown or written here: only `wscollectionid` is asked for.
* PROJECT ZOMBOID (pz): no LinuxGSM setting. The game's own Zomboid/Server/<selfname>.ini holds
  `WorkshopItems=` (ids it downloads at start) and `Mods=` (the Mod IDs it loads, which are not
  Workshop ids: each comes from an item's mods/<dir>/mod.info). The card offers the Mod IDs found in
  items already downloaded under serverfiles/steamapps/workshop/content/108600.

Reads and writes go through the helpers the Settings tab and the file editor use, as the game
account: lgsm_get_values / lgsm_write_config for the instance cfg (which keep every other line and
refuse a key that secrets-<selfname>.cfg shadows), read_file / write_file for the ini, changing only
the two lines it is about. PERMISSION: the Settings tab's, VIEW_FILES to read and EDIT_FILES to save,
plus the file browser's refusals of a root-capable account (_read_refused, _write_refused). Every
save is audited with the ids before and after, against the server.

TITLES come from Steam's public API, asked by the panel host (panel/services/steam_workshop.py).
When Steam does not answer, the ids are shown bare and editing still works.
"""
import re

from flask import jsonify, request
from flask_login import current_user, login_required
from panel.core import i18n
from panel.core.http import _json_body, _log_and_generic, _unreachable
from panel.ops import ssh_manager as _sm
from panel.routes._shared import _r20b_audit_on_raise
from panel.security.auth import _fpm_can_edit, _fpm_can_view, get_game, log_action, server_access_required
from panel.services import steam_workshop as _ws

MODS_GAMES = frozenset({"arma3", "dayz", "squad", "squad44", "ohd", "bt", "hw", "col", "st", "l4d2", "sb",
                        "sol"})
COLLECTION_GAMES = frozenset({"gmod", "csgo"})
PZ_GAMES = frozenset({"pz"})
_WSC_PZ_CONTENT = "serverfiles/steamapps/workshop/content/108600"
# A Mod ID goes into the ini's Mods= line, so only what breaks that line is refused: `;` (the
# separator), `=`, and any control or line-separator character (a line break would start a key of its
# own). Real Mod IDs hold brackets, parentheses, quotes and plus signs (Arsenal(26)GunFighter[MAIN MOD
# 2.0]). A leading backslash is kept: Build 42 ini files may write each Mod ID as \ModID; a backslash
# anywhere else is refused.
_WSC_MOD_ID = re.compile(r"\\?[^;=\\\x00-\x1f\x7f-\x9f\u2028\u2029]{1,100}")
_WSC_MOD_DIR = re.compile(r"[A-Za-z0-9_.\-+()' ]{1,100}")
# How far the Mod ID search reaches: items looked at, mod folders per item, files read in all.
_WSC_PZ_ITEMS = 30
_WSC_PZ_DIRS = 10
_WSC_PZ_READS = 60
_WSC_MODINFO_MAX = 16384
_WSC_NO_FILE = "File not found"

NOT_WORKSHOP = "This game has no Steam Workshop list the panel can edit."
UNREAD = "Could not read the current config — nothing has been changed."
BAD_MOD_ID = ("A Mod ID is 1 to 100 characters with no ; or =, line break or control character, and no "
              "blank at either end (a leading backslash is kept).")
MOD_TOO_MANY = "A list holds at most 200 Mod IDs."
PZ_NO_INI = ("Zomboid/Server/{name}.ini is not there yet. Project Zomboid writes it the first time the "
             "server starts; start it once, then add Workshop items here.")
_WSC_SAVED = "Saved."


def workshop_kind(game_type):
    """'mods', 'collection' or 'pz' for a game whose Workshop list the card edits, else None."""
    g = (game_type or "").lower()
    if g in MODS_GAMES:
        return "mods"
    if g in COLLECTION_GAMES:
        return "collection"
    return "pz" if g in PZ_GAMES else None


def workshop_supported(game_type):
    """Does this LinuxGSM game have a Workshop list the card edits?"""
    return workshop_kind(game_type) is not None


def pz_ini_rel(gs):
    """The Project Zomboid server config, relative to the game account's home."""
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string - a file path, not a response
    return "Zomboid/Server/%s.ini" % gs.lgsm_name


# ── the Project Zomboid ini ─────────────────────────────────────────────────────────────────────
def _wsc_key_line(line, key):
    """Whether `line` assigns `key` (not a comment)."""
    s = line.lstrip()
    return not s.startswith(("#", ";")) and s.split("=", 1)[0].strip() == key and "=" in s


def ini_list(content, key):
    """The `;`-separated values of the last `key=` line in `content`, stripped, blanks dropped."""
    value = ""
    for line in (content or "").splitlines():
        if _wsc_key_line(line, key):
            value = line.split("=", 1)[1]
    return [v.strip() for v in value.split(";") if v.strip()]


def ini_set(content, updates):
    """`content` with each key's lines set to its value; every other byte as it was.

    Every uncommented line of the key is rewritten (keeping its own line ending); a key with no
    line is added at the end, with the file's line ending.
    """
    lines = (content or "").splitlines(keepends=True)
    nl = "\r\n" if "\r\n" in (content or "") else "\n"
    for key, value in updates.items():
        hit = False
        for i, line in enumerate(lines):
            if _wsc_key_line(line, key):
                body = line.rstrip("\r\n")
                lines[i] = "%s=%s%s" % (key, value, line[len(body):])
                hit = True
        if not hit:
            if lines and not lines[-1].endswith(("\n", "\r")):
                lines[-1] += nl
            lines.append("%s=%s%s" % (key, value, nl))
    return "".join(lines)


def check_mod_ids(values):
    """(mod ids, None) for a list of Mod IDs, in order, or (None, why)."""
    if not isinstance(values, list):
        return None, BAD_MOD_ID
    if len(values) > _ws.MAX_IDS:
        return None, MOD_TOO_MANY
    out = []
    for v in values:
        if not isinstance(v, str) or v != v.strip() or not _WSC_MOD_ID.fullmatch(v):
            return None, BAD_MOD_ID
        if v in out:
            return None, _ws.DUPLICATE
        out.append(v)
    return out, None


def _wsc_mod_info(text):
    """(id, name) from a mod.info's text, or None when its id is not a valid Mod ID."""
    found = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() in ("id", "name") and k.strip() not in found:
            found[k.strip()] = v.strip()
    mid = found.get("id", "")
    if not _WSC_MOD_ID.fullmatch(mid) or mid.startswith("\\"):
        return None
    return mid, found.get("name", "")[:100]


def _wsc_listing(gs, rel):
    """The entries of folder `rel`, or None when it is not there or could not be read."""
    out = _sm.browse_dir(gs.remote, gs.short_name, rel, gs.lgsm_name)
    if not out or out.get("unreadable") or out.get("outside_home"):
        return None
    return out.get("entries") or []


def _wsc_mod_dirs(entries):
    """The folder names in an item's mods/ listing that can be read: plain names, not hidden."""
    return [e["name"] for e in entries if e.get("is_dir") and _WSC_MOD_DIR.fullmatch(e.get("name") or "")
            and not e["name"].startswith(".")]


def _wsc_dir_mod(gs, folder, budget):
    """(id, name) from one mod folder's mod.info, or None; each read spends one of `budget` (a one-item list).

    Build 41 keeps mod.info in the mod's folder, Build 42 in its 42/ folder.
    """
    for rel in (folder + "/mod.info", folder + "/42/mod.info"):
        if budget[0] <= 0:
            return None
        budget[0] -= 1
        text, err = _sm.read_file(gs.remote, gs.short_name, rel, max_bytes=_WSC_MODINFO_MAX)
        info = None if err else _wsc_mod_info(text)
        if info:
            return info
    return None


def _wsc_item_mods(gs, wid, budget):
    """The mods one downloaded item holds, as [{id, name, item}]; `budget` is a one-item list of reads left."""
    base = "%s/%s/mods" % (_WSC_PZ_CONTENT, wid)
    found = []
    for d in _wsc_mod_dirs(_wsc_listing(gs, base) or [])[:_WSC_PZ_DIRS]:
        info = _wsc_dir_mod(gs, "%s/%s" % (base, d), budget)
        if info:
            found.append({"id": info[0], "name": info[1], "item": wid})
        if budget[0] <= 0:
            break
    return found


def pz_found_mods(gs, items):
    """The Mod IDs in the given Workshop items already downloaded on the server, at most once each."""
    budget, out, seen = [_WSC_PZ_READS], [], set()
    for wid in items[:_WSC_PZ_ITEMS]:
        if budget[0] <= 0:
            break
        for m in _wsc_item_mods(gs, wid, budget):
            if m["id"] not in seen:
                seen.add(m["id"])
                out.append(m)
    return out


# ── reads ───────────────────────────────────────────────────────────────────────────────────────
def _wsc_cfg_value(gs, key):
    """The merged LinuxGSM value of `key`, or None when the config could not be read."""
    vals = _sm.lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, [key])
    return None if vals is None else str(vals.get(key) or "")


def _wsc_read_pz(gs):
    """(the Project Zomboid ini's two lists, None), or (None, why); an ini not written yet is empty lists."""
    content, err = _sm.read_file(gs.remote, gs.short_name, pz_ini_rel(gs))
    if err == _WSC_NO_FILE:
        return {"kind": "pz", "items": [], "mods": [], "missing": True}, None
    if err:
        return None, err
    items = ini_list(content, "WorkshopItems")
    return {"kind": "pz", "items": [i for i in items if _ws.valid_id(i)], "mods": ini_list(content, "Mods"),
            "missing": False, "ignored": [i for i in items if not _ws.valid_id(i)]}, None


def _wsc_read(gs, kind):
    """(the card's view of the server's list, None), or (None, why)."""
    if kind == "pz":
        return _wsc_read_pz(gs)
    key = "workshopmods" if kind == "mods" else "wscollectionid"
    value = _wsc_cfg_value(gs, key)
    if value is None:
        return None, UNREAD
    ids, ignored = _ws.split_ids(value)
    if kind == "collection" and len(ids) > 1:
        # One collection id is all the game takes; anything else is shown as it is, not guessed at.
        ids, ignored = [], [value.strip()]
    return {"kind": kind, "ids": ids, "ignored": ignored}, None


# ── saves ───────────────────────────────────────────────────────────────────────────────────────
def _wsc_audit(gs, detail, success):
    """One audit row for a Workshop save against the server."""
    log_action(current_user, "workshop_save", target=gs.name, detail=detail, success=success, server=gs)


def _wsc_refuse(gs, detail, why, status=400):
    """Audit a save refused before the server was written, and answer it."""
    _wsc_audit(gs, "%s (refused: %s)" % (detail, why), False)
    return jsonify({"success": False, "message": i18n.tr(why)}), status


def _wsc_change(label, before, after):
    """`label: a b -> a b c`, for the audit row."""
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string - audit text, not a response
    return "%s: %s -> %s" % (label, " ".join(before) or "(none)", " ".join(after) or "(none)")


def _wsc_cfg_ids(kind, data):
    """(ids, None) from a save's body: `ids` for workshopmods, one `id` (or "" to clear) for a collection."""
    if kind == "mods":
        return _ws.check_ids(data.get("ids"))
    ids, why = _ws.check_ids([data["id"]] if data.get("id") else [])
    return (None, _ws.BAD_ID) if why is None and len(ids) > 1 else (ids, why)


def _wsc_save_cfg(gs, kind, data):
    """Write workshopmods or wscollectionid in the instance cfg: the save route's answer."""
    key = "workshopmods" if kind == "mods" else "wscollectionid"
    ids, why = _wsc_cfg_ids(kind, data)
    if why:
        return _wsc_refuse(gs, key, why)
    before = _wsc_cfg_value(gs, key)
    if before is None:
        return _wsc_refuse(gs, key, UNREAD, 409)
    detail = _wsc_change(key, _ws.split_ids(before)[0], ids)
    with _r20b_audit_on_raise("workshop_save", detail=detail, target=gs.name, server=gs):
        ok, msg = _sm.lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, {key: " ".join(ids)})
    _wsc_audit(gs, detail, ok)
    if not ok:
        return jsonify({"success": False, "message": i18n.tr(_sm.write_failure_reason(msg) or "Failed")})
    return jsonify({"success": True, "message": i18n.tr(_WSC_SAVED), "ids": ids})


def _wsc_pz_lists(data):
    """(items, mods, None) from a pz save's body, or (None, None, why)."""
    items, why = _ws.check_ids(data.get("items"))
    if why:
        return None, None, why
    mods, why = check_mod_ids(data.get("mods"))
    return (None, None, why) if why else (items, mods, None)


def _wsc_save_pz(gs, data):
    """Write WorkshopItems= and Mods= in the Project Zomboid ini: the save route's answer."""
    items, mods, why = _wsc_pz_lists(data)
    if why:
        return _wsc_refuse(gs, "WorkshopItems/Mods", why)
    rel = pz_ini_rel(gs)
    content, err = _sm.read_file(gs.remote, gs.short_name, rel)
    if err:
        why = i18n.Sentence(PZ_NO_INI, name=gs.lgsm_name) if err == _WSC_NO_FILE else err
        return _wsc_refuse(gs, "WorkshopItems/Mods", why, 409)
    detail = "%s; %s" % (_wsc_change("WorkshopItems", ini_list(content, "WorkshopItems"), items),
                         _wsc_change("Mods", ini_list(content, "Mods"), mods))
    new = ini_set(content, {"WorkshopItems": ";".join(items), "Mods": ";".join(mods)})
    with _r20b_audit_on_raise("workshop_save", detail=detail, target=gs.name, server=gs):
        ok, msg = _sm.write_file(gs.remote, gs.short_name, rel, new, selfname=gs.lgsm_name)
    _wsc_audit(gs, detail, ok)
    if not ok:
        return jsonify({"success": False, "message": i18n.tr(_sm.write_failure_reason(msg) or "Failed")})
    return jsonify({"success": True, "message": i18n.tr(_WSC_SAVED), "items": items, "mods": mods})


# ── route answers ───────────────────────────────────────────────────────────────────────────────
def _wsc_gate(gs):
    """(kind, None), or (None, a refusal) for a game with no Workshop list here."""
    kind = workshop_kind(gs.game_type)
    if kind is None:
        return None, (jsonify({"success": False, "error": i18n.tr(NOT_WORKSHOP),
                               "message": i18n.tr(NOT_WORKSHOP)}), 400)
    return kind, None


def _wsc_read_answer(gs):
    """The read route's answer once its permission has passed."""
    from panel.routes import server_files as _sf
    kind, bad = _wsc_gate(gs)
    if bad is None:
        bad = _sf._read_refused(gs, "workshop_read", pz_ini_rel(gs) if kind == "pz" else "")
    if bad is not None:
        return bad
    try:
        view, why = _wsc_read(gs, kind)
        if why:
            return jsonify({"success": False, "error": i18n.tr(why)})
        view["success"] = True
        return jsonify(view)
    except ConnectionError:
        return _unreachable("read the Workshop list")
    except Exception:
        return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500


def _wsc_titles_answer(gs):
    """The titles route's answer: Steam's titles for `ids` (comma separated), or unavailable."""
    _kind, bad = _wsc_gate(gs)
    if bad is not None:
        return bad
    ids = [i for i in (request.args.get("ids") or "").split(",") if _ws.valid_id(i)][:_ws.MAX_IDS]
    found, complete = _ws.details(ids)
    return jsonify({"success": True, "titles": found, "complete": complete})


def _wsc_pz_gate(gs):
    """A refusal for a server that is not Project Zomboid or may not be read as, else None."""
    from panel.routes import server_files as _sf
    if workshop_kind(gs.game_type) != "pz":
        return jsonify({"success": False, "error": i18n.tr(NOT_WORKSHOP)}), 400
    return _sf._read_refused(gs, "workshop_read", _WSC_PZ_CONTENT)


def _wsc_pz_mods_answer(gs):
    """The Mod ID search's answer: the mods in the given items already downloaded on the server."""
    bad = _wsc_pz_gate(gs)
    if bad is not None:
        return bad
    items, why = _ws.check_ids([i for i in (request.args.get("items") or "").split(",") if i])
    if why:
        return jsonify({"success": False, "error": i18n.tr(why)}), 400
    try:
        return jsonify({"success": True, "mods": pz_found_mods(gs, items)})
    except ConnectionError:
        return _unreachable("read the Workshop items")
    except Exception:
        return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500


def _wsc_save_answer(gs):
    """The save route's answer once its permission has passed."""
    from panel.routes import server_files as _sf
    kind, bad = _wsc_gate(gs)
    if bad is not None:
        return bad
    data = _json_body()
    if not isinstance(data, dict):
        data = {}
    refused = _sf._write_refused(gs, "workshop_save", pz_ini_rel(gs) if kind == "pz" else "")
    if refused is not None:
        return refused
    try:
        return _wsc_save_pz(gs, data) if kind == "pz" else _wsc_save_cfg(gs, kind, data)
    except ConnectionError:
        return _unreachable("save the Workshop list")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def register(app):
    """The Workshop card's routes, and the template's `workshop_kind`.

    Each view asks the Settings tab's permission itself (rbac_test reads each view's own gate), then
    hands the rest to its module-level answer.
    """
    app.jinja_env.globals["workshop_kind"] = workshop_kind

    @app.route("/api/server/<int:server_id>/workshop", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_workshop(server_id):
        """The server's Workshop list (GET), or a new one written into its config (POST)."""
        gs = get_game(server_id)
        if not (_fpm_can_edit() if request.method == "POST" else _fpm_can_view()):
            return jsonify({"success": False, "error": "Permission denied", "message": "Permission denied"}), 403
        return _wsc_read_answer(gs) if request.method == "GET" else _wsc_save_answer(gs)

    @app.route("/api/server/<int:server_id>/workshop/titles")
    @login_required
    @server_access_required
    def api_server_workshop_titles(server_id):
        """Steam's titles for up to 200 Workshop ids, asked by the panel host."""
        gs = get_game(server_id)
        if not _fpm_can_view():
            return jsonify({"error": "Permission denied"}), 403
        return _wsc_titles_answer(gs)

    @app.route("/api/server/<int:server_id>/workshop/pz-mods")
    @login_required
    @server_access_required
    def api_server_workshop_pz_mods(server_id):
        """The Mod IDs in a Project Zomboid server's downloaded Workshop items."""
        gs = get_game(server_id)
        if not _fpm_can_view():
            return jsonify({"error": "Permission denied"}), 403
        return _wsc_pz_mods_answer(gs)
