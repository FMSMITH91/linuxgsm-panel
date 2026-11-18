"""Changing an installed add-on: B3's settings, and updating either add-on to the catalog's pin.

Both run in the background like an install (routes/addons.py) and end the same way: the add-on
restarted and watched for SETTLE_SECONDS, or a reason on its row. Its data, its settings file and its
database stay; the unit and the relays are written again. Both take MANAGE_ADDONS, the step-up
confirmation an install takes, and the root-capable-account guard (routes/addons._guarded), and both
are audited with the server, refusals included.

SETTINGS (B3). Geolocation (off, offline country, online city) and B3's own plugins (services/addons
B3_SWITCHABLE). Only what the panel owns is rewritten: the [plugins] lines of the plugins it offers
in b3.ini (b3_ini_apply) and two keys of plugin_geolocation.ini (geolocation_ini); the passwords, the
operator's other settings and every other file in conf/ are kept.

UPDATE. A new image (a pull by digest, or a build from the new commit), and for an offline B3 this
month's country database (services/geoip.py). The card offers it when the record (addon.json) says
another image, or an older database month, than the catalog's.
"""
import json
import threading
from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user

from panel.core import i18n
from panel.core.config import decrypt_secret
from panel.core.http import _json_body, _log_and_generic
from panel.db.models import GameDatabase, GameServer, claim_row, row_birth
from panel.ops import ssh_manager as _sm
from panel.security.auth import log_action
from panel.services import addons as _ad
from panel.services import geoip as _geoip

_NOT_INSTALLED = "That add-on isn't installed on this server."
_BAD_SETTINGS = "Choose a geolocation setting and only plugins this add-on offers."
_NOT_B3 = "Only B3 has settings here."
_NO_READ = "Couldn't read the add-on's settings on the host: it did not answer."
_STARTED = {"settings": "Applying the settings: the add-on restarts.",
            "update": "Updating the add-on. Downloading or building its image takes a few minutes."}
# Ports the read asks for: the add-on's page when it has none recorded, a database relay, the geolocators.
_PORTS_ASKED = 2 + len(_ad.B3_GEOLOCATORS)


def update_reason(addon_id, meta, month=None):
    """Why an installed add-on has an update: "image", "geoip" (B3 offline, an older month) or ""."""
    if (meta.get("image") or "") != _ad.CATALOG[addon_id]["image"]:
        return "image"
    if (addon_id == _ad.B3 and _ad.geo_mode(meta.get("geolocation")) == _ad.GEO_OFFLINE
            and str(meta.get("geoip") or "") < (month or _geoip.month_now())):
        return "geoip"
    return ""


def settings_choice(body):
    """(geolocation mode, plugins) from a settings post, or None when either is not one the card offers."""
    geo, plugins = body.get("geolocation"), body.get("plugins")
    if geo not in _ad.GEO_MODES or not isinstance(plugins, list):
        return None
    allowed = set(_ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE)
    if not all(isinstance(p, str) and p in allowed for p in plugins):
        return None
    return geo, [p for p in _ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE if p in plugins]


def _read(gs, addon_id):
    """The host's state for a change: (probe dict with "meta", b3.ini text, geolocation ini text) or None."""
    sh = (_ad.probe_sh(addon_id, gs.lgsm_name, gs.id, gs.game_type, _PORTS_ASKED) + "; " + _ad.status_sh()
          + "; " + (_ad.b3_conf_read_sh(gs.short_name) if addon_id == _ad.B3 else "") + "true")
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=60, selfname=gs.lgsm_name)
    if rc != 0:
        return None
    p = _ad.parse_probe(out)
    found = _ad.parse_status(out)["addons"].get(addon_id)
    p["meta"] = found["meta"] if found else None
    kv = _ad.kv_lines(out)
    return p, _ad._unb64(kv.get("b3ini.b64", "")), _ad._unb64(kv.get("geoini.b64", ""))


def _db_of(gs, meta):
    """(the database row the add-on uses, its host, its port), from the record's database name."""
    from panel.routes import addons as _ra   # it imports this module: read at call time
    name = meta.get("database") or ""
    r = GameDatabase.query.filter_by(game_server_id=gs.id, name=name).first() if name else None
    host, port = _ra._db_target(r) if r is not None else ("", 0)
    return r, host, port


def _unit(gs, addon_id, p, meta, geo):
    """(unit text, relay units, Network=, the page's port) for the add-on as it is set now."""
    r, host, port = _db_of(gs, meta)
    web = meta.get("port") if _ad.CATALOG[addon_id]["web_port"] else None
    free = [x for x in p["ports"] if x != web]
    if _ad.CATALOG[addon_id]["web_port"] and not web:
        web, free = (free[0], free[1:]) if free else (None, [])
    relay_list = _ad.relays(addon_id, host, port, geo, free)
    local_db = port if r is not None and host == "127.0.0.1" else None
    net = _ad.network(gs.port, local_db, relay_list, p["splice"])
    unit = _ad.quadlet(gs.short_name, addon_id, _ad.log_dir(gs.short_name, p["logdir"]), net, web, relay_list,
                       p["ids"])
    return unit, _ad.relay_units(addon_id, relay_list), net, web


def _secrets(gs, addon_id, meta, p):
    """The values to mask in what the host prints: the RCON password and the database's."""
    rcon, _why = _ad.game_rcon(gs.game_type, p["rcon_lines"])
    r, _h, _p = _db_of(gs, meta)
    return (rcon, (decrypt_secret(r.secret) or "") if r is not None else "")


def _b3_files(b3ini, geoini, geo, plugins):
    """(b3.ini's new text or None, the files to write) for B3 set to `geo` and `plugins`."""
    files = {}
    if geo != _ad.GEO_OFF:
        files[_ad.B3_GEO_INI] = _ad.geolocation_ini(geoini, geo)
    new = _ad.b3_ini_apply(b3ini, geo, plugins) if b3ini else None
    return (new if new != b3ini else None), files


def _settings_now(addon_id, meta, b3ini, choice):
    """(geolocation mode, plugins) to apply: the posted ones, else as the add-on is set now.

    For B3 the plugins are read from b3.ini itself, so an update keeps a plugin the operator turned
    on or off there by hand.
    """
    if choice is not None:
        return choice
    geo = _ad.geo_mode(meta.get("geolocation"))
    if addon_id == _ad.B3 and b3ini:
        allowed = _ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE
        return geo, [x for x in _ad.b3_ini_plugins(b3ini) if x in allowed]
    return geo, list(meta.get("plugins") or _ad.B3_PLUGINS)


def _geoip_for(gs, addon_id, rec, geo, kind):
    """Give an offline B3 this month's country database when it needs one (an update always asks). -> why not."""
    if addon_id != _ad.B3 or geo != _ad.GEO_OFFLINE:
        return ""
    if kind != "update" and str(rec.get("geoip") or "") >= _geoip.month_now():
        return ""
    from panel.routes import addons as _ra   # it imports this module: read at call time
    month, why = _ra.push_geoip(gs, addon_id)
    if not why:
        rec["geoip"] = month
    return why


def _change_steps(gs, addon_id, who, kind, choice=None):
    """A settings change or an update: ("", "") when the add-on runs again, else (why, log tail)."""
    got = _read(gs, addon_id)
    if got is None:
        return _NO_READ, ""
    p, b3ini, geoini = got
    meta = p["meta"]
    if meta is None:
        return _NOT_INSTALLED, ""
    geo, plugins = _settings_now(addon_id, meta, b3ini, choice)
    rec = dict(meta, **_record(addon_id, geo, plugins, meta, kind))
    why = _geoip_for(gs, addon_id, rec, geo, kind)
    if why:
        return why, ""
    new_ini, files = _b3_files(b3ini, geoini, geo, plugins) if addon_id == _ad.B3 else (None, {})
    if kind == "update":
        files.update(_ad.build_files(addon_id))
    unit, units, net, web = _unit(gs, addon_id, p, meta, geo)
    rec.update(network=net, port=web, changed_by=who)
    sh = _ad.reconfigure_sh(gs.short_name, addon_id, unit, json.dumps(rec) + "\n", files, units,
                            rebuild=kind == "update", settings=new_ini is not None, old_image=meta.get("image", ""))
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=_ad.INSTALL_TIMEOUT,
                                           selfname=gs.lgsm_name, stdin_text=new_ini)
    secrets = _secrets(gs, addon_id, meta, p)
    ok, said, tail = _ad.install_outcome(_ad.scrub(out or "", secrets), rc)
    return ("", "") if ok else (said, _ad.scrub(tail, secrets))


def _record(addon_id, geo, plugins, meta, kind):
    """The record's fields a change sets: the catalog's image after an update, B3's settings, who and when."""
    from panel.routes import addons as _ra
    rec = _ra.record(addon_id, geo, plugins, meta.get("geoip", "")) if kind == "update" else (
        {"geolocation": geo, "plugins": list(plugins)} if addon_id == _ad.B3 else {})
    rec["changed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return rec


def _worker(app, gs_id, born, addon_id, who, kind, choice):
    """Run one change in a thread, record how it went on the job, and audit it."""
    from panel.routes import addons as _ra
    with app.app_context():
        why, tail = "", ""
        try:
            gs = claim_row(GameServer, gs_id, born)
            if gs is not None:
                why, tail = _change_steps(gs, addon_id, who, kind, choice)
                log_action(None, "addon_update" if kind == "update" else "addon_settings", target=gs.name, actor=who, server=gs, success=not why,
                           detail="%s %s" % (addon_id, ("done" if not why else "not done: %s" % why)))
        except Exception:
            why = _log_and_generic("add-on %s failed" % kind)
        finally:
            with _ra._JOBS_LOCK:
                _ra._JOBS[(gs_id, addon_id)] = {"running": False, "why": why, "tail": tail, "kind": kind}


def start(app, gs, addon_id, kind):
    """Start a settings change or an update for the server's add-on (in the background), or refuse."""
    from panel.routes import addons as _ra
    choice = None
    if kind == "settings":
        if addon_id != _ad.B3:
            return _ra._say(400, _NOT_B3)
        choice = settings_choice(_json_body())
        if choice is None:
            return _ra._say(400, _BAD_SETTINGS)
    with _ra._JOBS_LOCK:
        if (_ra._JOBS.get((gs.id, addon_id)) or {}).get("running"):
            return _ra._say(409, _ra._BUSY)
        _ra._JOBS[(gs.id, addon_id)] = {"running": True, "why": "", "tail": "", "kind": kind}
    detail = "%s: started" % addon_id + ("" if choice is None else ", geolocation %s, plugins %s"
                                         % (choice[0], " ".join(choice[1]) or "none"))
    log_action(current_user, "addon_update" if kind == "update" else "addon_settings", target=gs.name, server=gs,
               detail=detail)
    threading.Thread(target=_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), addon_id, current_user.username, kind, choice)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTED[kind])}), 202

