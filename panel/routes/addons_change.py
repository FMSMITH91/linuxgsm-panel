"""Changing an installed add-on: B3's settings, and updating either add-on to the catalog's pin.

Both run in the background like an install (routes/addons.py) and end the same way: the add-on
restarted and watched for SETTLE_SECONDS, or a reason on its row. Its data, its settings file and its
database stay; the unit and the relays are written again. Both take MANAGE_ADDONS, the step-up
confirmation an install takes, and the root-capable-account guard (routes/addons._guarded), and both
are audited with the server, refusals included.

SETTINGS (B3). Geolocation (off, offline country, online city), B3's own plugins (services/addons
B3_SWITCHABLE) and the operator's own plugins folder (B3_OWN_PLUGINS: off unless turned on; a plugin
there is third-party code the panel does not check, run inside B3's container, so turning it on takes
the same step-up and is audited by name). Only what the panel owns is rewritten: the [plugins] lines
of the plugins it offers and [b3] external_plugins_dir in b3.ini (b3_ini_apply) and two keys of
plugin_geolocation.ini (geolocation_ini); the passwords, the operator's other settings and every other
file in conf/ are kept. The container's limits stay as they are: the folder is mounted read-only.
Panel actions (off unless turned on) writes [b3] control_socket, so the B3 players section can unban,
kick and warn through B3 itself (routes/addons_b3.py); purge_aliases_days is written only when set.

APPLY (B3). B3 checks the new settings first (`--check-config`, in the image that will run, before any
file is moved into place: services/b3_control.check_sh); a refusal changes and restarts nothing, and the
card shows B3's first ERROR line. When only plugin settings changed (b3.ini, the unit and the
geolocation mode stay as they are), B3 reloads them without a restart and must report no plugin that
kept its old settings; anything else restarts it.

UPDATE. A new image (a pull by digest, or a build from the new commit), and for an offline B3 this
month's country database (services/geoip.py). The card offers it when the record (addon.json) says
another image, or an older database month, than the catalog's. For BlueMap, also when the game logged
another Minecraft version than the record's: the update then fetches that version's client file
(services/addons_bluemap.py) and writes the unit with it; after a new image its web page is written
again (BlueMap's release notes ask for that).
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
from panel.services import addons_bluemap as _bm, b3_control as _b3c, geoip as _geoip

_NOT_INSTALLED = "That add-on isn't installed on this server."
_BAD_SETTINGS = ("Choose a geolocation setting, only plugins this add-on offers, whether to load your own plugins and "
                 "to allow panel actions, and a number of days from 1 to 3650 (or none) for B3 to keep earlier names "
                 "and addresses.")
_NOT_B3 = "Only B3 has settings here."
_NO_READ = "Couldn't read the add-on's settings on the host: it did not answer."
# A settings change writes the catalog's image into the unit but builds nothing: with an update pending,
# that image is not on the host, so the restart would fail and the add-on stay down until Update.
_UPDATE_FIRST = "Update the add-on first, then apply its settings."
_STARTED = {"settings": "Applying the settings: B3 checks them first, then reloads its plugins or restarts.",
            "update": "Updating the add-on. Downloading or building its image takes a few minutes."}
# Ports the read asks for: the add-on's page when it has none recorded, a database relay, the geolocators.
_PORTS_ASKED = 2 + len(_ad.B3_GEOLOCATORS)


def update_reason(addon_id, meta, month=None):
    """Why an installed add-on has an update: "image", "geoip" (B3 offline, an older month) or "".

    "geoip" only while Settings -> Outside services lets the panel download DB-IP's database: with it
    off, that update could fetch nothing, so it is not offered (the card says the switch is off).
    """
    if (meta.get("image") or "") != _ad.CATALOG[addon_id]["image"]:
        return "image"
    if (addon_id == _ad.B3 and _ad.geo_mode(meta.get("geolocation")) == _ad.GEO_OFFLINE
            and str(meta.get("geoip") or "") < (month or _geoip.month_now()) and _geoip.download_allowed()):
        return "geoip"
    return ""


# The longest version label a record may hold to be shown (the catalog's are under 40 characters).
_VERSION_MAX = 64


def shown_version(addon_id, meta, installed=True):
    """(the version the card names an add-on by, the pending one or "") from its record.

    The installed image's own label (the record's `version`, written by the install or the last update)
    while the catalog's image is another; the catalog's label when they are the same image, or when it is
    not installed (`installed` False: the version Install would put there). The pending
    one is the catalog's label while an image update waits. A record's label that is not plain text of
    at most _VERSION_MAX characters is not shown ("").
    """
    pin = _ad.CATALOG[addon_id]["version"]
    if not installed or (meta.get("image") or "") == _ad.CATALOG[addon_id]["image"]:
        return pin, ""
    had = meta.get("version")
    ok = isinstance(had, str) and 0 < len(had) <= _VERSION_MAX and had.isprintable()
    return (had if ok else ""), pin


def settings_choice(body):
    """(geolocation, plugins, own plugins on, panel actions on, purge days or None) from a settings post, or None.

    None when one is not what the card offers. own_plugins and actions must be true or false when given;
    left out, they are off. purge_aliases_days is a whole number from PURGE_MIN to PURGE_MAX, or null
    (or left out) for off (Input Validation Cheat Sheet: type, then range).
    """
    geo, plugins, own = body.get("geolocation"), body.get("plugins"), body.get("own_plugins", False)
    if geo not in _ad.GEO_MODES or not isinstance(plugins, list) or not isinstance(own, bool):
        return None
    allowed = set(_ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE)
    service = _service_choice(body)
    if not all(isinstance(p, str) and p in allowed for p in plugins) or service is None:
        return None
    return (geo, [p for p in _ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE if p in plugins], own) + service


def _service_choice(body):
    """(panel actions on, purge days or None) from a settings post, or None when either is not one."""
    actions, purge = body.get("actions", False), body.get("purge_aliases_days")
    if not isinstance(actions, bool):
        return None
    if purge is None:
        return actions, None
    ok = isinstance(purge, int) and not isinstance(purge, bool) and _b3c.PURGE_MIN <= purge <= _b3c.PURGE_MAX
    return (actions, purge) if ok else None


def _read(gs, addon_id):
    """The host's state for a change: (probe dict with "meta", b3.ini text, geolocation ini text) or None."""
    sh = (_ad.probe_sh(addon_id, gs.lgsm_name, gs.id, gs.game_type, _PORTS_ASKED) + "; " + _ad.status_sh()
          + "; " + (_ad.b3_conf_read_sh(gs.short_name) if addon_id == _ad.B3 else "") + "true")
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=60, selfname=gs.lgsm_name)
    if rc != 0:
        return None
    p = _ad.parse_probe(out, gs.game_type)
    if _ad.CATALOG[addon_id]["reads"] == "world":
        p["world"] = _bm.parse_world(_ad.kv_lines(out), _ad._unb64)
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


def _web_and_free(addon_id, meta, ports):
    """(the add-on page's port, the free ports left for relays): the recorded page port is kept."""
    if not _ad.CATALOG[addon_id]["web_port"]:
        return None, list(ports)
    web = meta.get("port")
    free = [x for x in ports if x != web]
    if web:
        return web, free
    return (free[0], free[1:]) if free else (None, [])


def _reach_port(gs, meta, p):
    """The port the add-on reaches the game on: where it really listens, else what the record says."""
    known = meta.get("game_port") or gs.port
    port, _why = _ad.game_port(gs.game_type, known, p.get("udp") or [])
    return port or known


def _unit(gs, addon_id, p, meta, geo, own=False):
    """(unit text, relay units, Network=, the page's port) for the add-on as it is set now (`own`: B3's own plugins)."""
    r, host, port = _db_of(gs, meta)
    web, free = _web_and_free(addon_id, meta, p["ports"])
    relay_list = _ad.relays(addon_id, host, port, geo, free)
    local_db = port if r is not None and host == "127.0.0.1" else None
    game = None if _ad.CATALOG[addon_id]["reads"] == "world" else _reach_port(gs, meta, p)     # BlueMap: nothing
    net = _ad.network(game, local_db, relay_list, p["splice"], gs.game_type in _ad.RCON_TCP_GAMES)
    from panel.routes import addons as _ra   # it imports this module: read at call time
    unit = _ad.quadlet(gs.short_name, addon_id, _ra.game_reads(gs, addon_id, p), net, web, relay_list, p["ids"],
                       own_plugins=own)
    return unit, _ad.relay_units(addon_id, relay_list), net, web


def _secrets(gs, meta, p, b3ini):
    """The values to mask in what the host prints: the RCON passwords (game config, b3.ini) and the database's."""
    r, _h, _p = _db_of(gs, meta)
    return _ad.rcon_values(p["rcon_lines"], b3ini) + [(decrypt_secret(r.secret) or "") if r is not None else ""]


def _b3_files(b3ini, geoini, choice):
    """(b3.ini's new text or None, the files to write) for B3 set to `choice` (settings_choice's five)."""
    geo, plugins, own, actions, purge = choice
    files = {}
    if geo != _ad.GEO_OFF:
        files[_ad.B3_GEO_INI] = _ad.geolocation_ini(geoini, geo)
    new = _ad.b3_ini_apply(b3ini, geo, plugins, own, {"actions": actions, "purge": purge}) if b3ini else None
    return (new if new != b3ini else None), files


def _settings_now(addon_id, meta, b3ini, choice):
    """settings_choice's five to apply: the posted ones, else as the add-on is set now.

    For B3 the plugins, Panel actions and purge_aliases_days are read from b3.ini itself, so an update
    keeps what the operator set there by hand; the own-plugins folder stays as the record says.
    """
    if choice is not None:
        return choice
    geo, own = _ad.geo_mode(meta.get("geolocation")), meta.get("own_plugins") is True
    svc = _b3c.service_settings(b3ini)
    if addon_id == _ad.B3 and b3ini:
        allowed = _ad.B3_SWITCHABLE + _ad.B3_GEO_SWITCHABLE
        return geo, [x for x in _ad.b3_ini_plugins(b3ini) if x in allowed], own, svc["actions"], svc["purge"]
    return geo, list(meta.get("plugins") or _ad.B3_PLUGINS), own, svc["actions"], svc["purge"]


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


def _unit_refusal(gs, p, addon_id="", kind=""):
    """Why the unit can't be written now ("" when it can): installed, the install's checks on the log and ids.

    For a settings change, also no new image pending (_settings_refusal).

    Without them a change wrote `Volume=:/gamelog:ro` (the log not found) or a unit with no
    User=/Group= (no ids), and the restart left the add-on down with only "didn't start".
    """
    from panel.routes import addons as _ra   # it imports this module: read at call time
    if p["meta"] is None:
        return _NOT_INSTALLED
    if "world" in p:
        return _bm.again(_ra.world_refusal(p, 0))     # the page's port is the recorded one
    return (_ra.change_log_refusal(gs, p) or (_ra._NO_IDS if p["ids"] is None else "")
            or _settings_refusal(addon_id, p["meta"], kind))


def _settings_refusal(addon_id, meta, kind):
    """Why a settings change waits ("" when it doesn't): a new image is pending, which only Update builds."""
    return _UPDATE_FIRST if kind == "settings" and update_reason(addon_id, meta) == "image" else ""


def _change_steps(gs, addon_id, who, kind, choice=None):
    """A settings change or an update: ("", "") when the add-on runs again, else (why, log tail)."""
    got = _read(gs, addon_id)
    if got is None:
        return _NO_READ, ""
    p, b3ini, geoini = got
    meta = p["meta"]
    why = _unit_refusal(gs, p, addon_id, kind)
    if why:
        return why, ""
    now = _settings_now(addon_id, meta, b3ini, choice)
    geo, own = now[0], now[2] and addon_id == _ad.B3
    rec = dict(meta, **_record(addon_id, now, meta, kind))
    extra, why = _fetches(gs, addon_id, p, rec, (geo, kind, meta))
    if why:
        return why, ""
    new_ini, files = _b3_files(b3ini, geoini, now) if addon_id == _ad.B3 else (None, {})
    if kind == "update":
        files.update(_ad.build_files(addon_id))
    unit, units, net, web = _unit(gs, addon_id, p, meta, geo, own)
    rec.update(network=net, port=web, changed_by=who)
    how = {"rebuild": kind == "update", "settings": new_ini is not None, "extra": extra,
           "old_image": meta.get("image", ""), "dirs": [_ad.B3_OWN_PLUGINS] if own else []}
    how.update(_b3_apply_steps(gs, p, meta, (kind, now, new_ini, files.get(_ad.B3_GEO_INI)), who))
    sh = _ad.reconfigure_sh(gs.short_name, addon_id, unit, json.dumps(rec) + "\n", files, units, how)
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=_ad.INSTALL_TIMEOUT,
                                           selfname=gs.lgsm_name, stdin_text=new_ini)
    return _outcome(out or "", rc, _secrets(gs, meta, p, b3ini), "check" in how)


def _outcome(out, rc, secrets, checked):
    """("", "") when the change's shell ended well, else (why, log tail): B3's own marks first when it was checked."""
    handled, why, tail = _b3c.change_outcome(out, rc, secrets) if checked else (False, "", "")
    if handled:
        return why, tail
    ok, said, tail = _ad.install_outcome(_ad.scrub(out, secrets), rc)
    return ("", "") if ok else (said, _ad.scrub(tail, secrets))


def _b3_apply_steps(gs, p, meta, change, who):
    """For a B3 settings Apply: {"check": the settings check, "reload": the reload when only plugins changed}; else {}.

    `change` is (kind, settings_choice's five, b3.ini's new text or None, plugin_geolocation.ini's new
    text or None). A reload is offered only when b3.ini stays as it is and so do the geolocation mode and
    the own-plugins folder (the unit's relays, hosts and mounts follow those); the shell still restarts
    instead when the unit isn't running or b3.ini was edited by hand after B3 started.
    """
    kind, now, new_ini, geo_text = change
    if kind != "settings":
        return {}
    geo, own = now[0], now[2]
    steps = {"check": _b3c.check_sh(gs.short_name, p["ids"], geo_text, own)}
    if (new_ini is None and geo == _ad.geo_mode(meta.get("geolocation"))
            and own == (meta.get("own_plugins") is True)):
        steps["reload"] = _b3c.reload_sh(gs.short_name, who)
    return steps


def _fetches(gs, addon_id, p, rec, how):
    """What a change fetches first: an offline B3's country database, BlueMap's client file. -> (extra shell, why not).

    `how` is (geolocation mode, kind of change, the add-on's record before it). The extra shell is BlueMap's
    (_client); "" for the others.
    """
    why = _geoip_for(gs, addon_id, rec, how[0], how[1])
    return ("", why) if why else _client(gs, addon_id, p, rec, how[2])


def _client(gs, addon_id, p, rec, meta):
    """The client file BlueMap needs for the version the game runs now: (the shell that fetches it, why not or "").

    Sets rec["mc_version"]. After a new image (`meta`, the record before, names another), the shell also removes
    web/index.html, so the new BlueMap writes its own page. ("", "") for an add-on that reads no world.
    """
    if "world" not in p:
        return "", ""
    from panel.routes import addons as _ra   # it imports this module: read at call time
    version = p["world"]["version"]
    url, sha1, why = _bm.client_download(version)
    if why:
        return "", why
    rec["mc_version"] = version
    fresh = (meta.get("image") or "") != _ad.CATALOG[addon_id]["image"]
    return _ra.client_step(gs, addon_id, version, (url, sha1), fresh_webapp=fresh), ""


def _record(addon_id, now, meta, kind):
    """The record's fields a change sets: the catalog's image after an update, B3's settings (`now`), who and when."""
    from panel.routes import addons as _ra
    geo, plugins, own = now[:3]
    rec = _ra.record(addon_id, geo, plugins, meta.get("geoip", ""), own) if kind == "update" else (
        {"geolocation": geo, "plugins": list(plugins), "own_plugins": own} if addon_id == _ad.B3 else {})
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


def _choice_words(choice):
    """The audit row's words for a settings post's choice ("" for an update)."""
    if choice is None:
        return ""
    geo, plugins, own, actions, purge = choice
    return (", geolocation %s, plugins %s, own plugins %s, panel actions %s, purge %s"
            % (geo, " ".join(plugins) or "none", "on" if own else "off", "on" if actions else "off",
               "%d days" % purge if purge else "off"))


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
        job = _ra.claim_job(gs.id, addon_id, kind)
    if job is not None:
        return _ra._say(409, _ra.busy_sentence(job))
    log_action(current_user, "addon_update" if kind == "update" else "addon_settings", target=gs.name, server=gs,
               detail="%s: started%s" % (addon_id, _choice_words(choice)))
    threading.Thread(target=_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), addon_id, current_user.username, kind, choice)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTED[kind])}), 202

