"""A game server's Add-ons card: admin tools in rootless containers (panel/services/addons.py).

PERMISSION. Every route takes MANAGE_ADDONS (granted to no group by default) and access to the
server (Authorization Cheat Sheet: "Deny by Default", "Validate the Permissions on Every Request"); the
list alone also answers View add-on pages, with just the add-ons that have a web page (their Open is
routes/addon_web.py).
Install and remove are high-risk: a sign-in past the confirmation window confirms the password first
(step-up). Every install, start, stop and remove is audited with the server (Logging Cheat Sheet),
refusals included. A path that writes into, or runs code as, the game account asks first whether the
account is a plain game account (game_account_write_refusal). Root is reached only through the
helper's verbs (`apt-install`, `addon-account-prepare`, `addon-account-release`).
"""
import base64
import json
import re
import threading
import time
from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n, terminal
from panel.core.config import decrypt_secret
from panel.core.http import _json_body, _log_and_generic, _unreachable
from panel.db.models import GameDatabase, GameServer, HostDatabaseServer, claim_row, db, row_birth
from panel.ops import ssh_manager as _sm
from panel.routes import addon_web as _web, addons_change as _change, databases_net as _net
from panel.routes._shared import _reboot_holds, game_account_write_refusal, uninstall_running
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.security.auth import MANAGE_ADDONS, get_game, has_permission, log_action, server_access_required
from panel.services import addon_web as _aw, addons as _ad, reboot_words as _rw
from panel.services import addons_bluemap as _bm, b3_control as _b3c, b3_players as _b3p, geoip as _geoip

_DENIED = "Permission denied"
_UNKNOWN = "This server can't run that add-on."
_NO_DB = "Choose one of this server's databases for the add-on."
_DB_TAKEN = "Another add-on already uses that database. Each add-on needs its own."
_BUSY = "The add-on is already being installed. Wait for it to finish."
_BUSY_START = "The add-on's last start is still being watched. Wait a few seconds and try again."
_BUSY_REMOVE = "The add-on is still being installed, updated or started. Wait for it to finish, then remove it."
_BUSY_REMOVING = "The add-on is being removed. Wait for it to finish."
_BUSY_UPDATE = "The add-on is being updated. Wait for it to finish."
_BUSY_SETTINGS = "The add-on's settings are being applied. Wait for it to finish."
_BUSY_UNINSTALL = "This server is being uninstalled, with its add-ons."
# For the Databases tab and the uninstall: an add-on job on the server is still running.
ADDON_BUSY = "An add-on is being installed, updated or removed on this server. Try again once it has finished."
_INSTALLED_ALREADY = "That add-on is already installed on this server."
_NO_LOG = "Couldn't find the game's log (games_mp.log). Start the server once so it writes one, then install again."
_NO_LOG_NAMED = "Couldn't find the game's log ({log}). Start the server once so it writes one, then install again."
_NO_RCON = "The server's config sets no RCON password. Set one, then install again."
_NO_CONSOLE_LOG = ("Couldn't find the game's console.log. Add -condebug to the server's start parameters (its LinuxGSM "
                   "config's startparameters), restart the server, then install again.")
# ET: Legacy writes a game log only once g_log names one; the panel leaves the operator's config as it is.
_NO_G_LOG = ("ET: Legacy writes no game log until g_log names one. In the server's config ({cfg}), add the line "
             "set g_log \"etserver.log\" below the line exec legacy.cfg (ET: Legacy's legacy.cfg sets g_log to \"\"), "
             "restart the server, then install again.")
_G_LOG_PLAIN = ("Set g_log in the server's config to a plain file name, such as \"etserver.log\" (no folder), restart "
                "the server, then install again.")
# The same steps for an Update or Apply on an installed add-on, where "install again" would mean
# Remove, which deletes the add-on's data: the change is simply tried again.
_AGAIN = {
    _NO_LOG: "Couldn't find the game's log (games_mp.log). Start the server once so it writes one, then try again.",
    _NO_LOG_NAMED: "Couldn't find the game's log ({log}). Start the server once so it writes one, then try again.",
    _NO_CONSOLE_LOG: ("Couldn't find the game's console.log. Add -condebug to the server's start parameters (its "
                      "LinuxGSM config's startparameters), restart the server, then try again."),
    _NO_G_LOG: ("ET: Legacy writes no game log until g_log names one. In the server's config ({cfg}), add the line "
                "set g_log \"etserver.log\" below the line exec legacy.cfg (ET: Legacy's legacy.cfg sets g_log to "
                "\"\"), restart the server, then try again."),
    _G_LOG_PLAIN: ("Set g_log in the server's config to a plain file name, such as \"etserver.log\" (no folder), "
                   "restart the server, then try again."),
}
_NO_SOURCEMOD = ("B3 needs SourceMod on this game server. Install Metamod: Source and SourceMod (LinuxGSM's "
                 "mods-install), restart the server, then install again.")
_NO_PORT = "No free port was found on this host for the add-on's page or relays."
_NO_IDS = "Couldn't read the server account's user and group ids on the host."
_BAD_DB_HOST = "The database's server address can't be used for the add-on's relay."
_NO_PODMAN = "Couldn't install Podman on this host."
_NO_PREPARE = "Couldn't ready the server's account for containers (subordinate ids and lingering)."
_NO_GEOIP = "Couldn't put the country database in the add-on's folder."
_STARTED = "Installing the add-on. Downloading or building its image takes a few minutes."
_DONE = {"start": "The add-on was started.", "stop": "The add-on was stopped."}
_STARTING = "Starting the add-on. It is watched for 30 seconds to see that it stays up."
_START_DIED = ("The add-on started but stopped again within 30 seconds, so it was left stopped. Its last log lines "
               "are below.")
_NOT_DONE = {"start": "The add-on didn't start. Its log says why.", "stop": "The add-on didn't stop."}
# Above the journal's lines that are newer than the add-on's own log file (a start that died before writing to it).
_JOURNAL_NEWER = "Newer lines from the add-on's journal, written after the last line of its log file:"
_REMOVED = {True: "The add-on was removed. Its database is kept in the Databases tab.",
            False: "The add-on was removed, with its data."}
_NOT_REMOVED = "The add-on couldn't be removed completely. Try again."
# The audit's words for BlueMap's install: the admin accepted Mojang's EULA (a legal opt-in: Logging Cheat Sheet).
_EULA_AUDIT = ", Mojang's EULA (%s) accepted for Minecraft's client file" % _bm.EULA_URL

# (server id, add-on id) -> {"running": bool, "why": str, "tail": str}: an install in the background.
_JOBS = {}
_JOBS_LOCK = threading.Lock()


def _with_reason(sentence, out, err):
    """The step's sentence, then the host's own words for why (its stderr, else its output), tidy and capped.

    The step's answer is the host's text: colours stripped, whitespace collapsed (as the install's
    other reasons are shown), its last 200 characters. The sentence alone when the host said nothing.
    """
    said = " ".join(terminal.strip_escapes((err or "").strip() or out or "").split())[-200:]
    return i18n.Sentence("{step} The host said: {detail}", step=i18n.Sentence(sentence), detail=said) if said else sentence


def _say(status, sentence, **extra):
    said = i18n.tr(sentence)
    return jsonify(dict({"success": False, "error": said, "message": said}, **extra)), status


def tab_access(server):
    """For the Files & Config page (`addons_tab(server)`): whether the viewer gets the tab, and what it offers.

    Manage add-ons gets the whole tab. View add-on pages alone gets it only where an add-on with a web
    page is offered, and sees just those add-ons, each with its Open button (`manage` False).
    """
    offered = _ad.offered(getattr(server, "game_type", ""))
    manage = has_permission(current_user, MANAGE_ADDONS)
    pages = any(k in _aw.WEB for k in offered) and _web.may_view(current_user)
    return {"view": bool(offered) and (manage or pages), "manage": manage, "offered": offered}


# ── reading the host ──────────────────────────────────────────────────────────────────────────
def _db_target(r):
    """(host, port) the game's host reaches database row `r` at."""
    far = _net.row_endpoint(r)
    if far is not None:
        return far[0], far[1]
    hd = HostDatabaseServer.query.filter_by(remote_id=r.remote_id).first()
    return "127.0.0.1", (hd.port if hd is not None else None) or 3306


def _databases(gs, found):
    """The server's databases, each with the add-on that uses it ("" for none)."""
    used = {}
    for k, a in found.items():
        name = (a.get("meta") or {}).get("database")
        if isinstance(name, str) and name:
            used[name] = k
    rows = GameDatabase.query.filter_by(game_server_id=gs.id).order_by(GameDatabase.name).all()
    return [{"id": r.id, "name": r.name, "used_by": used.get(r.name, "")} for r in rows]


def busy_sentence(job):
    """The 409 sentence for an add-on job already running (`job`: its _JOBS entry)."""
    return {"start": _BUSY_START, "remove": _BUSY_REMOVING, "update": _BUSY_UPDATE, "settings": _BUSY_SETTINGS,
            "other": ADDON_BUSY, "uninstall": _BUSY_UNINSTALL}.get(job.get("kind"), _BUSY)


def claim_job(gs_id, addon_id, kind):
    """Register add-on `addon_id`'s job of `kind` on server `gs_id`. -> None, or the running job that refuses it.

    The caller holds _JOBS_LOCK. Besides the add-on's own job, a remove and the other add-ons'
    jobs on the server exclude each other: a remove that finds no other add-on's folder purges the
    account's containers and turns its user manager off, under an install of another add-on still
    in its first steps, and an install begun during the remove's account release loses its user
    manager. A start being watched is not counted (its add-on is installed, so no purge runs).
    Nothing is registered while the server is being uninstalled (which asks job_running after it
    registers, so the two never both go on).
    """
    if uninstall_running(gs_id):
        return {"kind": "uninstall"}
    own = _JOBS.get((gs_id, addon_id)) or {}
    if own.get("running"):
        return own
    if _other_job_excludes(gs_id, addon_id, kind):
        return {"kind": "other"}
    _JOBS[(gs_id, addon_id)] = {"running": True, "why": "", "tail": "", "kind": kind}
    return None


def _other_job_excludes(gs_id, addon_id, kind):
    """Whether another add-on's running job on server `gs_id` refuses this one: a remove on either side."""
    return any(sid == gs_id and other != addon_id and j.get("running")
               and (j.get("kind") == "remove" or (kind == "remove" and j.get("kind") != "start"))
               for (sid, other), j in _JOBS.items())


def job_running(gs_id):
    """Whether an add-on install, update, settings change or remove is running on server `gs_id` (the reboot census).

    Not a start being watched: that is 30 seconds, and a reboot starts the add-on again anyway.
    """
    with _JOBS_LOCK:
        return any(k[0] == gs_id and j.get("running") and j.get("kind") != "start" for k, j in _JOBS.items())


def addon_using_database(gs, name):
    """The name of the add-on on `gs` whose record names database `name`, or "" (none, or not read).

    For the Databases tab: a password reset or a delete under a running add-on (B3 keeps the
    password in its own b3.ini) silently cuts it off. One read of the account's add-on records,
    only for a game an add-on with a database is offered for; a host that cannot be read, or an
    account the panel does not read as, is "" (the database change is not held on it).
    """
    if not any(_ad.CATALOG[k]["database"] for k in _ad.offered(gs.game_type)):
        return ""
    if game_account_write_refusal(gs.remote, gs.short_name, reading=True):
        return ""
    try:
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
    except ConnectionError:
        return ""
    if rc != 0:
        return ""
    for k, a in _ad.parse_status(out)["addons"].items():
        if (a.get("meta") or {}).get("database") == name:
            return _ad.CATALOG[k]["name"]
    return ""


def _page_rows(gs, found):
    """What a viewer with View add-on pages alone sees: the installed add-ons with a web page, and their state."""
    return [{"id": k, "name": _ad.CATALOG[k]["name"], "version": _change.shown_version(k, found[k].get("meta") or {})[0],
             "installed": True, "state": found[k].get("state", ""), "web": True}
            for k in _ad.offered(gs.game_type) if k in found and k in _aw.WEB]


def _addon_rows(gs, found):
    web = _web.may_view(current_user)
    rows = []
    for k in _ad.offered(gs.game_type):
        a, got = _ad.CATALOG[k], found.get(k)
        meta = (got or {}).get("meta") or {}
        with _JOBS_LOCK:
            job = dict(_JOBS.get((gs.id, k)) or {})
        version, pending = _change.shown_version(k, meta, got is not None)
        rows.append(dict({"id": k, "name": a["name"], "version": version, "version_new": pending, "source": a["source"],
                          "legacy": a["legacy"], "needs_database": a["database"], "data_kept": a["data_kept"],
                          "installed": got is not None, "state": (got or {}).get("state", ""), "port": meta.get("port"),
                          "database": meta.get("database", ""), "installing": bool(job.get("running")),
                          "job": job.get("kind", "install") if job.get("running") else "",
                          "error": i18n.tr(job["why"]) if job.get("why") else "", "tail": job.get("tail", ""),
                          "update": _change.update_reason(k, meta) if got is not None else "",
                          "web": web and k in _aw.WEB},
                         **_extra_fields(gs, k, meta, got)))
    return rows


def _extra_fields(gs, k, meta, got):
    """The row fields of one add-on's own: B3's settings, BlueMap's licence, version and disk use."""
    if k == _ad.B3:
        return _b3_fields(gs, meta, got)
    if k == _ad.BLUEMAP:
        return _bluemap_fields(meta, got)
    return {"geolocation_option": False}


def _bluemap_fields(meta, got):
    """The row fields of BlueMap: Mojang's EULA (its link; who accepted it and when), the version, disk, threads.

    render_threads is what config/core.conf sets (None when it was not read as a whole number).
    """
    fields = {"geolocation_option": False, "eula_url": _bm.EULA_URL, "eula_by": str(meta.get("eula_accepted_by") or ""),
              "eula_at": str(meta.get("eula_accepted_at") or ""), "mc_version": str(meta.get("mc_version") or ""),
              "disk_kb": (got or {}).get("disk_kb"), "render_threads": (got or {}).get("render_threads")}
    fields.update(_game_update(meta, got))
    return fields


def _game_update(meta, got):
    """The fields that offer BlueMap an Update for the game's Minecraft version ({} when there is none).

    Offered when the game logged another version at its last start than the one the add-on's client file
    is for, and no newer image is offered already: an Update fetches that version's file.
    """
    now = _bm.mc_version((got or {}).get("mc_version"))
    had = str(meta.get("mc_version") or "")
    if not (got is not None and now and had and now != had) or _change.update_reason(_ad.BLUEMAP, meta):
        return {}
    return {"update": "game", "mc_version_now": now}


# SoF2's and ET's B3 parsers have no private message: every reply is said to the whole server (vps-b3
# rounds 3 and 3d; ET: Legacy uses the same et parser).
_PUBLIC_REPLIES = {"sof2": "On Soldier of Fortune 2, B3 has no private messages: every reply is said in public chat.",
                   "wet": "On Wolfenstein: Enemy Territory, B3 has no private messages: every reply is said in public "
                          "chat.",
                   "etl": "On ET: Legacy, B3 has no private messages: every reply is said in public chat."}


def _b3_fields(gs, meta, got=None):
    """B3's row fields: its geolocation and plugins as set, what the card may switch, its notes and credit.

    An installed B3 also gets what it says of itself (b3_control.card: health, an exit code in words, the
    version it runs, Panel actions and purge_aliases_days as b3.ini sets them) and whether this server
    sends alerts for its bans and kicks.
    """
    geo = _ad.geo_mode(meta.get("geolocation"))
    own = _b3c.card(got["b3"], got.get("state", "")) if got is not None and "b3" in got else {}
    if own.get("stale_minutes"):
        own["stale"] = i18n.tr(_b3c.stale_sentence(own["stale_minutes"]))
    return dict({"geolocation_option": True, "geolocation": geo, "geo_modes": list(_ad.GEO_MODES),
                 "plugins": [x for x in meta.get("plugins") or _ad.B3_PLUGINS if isinstance(x, str)],
                 "switchable": list(_ad.B3_SWITCHABLE), "geo_switchable": list(_ad.B3_GEO_SWITCHABLE),
                 "own_plugins": meta.get("own_plugins") is True, "own_plugins_dir": _ad.B3_OWN_PLUGINS,
                 "geoip": meta.get("geoip", "") if geo == _ad.GEO_OFFLINE else "",
                 "credit": _geoip.CREDIT, "alerts": bool(getattr(gs, "b3_alerts", False)),
                 # Offline needs DB-IP's database: with its Outside services switch off, the card says so.
                 "geoip_off": "" if _geoip.download_allowed() else i18n.tr(_geoip.OFF),
                 "note": i18n.tr(_PUBLIC_REPLIES[gs.game_type]) if gs.game_type in _PUBLIC_REPLIES else ""}, **own)


def _db_host_state(gs, rows, dbs):
    """Whether the host has a database server, for an add-on that needs a database and has none free.

    "none" only when the Databases tab's own last look found none (it then offers to set one up
    first); "" otherwise, or when no add-on is waiting on a database. Read from what the panel
    stored (databases.host_state without a probe), so the tab asks nothing more of the host.
    """
    if not any(r["needs_database"] for r in rows) or any(not d["used_by"] for d in dbs):
        return ""
    if _net.endpoint_for_host(gs.remote_id) is not None:
        return ""
    from panel.routes import databases as _dbr   # it imports this module: read at call time
    return "none" if _dbr.host_state(gs.remote, may_probe=False)[0] == "none" else ""


def _status_answer(gs):
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
    if rc != 0:
        return _say(200, "Couldn't read this server's add-ons: the host did not answer. Try again.", unread=True)
    st = _ad.parse_status(out)
    _b3p.remember(gs.id, st["addons"])   # the B3 players section reads B3's database by this name
    if not has_permission(current_user, MANAGE_ADDONS):
        return jsonify({"success": True, "manage": False, "addons": _page_rows(gs, st["addons"])})
    why = _ad.runtime_refusal(st["os"], st["podman"])
    rows, dbs = _addon_rows(gs, st["addons"]), _databases(gs, st["addons"])
    return jsonify({"success": True, "manage": True, "addons": rows, "databases": dbs, "podman": st["podman"],
                    "db_host": _db_host_state(gs, rows, dbs), "runtime_error": i18n.tr(why) if why else ""})


# ── install, in the background ────────────────────────────────────────────────────────────────
def _apt_install(remote):
    """Podman and its two helpers from Ubuntu's archive (universe added once if apt can't find them).

    "" once they are installed, else _NO_PODMAN with apt's own last words.
    """
    if _sm.run_privileged(remote, "apt-install", list(_ad.PACKAGES), timeout=900)[2] == 0:
        return ""
    _sm.run_privileged(remote, "apt-add-repo", ["universe"], timeout=300)
    _sm.run_privileged(remote, "apt-update", [], timeout=300)
    out, err, rc = _sm.run_privileged(remote, "apt-install", list(_ad.PACKAGES), timeout=900)
    return "" if rc == 0 else _with_reason(_NO_PODMAN, out, err)


def _taken(p, addon_id):
    """The databases the account's other add-ons use, by name."""
    return {(a.get("meta") or {}).get("database") for k, a in p["addons"].items() if k != addon_id}


def _no_log(gs, p):
    """What to do when the game's log was not found: start the server once, (Source) add -condebug, or set g_log."""
    if gs.game_type in _ad.G_LOG_DIR:
        return _no_g_log(gs, p["log_name"])
    name = _ad.game_log_name(gs.game_type)
    if name == "console.log":
        return _NO_CONSOLE_LOG
    return _NO_LOG if name == "games_mp.log" else i18n.Sentence(_NO_LOG_NAMED, log=name)


def _no_g_log(gs, name):
    """What to do when ET: Legacy's log was not found: set g_log, make it a plain file name, or start the server."""
    if not name:
        return i18n.Sentence(_NO_G_LOG, cfg=_ad.game_cfg(gs.game_type, gs.lgsm_name))
    if not _ad.plain_log_name(name):
        return _G_LOG_PLAIN
    return i18n.Sentence(_NO_LOG_NAMED, log="%s/%s" % (_ad.G_LOG_DIR[gs.game_type], name))


def _log_refusal(gs, p):
    """Why the game's log can't be read ("" when it can): it is there, in a folder the unit can name."""
    return "" if p["log_found"] and _ad.log_dir(gs.short_name, p["logdir"]) else _no_log(gs, p)


def change_log_refusal(gs, p):
    """_log_refusal for an Update or Apply: the same steps, ending "then try again" rather than "install again"."""
    why = _log_refusal(gs, p)
    if isinstance(why, i18n.Sentence):
        return i18n.Sentence(_AGAIN.get(why.template, why.template), **why.vals)
    return _AGAIN.get(why, why)


def _host_refusal(gs, p, need_ports):
    """Why the host or the game stops the install: no game log, no SourceMod, no RCON, no port, no free ports.

    Sets p["game_port"]: the port the game really listens on (services/addons.game_port).
    """
    p["game_port"], why = _ad.game_port(gs.game_type, gs.port, p.get("udp") or [])
    if why:
        return why
    why = _log_refusal(gs, p)
    if why:
        return why
    if gs.game_type in _ad.SOURCEMOD_DIR and not p.get("sourcemod"):
        return _NO_SOURCEMOD
    if not p["rcon"]:
        return p["rcon_why"] or _NO_RCON
    if p["ids"] is None:
        return _NO_IDS
    return "" if len(p["ports"]) >= need_ports else _NO_PORT


def world_refusal(p, need_ports):
    """Why the host or the world stops BlueMap: no usable world or version, no ids, no free port ("" when none).

    Sets p["game_port"] to None: BlueMap reaches nothing of the game.
    """
    p["game_port"] = None
    if p["world"]["why"]:
        return p["world"]["why"]
    if p["ids"] is None:
        return _NO_IDS
    return "" if len(p["ports"]) >= need_ports else _NO_PORT


def _install_refusal(gs, plan, p):
    """Why the probe's answer stops the install ("" when it may go on)."""
    if p["installed"]:
        return _INSTALLED_ALREADY
    if plan["id"] == _ad.BLUEMAP:
        return _ad.runtime_refusal(p["os"], p["podman"]) or world_refusal(p, plan["ports"])
    r = plan["db"]
    if r is not None and r.name in _taken(p, plan["id"]):
        return _DB_TAKEN
    if plan["id"] == _ad.B3 and p["rcon"]:
        why = _ad.b3_ini_refusal(p["rcon"])
        if why:
            return why
    return _ad.runtime_refusal(p["os"], p["podman"]) or _host_refusal(gs, p, plan["ports"])


def _runtime(gs, p):
    """Podman on the host and the account readied: "" when both are done, else why not."""
    why = "" if p["podman"] else _apt_install(gs.remote)
    if why:
        return why
    # On the panel's own host the helper readies only an account in its game group, and an account
    # can be outside it (one made before the group existed, or by a per-user install, whose
    # sudoers grant never named the group). Enrolled first, with gameuser-group's own checks (it
    # refuses an account that can reach root); a remote host's form needs no group (enrol skips it).
    refused = _sm.enrol_game_user(gs.remote, gs.short_name)
    if refused:
        return _with_reason(_NO_PREPARE, "", refused)
    out, err, rc = _sm.run_privileged(gs.remote, "addon-account-prepare", [gs.short_name], timeout=60)
    return "" if rc == 0 else _with_reason(_NO_PREPARE, out, err)


# A relay's target goes into a unit file: an address or a host name, nothing that could break the line.
_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


def _plan(gs, addon_id, db_id, geolocation):
    """What the install needs before it reads the host: the database row and its endpoint, the ports."""
    r = db.session.get(GameDatabase, db_id) if db_id is not None else None
    host, port = _db_target(r) if r is not None else ("", 0)
    nrelays = (1 if r is not None and host != "127.0.0.1" else 0) + (
        len(_ad.B3_GEOLOCATORS) if _ad.geo_mode(geolocation) == _ad.GEO_ONLINE else 0)
    return {"id": addon_id, "db": r, "db_host": host, "db_port": port, "geolocation": geolocation,
            "ports": (1 if _ad.CATALOG[addon_id]["web_port"] else 0) + nrelays}


def _settings(gs, plan, p):
    """(the secret settings file's text, the other files, the secrets to scrub) for this add-on."""
    if plan["id"] == _ad.IW4MADMIN:
        return _ad.iw4madmin_settings(gs.game_type, p["game_port"], p["rcon"]), _ad.iw4madmin_files(), (p["rcon"],)
    r = plan["db"]
    secret = decrypt_secret(r.secret) or ""
    ini = _ad.b3_ini(gs.game_type, p["game_port"], p["rcon"], r.name, secret, plan["geolocation"],
                     log_name=p["log_name"])
    files = _ad.build_files(plan["id"])
    if _ad.geo_mode(plan["geolocation"]) != _ad.GEO_OFF:
        files[_ad.B3_GEO_INI] = _ad.geolocation_ini("", plan["geolocation"])
    return ini, files, (secret, p["rcon"])


def game_reads(gs, addon_id, p):
    """Quadlet's `logdir`: the game log's folder, or for BlueMap its World (the worlds' mounts and the version)."""
    if _ad.CATALOG[addon_id]["reads"] == "world":
        return _bm.world(gs.short_name, p["world"])
    return _ad.log_dir(gs.short_name, p["logdir"])


def _install_texts(gs, plan, p, who):
    """(settings, files, unit, relay units, record, secrets) the install writes."""
    addon_id = plan["id"]
    web = p["ports"][0] if _ad.CATALOG[addon_id]["web_port"] else None
    relay_list = _ad.relays(addon_id, plan["db_host"], plan["db_port"], plan["geolocation"],
                            p["ports"][1 if web else 0:])
    local_db = plan["db_port"] if plan["db"] is not None and plan["db_host"] == "127.0.0.1" else None
    net = _ad.network(p["game_port"], local_db, relay_list, p["splice"], gs.game_type in _ad.RCON_TCP_GAMES)
    unit = _ad.quadlet(gs.short_name, addon_id, game_reads(gs, addon_id, p), net, web, relay_list, p["ids"])
    when = datetime.now(timezone.utc).isoformat(timespec="seconds")
    settings, files, secrets = _settings(gs, plan, p) if addon_id != _ad.BLUEMAP else _bluemap_settings(p, who, when)
    meta = json.dumps(dict(record(addon_id, plan["geolocation"], list(_ad.B3_PLUGINS), plan.get("geoip", "")),
                           database=plan["db"].name if plan["db"] is not None else "", port=web, network=net,
                           game_port=p["game_port"], installed_at=when, installed_by=who,
                           **_bluemap_record(addon_id, p, who, when))) + "\n"
    return settings, files, unit, _ad.relay_units(addon_id, relay_list), meta, secrets


def _bluemap_settings(p, who, when):
    """The settings BlueMap gets: (core.conf, the other config files, no secrets); core.conf records the EULA's acceptance."""
    return _bm.core_conf(who, when), _bm.config_files(p["world"]), ()


def _bluemap_record(addon_id, p, who, when):
    """The record's BlueMap fields: the world and Minecraft version it renders, and who accepted Mojang's EULA when."""
    if addon_id != _ad.BLUEMAP:
        return {}
    w = p["world"]
    return {"world": w["level"], "mc_version": w["version"], "eula_url": _bm.EULA_URL, "eula_accepted_by": who,
            "eula_accepted_at": when}


def record(addon_id, geolocation, plugins, geoip="", own_plugins=False):
    """The addon.json fields that say what is installed and how it is set.

    image and version: what the catalog pinned at the time (an update compares them); B3's commit, its
    geolocation mode, the plugins the card turned on, the month of the country database it was given,
    and whether its own-plugins folder is mounted.
    """
    rec = {"kind": addon_id, "version": _ad.CATALOG[addon_id]["version"], "image": _ad.CATALOG[addon_id]["image"]}
    if addon_id == _ad.B3:
        rec.update(commit=_ad.B3_COMMIT, geolocation=_ad.geo_mode(geolocation), plugins=list(plugins), geoip=geoip,
                   own_plugins=bool(own_plugins))
    return rec


def push_geoip(gs, addon_id):
    """Put this month's country database in the add-on's geoip folder: (its month, "") or ("", why not)."""
    path, month, why = _geoip.latest()
    if path is None:
        return "", why or _geoip.UNREACHABLE
    with open(path, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.geoip_put_sh(gs.short_name, addon_id),
                                          timeout=300, stdin_text=b64)
    if rc != 0 or "GEOIP_PUT" not in (out or ""):
        return "", _with_reason(_NO_GEOIP, out, err)
    return month, ""


def _plan_refusal(gs, plan):
    """Why the plan itself stops the install: no database of this server, or one no relay can name."""
    r = plan["db"]
    if _ad.CATALOG[plan["id"]]["database"] and (r is None or r.game_server_id != gs.id):
        return _NO_DB
    if r is not None and plan["db_host"] != "127.0.0.1" and not _HOST_RE.fullmatch(plan["db_host"] or ""):
        return _BAD_DB_HOST
    return ""


def probe_answer(gs, addon_id, out):
    """The probe's answer as a dict (parse_probe's, with the RCON password the game reads, and BlueMap's world)."""
    p = dict(_ad.parse_probe(out, gs.game_type), addons=_ad.parse_status(out)["addons"])
    p["rcon"], p["rcon_why"] = _ad.game_rcon(gs.game_type, p["rcon_lines"])
    if _ad.CATALOG[addon_id]["reads"] == "world":
        p["world"] = _bm.parse_world(_ad.kv_lines(out), _ad._unb64)
    return p


def _fetches(gs, plan, p):
    """What the install fetches before it writes anything (why not, or ""): B3's country database, BlueMap's client file.

    For BlueMap, the client jar's address and SHA-1 from Mojang's version list (plan["client"]); the
    game's host downloads the jar itself in install_sh (addons_bluemap.client_sh).
    """
    if _ad.geo_mode(plan["geolocation"]) == _ad.GEO_OFFLINE:
        plan["geoip"], why = push_geoip(gs, plan["id"])
        return why
    if plan["id"] == _ad.BLUEMAP:
        url, sha1, why = _bm.client_download(p["world"]["version"])
        plan["client"] = (url, sha1)
        return why
    return ""


def client_step(gs, addon_id, version, client, fresh_webapp=False):
    """The install's or update's extra shell: BlueMap's client file for `version` (`client`: url, sha1), else ""."""
    if addon_id != _ad.BLUEMAP or not client:
        return ""
    return _bm.client_sh(_ad.addon_dir(gs.short_name, addon_id), version, client[0], client[1], fresh_webapp)


def _install_steps(gs, plan, who):
    """The install itself: ("", "") when the add-on runs, else (why, log tail); why is an English sentence."""
    why = _plan_refusal(gs, plan)
    if why:
        return why, ""
    out, err, rc = _sm.shell_as_game_user(
        gs.remote, gs.short_name,
        _ad.probe_sh(plan["id"], gs.lgsm_name, gs.id, gs.game_type, plan["ports"]) + "; " + _ad.status_sh(),
        timeout=60, selfname=gs.lgsm_name)
    if rc != 0:
        return _with_reason("Couldn't read the server's account on the host: it did not answer.", "", err), ""
    p = probe_answer(gs, plan["id"], out)
    why = _install_refusal(gs, plan, p) or _runtime(gs, p) or _fetches(gs, plan, p)
    if why:
        return why, ""
    settings, files, unit, units, meta, secrets = _install_texts(gs, plan, p, who)
    extra = client_step(gs, plan["id"], (p.get("world") or {}).get("version"), plan.get("client"))
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name,
                                           _ad.install_sh(gs.short_name, plan["id"], unit, meta, files, units, extra),
                                           timeout=_ad.INSTALL_TIMEOUT, selfname=gs.lgsm_name, stdin_text=settings)
    ok, said, tail = _ad.install_outcome(_ad.scrub(out or "", secrets), rc)
    return ("", "") if ok else (said, _ad.scrub(tail, secrets))


def _install_worker(app, gs_id, born, plan_args, who):
    """Run one install in a thread, record how it went, and audit it."""
    addon_id = plan_args[0]
    with app.app_context():
        why, tail = "", ""
        try:
            gs = claim_row(GameServer, gs_id, born)
            if gs is not None:
                why, tail = _install_steps(gs, _plan(gs, *plan_args), who)
                log_action(None, "addon_install", target=gs.name, actor=who, server=gs, success=not why,
                           detail="%s installed" % addon_id if not why else "%s not installed: %s" % (addon_id, why))
        except Exception:
            why = _log_and_generic("add-on install failed")
        finally:
            with _JOBS_LOCK:
                _JOBS[(gs_id, addon_id)] = {"running": False, "why": why, "tail": tail}


def _install_choice(gs, addon_id):
    """(database id or None, geolocation) from the request, or a refusal answer."""
    body = _json_body()
    geolocation = _ad.geo_mode(body.get("geolocation")) if addon_id == _ad.B3 else _ad.GEO_OFF
    if addon_id == _ad.BLUEMAP and body.get("accept_eula") is not True:
        # Accepting Mojang's EULA is the admin's own act (BlueMap's accept-download): never assumed.
        return None, _say(400, _bm.NO_EULA)
    if not _ad.CATALOG[addon_id]["database"]:
        return (None, geolocation), None
    db_id = body.get("database_id")
    if not isinstance(db_id, int) or isinstance(db_id, bool):
        return None, _say(400, _NO_DB)
    r = db.session.get(GameDatabase, db_id)
    if r is None or r.game_server_id != gs.id:
        return None, _say(400, _NO_DB)
    return (db_id, geolocation), None


def _install_answer(app, gs, addon_id):
    choice, refused = _install_choice(gs, addon_id)
    if refused is not None:
        return refused
    db_id, geolocation = choice
    with _JOBS_LOCK:
        job = claim_job(gs.id, addon_id, "install")
    if job is not None:
        return _say(409, busy_sentence(job))
    r = db.session.get(GameDatabase, db_id) if db_id is not None else None
    log_action(current_user, "addon_install", target=gs.name, server=gs,
               detail="%s: started%s%s%s" % (addon_id, ", database %s" % r.name if r is not None else "",
                                             ", geolocation %s" % geolocation if geolocation != _ad.GEO_OFF else "",
                                             _EULA_AUDIT if addon_id == _ad.BLUEMAP else ""))
    threading.Thread(target=_install_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), (addon_id, db_id, geolocation), current_user.username)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTED)}), 202


# ── start, stop, remove, logs ─────────────────────────────────────────────────────────────────
def _masked(gs, text, rcon):
    """`text` with the server's database passwords and the RCON passwords `rcon` masked (scrub).

    The RCON ones are what the same shell read (_ad.read_secrets): the game config's and b3.ini's.
    """
    secrets = [decrypt_secret(r.secret) or "" for r in GameDatabase.query.filter_by(game_server_id=gs.id).all()]
    return _ad.scrub(text, secrets + rcon)


def _start_steps(gs, addon_id):
    """The card's Start and its watch: ("", "") when the add-on stays up, else (why, its log's last lines, masked)."""
    sh = _ad.start_sh(gs.short_name, addon_id, _ad.game_cfg(gs.game_type, gs.lgsm_name))
    out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=_ad.ACTION_TIMEOUT + _ad.SETTLE_SECONDS)
    ok, mark, tail = _ad.start_outcome(out, rc)
    if ok:
        return "", ""
    said = {"ADDON_START_LIMIT": _ad.START_LIMIT, "ADDON_DIED": _START_DIED}.get(mark, _NOT_DONE["start"])
    return _with_reason(said, "", err) if mark != "ADDON_DIED" else said, _masked(gs, tail, _ad.read_secrets(out)[0])


def _stop_in_watch(gs_id, addon_id, on):
    """Mark (or unmark) a running Start's watch as stopped from the card; False when no Start is being watched."""
    with _JOBS_LOCK:
        job = _JOBS.get((gs_id, addon_id)) or {}
        if not (job.get("running") and job.get("kind") == "start"):
            return False
        job["stopped"] = on
        return True


def _await_start(gs_id, addon_id):
    """Wait, at most SETTLE_SECONDS, for a watched Start to see the card's Stop and end.

    The watch notices within its 2-second poll; until then a Start sent after the Stop was refused as busy.
    """
    end = time.monotonic() + _ad.SETTLE_SECONDS
    while time.monotonic() < end:
        with _JOBS_LOCK:
            if not (_JOBS.get((gs_id, addon_id)) or {}).get("running"):
                return
        time.sleep(0.5)


def _start_said(gs_id, addon_id, why, tail):
    """(why, tail, the audit's words) for a Start's outcome.

    A watch that saw the add-on stop because the card's Stop asked for it (VPS round E, O-E2) is not a failure.
    """
    with _JOBS_LOCK:
        stopped = why == _START_DIED and (_JOBS.get((gs_id, addon_id)) or {}).get("stopped")
    if stopped:
        return "", "", "stopped from the card during the start's watch"
    return why, tail, "done" if not why else "failed: %s" % why


def _start_worker(app, gs_id, born, addon_id, who):
    """Run the card's Start in a thread and audit it; a failure stays on the job (the card's error and log tail)."""
    with app.app_context():
        why, tail = "", ""
        try:
            gs = claim_row(GameServer, gs_id, born)
            if gs is not None:
                why, tail, said = _start_said(gs_id, addon_id, *_start_steps(gs, addon_id))
                log_action(None, "addon_start", target=gs.name, actor=who, server=gs, success=not why,
                           detail="%s %s" % (addon_id, said))
        except Exception:
            why = _log_and_generic("add-on start failed")
        finally:
            with _JOBS_LOCK:     # a start that stays up leaves no job: an earlier failure no longer applies
                if why:
                    _JOBS[(gs_id, addon_id)] = {"running": False, "why": why, "tail": tail, "kind": "start"}
                else:
                    _JOBS.pop((gs_id, addon_id), None)


def _start_answer(app, gs, addon_id):
    """Start the add-on in the background, watched as an install's start is (or refuse: a job is running)."""
    with _JOBS_LOCK:
        job = claim_job(gs.id, addon_id, "start")
    if job is not None:
        return _say(409, busy_sentence(job))
    threading.Thread(target=_start_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), addon_id, current_user.username)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTING)}), 202


def _clear_job(gs_id, addon_id):
    """Forget a finished job's failure: it no longer describes an add-on that runs now."""
    with _JOBS_LOCK:
        job = _JOBS.get((gs_id, addon_id))
        if job is not None and not job.get("running"):
            _JOBS.pop((gs_id, addon_id), None)


def _action_answer(app, gs, addon_id, action):
    if action == "start":
        return _start_answer(app, gs, addon_id)
    watched = _stop_in_watch(gs.id, addon_id, True)     # before the stop, so the watch can't see it first
    out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.action_sh(addon_id, action),
                                          timeout=_ad.ACTION_TIMEOUT)
    ok = rc == 0
    if watched and ok:
        _await_start(gs.id, addon_id)
    elif watched:
        _stop_in_watch(gs.id, addon_id, False)
    why = "" if ok else _with_reason(_NOT_DONE[action], out, err)
    if ok:
        _clear_job(gs.id, addon_id)
    log_action(current_user, "addon_stop", target=gs.name, server=gs, success=ok,
               detail="%s %s" % (addon_id, "done" if ok else "failed (rc %s): %s" % (rc, why)))
    if not ok:
        return _say(200, why)
    return jsonify({"success": True, "message": i18n.tr(_DONE[action])})


def _remove_answer(gs, addon_id):
    # An install, update or settings change still running would write its unit and relays again
    # after the remove, leaving an auto-starting unit for an add-on the card calls not installed.
    # The remove is a job itself while it runs, so an install, update, settings change or start
    # begun meanwhile is refused too (it would write the unit back, or lose its folder to rm -rf).
    with _JOBS_LOCK:
        job = claim_job(gs.id, addon_id, "remove")
    if job is not None:
        return _say(409, {"remove": _BUSY_REMOVING, "other": ADDON_BUSY, "uninstall": _BUSY_UNINSTALL}
                    .get(job.get("kind"), _BUSY_REMOVE))
    try:
        out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.remove_sh(gs.short_name, addon_id),
                                              timeout=_ad.ACTION_TIMEOUT)
        removed, others = _ad.remove_outcome(out, rc)
        if removed and not others:
            # The account runs no add-on any more: its user manager need not linger. Best-effort,
            # and still part of the job: an install begun before it ends would lose its user manager.
            # A host lost here leaves the remove done: it is still audited and answered "removed".
            try:
                _sm.run_privileged(gs.remote, "addon-account-release", [gs.short_name, "keep"], timeout=90)
            except ConnectionError:
                _log_and_generic("add-on account release after a remove")
    finally:
        with _JOBS_LOCK:
            _JOBS.pop((gs.id, addon_id), None)
    why = "" if removed else _with_reason(_NOT_REMOVED, "", err)
    log_action(current_user, "addon_remove", target=gs.name, server=gs, success=removed,
               detail="%s %s" % (addon_id, "removed" if removed else "not removed (rc %s): %s" % (rc, why)))
    if not removed:
        return _say(200, why)
    return jsonify({"success": True, "message": i18n.tr(_REMOVED[_ad.CATALOG[addon_id]["data_kept"]])})


def _logs_answer(gs, addon_id):
    sh = _ad.logs_sh(gs.short_name, addon_id, _ad.game_cfg(gs.game_type, gs.lgsm_name))
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, sh, timeout=30)
    if rc != 0:
        return _say(200, "Couldn't read the add-on's log: the host did not answer. Try again.")
    rcon, log = _ad.read_secrets(out)
    log, journal = _ad.split_journal(log)
    if journal:
        log = "%s\n\n%s\n%s" % (log, i18n.tr(_JOURNAL_NEWER), journal)
    return jsonify({"success": True, "log": _masked(gs, log, rcon)})


def _account_refusal(gs, what, reading):
    """The root-capable-account guard for a command run as the server's account; audited when it refuses."""
    why = game_account_write_refusal(gs.remote, gs.short_name, reading=reading)
    if why:
        log_action(current_user, "addon_refused", target=gs.name, server=gs, success=False,
                   detail="%s: %s" % (what, why))
    return why


def _guarded(server_id, addon_id, answer, reading=False):
    """Run `answer(gs)` for one of the server's offered add-ons, once the account has been asked about."""
    gs = get_game(server_id)
    if addon_id is not None and addon_id not in _ad.offered(gs.game_type):
        return _say(404, _UNKNOWN)
    why = _account_refusal(gs, addon_id or "add-ons", reading)
    if why:
        return _say(200, why)
    if not reading and _reboot_holds(gs):
        # The reboot's census has been taken: a job started now is never seen by it, and the
        # reboot would cut the install, image build or restart off part way.
        why = _rw.busy_message(gs.remote.display_name)
        log_action(current_user, "addon_refused", target=gs.name, server=gs, success=False,
                   detail="%s: %s" % (addon_id, why))
        return _say(409, why)
    try:
        return answer(gs)
    except ConnectionError:
        return _unreachable("reach the server's host")


def register(app):
    """Register the Add-ons card's routes, its pages' proxy (addon_web) and the template's `addons_tab(server)`."""
    app.jinja_env.globals["addons_tab"] = tab_access
    _web.register(app)

    @app.route("/api/server/<int:server_id>/addons")
    @login_required
    @server_access_required
    def api_server_addons(server_id):
        """The add-ons this server can run, which are installed and running, and its databases.

        With View add-on pages and not Manage add-ons: only the installed add-ons with a web page.
        """
        if not (has_permission(current_user, MANAGE_ADDONS) or _web.may_view(current_user)):
            return _say(403, _DENIED)
        return _guarded(server_id, None, _status_answer, reading=True)

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/install", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_install(server_id, addon_id):
        """Install an add-on (in the background): Podman if needed, then the add-on's container."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if step_up_needed():          # root installs on the host and the RCON password: confirm first
            return step_up_refusal()
        return _guarded(server_id, addon_id, lambda gs: _install_answer(app, gs, addon_id))

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/update", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_update(server_id, addon_id):
        """Update an installed add-on to the catalog's image (in the background), keeping its data and settings."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if step_up_needed():          # a new image runs as the game account: confirm first, as for install
            return step_up_refusal()
        return _guarded(server_id, addon_id, lambda gs: _change.start(app, gs, addon_id, "update"))

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/settings", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_settings(server_id, addon_id):
        """Apply B3's settings (geolocation, plugins) and restart it (in the background)."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if step_up_needed():          # geolocation can send players' addresses out: confirm first
            return step_up_refusal()
        return _guarded(server_id, addon_id, lambda gs: _change.start(app, gs, addon_id, "settings"))

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/<action>", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_action(server_id, addon_id, action):
        """Start or stop an installed add-on."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if action not in _DONE:
            return _say(404, _UNKNOWN)
        return _guarded(server_id, addon_id, lambda gs: _action_answer(app, gs, addon_id, action))

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/remove", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_remove(server_id, addon_id):
        """Remove an add-on: its container, image, unit and folder (its database stays)."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if step_up_needed():
            return step_up_refusal()
        return _guarded(server_id, addon_id, lambda gs: _remove_answer(gs, addon_id))

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/logs")
    @login_required
    @server_access_required
    def api_server_addon_logs(server_id, addon_id):
        """The add-on's last log lines (database passwords masked)."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        return _guarded(server_id, addon_id, lambda gs: _logs_answer(gs, addon_id), reading=True)

    from panel.routes import addons_b3   # it imports this module: read at call time
    addons_b3.register(app)
