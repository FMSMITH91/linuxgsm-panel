"""A game server's Add-ons card: admin tools in rootless containers (panel/services/addons.py).

PERMISSION. Every route takes MANAGE_ADDONS (granted to no group by default) and access to the
server (Authorization Cheat Sheet: "Deny by Default", "Validate the Permissions on Every Request").
Install and remove are high-risk: a sign-in past the confirmation window confirms the password first
(step-up). Every install, start, stop and remove is audited with the server (Logging Cheat Sheet),
refusals included. A path that writes into, or runs code as, the game account asks first whether the
account is a plain game account (game_account_write_refusal). Root is reached only through the
helper's verbs (`apt-install`, `addon-account-prepare`, `addon-account-release`).
"""
import json
import re
import threading
from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n, terminal
from panel.core.config import decrypt_secret
from panel.core.http import _json_body, _log_and_generic, _unreachable
from panel.db.models import GameDatabase, GameServer, HostDatabaseServer, claim_row, db, row_birth
from panel.ops import ssh_manager as _sm
from panel.routes import databases_net as _net
from panel.routes._shared import game_account_write_refusal
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.security.auth import MANAGE_ADDONS, get_game, has_permission, log_action, server_access_required
from panel.services import addons as _ad

_DENIED = "Permission denied"
_UNKNOWN = "This server can't run that add-on."
_NO_DB = "Choose one of this server's databases for the add-on."
_DB_TAKEN = "Another add-on already uses that database. Each add-on needs its own."
_BUSY = "The add-on is already being installed. Wait for it to finish."
_INSTALLED_ALREADY = "That add-on is already installed on this server."
_NO_LOG = "Couldn't find the game's log (games_mp.log). Start the server once so it writes one, then install again."
_NO_RCON = "The server's config sets no RCON password. Set one, then install again."
_NO_PORT = "No free port was found on this host for the add-on's page or relays."
_NO_IDS = "Couldn't read the server account's user and group ids on the host."
_BAD_DB_HOST = "The database's server address can't be used for the add-on's relay."
_NO_PODMAN = "Couldn't install Podman on this host."
_NO_PREPARE = "Couldn't ready the server's account for containers (subordinate ids and lingering)."
_STARTED = "Installing the add-on. Downloading or building its image takes a few minutes."
_DONE = {"start": "The add-on was started.", "stop": "The add-on was stopped."}
_NOT_DONE = {"start": "The add-on didn't start. Its log says why.", "stop": "The add-on didn't stop."}
_REMOVED = {True: "The add-on was removed. Its database is kept in the Databases tab.",
            False: "The add-on was removed, with its data."}
_NOT_REMOVED = "The add-on couldn't be removed completely. Try again."

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
    """For the Files & Config page (`addons_tab(server)`): whether the viewer gets the tab, and what it offers."""
    offered = _ad.offered(getattr(server, "game_type", ""))
    return {"view": bool(offered) and has_permission(current_user, MANAGE_ADDONS), "offered": offered}


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


def _addon_rows(gs, found):
    rows = []
    for k in _ad.offered(gs.game_type):
        a, got = _ad.CATALOG[k], found.get(k)
        meta = (got or {}).get("meta") or {}
        with _JOBS_LOCK:
            job = dict(_JOBS.get((gs.id, k)) or {})
        rows.append({"id": k, "name": a["name"], "version": a["version"], "source": a["source"],
                     "legacy": a["legacy"], "needs_database": a["database"], "data_kept": a["data_kept"],
                     "geolocation_option": k == _ad.B3, "geolocation": bool(meta.get("geolocation")),
                     "installed": got is not None, "state": (got or {}).get("state", ""), "port": meta.get("port"),
                     "database": meta.get("database", ""), "installing": bool(job.get("running")),
                     "error": i18n.tr(job["why"]) if job.get("why") else "", "tail": job.get("tail", "")})
    return rows


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
    why = _ad.runtime_refusal(st["os"], st["podman"])
    rows, dbs = _addon_rows(gs, st["addons"]), _databases(gs, st["addons"])
    return jsonify({"success": True, "addons": rows, "databases": dbs, "podman": st["podman"],
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


def _host_refusal(gs, p, need_ports):
    """Why the host or the game stops the install: no game log, no RCON, not enough free ports."""
    if not _ad.log_dir(gs.short_name, p["logdir"]):
        return _NO_LOG
    if not p["rcon"]:
        return p["rcon_why"] or _NO_RCON
    if p["ids"] is None:
        return _NO_IDS
    return "" if len(p["ports"]) >= need_ports else _NO_PORT


def _install_refusal(gs, plan, p):
    """Why the probe's answer stops the install ("" when it may go on)."""
    if p["installed"]:
        return _INSTALLED_ALREADY
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
        len(_ad.B3_GEOLOCATORS) if geolocation else 0)
    return {"id": addon_id, "db": r, "db_host": host, "db_port": port, "geolocation": geolocation,
            "ports": (1 if _ad.CATALOG[addon_id]["web_port"] else 0) + nrelays}


def _settings(gs, plan, p):
    """(the secret settings file's text, the other files, the secrets to scrub) for this add-on."""
    if plan["id"] == _ad.IW4MADMIN:
        return _ad.iw4madmin_settings(gs.game_type, gs.port, p["rcon"]), _ad.iw4madmin_files(), (p["rcon"],)
    r = plan["db"]
    secret = decrypt_secret(r.secret) or ""
    ini = _ad.b3_ini(gs.game_type, gs.port, p["rcon"], r.name, secret, plan["geolocation"])
    return ini, _ad.build_files(plan["id"]), (secret, p["rcon"])


def _install_texts(gs, plan, p, who):
    """(settings, files, unit, relay units, record, secrets) the install writes."""
    addon_id = plan["id"]
    web = p["ports"][0] if _ad.CATALOG[addon_id]["web_port"] else None
    relay_list = _ad.relays(addon_id, plan["db_host"], plan["db_port"], plan["geolocation"],
                            p["ports"][1 if web else 0:])
    local_db = plan["db_port"] if plan["db"] is not None and plan["db_host"] == "127.0.0.1" else None
    net = _ad.network(gs.port, local_db, relay_list, p["splice"])
    unit = _ad.quadlet(gs.short_name, addon_id, _ad.log_dir(gs.short_name, p["logdir"]), net, web, relay_list,
                       p["ids"])
    settings, files, secrets = _settings(gs, plan, p)
    meta = json.dumps({"kind": addon_id, "version": _ad.CATALOG[addon_id]["version"],
                       "image": _ad.CATALOG[addon_id]["image"],
                       "database": plan["db"].name if plan["db"] is not None else "", "port": web,
                       "geolocation": bool(plan["geolocation"]), "network": net,
                       "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "installed_by": who}) + "\n"
    return settings, files, unit, _ad.relay_units(addon_id, relay_list), meta, secrets


def _plan_refusal(gs, plan):
    """Why the plan itself stops the install: no database of this server, or one no relay can name."""
    r = plan["db"]
    if _ad.CATALOG[plan["id"]]["database"] and (r is None or r.game_server_id != gs.id):
        return _NO_DB
    if r is not None and plan["db_host"] != "127.0.0.1" and not _HOST_RE.fullmatch(plan["db_host"] or ""):
        return _BAD_DB_HOST
    return ""


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
    p = dict(_ad.parse_probe(out), addons=_ad.parse_status(out)["addons"])
    p["rcon"], p["rcon_why"] = _ad.game_rcon(gs.game_type, p["rcon_lines"])
    why = _install_refusal(gs, plan, p) or _runtime(gs, p)
    if why:
        return why, ""
    settings, files, unit, units, meta, secrets = _install_texts(gs, plan, p, who)
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name,
                                           _ad.install_sh(gs.short_name, plan["id"], unit, meta, files, units),
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
    geolocation = body.get("geolocation") is True and addon_id == _ad.B3
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
        if (_JOBS.get((gs.id, addon_id)) or {}).get("running"):
            return _say(409, _BUSY)
        _JOBS[(gs.id, addon_id)] = {"running": True, "why": "", "tail": ""}
    r = db.session.get(GameDatabase, db_id) if db_id is not None else None
    log_action(current_user, "addon_install", target=gs.name, server=gs,
               detail="%s: started%s%s" % (addon_id, ", database %s" % r.name if r is not None else "",
                                           ", geolocation on" if geolocation else ""))
    threading.Thread(target=_install_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), (addon_id, db_id, geolocation), current_user.username)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTED)}), 202


# ── start, stop, remove, logs ─────────────────────────────────────────────────────────────────
def _action_answer(gs, addon_id, action):
    out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.action_sh(addon_id, action),
                                          timeout=_ad.ACTION_TIMEOUT)
    ok = rc == 0
    why = "" if ok else _with_reason(_NOT_DONE[action], out, err)
    log_action(current_user, "addon_start" if action == "start" else "addon_stop", target=gs.name, server=gs, success=ok,
               detail="%s %s" % (addon_id, "done" if ok else "failed (rc %s): %s" % (rc, why)))
    if not ok:
        return _say(200, why)
    return jsonify({"success": True, "message": i18n.tr(_DONE[action])})


def _remove_answer(gs, addon_id):
    out, err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.remove_sh(gs.short_name, addon_id),
                                          timeout=_ad.ACTION_TIMEOUT)
    removed, others = _ad.remove_outcome(out, rc)
    why = "" if removed else _with_reason(_NOT_REMOVED, "", err)
    if removed and not others:
        # The account runs no add-on any more: its user manager need not linger. Best-effort.
        _sm.run_privileged(gs.remote, "addon-account-release", [gs.short_name, "keep"], timeout=90)
    log_action(current_user, "addon_remove", target=gs.name, server=gs, success=removed,
               detail="%s %s" % (addon_id, "removed" if removed else "not removed (rc %s): %s" % (rc, why)))
    if not removed:
        return _say(200, why)
    return jsonify({"success": True, "message": i18n.tr(_REMOVED[_ad.CATALOG[addon_id]["data_kept"]])})


def _logs_answer(gs, addon_id):
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.logs_sh(gs.short_name, addon_id),
                                           timeout=30)
    if rc != 0:
        return _say(200, "Couldn't read the add-on's log: the host did not answer. Try again.")
    secrets = [decrypt_secret(r.secret) or "" for r in GameDatabase.query.filter_by(game_server_id=gs.id).all()]
    return jsonify({"success": True, "log": _ad.scrub(out or "", secrets)})


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
    try:
        return answer(gs)
    except ConnectionError:
        return _unreachable("reach the server's host")


def register(app):
    """Register the Add-ons card's routes and the template's `addons_tab(server)`."""
    app.jinja_env.globals["addons_tab"] = tab_access

    @app.route("/api/server/<int:server_id>/addons")
    @login_required
    @server_access_required
    def api_server_addons(server_id):
        """The add-ons this server can run, which are installed and running, and its databases."""
        if not has_permission(current_user, MANAGE_ADDONS):
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

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/<action>", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_action(server_id, addon_id, action):
        """Start or stop an installed add-on."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        if action not in _DONE:
            return _say(404, _UNKNOWN)
        return _guarded(server_id, addon_id, lambda gs: _action_answer(gs, addon_id, action))

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
