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
import threading
from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n
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
_NO_RCON = "The server's config has no RCON password (rcon_password). Set one, then install again."
_NO_PORT = "No free port was found on this host for the add-on's page."
_NO_PODMAN = "Couldn't install Podman on this host."
_NO_PREPARE = "Couldn't ready the server's account for containers (subordinate ids and lingering)."
_STARTED = "Installing the add-on. Downloading its image takes a few minutes."
_DONE = {"start": "The add-on was started.", "stop": "The add-on was stopped."}
_NOT_DONE = {"start": "The add-on didn't start. Its log says why.", "stop": "The add-on didn't stop."}
_REMOVED = "The add-on was removed. Its database is kept in the Databases tab."
_NOT_REMOVED = "The add-on couldn't be removed completely. Try again."

# (server id, add-on id) -> {"running": bool, "why": str}: an install in the background.
_JOBS = {}
_JOBS_LOCK = threading.Lock()


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
        if isinstance(name, str):
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
                     "legacy": a["legacy"], "installed": got is not None,
                     "state": (got or {}).get("state", ""), "port": meta.get("port"),
                     "database": meta.get("database", ""), "installing": bool(job.get("running")),
                     "error": i18n.tr(job["why"]) if job.get("why") else ""})
    return rows


def _status_answer(gs):
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
    if rc != 0:
        return _say(200, "Couldn't read this server's add-ons: the host did not answer. Try again.", unread=True)
    st = _ad.parse_status(out)
    why = _ad.runtime_refusal(st["os"], st["podman"])
    return jsonify({"success": True, "addons": _addon_rows(gs, st["addons"]),
                    "databases": _databases(gs, st["addons"]), "podman": st["podman"],
                    "runtime_error": i18n.tr(why) if why else ""})


# ── install, in the background ────────────────────────────────────────────────────────────────
def _apt_install(remote):
    """Podman and its two helpers from Ubuntu's archive (universe added once if apt can't find them)."""
    rc = _sm.run_privileged(remote, "apt-install", list(_ad.PACKAGES), timeout=900)[2]
    if rc == 0:
        return True
    _sm.run_privileged(remote, "apt-add-repo", ["universe"], timeout=300)
    _sm.run_privileged(remote, "apt-update", [], timeout=300)
    return _sm.run_privileged(remote, "apt-install", list(_ad.PACKAGES), timeout=900)[2] == 0


def _taken(p, addon_id):
    """The databases the account's other add-ons use, by name."""
    return {(a.get("meta") or {}).get("database") for k, a in p["addons"].items() if k != addon_id}


def _host_refusal(gs, p):
    """Why the host or the game stops the install: an old system, no game log, no RCON, no port."""
    if not _ad.log_dir(gs.short_name, p["logdir"]):
        return _NO_LOG
    if not p["rcon"]:
        return _NO_RCON
    return "" if p["port"] else _NO_PORT


def _install_refusal(gs, addon_id, p, r):
    """Why the probe's answer stops the install ("" when it may go on)."""
    if p["installed"]:
        return _INSTALLED_ALREADY
    if r.name in _taken(p, addon_id):
        return _DB_TAKEN
    return _ad.runtime_refusal(p["os"], p["podman"]) or _host_refusal(gs, p)


def _runtime(gs, p):
    """Podman on the host and the account readied: "" when both are done, else why not."""
    if not p["podman"] and not _apt_install(gs.remote):
        return _NO_PODMAN
    _out, _err, rc = _sm.run_privileged(gs.remote, "addon-account-prepare", [gs.short_name], timeout=60)
    return "" if rc == 0 else _NO_PREPARE


def _install_texts(gs, addon_id, p, r, who):
    """(settings, unit, record) the install writes, and the secrets to scrub from its output."""
    host, port = _db_target(r)
    secret = decrypt_secret(r.secret) or ""
    conn = _ad.connection_string(host, port, r.name, secret)
    settings = _ad.iw4madmin_settings(gs.game_type, gs.port, p["rcon"], conn)
    unit = _ad.quadlet(gs.short_name, addon_id, _ad.log_dir(gs.short_name, p["logdir"]),
                       _ad.network(gs.port, host, port), p["port"])
    meta = json.dumps({"kind": addon_id, "version": _ad.CATALOG[addon_id]["version"],
                       "image": _ad.CATALOG[addon_id]["image"], "database": r.name, "port": p["port"],
                       "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "installed_by": who}) + "\n"
    return settings, unit, meta, (secret, p["rcon"])


def _install_steps(gs, addon_id, db_id, who):
    """The install itself: "" when the add-on runs, else why not (an English sentence)."""
    r = db.session.get(GameDatabase, db_id)
    if r is None or r.game_server_id != gs.id:
        return _NO_DB
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name,
                                           _ad.probe_sh(addon_id, gs.lgsm_name, gs.id) + "; " + _ad.status_sh(),
                                           timeout=60, selfname=gs.lgsm_name)
    if rc != 0:
        return "Couldn't read the server's account on the host: it did not answer."
    p = dict(_ad.parse_probe(out), addons=_ad.parse_status(out)["addons"])
    why = _install_refusal(gs, addon_id, p, r) or _runtime(gs, p)
    if why:
        return why
    settings, unit, meta, secrets = _install_texts(gs, addon_id, p, r, who)
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name,
                                           _ad.install_sh(gs.short_name, addon_id, unit, meta),
                                           timeout=_ad.INSTALL_TIMEOUT, selfname=gs.lgsm_name, stdin_text=settings)
    ok, said = _ad.install_outcome(_ad.scrub(out or "", secrets), rc)
    return "" if ok else said


def _install_worker(app, gs_id, born, addon_id, db_id, who):
    """Run one install in a thread, record how it went, and audit it."""
    with app.app_context():
        why = ""
        try:
            gs = claim_row(GameServer, gs_id, born)
            why = _install_steps(gs, addon_id, db_id, who) if gs is not None else ""
            if gs is not None:
                log_action(None, "addon_install", target=gs.name, actor=who, server=gs, success=not why,
                           detail="%s installed" % addon_id if not why else "%s not installed: %s" % (addon_id, why))
        except Exception:
            why = _log_and_generic("add-on install failed")
        finally:
            with _JOBS_LOCK:
                _JOBS[(gs_id, addon_id)] = {"running": False, "why": why}


def _install_answer(app, gs, addon_id):
    body = _json_body()
    db_id = body.get("database_id")
    if not isinstance(db_id, int) or isinstance(db_id, bool):
        return _say(400, _NO_DB)
    r = db.session.get(GameDatabase, db_id)
    if r is None or r.game_server_id != gs.id:
        return _say(400, _NO_DB)
    with _JOBS_LOCK:
        if (_JOBS.get((gs.id, addon_id)) or {}).get("running"):
            return _say(409, _BUSY)
        _JOBS[(gs.id, addon_id)] = {"running": True, "why": ""}
    log_action(current_user, "addon_install", target=gs.name, server=gs,
               detail="%s: started, database %s" % (addon_id, r.name))
    threading.Thread(target=_install_worker, daemon=True,
                     args=(app, gs.id, row_birth(gs), addon_id, db_id, current_user.username)).start()
    return jsonify({"success": True, "started": True, "message": i18n.tr(_STARTED)}), 202


# ── start, stop, remove, logs ─────────────────────────────────────────────────────────────────
def _action_answer(gs, addon_id, action):
    _out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.action_sh(addon_id, action),
                                            timeout=_ad.ACTION_TIMEOUT)
    ok = rc == 0
    log_action(current_user, "addon_start" if action == "start" else "addon_stop", target=gs.name, server=gs, success=ok,
               detail="%s %s" % (addon_id, "done" if ok else "failed (rc %s)" % rc))
    if not ok:
        return _say(200, _NOT_DONE[action])
    return jsonify({"success": True, "message": i18n.tr(_DONE[action])})


def _remove_answer(gs, addon_id):
    out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.remove_sh(gs.short_name, addon_id),
                                           timeout=_ad.ACTION_TIMEOUT)
    removed, others = _ad.remove_outcome(out, rc)
    if removed and not others:
        # The account runs no add-on any more: its user manager need not linger. Best-effort.
        _sm.run_privileged(gs.remote, "addon-account-release", [gs.short_name], timeout=30)
    log_action(current_user, "addon_remove", target=gs.name, server=gs, success=removed,
               detail="%s %s" % (addon_id, "removed" if removed else "not removed (rc %s)" % rc))
    if not removed:
        return _say(200, _NOT_REMOVED)
    return jsonify({"success": True, "message": i18n.tr(_REMOVED)})


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
