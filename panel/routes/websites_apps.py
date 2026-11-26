"""One-click apps: "Install an app" makes the site, its database, the app and its admin account, as one job.

Adding a site this way takes websites_access.can_create, as adding any site does. The app is a recipe
from the signed catalog (websites_catalog.recipes), its steps one of the fixed step types the runtime
layer implements (websites.recipe_steps); the job here runs them in order and records each one
finished on the site's row (install_step, install_steps_done), so a failure, or a panel restarted
mid-install, undoes exactly those in reverse and removes the site: no half-installed site, account,
database or container is left behind (the install undo route finishes one a restart cut short).

The app's admin password is generated with a CSPRNG (or typed, then at least ADMIN_PW_MIN
characters, OWASP Authentication Cheat Sheet, "Password Complexity": 15 without MFA) and handed to the
steps only inside the step they need it for, which the runtime layer passes on stdin, never on argv;
it is never stored, never logged, and shown once, to the person who started the install, by the
status route (OWASP Secrets Management Cheat Sheet, "2.7.1 Creation"; Logging Cheat Sheet, "Data to
exclude"). The database is made through the Databases tab's own code (routes/databases_sites) with
its own generated password, stored encrypted. Every step's outcome is one audit row.
"""
import re
import secrets
import threading

from flask import abort, current_app, jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.clock import utcnow
from panel.db.models import Website, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.auth import MANAGE_WEBSITE, MANAGE_WEBSITES
from panel.services import websites as _svc
from panel.services import websites_access as _wa

ADMIN_PW_MIN = 15
_ADMIN_USER_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
_EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
DB_STEP = "create-database"
# site id -> the job's state: {"state", "step", "done", "error", "owner", "password"}; the password is
# dropped the first time its owner reads a finished job.
_JOBS = {}
_LOCK = threading.Lock()


def _recipe(name):
    from panel.services import websites_catalog
    try:
        recipes = websites_catalog.recipes()
    except NotImplementedError:
        return None, _w.S_NOT_READY
    got = recipes.get(name) if isinstance(recipes, dict) and isinstance(name, str) else None
    return (got, None) if isinstance(got, dict) else (None, "Choose one of the apps this panel offers.")


def admin_fields(data):
    """(admin user, email, password, generated?, [problems]) from the form."""
    user, email = _w.field(data, "admin_user"), _w.field(data, "admin_email")
    typed = data.get("admin_password") if isinstance(data.get("admin_password"), str) else ""
    problems = []
    if not _ADMIN_USER_RE.fullmatch(user) or user.lower() in ("admin", "administrator", "root"):
        problems.append("The admin username is 3 to 32 letters, digits, dots, hyphens and underscores, and not "
                        "admin, administrator or root.")
    if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
        problems.append("Enter the admin's email address.")
    if typed and (len(typed) < ADMIN_PW_MIN or len(typed) > 128 or any(c in typed for c in "\x00\r\n")):
        problems.append("A typed admin password is %d to 128 characters on one line." % ADMIN_PW_MIN)
    password = typed or secrets.token_urlsafe(18)
    return user, email, password, not typed, problems


def _steps(site):
    """The recipe's steps for `site` (a list of dicts with a "name" and a "type")."""
    steps = _svc.recipe_steps(site.app_recipe)
    return [s for s in steps if isinstance(s, dict) and s.get("name")]


def _mark(site, step_name, finished):
    import json
    done = json.loads(site.install_steps_done or "[]")
    if finished and step_name not in done:
        done.append(step_name)
    site.install_step = step_name[:32]
    site.install_steps_done = json.dumps(done)
    db.session.commit()
    return done


def _run_step(site, step, secret_vals):
    """Run one step: (ok, sentence, database row or None)."""
    if step.get("type") == DB_STEP:
        from panel.routes import databases_sites
        ok, said, row, db_pw = databases_sites.create_for(site, str(step.get("slug") or "app"))
        if ok:
            secret_vals.update(db_name=row.name, db_user=row.name, db_password=db_pw)
        return ok, said
    return _w.host_call(_sw.app_install_step, site.remote, site, dict(step, secrets=dict(secret_vals)))


def _undo_step(site, step):
    if step.get("type") == DB_STEP:
        from panel.routes import databases_sites
        for row in databases_sites.site_rows(site):
            databases_sites.drop(site, row)
        return True, ""
    return _w.host_call(_sw.app_undo_step, site.remote, site, step)


def undo(site, steps, done):
    """Undo the finished steps `done` (names) in reverse, then the site's container and account. -> [failures]."""
    failed = []
    by_name = {s["name"]: s for s in steps}
    for name in reversed(done):
        if name == "site":
            continue
        ok, said = _undo_step(site, by_name.get(name, {"name": name, "type": ""}))
        if not ok:
            failed.append("%s: %s" % (name, i18n.tr(said)))
    if "site" in done:
        ok, said = _w.host_call(_sw.remove, site.remote, site)
        if not ok:
            failed.append("site: %s" % i18n.tr(said))
    return failed


def _job(site_id, **fields):
    with _LOCK:
        _JOBS.setdefault(site_id, {}).update(fields)


def _install(site, secret_vals):
    """The job body: (ok, the step that failed or "", why)."""
    steps = _steps(site)
    _mark(site, "site", True)          # marked first: a part-made account or container is undone too
    ok, said = _w.host_call(_sw.install, site.remote, site)
    if not ok:
        return False, "site", said, steps
    for step in steps:
        _job(site.id, step=step["name"])
        _mark(site, step["name"], False)
        ok, said = _run_step(site, step, secret_vals)
        if not ok:
            return False, step["name"], said, steps
        _mark(site, step["name"], True)
    return True, "", "", steps


def _worker(app, site_id, uid, secret_vals):
    from panel.db.models import User
    with app.app_context():
        site, user = db.session.get(Website, site_id), db.session.get(User, uid)
        try:
            ok, step, said, steps = _install(site, secret_vals)
        except Exception:  # noqa: BLE001 - any failure is undone, never left half-done
            _w._log.warning("app install raised", exc_info=True)
            ok, step, said, steps = False, site.install_step or "site", _w.S_UNREACHABLE, _safe_steps(site)
        _finish(site, user, ok, step, said, steps)


def _safe_steps(site):
    try:
        return _steps(site)
    except Exception:  # noqa: BLE001 - the undo still runs with the names alone
        return []


def _finish(site, user, ok, step, said, steps):
    import json
    if ok:
        site.state, site.install_step, site.state_reason = "running", "", ""
        db.session.commit()
        _job(site.id, state="done", step="")
        _w.audit_as(user, site, "website_app_install", "installed %s %s" % (site.app_recipe, site.app_version))
        return
    failed = undo(site, steps, json.loads(site.install_steps_done or "[]"))
    reason = i18n.tr(said)[:200]
    _job(site.id, state="failed", step=step, error=reason, password="")
    _w.audit_as(user, site, "website_app_install", "%s failed at %s: %s; undone%s" % (
        site.app_recipe, step, reason, " except %s" % "; ".join(failed) if failed else ""), False)
    if failed:
        site.state, site.state_reason = "failed", ("Undo incomplete: " + "; ".join(failed))[:200]
        db.session.commit()
    else:
        db.session.delete(site)
        db.session.commit()


def _status(site):
    with _LOCK:
        job = dict(_JOBS.get(site.id) or {})
        mine = job.get("owner") == current_user.id
        password = job.get("password") if mine and job.get("state") == "done" else ""
        if password:
            _JOBS[site.id]["password"] = ""       # shown once
    out = {"state": job.get("state") or ("done" if site.state == "running" else site.state), "step": job.get("step", ""),
           "error": job.get("error", ""), "recipe": site.app_recipe, "version": site.app_version}
    if password:
        out["admin_password"] = password
    return out


def _start(data):
    recipe_name = _w.field(data, "app")
    recipe, why = _recipe(recipe_name)
    if why:
        return _w.say(400 if why != _w.S_NOT_READY else 501, why)
    user, email, password, generated, problems = admin_fields(data)
    if problems:
        return _w.say(400, " ".join(i18n.tr(p) for p in problems))
    remote, group, refusal = _w.add_target(data)
    name = _w.field(data, "name").lower() or recipe_name
    refusal = refusal or _w.add_refusal(remote, name, str(recipe.get("kind") or "php"))
    if refusal:
        return _w.say(*refusal)
    site = _w.new_site(remote, name, str(recipe.get("kind") or "php"), group)
    site.app_recipe, site.app_version = recipe_name, str(recipe.get("version") or "")
    site.install_started_at, site.install_steps_done = utcnow(), "[]"
    db.session.commit()
    if _w.field(data, "domain"):
        from panel.routes import websites_domains
        websites_domains.add_first(site, _w.field(data, "domain"))
    _w.audit(site, "website_app_install", "started %s %s, admin %s%s" % (recipe_name, site.app_version, user,
                                                                         " (generated password)" if generated else ""))
    _job(site.id, state="running", step="site", error="", owner=current_user.id, password=password)
    secret_vals = {"admin_user": user, "admin_email": email, "admin_password": password}
    app = current_app._get_current_object()
    _w.threading.Thread(target=_worker, args=(app, site.id, current_user.id, secret_vals), daemon=True).start()
    return jsonify({"success": True, "id": site.id, "message": i18n.tr("Installing. This takes a few minutes.")})


def register(app):
    """The one-click install routes."""
    @app.route("/websites/install-app", methods=["POST"])
    @login_required
    def website_install_app():
        if not _wa.can_create(current_user):
            abort(404)
        return _start(_w.body())

    @app.route("/websites/<int:site_id>/install")
    @login_required
    def website_install_status(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        resp = jsonify(_status(site))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/websites/<int:site_id>/install/undo", methods=["POST"])
    @login_required
    def website_install_undo(site_id):
        import json
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        with _LOCK:
            running = (_JOBS.get(site.id) or {}).get("state") == "running"
        if running or site.state != "creating" or not site.app_recipe:
            return _w.say(409, "Only an app install that stopped part-way can be undone.")
        failed = undo(site, _safe_steps(site), json.loads(site.install_steps_done or "[]"))
        if failed:
            return _w.acted(site, "website_app_install", False, "Undo incomplete: " + "; ".join(failed))
        _w.audit(site, "website_app_install", "an install cut short was undone")
        db.session.delete(site)
        db.session.commit()
        return _w.done(True, "The half-installed website was removed.")
