"""The Websites tab: the list, a site's page, and running a site (add, start, stop, online, limits, remove).

Every route that names a site calls websites_access.site_for in its own body with the permission it
needs, so a site the user holds nothing on answers 404 exactly as a site that does not exist (OWASP
Insecure Direct Object Reference Prevention Cheat Sheet, "Mitigation"; Authorization Cheat Sheet,
"Deny by Default", "Validate the Permissions on Every Request", "Exit Safely when Authorization Checks
Fail"). The site id comes from the URL only, never from a form field. Every change is a POST under the
panel's CSRF protection (flask-wtf's synchronizer token, OWASP Cross-Site Request Forgery Prevention
Cheat Sheet, "Synchronizer Token Pattern"; no GET changes anything) and writes one audit row naming
the site, with no file contents, passwords or tokens in it (OWASP Logging Cheat Sheet, "Which events
to log", "Event attributes", "Data to exclude").

Who may do what (auth.py, websites_access.py): VIEW_WEBSITES sees a site; MANAGE_WEBSITE starts,
stops and restarts it; MANAGE_WEBSITES administers it (online/offline, which opens ports 80 and 443,
limits, image updates, removal); a superadmin may also give it the internet. Adding a site takes
websites_access.can_create. Everything on the host goes through ssh_manager.websites, which answers
(ok, sentence) and never a command's raw output.

The sibling modules (websites_domains, _files, _backups, _settings, _apps, _customers, _proxy and
databases_sites) share the helpers here and are registered by register().
"""
import logging
import secrets
import threading
import time

from flask import abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required
from jinja2 import TemplateNotFound
from panel.core import i18n
from panel.core.config import encrypt_secret
from panel.core.http import _json_body, _json_str
from panel.core.validation import WEBSITE_KINDS, WEBSITE_PORT_MAX, WEBSITE_PORT_MIN, website_name_problem
from panel.db.models import Group, RemoteServer, Website, WebsiteProxy, db
from panel.ops.ssh_manager import websites as _sw
from panel.security.auth import (MANAGE_WEBSITE, MANAGE_WEBSITES, VIEW_WEBSITES, get_host_remote, has_permission,
                                 log_website_action)
from panel.services import websites_access as _wa

_log = logging.getLogger(__name__)

S_UNREACHABLE = "The website's host did not answer. Nothing was changed; try again."
S_NOT_READY = "This part of websites is not available on this panel yet."
S_NAME_TAKEN = "A website with that name already exists on this host."
S_NO_PORT = "This host has no free website port left (20000-20999)."
S_NO_HOST = "Choose the host the website runs on."
S_QUOTA = "Your group already has as many websites as it may have."
S_CONFIRM = "Type the website's name to confirm."
S_BAD_LIMIT = "{field} must be a whole number from {low} to {high}."
STATUS_FRESH = 10                 # seconds a site's status probe is reused
_STATUS = {}                      # site id -> (monotonic time, probe dict)
# Limits an administrator may set: (low, high) per column.
LIMITS = {"mem_mb": (64, 65536), "cpu_milli": (100, 64000), "pids": (32, 32768), "disk_mb": (64, 1048576),
          "max_body_mb": (1, 4096)}


# ── answers ─────────────────────────────────────────────────────────────────────────────────────
def say(status, sentence, **extra):
    """A JSON refusal: `sentence` translated, with the same text in error and message."""
    said = i18n.tr(sentence)
    return jsonify(dict({"success": False, "error": said, "message": said}, **extra)), status


def done(ok, sentence, **extra):
    """A JSON answer for a change the host was asked to make: 200 when it was made, else 502."""
    said = i18n.tr(sentence or ("Done." if ok else "Failed"))
    return jsonify(dict({"success": bool(ok), "message": said}, **extra)), 200 if ok else 502


def body():
    """The request's fields: its JSON object, else its form."""
    data = _json_body()
    return data if data else request.form.to_dict()


def field(data, key, default=""):
    """A request field as a stripped string (any JSON type)."""
    return _json_str(data, key, default)


def flag(data, key):
    """A request field as a boolean (true/1/on/yes)."""
    v = data.get(key)
    return v is True or str(v).strip().lower() in ("1", "true", "on", "yes")


# ── audit ───────────────────────────────────────────────────────────────────────────────────────
def audit(site, action, detail="", success=True):
    """One audit row about `site` by the signed-in user (audit_as)."""
    audit_as(current_user, site, action, detail, success)


def audit_as(user, site, action, detail="", success=True):
    """One audit row about `site` (auth.log_website_action: its name as the target, its id in website_id).

    `detail` names what was done (a path, a domain, a setting), made printable; never file contents or a
    secret. `user` is None for the panel itself (a background job whose starter is gone).
    """
    from panel.routes.server_files import _audit_safe
    log_website_action(user, site, action, _audit_safe(detail, 1000), bool(success))


def manage_perm(site_id):
    """The permission a "run this site" route asks site_for for: MANAGE_WEBSITES when the user administers
    the site (an administrator runs it too), else MANAGE_WEBSITE. Either way site_for decides, per site.
    """
    admin = _wa.visible_sites(current_user, MANAGE_WEBSITES).filter(Website.id == site_id).first()
    return MANAGE_WEBSITES if admin is not None else MANAGE_WEBSITE


def host_call(fn, *args):
    """Call an ssh_manager.websites function: its (ok, sentence), or (False, why) when it raised."""
    try:
        return fn(*args)
    except NotImplementedError:
        return False, S_NOT_READY
    except Exception:  # noqa: BLE001 - a host that cannot be reached is one answer to the page
        _log.warning("website host call %s failed", getattr(fn, "__name__", "?"), exc_info=True)
        return False, S_UNREACHABLE


def site_db(site):
    """(host, port) of the site's database server as its host sees it, or None when the site has no database.

    A site's databases are made by the Databases code on its own host's server, reached on the loopback;
    the container gets that port forwarded (ssh_manager.websites.install's `db`).
    """
    from panel.routes import databases, databases_sites
    if not databases_sites.site_rows(site):
        return None
    hd = databases._host_row(site.remote_id)
    return "127.0.0.1", int(getattr(hd, "port", None) or 3306)


def install_site(site):
    """(Re)install `site` on its host with its database forwarded, and restart it: (ok, sentence)."""
    return host_call(_sw.install, site.remote, site, site_db(site))


def acted(site, action, ok, said, detail=""):
    """Audit a host action on `site` and answer it."""
    audit(site, action, detail or ("done" if ok else "failed: %s" % i18n.tr(said)), ok)
    return done(ok, said)


# ── what a site looks like to the page ─────────────────────────────────────────────────────────
def is_admin(user, site=None):
    """Whether `user` administers `site` (MANAGE_WEBSITES on it), or any site when `site` is None."""
    if getattr(user, "is_superadmin", False):
        return True
    if site is None:
        return has_permission(user, MANAGE_WEBSITES)
    return _wa.visible_sites(user, MANAGE_WEBSITES).filter(Website.id == site.id).first() is not None


def site_json(site, admin=False):
    """A site as the list and the page read it: never a secret, admin-only fields only for an admin."""
    dom = site.primary_domain
    out = {"id": site.id, "name": site.name, "kind": site.kind, "state": site.state,
           "state_reason": site.state_reason or "", "enabled": bool(site.enabled),
           "domain": dom.domain if dom else "", "cert_state": dom.cert_state if dom else "",
           "php_version": site.php_version or "", "runtime": site.runtime or "", "app": site.app_recipe or ""}
    if admin:
        out.update({k: getattr(site, k) for k in LIMITS})
        out.update({"remote_id": site.remote_id, "access_log": bool(site.access_log), "full_egress": bool(site.full_egress),
                    "backup_keep": site.backup_keep, "customer_note": site.customer_note or ""})
    return out


def page(template, **ctx):
    """Render a Websites page; until its template exists, the same context as JSON (the routes work first)."""
    try:
        return render_template(template, **ctx)
    except TemplateNotFound:
        return jsonify({k: (site_json(v) if isinstance(v, Website) else v) for k, v in ctx.items()
                        if isinstance(v, (str, int, bool, list, dict, type(None), Website))})


# ── the web proxy and its ports, after a site goes online or offline ──────────────────────────
def proxy_row(remote_id):
    """The host's WebsiteProxy row, made with its defaults when there is none."""
    row = WebsiteProxy.query.filter_by(remote_id=remote_id).first()
    if row is None:
        row = WebsiteProxy(remote_id=remote_id)
        db.session.add(row)
        db.session.flush()
    return row


def _cache_checked(remote, opts):
    """`opts` with the page cache left out unless this host's proxy was built with its module."""
    if opts.get("cache_build"):
        ok, out = host_call(_sw.proxy_status, remote)
        opts["cache_build"] = bool(ok) and _sw.parse_proxy_status(out)["cache"]
    return opts


def page_cache_ready(remote):
    """Whether a site's page cache takes effect on `remote`: the setting is on and its proxy has the module."""
    from panel.routes.websites_view import options
    return _cache_checked(remote, {"cache_build": options()["cache_build"]})["cache_build"]


def reconcile_proxy(remote):
    """Bring the host's proxy and ports in line with its online sites: (ok, sentence).

    With a site online: ports first (opened for the exposure mode), then the new proxy configuration,
    rendered with the saved global settings (websites_view.proxy_options: certificates, TLS, HSTS, the
    page cache) and applied with its certificate files, the proxy left running AND enabled. With none:
    the proxy stopped first, then the ports closed. A failure between the two leaves the safe state (a
    port open and nothing listening, or nothing listening at all) for the next try.
    """
    from panel.routes.websites_view import proxy_options
    from panel.services import websites_proxy as _wp
    proxy = proxy_row(remote.id)
    online = Website.query.filter_by(remote_id=remote.id, enabled=True).order_by(Website.id).all()
    if not online:
        ok, said = host_call(_sw.proxy_stop, remote)
        return host_call(_sw.ports_apply, remote, proxy, False) if ok else (ok, said)
    try:
        text = _wp.render(online, proxy, _cache_checked(remote, proxy_options()))
    except NotImplementedError:
        return False, S_NOT_READY
    ok, said = host_call(_sw.ports_apply, remote, proxy, True)
    return host_call(_sw.proxy_apply, remote, text, online, proxy, True) if ok else (ok, said)


# ── list and pages ──────────────────────────────────────────────────────────────────────────────
def _list_routes(app):
    from panel.routes import websites_view as _view

    @app.route("/websites")
    @login_required
    def websites_page():
        if not _wa.can_open_page(current_user):
            abort(404)
        return page("websites.html", can_add=_wa.can_create(current_user), site_admin=is_admin(current_user))

    @app.route("/websites/<int:site_id>")
    @login_required
    def website_page(site_id):
        site = _wa.site_for(current_user, site_id, VIEW_WEBSITES)
        tab = request.args.get("tab", "overview")
        return page("website.html", site=site, tab=tab if tab.isalnum() and len(tab) <= 16 else "overview",
                    **_view.page_flags(site))

    @app.route("/api/websites")
    @login_required
    def api_websites():
        if not _wa.can_open_page(current_user):
            return jsonify({"success": True, "sites": [], "can_create": False})
        return jsonify(_view.list_answer(site_json))

    @app.route("/api/websites/<int:site_id>")
    @login_required
    def api_website(site_id):
        site = _wa.site_for(current_user, site_id, VIEW_WEBSITES)
        from panel.routes import websites_apps, websites_domains
        websites_domains.refresh_certs(site.remote)
        return jsonify(_view.site_answer(site, _status(site), websites_apps.install_json(site)))


def _status(site):
    """The site's probe, reused for STATUS_FRESH seconds (one SSH round trip at most per site per window)."""
    now = time.monotonic()
    hit = _STATUS.get(site.id)
    if hit and now - hit[0] < STATUS_FRESH:
        return hit[1]
    ok, said = host_call(_sw.site_probe, site.remote, site)
    probe = {"ok": bool(ok), "text": i18n.tr(said) if not isinstance(said, dict) else "",
             "facts": said if isinstance(said, dict) else {}}
    _STATUS[site.id] = (now, probe)
    return probe


def forget_status(site_id):
    """Drop a site's cached probe (it was just started, stopped or changed)."""
    _STATUS.pop(site_id, None)


# ── adding a site ───────────────────────────────────────────────────────────────────────────────
def _free_port(remote_id):
    taken = {p for (p,) in db.session.query(Website.port).filter(Website.remote_id == remote_id)}
    return next((p for p in range(WEBSITE_PORT_MIN, WEBSITE_PORT_MAX + 1) if p not in taken), None)


def _local_host():
    return RemoteServer.query.filter((RemoteServer.is_local.is_(True)) | (RemoteServer.auth_method == "local")).first()


def creates_as_admin(user):
    """Whether `user` adds sites as an administrator (superadmin, or MANAGE_WEBSITES in an ordinary group)."""
    return bool(getattr(user, "is_superadmin", False)) or any(
        MANAGE_WEBSITES in g.get_permissions() and not g.is_customer for g in user.groups)


def _admin_host(data):
    """The host an administrator named (host_id): any for a superadmin (the panel's own when none is named),
    else one they have host-level access to (get_host_remote); None when none is named."""
    try:
        rid = int(data.get("host_id") or data.get("remote_id"))
    except (TypeError, ValueError):
        return _local_host() if current_user.is_superadmin else None
    return db.session.get(RemoteServer, rid) if current_user.is_superadmin else get_host_remote(rid)


def add_target(data):
    """(host, customer group or None, refusal or None) for a new site from the add form's fields.

    An administrator names the host (_admin_host) and may give the site to a customer group. A customer's
    site joins their own group and runs on that group's host (its first site's, else the panel's own).
    """
    if creates_as_admin(current_user):
        remote = _admin_host(data)
        return remote, _customer_group(data), (None if remote else (400, S_NO_HOST))
    group = _wa.create_target(current_user)
    if group is None:
        return None, None, (403, S_QUOTA)
    first = next(iter(group.websites or []), None)
    remote = first.remote if first is not None else _local_host()
    return remote, group, (None if remote else (409, S_NO_HOST))


def _customer_group(data):
    """The customer group an administrator named for a new site, or None (no group, or not a customer group)."""
    try:
        group = db.session.get(Group, int(data.get("customer_id") or data.get("group_id")))
    except (TypeError, ValueError):
        return None
    return group if group is not None and group.is_customer else None


def _defaults():
    """What a new site starts with: the Settings card's default limits and access-log switch."""
    from panel.routes.websites_view import options
    opts = options()
    return dict({key: opts[key] for key in LIMITS}, access_log=bool(opts["access_log_default"]))


def _php_fields(data):
    from panel.routes.websites_view import php_versions
    versions = php_versions()
    version = field(data, "php_version") or (versions[-1] if versions else "")
    if version not in versions:
        return {}, (400, "Choose one of the PHP versions this panel offers.")
    return {"php_version": version}, None


def _runtime_fields(data):
    """(a new app site's runtime, version, port and commands, refusal or None): the catalog's defaults for the runtime.

    The signed catalog's runtimes.<name> holds the app's usual port and its start and build commands (Node.js:
    3000, npm start, npm ci); the app's settings change them later. A site without a port could not be made.
    """
    from panel.routes.websites_view import runtime_versions
    from panel.services import websites_catalog
    runtime = field(data, "runtime") or "node"
    versions = runtime_versions().get(runtime, [])
    version = field(data, "runtime_version") or (versions[-1] if versions else "")
    if version not in versions:
        return {}, (400, "Choose a runtime and version this panel offers.")
    entry = websites_catalog.runtimes().get(runtime, {})
    return {"runtime": runtime, "runtime_version": version, "app_port": int(entry.get("port") or 0) or None,
            "start_command": str(entry.get("start") or ""), "build_command": str(entry.get("build") or "")}, None


def runtime_fields(data, kind):
    """(the kind-specific columns of a new site, refusal or None): its PHP version, or its runtime and version."""
    if kind in ("php", "wordpress", "phpbb"):
        return _php_fields(data)
    return _runtime_fields(data) if kind == "app" else ({}, None)


def new_site(remote, name, kind, group=None, extra=None):
    """The new site's row (state creating, account and port chosen, a fresh proxy token), committed."""
    site = Website(remote_id=remote.id, name=name, kind=kind, state="creating",
                   created_by=(current_user.username or "")[:80], **dict(_defaults(), **(extra or {})))
    db.session.add(site)
    db.session.flush()
    site.account, site.port = "ws%d" % site.id, _free_port(remote.id)
    site.proxy_secret = encrypt_secret(secrets.token_urlsafe(32))
    if group is not None:
        group.websites.append(site)
    db.session.commit()
    return site


def add_refusal(remote, name, kind):
    """Why a site `name` of `kind` cannot be added on `remote`, as (status, sentence), or None."""
    problem = website_name_problem(name)
    if problem:
        return 400, problem
    if kind not in WEBSITE_KINDS:
        return 400, i18n.Sentence("Choose what kind of website it is.")
    if Website.query.filter_by(remote_id=remote.id, name=name).first() is not None:
        return 409, S_NAME_TAKEN
    if _free_port(remote.id) is None:
        return 409, S_NO_PORT
    return None


def start_install(site):
    """Run the site's install (account, folders, image, unit, start) in the background."""
    app = current_app._get_current_object()
    threading.Thread(target=_install_worker, args=(app, site.id), daemon=True).start()


def note_run_state(site, ok, said):
    """Record on `site` what an install, update or rebuild that ran it left (committed).

    Done: running, or stopped with the reason when it is an app waiting for its files (OK_WAITING). Failed:
    failed with the reason. A site being made by an app install or being removed keeps its state.
    """
    if site.state == "removing" or (site.state == "creating" and site.app_recipe):
        return
    waiting = ok and said == _sw.OK_WAITING
    site.state = ("stopped" if waiting else "running") if ok else "failed"
    site.state_reason = i18n.tr(said)[:200] if waiting or not ok else ""
    db.session.commit()


def _install_worker(app, site_id):
    with app.app_context():
        site = db.session.get(Website, site_id)
        if site is None:
            return
        ok, said = install_site(site)
        site.state = "running"          # a new site's "creating" ends here, whatever the outcome
        note_run_state(site, ok, said)
        forget_status(site_id)


def _add_route(app):
    @app.route("/websites/add", methods=["POST"])
    @login_required
    def website_add():
        if not _wa.can_create(current_user):
            abort(404)
        return _add(body())


def _add(data):
    """Add the site the add form describes (the route has checked can_create)."""
    remote, group, refusal = add_target(data)
    name, kind = field(data, "name").lower(), field(data, "kind") or "static"
    refusal = refusal or add_refusal(remote, name, kind)
    extra, bad = runtime_fields(data, kind) if not refusal else ({}, None)
    if refusal or bad:
        return say(*(refusal or bad))
    site = new_site(remote, name, kind, group, extra)
    from panel.routes import websites_domains
    dom_said = websites_domains.add_first(site, field(data, "domain")) if field(data, "domain") else None
    audit(site, "website_create", "created a %s website on %s%s" % (kind, remote.name, " for %s" % group.name if group else ""))
    start_install(site)
    return jsonify({"success": True, "id": site.id, "message": i18n.tr("Website added. It is being set up."),
                    "domain_note": i18n.tr(dom_said) if dom_said else ""})


# ── running a site ──────────────────────────────────────────────────────────────────────────────
def _run_routes(app):
    @app.route("/websites/<int:site_id>/start", methods=["POST"])
    @login_required
    def website_start(site_id):
        site = _wa.site_for(current_user, site_id, manage_perm(site_id))
        ok, said = host_call(_sw.start, site.remote, site)
        return _ran(site, "website_start", ok, said, "running")

    @app.route("/websites/<int:site_id>/stop", methods=["POST"])
    @login_required
    def website_stop(site_id):
        site = _wa.site_for(current_user, site_id, manage_perm(site_id))
        ok, said = host_call(_sw.stop, site.remote, site)
        return _ran(site, "website_stop", ok, said, "stopped")

    @app.route("/websites/<int:site_id>/restart", methods=["POST"])
    @login_required
    def website_restart(site_id):
        site = _wa.site_for(current_user, site_id, manage_perm(site_id))
        ok, said = host_call(_sw.stop, site.remote, site)
        if ok:
            ok, said = host_call(_sw.start, site.remote, site)
        return _ran(site, "website_restart", ok, said, "running")

    @app.route("/websites/<int:site_id>/logs")
    @login_required
    def website_logs(site_id):
        site = _wa.site_for(current_user, site_id, VIEW_WEBSITES)
        reader = getattr(_sw, "site_logs", None)
        if reader is None:
            return say(501, S_NOT_READY)
        ok, said = host_call(reader, site.remote, site)
        lines = said.splitlines()[-500:] if ok and isinstance(said, str) else []
        return jsonify({"success": bool(ok), "lines": lines, "message": "" if ok else i18n.tr(said)})


def _ran(site, action, ok, said, state):
    if ok and site.state != "creating":
        site.state = state
        site.state_reason = ""
        db.session.commit()
    forget_status(site.id)
    return acted(site, action, ok, said)


# ── administering a site ────────────────────────────────────────────────────────────────────────
def online_refusal(site):
    """Why `site` may not go online now (a sentence), or None.

    It needs a domain, and every domain's DNS must point at the host (website_dns) unless a
    superadmin puts it online anyway, which is audited as such.
    """
    domains = list(site.domains or [])
    if not domains:
        return i18n.Sentence("Add a domain to this website before putting it online.")
    if not current_user.is_superadmin and any(d.dns_state != "matching" for d in domains):
        return i18n.Sentence("A domain of this website does not point at its host yet. Check its DNS on the "
                             "Domains tab, then try again.")
    return None


def _admin_routes(app):
    @app.route("/websites/<int:site_id>/enable", methods=["POST"])
    @login_required
    def website_enable(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        why = online_refusal(site)
        if why:
            audit(site, "website_refused", "not put online: %s" % why)
            return say(409, why)
        site.enabled = True
        db.session.commit()
        ok, said = reconcile_proxy(site.remote)
        if not ok:
            site.enabled = False
            db.session.commit()
            reconcile_proxy(site.remote)
        unchecked = [d.domain for d in site.domains if d.dns_state != "matching"]
        return acted(site, "website_enable", ok, said or "The website is online.",
                     "put online" + (" with DNS not matching for %s" % ", ".join(unchecked) if unchecked else ""))

    @app.route("/websites/<int:site_id>/disable", methods=["POST"])
    @login_required
    def website_disable(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        site.enabled = False
        db.session.commit()
        ok, said = reconcile_proxy(site.remote)
        return acted(site, "website_disable", ok, said or "The website is offline.", "taken offline")

    @app.route("/websites/<int:site_id>/delete", methods=["POST"])
    @login_required
    def website_delete(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        if field(body(), "confirm") != site.name:
            return say(400, S_CONFIRM)
        return _delete(site)

    @app.route("/websites/<int:site_id>/update-image", methods=["POST"])
    @login_required
    def website_update_image(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        ok, said = install_site(site)
        forget_status(site.id)
        return acted(site, "website_update", ok, said, "image updated" if ok else "")

    @app.route("/websites/<int:site_id>/settings", methods=["POST"])
    @login_required
    def website_settings(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        return _settings(site, body())


def _drop_databases(site):
    """Drop every database of `site` (and its user) through the Databases code: (ok, sentence of the first failure)."""
    from panel.routes import databases_sites
    for row in databases_sites.site_rows(site):
        ok, said = databases_sites.drop(site, row)
        if not ok:
            return False, said
    return True, ""


def _delete(site):
    """Take `site` offline, drop its databases, remove its container, unit and account, then its row.

    The databases go first: one that cannot be dropped stops the delete with the site still whole (and
    offline), so a retry finds it; none is left behind belonging to no site.
    """
    remote, name = site.remote, site.name
    was_online = site.enabled
    site.state, site.enabled = "removing", False
    db.session.commit()
    if was_online:
        reconcile_proxy(remote)
    ok, said = _drop_databases(site)
    if ok:
        ok, said = host_call(_sw.remove, remote, site)
    if not ok:
        site.state, site.state_reason = "failed", i18n.tr(said)[:200]
        db.session.commit()
        return acted(site, "website_delete", False, said)
    sid = site.id
    audit(site, "website_delete", "removed website %s, its databases and its account" % name)
    db.session.delete(site)
    db.session.commit()
    forget_status(sid)
    return done(True, "Website removed.")


def _limits(site, fields):
    """Set the limits in `fields` on `site` (not committed): None, or the refusal naming the first bad one."""
    changed = {}
    for key, (low, high) in LIMITS.items():
        if key not in fields:
            continue
        try:
            v = int(str(fields.get(key)).strip())
        except (TypeError, ValueError):
            v = None
        if v is None or not low <= v <= high:
            db.session.rollback()
            return say(400, i18n.Sentence(S_BAD_LIMIT, field=key, low=low, high=high))
        changed[key] = v
    for key, v in changed.items():
        setattr(site, key, v)
    return None


def _keep(site, fields):
    """Set backup_keep from `fields` when given: None, or the refusal."""
    if "backup_keep" not in fields:
        return None
    try:
        keep = int(str(fields.get("backup_keep")))
    except (TypeError, ValueError):
        keep = 0
    if not 1 <= keep <= 60:
        db.session.rollback()
        return say(400, i18n.Sentence(S_BAD_LIMIT, field="backup_keep", low=1, high=60))
    site.backup_keep = keep
    return None


def _settings_flags(site, form):
    """Set the access-log and egress switches and the customer note from the form; their audit words."""
    words = []
    for key in ("access_log", "full_egress"):
        if key in form:
            setattr(site, key, flag(form, key))
            words.append("%s=%s" % (key, "on" if getattr(site, key) else "off"))
    if "customer_note" in form:
        site.customer_note = field(form, "customer_note")[:2000]
        words.append("customer note")
    return words


def _settings_apply(site, limits, form):
    """Apply a saved Settings form on the host: (ok, sentence)."""
    if not any(k in LIMITS for k in limits):
        ok, said = True, "Saved."
    else:
        ok, said = install_site(site)
    if ok and "disk_mb" in limits:
        host_call(_sw.quota_set, site.remote, site)
    if ok and site.enabled and "access_log" in form:
        ok, said = reconcile_proxy(site.remote)
    return ok, said


def _egress_refusal(site, form):
    """404 for anyone but a superadmin changing the site's full-internet switch."""
    changing = "full_egress" in form and flag(form, "full_egress") != bool(site.full_egress)
    if changing and not current_user.is_superadmin:
        abort(404)


def _settings(site, form):
    """The Settings form: {limits: {..., backup_keep}, access_log, full_egress, customer_note}."""
    limits = dict(form.get("limits")) if isinstance(form.get("limits"), dict) else {}
    _egress_refusal(site, form)
    refused = _limits(site, limits) or _keep(site, limits)
    if refused is not None:
        return refused
    words = ["%s=%s" % (k, limits[k]) for k in sorted(limits) if k in LIMITS or k == "backup_keep"]
    words += _settings_flags(site, form)
    db.session.commit()
    ok, said = _settings_apply(site, limits, form)
    return acted(site, "website_settings", ok, said, ", ".join(words) or "none")


def register(app):
    """The Websites routes: these, and the sibling modules'."""
    from panel.routes import (databases_sites, websites_apps, websites_backups, websites_customers, websites_domains,
                              websites_files, websites_proxy, websites_settings, websites_view)
    app.jinja_env.globals["websites_nav"] = websites_view.nav_url
    _list_routes(app)
    _add_route(app)
    _run_routes(app)
    _admin_routes(app)
    for mod in (websites_domains, websites_files, websites_backups, websites_settings, websites_apps,
                websites_customers, websites_proxy, databases_sites):
        mod.register(app)
