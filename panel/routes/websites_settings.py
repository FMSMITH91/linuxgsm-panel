"""A website's PHP settings, performance switches, custom proxy rules and runtime-app settings.

Who: MANAGE_WEBSITE on the site (site_for, 404 otherwise) for the PHP form, the Advanced php.ini, the
Performance card, the cache purge, the custom rules and an app's environment, build and restart;
MANAGE_WEBSITES for what changes the site's software or resources (its PHP version, its object cache
container, an app's runtime, commands and port); a superadmin only for a raw proxy snippet.

Every value is checked before anything is stored (services/website_settings; the Advanced php.ini
line by line and the custom rules by the runtime layer's own checkers), then applied by the runtime
layer: the php.ini is written to the site's own conf.d and the container restarted, a proxy change is
validated by the proxy BEFORE it replaces the running configuration, so a bad rule never takes down
another site (websites.reconcile_proxy -> ssh_manager.websites.proxy_apply). OWASP PHP Configuration
Cheat Sheet (the hardening lines the panel always appends), Input Validation Cheat Sheet, Secrets
Management Cheat Sheet (environment variables encrypted at rest, never logged, never shown back).
"""
import json

from flask import abort, jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import decrypt_secret, encrypt_secret
from panel.core.validation import WEBSITE_APP_PORT_MIN, WEBSITE_COMMAND_MAX, WEBSITE_RUNTIME_VERSION_RE
from panel.db.models import db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.auth import MANAGE_WEBSITE, MANAGE_WEBSITES
from panel.services import website_settings as _ws
from panel.services import websites as _svc
from panel.services import websites_access as _wa

PHP_KINDS = ("php", "wordpress", "phpbb")
S_NOT_PHP = "This website does not run PHP."
S_NOT_APP = "This website is not an app."
S_RULES_MAX = 50


def _php_versions():
    """The PHP versions the signed catalog pins now (none until the catalog layer answers)."""
    from panel.services import websites_catalog
    try:
        got = websites_catalog.pins("php")
    except NotImplementedError:
        return ()
    versions = got.get("versions") if isinstance(got, dict) else None
    return tuple(sorted(versions)) if isinstance(versions, dict) else ()


def _problems(problems):
    return _w.say(400, " ".join(i18n.tr(p) for p in problems))


def _apply_php(site, what):
    db.session.commit()
    ok, said = _w.host_call(_sw.php_apply, site.remote, site)
    _w.forget_status(site.id)
    return _w.acted(site, "website_php", ok, said or "PHP settings applied.", what)


def _php_save(site, data):
    values, problems = _ws.php_form(data, site)
    if "php_version" in data and data.get("php_version") != site.php_version:
        if not _w.is_admin(current_user, site):
            abort(404)
        if data.get("php_version") not in _php_versions():
            problems.append("Choose one of the PHP versions this panel offers.")
    if problems:
        return _problems(problems)
    merged = dict(json.loads(site.php_settings or "{}"), **values)
    site.php_settings = json.dumps(merged, sort_keys=True)
    words = ["%s=%s" % kv for kv in sorted(values.items())]
    if "php_version" in data and data.get("php_version") != site.php_version:
        site.php_version = data.get("php_version")
        words.append("php_version=%s" % site.php_version)
    return _apply_php(site, ", ".join(words) or "none")


def _ini_save(site, text):
    problem = _ws.ini_size_problem(text)
    if problem:
        return _w.say(400, problem)
    try:
        problems = _svc.php_ini_problems(text)
    except NotImplementedError:
        return _w.say(501, _w.S_NOT_READY)
    if problems:
        return _problems(problems)
    site.php_ini_custom = text
    return _apply_php(site, "Advanced php.ini (%d lines)" % (text.count("\n") + 1 if text else 0))


def _php_routes(app):
    @app.route("/websites/<int:site_id>/php")
    @login_required
    def website_php(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if site.kind not in PHP_KINDS:
            return _w.say(409, S_NOT_PHP)
        values = json.loads(site.php_settings or "{}")
        ok, effective = _w.host_call(_sw.php_effective, site.remote, site)
        return jsonify({"version": site.php_version or "", "versions": list(_php_versions()), "values": values,
                        "advanced": site.php_ini_custom or "", "owasp": {k: v[3] for k, v in _ws.PHP_FIELDS.items()},
                        "owasp_notes": _ws.owasp_notes(values),
                        "effective": effective if ok and isinstance(effective, dict) else {}})

    @app.route("/websites/<int:site_id>/php", methods=["POST"])
    @login_required
    def website_php_save(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if site.kind not in PHP_KINDS:
            return _w.say(409, S_NOT_PHP)
        return _php_save(site, _w.body())

    @app.route("/websites/<int:site_id>/php/advanced", methods=["POST"])
    @login_required
    def website_php_advanced(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if site.kind not in PHP_KINDS:
            return _w.say(409, S_NOT_PHP)
        text = _w.body().get("text")
        return _ini_save(site, text if isinstance(text, str) else None)


def _performance(site, data):
    changes, problems = _ws.performance_form(data)
    if problems:
        return _problems(problems)
    if "object_cache" in changes and changes["object_cache"] != site.object_cache and not _w.is_admin(current_user, site):
        abort(404)
    if changes.get("object_cache") and not site.object_cache_secret:
        import secrets
        site.object_cache_secret = encrypt_secret(secrets.token_urlsafe(32))
    for key, value in changes.items():
        setattr(site, key, value)
    db.session.commit()
    ok, said = _w.host_call(_sw.php_apply, site.remote, site) if site.kind in PHP_KINDS else (True, "")
    if ok and site.enabled and ({"page_cache", "page_cache_ttl", "static_cache"} & set(changes)):
        ok, said = _w.reconcile_proxy(site.remote)
    return _w.acted(site, "website_cache", ok, said or "Saved.",
                    ", ".join("%s=%s" % kv for kv in sorted(changes.items())) or "none")


def _rules(site, data):
    rules = data.get("rules", [])
    if not isinstance(rules, list) or len(rules) > S_RULES_MAX or not all(isinstance(r, dict) for r in rules):
        return _w.say(400, "Custom rules must be a list of at most %d rules." % S_RULES_MAX)
    from panel.services import websites_proxy as _wp
    try:
        problems = _wp.rules_problems(rules)
    except NotImplementedError:
        return _w.say(501, _w.S_NOT_READY)
    if problems:
        return _problems(problems)
    old_rules, old_raw = site.custom_rules, site.raw_proxy_snippet
    site.custom_rules = json.dumps(rules, sort_keys=True)
    if "raw" in data:
        if not current_user.is_superadmin:
            abort(404)
        raw = data.get("raw")
        site.raw_proxy_snippet = raw[:8192] if isinstance(raw, str) else ""
    db.session.commit()
    ok, said = _w.reconcile_proxy(site.remote) if site.enabled else (True, "Saved; they apply when the website is online.")
    if not ok:
        site.custom_rules, site.raw_proxy_snippet = old_rules, old_raw
        db.session.commit()
    return _w.acted(site, "website_rules", ok, said, "%d custom rules%s" % (len(rules), ", raw snippet" if "raw" in data else ""))


def _perf_routes(app):
    @app.route("/websites/<int:site_id>/performance", methods=["POST"])
    @login_required
    def website_performance(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        return _performance(site, _w.body())

    @app.route("/websites/<int:site_id>/cache/purge", methods=["POST"])
    @login_required
    def website_cache_purge(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if not site.page_cache:
            return _w.say(409, "This website's page cache is off.")
        ok, said = _w.host_call(_sw.cache_purge, site.remote, site)
        return _w.acted(site, "website_cache_purge", ok, said or "Cache emptied.")

    @app.route("/websites/<int:site_id>/rules", methods=["POST"])
    @login_required
    def website_rules(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        return _rules(site, _w.body())


# ── runtime apps ────────────────────────────────────────────────────────────────────────────────
def _env_save(site, data):
    env = data.get("env")
    problems = _ws.env_problems(env)
    if problems:
        return _problems(problems)
    site.env_enc = encrypt_secret(json.dumps(env, sort_keys=True)) if env else ""
    db.session.commit()
    ok, said = _w.host_call(_sw.env_apply, site.remote, site)
    return _w.acted(site, "website_env", ok, said or "Saved.", "environment: %d variables (%s)" % (len(env), ", ".join(sorted(env))))


def _app_settings(site, data):
    problems = []
    version = _w.field(data, "runtime_version", site.runtime_version or "")
    if not WEBSITE_RUNTIME_VERSION_RE.match(version):
        problems.append("Choose a runtime version this panel offers.")
    commands = {}
    for key in ("build_command", "start_command"):
        if key in data:
            text = data.get(key) if isinstance(data.get(key), str) else ""
            if len(text) > WEBSITE_COMMAND_MAX or any(c in text for c in "\x00\r\n"):
                problems.append("%s must be one line of at most %d characters." % (key, WEBSITE_COMMAND_MAX))
            commands[key] = text.strip()
    port = site.app_port
    if "app_port" in data:
        text = _w.field(data, "app_port")
        port = int(text) if text.isdecimal() and len(text) <= 5 else 0
        if not WEBSITE_APP_PORT_MIN <= port <= 65535:
            problems.append("The app's port must be %d to 65535." % WEBSITE_APP_PORT_MIN)
    if problems:
        return _problems(problems)
    site.runtime_version, site.app_port = version, port
    for key, text in commands.items():
        setattr(site, key, text)
    db.session.commit()
    ok, said = _w.host_call(_sw.install, site.remote, site)
    return _w.acted(site, "website_update", ok, said, "app settings: version %s, port %s%s" % (
        version or "-", port or "-", ", commands changed" if commands else ""))


def _app_routes(app):
    @app.route("/websites/<int:site_id>/app/env")
    @login_required
    def website_app_env(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        return jsonify({"names": _ws.env_names(site.env_enc, decrypt_secret)})

    @app.route("/websites/<int:site_id>/app/env", methods=["POST"])
    @login_required
    def website_app_env_save(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if site.kind != "app":
            return _w.say(409, S_NOT_APP)
        return _env_save(site, _w.body())

    @app.route("/websites/<int:site_id>/app/settings", methods=["POST"])
    @login_required
    def website_app_settings(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITES)
        if site.kind != "app":
            return _w.say(409, S_NOT_APP)
        return _app_settings(site, _w.body())

    @app.route("/websites/<int:site_id>/app/build", methods=["POST"])
    @login_required
    def website_app_build(site_id):
        site = _wa.site_for(current_user, site_id, MANAGE_WEBSITE)
        if site.kind != "app":
            return _w.say(409, S_NOT_APP)
        ok, said = _w.host_call(_sw.app_build, site.remote, site)
        _w.forget_status(site.id)
        return _w.acted(site, "website_build", ok, said or "Built.")


def register(app):
    """The settings routes."""
    _php_routes(app)
    _perf_routes(app)
    _app_routes(app)
