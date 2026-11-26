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
from panel.services import website_settings as _ws
from panel.services import websites as _svc
from panel.services import websites_access as _wa

PHP_KINDS = ("php", "wordpress", "phpbb")
S_NOT_PHP = "This website does not run PHP."
S_NOT_APP = "This website is not an app."
S_RULES_MAX = 50


def _php_versions():
    """The PHP versions a site may choose now (websites_view.php_versions: the catalog's supported ones)."""
    from panel.routes.websites_view import php_versions
    return tuple(php_versions())


def _problems(problems):
    return _w.say(400, " ".join(i18n.tr(p) for p in problems))


def _php_values(settings):
    """The PHP form's values as text, a switch (display_errors) as On/Off; unknown keys left out."""
    out = {}
    for key, value in (settings or {}).items():
        if key in _ws.PHP_FIELDS and not key.startswith("opcache."):
            out[key] = ("On" if value else "Off") if isinstance(value, bool) else value
    return out


def _version_problem(site, version):
    """Why `version` may not become the site's PHP version (a sentence), None when it may or is unchanged."""
    if version is None or version == site.php_version:
        return None
    if not _w.is_admin(current_user, site):
        abort(404)
    return None if version in _php_versions() else "Choose one of the PHP versions this panel offers."


def _custom_problems(text):
    """[problems] with an Advanced php.ini text (the size here, the lines by the runtime layer's checker)."""
    if text is None:
        return []
    problem = _ws.ini_size_problem(text)
    if problem:
        return [problem]
    return list(_svc.php_ini_problems(text) or [])


def _php_parts(form):
    """(settings dict, Advanced text or None, version or None) from the PHP form, each by its type."""
    settings = form.get("settings") if isinstance(form.get("settings"), dict) else {}
    custom = form.get("custom") if isinstance(form.get("custom"), str) else None
    version = form.get("version") if isinstance(form.get("version"), str) and form.get("version") else None
    return settings, custom, version


def _php_store(site, values, custom, version):
    """Store the checked PHP values, version and Advanced text on `site`; their audit words."""
    site.php_settings = json.dumps(dict(json.loads(site.php_settings or "{}"), **values), sort_keys=True)
    words = ["%s=%s" % kv for kv in sorted(values.items())]
    if version and version != site.php_version:
        site.php_version = version
        words.append("php_version=%s" % version)
    if custom is not None and custom != (site.php_ini_custom or ""):
        site.php_ini_custom = custom
        words.append("Advanced php.ini (%d lines)" % (custom.count("\n") + 1 if custom else 0))
    return words


def _php_save(site, form):
    """POST {version, settings: {...}, custom}: check everything, store it, write the php.ini, restart."""
    settings, custom, version = _php_parts(form)
    values, problems = _ws.php_form(_php_values(settings), site)
    why = _version_problem(site, version)
    try:
        problems += ([why] if why else []) + _custom_problems(custom)
    except NotImplementedError:
        return _w.say(501, _w.S_NOT_READY)
    if problems:
        return _problems(problems)
    new_version = bool(version) and version != site.php_version
    words = _php_store(site, values, custom, version)
    db.session.commit()
    # A new PHP version is a new image: the whole site is installed again (its php.ini with it), else only the php.ini.
    ok, said = _w.install_site(site) if new_version else _w.host_call(_sw.php_apply, site.remote, site)
    _w.forget_status(site.id)
    return _w.acted(site, "website_php", ok, said or "PHP settings applied.", ", ".join(words) or "none")


def _php_routes(app):
    @app.route("/websites/<int:site_id>/php/effective")
    @login_required
    def website_php_effective(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        if site.kind not in PHP_KINDS:
            return _w.say(409, S_NOT_PHP)
        ok, effective = _w.host_call(_sw.php_effective, site.remote, site)
        if not ok or not isinstance(effective, dict):
            return jsonify({"success": False, "values": {}, "message": i18n.tr(effective if not ok else _w.S_UNREACHABLE)})
        return jsonify({"success": True, "values": effective})

    @app.route("/websites/<int:site_id>/php", methods=["POST"])
    @login_required
    def website_php_save(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        if site.kind not in PHP_KINDS:
            return _w.say(409, S_NOT_PHP)
        return _php_save(site, _w.body())


def _opcache_values(form, site):
    """(the OPcache php.ini values from the Performance card, [problems])."""
    fields = {}
    for key, ini in (("opcache_memory_mb", "opcache.memory_consumption"), ("opcache_revalidate_s", "opcache.revalidate_freq")):
        value = form.get(key)
        if value is not None and not isinstance(value, bool):
            fields[ini] = str(value).strip()
    return _ws.php_form(fields, site)


def _perf_check(site, form):
    """(column changes, OPcache values, [problems]) from the Performance card; 404 for a non-admin's object cache."""
    changes, problems = _ws.performance_form({k: v for k, v in form.items() if v is not None})
    opcache, more = _opcache_values(form, site)
    turning = changes.get("object_cache", site.object_cache) != site.object_cache
    if turning and not _w.is_admin(current_user, site):
        abort(404)
    return changes, opcache, problems + more


def _perf_store(site, changes, opcache):
    if changes.get("object_cache") and not site.object_cache_secret:
        import secrets
        site.object_cache_secret = encrypt_secret(secrets.token_urlsafe(32))
    for key, value in changes.items():
        setattr(site, key, value)
    if opcache:
        site.php_settings = json.dumps(dict(json.loads(site.php_settings or "{}"), **opcache), sort_keys=True)
    db.session.commit()


def _perf_apply(site, changes):
    ok, said = _w.host_call(_sw.php_apply, site.remote, site) if site.kind in PHP_KINDS else (True, "")
    proxied = {"page_cache", "page_cache_ttl", "static_cache"} & set(changes)
    if ok and site.enabled and proxied:
        ok, said = _w.reconcile_proxy(site.remote)
    return ok, said


def _performance(site, form):
    """POST the Performance card: OPcache (and its two values), object cache, page cache and its TTL, static caching."""
    changes, opcache, problems = _perf_check(site, form)
    if problems:
        return _problems(problems)
    _perf_store(site, changes, opcache)
    ok, said = _perf_apply(site, changes)
    words = ["%s=%s" % kv for kv in sorted(changes.items())] + ["%s=%s" % kv for kv in sorted(opcache.items())]
    return _w.acted(site, "website_cache", ok, said or "Saved.", ", ".join(words) or "none")


def _rules_list(data):
    """The form's rules as a list of dicts, or None when they are not one (or too many)."""
    rules = data.get("rules", [])
    if not isinstance(rules, list) or len(rules) > S_RULES_MAX:
        return None
    return rules if all(isinstance(r, dict) for r in rules) else None


def _rules_problems(rules):
    """[problems] with the rules (the proxy layer's checker), or None while it is not built."""
    from panel.services import websites_proxy as _wp
    try:
        return list(_wp.rules_problems(rules) or [])
    except NotImplementedError:
        return None


def _rules(site, data):
    rules = _rules_list(data)
    if rules is None:
        return _w.say(400, i18n.Sentence("Custom rules must be a list of at most {n} rules.", n=S_RULES_MAX))
    if "raw" in data and not current_user.is_superadmin:
        abort(404)
    problems = _rules_problems(rules)
    if problems is None:
        return _w.say(501, _w.S_NOT_READY)
    if problems:
        return _problems(problems)
    ok, said = _rules_store(site, rules, data)
    return _w.acted(site, "website_rules", ok, said, "%d custom rules%s" % (len(rules), ", raw snippet" if "raw" in data else ""))


def _rules_store(site, rules, form):
    """Store the checked rules (and a superadmin's raw snippet) and apply them; put the old ones back on a failure."""
    old = (site.custom_rules, site.raw_proxy_snippet)
    site.custom_rules = json.dumps(rules, sort_keys=True)
    if "raw" in form:
        site.raw_proxy_snippet = form["raw"][:8192] if isinstance(form["raw"], str) else ""
    db.session.commit()
    ok, said = _w.reconcile_proxy(site.remote) if site.enabled else (True, "Saved; they apply when the website is online.")
    if not ok:
        site.custom_rules, site.raw_proxy_snippet = old
        db.session.commit()
    return ok, said


def _perf_routes(app):
    @app.route("/websites/<int:site_id>/performance", methods=["POST"])
    @login_required
    def website_performance(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        return _performance(site, _w.body())

    @app.route("/websites/<int:site_id>/cache/purge", methods=["POST"])
    @login_required
    def website_cache_purge(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        if not site.page_cache:
            return _w.say(409, "This website's page cache is off.")
        ok, said = _w.host_call(_sw.cache_purge, site.remote, site)
        return _w.acted(site, "website_cache_purge", ok, said or "Cache emptied.")

    @app.route("/websites/<int:site_id>/rules", methods=["POST"])
    @login_required
    def website_rules(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        return _rules(site, _w.body())


# ── runtime apps ────────────────────────────────────────────────────────────────────────────────
def _saved_env(site):
    """The app's stored environment as a dict ({} when none or unreadable)."""
    try:
        saved = json.loads(decrypt_secret(site.env_enc) or "{}") if site.env_enc else {}
    except (TypeError, ValueError):
        return {}
    return dict(saved) if isinstance(saved, dict) else {}


def merged_env(site, form):
    """(the app's environment after this save, [problems]).

    `env` maps a name to its new value, or to null to keep the value saved (the page never has it);
    `env_remove` lists names to drop.
    """
    env = _saved_env(site)
    asked = form.get("env") if isinstance(form.get("env"), dict) else {}
    for name, value in asked.items():
        if value is None and name not in env:
            return env, [i18n.Sentence("{name} has no saved value to keep.", name=str(name)[:64])]
        if value is not None:
            env[name] = value
    for name in form.get("env_remove") if isinstance(form.get("env_remove"), list) else []:
        env.pop(name, None)
    return env, _ws.env_problems(env)


def _command_field(form, key, out, problems):
    text = form.get(key) if isinstance(form.get(key), str) else ""
    if len(text) > WEBSITE_COMMAND_MAX or any(c in text for c in "\x00\r\n"):
        problems.append(i18n.Sentence("{key} must be one line of at most {n} characters.", key=key, n=WEBSITE_COMMAND_MAX))
    out[key] = text.strip()


def _port_field(form, out, problems):
    text = _w.field(form, "app_port")
    port = int(text) if text.isdecimal() and len(text) <= 5 else 0
    if not WEBSITE_APP_PORT_MIN <= port <= 65535:
        problems.append(i18n.Sentence("The app's port must be {low} to 65535.", low=WEBSITE_APP_PORT_MIN))
    out["app_port"] = port


def _app_fields(site, form):
    """({column: value} the form changes in the app's runtime, commands and port, [problems])."""
    problems, out = [], {}
    if "runtime_version" in form:
        out["runtime_version"] = _w.field(form, "runtime_version")
        if not WEBSITE_RUNTIME_VERSION_RE.match(out["runtime_version"]):
            problems.append("Choose a runtime version this panel offers.")
    for key in ("build_command", "start_command"):
        if key in form:
            _command_field(form, key, out, problems)
    if form.get("app_port") is not None:
        _port_field(form, out, problems)
    return {k: v for k, v in out.items() if v != getattr(site, k)}, problems


def _app_words(fields, env, env_changed):
    words = ["%s=%s" % (k, v) for k, v in sorted(fields.items()) if not k.endswith("_command")]
    if any(k.endswith("_command") for k in fields):
        words.append("commands changed")
    if env_changed:
        words.append("environment: %d variables (%s)" % (len(env), ", ".join(sorted(env))))
    return ", ".join(words) or "none"


def _app_apply(site, fields, env_changed):
    ok, said = _w.install_site(site) if fields else (True, "Saved.")
    if ok and env_changed:
        ok, said = _w.host_call(_sw.env_apply, site.remote, site)
    return ok, said


def _app_save(site, form):
    """POST /app: the runtime, commands and port (administrators) and the environment (whoever runs the site)."""
    fields, problems = _app_fields(site, form)
    env, env_problems = merged_env(site, form)
    if fields and not _w.is_admin(current_user, site):
        abort(404)
    if problems or env_problems:
        return _problems(problems + env_problems)
    env_changed = "env" in form or "env_remove" in form
    for key, value in fields.items():
        setattr(site, key, value)
    if env_changed:
        site.env_enc = encrypt_secret(json.dumps(env, sort_keys=True)) if env else ""
    db.session.commit()
    ok, said = _app_apply(site, fields, env_changed)
    return _w.acted(site, "website_app", ok, said or "Saved.", _app_words(fields, env, env_changed))


def _app_routes(app):
    @app.route("/websites/<int:site_id>/app", methods=["POST"])
    @login_required
    def website_app(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        if site.kind != "app":
            return _w.say(409, S_NOT_APP)
        return _app_save(site, _w.body())

    @app.route("/websites/<int:site_id>/app/build", methods=["POST"])
    @login_required
    def website_app_build(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
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
