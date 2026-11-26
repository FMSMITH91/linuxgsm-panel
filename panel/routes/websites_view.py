"""What the Websites pages read: GET /api/websites (the list) and GET /api/websites/<id> (one site).

The shapes are the ones the pages' scripts document (static/js/websites.js, websites_proxy.js,
website_site.js, website_tuning.js). Every field is cut to what the viewer may see: secrets never (a
tunnel token or an object-cache password only as "set"; an app's environment by its names), admin
fields (limits, the customer note, hosts, customers, how many sites are online) only for an
administrator of that site, the proxy and its settings only for a superadmin, a site's databases only
for someone who may manage it. The caller has already passed site_for.
"""
import json

from flask_login import current_user

from panel.core.config import load_config
from panel.db.models import Group, RemoteServer, Website, WebsiteProxy, db
from panel.security.auth import EDIT_WEBSITE_FILES, MANAGE_WEBSITE, MANAGE_WEBSITES, VIEW_WEBSITES
from panel.services import websites_access as _wa

# Global website settings (config.json websites_<key>): default, low, high (None for text and switches).
# OWASP's recommended values are printed beside them by the page; a value outside them is saved with a
# note (HTTP Strict Transport Security Cheat Sheet, "Examples": max-age=63072000; Transport Layer
# Security Cheat Sheet: TLS 1.3, 1.2 where clients need it; Multifactor Authentication Cheat Sheet).
OPTIONS = {"hsts_max_age": (63072000, 0, 126144000), "tls_min": ("1.2", None, None), "acme_contact": ("", None, None),
           "acme_staging": (False, None, None), "access_log_default": (False, None, None),
           "access_log_days": (7, 1, 90), "max_sites": (3, 1, 100), "require_2fa": (True, None, None),
           "mem_mb": (512, 64, 65536), "cpu_milli": (1000, 100, 64000), "pids": (256, 32, 32768),
           "disk_mb": (2048, 64, 1048576), "max_body_mb": (64, 1, 4096)}
TLS_CHOICES = ("1.2", "1.3")


def _catalog(fn_name, default):
    """A websites_catalog answer, or `default` while the catalog layer has none."""
    from panel.services import websites_catalog
    try:
        got = getattr(websites_catalog, fn_name)()
    except NotImplementedError:
        return default
    return got if isinstance(got, type(default)) else default


def _php_pins():
    from panel.services import websites_catalog
    try:
        got = websites_catalog.pins("php")
    except NotImplementedError:
        return {}
    versions = got.get("versions") if isinstance(got, dict) else None
    return versions if isinstance(versions, dict) else {}


def php_versions():
    """The PHP versions the signed catalog pins, oldest first."""
    return sorted(_php_pins())


def runtime_versions():
    """{runtime: [versions]} the signed catalog offers."""
    out = {}
    for name, entry in _catalog("runtimes", {}).items():
        versions = entry.get("versions") if isinstance(entry, dict) else None
        if isinstance(versions, dict):
            out[str(name)] = sorted(versions)
    return out


def options():
    """The global website settings in force, each checked against its range (else its default)."""
    cfg = load_config()
    out = {}
    for key, (default, low, high) in OPTIONS.items():
        v = cfg.get("websites_" + key, default)
        if isinstance(default, bool):
            v = v if isinstance(v, bool) else default
        elif isinstance(default, int):
            v = v if isinstance(v, int) and not isinstance(v, bool) and low <= v <= high else default
        else:
            v = v if isinstance(v, str) and len(v) <= 254 else default
        out[key] = v
    if out["tls_min"] not in TLS_CHOICES:
        out["tls_min"] = OPTIONS["tls_min"][0]
    return out


def _proxy_json(remote, row):
    from panel.routes.websites_proxy import proxy_json
    if row is None:
        row = WebsiteProxy(remote_id=remote.id)
    return dict(proxy_json(row), host_id=remote.id, host_name=remote.name, installed=bool(row.installed_version),
                version=row.installed_version or "")


def _ports(sites):
    online = [s for s in sites if s.enabled]
    rows = {p.remote_id: p for p in WebsiteProxy.query.filter(
        WebsiteProxy.remote_id.in_(sorted({s.remote_id for s in sites}) or [0])).all()}
    modes = [rows[s.remote_id].exposure_mode for s in online if s.remote_id in rows]
    mode = max(set(modes), key=modes.count) if modes else "public"
    return {"mode": mode, "open": bool(online) and mode != "tunnel", "sites_enabled": len(online), "firewall": "unknown"}


def _missing(admin):
    if not admin:
        return []
    if WebsiteProxy.query.filter(WebsiteProxy.installed_version != "").first() is not None:
        return []
    fix = "" if not current_user.is_superadmin else "/websites#proxy"
    return [{"key": "proxy", "text": "The web proxy is not installed yet: sites can be made, but none can go online.",
             "fix_url": fix}]


def _hosts():
    if current_user.is_superadmin:
        rows = RemoteServer.query.order_by(RemoteServer.id).all()
    else:
        ids = {r.id for g in current_user.groups if not g.is_customer and MANAGE_WEBSITES in g.get_permissions()
               for r in g.servers}
        rows = [r for r in RemoteServer.query.filter(RemoteServer.id.in_(sorted(ids) or [0])).all()
                if not (r.is_local or r.auth_method == "local")]
    return [{"id": r.id, "name": r.name} for r in rows]


def _quota():
    group = next((g for g in current_user.groups if g.is_customer), None) if not current_user.is_superadmin else None
    return {"used": len(group.websites or []), "max": int(group.max_sites or 0)} if group is not None else None


def list_answer(site_json):
    """GET /api/websites."""
    from panel.routes.websites import creates_as_admin, is_admin
    sites = _wa.visible_sites(current_user, VIEW_WEBSITES).all()
    admin = is_admin(current_user)
    out = {"success": True, "sites": [site_json(s, is_admin(current_user, s)) for s in sites],
           "can_create": _wa.can_create(current_user), "missing": _missing(admin), "quota": _quota(),
           "php_versions": php_versions(), "runtimes": runtime_versions(),
           "apps": [{"key": k, "name": str(v.get("name") or k), "version": str(v.get("version") or "")}
                    for k, v in sorted(_catalog("recipes", {}).items()) if isinstance(v, dict)]}
    if admin:
        out["ports"] = _ports(sites)
    if creates_as_admin(current_user):
        out["hosts"] = _hosts()
        out["customers"] = [{"id": g.id, "name": g.name} for g in Group.query.filter_by(is_customer=True).order_by(Group.name)]
    if current_user.is_superadmin:
        rows = {p.remote_id: p for p in WebsiteProxy.query.all()}
        out["proxies"] = [_proxy_json(r, rows.get(r.id)) for r in RemoteServer.query.order_by(RemoteServer.id)]
        out["options"] = options()
    return out


# ── one site ────────────────────────────────────────────────────────────────────────────────────
def _holds(site, perm):
    return _wa.visible_sites(current_user, perm).filter(Website.id == site.id).first() is not None


def _site_block(site, admin, probe):
    dom = site.primary_domain
    facts = (probe or {}).get("facts") or {}
    out = {"id": site.id, "name": site.name, "kind": site.kind, "state": site.state, "state_reason": site.state_reason or "",
           "enabled": bool(site.enabled), "open_url": "https://%s/" % dom.domain if dom and site.enabled else "",
           "image": {"name": site.image_key or "", "version": (site.image_digest or "")[-12:], "update_available": False},
           "app_version": site.app_version or "", "php_version": site.php_version or "",
           "runtime_version": site.runtime_version or "", "last_backup": None,
           "usage": {k: facts.get(k) for k in ("mem_mb", "disk_mb", "cpu_pct") if isinstance(facts.get(k), (int, float))}}
    if admin:
        out["limits"] = {k: getattr(site, k) for k in ("mem_mb", "cpu_milli", "pids", "disk_mb", "max_body_mb", "backup_keep")}
        out.update(access_log=bool(site.access_log), full_egress=bool(site.full_egress), customer_note=site.customer_note or "")
    return out


def _php(site):
    settings = json.loads(site.php_settings or "{}")
    return {"versions": [{"version": v, "eol": False} for v in php_versions()], "version": site.php_version or "",
            "settings": {k: v for k, v in settings.items() if not k.startswith("opcache.")},
            "custom": site.php_ini_custom or "", "eol_note": ""}


def _perf(site):
    settings = json.loads(site.php_settings or "{}")
    return {"opcache": bool(site.opcache), "opcache_memory_mb": _int(settings.get("opcache.memory_consumption")),
            "opcache_revalidate_s": _int(settings.get("opcache.revalidate_freq")), "object_cache": bool(site.object_cache),
            "object_cache_host": "127.0.0.1" if site.object_cache else "", "object_cache_port": 6379 if site.object_cache else None,
            "page_cache": bool(site.page_cache), "page_cache_ttl": site.page_cache_ttl, "static_cache": bool(site.static_cache)}


def _int(v):
    return int(v) if isinstance(v, str) and v.isdecimal() else None


def _app(site):
    from panel.core.config import decrypt_secret
    from panel.services import website_settings
    return {"versions": runtime_versions().get(site.runtime or "node", []), "version": site.runtime_version or "",
            "build": site.build_command or "", "start": site.start_command or "", "port": site.app_port,
            "env_names": website_settings.env_names(site.env_enc, decrypt_secret)}


def site_answer(site, probe, install):
    """GET /api/websites/<id>."""
    from panel.routes.websites import is_admin
    from panel.routes.websites_domains import domain_json
    from panel.services import website_dns
    admin = is_admin(current_user, site)
    manage = _holds(site, MANAGE_WEBSITE)
    records = website_dns.records(site.remote)
    out = {"success": True, "site": _site_block(site, admin, probe), "install": install, "logs": [],
           "domains": [domain_json(site, d) for d in site.domains],
           "dns": {"a": [v for t, v in records if t == "A"], "aaaa": [v for t, v in records if t == "AAAA"]},
           "can": {"manage": manage, "files": _holds(site, EDIT_WEBSITE_FILES), "admin": admin}}
    if manage:
        from panel.routes.databases_sites import site_rows
        out["databases"] = [{"id": r.id, "name": r.name, "user": r.name} for r in site_rows(site)]
        out["php"] = _php(site)
        out["perf"] = _perf(site)
        out["rules"] = json.loads(site.custom_rules or "[]")
        out["app"] = _app(site) if site.kind == "app" else None
        if current_user.is_superadmin:
            out["raw_rules"] = site.raw_proxy_snippet or ""
    return out


def page_flags(site):
    """The flags website.html reads for `site`: can_manage, can_files, site_admin."""
    from panel.routes.websites import is_admin
    return {"can_manage": _holds(site, MANAGE_WEBSITE), "can_files": _holds(site, EDIT_WEBSITE_FILES),
            "site_admin": is_admin(current_user, site)}


def nav_url():
    """websites_nav(): the Websites page's address when the viewer may open it, else ''."""
    from flask import url_for
    try:
        return url_for("websites_page") if _wa.can_open_page(current_user) else ""
    except Exception:  # noqa: BLE001 - the sidebar never breaks a page
        db.session.rollback()
        return ""
