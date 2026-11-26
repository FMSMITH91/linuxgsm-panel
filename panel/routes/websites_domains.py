"""A website's domains: add, remove, check DNS, choose the primary one.

MANAGE_WEBSITE on the site (site_for, 404 otherwise). A domain is held to validation.website_domain
(an allow-list matched whole: lowercase letters, digits and hyphens per label, IDN as punycode, no IP
literal, no wildcard, no reserved suffix; OWASP Input Validation Cheat Sheet, "Allowlist vs Denylist",
"Regular Expressions"), must not be the panel's own name or one any site already has (the unique
column is the backstop), and the site's cap and hourly rate apply (websites_access). The DNS check
compares answers only (services/website_dns; OWASP Server Side Request Forgery Prevention Cheat
Sheet): nothing connects to the domain.
"""
from flask_login import current_user, login_required
from flask import jsonify
from sqlalchemy.exc import IntegrityError

from panel.core import i18n
from panel.core.clock import utcnow
from panel.core.config import load_config
from panel.core.validation import website_domain
from panel.db.models import WebsiteDomain, db
from panel.routes import websites as _w
from panel.security.auth import VIEW_WEBSITES
from panel.services import website_dns as _dns
from panel.services import websites_access as _wa

S_BAD = "That is not a domain a public website can use: letters, digits, hyphens and dots, like www.example.org."
S_TAKEN = "That domain is already used by a website."
S_PANEL = "That is the panel's own address, which is never served as a website."
S_NO_SUCH = "No such domain on this website."


def domain_refusal(site, text):
    """(clean domain, None) when `text` may be added to `site`, else (None, (status, sentence))."""
    clean = website_domain(text)
    if clean is None:
        return None, (400, S_BAD)
    own = website_domain(str(load_config().get("site_domain") or "").split(":", 1)[0])
    if own and clean == own:
        return None, (409, S_PANEL)
    if WebsiteDomain.query.filter_by(domain=clean).first() is not None:
        return None, (409, S_TAKEN)
    quota = _wa.domain_quota_refusal(site)
    if quota:
        return None, (429, quota)
    return clean, None


def _store(site, clean):
    """The new domain row (primary when it is the site's first), or None when another site took it meanwhile."""
    row = WebsiteDomain(website_id=site.id, domain=clean, is_primary=not site.domains,
                        created_by=(current_user.username or "")[:80])
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None
    return row


def add_first(site, text):
    """Add the add form's domain to a new site: None when added, else the sentence why not."""
    clean, refused = domain_refusal(site, text)
    if refused:
        return refused[1]
    if _store(site, clean) is None:
        return S_TAKEN
    _w.audit(site, "website_domain_add", "added domain %s" % clean)
    return None


def _check(site, row):
    state, addrs, hosts = _dns.check(row.domain, site.remote)
    row.dns_state, row.last_check_at = state, utcnow()
    if state == "matching" and row.verified_at is None:
        row.verified_at = utcnow()
    db.session.commit()
    return {"domain": row.domain, "dns_state": state, "answers": addrs, "host": hosts,
            "message": i18n.tr(_dns.S_STATES[state])}


def _row(site, form):
    """The site's domain the form names, by its id (`id`) or its name (`domain`), else None."""
    try:
        did = int(form.get("id"))
    except (TypeError, ValueError):
        did = None
    if did is not None:
        return next((d for d in site.domains if d.id == did), None)
    clean = website_domain(_w.field(form, "domain"))
    return next((d for d in site.domains if d.domain == clean), None) if clean else None


def domain_json(site, row):
    """A domain as the Domains tab shows it."""
    return {"id": row.id, "domain": row.domain, "is_primary": bool(row.is_primary), "dns_state": row.dns_state or "unchecked",
            "cert_not_after": row.cert_not_after.isoformat() if row.cert_not_after else None,
            "cert_state": row.cert_state or "pending", "cert_error": row.cert_error or "",
            "records": [{"type": t, "value": a} for t, a in _dns.records(site.remote)]}


def register(app):
    """The domain routes."""
    @app.route("/websites/<int:site_id>/domains")
    @login_required
    def website_domains(site_id):
        site = _wa.site_for(current_user, site_id, VIEW_WEBSITES)
        return jsonify({"domains": [domain_json(site, d) for d in site.domains]})

    @app.route("/websites/<int:site_id>/domains/add", methods=["POST"])
    @login_required
    def website_domain_add(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        clean, refused = domain_refusal(site, _w.field(_w.body(), "domain"))
        if refused:
            _w.audit(site, "website_domain_add", "refused domain: %s" % i18n.tr(refused[1]), False)
            return _w.say(*refused)
        row = _store(site, clean)
        if row is None:
            return _w.say(409, S_TAKEN)
        _w.audit(site, "website_domain_add", "added domain %s" % clean)
        return jsonify(dict(_check(site, row), success=True))

    @app.route("/websites/<int:site_id>/domains/remove", methods=["POST"])
    @login_required
    def website_domain_remove(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        row = _row(site, _w.body())
        if row is None:
            return _w.say(404, S_NO_SUCH)
        name, was_primary, was_online = row.domain, row.is_primary, site.enabled
        db.session.delete(row)
        db.session.flush()
        rest = [d for d in site.domains if d.domain != name]
        if was_primary and rest:
            rest[0].is_primary = True
        if not rest:
            site.enabled = False          # a site with no domain is served by nothing
        db.session.commit()
        ok, said = _w.reconcile_proxy(site.remote) if was_online else (True, "")
        return _w.acted(site, "website_domain_remove", ok, said or "Domain removed.", "removed domain %s" % name)

    @app.route("/websites/<int:site_id>/domains/check", methods=["POST"])
    @login_required
    def website_domain_check(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        row = _row(site, _w.body())
        if row is None:
            return _w.say(404, S_NO_SUCH)
        got = _check(site, row)
        _w.audit(site, "website_domain_check", "%s: %s" % (row.domain, got["dns_state"]))
        return jsonify(dict(got, success=True))

    @app.route("/websites/<int:site_id>/domains/primary", methods=["POST"])
    @login_required
    def website_domain_primary(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        row = _row(site, _w.body())
        if row is None:
            return _w.say(404, S_NO_SUCH)
        for d in site.domains:
            d.is_primary = d is row
        db.session.commit()
        ok, said = _w.reconcile_proxy(site.remote) if site.enabled else (True, "")
        return _w.acted(site, "website_domain_primary", ok, said or "Primary domain set.", "primary domain %s" % row.domain)
