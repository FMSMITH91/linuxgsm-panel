"""A website's domains: add, remove, check DNS, choose the primary one.

MANAGE_WEBSITE on the site (site_for, 404 otherwise). A domain is held to validation.website_domain
(an allow-list matched whole: lowercase letters, digits and hyphens per label, IDN as punycode, no IP
literal, no wildcard, no reserved suffix; OWASP Input Validation Cheat Sheet, "Allowlist vs Denylist",
"Regular Expressions"), must not be the panel's own name or one any site already has (the unique
column is the backstop), and the site's cap and hourly rate apply (websites_access). The DNS check
compares answers only (services/website_dns; OWASP Server Side Request Forgery Prevention Cheat
Sheet): nothing connects to the domain.

CERTIFICATES. Each domain shows the certificate the web proxy serves for it (website-proxy-status: the
issuer the proxy's configuration uses, else the latest), read at most every CERTS_FRESH seconds per host
when a site's page or its Domains tab is opened, and whenever a superadmin reads the proxy's status. A
test (Let's Encrypt staging) or local certificate is said plainly: browsers do not trust it (OWASP
Transport Layer Security Cheat Sheet, "Use an Appropriate Certification Authority for the Application's
User Base"). So is one close to expiry: the proxy renews a certificate once a third of its lifetime is
left (15 days or more for Let's Encrypt's 45- to 90-day certificates), so fewer than CERT_SOON_DAYS left
means renewal has been failing for days.

YOUR OWN CERTIFICATE (POST .../domains/cert, the same permission as the other domain routes). A domain may
use a certificate the operator pastes (its chain and private key, PEM; a Cloudflare Origin CA certificate
is this case) instead of the automatic one, and go back to automatic at any time. The pair is checked by
tls_own.check_for_domain, the panel's own certificate checks (OWASP Transport Layer Security Cheat Sheet,
"Use Strong Keys and Protect Them", "Use Strong Cryptographic Hashing Algorithms", "Use Correct Domain
Names", "Use an Appropriate Certification Authority for the Application's User Base"): what would fail
every visitor is refused, the rest is a note shown with OWASP's value. The chain is stored re-encoded from
what was parsed; the key re-encoded and encrypted (encrypt_secret), never returned by any route, never in
an audit row or a log line (OWASP Logging Cheat Sheet, "Data to exclude"; Key Management Cheat Sheet,
"Storage"), and sent to the host only on the helper's stdin. The audit row names the domain, the issuer,
the expiry and the SHA-256 fingerprint. A domain online is applied at once (websites.reconcile_proxy); a
failed apply puts the previous certificate back, applies that again, and says why. The proxy never renews
such a certificate: the domain's line warns from tls_own.SOON_DAYS days before expiry, and so does the
cert_expiring alert (services/website_certs).
"""
import time
from datetime import datetime, timezone

from flask_login import current_user, login_required
from flask import jsonify
from sqlalchemy.exc import IntegrityError

from panel.core import i18n
from panel.core.clock import utcnow
from panel.core.config import encrypt_secret, load_config
from panel.core.validation import website_domain
from panel.db.models import Website, WebsiteDomain, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.auth import VIEW_WEBSITES
from panel.services import tls_own
from panel.services import website_certs as _wcert
from panel.services import website_dns as _dns
from panel.services import websites_access as _wa

S_BAD = "That is not a domain a public website can use: letters, digits, hyphens and dots, like www.example.org."
S_TAKEN = "That domain is already used by a website."
S_PANEL = "That is the panel's own address, which is never served as a website."
S_NO_SUCH = "No such domain on this website."
# The domain's label already says "browsers do not trust it" (WS.CERT): the warning under it says what to do.
S_CERT_STAGING = "Turn off the test service in the web proxy's Security settings to get a certificate browsers trust."
S_CERT_LOCAL = "Turn off local certificates in the web proxy's Security settings to get a certificate browsers trust."
S_CERT_EXPIRED = ("This domain's certificate has expired and was not renewed. Check that ports 80 and 443 of this "
                  "host are reachable from the internet.")
S_CERT_SOON = ("This domain's certificate expires in {days} days and should have been renewed by now. Check that "
               "ports 80 and 443 of this host are reachable from the internet.")
S_OWN_EXPIRED = ("The certificate you gave this domain has expired, so browsers refuse it. Paste a renewed one, or "
                 "switch back to automatic.")
S_OWN_SOON = "The certificate you gave this domain expires in {days} day(s). Paste the renewed one before then."
S_CERT_MODE = "Choose Automatic (Let's Encrypt) or Your own certificate."
S_CERT_OWN_SAVED = "Saved: {domain} uses your own certificate."
S_CERT_AUTO_SAVED = "Saved: {domain} gets its certificate automatically from Let's Encrypt."
S_CERT_ROLLED_BACK = "The web proxy did not take the change, so {domain} keeps its previous certificate. {why}"
S_CERT_NOT_SERVED = "It is used once the domain's DNS points here and the website is online."
S_CERT_TUNNEL = ("This host's websites are reached through a tunnel, so the tunnel's provider serves the "
                 "certificate visitors see. This one is used if the host stops using the tunnel.")
CERTS_FRESH = 300                 # seconds a host's certificate read is reused
CERT_SOON_DAYS = 10
_CERTS_AT = {}                    # remote id -> monotonic time of its last certificate read
TRUSTED = ("issued", "zerossl", "other")


def cert_kind(issuer):
    """The domain's cert_state for the proxy's storage folder of its issuer."""
    if issuer == "local":
        return "local"
    if "staging" in issuer:
        return "staging"
    if "zerossl" in issuer:
        return "zerossl"
    return "issued" if "letsencrypt" in issuer else "other"


def apply_certs(remote, status):
    """Write the certificates the proxy serves (parse_proxy_status's certs) onto the host's automatic domains."""
    certs = (status or {}).get("certs") or {}
    rows = (WebsiteDomain.query.join(Website, WebsiteDomain.website_id == Website.id)
            .filter(Website.remote_id == remote.id, WebsiteDomain.cert_mode == "acme").all())
    for row in rows:
        got = certs.get(row.domain)
        if got:
            row.cert_state = cert_kind(got["issuer"])
            row.cert_not_after = datetime.fromtimestamp(got["not_after"], timezone.utc).replace(tzinfo=None)
    db.session.commit()


def refresh_certs(remote):
    """Read the host's served certificates onto its domains, at most once per CERTS_FRESH seconds."""
    now = time.monotonic()
    last = _CERTS_AT.get(remote.id)
    if last is not None and now - last < CERTS_FRESH:
        return
    _CERTS_AT[remote.id] = now
    ok, out = _w.host_call(_sw.proxy_status, remote)
    if ok:
        apply_certs(remote, _sw.parse_proxy_status(out))


def _own_note(row, now):
    """The warning for a domain's own certificate: expired, or tls_own.SOON_DAYS days or fewer left."""
    if row.cert_not_after is None:
        return ""
    left = row.cert_not_after - (now or utcnow())
    if left.total_seconds() <= 0:
        return S_OWN_EXPIRED
    return i18n.Sentence(S_OWN_SOON, days=left.days) if left.days <= tls_own.SOON_DAYS else ""


def cert_note(row, now=None):
    """The plain warning for the certificate `row` is served, or "" when there is nothing to say."""
    if row.cert_mode == "own":
        return _own_note(row, now)
    if row.cert_state == "staging":
        return S_CERT_STAGING
    if row.cert_state == "local":
        return S_CERT_LOCAL
    if row.cert_not_after is None or row.cert_state not in TRUSTED:
        return ""
    left = row.cert_not_after - (now or utcnow())
    if left.total_seconds() <= 0:
        return S_CERT_EXPIRED
    return i18n.Sentence(S_CERT_SOON, days=left.days) if left.days < CERT_SOON_DAYS else ""


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
    note = cert_note(row)
    own = _wcert.info(row.own_cert_pem) if row.cert_mode == "own" else None
    return {"id": row.id, "domain": row.domain, "is_primary": bool(row.is_primary), "dns_state": row.dns_state or "unchecked",
            "cert_not_after": row.cert_not_after.isoformat() if row.cert_not_after else None,
            "cert_state": row.cert_state or "pending", "cert_error": row.cert_error or "",
            "cert_warning": i18n.tr(note) if note else "", "cert_mode": "own" if own else "acme",
            "own_cert": {k: own[k] for k in ("issuer", "subject", "names", "not_after", "fingerprint", "cdn_origin")}
            if own else None,
            "records": [{"type": t, "value": a} for t, a in _dns.records(site.remote)]}


# ── a domain's own certificate ────────────────────────────────────────────────────────────────
_CERT_COLUMNS = ("cert_mode", "own_cert_pem", "own_key_secret", "cert_state", "cert_not_after", "cert_error")


def _pem_field(form, name):
    """A pasted PEM field as bytes (b"" when absent or not text; tls_own bounds its size)."""
    value = form.get(name)
    return value.encode("utf-8", "replace") if isinstance(value, str) else b""


def _set_own(row, checked):
    row.cert_mode, row.cert_state, row.cert_error = "own", "own", ""
    row.own_cert_pem = checked.cert_pem().decode("ascii")
    row.own_key_secret = encrypt_secret(checked.key_pem().decode("ascii"))
    row.cert_not_after = _wcert.not_after(checked)


def _set_auto(row):
    row.cert_mode, row.cert_state, row.cert_error = "acme", "pending", ""
    row.own_cert_pem, row.own_key_secret, row.cert_not_after = "", "", None


def _cert_detail(row, checked):
    """The audit row's text: the domain, and of an own certificate its issuer, expiry and fingerprint (never the key)."""
    if checked is None:
        return "%s: automatic certificate" % row.domain
    got = tls_own.summary(checked.chain)
    return "%s: own certificate, issuer %s, expires %s, sha256 %s" % (
        row.domain, got["issuer"], got["not_after"], got["fingerprint"])


def _apply_cert(site, row, before):
    """Apply the domain's new certificate when the site is online: (ok, sentence); on failure `before` is put back."""
    if not site.enabled:
        return True, ""
    ok, said = _w.reconcile_proxy(site.remote)
    if ok:
        return True, ""
    for col, value in zip(_CERT_COLUMNS, before):
        setattr(row, col, value)
    db.session.commit()
    _w.reconcile_proxy(site.remote)       # the previous configuration and files, written again
    return False, i18n.Sentence(S_CERT_ROLLED_BACK, domain=row.domain, why=i18n.tr(said))


def _cert_notes(site, row, checked):
    """The notes the page shows after a save: the checks' notes, and where the certificate is not served yet."""
    notes = [i18n.tr(n) for n in (checked.notes if checked is not None else [])]
    if checked is not None and (row.verified_at is None or not site.enabled):
        notes.append(i18n.tr(S_CERT_NOT_SERVED))
    if checked is not None and _w.proxy_row(site.remote_id).exposure_mode == "tunnel":
        notes.append(i18n.tr(S_CERT_TUNNEL))
    return notes


def set_cert(site, row, form):
    """POST .../domains/cert's work: check, store, apply (or put back). -> the route's answer."""
    mode = _w.field(form, "mode")
    if mode not in ("acme", "own"):
        return _w.say(400, S_CERT_MODE)
    checked = None
    if mode == "own":
        checked = tls_own.check_for_domain(_pem_field(form, "cert"), _pem_field(form, "key"), row.domain)
        if checked.refusal:
            _w.audit(site, "website_domain_cert", "%s: own certificate refused: %s" % (row.domain, checked.refusal), False)
            return _w.say(400, checked.refusal)
    before = tuple(getattr(row, col) for col in _CERT_COLUMNS)
    if checked is None:
        _set_auto(row)
    else:
        _set_own(row, checked)
    db.session.commit()
    _CERTS_AT.pop(site.remote_id, None)   # the next read of the served certificates is a fresh one
    ok, why = _apply_cert(site, row, before)
    if not ok:
        _w.audit(site, "website_domain_cert", "%s: not applied: %s" % (_cert_detail(row, checked), why), False)
        return _w.done(False, why)
    _w.audit(site, "website_domain_cert", _cert_detail(row, checked))
    said = i18n.Sentence(S_CERT_OWN_SAVED if checked is not None else S_CERT_AUTO_SAVED, domain=row.domain)
    return jsonify({"success": True, "message": i18n.tr(said), "notes": _cert_notes(site, row, checked),
                    "domain": domain_json(site, row)})


def register(app):
    """The domain routes."""
    @app.route("/websites/<int:site_id>/domains")
    @login_required
    def website_domains(site_id):
        site = _wa.site_for(current_user, site_id, VIEW_WEBSITES)
        refresh_certs(site.remote)
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

    @app.route("/websites/<int:site_id>/domains/cert", methods=["POST"])
    @login_required
    def website_domain_cert(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        form = _w.body()
        row = _row(site, form)
        if row is None:
            return _w.say(404, S_NO_SUCH)
        return set_cert(site, row, form)

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
