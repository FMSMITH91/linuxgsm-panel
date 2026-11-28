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

THE SITE'S CERTIFICATE (POST .../cert, the same permission as the other domain routes). The operator pastes one
chain and key for the site; each of its domains the certificate covers (tls_own.check_for_domain per domain) uses
it, and each it does not stays automatic, listed with the reason. A domain added later that it covers uses it at
once. The pair is stored once on the site (Website.own_cert_pem, own_key_secret), the domains only point at it
(cert_mode 'site'); "Back to automatic" is one action for the site. A Cloudflare Origin CA certificate for a name
and its wildcard is pasted once for both.

YOUR OWN CERTIFICATE FOR ONE DOMAIN (POST .../domains/cert), kept for a domain that needs a different one. A domain
may use a certificate the operator pastes (its chain and private key, PEM; a Cloudflare Origin CA certificate
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
from panel.core.config import decrypt_secret, encrypt_secret, load_config
from panel.core.validation import website_address, website_domain, website_folder
from panel.db.models import Website, WebsiteDomain, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.services import tls_own
from panel.services import website_certs as _wcert
from panel.services import website_dns as _dns
from panel.services import website_folders as _wf
from panel.services import websites_access as _wa
from panel.services import websites_catalog as _wcat

S_BAD = "That is not a domain a public website can use: letters, digits, hyphens and dots, like www.example.org."
S_TAKEN = "That domain is already used by a website."
S_BAD_FOLDER = ("A folder is lowercase letters, digits, - and _ after the domain and a /, like example.org/forums, "
                "at most 64 characters.")
S_FOLDER_NEEDED = "Type the folder the website lives in, like forums."
S_MOVED_FAILED = "The address was added, but the website's own server could not be set up for the folder: {why}"
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
# A self-signed certificate is noted once when it is saved (tls_own's chain notes); the domain's line keeps saying
# so, as browsers keep warning (OWASP Transport Layer Security Cheat Sheet, "Use an Appropriate
# Certification Authority for the Application's User Base").
S_OWN_SELF_SIGNED = ("The certificate you gave this domain is self-signed, so visitors' browsers warn. Use one from a "
                     "well-known authority, or switch back to automatic (Let's Encrypt).")
# The site's one certificate is warned about once, on the site's certificate line, never again on each domain on it.
S_SITE_SELF_SIGNED = ("The site's certificate is self-signed, so visitors' browsers warn. Use one from a well-known "
                      "authority, or switch back to automatic (Let's Encrypt).")
S_SITE_EXPIRED = "The site's certificate has expired, so browsers refuse it. Paste a renewed one, or switch back to automatic."
S_SITE_SOON = "The site's certificate expires in {days} day(s). Paste the renewed one before then."
S_CERT_MODE = "Choose Automatic (Let's Encrypt) or Your own certificate."
S_CERT_OWN_SAVED = "Saved: {domain} uses your own certificate."
S_CERT_AUTO_SAVED = "Saved: {domain} gets its certificate automatically from Let's Encrypt."
S_CERT_ROLLED_BACK = "The web proxy did not take the change, so {domain} keeps its previous certificate. {why}"
S_CERT_NOT_SERVED = "It is used once the domain's DNS points here and the website is online."
S_SITE_CERT_SAVED = "Saved: the site's certificate is used for {names}."
S_SITE_CERT_AUTO = "Saved: every domain of this site gets its certificate automatically from Let's Encrypt again."
S_SITE_CERT_NONE = "The certificate covers none of this site's domains, so nothing was saved. {why}"
S_SITE_CERT_NO_DOMAIN = "Add a domain first: a certificate is checked against the site's domains."
S_SITE_CERT_UNCOVERED = "{domain} stays automatic: {why}"
S_SITE_CERT_ROLLED_BACK = "The web proxy did not take the change, so the site keeps its previous certificates. {why}"
S_CERT_TUNNEL = ("This host's websites are reached through a tunnel, so the tunnel's provider serves the "
                 "certificate visitors see. This one is used if the host stops using the tunnel.")
S_SERVED_NOW = "The domain points here: the website now answers on it."
S_WP_ADDRESS_SET = "WordPress now uses https://{domain} as its address."
S_WP_ADDRESS_FAILED = "WordPress's address could not be changed to https://{domain}, so the primary domain stays {old}. {why}"
S_CERT_MISSING = ("No certificate yet. Usually ports 80 and 443 of this host do not reach it from the internet: check "
                  "the host's firewall and your cloud provider's.")
S_CERT_PROXY_SAID = "No certificate yet. The web proxy said: {why}"
CERT_MISSING_AFTER = 600          # seconds a served domain may wait for its first certificate before it is called failed
_MISSING_SINCE = {}               # domain name -> monotonic time apply_certs first found it served without a certificate
# A domain behind a CDN (dns_state cdn): what its certificate needs. The CDN's name, and its own origin certificate
# and strict TLS mode where the signed catalog names them, come from the catalog (websites_catalog.cdn_info).
S_CDN_ACME = ("Otherwise the automatic certificate needs {provider} to pass plain HTTP to this host for "
              "/.well-known/acme-challenge/.")
S_CDN_MAYBE = ("If {provider} offers an origin certificate, paste it under Your own certificate and use its strict "
               "TLS mode.")
S_CDN_ORIGIN = ("Paste a {origin_cert} certificate under Your own certificate and set {provider}'s encryption mode to "
                "{strict_mode}.")
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
    errors = (status or {}).get("cert_errors") or {}
    rows = (WebsiteDomain.query.join(Website, WebsiteDomain.website_id == Website.id)
            .filter(Website.remote_id == remote.id, WebsiteDomain.cert_mode == "acme").all())
    tunnel = _w.tunnel_mode(remote.id)      # the proxy asks for no certificate: none is missing
    for row in rows:
        got = certs.get(row.domain)
        if got:
            _MISSING_SINCE.pop(row.domain, None)
            row.cert_state, row.cert_error = cert_kind(got["issuer"]), ""
            row.cert_not_after = datetime.fromtimestamp(got["not_after"], timezone.utc).replace(tzinfo=None)
        elif tunnel:
            _MISSING_SINCE.pop(row.domain, None)
        else:
            _note_missing(row, errors.get(row.domain, ""))
    db.session.commit()


def _note_missing(row, why="", now=None):
    """Note a domain served by an online site with no certificate.

    The proxy's own reason (`why`) is kept as soon as it has one, and the domain is failed after CERT_MISSING_AFTER
    seconds, with that reason or the usual one (S_CERT_MISSING).
    """
    if row.verified_at is None or row.website is None or not row.website.enabled:
        _MISSING_SINCE.pop(row.domain, None)
        return
    now = time.monotonic() if now is None else now
    since = _MISSING_SINCE.setdefault(row.domain, now)
    if why:
        row.cert_error = why[:200]
    if now - since >= CERT_MISSING_AFTER and row.cert_state in ("pending", "failed"):
        row.cert_state, row.cert_error = "failed", why[:200] or S_CERT_MISSING


def _error_text(row):
    """The domain's certificate error for the page, in the viewer's language: the usual reason, or the proxy's words."""
    if not row.cert_error:
        return ""
    if row.cert_error == S_CERT_MISSING:
        return i18n.tr(S_CERT_MISSING)
    return i18n.tr(S_CERT_PROXY_SAID, why=row.cert_error)


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


def _own_pem(row):
    """The chain a domain on an operator's certificate is served with: the site's for 'site', its own for 'own'."""
    if row.cert_mode == "site":
        return (row.website.own_cert_pem if row.website is not None else "") or ""
    return row.own_cert_pem or "" if row.cert_mode == "own" else ""


def _own_note(row, now):
    """The warning for a domain's own certificate: self-signed, and expired or tls_own.SOON_DAYS days or fewer left."""
    info = _wcert.info(_own_pem(row)) or {}
    notes = [S_OWN_SELF_SIGNED] if info.get("self_signed") and not info.get("cdn_origin") else []
    if row.cert_not_after is not None:
        left = row.cert_not_after - (now or utcnow())
        if left.total_seconds() <= 0:
            notes.append(S_OWN_EXPIRED)
        elif left.days <= tls_own.SOON_DAYS:
            notes.append(i18n.Sentence(S_OWN_SOON, days=left.days))
    return i18n.Sentences(*notes) if notes else ""


def cert_note(row, now=None):
    """The plain warning for the certificate `row` is served, or "" when there is nothing to say.

    A domain on the site's certificate has none of its own: the site's certificate line says it once (site_cert_json).
    """
    if row.cert_mode == "site":
        return ""
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


def _address(text, folder=None):
    """((domain, folder), None) of the typed address, `folder` (when given) as its folder; else (None, the refusal)."""
    got = website_address(text)
    if got is None:
        head = text.strip().partition("/")[0] if isinstance(text, str) else None
        return None, (400, S_BAD_FOLDER if website_domain(head) is not None else S_BAD)
    clean, path = got
    if folder is not None and not path:
        path = website_folder(folder)
        if not path:
            return None, (400, S_BAD_FOLDER if path is None else S_FOLDER_NEEDED)
    return (clean, path), None


def domain_refusal(site, text, folder=None):
    """((domain, folder), None) when address `text` may be added to `site`, else (None, (status, sentence)).

    `text` is a domain, or a domain and its folder (example.org/forums); `folder`, from the Domains tab's folder
    form, is the folder when `text` names none ("" there is refused: that form adds a folder). Who may put a site
    in a folder of which domain is website_folders.refusal's question.
    """
    got, refused = _address(text, folder)
    if refused:
        return None, refused
    clean, path = got
    own = website_domain(str(load_config().get("site_domain") or "").split(":", 1)[0])
    if own and clean == own:
        return None, (409, S_PANEL)
    refused = _wf.refusal(current_user, site, clean, path)
    if refused:
        return None, refused
    quota = _wa.domain_quota_refusal(site)
    if quota:
        return None, (429, quota)
    return got, None


def _store(site, clean, path=""):
    """The new address row (primary when it is the site's first), or None when another site took it meanwhile."""
    row = WebsiteDomain(website_id=site.id, domain=clean, path=path, is_primary=not site.domains,
                        created_by=(current_user.username or "")[:80])
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None
    checked = _site_check(site, clean)
    if checked is not None and not checked.refusal:
        _use_site_cert(row, checked)
        db.session.commit()
    return row


def _site_check(site, name):
    """tls_own.check_for_domain of the site's own certificate for `name`, or None when the site has none."""
    if not (site.own_cert_pem and site.own_key_secret):
        return None
    key = decrypt_secret(site.own_key_secret) or ""
    return tls_own.check_for_domain(site.own_cert_pem.encode("ascii", "replace"), key.encode("ascii", "replace"), name)


def add_first(site, text):
    """Add the add form's address (a domain, or domain/folder) to a new site: None when added, else the sentence why not."""
    got, refused = domain_refusal(site, text)
    if refused:
        return refused[1]
    row = _store(site, *got)
    if row is None:
        return S_TAKEN
    _w.audit(site, "website_domain_add", "added domain %s" % row.address)
    _check(site, row)         # its DNS at once, so it is verified (and served once online) without a Check again
    return None


def check_all(site):
    """Check every domain of `site` again (before it goes online): a domain now pointing here is verified."""
    for row in list(site.domains or []):
        _check(site, row)


def _check(site, row):
    """Check the domain's DNS; one newly verified on a site online is applied at once (served from now on)."""
    state, addrs, hosts = _dns.check(row.domain, site.remote)
    row.dns_state, row.last_check_at = state, utcnow()
    row.dns_cdn = _dns.provider(addrs) if state == "cdn" else ""
    newly = state in _dns.VERIFIED and row.verified_at is None
    if newly:
        row.verified_at = utcnow()
    db.session.commit()
    said = _dns.state_sentence(state, row.dns_cdn)
    if newly and site.enabled:
        ok, why = _w.reconcile_proxy(site.remote)
        said = S_SERVED_NOW if ok else why
    return {"domain": row.domain, "address": row.address, "dns_state": state, "answers": addrs, "host": hosts,
            "message": i18n.tr(said)}


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


def domain_json(site, row, tunnel=None):
    """A domain as the Domains tab shows it.

    On a host in tunnel mode (`tunnel`, read from the host's proxy row when None) the proxy holds no certificate:
    the tunnel's provider serves HTTPS, so the state is "tunnel", never a certificate pending for good.
    """
    tunnel = _w.tunnel_mode(site.remote_id) if tunnel is None else tunnel
    return {**_cert_part(row, tunnel), **_cert_json(row, tunnel), "id": row.id, "domain": row.domain,
            "path": row.path or "", "address": row.address, "shared_note": _wf.shared_note(row),
            "is_primary": bool(row.is_primary), "dns_state": row.dns_state or "unchecked", "cdn_name": _cdn_name(row),
            "cert_error": "" if tunnel else _error_text(row),
            "records": [{"type": t, "value": a} for t, a in _dns.records(site.remote)]}


def _cert_part(row, tunnel):
    """The domain's certificate fields: its state, expiry and warning; the tunnel's state in tunnel mode."""
    if tunnel:
        return {"cert_state": "tunnel", "cert_not_after": None, "cert_warning": ""}
    note = cert_note(row)
    return {"cert_state": row.cert_state or "pending", "cert_warning": i18n.tr(note) if note else "",
            "cert_not_after": row.cert_not_after.isoformat() if row.cert_not_after else None}


def _cert_json(row, tunnel=False):
    """A domain's certificate source for the Domains tab: its own certificate's public facts, or the CDN note.

    In tunnel mode the tunnel's provider holds the certificate visitors see, so there is no CDN note about an
    automatic one; an own certificate's facts still show (it is used again if the host stops using the tunnel).
    """
    own = _wcert.info(_own_pem(row))
    if own:
        return {"cert_mode": row.cert_mode, "cdn_note": "", "cert_uncovered": "",
                "own_cert": {k: own[k] for k in ("issuer", "subject", "names", "not_after", "fingerprint", "cdn_origin")}}
    cdn = row.dns_state == "cdn" and not tunnel
    return {"cert_mode": "acme", "own_cert": None, "cdn_note": cdn_note(row.dns_cdn) if cdn else "",
            "cert_uncovered": _uncovered_text(row)}


def _uncovered_text(row):
    """Why an automatic domain of a site that has its own certificate is not on it ("" when it is covered or none)."""
    site = row.website
    if site is None or not site.own_cert_pem:
        return ""
    try:
        leaf = tls_own._load_chain(site.own_cert_pem.encode("ascii", "replace"))[0]
    except (ValueError, IndexError):
        return ""
    if tls_own.covers(leaf, row.domain):
        return ""
    names = ", ".join(tls_own.san_names(leaf)[:8])
    return i18n.tr(S_SITE_CERT_UNCOVERED, domain=row.domain, why=i18n.Sentence(
        "The certificate does not cover {domain}: its names are {names}.", domain=row.domain, names=names))


def site_cert_json(site):
    """The site's own certificate as the Domains tab shows it (public facts only, never the key), or None."""
    info = _wcert.info(site.own_cert_pem) if site.own_cert_pem else None
    if not info:
        return None
    on = sorted(d.domain for d in site.domains if d.cert_mode == "site")
    return dict({k: info[k] for k in ("issuer", "subject", "names", "not_after", "fingerprint", "cdn_origin")},
                domains=on, warning=_site_cert_note(info))


def _site_cert_note(info):
    """The site certificate's warning (self-signed, expired, or tls_own.SOON_DAYS days or fewer left), or ""."""
    notes = [S_SITE_SELF_SIGNED] if info.get("self_signed") and not info.get("cdn_origin") else []
    days = info.get("days")
    if isinstance(days, int) and days < 0:
        notes.append(S_SITE_EXPIRED)
    elif isinstance(days, int) and days <= tls_own.SOON_DAYS:
        notes.append(i18n.Sentence(S_SITE_SOON, days=days))
    return i18n.tr(i18n.Sentences(*notes)) if notes else ""


def _cdn_name(row):
    """The CDN a domain in the cdn state goes through, as the pages name it ("" in any other state)."""
    return _wcat.cdn_info(row.dns_cdn or "cloudflare")["name"] if row.dns_state == "cdn" else ""


def cdn_note(preset):
    """What an automatic certificate needs behind CDN preset `preset`, in the viewer's language.

    The CDN's own origin certificate and strict mode when the signed catalog names them, else the general advice;
    either way the automatic certificate's need. A domain checked as cdn before dns_cdn existed went through
    Cloudflare, the only preset then.
    """
    info = _wcat.cdn_info(preset or "cloudflare")
    first = (i18n.Sentence(S_CDN_ORIGIN, provider=info["name"], origin_cert=info["origin_cert"],
                           strict_mode=info["strict_mode"]) if info["origin_cert"] else
             i18n.Sentence(S_CDN_MAYBE, provider=info["name"]))
    return i18n.tr(i18n.Sentences(first, i18n.Sentence(S_CDN_ACME, provider=info["name"])))


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


def _use_site_cert(row, checked):
    """`row` on its site's certificate: no copy of its own, its expiry the site certificate's."""
    row.cert_mode, row.cert_state, row.cert_error = "site", "own", ""
    row.own_cert_pem, row.own_key_secret = "", ""
    row.cert_not_after = _wcert.not_after(checked)


# ── the site's certificate ───────────────────────────────────────────────────────────────────────
def _site_before(site):
    """What a site certificate save changes, for putting it back: the site's pair and each domain's columns."""
    return ((site.own_cert_pem, site.own_key_secret),
            {d.id: tuple(getattr(d, col) for col in _CERT_COLUMNS) for d in site.domains})


def _site_restore(site, before):
    site.own_cert_pem, site.own_key_secret = before[0]
    for d in site.domains:
        for col, value in zip(_CERT_COLUMNS, before[1].get(d.id, ())):
            setattr(d, col, value)
    db.session.commit()


def _site_own(site, form):
    """Store the pasted pair on the site and put each domain it covers on it. -> (covered, uncovered, notes) or a refusal."""
    cert, key = _pem_field(form, "cert"), _pem_field(form, "key")
    results = [(d, tls_own.check_for_domain(cert, key, d.domain)) for d in site.domains]
    covered = [(d, c) for d, c in results if not c.refusal]
    if not covered:
        return None, i18n.Sentence(S_SITE_CERT_NONE, why=i18n.tr(results[0][1].refusal))
    first = covered[0][1]
    site.own_cert_pem = first.cert_pem().decode("ascii")
    site.own_key_secret = encrypt_secret(first.key_pem().decode("ascii"))
    for d, c in covered:
        _use_site_cert(d, c)
    uncovered = [(d, c.refusal) for d, c in results if c.refusal]
    for d, _why in uncovered:
        if d.cert_mode == "site":       # on the site's previous certificate, which this one replaces
            _set_auto(d)
    return (covered, uncovered, first), None


def _site_auto(site):
    """Every domain of the site back to automatic, the site's pair gone."""
    site.own_cert_pem, site.own_key_secret = "", ""
    for d in site.domains:
        if d.cert_mode in ("site", "own"):
            _set_auto(d)


def _site_detail(got):
    if got is None:
        return "site certificate: automatic for every domain"
    covered, uncovered, first = got
    s = tls_own.summary(first.chain)
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string -- audit-log text for a helper, not a view
    return "site certificate for %s, issuer %s, expires %s, sha256 %s%s" % (
        ", ".join(d.domain for d, _c in covered), s["issuer"], s["not_after"], s["fingerprint"],
        "; automatic: %s" % ", ".join(d.domain for d, _w in uncovered) if uncovered else "")


def _site_notes(site, got):
    """The notes after a site certificate save: the checks' notes, each domain left automatic and why, where not served."""
    if got is None:
        return []
    covered, uncovered, first = got
    notes = [i18n.tr(n) for n in first.notes]
    notes += [i18n.tr(S_SITE_CERT_UNCOVERED, domain=d.domain, why=i18n.tr(why)) for d, why in uncovered]
    if not site.enabled or any(d.verified_at is None for d, _c in covered):
        notes.append(i18n.tr(S_CERT_NOT_SERVED))
    if _w.proxy_row(site.remote_id).exposure_mode == "tunnel":
        notes.append(i18n.tr(S_CERT_TUNNEL))
    return notes


def _site_apply(site, before):
    """Apply the site's certificates when it is online: "" when applied, else why (the previous ones put back)."""
    _CERTS_AT.pop(site.remote_id, None)
    if not site.enabled:
        return ""
    ok, said = _w.reconcile_proxy(site.remote)
    if ok:
        return ""
    _site_restore(site, before)
    _w.reconcile_proxy(site.remote)
    return i18n.Sentence(S_SITE_CERT_ROLLED_BACK, why=i18n.tr(said))


def set_site_cert(site, form):
    """POST .../cert's work: check the pair against every domain, store it once, apply (or put back)."""
    mode = _w.field(form, "mode")
    if mode not in ("acme", "own"):
        return _w.say(400, S_CERT_MODE)
    if mode == "own" and not site.domains:
        return _w.say(400, S_SITE_CERT_NO_DOMAIN)
    before, got = _site_before(site), None
    if mode == "own":
        got, refused = _site_own(site, form)
        if refused:
            db.session.rollback()
            _w.audit(site, "website_cert", "site certificate refused: %s" % refused, False)
            return _w.say(400, refused)
    else:
        _site_auto(site)
    db.session.commit()
    why = _site_apply(site, before)
    if why:
        _w.audit(site, "website_cert", "%s: not applied: %s" % (_site_detail(got), why), False)
        return _w.done(False, why)
    _w.audit(site, "website_cert", _site_detail(got))
    said = (i18n.Sentence(S_SITE_CERT_SAVED, names=", ".join(d.domain for d, _c in got[0])) if got
            else S_SITE_CERT_AUTO)
    return jsonify({"success": True, "message": i18n.tr(said), "notes": _site_notes(site, got),
                    "site_cert": site_cert_json(site), "domains": [domain_json(site, d) for d in site.domains]})


def _cert_detail(row, checked):
    """The audit row's text: the domain, and of an own certificate its issuer, expiry and fingerprint (never the key)."""
    if checked is None:
        return " ".join((row.domain + ":", "automatic certificate"))
    got = tls_own.summary(checked.chain)
    return "".join((row.domain, ": own certificate, issuer ", str(got["issuer"]), ", expires ", str(got["not_after"]),
                    ", sha256 ", str(got["fingerprint"])))


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


def _primary_name(site):
    dom = site.primary_domain
    return dom.address if dom is not None else ""


def _move_into(site, moving):
    """Write the site's own server again for its new folder when the address moved it into one: "" or why not.

    A running site restarts with it; a stopped one has its files written and stays stopped.
    """
    if not moving:
        return ""
    ok, said = _w.host_call(_sw.install, site.remote, site, _w.site_db(site), site.state == "running")
    return "" if ok else i18n.tr(S_MOVED_FAILED, why=i18n.tr(said))


def _add(site, form):
    """POST .../domains/add's work: a domain, or (with `folder`) a folder of a domain the user's sites hold."""
    folder = form.get("folder") if "folder" in form else None
    got, refused = domain_refusal(site, _w.field(form, "domain"), folder if folder is None or isinstance(folder, str) else "")
    if refused:
        _w.audit(site, "website_domain_add", "refused domain: %s" % i18n.tr(refused[1]), False)
        return _w.say(*refused)
    moving = _wf.moves(site, got[1])
    row = _store(site, *got)
    if row is None:
        return _w.say(409, S_TAKEN)
    _w.audit(site, "website_domain_add", "added domain %s" % row.address)
    moved = _move_into(site, moving)
    got = _check(site, row)
    return jsonify(dict(got, success=True, moved_note=moved))


def _wp_address(site, row):
    """For a WordPress site, set its own address (home, siteurl) to `row`'s domain first: (ok, sentence), else None.

    WordPress keeps the address it was installed with and sends visitors there, whatever the proxy's order. A
    failure keeps the old primary domain (the caller changes nothing) and says why.
    """
    if site.app_recipe != "wordpress":
        return None
    ok, why = _w.host_call(_sw.wp_set_address, site.remote, site, row.address)
    if ok:
        return True, i18n.Sentence(S_WP_ADDRESS_SET, domain=row.address)
    return False, i18n.Sentence(S_WP_ADDRESS_FAILED, domain=row.address, old=_primary_name(site), why=i18n.tr(why))


def register(app):
    """The domain routes."""
    @app.route("/websites/<int:site_id>/domains/add", methods=["POST"])
    @login_required
    def website_domain_add(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        return _add(site, _w.body())

    @app.route("/websites/<int:site_id>/domains/remove", methods=["POST"])
    @login_required
    def website_domain_remove(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        row = _row(site, _w.body())
        if row is None:
            return _w.say(404, S_NO_SUCH)
        name, was_primary, was_online = row.address, row.is_primary, site.enabled
        db.session.delete(row)
        db.session.flush()
        rest = [d for d in site.domains if d.address != name]
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
        _dns.refresh_public_ip(site.remote)     # the host's address now, never only what was found once
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

    @app.route("/websites/<int:site_id>/cert", methods=["POST"])
    @login_required
    def website_site_cert(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        return set_site_cert(site, _w.body())

    @app.route("/websites/<int:site_id>/domains/primary", methods=["POST"])
    @login_required
    def website_domain_primary(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        row = _row(site, _w.body())
        if row is None:
            return _w.say(404, S_NO_SUCH)
        wp_said = _wp_address(site, row)
        if wp_said is not None and not wp_said[0]:
            return _w.acted(site, "website_domain_primary", False, wp_said[1],
                            "primary domain %s kept: WordPress's address not changed" % _primary_name(site))
        for d in site.domains:
            d.is_primary = d is row
        db.session.commit()
        ok, said = _w.reconcile_proxy(site.remote) if site.enabled else (True, "")
        said = said or "Primary domain set."
        if ok and wp_said is not None:
            said = i18n.Sentences(said, wp_said[1])
        return _w.acted(site, "website_domain_primary", ok, said, "primary domain %s" % row.domain)
