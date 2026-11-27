"""A website domain's own certificate: what it says, and the alert before it expires.

An operator may give a domain a certificate of their own (a CDN's origin certificate is one) instead of
the web proxy's automatic Let's Encrypt one (routes/websites_domains.py, POST .../domains/cert). The
chain is public and kept as PEM (WebsiteDomain.own_cert_pem); the private key is kept encrypted
(own_key_secret, at_rest.SECRET_COLUMNS) and nothing here reads it.

The proxy never renews such a certificate: renewing it is the operator's job. So the domain's line warns
from SOON_DAYS days before its expiry (tls_own.SOON_DAYS, as for the panel's own certificate), and the
update-check ticker sends the cert_expiring alert once a week per domain while it is that close or past.
OWASP's Transport Layer Security Cheat Sheet gives no number of days for this; 30 is the panel's.
"""
import logging
import time
from datetime import timezone

from panel.core import i18n
from panel.core.clock import utcnow
from panel.services import tls_own

_log = logging.getLogger("panel.website_certs")

SOON_DAYS = tls_own.SOON_DAYS
ALERT_EVERY = 7 * 86400
_ALERTED = {}                     # domain name -> time.time() of its last alert
S_ALERT_SOON = ("The certificate you gave {domain} (website {site}) expires in {days} day(s). Paste the renewed "
                "one on the website's Domains tab.")
S_ALERT_EXPIRED = ("The certificate you gave {domain} (website {site}) has expired, so browsers refuse the site. "
                   "Paste a renewed one on the website's Domains tab, or switch it back to automatic.")


def info(pem):
    """What the Domains tab shows of a stored chain: {subject, issuer, names, not_after, days, fingerprint, ...}.

    None when there is none or it cannot be read. Never anything of the private key.
    """
    if not pem:
        return None
    try:
        chain = tls_own._load_chain(pem.encode() if isinstance(pem, str) else pem)
        if not chain:
            return None
        out = tls_own.summary(chain)
        out["cdn_origin"] = tls_own.is_cdn_origin(chain[0])
        return out
    except Exception:  # noqa: BLE001 - an odd certificate must not take the Domains tab down
        _log.debug("own certificate summary failed", exc_info=True)
        return None


def not_after(checked):
    """The leaf's expiry of a tls_own.Checked, as the naive UTC datetime WebsiteDomain.cert_not_after holds."""
    return checked.chain[0].not_valid_after_utc.astimezone(timezone.utc).replace(tzinfo=None)


def alert_text(row, now=None):
    """The alert for own-certificate domain `row`, or "" when it has more than SOON_DAYS days left."""
    if row.cert_not_after is None:
        return ""
    days = (row.cert_not_after - (now or utcnow())).days
    site = row.website.name if row.website is not None else ""
    if row.cert_not_after <= (now or utcnow()):
        return i18n.Sentence(S_ALERT_EXPIRED, domain=row.domain, site=site)
    return i18n.Sentence(S_ALERT_SOON, domain=row.domain, site=site, days=days) if days <= SOON_DAYS else ""


def alert_expiring(now=None, clock=None):
    """Send cert_expiring for each own-certificate domain close to or past its expiry, once a week each.

    Runs in an app context (the update-check ticker's _alert_website_certs). Never raises.
    """
    from panel.db.models import WebsiteDomain
    from panel.services import notifications
    clock = time.time() if clock is None else clock
    try:
        for row in WebsiteDomain.query.filter_by(cert_mode="own").all():
            text = alert_text(row, now)
            if not text or clock - _ALERTED.get(row.domain, 0) < ALERT_EVERY:
                continue
            _ALERTED[row.domain] = clock
            remote = row.website.remote if row.website is not None else None
            notifications.notify("cert_expiring", "TLS certificate expiring", str(text), remote=remote)
    except Exception:  # noqa: BLE001 - a background tick; the Domains tab still warns
        _log.debug("website certificate expiry check failed", exc_info=True)
