"""The panel's own TLS certificate: creating one, and warning before it expires.

Both halves were in app.py — the generator at the very bottom next to `__main__`, the expiry
alert 7,000 lines above it, with nothing in between relating them. Neither touches the Flask
app: the generator is called from the boot path with explicit paths, and the alert rides the
update-check ticker's cadence and reads the cert straight off disk.

`_CERT_ALERTED` moves with them. It is the weekly dedup for the alert and has exactly one
reader and one writer, both here.
"""
import logging
import os
import time
from datetime import datetime, timezone

from panel.services import notifications
from panel.core.clock import aware_utcnow
from panel.core.config import DATA_DIR, load_config
from panel.core.validation import ip_address_or_none

_log = logging.getLogger("panel.certs")

_CERT_ALERTED = {"at": 0}   # last time we alerted about the TLS cert (weekly dedup)
# Where the panel's own HTTPS certificate and key live (cert.pem, key.pem). A name of its own so the
# tests can point it at a scratch directory.
SSL_DIR = DATA_DIR / "ssl"
# What config.json's tls_cert_source names when the operator put in a certificate of their own
# through Settings (panel/services/tls_own.py): pasted, or copied from Let's Encrypt.
OPERATOR_SOURCES = ("own", "letsencrypt")


def _maybe_alert_cert_expiring(boot=None):
    """Alert when the panel's own TLS certificate is within 14 days of expiry, at most once a week.

    No-op if the cert file isn't present (e.g. Tailscale Serve / a reverse proxy terminates TLS).
    Best-effort — never raises.

    `boot` is the app's config, holding app.py's boot record (BOOT_TLS, BOOT_TLS_ERROR). A panel
    that booted serving plain HTTP on purpose is not using the file: a cert of the operator's own
    left there after TLS moved to Tailscale Serve paged "renew it" for a certificate nothing
    served (system_ops._diag_tls already calls it leftover). A TLS start that FAILED still alerts,
    and so does a caller with no boot record.
    """
    if boot is not None and boot.get("BOOT_TLS") is False and not boot.get("BOOT_TLS_ERROR"):
        return
    try:
        from cryptography import x509
        cert_path = SSL_DIR / "cert.pem"
        if not cert_path.exists():
            return
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            not_after = cert.not_valid_after_utc              # cryptography >= 42
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        source = _operator_source(cert)
        own = _operator_cert(cert) or bool(source)
        # The operator's certificate is warned from 30 days (renewing it is their job, and with HSTS an
        # expired one locks browsers out); the panel's own from 14, since a restart makes a new one.
        if days <= (30 if own else 14) and (time.time() - _CERT_ALERTED["at"]) > 7 * 86400:
            _CERT_ALERTED["at"] = time.time()
            notifications.notify("cert_expiring", "TLS certificate expiring", _expiry_text(days, own, source))
    except Exception:
        _log.debug("cert-expiry check failed", exc_info=True)


def _expiry_text(days, own, source=""):
    """The expiry alert's text: what to do depends on whose certificate it is.

    A certificate already past its date said "expires in 0 day(s)" (max(days, 0)): one that has
    stopped working read as one with a day left. A Let's Encrypt one is copied again every day
    once certbot has renewed it, so the step that is missing is certbot's.
    """
    if own:
        fix = ("renew it and put the new one in under Settings > HTTPS certificate (the panel restarts "
               "to load it)")
        if source == "letsencrypt":
            fix = ("check that certbot renews it (sudo certbot renew --dry-run); the panel copies a renewed "
                   "certificate every day and restarts to load it")
        return ("Your TLS certificate has expired — %s." % fix if days < 0
                else "Your TLS certificate expires in %d day(s) — %s." % (days, fix))
    return ("The panel's built-in TLS certificate has expired — restart the panel and it makes a new one."
            if days < 0 else
            "The panel's built-in TLS certificate expires in %d day(s) — restart the panel and it makes a "
            "new one." % days)


# OWASP Transport Layer Security Cheat Sheet: ECDSA P-256 keys, SHA-256 signatures, and certificates
# that do not live for years. 397 days is the longest validity browsers accept for any certificate;
# a new one is made at start-up once fewer than 30 days remain (the expiry notice warns before that).
_CERT_DAYS = 397


def _operator_source(cert=None):
    """config.json's tls_cert_source when it names an operator certificate ("own"/"letsencrypt"), else "".

    Set when a certificate is put in through Settings, which a self-signed certificate of the
    operator's own can be too: issuer == subject alone would read that as the panel's and replace it.
    With `cert`, only while it is the certificate that was put in (tls_cert_sha256): a config.json
    restored onto a host without that certificate must not stop the built-in one being renewed.
    """
    try:
        cfg = load_config()
    except Exception:  # noqa: BLE001 - an unreadable config is "not marked"; the issuer test still runs
        _log.debug("tls_cert_source unreadable", exc_info=True)
        return ""
    source = cfg.get("tls_cert_source")
    if source not in OPERATOR_SOURCES:
        return ""
    if cert is not None and cfg.get("tls_cert_sha256") != fingerprint(cert):
        return ""
    return source


def fingerprint(cert):
    """The certificate's SHA-256 fingerprint as lower-case hex."""
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex()


def _operator_cert(cert):
    """Whether `cert` is one the operator put in data/ssl: signed by another issuer (a CA), not self-signed.

    The panel's own certificates are self-signed (issuer == subject). OWASP Transport Layer Security
    Cheat Sheet, "Use an Appropriate Certification Authority": a CA-signed certificate is the one to
    keep.
    """
    return cert.issuer != cert.subject


def _note_operator_cert(cert, key_path):
    """Log what the TLS Cheat Sheet would flag in the operator's certificate; nothing is refused.

    "Use Strong Keys": RSA of at least 2048 bits. "Use Strong Cryptographic Hashing Algorithms":
    SHA-256 or stronger, not MD5 or SHA-1. Also a key file that does not match the certificate (TLS
    would then fail to start) and a certificate already past its date.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        _log.warning("TLS: your certificate's RSA key is %d bits; OWASP recommends at least 2048", key.key_size)
    algo = getattr(cert.signature_hash_algorithm, "name", "")
    if algo in ("md5", "sha1"):
        _log.warning("TLS: your certificate is signed with %s; OWASP recommends SHA-256 or stronger", algo)
    if cert.not_valid_after_utc <= aware_utcnow():
        _log.warning("TLS: your certificate in data/ssl has expired; renew it and restart the panel")
    try:
        with open(key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        pub = serialization.PublicFormat.SubjectPublicKeyInfo
        if (priv.public_key().public_bytes(serialization.Encoding.PEM, pub)
                != key.public_bytes(serialization.Encoding.PEM, pub)):
            _log.warning("TLS: data/ssl/key.pem is not the key of data/ssl/cert.pem; HTTPS cannot start with them")
    except Exception:  # noqa: BLE001 - an unreadable key is reported by the TLS start itself
        _log.warning("TLS: data/ssl/key.pem could not be read as an unencrypted PEM private key")


def _ensure_self_signed_cert(cert_path, key_path, hostname):
    """Create a self-signed ECDSA P-256 cert/key (397 days) unless a current one is already present.

    A new pair is made when either file is missing, the cert has (nearly) expired, or its key is
    not an elliptic-curve key (an RSA-2048 / 10-year certificate from before is replaced once). Used
    when use_https is on and there's no reverse proxy. Returns (cert_path, key_path).
    """
    import datetime as _dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            with open(cert_path, "rb") as f:
                existing = x509.load_pem_x509_certificate(f.read())
            if _operator_cert(existing) or _operator_source(existing):
                # The operator's own certificate (a CA signed it, or it was put in through Settings):
                # never replaced by a self-signed one, whatever its key or dates. With HSTS a self-signed one would be refused as well, and
                # silently swapping it would undo the operator's setup. What is wrong is said instead.
                _note_operator_cert(existing, key_path)
                return cert_path, key_path
            if (existing.not_valid_after_utc > aware_utcnow() + _dt.timedelta(days=30)
                    and isinstance(existing.public_key(), ec.EllipticCurvePublicKey)):
                return cert_path, key_path
        except Exception:
            _log.debug("_ensure_self_signed_cert: ignored non-fatal error", exc_info=True)

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname or "linuxgsm-panel")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(aware_utcnow() - _dt.timedelta(days=1))
            .not_valid_after(aware_utcnow() + _dt.timedelta(days=_CERT_DAYS))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname or "localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    # Create the key file 0600 FROM THE START rather than writing it at the process umask and
    # chmod'ing after: the old order left an unencrypted TLS private key world-readable for the
    # length of the write. O_EXCL would refuse an existing file, so remove a stale one first —
    # we only reach here when the cert is missing or has (nearly) expired.
    try:
        os.remove(key_path)
    except OSError:
        pass   # not there, or not removable — the open below reports anything that matters
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(key_path, 0o600)   # belt and braces on a pre-existing file / odd umask
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


# HSTS on the panel's own TLS, for an operator's CA-signed certificate only (never a self-signed one:
# HSTS removes the browser's "continue anyway", which would lock everyone out of a self-signed panel).
# OWASP HTTP Strict Transport Security Cheat Sheet, "Examples": a very short max-age while rolling it
# out, then headers.HSTS (two years). The first 30 days after the certificate was put in through
# Settings get one day, so going back to the built-in certificate in that time locks a browser out
# for a day at most, not two years.
HSTS_ROLLOUT = "max-age=86400; includeSubDomains"
HSTS_ROLLOUT_DAYS = 30


def own_cert_until(paths):
    """What HSTS needs to know about the certificate the boot will serve: {"until", "since"}, or None.

    `paths` is _ensure_self_signed_cert's (cert_path, key_path). None unless cert_path holds a
    CA-signed certificate (an operator's): "until" is its notAfter, "since" config.json's
    tls_installed_at (0 when it was put in by hand). Read once, at boot.
    """
    try:
        from cryptography import x509
        with open(paths[0], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        if not _operator_cert(cert):
            return None
        since = load_config().get("tls_installed_at")
        return {"until": cert.not_valid_after_utc, "since": since if isinstance(since, int) else 0}
    except Exception:  # noqa: BLE001 - no record means no HSTS on the panel's own TLS, as before
        _log.debug("own_cert_until: no record", exc_info=True)
        return None


def own_tls_hsts(record, now=None):
    """The Strict-Transport-Security value for the panel's own TLS with `record` (own_cert_until), or "".

    "" for no record or a certificate past its date; HSTS_ROLLOUT for the first HSTS_ROLLOUT_DAYS
    after it was put in (and always for one put in by hand); headers.HSTS after that.
    """
    from panel.security import headers
    if not record:
        return ""
    now = now or time.time()
    if record["until"].timestamp() <= now:
        return ""
    since = record.get("since") or 0
    if not since or now - since < HSTS_ROLLOUT_DAYS * 86400:
        return HSTS_ROLLOUT
    return headers.HSTS


# Where a panel listens when its own HTTPS was configured and could not start (OWASP Transport Layer
# Security Cheat Sheet, "Use TLS for All Pages"). Plain HTTP on a network-facing address would carry
# every password, session cookie and API token in the clear, so the listener moves to loopback, where
# only this host (and Tailscale Serve or an SSH tunnel through it) can reach it.
TLS_FAILED_BIND = "127.0.0.1"


def tls_failed_bind(conf, host, port, exc):
    """The address to listen on after self-signed HTTPS failed to start, said on the console and log.

    A loopback `host` is kept: plain HTTP there is the design whenever Tailscale Serve or a reverse
    proxy on this host terminates TLS, and nothing off the host can read it. Any other bind is moved
    to TLS_FAILED_BIND rather than served in the clear, and `conf` (the app's config) records the
    bind that really listens (BOOT_BIND and _BOOT_BIND), so the pages and the debug report do not
    claim the configured one. The operator is told what happened, how to reach the panel now and how
    to fix it. The exception's text goes to the console only; the log gets its class.
    """
    addr = ip_address_or_none(host)
    if addr is not None and addr.is_loopback:
        print(f"  [!] Could not enable HTTPS ({exc}); serving plain HTTP on loopback {host} only.")
        _log.warning("self-signed HTTPS failed to start (%s); plain HTTP on loopback only",
                     type(exc).__name__)
        return host
    conf["BOOT_BIND"] = conf["_BOOT_BIND"] = TLS_FAILED_BIND
    for line in (
            f"  [!] HTTPS is configured but could not start ({exc}).",
            f"      Plain HTTP on {host} would send passwords across the network unencrypted, so the",
            f"      panel listens on {TLS_FAILED_BIND}:{port} only. Reach it through Tailscale Serve",
            f"      or an SSH tunnel: ssh -L {port}:{TLS_FAILED_BIND}:{port} <this host>.",
            f"      To fix: let the panel's account write {DATA_DIR / 'ssl'} and check the",
            "      cryptography package is installed, then restart the panel. Behind a reverse proxy",
            "      that terminates TLS, set trust_proxy instead."):
        print(line)
    _log.error("self-signed HTTPS failed to start (%s): listening on %s only, not on the configured "
               "bind, so no plain HTTP reaches the network", type(exc).__name__, TLS_FAILED_BIND)
    return TLS_FAILED_BIND
