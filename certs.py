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

import notifications
from clock import aware_utcnow
from config import DATA_DIR

_log = logging.getLogger("panel.certs")

_CERT_ALERTED = {"at": 0}   # last time we alerted about the TLS cert (weekly dedup)


def _maybe_alert_cert_expiring():
    """Alert when the panel's own TLS certificate is within 14 days of expiry, at most once a week.
    No-op if the cert file isn't present (e.g. Tailscale Serve / a reverse proxy terminates TLS).
    Best-effort — never raises."""
    try:
        from cryptography import x509
        cert_path = DATA_DIR / "ssl" / "cert.pem"
        if not cert_path.exists():
            return
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            not_after = cert.not_valid_after_utc              # cryptography >= 42
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        if days <= 14 and (time.time() - _CERT_ALERTED["at"]) > 7 * 86400:
            _CERT_ALERTED["at"] = time.time()
            notifications.notify("cert_expiring", "TLS certificate expiring",
                                 "The panel's TLS certificate expires in %d day(s) — renew it." % max(days, 0))
    except Exception:
        _log.debug("cert-expiry check failed", exc_info=True)


def _ensure_self_signed_cert(cert_path, key_path, hostname):
    """Create a long-lived (10-year) self-signed cert/key if one isn't already present
    or has (nearly) expired. Used when use_https is on and there's no reverse proxy.
    Returns (cert_path, key_path). Uses cryptography (already a dependency)."""
    import datetime as _dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            with open(cert_path, "rb") as f:
                existing = x509.load_pem_x509_certificate(f.read())
            if existing.not_valid_after_utc > aware_utcnow() + _dt.timedelta(days=30):
                return cert_path, key_path
        except Exception:
            _log.debug("_ensure_self_signed_cert: ignored non-fatal error", exc_info=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname or "linuxgsm-panel")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(aware_utcnow() - _dt.timedelta(days=1))
            .not_valid_after(aware_utcnow() + _dt.timedelta(days=3650))
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
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    os.chmod(key_path, 0o600)   # belt and braces on a pre-existing file / odd umask
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
