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
from panel.core.config import DATA_DIR
from panel.core.validation import ip_address_or_none

_log = logging.getLogger("panel.certs")

_CERT_ALERTED = {"at": 0}   # last time we alerted about the TLS cert (weekly dedup)


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
            # A certificate already past its date said "expires in 0 day(s)" (max(days, 0)): one
            # that has stopped working read as one with a day left.
            notifications.notify("cert_expiring", "TLS certificate expiring",
                                 "The panel's TLS certificate has expired — renew it." if days < 0
                                 else "The panel's TLS certificate expires in %d day(s) — renew it." % days)
    except Exception:
        _log.debug("cert-expiry check failed", exc_info=True)


# OWASP Transport Layer Security Cheat Sheet: ECDSA P-256 keys, SHA-256 signatures, and certificates
# that do not live for years. 397 days is the longest validity browsers accept for any certificate;
# a new one is made at start-up once fewer than 30 days remain (the expiry notice warns before that).
_CERT_DAYS = 397


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
