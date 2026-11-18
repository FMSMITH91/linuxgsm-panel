"""The operator's own certificate for the panel's built-in HTTPS: checking it, putting it in, renewing it.

Two ways in, both from Settings > HTTPS certificate (panel/routes/tls_cert.py):
- pasted: the certificate with its chain, and the private key, as PEM;
- Let's Encrypt: the name of a certbot certificate on this host. certbot's files are root's and the
  key is root-only, so the privileged helper copies those two files into data/ssl (the tls-le-copy
  verb, tools/panel-helper do_tls_le_copy) and this module checks the copies before using them.

What is checked, read against the OWASP Transport Layer Security Cheat Sheet (2026-11-17):
- refused: a certificate or key that cannot be read, a key protected by a passphrase, a key that is
  not the certificate's, and a certificate already past its date. Each would stop HTTPS starting
  or serve a certificate every browser rejects.
- noted, and put in anyway: "Use Strong Keys and Protect Them" (RSA under 2048 bits; a key type
  browsers do not accept), "Use Strong Cryptographic Hashing Algorithms" (MD5 or SHA-1), "Use
  Correct Domain Names" (the panel's address not in the subjectAltName), "Use an Appropriate
  Certification Authority" (a self-signed certificate), a chain with no intermediate certificate
  or out of order, a certificate not valid yet, and one with 30 days or fewer left.

The files are written as the panel writes its own (certs.py): the key 0600 from the moment it is
created, then both renamed into place. config.json's tls_cert_source records that the certificate
is the operator's, so certs._ensure_self_signed_cert never replaces it with a self-signed one.
"""
import logging
import os
import re
import time
from urllib.parse import urlsplit

from panel.core import i18n
from panel.core.clock import aware_utcnow
from panel.core.config import load_config, update_config
from panel.core.validation import ip_address_or_none
from panel.services import certs

_log = logging.getLogger("panel.tls_own")

# The most a pasted certificate chain or key may be. A chain of four RSA-4096 certificates is under
# 10 KB; this leaves room and still bounds what is parsed.
PEM_MAX = 65536
# certbot's certificate names (privileged.TLS_LE_NAME_RE, the helper's own copy beside the verb).
LE_NAME_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
# The names the helper copies certbot's two files to, inside data/ssl (TLS_LE_FILES there).
LE_STAGED = ("le-fullchain.pem", "le-privkey.pem")
# How often the Let's Encrypt copy is refreshed: certbot renews 30 days before expiry, so once a day
# picks a renewal up with weeks to spare.
RENEW_EVERY = 86400
_RENEW = {"at": 0.0}
# The days left below which a certificate is noted, as certs.py warns from for an operator's.
SOON_DAYS = 30

LE_NOT_FOUND = "There is no Let's Encrypt certificate called {name} on this host (sudo certbot certificates lists them)."
LE_FAILED = "The Let's Encrypt files could not be copied. Check the panel log."
# The helper copies only the certificates the operator opened at install (its tls_le_names).
LE_NOT_OPENED = ("The Let's Encrypt certificate {name} was not opened to the panel at install. To allow it, run "
                 "the installer again as root with PANEL_TLS_LE_NAMES={name} (sudo PANEL_TLS_LE_NAMES={name} bash "
                 "install.sh).")


def _x509():
    """The cryptography modules this needs, imported when first used (as certs.py does)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    return x509, serialization, ec, rsa


def _spki(public_key):
    serialization = _x509()[1]
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _load_chain(cert_pem):
    """The certificates in `cert_pem`, in order; an empty list when there are none or one is unreadable."""
    x509 = _x509()[0]
    try:
        return list(x509.load_pem_x509_certificates(cert_pem))
    except ValueError:
        return []


def _load_key(key_pem):
    """(private key or None, why it could not be read or "")."""
    serialization = _x509()[1]
    try:
        return serialization.load_pem_private_key(key_pem, password=None), ""
    except TypeError:
        return None, ("The private key is protected by a passphrase. The panel needs it without one: "
                      "openssl pkey -in key.pem -out key-open.pem")
    except Exception:  # noqa: BLE001 - ValueError, UnsupportedAlgorithm: either way it is unusable
        return None, "The private key could not be read. Paste it in PEM form: the text from its BEGIN PRIVATE KEY line to its END line."


def _with_leaf_first(chain, key):
    """`chain` with the key's own certificate first, and whether it had to be moved; None if it is not there."""
    want = _spki(key.public_key())
    for i, cert in enumerate(chain):
        if _spki(cert.public_key()) == want:
            return [cert] + chain[:i] + chain[i + 1:], i > 0
    return None, False


def _key_notes(leaf):
    """OWASP "Use Strong Keys": RSA of at least 2048 bits, or an ECDSA key on a curve browsers accept."""
    _x, _s, ec, rsa = _x509()
    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return [] if key.key_size >= 2048 else [
            i18n.Sentence("The key is RSA {bits} bits. OWASP recommends at least 2048.", bits=key.key_size)]
    if isinstance(key, ec.EllipticCurvePublicKey):
        return [] if key.curve.name in ("secp256r1", "secp384r1") else [
            i18n.Sentence("The key is on the {curve} curve. Browsers accept P-256 and P-384.", curve=key.curve.name)]
    return ["The key is neither RSA nor ECDSA. Browsers may refuse it."]


def _hash_notes(leaf):
    """OWASP "Use Strong Cryptographic Hashing Algorithms": SHA-256 or stronger."""
    algo = getattr(leaf.signature_hash_algorithm, "name", "") or ""
    if algo in ("md5", "sha1"):
        return [i18n.Sentence("The certificate is signed with {algo}. OWASP recommends SHA-256 or stronger.",
                              algo=algo.upper())]
    return []


def san_names(leaf):
    """The DNS names and IP addresses in `leaf`'s subjectAltName, as text ([] when it has none)."""
    x509 = _x509()[0]
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return (list(san.get_values_for_type(x509.DNSName))
            + [str(a) for a in san.get_values_for_type(x509.IPAddress)])


def covers(leaf, name):
    """Whether `leaf`'s subjectAltName covers host `name` (a wildcard matches one left-most label)."""
    name = (name or "").strip().lower().rstrip(".")
    if not name:
        return False
    ip = ip_address_or_none(name)
    for entry in san_names(leaf):
        entry = entry.lower().rstrip(".")
        if ip is not None:
            if ip_address_or_none(entry) == ip:
                return True
        elif entry == name or (entry.startswith("*.") and name.partition(".")[2] == entry[2:]):
            return True
    return False


def _name_notes(leaf, names):
    """OWASP "Use Correct Domain Names": the panel's address belongs in the subjectAltName."""
    if not san_names(leaf):
        return ["The certificate has no subjectAltName. Browsers check names only there."]
    missing = [n for n in names if n and not covers(leaf, n)]
    if missing:
        return [i18n.Sentence("The certificate does not cover {names}, so a browser opening the panel by that name "
                              "warns.", names=", ".join(missing))]
    return []


def _chain_notes(chain):
    """A CA-signed certificate needs its intermediates, each followed by the one that signed it."""
    leaf = chain[0]
    if leaf.issuer == leaf.subject:
        return ["The certificate is self-signed, so browsers warn. OWASP recommends a well-known CA "
                "(Let's Encrypt is free)."]
    if len(chain) == 1:
        return ["Only the server certificate was given. Paste the full chain (fullchain.pem), or some "
                "browsers and apps cannot trust it."]
    if any(a.issuer != b.subject for a, b in zip(chain, chain[1:])):
        return ["The chain is not in order: each certificate should be followed by the one that signed it."]
    return []


def _date_notes(leaf, now):
    if leaf.not_valid_before_utc > now:
        return [i18n.Sentence("The certificate is not valid until {date}.",
                              date=leaf.not_valid_before_utc.strftime("%Y-%m-%d"))]
    days = (leaf.not_valid_after_utc - now).days
    if days <= SOON_DAYS:
        return [i18n.Sentence("The certificate expires in {days} day(s).", days=days)]
    return []


def _key_label(leaf):
    _x, _s, ec, rsa = _x509()
    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA %d" % key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA %s" % key.curve.name
    return type(key).__name__


def _first_attr(name, oid):
    vals = name.get_attributes_for_oid(oid)
    return str(vals[0].value) if vals else name.rfc4514_string()


def summary(chain, now=None):
    """What Settings shows about a certificate chain: names, issuer, expiry, key, self-signed."""
    x509 = _x509()[0]
    leaf = chain[0]
    now = now or aware_utcnow()
    cn = x509.oid.NameOID.COMMON_NAME
    return {"subject": _first_attr(leaf.subject, cn), "issuer": _first_attr(leaf.issuer, cn),
            "names": san_names(leaf), "not_after": leaf.not_valid_after_utc.strftime("%Y-%m-%d"),
            "days": (leaf.not_valid_after_utc - now).days, "key": _key_label(leaf),
            "self_signed": leaf.issuer == leaf.subject, "chain": len(chain),
            "fingerprint": certs.fingerprint(leaf)}


class Checked:
    """The result of check(): a refusal, or the normalised PEM to write plus notes and a summary."""

    def __init__(self, refusal="", notes=(), chain=(), key=None):
        """Hold what check() found."""
        self.refusal = refusal
        self.notes = list(notes)
        self.chain = list(chain)
        self.key = key

    def cert_pem(self):
        """The chain as PEM, leaf first, re-encoded from what was parsed (nothing else from the input)."""
        serialization = _x509()[1]
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in self.chain)

    def key_pem(self):
        """The private key as unencrypted PKCS#8 PEM, re-encoded from what was parsed."""
        serialization = _x509()[1]
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())


def _parse(cert_pem, key_pem):
    """(refusal or "", chain with the key's certificate first, key, whether it was moved first)."""
    if not cert_pem or len(cert_pem) > PEM_MAX or not key_pem or len(key_pem) > PEM_MAX:
        return "Paste both the certificate and its private key (at most 64 KB each).", [], None, False
    chain = _load_chain(cert_pem)
    if not chain:
        return ("The certificate could not be read. Paste it in PEM form, starting with -----BEGIN CERTIFICATE-----.",
                [], None, False)
    key, why = _load_key(key_pem)
    if key is None:
        return why, [], None, False
    chain, moved = _with_leaf_first(chain, key)
    if chain is None:
        return "The private key does not belong to this certificate.", [], None, False
    return "", chain, key, moved


def check(cert_pem, key_pem, names=(), now=None):
    """Check a certificate chain and its private key (bytes, PEM) for the panel's HTTPS. -> Checked.

    `names` are the addresses the panel is reached by (site_domain, the request's host): each is
    looked for in the subjectAltName. Refused only when HTTPS could not start with the pair or every
    browser would reject it; everything else is a note.
    """
    now = now or aware_utcnow()
    refusal, chain, key, moved = _parse(cert_pem, key_pem)
    if refusal:
        return Checked(refusal)
    leaf = chain[0]
    if leaf.not_valid_after_utc <= now:
        return Checked(i18n.Sentence("The certificate expired on {date}.",
                                     date=leaf.not_valid_after_utc.strftime("%Y-%m-%d")))
    notes = ["The server certificate was not first in the file; it has been put first."] if moved else []
    notes += (_key_notes(leaf) + _hash_notes(leaf) + _name_notes(leaf, names) + _chain_notes(chain)
              + _date_notes(leaf, now))
    return Checked("", notes, chain, key)


def panel_names(cfg, request_host=""):
    """The addresses to check a certificate against: site_domain, and the host this page was opened by."""
    out = []
    for raw in ((cfg or {}).get("site_domain") or "", request_host or ""):
        host = urlsplit("//" + raw.strip()).hostname if raw.strip() else None
        if host and host not in out:
            out.append(host)
    return out


def _write_new(path, data, mode):
    """Create `path` afresh with `mode` from the start (O_EXCL, never through a link) and write `data`."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass    # nothing left from an earlier attempt
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def install(checked, source, le_name=""):
    """Put a checked pair in place as data/ssl/cert.pem and key.pem, and record whose it is.

    The key is written 0600 from the moment it exists (OWASP "Use Strong Keys and Protect Them"),
    both are written under new names first and then renamed over the old ones, so a reader sees the
    old pair or the new one. The panel must restart to serve it.
    """
    ssl_dir = certs.ssl_dir()
    os.makedirs(ssl_dir, mode=0o700, exist_ok=True)
    key_new, cert_new = ssl_dir / "key.pem.new", ssl_dir / "cert.pem.new"
    _write_new(key_new, checked.key_pem(), 0o600)
    _write_new(cert_new, checked.cert_pem(), 0o600)   # public, but only the panel reads it
    os.replace(key_new, ssl_dir / "key.pem")
    os.replace(cert_new, ssl_dir / "cert.pem")

    def _mut(cfg):
        # The time HSTS's rollout counts from (certs.own_tls_hsts): when an operator certificate was first
        # put in, kept through renewals and replacements, since HSTS is about the name staying on
        # trusted TLS, not about one certificate.
        if cfg.get("tls_cert_source") not in certs.OPERATOR_SOURCES or not cfg.get("tls_installed_at"):
            cfg["tls_installed_at"] = int(time.time())
        cfg.update({"tls_cert_source": source, "tls_le_name": le_name if source == "letsencrypt" else "",
                    "tls_cert_sha256": certs.fingerprint(checked.chain[0])})
    update_config(_mut)


def remove():
    """Go back to the built-in certificate: drop the operator's pair; the next start makes a self-signed one."""
    for name in ("cert.pem", "key.pem"):
        try:
            os.unlink(certs.ssl_dir() / name)
        except FileNotFoundError:
            pass    # already gone: the start makes a new pair either way

    def _mut(cfg):
        for key in ("tls_cert_source", "tls_le_name", "tls_installed_at", "tls_cert_sha256"):
            cfg.pop(key, None)
    update_config(_mut)


def _read_staged():
    """(chain bytes, key bytes) the helper copied, removing both copies; (b"", b"") if they are missing."""
    out = []
    for name in LE_STAGED:
        path = certs.ssl_dir() / name
        try:
            with open(path, "rb") as f:
                out.append(f.read(PEM_MAX + 1))
        except OSError:
            out.append(b"")
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass    # never copied: nothing to clean up
    return out[0], out[1]


def _le_failure(name, rc, err):
    """What to tell the operator when the helper did not copy certificate `name`."""
    if "no such certificate" in err:
        return i18n.Sentence(LE_NOT_FOUND, name=name)
    if "not opened to the panel" in err:
        return i18n.Sentence(LE_NOT_OPENED, name=name)
    if "privileged helper" in err:
        return "This needs the panel's privileged helper: re-run install.sh as root."
    _log.warning("tls-le-copy failed: rc=%s %s", rc, err[:200])
    return LE_FAILED


def fetch_letsencrypt(name):
    """Copy Let's Encrypt certificate `name` through the helper. -> (chain bytes, key bytes, why it failed)."""
    from panel.ops import system_ops as so
    if not LE_NAME_RE.fullmatch(name or ""):
        return b"", b"", "That is not a certificate name: use the name certbot shows, e.g. panel.example.com."
    os.makedirs(certs.ssl_dir(), mode=0o700, exist_ok=True)
    out, err, rc = so._run_verb("tls-le-copy", [name], timeout=30, merge_stderr=False)
    if rc != 0 or "COPIED" not in (out or ""):
        _read_staged()
        return b"", b"", _le_failure(name, rc, err or "")
    chain, key = _read_staged()
    return chain, key, ""


def current_chain():
    """The certificates in data/ssl/cert.pem now ([] when there is none or it cannot be read)."""
    try:
        with open(certs.ssl_dir() / "cert.pem", "rb") as f:
            return _load_chain(f.read(PEM_MAX + 1))
    except OSError:
        return []


def settings_view(cfg, boot):
    """What Settings > HTTPS certificate shows: whose certificate it is, what it says, whether it is served."""
    source = cfg.get("tls_cert_source") if cfg.get("tls_cert_source") in certs.OPERATOR_SOURCES else "builtin"
    chain = current_chain()
    try:
        info = summary(chain) if chain else None
    except Exception:  # noqa: BLE001 - an odd certificate must not take the Settings page down
        _log.debug("certificate summary failed", exc_info=True)
        info = None
    return {"source": source, "le_name": cfg.get("tls_le_name") or "",
            "autorenew": cfg.get("tls_le_autorenew", True) is not False,
            "serving": bool((boot or {}).get("BOOT_TLS")), "cert": info, "soon_days": SOON_DAYS,
            "hsts": certs.own_tls_hsts((boot or {}).get("BOOT_TLS_OWN"))}


def _renew_due(cfg, boot, now):
    """Whether the daily Let's Encrypt refresh should run now."""
    if cfg.get("tls_cert_source") != "letsencrypt" or cfg.get("tls_le_autorenew", True) is False:
        return False
    if not LE_NAME_RE.fullmatch(cfg.get("tls_le_name") or ""):
        return False
    if boot is not None and boot.get("BOOT_TLS") is False and not boot.get("BOOT_TLS_ERROR"):
        return False    # Tailscale Serve or a proxy terminates TLS: the file is not what is served
    return now - _RENEW["at"] >= RENEW_EVERY


def maybe_renew(boot=None, now=None):
    """Once a day, load a Let's Encrypt certificate certbot has renewed. -> what happened, as a word.

    "renewed" (installed and a restart asked for), "same" (nothing newer), "refused" (the copy
    failed its check), "failed" (it could not be copied), "busy" (the panel may not restart now:
    host_reboot.panel_host_busy; the next tick tries again) or "" (not due). Never raises: it rides
    the update-check ticker beside the expiry alert.
    """
    now = time.time() if now is None else now
    try:
        cfg = load_config()
        if not _renew_due(cfg, boot, now):
            return ""
        from panel.services import host_reboot
        if host_reboot.panel_host_busy():
            return "busy"     # a restore or the host's reboot is running; not marked as done
        _RENEW["at"] = now
        return _renew(cfg)
    except Exception:  # noqa: BLE001 - a background tick; the expiry alert still warns
        _log.warning("Let's Encrypt refresh failed", exc_info=True)
        return "failed"


def _renew(cfg):
    from panel.ops import system_ops as so
    chain_pem, key_pem, why = fetch_letsencrypt(cfg.get("tls_le_name") or "")
    if why:
        _log.warning("Let's Encrypt refresh: %s", why)
        return "failed"
    checked = check(chain_pem, key_pem, panel_names(cfg))
    if checked.refusal:
        _log.warning("Let's Encrypt refresh: the renewed certificate was not loaded: %s", checked.refusal)
        return "refused"
    now_chain = current_chain()
    if now_chain and checked.chain[0].not_valid_after_utc <= now_chain[0].not_valid_after_utc:
        return "same"
    install(checked, "letsencrypt", cfg.get("tls_le_name") or "")
    ok, _msg = so.restart_panel(delay_seconds=2)
    _log.warning("Let's Encrypt certificate renewed (valid until %s); %s",
                 checked.chain[0].not_valid_after_utc.strftime("%Y-%m-%d"),
                 "the panel restarts to load it" if ok else "restart the panel to load it")
    return "renewed"

