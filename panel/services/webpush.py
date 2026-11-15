"""Web Push: the VAPID signature (RFC 8292), the payload encryption (RFC 8291) and the one POST.

Built on the `cryptography` package the panel already pins, so no new dependency: P-256 ECDH and
ECDSA, HKDF-SHA-256 and AES-128-GCM are all there, and the two RFCs are a page of glue each. The unit
suite proves the encryption byte for byte against RFC 8291 Appendix A and the signature against RFC
8292's own example token.

Where a push goes (OWASP Server-Side Request Forgery Prevention Cheat Sheet, "Case 1: application can
send request only to identified and trusted applications"): the endpoint is a URL the BROWSER hands
the panel, so it is checked against an allow-list of the real push services' hosts, https on port 443
only, and the request is rebuilt from the parts that matched; the address the name resolves to must be
a public one (no loopback, private, link-local, tailnet 100.64.0.0/10, multicast or reserved, with an
IPv4 carried in an IPv6 form unwrapped first) and the connection goes to exactly the addresses that
were checked; redirects are never followed (http.client follows none). The check runs again at every
send, not only when the subscription was stored.

What never reaches a log: the endpoint (its path is the subscription's bearer capability), the
browser's keys and the payload. A failure is logged as the push service's fixed label and the HTTP
status as an int (OWASP Logging Cheat Sheet, "Data to exclude").
"""
import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from panel.core.config import decrypt_secret, encrypt_secret, load_config, update_config

# ── the push services a subscription may point at ──────────────────────────────────────────────────
# Checked 2026-11-15 against each vendor's own documentation:
#   Chrome, Edge-on-Android, Brave, Opera, Samsung: Firebase Cloud Messaging, fcm.googleapis.com.
#   Firefox: Mozilla's autopush, updates.push.services.mozilla.com.
#   Safari (macOS, iOS/iPadOS home-screen web apps): Apple, "allow access for https://*.push.apple.com"
#     (Apple: Sending web push notifications in web apps and browsers).
#   Edge on Windows: WNS. Microsoft (WNS overview): "ensures that the channel URI uses the domain
#     notify.windows.com ... The subdomain of the channel URI is subject to change".
# Exact names where the vendor names one host, a suffix (leading dot, so "evilpush.apple.com" is not
# "x.push.apple.com") where the vendor names a domain whose subdomains change.
PUSH_HOSTS = {"fcm.googleapis.com": "fcm", "updates.push.services.mozilla.com": "mozilla"}
PUSH_HOST_SUFFIXES = ((".push.apple.com", "apple"), (".notify.windows.com", "windows"))

# The whole endpoint, read one way: https, a lower-case host of DNS characters, optionally :443, then a
# path and an optional query of RFC 3986 characters with no backslash, space, '#' or '@' before the
# path. No userinfo can be expressed, so no parser can read a different host out of it than this one
# does (SSRF Prevention Cheat Sheet, "URL": reject a URL whose host is not read identically by every
# parser). The lengths are generous for every service above (FCM's are ~180 characters).
_ENDPOINT_RE = re.compile(
    r"https://(?P<host>[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?){1,8})"
    r"(?::443)?(?P<target>/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,1000}(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,1000})?)")
ENDPOINT_MAX = 1024

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{1,200}={0,2}")

# A push is a short notice: the RFC lets a service refuse a body over 4096 octets, and the panel's are
# a few hundred bytes. Seconds a POST may take, connect and answer each.
_TIMEOUT = 10.0
_RECORD_SIZE = 4096
# RFC 8030 "Urgency": the only words it defines.
URGENCIES = ("very-low", "low", "normal", "high")
# RFC 8292 caps a token at 24 hours; it is made fresh for every send, so a short life costs nothing.
_JWT_LIFE = 12 * 3600
# The contact the push services see in every token's "sub" (RFC 8292 2.1; Apple refuses a token whose
# subject is not an https: or mailto: URI). The panel sends no e-mail, so the project's public home.
VAPID_SUBJECT = "https://github.com/FMSMITH91/linuxgsm-panel"


def b64url(data):
    """Unpadded base64url, as RFC 7515 and RFC 8292 write keys and tokens."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text, max_len=200):
    """The bytes of a base64url string (padding optional), or None when it is not one."""
    if not isinstance(text, str) or len(text) > max_len or not _B64URL_RE.fullmatch(text):
        return None
    try:
        return base64.urlsafe_b64decode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 4))
    except (ValueError, TypeError):
        return None


# ── the endpoint and the address it resolves to ───────────────────────────────────────────────────
def service_label(host):
    """The fixed label of the push service `host` belongs to, or None when it is not one of them."""
    if host in PUSH_HOSTS:
        return PUSH_HOSTS[host]
    for suffix, label in PUSH_HOST_SUFFIXES:
        if host.endswith(suffix) and len(host) > len(suffix):
            return label
    return None


def parse_endpoint(url):
    """(host, target, label) for an endpoint the panel may POST to, else None.

    `target` is the path and query the request is rebuilt from; `label` the service's fixed name
    (what a log line may say about where a push went).
    """
    if not isinstance(url, str) or len(url) > ENDPOINT_MAX:
        return None
    m = _ENDPOINT_RE.fullmatch(url)
    if m is None:
        return None
    label = service_label(m.group("host"))
    if label is None:
        return None
    return m.group("host"), m.group("target"), label


_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_TAILNET = ipaddress.ip_network("100.64.0.0/10")


def _unwrapped(addr):
    """The IPv4 address an IPv6 one carries (mapped, NAT64, 6to4), else `addr` itself."""
    if addr.version == 4:
        return addr
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if any(addr in net for net in _NAT64):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr.sixtofour or addr


def address_refused(ip_text):
    """Whether a push must not connect to `ip_text`: anything but a public unicast address."""
    try:
        addr = _unwrapped(ipaddress.ip_address(str(ip_text).split("%", 1)[0]))
    except ValueError:
        return True
    return (not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_loopback
            or addr.is_link_local or addr.is_unspecified or addr.is_private
            or (addr.version == 4 and addr in _TAILNET))


class RefusedAddress(OSError):
    """The push service's name resolved to an address a push is never sent to."""


def _resolve(host):
    """Resolve `host`:443 with getaddrinfo (a seam the unit suite stubs)."""
    return socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM)


def _connect_checked(address, timeout=None, source_address=None):
    """Resolve once, refuse when ANY answer is not public, then connect to those checked answers."""
    from panel.services.notifications import _connect_infos
    infos = _resolve(address[0])
    if not infos or any(address_refused(info[4][0]) for info in infos):
        raise RefusedAddress("refused address")
    return _connect_infos(infos, timeout, source_address)


class _PushConnection(http.client.HTTPSConnection):
    """HTTPS to a push service, the socket opened by _connect_checked; certificate and SNI unchanged.

    No proxy is ever used (http.client reads none from the environment), so the address checked is
    the address connected to.
    """

    def __init__(self, host):
        super().__init__(host, 443, timeout=_TIMEOUT, context=ssl.create_default_context())
        self._create_connection = _connect_checked


# ── keys ──────────────────────────────────────────────────────────────────────────────────────────
_KEY_LOCK = threading.Lock()


def _private_from_raw(raw):
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def public_raw(key):
    """The uncompressed point (65 bytes, 0x04 first) of an EC key, private or public."""
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _stored_key(cfg):
    """The VAPID private key config.json holds, or None (absent, or unreadable with this host's key)."""
    raw = b64url_decode(decrypt_secret((cfg.get("push") or {}).get("vapid_private") or ""))
    if raw is None or len(raw) != 32:
        return None
    try:
        return _private_from_raw(raw)
    except ValueError:
        return None


def vapid_key():
    """The panel's VAPID signing key, made on first use and kept in config.json encrypted.

    Stored like the panel's other secrets (config.encrypt_secret: AES-256-GCM under data/cred_key, the
    key ring panel/db/at_rest.py re-encrypts on rotation). Made once under a lock and written with
    update_config, so two first sends at once keep one key. One key, one purpose: it only signs VAPID
    tokens; every message's ECDH key is a fresh one (RFC 8292 3.2).
    """
    key = _stored_key(load_config())
    if key is not None:
        return key
    with _KEY_LOCK:
        made = []

        def _mutate(cfg):
            if _stored_key(cfg) is not None:
                return
            new = ec.generate_private_key(ec.SECP256R1())
            d = new.private_numbers().private_value.to_bytes(32, "big")
            cfg["push"] = dict(cfg.get("push") or {}, vapid_private=encrypt_secret(b64url(d)),
                               vapid_public=b64url(public_raw(new)))
            made.append(new)
        cfg = update_config(_mutate)
        return made[0] if made else _stored_key(cfg)


def vapid_public_key():
    """The applicationServerKey a browser subscribes with: the VAPID public key, base64url."""
    return b64url(public_raw(vapid_key()))


# ── RFC 8292: the VAPID token ─────────────────────────────────────────────────────────────────────
def _jws_signature(key, signing_input):
    """ES256 over `signing_input`: the raw 64-byte r||s RFC 7518 3.4 requires (not DER)."""
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def vapid_token(key, audience, now=None):
    """The JWT for one push service origin: {"aud", "exp", "sub"}, ES256."""
    head = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = {"aud": audience, "exp": int(now if now is not None else time.time()) + _JWT_LIFE,
              "sub": VAPID_SUBJECT}
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = (head + "." + body).encode("ascii")
    return head + "." + body + "." + b64url(_jws_signature(key, signing_input))


def vapid_authorization(key, host, now=None):
    """The Authorization header value: `vapid t=<jwt>, k=<public key>` (RFC 8292 3)."""
    return "vapid t=%s, k=%s" % (vapid_token(key, "https://" + host, now), b64url(public_raw(key)))


# ── RFC 8291: the payload ─────────────────────────────────────────────────────────────────────────
def _hkdf(salt, ikm, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(plaintext, ua_public, auth_secret, salt=None, as_private=None):
    """One aes128gcm record (RFC 8188) of `plaintext` for the browser key `ua_public`.

    `salt` and `as_private` are for the RFC's test vector only: a real send always gets a fresh
    16-byte salt and a fresh P-256 key (os.urandom and the library's generator, OWASP Cryptographic
    Storage Cheat Sheet, "Secure Random Number Generation"). Raises ValueError for a key that is not a
    point on P-256 or a secret that is not 16 bytes.
    """
    if len(auth_secret) != 16:
        raise ValueError("the auth secret is 16 bytes")
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    as_key = as_private or ec.generate_private_key(ec.SECP256R1())
    as_public = public_raw(as_key)
    salt = salt if salt is not None else os.urandom(16)
    ecdh_secret = as_key.exchange(ec.ECDH(), ua_key)
    # RFC 8291 3.4: IKM from the ECDH secret, keyed by the auth secret, bound to both public keys.
    ikm = _hkdf(auth_secret, ecdh_secret, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    # One record, the last: the 0x02 delimiter and no padding (RFC 8291 4).
    body = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + struct.pack("!IB", _RECORD_SIZE, len(as_public)) + as_public
    return header + body


# ── the POST ──────────────────────────────────────────────────────────────────────────────────────
def _post(host, target, headers, body):
    """POST `body` to https://host<target>; the status as an int. Raises OSError/HTTPException."""
    conn = _PushConnection(host)
    try:
        conn.request("POST", target, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read(4096)
        return int(resp.status)
    finally:
        conn.close()


def send(endpoint, p256dh, auth, payload, ttl, urgency="normal"):
    """Encrypt and POST one push. -> (status, label): the HTTP status, or 0 when none came back.

    Negative status words instead of a number: -1 the endpoint is not a push service's (re-checked
    here, at send time), -2 its name resolves to a refused address, -3 the browser keys are unusable.
    Never raises; logs nothing (the caller logs the label and the status).
    """
    parsed = parse_endpoint(endpoint)
    if parsed is None:
        return -1, "?"
    host, target, label = parsed
    try:
        body = encrypt(payload, p256dh, auth)
    except (ValueError, TypeError):
        return -3, label
    headers = {"TTL": str(max(0, int(ttl))), "Urgency": urgency if urgency in URGENCIES else "normal",
               "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
               "Authorization": vapid_authorization(vapid_key(), host), "User-Agent": "linuxgsm-panel"}
    try:
        return _post(host, target, headers, body), label
    except RefusedAddress:
        return -2, label
    except (OSError, http.client.HTTPException, ValueError):
        return 0, label
