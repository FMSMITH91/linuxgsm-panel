"""The SFTP service's settings, host key and accepted user keys: what the panel and the service share.

The service itself is panel/services/sftp_server.py (its own process); the panel side that starts it
and answers its questions is panel/services/sftp_broker.py; the Settings card and the Account page's
keys are panel/routes/sftp_settings.py. Everything here is plain data and checks, safe in both
processes.

Sources, read 2026-11-18 (each named where it is applied):
* OWASP Authentication Cheat Sheet ("Protect Against Automated Attacks", "Login Throttling",
  "Account Lockout", "Authentication and Error Messages", "Logging and Monitoring").
* OWASP Multifactor Authentication Cheat Sheet (4 "Quick Recommendations", 5.2 "When to Require
  MFA", 5.3.2 "TOTP Seeds and Validation Window", 5.5 "Failed Login Attempts").
* OWASP Key Management Cheat Sheet ("Key Strength": key sizes from NIST SP 800-57 and SP 800-131A;
  "Storage": keys never in plaintext).
* OWASP File Upload Cheat Sheet ("Upload and Download Limits", "Filename Safety", "User Permissions").
* NIST SP 800-57 Part 1 Rev. 5, Table 2: RSA-3072 and the 256-bit curves give 128-bit security;
  RSA-2048 only 112 bits, acceptable to 2030.
* OpenSSH sshd_config(5): its default Ciphers, MACs, KexAlgorithms and key types; RFC 9142 (key
  exchange method updates) for the SHA-1 exchanges left out.
"""
import base64
import hashlib
import io
import ipaddress
import re

# The environment variable that hands the service its end of the panel's socket pair (a fd number).
IPC_FD_ENV = "LGSM_PANEL_SFTP_IPC_FD"

# ── Settings (config.json keys) ────────────────────────────────────────────────────────────────
ENABLED_KEY = "sftp_enabled"
BIND_KEY = "sftp_bind"
PORT_KEY = "sftp_port"
KBD_SIGNIN_KEY = "sftp_password_auth"
CAP_KEY = "sftp_max_upload_mb"
IDLE_KEY = "sftp_idle_minutes"
ABSOLUTE_KEY = "sftp_absolute_hours"
HOST_KEY_KEY = "sftp_host_key"

BIND_TAILSCALE, BIND_LOOPBACK, BIND_ALL = "tailscale", "loopback", "all"
BIND_CHOICES = (BIND_TAILSCALE, BIND_LOOPBACK, BIND_ALL)

DEFAULT_PORT = 2222
# The OWASP File Upload Cheat Sheet ("Upload and Download Limits") asks for a size limit and names no
# number. Game servers take maps, mods and worlds of a few gigabytes, so the suggested cap is 4 GiB:
# large enough for those, small enough that one upload cannot fill a typical host's disk.
RECOMMENDED_CAP_MB = 4096
CAP_MIN_MB, CAP_MAX_MB = 1, 1024 * 1024
# A write is refused when it would leave less than this free on the game host's filesystem: the
# backup upload keeps the same headroom (ops/backup.py _UPLOAD_SLACK).
FREE_SPACE_SLACK = 256 * 1024 * 1024
# OWASP Session Management Cheat Sheet, "Session Expiration" (read 2026-11-19): "Common idle timeouts ranges
# are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications", enforced
# server-side, the session invalidated when it expires. An SFTP session is a sign-in like a web session; its
# activity is the client's SFTP requests (a listing, a read, a write), so a transfer in progress is activity
# and an idle FileZilla window is not. 15 minutes, the start of the low-risk range: an SFTP client sits idle
# between transfers far more than a browser tab sits between clicks. 0 never closes an idle session.
RECOMMENDED_IDLE_MINUTES = 15
OWASP_IDLE_MAX_MINUTES = 30
IDLE_MIN_MINUTES, IDLE_MAX_MINUTES = 0, 24 * 60
# The same Cheat Sheet's "Absolute Timeout": "All sessions should implement an absolute timeout, regardless of
# session activity", with 4-8 hours as its example for a working day. The panel's own sign-in already has this
# setting (core/session_policy: `session_absolute_hours`, default 8, 1-168, a note past OWASP's 8), so the SFTP
# one takes the same range, the same note and, until it is set, the web sign-in's own value.
# When it passes, the session takes no new request but lets a file already open finish, for at most
# ABSOLUTE_GRACE_MINUTES: an hour is what an upload of the recommended 4 GiB cap needs over a 10 Mbit/s uplink
# (4 GiB / 1.25 MB/s ≈ 57 min), the slow end of a home connection; anything longer is cut, as a web session
# past its limit is.
ABSOLUTE_GRACE_MINUTES = 60
# Keys one account may hold.
MAX_KEYS_PER_USER = 20


def settings(cfg):
    """The SFTP settings in force, every value checked: {enabled, bind, port, password, cap_mb}."""
    cfg = cfg or {}
    bind = cfg.get(BIND_KEY)
    return {
        "enabled": cfg.get(ENABLED_KEY) is True,
        "bind": bind if bind in BIND_CHOICES else None,
        "port": port_or(cfg.get(PORT_KEY), DEFAULT_PORT),
        "password": cfg.get(KBD_SIGNIN_KEY) is True,
        "cap_mb": cap_or(cfg.get(CAP_KEY), RECOMMENDED_CAP_MB),
        "idle_min": idle_or(cfg.get(IDLE_KEY), RECOMMENDED_IDLE_MINUTES),
        "absolute_h": absolute_or(cfg.get(ABSOLUTE_KEY), _web_absolute_hours(cfg)),
    }


def _web_absolute_hours(cfg):
    """The panel's own sign-in absolute limit (Settings → Sessions & Security), the SFTP one's default."""
    from panel.core import session_policy
    return session_policy.absolute_hours(cfg)


def absolute_or(value, default):
    """`value` as an absolute limit in whole hours within the web sign-in's own range (1-168), else `default`."""
    from panel.core import session_policy
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return default
    try:
        n = int(str(value).strip())
    except ValueError:
        return default
    return n if session_policy.ABSOLUTE_MIN_HOURS <= n <= session_policy.ABSOLUTE_MAX_HOURS else default


def absolute_past_owasp(hours):
    """Whether an absolute limit is longer than OWASP's 8 hours (the web sign-in's own note)."""
    from panel.core import session_policy
    return hours > session_policy.OWASP_ABSOLUTE_MAX_HOURS


def idle_or(value, default):
    """`value` as an idle timeout in whole minutes within IDLE_MIN_MINUTES..IDLE_MAX_MINUTES, else `default`."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return default
    try:
        n = int(str(value).strip())
    except ValueError:
        return default
    return n if IDLE_MIN_MINUTES <= n <= IDLE_MAX_MINUTES else default


def idle_outside_owasp(minutes):
    """Whether an idle timeout is outside what OWASP recommends: off (0), or longer than 30 minutes."""
    return minutes == 0 or minutes > OWASP_IDLE_MAX_MINUTES


def port_or(value, default):
    """`value` as a TCP port (1-65535, a whole number), else `default`."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return default
    try:
        n = int(str(value).strip())
    except ValueError:
        return default
    return n if 1 <= n <= 65535 else default


def cap_or(value, default):
    """`value` as an upload cap in MiB within CAP_MIN_MB..CAP_MAX_MB, else `default`."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return default
    try:
        n = int(str(value).strip())
    except ValueError:
        return default
    return n if CAP_MIN_MB <= n <= CAP_MAX_MB else default


def default_bind(tailscale_up):
    """The address choice offered first: the Tailscale address when Tailscale is up, else 127.0.0.1."""
    return BIND_TAILSCALE if tailscale_up else BIND_LOOPBACK


def host_has_ipv6(path="/proc/net/if_inet6"):
    """Whether this host has an IPv6 address on an interface other than loopback."""
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            return any(len(line.split()) >= 6 and line.split()[5] != "lo" for line in f)
    except OSError:
        return False


def bind_addresses(choice, tailscale_ips, ipv6):
    """The addresses the service listens on for `choice`; [] when there is none to use yet.

    * tailscale: this host's Tailscale addresses (IPv4 first), only those inside Tailscale's ranges.
    * loopback: 127.0.0.1.
    * all: 0.0.0.0, and :: as well when the host has IPv6 (`ipv6`).
    Never 0.0.0.0 or :: for any choice but `all`.
    """
    if choice == BIND_LOOPBACK:
        return ["127.0.0.1"]
    if choice == BIND_ALL:
        return ["0.0.0.0"] + (["::"] if ipv6 else [])  # nosec B104 - the operator's explicit "all addresses"
    if choice == BIND_TAILSCALE:
        return _tailnet_addresses(tailscale_ips)
    return []


def _tailnet_addresses(ips):
    """The addresses in `ips` that are inside Tailscale's ranges, IPv4 first, each once."""
    out = []
    for raw in ips or ():
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if any(addr in n for n in TAILNET) and str(addr) not in out:
            out.append(str(addr))
    return sorted(out, key=lambda a: ":" in a)


# Tailscale's CGNAT IPv4 range and its IPv6 ULA prefix (security/banlist._TAILNET).
TAILNET = tuple(ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48"))  # NOSONAR - Tailscale's fixed ranges


def parse_form(form, tailscale_up):
    """(changes for config.json, refusal or None) from the Settings card's form.

    Out-of-range numbers are refused, never quietly changed. Values outside the recommendation are
    saved (the card shows a note beside them).
    """
    bind = (form.get("sftp_bind") or "").strip()
    if bind not in BIND_CHOICES or (bind == BIND_TAILSCALE and not tailscale_up):
        return None, "Choose where the SFTP service listens."
    port = port_or(form.get("sftp_port"), None)
    if port is None:
        return None, "The SFTP port must be a whole number from 1 to 65535."
    cap = cap_or(form.get("sftp_max_upload_mb"), None)
    if cap is None:
        return None, "The upload size limit must be a whole number of MiB from 1 to 1048576."
    idle = idle_or(form.get("sftp_idle_minutes"), None)
    if idle is None:
        return None, "The idle timeout must be a whole number of minutes from 0 to 1440."
    absolute = absolute_or(form.get("sftp_absolute_hours"), None)
    if absolute is None:
        return None, "The absolute session limit must be a whole number of hours from 1 to 168."
    if idle > absolute * 60:
        return None, ("The idle timeout cannot be longer than the absolute session limit. Shorten the "
                      "idle timeout or lengthen the limit.")
    return {ENABLED_KEY: form.get("sftp_enabled") == "on", BIND_KEY: bind, PORT_KEY: port,
            KBD_SIGNIN_KEY: form.get("sftp_password_auth") == "on", CAP_KEY: cap, IDLE_KEY: idle,
            ABSOLUTE_KEY: absolute}, None


# ── The service's host key ─────────────────────────────────────────────────────────────────────
def new_host_key_text():
    """A new Ed25519 host key as OpenSSH private-key text (unencrypted: the caller encrypts it)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode("ascii")


def host_key_from_text(text):
    """The paramiko Ed25519 key for stored host-key text, or None when it is not one."""
    import paramiko
    try:
        return paramiko.Ed25519Key(file_obj=io.StringIO(text))
    except (paramiko.SSHException, ValueError, TypeError):
        return None


def fingerprint(blob):
    """The SHA256 fingerprint OpenSSH shows for a public key in SSH wire format: `SHA256:<base64>`."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def ensure_host_key(update_config, load_config, encrypt_secret, decrypt_secret):
    """The service's host key text, made and stored (encrypted in config.json) the first time.

    Kept under the panel's own key ring like every other stored secret (panel_encryption_model:
    config.json's secrets are AES-256-GCM under data/cred_key, and the re-encryption pass walks them),
    so a copied config.json or backup carries no usable host key. config.json itself is 0600.
    """
    stored = load_config().get(HOST_KEY_KEY) or ""
    text = decrypt_secret(stored) if stored else ""
    if text and host_key_from_text(text) is not None:
        return text
    made = {}

    def _mut(cfg):
        have = cfg.get(HOST_KEY_KEY) or ""
        plain = decrypt_secret(have) if have else ""
        if plain and host_key_from_text(plain) is not None:
            made["text"] = plain       # another writer made it first
            return
        made["text"] = new_host_key_text()
        cfg[HOST_KEY_KEY] = encrypt_secret(made["text"])
    update_config(_mut)
    return made["text"]


def host_fingerprint(text):
    """The SHA256 fingerprint of the host key in `text`, or "" when there is none."""
    key = host_key_from_text(text) if text else None
    return fingerprint(key.asbytes()) if key is not None else ""


# ── The algorithms the service offers ──────────────────────────────────────────────────────────
# OpenSSH's own defaults (sshd_config(5), read 2026-11-18) as far as paramiko implements them: no
# SHA-1 key exchange or MAC (RFC 9142 moves the SHA-1 exchanges to SHOULD NOT), no CBC cipher, no
# DSA or ssh-rsa (SHA-1) signatures. mlkem768x25519-sha256 is OpenSSH's first choice (a post-quantum
# hybrid); curve25519 and the NIST curves follow, as in OpenSSH's list.
CIPHERS = ("aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr")
MACS = ("hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256")
KEX = ("mlkem768x25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
       "ecdh-sha2-nistp384", "ecdh-sha2-nistp521")
HOST_KEY_TYPES = ("ssh-ed25519",)
PUBKEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                "rsa-sha2-512", "rsa-sha2-256")


def offered(preferred, supported):
    """`preferred` without the names `supported` (this paramiko's list) does not have, order kept."""
    have = set(supported)
    return tuple(n for n in preferred if n in have)


# ── Users' public keys ─────────────────────────────────────────────────────────────────────────
# NIST SP 800-57 Part 1 Rev. 5 Table 2 (the OWASP Key Management Cheat Sheet's reference for key
# strength): RSA-3072 matches the 128-bit security of Ed25519 and the NIST P-256 curve; RSA-2048 is
# only 112 bits, acceptable until 2030. The recommended size is taken, so an RSA key needs 3072 bits.
RSA_MIN_BITS = 3072
KEY_TYPES = {"ssh-ed25519": "Ed25519", "ecdsa-sha2-nistp256": "ECDSA P-256",
             "ecdsa-sha2-nistp384": "ECDSA P-384", "ecdsa-sha2-nistp521": "ECDSA P-521",
             "ssh-rsa": "RSA"}
RSA_TOO_SMALL = "RSA keys need at least 3072 bits. An Ed25519 key is recommended (ssh-keygen -t ed25519)."
_KEY_LINE_MAX = 16384
# The base64 alphabet (RFC 4648 section 4) a key line's middle field is made of; checked by set, not by a regex.
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
LABEL_MAX = 80


class ParsedKey:
    """One accepted public key: its type, wire-format blob (base64), fingerprint and a label."""

    def __init__(self, key_type, blob, label):
        """The key of `key_type` whose wire-format bytes are `blob`, labelled `label`."""
        self.key_type = key_type
        self.blob_b64 = base64.b64encode(blob).decode("ascii")
        self.fingerprint = fingerprint(blob)
        self.label = label


def parse_public_key(text, label=""):
    """(ParsedKey, None) for one OpenSSH public-key line, or (None, why it is refused).

    The line is `<type> <base64> [comment]`, as in a .pub file or authorized_keys (no options before
    it). Ed25519, ECDSA on the NIST curves, and RSA of at least RSA_MIN_BITS bits. The comment is the
    label when none is given.
    """
    parts, why = _key_line_parts(text)
    if why:
        return None, why
    key_type = parts[0]
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        return None, NOT_A_KEY_LINE
    why = _blob_problem(key_type, blob)
    if why:
        return None, why
    shown = (label or "").strip() or (parts[2].strip() if len(parts) > 2 else "")
    return ParsedKey(key_type, blob, clean_label(shown)), None


NOT_A_KEY_LINE = "That is not an OpenSSH public key line (type, then the key, then a comment)."


def _is_b64(field):
    """True when `field` is base64 characters with at most two "=" of padding at its end."""
    body = field.rstrip("=")
    return bool(body) and len(field) - len(body) <= 2 and set(body) <= _B64_CHARS


def _key_line_parts(text):
    """([type, base64, comment...], None) for one public-key line, or (None, why it is not one)."""
    line = (text or "").strip()
    if not line:
        return None, "Paste a public key (the one line in your .pub file)."
    if len(line) > _KEY_LINE_MAX or "\n" in line or "\r" in line:
        return None, "Paste one public key: a single line."
    parts = line.split(None, 2)
    if len(parts) < 2 or not _is_b64(parts[1]):
        return None, NOT_A_KEY_LINE
    if parts[0] not in KEY_TYPES:
        return None, "Use an Ed25519, ECDSA or RSA key (Ed25519 is recommended)."
    return parts, None


def _blob_problem(key_type, blob):
    """Why the key blob is refused (does not parse, names another type, RSA too small), else None."""
    import paramiko
    try:
        key = paramiko.PKey.from_type_string(key_type, blob)
    except (paramiko.SSHException, ValueError, TypeError, IndexError, AttributeError,
            paramiko.UnknownKeyType):
        return "That public key could not be read."
    if key.get_name() != key_type and not (key_type == "ssh-rsa" and key.get_name() == "ssh-rsa"):
        return "That public key could not be read."
    if key_type == "ssh-rsa" and key.get_bits() < RSA_MIN_BITS:
        return RSA_TOO_SMALL
    return None


def clean_label(text):
    """A key's label as the page and the audit log show it: printable, one line, at most LABEL_MAX."""
    out = "".join(c for c in str(text or "") if c.isprintable())
    return out.strip()[:LABEL_MAX]


def key_matches(row_type, row_blob_b64, offered_type, offered_blob):
    """Whether a stored key is the key offered at sign-in (type and blob, compared whole)."""
    import hmac
    try:
        stored = base64.b64decode(row_blob_b64 or "", validate=True)
    except ValueError:
        return False
    same_family = row_type == offered_type or (row_type == "ssh-rsa" and offered_type in ("rsa-sha2-256",
                                                                                         "rsa-sha2-512"))
    return same_family and hmac.compare_digest(stored, offered_blob)


# ── What a folder in the top level is called ───────────────────────────────────────────────────
_FOLDER_MAX = 120


def folder_names(servers):
    """{folder name: server id} for (id, name) pairs: each server's name, made safe and unique.

    A slash would make a name a path and a control character hides what a name is, so both become
    "-"; leading and trailing spaces and dots go; an empty name, or one two servers share, gets the
    server's id in brackets.
    """
    base = {}
    for sid, name in servers:
        clean = "".join("-" if (c == "/" or not c.isprintable()) else c for c in str(name or ""))
        clean = clean.strip(" .")[:_FOLDER_MAX]
        base[sid] = clean
    seen = {}
    for sid, clean in base.items():
        seen.setdefault(clean, []).append(sid)
    out = {}
    for sid, clean in sorted(base.items()):
        if not clean or len(seen[clean]) > 1:
            clean = ("%s [%d]" % (clean, sid)).strip()
        out[clean] = sid
    return out

