"""The key ring that encrypts the panel's secrets at rest (data/cred_key).

A stored secret is "enc:v2:<key id>:<base64url(nonce || ciphertext || tag)>": AES-256-GCM with a
96-bit random nonce from os.urandom and associated data naming the format and the key id, so a
value cannot be moved under another key's id without failing its tag. This follows the OWASP
Cryptographic Storage Cheat Sheet, "Algorithms" and "Cipher Modes" (AES with a 256-bit key in an
authenticated mode, GCM first), "Secure Random Number Generation" (keys and nonces from a CSPRNG)
and "Key Lifetimes and Rotation" (several keys, each value tagged with the id of the key that
encrypted it, old values re-encrypted to the new key).

Values written before this format are "enc:v1:<Fernet token>" (AES-128-CBC + HMAC-SHA256). They
still decrypt: the ring keeps the Fernet key that wrote them until nothing uses it.

The file is JSON: {"format", "version", "current", "keys": {id: {"key", "created"}}, "fernet": [...],
"unused": [...]}. A file holding one bare Fernet key is the format before the ring, and reads as a
ring with no current key; the first encryption adds one (add_key). "unused" records which retired
keys the last full re-encryption pass found nothing using; the NEXT pass removes a key only if it
is still unused then, so the rolling known-good copy of panel.db the panel takes at every start
(models._ensure_db_healthy), which holds the database as the previous run left it, never refers to
a key that is gone.
"""
import base64
import binascii
import fcntl
import json
import os
import re
import tempfile
import threading
import time
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

V1_PREFIX = "enc:v1:"
V2_PREFIX = "enc:v2:"
RING_FORMAT = "lgsm-panel-keyring"
FERNET_REF = "fernet"          # the name a v1 value's key goes by in "unused" and in references
_NONCE_LEN, _TAG_LEN = 12, 16
_AAD = b"lgsm-panel secret at rest|enc:v2|"
_V2_RE = re.compile(r"enc:v2:([0-9a-f]{8}):([A-Za-z0-9_-]+)\Z")
_KID_RE = re.compile(r"[0-9a-f]{8}\Z")


def _strings(value):
    """A list of str from a JSON list (None reads as empty)."""
    return [str(v) for v in value or []]


class UndecryptableValue(ValueError):
    """A stored value that no key in the ring opens (unknown key id, wrong key, or tampered)."""


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text):
    return base64.urlsafe_b64decode(text.encode("ascii") + b"=" * (-len(text) % 4))


def split_v2(value):
    """The (key id, nonce||ciphertext||tag) of a structurally valid v2 value, else None.

    Structure only: it needs no key, so a value reads as encrypted even with the key file missing
    (see config.is_encrypted for why that matters).
    """
    m = _V2_RE.match(value) if isinstance(value, str) else None
    if not m:
        return None
    try:
        raw = _b64d(m.group(2))
    except (binascii.Error, ValueError):
        return None
    if len(raw) < _NONCE_LEN + _TAG_LEN:
        return None
    return m.group(1), raw


def is_fernet_token(blob):
    """True if `blob` is STRUCTURALLY a Fernet token; the key is not consulted.

    Fernet layout: 0x80 | 8-byte timestamp | 16-byte IV | AES-CBC ciphertext (16-byte blocks) |
    32-byte HMAC, base64url-encoded. 57 = 1 + 8 + 16 + 32, i.e. everything but the ciphertext.
    """
    try:
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    except Exception:
        return False
    return len(raw) >= 57 and raw[0] == 0x80 and (len(raw) - 57) % 16 == 0


def key_ref(value):
    """The key a stored value names: its v2 key id, FERNET_REF for a v1 value, None if neither."""
    if not isinstance(value, str):
        return None
    parts = split_v2(value)
    if parts:
        return parts[0]
    if value.startswith(V1_PREFIX) and is_fernet_token(value[len(V1_PREFIX):]):
        return FERNET_REF
    return None


class KeyRing:
    """The panel's encryption keys: one current (encrypts), any number retired (decrypt only)."""

    def __init__(self, current=None, keys=None, fernet=(), unused=()):
        """Hold `keys` ({id: (32-byte key, created epoch)}), `current` among them, and the Fernet keys."""
        self.current = current
        self.keys = dict(keys or {})
        self.fernet = list(fernet)
        self.unused = sorted(set(unused))

    # ── reading and writing the file ──
    @classmethod
    def parse(cls, raw):
        """A KeyRing from the bytes of data/cred_key: the JSON ring, or one bare Fernet key."""
        text = raw.strip()
        if not text:
            raise ValueError("empty key file")
        if text[:1] != b"{":
            from cryptography.fernet import Fernet
            Fernet(text)                     # raises ValueError for anything but a Fernet key
            return cls(fernet=[text.decode("ascii")])
        return cls._from_doc(json.loads(text.decode("utf-8")))

    @classmethod
    def _from_doc(cls, doc):
        """A KeyRing from the parsed JSON document; ValueError for anything that is not one."""
        if not isinstance(doc, dict) or (doc.get("format"), doc.get("version")) != (RING_FORMAT, 1):
            raise ValueError("not a panel key ring")
        keys = {kid: cls._entry(kid, ent) for kid, ent in dict(doc.get("keys") or {}).items()}
        current = doc.get("current")
        if current not in keys and current is not None:
            raise ValueError("the current key is not in the ring")
        return cls(current, keys, _strings(doc.get("fernet")), _strings(doc.get("unused")))

    @staticmethod
    def _entry(kid, ent):
        key = _b64d(str((ent or {}).get("key", ""))) if isinstance(ent, dict) else b""
        if not _KID_RE.match(str(kid)) or len(key) != 32:
            raise ValueError("a malformed key in the ring")
        created = ent.get("created")
        return key, created if isinstance(created, int) else None

    def to_bytes(self):
        """The JSON this ring is stored as."""
        doc = {"format": RING_FORMAT, "version": 1, "current": self.current,
               "keys": {kid: {"key": _b64e(k), "created": c} for kid, (k, c) in self.keys.items()},
               "fernet": self.fernet, "unused": self.unused}
        return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")

    # ── deriving new rings ──
    def with_new_key(self):
        """A copy of the ring plus a new current key (256 bits from os.urandom); the old one is retired."""
        kid = os.urandom(4).hex()
        while kid in self.keys:
            kid = os.urandom(4).hex()
        keys = dict(self.keys)
        keys[kid] = (AESGCM.generate_key(bit_length=256), int(time.time()))
        return KeyRing(kid, keys, self.fernet, [u for u in self.unused if u != kid])

    def without(self, refs):
        """A copy of the ring minus the retired keys named in `refs` (key ids and/or FERNET_REF)."""
        keys = {k: v for k, v in self.keys.items() if k == self.current or k not in refs}
        fernet = [] if FERNET_REF in refs else self.fernet
        return KeyRing(self.current, keys, fernet, [u for u in self.unused if u not in refs])

    def retired(self):
        """The names of every key that is not current (key ids, and FERNET_REF when one is held)."""
        out = {k for k in self.keys if k != self.current}
        if self.fernet:
            out.add(FERNET_REF)
        return out

    # ── encrypting and decrypting ──
    def encrypt(self, plaintext):
        """`plaintext` (str) as a v2 value under the current key."""
        key = self.keys[self.current][0]
        nonce = os.urandom(_NONCE_LEN)
        sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"),
                                     _AAD + self.current.encode("ascii"))
        return "%s%s:%s" % (V2_PREFIX, self.current, _b64e(nonce + sealed))

    def decrypt(self, value):
        """The plaintext of a stored v2 or v1 value; UndecryptableValue when no key here opens it."""
        parts = split_v2(value)
        if parts:
            kid, raw = parts
            if kid not in self.keys:
                raise UndecryptableValue("encrypted under a key this ring does not hold")
            try:
                plain = AESGCM(self.keys[kid][0]).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:],
                                                          _AAD + kid.encode("ascii"))
            except InvalidTag:
                raise UndecryptableValue("authentication failed") from None
            return plain.decode("utf-8")
        if key_ref(value) == FERNET_REF and self.fernet:
            from cryptography.fernet import Fernet, InvalidToken, MultiFernet
            try:
                return MultiFernet([Fernet(k) for k in self.fernet]).decrypt(
                    value[len(V1_PREFIX):].encode("ascii")).decode("utf-8")
            except InvalidToken:
                raise UndecryptableValue("authentication failed") from None
        raise UndecryptableValue("not a value this ring can open")

    def is_current(self, value):
        """True when `value` is a v2 value under the current key (it needs no re-encryption)."""
        parts = split_v2(value)
        return bool(parts) and parts[0] == self.current


# ── the file on disk ──
_cache = {"sig": None, "ring": None}
_lock = threading.RLock()       # green under eventlet; flock below is for other processes
_depth = [0]


def read_ring(path):
    """The ring in `path`, parsed once per version of the file (re-read when it is replaced)."""
    with open(path, "rb") as f:
        st = os.fstat(f.fileno())
        sig = (str(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        if _cache["sig"] == sig:
            return _cache["ring"]
        ring = KeyRing.parse(f.read())
    _cache.update(sig=sig, ring=ring)
    return ring


@contextmanager
def ring_lock(path):
    """Hold the ring for changes: this process's threads, and every other process, wait.

    Re-entrant within a thread. Taken by every write of the ring, and by a panel backup while it
    copies panel.db and the ring, so an archive never pairs a database with a ring that lacks one
    of its keys.
    """
    with _lock:
        fd = None
        if _depth[0] == 0:
            fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
        _depth[0] += 1
        try:
            yield
        finally:
            _depth[0] -= 1
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)


def _write_ring(path, ring):
    """Replace `path` with `ring` atomically (a private temp file, fsync, rename, fsync the dir)."""
    folder = os.path.dirname(str(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".key-")   # 0600, owner only
    try:
        try:
            os.write(fd, ring.to_bytes())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass                     # nothing to remove
        raise
    dfd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def add_key(path, only_if_none=False):
    """Make a new key current in the ring at `path` and return the new ring.

    With `only_if_none`, a ring that already has a current key is returned unchanged: that is the
    first encryption on a panel whose file still holds only the Fernet key, and several threads or
    processes may get there at once; the lock and the re-read make exactly one of them add the key.
    """
    with ring_lock(path):
        ring = read_ring(path)
        if only_if_none and ring.current is not None:
            return ring
        new = ring.with_new_key()
        _write_ring(path, new)
        return new


def update_unused(path, current, unused, drop):
    """Record `unused` and remove the retired keys in `drop`, if `current` is still the current key.

    A rotation since the pass began means its findings describe an older ring: nothing changes.
    Returns the ring as it now is. Nothing to change is answered without taking the lock.
    """
    if _pruned(read_ring(path), current, unused, drop) is None:
        return read_ring(path)
    with ring_lock(path):
        ring = read_ring(path)
        new = _pruned(ring, current, unused, drop)
        if new is not None:
            _write_ring(path, new)
            return new
        return ring


def _pruned(ring, current, unused, drop):
    """The ring after update_unused's change, or None when it changes nothing (or `current` moved)."""
    if ring.current != current:
        return None
    new = ring.without(set(drop) & ring.retired())
    new.unused = sorted(set(unused) & new.retired())
    return None if new.to_bytes() == ring.to_bytes() else new


def new_ring_bytes():
    """The bytes of a fresh ring holding one new current key (a first install)."""
    return KeyRing().with_new_key().to_bytes()
