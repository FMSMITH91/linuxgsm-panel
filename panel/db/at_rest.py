"""Keeping the panel's stored secrets encrypted under the current key.

Three jobs, all idempotent:

* encrypt_legacy_plaintext: secrets from before encryption at rest (remote SSH credentials,
  e-mail addresses) still stored in the clear are encrypted.
* reencrypt_pass: every encrypted value in panel.db and config.json that is not under the current
  key (the legacy Fernet format after an upgrade, or an older key after a rotation) is decrypted
  and written again under the current key. OWASP Cryptographic Storage Cheat Sheet, "Key
  Lifetimes and Rotation": re-encrypting old data under the new key is preferred to keeping every
  key forever.
* start_reencrypt: that pass on a background thread, so start-up and the rotate action never wait.

The pass finds values by their shape ("enc:v..." in any text column of any table, and any string
in config.json), so a column added later is covered without being listed here. It works in
batches with a commit after each, and each row is written only if it still holds the value that
was read (compare-and-swap), so a save that lands meanwhile is never overwritten and an
interrupted pass simply finds less to do next time. A value no key opens is left exactly as it is
and counted: it may belong to a key file that can still be put back.
"""
import logging
import threading
import time

from panel.core import cred_keyring as _kr

_log = logging.getLogger("panel.at_rest")

BATCH = 200
# The last pass's outcome, for the Settings card. `pending` means a rotation asked for another
# pass while one was running; the running one starts it again when it finishes.
STATUS = {"running": False, "pending": False, "rewritten": 0, "unreadable": 0, "pruned": [],
          "finished": None, "failed": False}
_state_lock = threading.Lock()
_generation = [0]       # bumped by every rotation: a pass that began before one never prunes


def encrypt_legacy_plaintext():
    """Encrypt remote SSH credentials and user e-mail addresses still stored in the clear."""
    from panel.core.config import encrypt_secret, is_encrypted
    from panel.db.models import RemoteServer, User, db
    changed = False
    for r in RemoteServer.query.all():
        if r.auth_credential and not is_encrypted(r.auth_credential) \
                and r.auth_method in ("password", "key"):
            r.auth_credential = encrypt_secret(r.auth_credential)
            changed = True
    for u in User.query.all():
        if u.email and not is_encrypted(u.email):
            u.email = encrypt_secret(u.email)
            changed = True
    if changed:
        db.session.commit()


def _text_columns():
    """(table name, primary-key column name, column name) for every text column of every table."""
    from sqlalchemy import String
    from panel.db.models import EncryptedString, db
    for tbl in db.metadata.sorted_tables:
        pk = list(tbl.primary_key.columns)
        if len(pk) != 1:
            continue
        for col in tbl.columns:
            if col is not pk[0] and isinstance(col.type, (String, EncryptedString)):
                yield tbl.name, pk[0].name, col.name


class _Tally:
    """What one pass did: values rewritten, values no key opens, and the keys those still name."""

    def __init__(self):
        """Start at zero."""
        self.rewritten = 0
        self.unreadable = 0
        self.refs = set()
        self.pruned = []

    def absorb(self, other):
        """Add another tally's counts and references to this one."""
        self.rewritten += other.rewritten
        self.unreadable += other.unreadable
        self.refs |= other.refs

    def redo(self, ring, value):
        """`value` under the current key, or None when it needs nothing or cannot be opened."""
        ref = _kr.key_ref(value)
        if ref is None or ring.is_current(value):
            return None
        try:
            return ring.encrypt(ring.decrypt(value))
        except ValueError:
            self.unreadable += 1
            self.refs.add(ref)
            return None


def _reencrypt_column(ring, tally, tname, pkname, cname):
    """Re-encrypt one column's values, BATCH rows at a time, committing after each batch."""
    from sqlalchemy import column, select, table, update
    from panel.db.models import db
    t = table(tname, column(pkname), column(cname))
    pkc, col = t.c[pkname], t.c[cname]
    base = select(pkc, col).where(col.like("enc:v%"),
                                  ~col.like(_kr.V2_PREFIX + ring.current + ":%")).order_by(pkc)
    last = None
    while True:
        stmt = base if last is None else base.where(pkc > last)
        rows = db.session.execute(stmt.limit(BATCH)).fetchall()
        if not rows:
            return
        for rid, old in rows:
            new = tally.redo(ring, old)
            if new is not None:
                done = db.session.execute(update(t).where(pkc == rid, col == old).values({cname: new}))
                tally.rewritten += done.rowcount
        db.session.commit()
        last = rows[-1][0]
        time.sleep(0)            # let the rest of the panel run between batches


def _walk(obj, ring, tally):
    """Re-encrypt, in place, every encrypted string inside a config dict/list; return how many."""
    n = 0
    items = obj.items() if isinstance(obj, dict) else enumerate(obj)
    for key, val in list(items):
        if isinstance(val, (dict, list)):
            n += _walk(val, ring, tally)
        elif isinstance(val, str):
            new = tally.redo(ring, val)
            if new is not None:
                obj[key] = new
                n += 1
    return n


def _reencrypt_config(ring, tally):
    """Re-encrypt config.json's encrypted values (bot tokens, webhooks, the backup passphrase).

    Read first and written only when something changes; the write re-reads under the config lock
    (update_config), so a setting saved meanwhile is kept.
    """
    from panel.core.config import is_unreadable, load_config, update_config
    cfg = load_config()
    if is_unreadable(cfg):
        return
    probe = _Tally()
    if not _walk(cfg, ring, probe):
        tally.absorb(probe)
        return
    done = []

    def _mutate(c):
        t = _Tally()
        t.rewritten = _walk(c, ring, t)
        done[:] = [t]
    update_config(_mutate)
    tally.absorb(done[0] if done else probe)


def reencrypt_pass(prune=False):
    """Bring every stored secret under the current key; with `prune`, retire unused old keys.

    A retired key is removed only when this pass AND the previous one both found nothing using it
    (cred_keyring's module docstring says why two). Returns the _Tally. Needs an app context.
    """
    from panel.core import config as cfgmod
    tally = _Tally()
    if cfgmod._key_missing(cfgmod.CRED_KEY_FILE):
        return tally             # nothing was ever encrypted here; do not create a key for nothing
    gen = _generation[0]
    ring = cfgmod._cred_keyring_for_write()
    if ring.retired():
        for tname, pkname, cname in _text_columns():
            _reencrypt_column(ring, tally, tname, pkname, cname)
        _reencrypt_config(ring, tally)
    if prune and gen == _generation[0]:
        unused = ring.retired() - tally.refs
        drop = unused & set(ring.unused)
        after = _kr.update_unused(cfgmod.CRED_KEY_FILE, ring.current, unused, drop)
        tally.pruned = sorted(drop - after.retired())
    return tally


def _run(app, prune):
    """The background pass, again for as long as a rotation asked for one while it ran."""
    while True:
        try:
            with app.app_context():
                tally = reencrypt_pass(prune)
            with _state_lock:
                STATUS.update(rewritten=tally.rewritten, unreadable=tally.unreadable, failed=False,
                              pruned=tally.pruned, finished=int(time.time()))
            if tally.rewritten or tally.unreadable:
                _log.info("re-encrypted %d stored value(s) under the current key; %d could not be "
                          "decrypted and were left as they are", tally.rewritten, tally.unreadable)
        except Exception:
            _log.exception("re-encrypting stored secrets failed; nothing was lost, the next start "
                           "tries again")
            _rollback(app)
            with _state_lock:
                STATUS.update(failed=True, finished=int(time.time()))
        with _state_lock:
            if not STATUS["pending"]:
                STATUS["running"] = False
                return
            STATUS["pending"] = False
            prune = False


def _rollback(app):
    """Roll back whatever the failed batch left open."""
    from panel.db.models import db
    try:
        with app.app_context():
            db.session.rollback()
    except Exception:
        _log.debug("rollback after a failed re-encryption pass failed too", exc_info=True)


def start_reencrypt(app, prune=False, rotated=False):
    """Run reencrypt_pass on a background thread; a call while one runs queues one more pass.

    `rotated` marks a call made just after a rotation, so a pass already running does not prune
    on the strength of what it saw under the old key.
    """
    with _state_lock:
        if rotated:
            _generation[0] += 1
        if STATUS["running"]:
            STATUS["pending"] = True
            return False
        STATUS["running"] = True
    threading.Thread(target=_run, args=(app, prune), name="reencrypt-secrets", daemon=True).start()
    return True


def key_status():
    """The ring and the last pass, for the Settings card: never a key, only ids and dates."""
    from panel.core import config as cfgmod
    if cfgmod._key_missing(cfgmod.CRED_KEY_FILE):
        return {"present": False}
    ring = cfgmod._cred_keyring()
    created = ring.keys[ring.current][1] if ring.current else None
    with _state_lock:
        last = dict(STATUS)
    return {"present": True, "current": ring.current or "", "created": created,
            "algorithm": "AES-256-GCM" if ring.current else "Fernet (AES-128-CBC + HMAC-SHA256)",
            "retired": len(ring.retired()) - (0 if ring.current else 1), "pass": last}
