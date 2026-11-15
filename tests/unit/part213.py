"""Part 213 of the unit suite: secrets at rest as AES-256-GCM under a key ring, and rotating it.

* The format: encrypt_secret writes enc:v2:<key id>:<nonce||ciphertext||tag> under the current key
  and round-trips; a tampered value, or one moved under another key id, is refused by the GCM tag
  and reads as "" (models.UnreadableSecret through a column), never a crash.
* Legacy: a cred_key holding one bare Fernet key still decrypts enc:v1 values; the first encryption
  adds an AES key to the ring (once, however many callers) and keeps the Fernet key; an enc:v1
  value passing through encrypt_secret comes out as v2.
* The re-encryption pass over panel.db and config.json: an interrupted pass loses nothing and the
  next one finishes the job; a value no key opens is left byte for byte; a second pass rewrites
  nothing; a retired key goes only after two passes in a row found nothing using it.
* Rotation: a new key becomes current, the old one still reads during the pass, and after it every
  value is under the new key.
* Backups: an archive carries the ring, is staged under the ring's lock, and the restore check reads
  an archive's cred_key in either form (ring, or the single Fernet key of an archive made before).
* Through the app: the remote edit route stores a new credential as v2 and it reads back; the
  status route shows ids and never key material; the rotate route is superadmin-only and audited.
Each standalone check runs on its own app, database, key file and config file in a temp dir; the
route checks drive part12's app with its transport tripwire armed. Nothing reaches a host or data/.
"""
import json as _json213
import pathlib as _pl213
import shutil as _sh213
import sqlite3 as _sq213
import tarfile as _tar213
import tempfile as _tf213
import threading as _th213

from cryptography.fernet import Fernet as _Fernet213
from flask import Flask as _Flask213

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all, P9_ADMIN, P9_VIEWER)
from panel.core import config as _cfg213, cred_keyring as _kr213
from panel.db import at_rest as _ar213
from panel.db.models import (RemoteServer as _RS213, UnreadableSecret as _UR213, User as _U213,
                             db as _db213)
from panel.ops import backup as _bk213

_trips213 = len(_P9_TRIPPED)
_LIVE_KEY213 = _cfg213.CRED_KEY_FILE      # the run's key file (tests/unit_test.py points it at a temp dir)
_T213 = _pl213.Path(_tf213.mkdtemp(prefix="p213-"))
# The fixtures' secrets, as named constants (none is a real credential).
_S213_OLD = "legacy " + "ssh pass 1"
_S213_NEW = "edited " + "ssh pass 2"
_S213_TOK = "bot " + "token 213"
_XHR213 = {"X-Requested-With": "XMLHttpRequest"}


def _v1(fkey, text):
    """An enc:v1 value: `text` as a Fernet token under `fkey`."""
    return "enc:v1:" + _Fernet213(fkey).encrypt(text.encode()).decode()


def _use_files213(tag):
    """Point config's key and config files at fresh paths under the temp dir; returns the key path."""
    folder = _T213 / tag
    folder.mkdir()
    _p9_patch(_cfg213, "CRED_KEY_FILE", folder / "cred_key")
    _p9_patch(_cfg213, "CONFIG_FILE", folder / "config.json")
    _cfg213._cfg_cache["key"] = None
    return folder / "cred_key"


# ── 1. the format ───────────────────────────────────────────────────────────────────────────────
def _s213_format():
    _use_files213("format")
    enc = _cfg213.encrypt_secret(_S213_NEW)
    ring = _cfg213._cred_keyring()
    parts = _kr213.split_v2(enc)
    check("v2: encrypt_secret writes enc:v2:<current key id>:..., and it decrypts back",
          enc.startswith("enc:v2:%s:" % ring.current) and _cfg213.decrypt_secret(enc) == _S213_NEW, enc[:30])
    check("v2: the key is 256 bits and the nonce 96 bits, fresh for every value",
          len(ring.keys[ring.current][0]) == 32 and parts is not None
          and _kr213.split_v2(_cfg213.encrypt_secret(_S213_NEW))[1][:12] != parts[1][:12])
    raw = bytearray(parts[1])
    raw[-1] ^= 1
    tampered = "enc:v2:%s:%s" % (parts[0], _kr213._b64e(bytes(raw)))
    other = _cfg213.rotate_cred_key()
    moved = "enc:v2:%s:%s" % (other.current, _kr213._b64e(parts[1]))
    check("v2: a value with one bit flipped is refused by the GCM tag and reads as '', not raised",
          _cfg213.is_encrypted(tampered) and _cfg213.decrypt_secret(tampered) == "")
    check("v2: a value moved under another key id of the same ring is refused too (the id is "
          "authenticated)", _cfg213.decrypt_secret(moved) == "" and _cfg213.decrypt_secret(enc) == _S213_NEW)
    col = _RS213.__table__.c.host.type
    check("v2: through an encrypted column a tampered value reads as UnreadableSecret",
          isinstance(col.process_result_value(tampered, None), _UR213))
    once = _cfg213.encrypt_secret("x")
    check("v2: encrypting a value already under the current key is a no-op; one under an older key "
          "is brought up to the current one",
          _cfg213.encrypt_secret(once) == once and once.startswith("enc:v2:%s:" % other.current)
          and _cfg213.encrypt_secret(enc).startswith("enc:v2:%s:" % other.current)
          and _cfg213.decrypt_secret(_cfg213.encrypt_secret(enc)) == _S213_NEW)


# ── 2. the legacy key file ───────────────────────────────────────────────────────────────────────
def _s213_legacy():
    keyf = _use_files213("legacy")
    fkey = _Fernet213.generate_key()
    keyf.write_bytes(fkey + b"\n")
    old = _v1(fkey, _S213_OLD)
    read = _cfg213.decrypt_secret(old)
    check("legacy: a bare Fernet cred_key still decrypts enc:v1, and reading does not rewrite the file",
          read == _S213_OLD and keyf.read_bytes() == fkey + b"\n", repr(read))
    seen = []
    workers = [_th213.Thread(target=lambda: seen.append(_cfg213._cred_keyring_for_write().current))
               for _ in range(4)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(30)
    again = {_kr213.add_key(keyf, only_if_none=True).current for _ in range(3)}
    ring = _cfg213._cred_keyring()
    check("legacy: the first encryption adds ONE AES key however many callers race to it, and keeps "
          "the Fernet key", len(set(seen)) == 1 and seen[0] == ring.current and again == {ring.current}
          and len(ring.keys) == 1
          and ring.fernet == [fkey.decode()], repr((seen, ring.fernet)))
    new = _cfg213.encrypt_secret(old)
    check("legacy: an enc:v1 value through encrypt_secret comes out as v2 with the same plaintext",
          new.startswith("enc:v2:%s:" % ring.current) and _cfg213.decrypt_secret(new) == _S213_OLD, new[:30])


# ── 3. the re-encryption pass ────────────────────────────────────────────────────────────────────
def _app213(tag):
    app = _Flask213("p213" + tag)
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + str(_T213 / tag / "p.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    _db213.init_app(app)
    with app.app_context():
        _db213.create_all()
    return app


def _exec213(app, sql, **params):
    with app.app_context():
        _db213.session.execute(_db213.text(sql), params)
        _db213.session.commit()


def _raw213(app, sql, **params):
    with app.app_context():
        return _db213.session.execute(_db213.text(sql), params).fetchall()


def _seed213(app, fkey, foreign):
    """Six hosts and a user with legacy v1 values, one host field no key here opens; config too."""
    with app.app_context():
        _db213.session.add_all([_RS213(name="p213-%d" % i, host="h%d.p213.invalid" % i, port=22,
                                       username="root", auth_method="password") for i in range(6)]
                               + [_U213(username="p213u", password_hash="x")])
        _db213.session.commit()
    # The stored values as an older panel wrote them: enc:v1 under the Fernet key, written raw.
    for i in range(6):
        _exec213(app, "UPDATE remote_server SET host = :h, username = :u, auth_credential = :c WHERE name = :n",
                 h=_v1(fkey, "h%d.p213.invalid" % i), u=_v1(fkey, "root"), c=_v1(fkey, _S213_OLD),
                 n="p213-%d" % i)
    _exec213(app, "UPDATE user SET email = :e, totp_secret = :t",
             e=_v1(fkey, "p213@example.invalid"), t=_v1(fkey, "JBSWY3DPEHPK3PXP"))
    _exec213(app, "UPDATE remote_server SET public_ip = :f WHERE name = 'p213-3'", f=foreign)
    _cfg213.CONFIG_FILE.write_text(_json213.dumps({"telegram": {"token": _v1(fkey, _S213_TOK)},
                                                   "nested": [{"webhook": _v1(fkey, "hook")}]}))


def _values213(app):
    """Every encrypted value the fixtures stored (raw), hosts first, then the user, then config."""
    rows = _raw213(app, "SELECT host, username, auth_credential FROM remote_server ORDER BY id")
    out = [v for r in rows for v in r]
    out += list(_raw213(app, "SELECT email, totp_secret FROM user")[0])
    cfg = _json213.loads(_cfg213.CONFIG_FILE.read_text())
    return out + [cfg["telegram"]["token"], cfg["nested"][0]["webhook"]]


def _all_read213(values):
    return all(_cfg213.decrypt_secret(v) for v in values)


def _interrupt213(after):
    """Make the pass raise once it has re-encrypted `after` values; returns the undo."""
    real = _ar213._Tally.redo
    count = [0]

    def _redo(self, ring, value):
        count[0] += 1
        if count[0] > after:
            raise RuntimeError("p213: interrupted")
        return real(self, ring, value)
    _ar213._Tally.redo = _redo
    return lambda: setattr(_ar213._Tally, "redo", real)


def _pass213(app, prune=False, stop_after=None):
    undo = _interrupt213(stop_after) if stop_after is not None else None
    try:
        with app.app_context():
            try:
                return _ar213.reencrypt_pass(prune)
            except RuntimeError:
                _db213.session.rollback()
                return None
    finally:
        if undo:
            undo()


def _s213_pass():
    keyf = _use_files213("pass")
    app = _app213("pass")
    _p9_patch(_ar213, "BATCH", 2)
    fkey = _Fernet213.generate_key()
    keyf.write_bytes(fkey)
    foreign = _v1(_Fernet213.generate_key(), "198.51.100.213")
    _seed213(app, fkey, foreign)
    cut = _pass213(app, stop_after=5)
    mid = _values213(app)
    check("pass: an interrupted pass committed the batches it finished, and every value still reads",
          cut is None and 0 < sum(v.startswith("enc:v2:") for v in mid) < len(mid) and _all_read213(mid),
          repr([v[:7] for v in mid]))
    done = _pass213(app, prune=True)
    after = _values213(app)
    ring = _cfg213._cred_keyring()
    pub = _raw213(app, "SELECT public_ip FROM remote_server WHERE name = 'p213-3'")[0][0]
    check("pass: the next pass finishes: every value in panel.db and config.json is v2 under the "
          "current key and reads as before",
          len(after) == 22 and all(ring.is_current(v) for v in after) and _all_read213(after)
          and _cfg213.decrypt_secret(after[2]) == _S213_OLD and _cfg213.decrypt_secret(after[-2]) == _S213_TOK,
          repr([v[:16] for v in after]))
    check("pass: a value no key opens is left byte for byte, counted, and keeps the Fernet key",
          pub == foreign and done is not None and done.unreadable == 1 and ring.fernet == [fkey.decode()],
          repr((done and done.unreadable, ring.fernet)))
    again = _pass213(app, prune=True)
    check("pass: a second pass rewrites nothing", again is not None and again.rewritten == 0,
          repr(again and again.rewritten))
    return app


def _s213_prune(app):
    _exec213(app, "UPDATE remote_server SET public_ip = '' WHERE name = 'p213-3'")
    _pass213(app, prune=True)
    marked = _cfg213._cred_keyring()
    _pass213(app, prune=True)
    gone = _cfg213._cred_keyring()
    check("prune: a retired key is only marked unused by the first pass that finds nothing using it, "
          "and removed by the next", marked.fernet and marked.unused == ["fernet"] and not gone.fernet
          and gone.unused == [] and _all_read213(_values213(app)), repr((marked.unused, gone.fernet)))


def _s213_rotate(app):
    before = _values213(app)
    old = _cfg213._cred_keyring().current
    new = _cfg213.rotate_cred_key()
    check("rotate: a new current key, the old one kept, and every value still reads before the pass",
          new.current != old and old in new.keys and _all_read213(before))
    _pass213(app, stop_after=3)
    mid = _values213(app)
    check("rotate: ...and while the pass is part-way through",
          any(v.startswith("enc:v2:%s:" % new.current) for v in mid)
          and any(v.startswith("enc:v2:%s:" % old) for v in mid) and _all_read213(mid))
    _pass213(app)
    after = _values213(app)
    check("rotate: after the pass every value is under the new key and reads the same; the old key "
          "stays until two passes find it unused", all(new.is_current(v) for v in after)
          and [_cfg213.decrypt_secret(v) for v in after] == [_cfg213.decrypt_secret(v) for v in before]
          and old in _cfg213._cred_keyring().keys)


# ── 4. backups ───────────────────────────────────────────────────────────────────────────────────
def _archive213(name, members):
    path = _T213 / name
    with _tar213.open(str(path), "w") as tar:
        for arc, data in members.items():
            src = _T213 / ("m-" + arc)
            src.write_bytes(data)
            tar.add(str(src), arcname=arc)
    return _tar213.open(str(path), "r")


def _s213_backup_keys():
    fkey = _Fernet213.generate_key()
    ring = _kr213.KeyRing(fernet=[fkey.decode()]).with_new_key()
    with _archive213("old.tar", {"cred_key": fkey}) as tar:
        legacy = _bk213._restore_fernet(tar, tar.getnames())
    with _archive213("new.tar", {"cred_key": ring.to_bytes()}) as tar:
        current = _bk213._restore_fernet(tar, tar.getnames())
    check("backup: the restore check reads an archive made before the ring (one Fernet key) and opens "
          "its enc:v1 values", legacy is not None
          and _bk213._stored_plaintext(_v1(fkey, "root"), legacy) == "root")
    check("backup: ...and an archive with the ring opens v2 and v1 values; another key's value is unreadable",
          current is not None and _bk213._stored_plaintext(ring.encrypt("root"), current) == "root"
          and _bk213._stored_plaintext(_v1(fkey, "root"), current) == "root"
          and _bk213._stored_plaintext(_v1(_Fernet213.generate_key(), "x"), current) is _bk213._UNREADABLE)


def _s213_backup_archive():
    keyf = _use_files213("bk")
    saved = {k: getattr(_bk213, k) for k in ("BACKUP_DIR", "DATA_DIR", "DB_PATH", "CONFIG_FILE",
                                              "SECRET_FILE", "CRED_KEY_FILE")}
    folder = keyf.parent
    try:
        _bk213.BACKUP_DIR, _bk213.DATA_DIR = folder / "backups", folder
        _bk213.DB_PATH, _bk213.CONFIG_FILE = folder / "panel.db", folder / "config.json"
        _bk213.SECRET_FILE, _bk213.CRED_KEY_FILE = folder / "secret_key", keyf
        con = _sq213.connect(str(_bk213.DB_PATH))
        with con:
            con.execute("CREATE TABLE t (v INTEGER)")
        con.close()
        _bk213.CONFIG_FILE.write_text("{}")
        _bk213.SECRET_FILE.write_text("s")
        _cfg213.encrypt_secret("x")
        held = []
        real = _bk213._snapshot_db
        _bk213._snapshot_db = lambda dest: held.append(_kr213._depth[0]) or real(dest)
        try:
            ok, name = _bk213.create_backup("manual", passphrase="")  # nosec B106 - in the clear
        finally:
            _bk213._snapshot_db = real
        with _tar213.open(str(_bk213.BACKUP_DIR / name), "r:gz") as tar:
            carried = tar.extractfile("cred_key").read() if ok else b""
        check("backup: a new archive carries the key ring as it is, copied with the database under the "
              "ring's lock", ok and carried == keyf.read_bytes() and held == [1], repr((ok, held)))
    finally:
        for k, v in saved.items():
            setattr(_bk213, k, v)


# ── 5. through the app ───────────────────────────────────────────────────────────────────────────
def _s213_routes():
    live = _cfg213._cred_keyring()
    keyf = _use_files213("routes")
    fkey = _Fernet213.generate_key()
    keyf.write_bytes(_kr213.KeyRing(live.current, live.keys, [fkey.decode()]).to_bytes())
    with _p9.app_context():
        row = _RS213(name="p213-edit", host="198.51.100.213", port=22, username="root",
                     auth_method="password", auth_credential="")
        _db213.session.add(row)
        _db213.session.commit()
        rid = row.id
        _db213.session.execute(_db213.text("UPDATE remote_server SET auth_credential = :c WHERE id = :i"),
                               {"c": _v1(fkey, _S213_OLD), "i": rid})
        _db213.session.commit()
    try:
        _s213_routes_edit(rid)
        _s213_routes_rotate()
    finally:
        with _p9.app_context():
            _RS213.query.filter_by(id=rid).delete()
            _db213.session.commit()
        # Anything part12's app encrypted meanwhile stays readable for the parts after this one: the
        # run's own ring keeps its current key and gains the keys this check added.
        mine = _cfg213._cred_keyring()
        _kr213._write_ring(_LIVE_KEY213, _kr213.KeyRing(live.current, mine.keys, live.fernet))


def _s213_routes_edit(rid):
    from panel.ops.ssh_manager import _core as _core213
    with _p9.app_context():
        read_old = _core213.decrypt_secret(_db213.session.get(_RS213, rid).auth_credential)
    r = _p9_client(P9_ADMIN).post("/remotes/%d/edit" % rid, headers=_XHR213,
                                  data={"ssh_port": "22", "auth_method": "password", "credential": _S213_NEW})
    with _p9.app_context():
        raw = _db213.session.execute(_db213.text("SELECT auth_credential FROM remote_server WHERE id = :i"),
                                     {"i": rid}).scalar()
        back = _core213.decrypt_secret(_db213.session.get(_RS213, rid).auth_credential)
    check("app: a legacy enc:v1 credential reads through the SSH path, and the edit route stores the "
          "new one as v2 that reads back", read_old == _S213_OLD and r.status_code == 200
          and raw.startswith("enc:v2:%s:" % _cfg213._cred_keyring().current) and back == _S213_NEW,
          repr((read_old, r.status_code, raw[:20], back)))


def _s213_routes_rotate():
    started = []
    _p9_patch(_ar213, "start_reencrypt", lambda app, **k: started.append(k))
    before = _cfg213._cred_keyring()
    n_audit = _p9_audit_count("panel_cred_key_rotate")
    denied = _p9_client(P9_VIEWER).post("/api/panel/encryption/rotate", json={})
    unchanged = _cfg213._cred_keyring().to_bytes() == before.to_bytes()
    n_denied = _p9_audit_count("panel_cred_key_rotate")
    r = _p9_client(P9_ADMIN).post("/api/panel/encryption/rotate", json={})
    after = _cfg213._cred_keyring()
    audit = _p9_audit("panel_cred_key_rotate")
    check("app: rotate is refused to a non-superadmin and changes nothing",
          denied.status_code == 403 and unchanged and n_denied == n_audit, repr(denied.status_code))
    check("app: a superadmin's rotate makes a new key current, keeps the old, audits the new id and "
          "starts the background pass", r.status_code == 200 and _p9_json(r).get("current") == after.current
          and after.current != before.current and before.current in after.keys
          and audit.detail == "new key %s" % after.current and started == [{"rotated": True}],
          repr((r.status_code, audit.detail, started)))
    st = _p9_client(P9_ADMIN).get("/api/panel/encryption")
    body = st.get_data(as_text=True)
    secret = [_kr213._b64e(k) for k, _c in after.keys.values()] + list(after.fernet)
    check("app: the status route names the current key id and how many older keys are kept, never a key",
          st.status_code == 200 and _p9_json(st).get("current") == after.current
          and _p9_json(st).get("retired") == 2 and not any(s in body for s in secret), body[:200])


try:
    _p9_arm(who="part213")
    _s213_format()
    _s213_legacy()
    _p213_app = _s213_pass()
    _s213_prune(_p213_app)
    _s213_rotate(_p213_app)
    _s213_backup_keys()
    _s213_backup_archive()
    _s213_routes()
finally:
    _p9_restore_all()
    _cfg213._cfg_cache["key"] = None
    _sh213.rmtree(_T213, ignore_errors=True)

check("part213: nothing it drove reached a real transport",
      len(_P9_TRIPPED) == _trips213, repr(_P9_TRIPPED[_trips213:][:6]))
