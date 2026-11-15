"""Part 212 of the unit suite: passwords stored as Argon2id, the bcrypt formats before it, the backup KDF.

* New account passwords and 2FA backup codes are Argon2id PHC strings at the pinned parameters
  (m=19456 KiB, t=2, p=1: the OWASP Password Storage Cheat Sheet's minimum).
* The login route: an account whose stored hash is `sha256$<bcrypt>`, a bare `$2b$` bcrypt, or
  Argon2id at lower parameters signs in, is rehashed to the current Argon2id in that same request,
  and signs in again on the new hash; a wrong password signs nothing in and rewrites nothing.
* The password-change route refuses a reused password whether its stored hash is Argon2id or bcrypt.
* The login's 2FA step: an Argon2id backup code and a bcrypt one from before each sign in once.
* A stored Argon2id hash asking for more than four times the current cost, and a password over
  MAX_PASSWORD_BYTES, are refused.
* Backups: a new archive's header records scrypt N=2^17, r=8, p=1 and opens again; one written at
  the old N=2^15 still opens; a header asking for more than the bound is refused by the restore
  before anything is derived; the derivation runs through tpool under eventlet.
Every account lives in part12's app database, with its transport tripwire armed; the backup paths
point at a temp dir. Nothing reaches a host or data/.
"""
import base64 as _b64212
import hashlib as _hl212
import json as _json212
import os as _os212
import pathlib as _pl212
import shutil as _sh212
import sqlite3 as _sq212
import tarfile as _tar212
import tempfile as _tf212
import time as _time212

import bcrypt as _bc212
import eventlet.patcher as _patcher212
import eventlet.tpool as _tpool212
import pyotp as _pyotp212
from argon2 import PasswordHasher as _PH212, Type as _AT212, extract_parameters as _xp212
from cryptography.fernet import Fernet as _Fernet212

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_app, _p9_arm, _p9_client, _p9_flashes, _p9_patch, _p9_queue,
                         _p9_restore_all)
from panel.core.config import encrypt_secret as _enc212
from panel.db.models import User as _U212, UserSession as _US212, db as _db212
from panel.ops import backup as _bk212
from panel.routes import _shared as _shr212
from panel.security import auth as _auth212
from panel.services import notifications as _notif212

_trips212 = len(_P9_TRIPPED)
_R212 = {"users": [], "ips": []}
# The fixtures' secrets, as named constants (none is a real credential).
_K212_CUR = "Argon2id!" + "Now1"
_K212_OLD = "Bcrypt256!" + "Then2"
_K212_RAW = "Bare2b!" + "Then3"
_K212_NEW = "Fresh!" + "Choice4"
_K212_WRONG = "Wrong!" + "Guess5"
_K212_BK = "backup " + "phrase 212"
_PINNED212 = "$argon2id$v=19$m=19456,t=2,p=1$"
_BOUND_MSG212 = "The encrypted backup's header asks for parameters this panel will not use."
_REUSE_MSG212 = "That is a password you have used before"


def _sha256_bcrypt212(secret):
    """The `sha256$<bcrypt>` format, byte for byte (at bcrypt's cheapest cost)."""
    digest = _b64212.b64encode(_hl212.sha256(secret.encode("utf-8")).digest())
    return "sha256$" + _bc212.hashpw(digest, _bc212.gensalt(4)).decode()


def _raw_bcrypt212(secret):
    """A bare bcrypt hash over the raw secret, the format before `sha256$`."""
    return _bc212.hashpw(secret.encode("utf-8"), _bc212.gensalt(4)).decode()


def _argon_at212(secret, m, t, p=1):
    """An Argon2id hash of `secret` at the given parameters (not the panel's)."""
    return _PH212(time_cost=t, memory_cost=m, parallelism=p, hash_len=32, salt_len=16,
                  type=_AT212.ID).hash(secret)


def _user212(name, stored, history=(), **kw):
    with _p9.app_context():
        u = _U212(username=name, password_hash=stored, display_name=name, is_active=True,
                  password_history=_json212.dumps(list(history)), **kw)
        _db212.session.add(u)
        _db212.session.commit()
        _R212["users"].append(u.id)
        return u.id


def _row212(uid):
    """(password_hash, password_history, backup_codes) of the account, or Nones."""
    with _p9.app_context():
        u = _db212.session.get(_U212, uid)
        return (u.password_hash, u.password_history, u.backup_codes) if u else (None, None, None)


def _client212(ip):
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    _R212["ips"].append(ip)
    return c


def _signed_in212(client, uid):
    with client.session_transaction() as s:
        return str(s.get("_user_id") or "").split(":")[0] == str(uid)


def _login212(name, secret, ip):
    """POST the login form; (status, signed in as someone)."""
    c = _client212(ip)
    r = c.post("/login", data={"username": name, "password": secret})
    with c.session_transaction() as s:
        return r.status_code, bool(s.get("_user_id"))


# ── 1. what a new hash is ──────────────────────────────────────────────────────────────────────
def _s212_new_hash():
    new = _auth212.hash_password(_K212_CUR)
    # Read only from an Argon2id string: anything else fails the check by name, not the part.
    params = _xp212(new) if new.startswith("$argon2id$") else None
    check("argon2: a new password hash is an Argon2id PHC string at the pinned parameters",
          params is not None and new.startswith(_PINNED212) and params.type is _AT212.ID
          and (params.memory_cost, params.time_cost, params.parallelism) == (19456, 2, 1)
          and _auth212.check_password(_K212_CUR, new)
          and not _auth212.check_password(_K212_WRONG, new), new[:40])
    check("argon2: ...and the parameters are the module's pinned values, not argon2-cffi's defaults",
          (_auth212.ARGON2_MEMORY_KIB, _auth212.ARGON2_TIME_COST, _auth212.ARGON2_PARALLELISM)
          == (19456, 2, 1) and not _auth212.needs_rehash(new))


# ── 2. the login route, for every stored format ────────────────────────────────────────────────
def _login_kind212(label, stored, n):
    """Wrong password, right password, right again — for one stored format. Returns a dict."""
    name = "p212_%s" % label
    uid = _user212(name, stored)
    out = {"wrong": _login212(name, _K212_WRONG, "198.51.100.%d" % n)}
    out["after_wrong"] = _row212(uid)[0]
    out["right"] = _login212(name, _K212_CUR, "198.51.100.%d" % (n + 1))
    out["after_right"] = _row212(uid)[0]
    out["again"] = _login212(name, _K212_CUR, "198.51.100.%d" % (n + 2))
    out["after_again"] = _row212(uid)[0]
    return out


def _s212_login():
    kinds = {
        "sha256_bcrypt": _sha256_bcrypt212(_K212_CUR),
        "raw_bcrypt": _raw_bcrypt212(_K212_CUR),
        "argon2_low": _argon_at212(_K212_CUR, 8192, 1),
    }
    for i, (kind, stored) in enumerate(kinds.items()):
        o = _login_kind212(kind, stored, 10 + 5 * i)
        check("argon2 login (%s): a wrong password signs nothing in and leaves the hash as it was" % kind,
              o["wrong"] == (200, False) and o["after_wrong"] == stored, repr(o["wrong"]))
        check("argon2 login (%s): the right password signs in and the hash is rehashed to the current "
              "Argon2id in that request" % kind,
              o["right"][1] is True and (o["after_right"] or "").startswith(_PINNED212)
              and _auth212.check_password(_K212_CUR, o["after_right"]),
              "%r %s" % (o["right"], (o["after_right"] or "")[:40]))
        check("argon2 login (%s): ...and signs in again on the new hash, which is not rehashed again" % kind,
              o["again"][1] is True and o["after_again"] == o["after_right"], repr(o["again"]))


# ── 3. a stored hash may not ask for more than four times the current cost ──────────────────────
def _s212_cost_bound():
    _user212("p212_big_m", _argon_at212(_K212_CUR, 19456 * 5, 2))
    edge = _user212("p212_edge_m", _argon_at212(_K212_CUR, 19456 * 4, 2))
    check("argon2: a stored hash asking for five times the memory, or the time, is refused even for "
          "the right password",
          _login212("p212_big_m", _K212_CUR, "198.51.100.40") == (200, False)
          and not _auth212.check_password(_K212_CUR, _argon_at212(_K212_CUR, 8192, 9)))
    check("argon2: ...while four times the memory still signs in and is rehashed down (control)",
          _login212("p212_edge_m", _K212_CUR, "198.51.100.41")[1] is True
          and (_row212(edge)[0] or "").startswith(_PINNED212))


# ── 4. a password over MAX_PASSWORD_BYTES is never hashed ──────────────────────────────────────
def _s212_length_bound():
    most = _auth212.MAX_PASSWORD_BYTES
    over = "Aa1!" + "x" * most
    at_most = "Aa1!" + "x" * (most - 4)
    over_uid = _user212("p212_over", _argon_at212(over, 8192, 1))
    most_uid = _user212("p212_atmax", _argon_at212(at_most, 8192, 1))
    with _p9.app_context():
        over_ans = _shr212.reauth_password(_db212.session.get(_U212, over_uid), over)
        most_ans = _shr212.reauth_password(_db212.session.get(_U212, most_uid), at_most)
    try:
        _auth212.hash_password(over)
        raised = None
    except ValueError as exc:
        raised = str(exc)
    check("argon2: a password one byte over MAX_PASSWORD_BYTES is a wrong password even against its "
          "own hash, and is not hashed for storage",
          most == 1024 * 1024 and over_ans == "wrong" and raised is not None,
          "reauth=%r raise=%r" % (over_ans, raised))
    check("argon2: ...while one of exactly MAX_PASSWORD_BYTES still verifies (control)",
          len(at_most.encode()) == most and most_ans == "ok", repr(most_ans))


# ── 5. the password-change route: reuse is caught across hash kinds ─────────────────────────────
def _change212(uid, new):
    c = _p9_client(uid)
    r = c.post("/account/password", data={"current_password": _K212_CUR, "new_password": new,
                                          "confirm_password": new})
    return r.status_code, " | ".join(str(m) for m in _p9_flashes(c))


def _s212_history():
    uid = _user212("p212_hist", _auth212.hash_password(_K212_CUR),
                   history=[_sha256_bcrypt212(_K212_OLD), _raw_bcrypt212(_K212_RAW)])
    before = _row212(uid)[0]
    reuse_old, reuse_raw, reuse_cur = (_change212(uid, k) for k in (_K212_OLD, _K212_RAW, _K212_CUR))
    check("argon2 history: a password whose old hash is `sha256$<bcrypt>` is refused for reuse",
          _REUSE_MSG212 in reuse_old[1], repr(reuse_old))
    check("argon2 history: ...and one whose old hash is a bare bcrypt", _REUSE_MSG212 in reuse_raw[1],
          repr(reuse_raw))
    check("argon2 history: ...and the current password, an Argon2id hash",
          _REUSE_MSG212 in reuse_cur[1] and _row212(uid)[0] == before, repr(reuse_cur))
    fresh = _change212(uid, _K212_NEW)
    after, history, _codes = _row212(uid)
    check("argon2 history: a new password is stored as the current Argon2id, and the Argon2id hash it "
          "replaced heads the history",
          _REUSE_MSG212 not in fresh[1] and (after or "").startswith(_PINNED212)
          and _auth212.check_password(_K212_NEW, after)
          and _json212.loads(history or "[]")[:1] == [before], repr(fresh))


# ── 6. 2FA backup codes through the login's second step ────────────────────────────────────────
def _code212(uid, code, n):
    """Answer the 2FA prompt with `code`; True if that signed the account in."""
    c = _client212("198.51.100.%d" % n)
    with c.session_transaction() as s:
        s["_2fa_pending"] = uid
        s["_2fa_at"] = _time212.time()
    c.post("/login", data={"totp_code": code})
    return _signed_in212(c, uid)


def _s212_backup_codes():
    uid = _user212("p212_codes", _auth212.hash_password(_K212_CUR), totp_enabled=True,
                   totp_secret=_enc212(_pyotp212.random_base32()))
    new_code, old_code = "abcde-fghjk", "mnpqr-stuvw"
    with _p9.app_context():
        u = _db212.session.get(_U212, uid)
        u.set_backup_codes([new_code])
        stored = _json212.loads(u.backup_codes)
        # One code as the panel stored it before Argon2id: bcrypt over the normalised code.
        u.backup_codes = _json212.dumps(stored + [_raw_bcrypt212(old_code.replace("-", ""))])
        _db212.session.commit()
    check("argon2 backup codes: a new code is stored as an Argon2id hash at the pinned parameters",
          len(stored) == 1 and stored[0].startswith(_PINNED212), repr(stored))
    seen = [_code212(uid, c, 60 + i) for i, c in enumerate(("zzzzz-zzzzz", new_code, new_code,
                                                            old_code, old_code))]
    check("argon2 backup codes: a wrong code is refused, an Argon2id code signs in once and is spent",
          seen[:3] == [False, True, False], repr(seen))
    check("argon2 backup codes: ...and a bcrypt code from before signs in once and is spent too",
          seen[3:] == [True, False] and _row212(uid)[2] == "[]", "%r %r" % (seen, _row212(uid)[2]))


# ── 7. backups: the KDF parameters, old archives, crafted headers, off the hub ──────────────────
_BK_NAMES212 = ("BACKUP_DIR", "DATA_DIR", "DB_PATH", "CONFIG_FILE", "SECRET_FILE", "CRED_KEY_FILE")


def _bk_setup212(tmp):
    _bk212.BACKUP_DIR = tmp / "backups"
    _bk212.DATA_DIR = tmp
    _bk212.DB_PATH = tmp / "panel.db"
    _bk212.CONFIG_FILE = tmp / "config.json"
    _bk212.SECRET_FILE = tmp / "secret_key"
    _bk212.CRED_KEY_FILE = tmp / "cred_key"
    con = _sq212.connect(str(_bk212.DB_PATH))
    with con:
        con.execute("CREATE TABLE t (v INTEGER)")
    con.close()
    _bk212.CONFIG_FILE.write_text("{}")
    _bk212.SECRET_FILE.write_text("s")
    _bk212.CRED_KEY_FILE.write_text("k")


def _enc_file212(name, n, payload):
    """Write an archive in the panel's format at scrypt `n` (r=8, p=1); its path under BACKUP_DIR.

    `payload` is the plain archive's bytes, encrypted under the fixture passphrase, or a ready
    token (bytes starting b"not-") written as it is.
    """
    salt = _os212.urandom(16)
    head = _json212.dumps({"kdf": "scrypt", "n": n, "r": 8, "p": 1,
                           "salt": _b64212.b64encode(salt).decode()}).encode()
    token = payload if payload.startswith(b"not-") else \
        _Fernet212(_bk212._derive_key(_K212_BK, salt, n=n, r=8, p=1)).encrypt(payload)
    path = _bk212.BACKUP_DIR / name
    path.write_bytes(_bk212._ENC_MAGIC + head + b"\n" + token)
    return path


def _opens212(path, phrase=_K212_BK):
    """(opened, refusal): decrypt as the restore does and read the archive's members."""
    tmp, plain, refusal = _bk212._decrypt_for_restore(path, phrase)
    if tmp is None:
        return False, refusal
    try:
        with _tar212.open(str(plain), "r:gz") as tar:
            return "panel.db" in tar.getnames(), ""
    finally:
        _sh212.rmtree(tmp, ignore_errors=True)


def _s212_backup_new_and_old():
    ok, name = _bk212.create_backup("manual", passphrase=_K212_BK)
    plain_ok, plain_name = _bk212.create_backup("plain", passphrase="")  # nosec B106 - in the clear
    path = _bk212.BACKUP_DIR / name if ok else _bk212.BACKUP_DIR / "none"
    head = {}
    if ok:
        head = _json212.loads(path.read_bytes()[len(_bk212._ENC_MAGIC):].split(b"\n", 1)[0])
    check("backup kdf: a new encrypted archive's header records scrypt N=2^17, r=8, p=1",
          ok and (head.get("kdf"), head.get("n"), head.get("r"), head.get("p")) == ("scrypt", 2 ** 17, 8, 1),
          repr(head))
    check("backup kdf: ...and the restore's decrypt opens it with the passphrase, and not without it",
          ok and _opens212(path) == (True, "") and not _opens212(path, _K212_WRONG)[0])
    plain = (_bk212.BACKUP_DIR / plain_name).read_bytes() if plain_ok else b""
    old = _enc_file212("panel-backup-20260101-000000-manual.tar.gz.enc", 2 ** 15, plain)
    check("backup kdf: an archive written at the old N=2^15 still opens",
          plain_ok and _opens212(old) == (True, ""), repr(_opens212(old)))


def _s212_backup_crafted():
    derived = []
    real = _bk212._scrypt
    _bk212._scrypt = lambda *a: derived.append(a[2]) or real(*a)
    try:
        crafted = _enc_file212("panel-backup-20260101-000001-manual.tar.gz.enc", 2 ** 19,
                               b"not-a-real-token")
        ans = _bk212._restore_backup_locked(crafted.name, _K212_BK)
    finally:
        _bk212._scrypt = real
    check("backup kdf: a crafted header asking for N=2^19 is refused by the restore before any key "
          "is derived", ans == (False, _BOUND_MSG212) and derived == [], "%r derived=%r" % (ans, derived))
    # Off the hub: under a monkey-patched runtime the derivation goes through tpool.
    calls = []
    saved = (_patcher212.is_monkey_patched, _tpool212.execute)
    _patcher212.is_monkey_patched = lambda name: True
    _tpool212.execute = lambda fn, *a: calls.append(fn) or fn(*a)
    try:
        key = _bk212._derive_key(_K212_BK, b"s" * 16, n=2 ** 12, r=8, p=1)
    finally:
        _patcher212.is_monkey_patched, _tpool212.execute = saved
    check("backup kdf: the scrypt derivation runs through tpool under eventlet",
          calls == [_bk212._scrypt] and len(_b64212.urlsafe_b64decode(key)) == 32, repr(calls))


def _s212_backups():
    saved = {k: getattr(_bk212, k) for k in _BK_NAMES212}
    tmp = _pl212.Path(_tf212.mkdtemp(prefix="p212-bk-"))
    try:
        _bk_setup212(tmp)
        _s212_backup_new_and_old()
        _s212_backup_crafted()
    finally:
        for k, v in saved.items():
            setattr(_bk212, k, v)
        _sh212.rmtree(tmp, ignore_errors=True)


def _cleanup212():
    with _p9_app._LOGIN_FAILS_LOCK:
        for ip in _R212["ips"]:
            _p9_app._LOGIN_FAILS.pop(_auth212.throttle_key(ip), None)
    with _shr212._REAUTH_LOCK:
        for uid in _R212["users"]:
            _shr212._REAUTH_FAILS.pop(uid, None)
    with _p9.app_context():
        for uid in _R212["users"]:
            _US212.query.filter_by(user_id=uid).delete(synchronize_session=False)
            u = _db212.session.get(_U212, uid)
            if u is not None:
                _db212.session.delete(u)
        _db212.session.commit()
    _p9_queue.clear()


# ── 8. the absolute session lifetime (OWASP Session Management, "Absolute Timeout") ───────────────
def _aged212(uid, hours, remember=False):
    """Make the user's one session row `hours` old (signed in then) but active a minute ago."""
    from datetime import timedelta as _td212
    with _p9.app_context():
        row = _US212.query.filter_by(user_id=uid).first()
        if row is None:
            return False
        from panel.core import clock as _clock212
        now = _clock212.utcnow()
        row.created_at, row.last_seen, row.remember = now - _td212(hours=hours), now - _td212(minutes=1), remember
        _db212.session.commit()
        return True


def _s212_absolute():
    from panel.db import models as _models212
    plain, remember = _models212.session_absolute_limits()
    check("session: a plain login ends 8 hours after sign-in (OWASP's full-day absolute timeout), a remember-me "
          "login after its 3-day cookie, however active either is",
          (plain, remember) == (8 * 3600.0, 3 * 86400.0), repr((plain, remember)))
    from datetime import timedelta as _tdl212
    results, saved = {}, {k: _p9.config.get(k) for k in ("PERMANENT_SESSION_LIFETIME", "REMEMBER_COOKIE_DURATION")}
    # The shipped defaults (8 h idle, 3-day remember-me): the test app's own windows are longer, and an
    # idle window longer than 8 h raises the absolute limit with it (session_absolute_limits).
    _p9.config.update(PERMANENT_SESSION_LIFETIME=8 * 3600, REMEMBER_COOKIE_DURATION=_tdl212(days=3))
    try:
        _absolute_runs212(results)
    finally:
        _p9.config.update(saved)
    _absolute_checks212(results)


def _absolute_runs212(results):
    for label, hours, rem in (("7h", 7, False), ("9h", 9, False), ("rem-2d", 48, True), ("rem-4d", 96, True)):
        name = "p212_abs_%s" % label.replace("-", "")
        uid = _user212(name, _auth212.hash_password(_K212_CUR))
        c = _client212("198.51.100.%d" % (60 + len(results)))
        c.post("/login", data={"username": name, "password": _K212_CUR})
        aged = _aged212(uid, hours, rem)
        r = c.get("/")
        with _p9.app_context():
            left = _US212.query.filter_by(user_id=uid).count()
        results[label] = (aged, r.status_code, left)


def _absolute_checks212(results):
    check("session: an active login signed in 7 hours ago still works; at 9 hours the server ends it (the page "
          "asks for a sign-in) and drops the session row",
          results["7h"] == (True, 200, 1) and results["9h"][0] is True and results["9h"][1] in (302, 401)
          and results["9h"][2] == 0, repr(results))
    check("session: a remember-me login signed in 2 days ago still works; at 4 days it ends the same way",
          results["rem-2d"] == (True, 200, 1) and results["rem-4d"][0] is True
          and results["rem-4d"][1] in (302, 401) and results["rem-4d"][2] == 0, repr(results))


# ── 9. __Host- cookies when the login cookies are Secure (OWASP Session Management) ──────────────
def _s212_host_prefix():
    from flask import Flask as _Flask212, session as _fsession212
    names = {}
    for secure in (True, False):
        app = _Flask212("unit_part212_cookies_%s" % secure)
        app.config.update(SECRET_KEY="k" * 32, SESSION_COOKIE_NAME="lgpanel_session", SESSION_COOKIE_SECURE=secure,
                          REMEMBER_COOKIE_SECURE=secure, SESSION_COOKIE_DOMAIN="example.invalid")
        _auth212._host_prefix_cookies(app)
        app.session_interface = _auth212._session_cookie.ThrottledCookieSessions()

        @app.route("/set")
        def _set212():
            _fsession212["x"] = 1
            return "ok"
        hdr = app.test_client().get("/set", base_url="https://panel.invalid").headers.get("Set-Cookie", "")
        names[secure] = (app.config["SESSION_COOKIE_NAME"], app.config.get("REMEMBER_COOKIE_NAME"), hdr)
    sec_hdr = names[True][2]
    check("cookies: over HTTPS (Secure cookies) the login cookies are __Host-lgpanel_session and "
          "__Host-remember_token, sent Secure with Path=/ and no Domain",
          names[True][:2] == ("__Host-lgpanel_session", "__Host-remember_token")
          and sec_hdr.startswith("__Host-lgpanel_session=") and "Secure" in sec_hdr and "Path=/" in sec_hdr
          and "Domain=" not in sec_hdr, repr(names[True]))
    via = _Flask212("unit_part212_cookies_init_auth")
    via.config.update(SECRET_KEY="k" * 32, SESSION_COOKIE_NAME="lgpanel_session", SESSION_COOKIE_SECURE=True,
                      REMEMBER_COOKIE_SECURE=True)
    _auth212.init_auth(via)
    check("cookies: init_auth itself (the app factory's call) gives a Secure panel the __Host- names",
          (via.config["SESSION_COOKIE_NAME"], via.config.get("REMEMBER_COOKIE_NAME"))
          == ("__Host-lgpanel_session", "__Host-remember_token"),
          repr((via.config["SESSION_COOKIE_NAME"], via.config.get("REMEMBER_COOKIE_NAME"))))
    check("cookies: ...while an install served over plain HTTP keeps the plain names",
          names[False][0] == "lgpanel_session" and not str(names[False][1] or "").startswith("__Host-"),
          repr(names[False][:2]))


# ── 10. the self-signed fallback certificate (OWASP Transport Layer Security) ────────────────────
def _old_rsa_cert212(cert_path, key_path):
    """Write a pre-change certificate: RSA-2048, ten years."""
    import datetime as _dtc212
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "old.invalid")])
    start = _dtc212.datetime.now(_dtc212.timezone.utc)
    cert = (_x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(_x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start + _dtc212.timedelta(days=3650)).sign(key, _hashes.SHA256()))
    _os212.makedirs(_os212.path.dirname(cert_path), exist_ok=True)
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(_ser.Encoding.PEM))


def _s212_cert():
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from panel.services import certs as _certs212
    tmp = _tf212.mkdtemp(prefix="p212-cert-")
    try:
        cp, kp = _os212.path.join(tmp, "ssl", "cert.pem"), _os212.path.join(tmp, "ssl", "key.pem")
        _old_rsa_cert212(cp, kp)
        _certs212._ensure_self_signed_cert(cp, kp, "panel.invalid")
        with open(cp, "rb") as fh:
            new = _x509.load_pem_x509_certificate(fh.read())
        days = (new.not_valid_after_utc - new.not_valid_before_utc).days
        key = new.public_key()
        check("tls: the fallback certificate is ECDSA P-256 / SHA-256 for about 397 days, and an older RSA one "
              "(ten years) is replaced at the next start",
              isinstance(key, _ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
              and new.signature_hash_algorithm.name == "sha256" and 396 <= days <= 399, repr((type(key), days)))
        serial = new.serial_number
        _certs212._ensure_self_signed_cert(cp, kp, "panel.invalid")
        with open(cp, "rb") as fh:
            again = _x509.load_pem_x509_certificate(fh.read())
        check("tls: ...while a current ECDSA certificate is kept as it is (no new one at every start)",
              again.serial_number == serial)
    finally:
        _sh212.rmtree(tmp, ignore_errors=True)


try:
    _p9_arm(who="part212")
    _p9_patch(_notif212, "notify", lambda *a, **k: None)
    _s212_new_hash()
    _s212_login()
    _s212_cost_bound()
    _s212_length_bound()
    _s212_history()
    _s212_backup_codes()
    _s212_backups()
    _s212_absolute()
    _s212_host_prefix()
    _s212_cert()
finally:
    _p9_restore_all()
    _cleanup212()

check("part212: nothing it drove reached a real transport",
      len(_P9_TRIPPED) == _trips212, repr(_P9_TRIPPED[_trips212:][:6]))
