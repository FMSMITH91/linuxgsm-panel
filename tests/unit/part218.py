"""Part 218 of the unit suite: alerts on a user's own devices (Web Push).

* The crypto: RFC 8291's aes128gcm payload byte for byte against Appendix A's test vector, a fresh
  message decrypted the way a browser does, and the VAPID token (RFC 8292): its claims, a raw ES256
  signature that verifies, checked with a verifier that also accepts the RFC's own example token.
* Where a push may go (OWASP SSRF Prevention): only the real push services' hosts, https on 443, the
  resolved address public (no private, loopback, link-local, tailnet, metadata), re-checked at send.
* The routes: subscribe (step-up, validation, the device cap, keys and endpoint encrypted at rest),
  turn off, remove (own rows only), the rate-limited test alert, the alert choices, CSRF/Fetch Metadata.
* Who gets what, decided at send time: server events to who can access the server, panel-wide ones
  to superadmins, each user's own choice, account changes to that account; access removed,
  deactivated or deleted gets nothing; 404/410 removes the device; the text carries no address.
* Sign-out: alerts kept (Clear-Site-Data "cookies" only) or stopped (the row gone, storage cleared).
Every route runs on part12's app with its transport tripwire armed; the push POST itself is stubbed.
"""
import base64 as _b64_218
import hashlib as _hl218
import json as _json218
import logging as _logging218
import os as _os218
import time as _time218
from types import SimpleNamespace as _NS218

from cryptography.exceptions import InvalidTag as _InvalidTag218
from cryptography.hazmat.primitives import hashes as _h218
from cryptography.hazmat.primitives.asymmetric import ec as _ec218
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as _dss218
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _GCM218
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF218

from unit import REPO_ROOT
from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_OTHER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_drain,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_threading, _P9Thread)
from panel.db.models import AuditLog as _AL218, Group as _G218, PushSubscription as _PS218, User as _U218
from panel.db.models import db as _db218
from panel.security import auth as _auth218
from panel.services import notifications as _nt218, push_alerts as _pa218, webpush as _wp218

_trips218 = len(_P9_TRIPPED)
_REAL_POST218 = _wp218._post             # the real POST, for the checks of what happens before any socket
_IDS218 = []
_K218 = "orchard lantern pebble"          # the fixtures' password (no real credential)
_d218 = _wp218.b64url_decode


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────
def _user218(name, superadmin=False, servers=(), hosts=()):
    """A fresh active account, granted these game servers / hosts through its own group; its id."""
    with _p9.app_context():
        u = _U218(username=name, password_hash=_auth218.hash_password(_K218), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        if servers or hosts:
            from panel.db.models import GameServer, RemoteServer
            grp = _G218(name="p218-" + name, description="", is_default=False)
            grp.set_permissions([_auth218.VIEW_SERVERS])
            for sid in servers:
                grp.game_servers.append(_db218.session.get(GameServer, sid))
            for rid in hosts:
                grp.servers.append(_db218.session.get(RemoteServer, rid))
            _db218.session.add(grp)
            u.groups.append(grp)
        _db218.session.add(u)
        _db218.session.commit()
        _IDS218.append(u.id)
        return u.id


def _browser218(n):
    """A stand-in browser: its P-256 key, auth secret and the subscription JSON it would post."""
    key = _ec218.generate_private_key(_ec218.SECP256R1())
    auth = bytes([n % 256]) * 16
    sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/p218-%d-%s" % (n, "x" * 40),
           "keys": {"p256dh": _wp218.b64url(_wp218.public_raw(key)), "auth": _wp218.b64url(auth)}}
    return _NS218(key=key, auth=auth, sub=sub)


def _decrypt218(body, ua_key, auth):
    """What a browser does with a push body (RFC 8291 3.4, the receiver's side); the plaintext."""
    salt, idlen = body[:16], body[20]
    as_pub = body[21:21 + idlen]
    ua_pub = _wp218.public_raw(ua_key)
    secret = ua_key.exchange(_ec218.ECDH(), _ec218.EllipticCurvePublicKey.from_encoded_point(_ec218.SECP256R1(), as_pub))

    def kdf(s, ikm, info, n):
        return _HKDF218(algorithm=_h218.SHA256(), length=n, salt=s, info=info).derive(ikm)
    ikm = kdf(auth, secret, b"WebPush: info\x00" + ua_pub + as_pub, 32)
    try:
        plain = _GCM218(kdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)).decrypt(
            kdf(salt, ikm, b"Content-Encoding: nonce\x00", 12), body[21 + idlen:], None)
    except _InvalidTag218:   # wrong keys or labels: a failed check by name, never a crash of the part
        return b"<undecryptable>"
    return plain[:-1] if plain.endswith(b"\x02") else b"<no delimiter>"


def _jwt_ok218(token, pub_raw):
    """Whether `token` is an ES256 JWT whose raw r||s signature verifies under the P-256 key `pub_raw`."""
    head, body, sig = token.split(".")
    raw = _d218(sig)
    if raw is None or len(raw) != 64:
        return False
    pub = _ec218.EllipticCurvePublicKey.from_encoded_point(_ec218.SECP256R1(), pub_raw)
    try:
        pub.verify(_dss218(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   (head + "." + body).encode("ascii"), _ec218.ECDSA(_h218.SHA256()))
    except Exception:  # noqa: BLE001 - InvalidSignature: the answer is "no"
        return False
    return True


def _aud218(header):
    """The aud claim of the token in a `vapid t=<jwt>, k=<key>` header, or None."""
    try:
        return _claims218(header[len("vapid t="):].split(",")[0]).get("aud")
    except (ValueError, IndexError, TypeError):
        return None


def _claims218(token):
    part = token.split(".")[1]
    return _json218.loads(_b64_218.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _payload218(raw):
    """A push payload as a dict; {"unreadable": ...} when it is not JSON (so a check fails by name)."""
    try:
        return _json218.loads(raw)
    except ValueError:
        return {"unreadable": raw[:40].decode("latin-1")}


class _Pusher218:
    """webpush._post's stand-in: records each POST; answers `status` (or per-target from `by_target`)."""

    def __init__(self, status=201):
        self.sent, self.status, self.by_target = [], status, {}

    def __call__(self, host, target, headers, body):
        self.sent.append(_NS218(host=host, target=target, headers=dict(headers), body=body))
        return self.by_target.get(target, self.status)

    def to(self, browser):
        """The decrypted payloads that reached `browser`, as dicts."""
        target = browser.sub["endpoint"].split("fcm.googleapis.com", 1)[1]
        return [_payload218(_decrypt218(s.body, browser.key, browser.auth)) for s in self.sent
                if s.target == target]


class _Said218(_logging218.Handler):
    """Every record that reaches it, at WARNING and up (the journal's own threshold)."""

    def __init__(self):
        """Collect at WARNING, as errors.StderrHandler does."""
        super().__init__(level=30)
        self.records = []

    def emit(self, record):
        """Keep the record."""
        self.records.append(record)


def _journal218(run):
    """The "subscription removed" records `run()` sends to the loggers the journal's handler is put on."""
    from panel.ops.debug_report import errors as _err218
    said = _Said218()
    journal = [_logging218.getLogger(n) for n in _err218.LOGGERS]
    for lg in journal:
        lg.addHandler(said)
    try:
        run()
    finally:
        for lg in journal:
            lg.removeHandler(said)
    return [r for r in said.records if "subscription removed" in r.getMessage()]


def _line218(record, hidden):
    """(level, logger, message up to its note, whether any of `hidden` is in it) for one record."""
    msg = record.getMessage()
    return record.levelname, record.name, msg.split(" (")[0], any(x in msg for x in hidden)


def _rig218(status=201):
    """Stub the push POST and run the sender's thread inline (part12's queued threads); the stand-in."""
    pusher = _Pusher218(status)
    _p9_patch(_wp218, "_post", pusher)
    _p9_patch(_pa218, "threading", _p9_threading(_P9Thread))
    _p9_patch(_pa218, "_APP", [_p9])
    # The panel-wide channels are off in this config; their queue is recorded, never sent.
    _p9_patch(_nt218, "_queue_alert", lambda item: None)
    _pa218.reset_tests()
    return pusher


def _subscribe218(uid, browser):
    r = _p9_client(uid).post("/account/push/subscribe", json=browser.sub)
    return r.status_code, _p9_json(r)


def _rows218(uid):
    with _p9.app_context():
        return _PS218.query.filter_by(user_id=uid).count()


def _audit218(action, since=0):
    with _p9.app_context():
        return [(r.username, r.target, r.detail) for r in
                _AL218.query.filter(_AL218.action == action, _AL218.id > since).order_by(_AL218.id).all()]


def _last218():
    with _p9.app_context():
        r = _AL218.query.order_by(_AL218.id.desc()).first()
        return r.id if r else 0


# ── 1. the crypto ────────────────────────────────────────────────────────────────────────────────
def _s218_rfc8291_vector():
    as_priv = _wp218._private_from_raw(_d218("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
    ua_pub = _d218("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
    out = _wp218.encrypt(b"When I grow up, I want to be a watermelon", ua_pub, _d218("BTBZMqHH6r4Tts7J_aSIgg"),
                         salt=_d218("DGv6ra1nlYgDCS1FRnbzlw"), as_private=as_priv)
    want = ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK"
            "6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
    eq("web push: the aes128gcm body is RFC 8291 Appendix A's, byte for byte (86-octet header + ciphertext)",
       _wp218.b64url(out), want)
    b = _browser218(7)
    sent = _wp218.encrypt(b"hello device", _d218(b.sub["keys"]["p256dh"]), b.auth)
    again = _wp218.encrypt(b"hello device", _d218(b.sub["keys"]["p256dh"]), b.auth)
    check("web push: a real message decrypts the way a browser decrypts it, with a fresh salt and key each time",
          _decrypt218(sent, b.key, b.auth) == b"hello device" and sent[:16] != again[:16]
          and sent[21:86] != again[21:86], repr(sent[:24]))
    refused = []
    for bad in (b"\x04" + b"\x01" * 64, b"\x04" * 10):
        try:
            _wp218.encrypt(b"x", bad, b.auth)
        except ValueError:
            refused.append(True)
    eq("web push: a browser key that is not a point on P-256 is refused", refused, [True, True])


def _s218_vapid():
    # RFC 8292 2.4's own example: the verifier below accepts a token the RFC published.
    rfc_example = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0"
                 "NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2"
                 "rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA")
    rfc_key = _d218("BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs")
    check("vapid: the verifier accepts RFC 8292's example token (so it checks the real format)",
          _jwt_ok218(rfc_example, rfc_key), "")
    key = _wp218.vapid_key()
    now = 1_900_000_000
    tok = _wp218.vapid_token(key, "https://fcm.googleapis.com", now)
    claims = _claims218(tok)
    check("vapid: the token is ES256 with a raw 64-byte r||s signature that verifies under the panel's key",
          _jwt_ok218(tok, _wp218.public_raw(key)), tok[:60])
    check("vapid: aud is the push service's origin, exp at most 24 hours ahead, sub an https: contact",
          claims.get("aud") == "https://fcm.googleapis.com" and now < claims.get("exp", 0) <= now + 24 * 3600
          and str(claims.get("sub", "")).startswith("https://"), repr(claims))
    hdr = _wp218.vapid_authorization(key, "web.push.apple.com", now)
    k = hdr.rpartition("k=")[2]
    check("vapid: the Authorization header is 'vapid t=<jwt>, k=<the 65-byte public key>'",
          hdr.startswith("vapid t=") and ", k=" in hdr and _d218(k) == _wp218.public_raw(key)
          and _claims218(hdr[8:hdr.index(",")])["aud"] == "https://web.push.apple.com", hdr[:80])
    with _p9.app_context():
        from panel.core.config import load_config
        stored = (load_config().get("push") or {})
    check("vapid: the private key is stored encrypted, and made once (the same key every call)",
          str(stored.get("vapid_private", "")).startswith("enc:")
          and _wp218.public_raw(_wp218.vapid_key()) == _wp218.public_raw(key)
          and stored.get("vapid_public") == _wp218.vapid_public_key(), repr(sorted(stored)))


# ── 2. where a push may go ───────────────────────────────────────────────────────────────────────
_OK218 = ("https://fcm.googleapis.com/fcm/send/abc:DEF_1-2", "https://fcm.googleapis.com:443/wp/x",
          "https://updates.push.services.mozilla.com/wpush/v2/gAAAA", "https://web.push.apple.com/QH1",
          "https://wns2-par02p.notify.windows.com/w/?token=AbC%2b")
_BAD218 = ("http://fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x", "https://evil.example@fcm.googleapis.com/x",
           "https://fcm.googleapis.com.evil.example/x", "https://push.apple.com/x", "https://evilpush.apple.com/x",
           "https://fcm.googleapis.com/x#frag", "https://fcm.googleapis.com\\@evil/x", "https://127.0.0.1/x",
           "https://FCM.googleapis.com/x", "https://fcm.googleapis.com", "https://notify.windows.com/x",
           "https://fcm.googleapis.com/" + "a" * 1100, None, 5)


def _s218_endpoints():
    eq("ssrf: the real push services' endpoints are accepted",
       [bool(_wp218.parse_endpoint(u)) for u in _OK218], [True] * len(_OK218))
    eq("ssrf: anything else is refused: http, another port, userinfo, a look-alike host, a fragment, "
       "a backslash, an address, no path, too long",
       [_wp218.parse_endpoint(u) for u in _BAD218], [None] * len(_BAD218))
    eq("ssrf: the request is rebuilt from the parts that matched (host, path + query)",
       _wp218.parse_endpoint(_OK218[4]), ("wns2-par02p.notify.windows.com", "/w/?token=AbC%2b", "windows"))
    public = ("142.250.1.1", "2607:f8b0:4004::1")
    refused = ("10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.100.100.100",
               "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fd7a:115c:a1e0::1",  # nosec B104 - addresses the check refuses, no bind
               "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe", "2002:a00:1::", "ff02::1", "192.0.2.1", "::7f00:1", "::a00:1", "::8.8.8.8", "not an address")
    eq("ssrf: a public address may be connected to", [_wp218.address_refused(a) for a in public], [False, False])
    eq("ssrf: private, loopback, link-local/metadata, tailnet, multicast, reserved, and an IPv4 inside an IPv6 "
       "form are refused", [_wp218.address_refused(a) for a in refused], [True] * len(refused))


def _s218_send_guard():
    import socket
    connects, posts = [], []
    b = _browser218(9)
    p256, auth = _d218(b.sub["keys"]["p256dh"]), b.auth
    _p9_patch(_wp218, "_post", _REAL_POST218)

    def _no_connect(infos, timeout, src):
        connects.append(infos)
        raise OSError("part218: no connection is ever made")
    _p9_patch(_nt218, "_connect_infos", _no_connect)
    _p9_patch(_wp218, "_resolve", lambda host: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))])
    out_private = _wp218.send(b.sub["endpoint"], p256, auth, b"{}", 60)
    _p9_patch(_wp218, "_resolve", lambda host: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.1.1", 443)),
                                                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))])
    out_mixed = _wp218.send(b.sub["endpoint"], p256, auth, b"{}", 60)
    eq("ssrf: at send time, a push service name resolving to a private (or partly loopback) address is refused "
       "before any connection", (out_private, out_mixed, connects), ((-2, "fcm"), (-2, "fcm"), []))
    _p9_patch(_wp218, "_post", lambda *a: posts.append(a) or 201)
    out_bad = _wp218.send("https://internal.example/hook", p256, auth, b"{}", 60)
    eq("ssrf: an endpoint that is not a push service's is refused at send time too, with nothing posted",
       (out_bad, posts), ((-1, "?"), []))
    pusher = _Pusher218(201)
    _p9_patch(_wp218, "_post", pusher)
    out = _wp218.send(b.sub["endpoint"], p256, auth, b'{"title":"t"}', 600, "high")
    s = pusher.sent[0] if pusher.sent else _NS218(host="", target="", headers={}, body=b"")
    eq("web push: a send posts to the push service's host with TTL, Urgency, aes128gcm, a VAPID token for that "
       "origin, and a body only the browser can read",
       (out, s.host, s.target[:len("/fcm/send/p218-9-")], s.headers.get("TTL"), s.headers.get("Urgency"),
        s.headers.get("Content-Encoding"), _aud218(s.headers.get("Authorization", "")),
        _decrypt218(s.body, b.key, b.auth) if s.body else b""),
       ((201, "fcm"), "fcm.googleapis.com", "/fcm/send/p218-9-", "600", "high", "aes128gcm",
        "https://fcm.googleapis.com", b'{"title":"t"}'))


# ── 3. the routes ────────────────────────────────────────────────────────────────────────────────
def _s218_subscribe_route():
    uid = _user218("p218_sub")
    b = _browser218(1)
    anon = _p9.test_client().post("/account/push/subscribe", json=b.sub)
    c = _p9_client(uid)
    with c.session_transaction() as s:
        s["_auth_at"] = _time218.time() - 3600
        s.permanent = True
    stale = c.post("/account/push/subscribe", json=b.sub, headers={"X-Requested-With": "XMLHttpRequest"})
    eq("subscribe: needs a signed-in account, and a recent password confirmation (step-up), storing nothing "
       "otherwise", (anon.status_code in (302, 401), stale.status_code, _p9_json(stale).get("error"), _rows218(uid)),
       (True, 403, "reauth_required", 0))
    bad = []
    for sub in (dict(b.sub, endpoint="https://192.0.2.7/push"), dict(b.sub, endpoint="http://fcm.googleapis.com/x"),
                {"endpoint": b.sub["endpoint"], "keys": {"p256dh": "AAAA", "auth": b.sub["keys"]["auth"]}},
                {"endpoint": b.sub["endpoint"], "keys": {"p256dh": b.sub["keys"]["p256dh"], "auth": "AAAA"}}, []):
        r = _p9_client(uid).post("/account/push/subscribe", json=sub)
        bad.append(r.status_code)
    eq("subscribe: an endpoint that is no push service's, or keys that are not a P-256 point and 16 bytes, are "
       "refused (400) and nothing is stored", (bad, _rows218(uid)), ([400] * 5, 0))
    since = _last218()
    code, body = _subscribe218(uid, b)
    with _p9.app_context():
        from sqlalchemy import Text, select, type_coerce
        t = _PS218.__table__
        raw = _db218.session.execute(select(*(type_coerce(t.c[n], Text) for n in ("endpoint", "p256dh", "auth")),
                                            t.c.endpoint_hash).where(t.c.user_id == uid)).first()
    eq("subscribe: stored, with the endpoint and both browser keys encrypted at rest and found by the "
       "endpoint's SHA-256", (code, body.get("success"), [str(v)[:4] for v in (raw or ())[:3]], (raw or [0] * 4)[3]),
       (200, True, ["enc:"] * 3, _hl218.sha256(b.sub["endpoint"].encode()).hexdigest()))
    rows = _audit218("push_subscribe", since)
    eq("subscribe: audited as push_subscribe naming the device, never its endpoint or keys",
       [(r[1], "fcm" in r[2] or b.sub["keys"]["auth"] in r[2]) for r in rows], [("p218_sub", False)])
    _subscribe218(uid, b)
    eq("subscribe: the same browser again refreshes its row rather than adding one", _rows218(uid), 1)


def _s218_takeover():
    owner, other, heir = _user218("p218_own_e"), _user218("p218_thief"), _user218("p218_heir")
    b = _browser218(160)
    _subscribe218(owner, b)
    since = _last218()
    forged = _NS218(sub={"endpoint": b.sub["endpoint"], "keys": _browser218(161).sub["keys"]})   # the URL only
    code, body = _subscribe218(other, forged)
    with _p9.app_context():
        rows = [(r.success, r.detail) for r in _AL218.query.filter(_AL218.action == "push_subscribe",
                                                                     _AL218.id > since).all()]
    eq("takeover: another account posting an endpoint it knows, with keys it made up, is refused (409, in plain "
       "words); the owner keeps the device; the refusal is audited without the endpoint",
       (code, body.get("message", "")[:44], _rows218(owner), _rows218(other),
        [(ok, "refused" in d, "fcm" in d or "p218-160" in d) for ok, d in rows]),
       (409, "This browser's alerts belong to another acco", 1, 0, [(False, True, False)]))
    code2, _b2 = _subscribe218(other, b)
    eq("takeover: ...the same browser's own subscription (its keys match the stored ones) moves to the account "
       "turning alerts on there", (code2, _rows218(owner), _rows218(other)), (200, 0, 1))
    with _p9.app_context():           # its holder deactivated (rows kept, as a direct write could leave them)
        u = _db218.session.get(_U218, other)
        u.is_active = False
        _db218.session.commit()
    code3, _b3 = _subscribe218(heir, _NS218(sub={"endpoint": b.sub["endpoint"], "keys": _browser218(162).sub["keys"]}))
    eq("takeover: an endpoint held by a deactivated account may be taken over", (code3, _rows218(heir)), (200, 1))
    with _p9.app_context():           # its holder gone (a row pointing at no account)
        _r = _PS218.query.filter_by(user_id=heir).first()
        if _r is not None:            # absent only when an earlier step already failed by name
            _r.user_id = 987654
            _db218.session.commit()
    code4, _b4 = _subscribe218(owner, _NS218(sub={"endpoint": b.sub["endpoint"], "keys": _browser218(163).sub["keys"]}))
    eq("takeover: ...and so may one whose account no longer exists", (code4, _rows218(owner)), (200, 1))


def _s218_device_cap():
    uid = _user218("p218_cap")
    codes = [_subscribe218(uid, _browser218(100 + i))[0] for i in range(_pa218.DEVICE_MAX)]
    code, body = _subscribe218(uid, _browser218(150))
    check("subscribe: an account holds at most %d devices; one more is refused with what to do"
          % _pa218.DEVICE_MAX, codes == [200] * _pa218.DEVICE_MAX and code == 400
          and "Remove one first" in body.get("message", "") and _rows218(uid) == _pa218.DEVICE_MAX,
          repr((codes, code, body)))


def _s218_remove_and_off():
    a, other = _user218("p218_own"), _user218("p218_other")
    ba, bo = _browser218(21), _browser218(22)
    _subscribe218(a, ba)
    _subscribe218(other, bo)
    with _p9.app_context():
        other_row = _PS218.query.filter_by(user_id=other).first().id
        own_row = _PS218.query.filter_by(user_id=a).first().id
    cross = _p9_client(a).post("/account/push/devices/%d/remove" % other_row)
    cross_off = _p9_client(a).post("/account/push/unsubscribe", json={"endpoint": bo.sub["endpoint"]})
    check("devices: one account can neither remove nor turn off another's device (looked up by id AND owner)",
          _rows218(other) == 1 and cross.status_code == 302 and cross_off.status_code == 200,
          repr((cross.status_code, _rows218(other))))
    since = _last218()
    own = _p9_client(a).post("/account/push/devices/%d/remove" % own_row)
    _subscribe218(a, ba)
    off = _p9_client(a).post("/account/push/unsubscribe", json={"endpoint": ba.sub["endpoint"]})
    rows = _audit218("push_unsubscribe", since)
    check("devices: removing one's own device and turning alerts off each delete the row and are audited without "
          "the endpoint", own.status_code == 302 and off.status_code == 200 and _rows218(a) == 0 and len(rows) == 2
          and not any("fcm" in r[2] for r in rows), repr((own.status_code, off.status_code, rows)))
    cross_site = _p9_client(other).post("/account/push/unsubscribe", json={"endpoint": bo.sub["endpoint"]},
                                        headers={"Sec-Fetch-Site": "cross-site"})
    check("devices: a cross-site POST is refused by the Fetch Metadata guard like every other",
          cross_site.status_code == 403 and _rows218(other) == 1, repr(cross_site.status_code))


def _s218_test_route():
    pusher = _rig218()
    uid, bystander = _user218("p218_test"), _user218("p218_by")
    none = _p9_client(uid).post("/account/push/test")
    b1, b2, bb = _browser218(31), _browser218(32), _browser218(33)
    _subscribe218(uid, b1)
    _subscribe218(uid, b2)
    _subscribe218(bystander, bb)
    _p9_drain()
    pusher.sent.clear()
    first = _p9_client(uid).post("/account/push/test")
    _p9_drain()
    got = (pusher.to(b1), pusher.to(b2), pusher.to(bb))
    check("test alert: refused with no device; otherwise sent to each of this account's devices only, and the "
          "route returned before any push was sent", none.status_code == 400 and first.status_code == 200
          and len(got[0]) == 1 and len(got[1]) == 1 and got[2] == [] and got[0][0].get("url") == "account",
          repr((none.status_code, first.status_code, got)))
    more = [_p9_client(uid).post("/account/push/test").status_code for _ in range(_pa218.TEST_MAX)]
    _p9_drain()
    eq("test alert: rate-limited (%d per %d s); the next one is answered 429"
       % (_pa218.TEST_MAX, _pa218.TEST_WINDOW), more, [200] * (_pa218.TEST_MAX - 1) + [429])


def _s218_choices_route():
    viewer = _user218("p218_choose", servers=(P9_GS,))
    _p9_client(viewer).post("/account/push/events", data={"events": ["server_up", "admin_login", "my_account"]})
    with _p9.app_context():
        saved = _pa218.chosen_events(_db218.session.get(_U218, viewer))
        offered = [k for k, _l in _pa218.available_events(_db218.session.get(_U218, viewer))]
    check("choices: a user stores only alerts they may receive (a panel-wide one is dropped for a non-admin)",
          saved == {"server_up", "my_account"} and "admin_login" not in offered and "server_down" in offered,
          repr((saved, offered)))
    with _p9.app_context():
        fresh = _pa218.chosen_events(_db218.session.get(_U218, _user218("p218_fresh")))
    eq("choices: until a user chooses, the important ones are on (a crash, a host down, attacks, own account)",
       fresh, set(_pa218.DEFAULT_EVENTS))


# ── 4. who gets what ─────────────────────────────────────────────────────────────────────────────
def _s218_audience():
    pusher = _rig218()
    admin = _user218("p218_admin", superadmin=True)
    can, cannot = _user218("p218_can", servers=(P9_GS,)), _user218("p218_cannot", servers=(P9_OTHER,))
    host_user = _user218("p218_hosts", hosts=(P9_HOST,))
    bs = {u: _browser218(40 + i) for i, u in enumerate((admin, can, cannot, host_user))}
    for u, b in bs.items():
        _subscribe218(u, b)
    _p9_drain()
    pusher.sent.clear()
    _nt218.notify("server_down", "Server offline", "p9-cs on p9-host (203.0.113.9) went offline unexpectedly.",
                  server=_NS218(id=P9_GS))
    _p9_drain()
    got = {u: pusher.to(b) for u, b in bs.items()}
    eq("who: a server alert reaches who can access that server (by server or host grant) and superadmins, "
       "not a user without access", {k: len(v) for k, v in got.items()}, {admin: 1, can: 1, cannot: 0, host_user: 1})
    note = got[can][0] if got[can] else {}
    eq("who: the push says what a lock screen may show: the title and the server's name, no address, and "
       "opens that server's page",
       (note.get("title"), note.get("body"), "203.0.113.9" in _json218.dumps(note), note.get("url"),
        pusher.sent[0].headers.get("Urgency") if pusher.sent else None),
       ("Server offline", "p9-cs went offline unexpectedly.", False, "server/%d" % P9_GS, "high"))
    pusher.sent.clear()
    _nt218.notify("admin_bruteforce", "Brute-force", "p9_admin from 203.0.113.9")
    _p9_drain()
    eq("who: a panel-wide alert reaches superadmins only",
       {u: len(pusher.to(b)) for u, b in bs.items()}, {admin: 1, can: 0, cannot: 0, host_user: 0})
    pusher.sent.clear()
    _nt218.notify("remote_unreachable", "Host unreachable", "p9-host stopped responding.", remote=_NS218(id=P9_HOST))
    _p9_drain()
    eq("who: a host alert reaches who was granted that host (and superadmins), not a server-only grant",
       {u: len(pusher.to(b)) for u, b in bs.items()}, {admin: 1, can: 0, cannot: 0, host_user: 1})
    return pusher, bs, admin, can


def _s218_send_time_checks(pusher, bs, admin, can):
    pusher.sent.clear()
    _nt218.notify("server_down", "Server offline", "x", server=_NS218(id=P9_GS))
    with _p9.app_context():          # queued, then access removed before the sender runs
        u = _db218.session.get(_U218, can)
        u.groups = []
        _db218.session.commit()
    _p9_drain()
    check("who: decided at SEND time: access removed between the alert and the send gets nothing",
          pusher.to(bs[can]) == [] and len(pusher.to(bs[admin])) == 1, repr(len(pusher.to(bs[can]))))
    with _p9.app_context():
        u = _db218.session.get(_U218, admin)
        u.set_ui_pref("push_events", ["server_up"])
        _db218.session.commit()
    pusher.sent.clear()
    _nt218.notify("server_down", "Server offline", "x", server=_NS218(id=P9_GS))
    # "back online" from the monitor itself (the caller passes the server it is about).
    from panel.services import monitoring as _mon218
    _mon218._monitor_state["server_unannounced"].pop(P9_GS, None)
    _mon218._mon_server_came_up(_NS218(id=P9_HOST, display_name="p9-host"),
                                _NS218(id=P9_GS, name="p9-cs"), False, False)
    _p9_drain()
    eq("who: each user's own choice: an admin who chose only 'back online' is not pushed 'offline' (and the "
       "monitor's own 'back online' names its server, so it is pushed)",
       [n.get("title") for n in pusher.to(bs[admin])], ["Server back online"])


def _s218_account_change():
    pusher = _rig218()
    a, b = _user218("p218_acct"), _user218("p218_acct2", superadmin=True)
    ba, bb = _browser218(61), _browser218(62)
    _subscribe218(a, ba)
    _subscribe218(b, bb)
    _p9_drain()
    pusher.sent.clear()
    with _p9.app_context():
        _auth218.log_action(_db218.session.get(_U218, b), "password_changed", target="p218_acct")
        _auth218.log_action(None, "password_changed", target="p218_acct2", success=False)
    _p9_drain()
    got = pusher.to(ba)
    check("account: a change to an account's own security is pushed to that account's devices only, failed "
          "attempts are not", len(got) == 1 and got[0].get("title") == "Your account changed"
          and got[0].get("body") == "Password changed" and pusher.to(bb) == [], repr((got, pusher.to(bb))))
    pusher.sent.clear()
    _subscribe218(a, _browser218(63))
    _p9_drain()
    check("account: a new alert device is itself such a change: the account's devices are told",
          any(n.get("body") == "Alerts turned on for a new device" for n in pusher.to(ba)), repr(pusher.to(ba)))


def _s218_gone_and_failures():
    pusher = _rig218()
    uid = _user218("p218_gone", superadmin=True)
    b410, b404, b500, b302 = (_browser218(70 + i) for i in range(4))
    for b in (b410, b404, b500, b302):
        _subscribe218(uid, b)
    tgt = {b["endpoint"].split("fcm.googleapis.com", 1)[1]: c for b, c in
           ((b410.sub, 410), (b404.sub, 404), (b500.sub, 500), (b302.sub, 302))}
    _p9_drain()
    with _p9.app_context():
        for _row in _PS218.query.filter_by(user_id=uid).all():
            _row.last_success = None
        _db218.session.commit()
    pusher.by_target = tgt
    gone = _journal218(lambda: (_pa218.queue_test(uid), _p9_drain()))
    eq("delivery: each removal is a WARNING on a logger the journal's handler covers, naming the service and "
       "the status and no endpoint, key or payload",
       sorted(_line218(r, (b410.sub["endpoint"], b404.sub["endpoint"], "p218-", b410.sub["keys"]["auth"]))
              for r in gone),
       [("WARNING", "panel.push_alerts", "push subscription removed: fcm answered HTTP 404", False),
        ("WARNING", "panel.push_alerts", "push subscription removed: fcm answered HTTP 410", False)])
    with _p9.app_context():
        left = sorted(_d.endpoint_hash for _d in _PS218.query.filter_by(user_id=uid).all())
        last = [_d.last_success for _d in _PS218.query.filter_by(user_id=uid).all()]
    want = sorted(_pa218.endpoint_hash(b.sub["endpoint"]) for b in (b500, b302))
    check("delivery: a 410 or 404 from the push service removes that device; a 500 or a redirect (never "
          "followed) keeps it and records no delivery", left == want and last == [None, None], repr((left, want)))


def _s218_gone_refused():
    _rig218()
    uid = _user218("p218_gone2")
    b = _browser218(170)
    _subscribe218(uid, b)
    _p9_drain()
    with _p9.app_context():           # a stored endpoint that no longer passes the allow-list
        _r = _PS218.query.filter_by(user_id=uid).first()
        if _r is not None:
            _r.endpoint = "https://push.internal.example/p218-170"
            _db218.session.commit()
    gone = _journal218(lambda: (_pa218.queue_test(uid), _p9_drain()))
    eq("delivery: a stored endpoint that is no push service's is removed with a line that says so (no '?' for a "
       "service it does not have, and no endpoint)", ([_line218(r, ("push.internal", "p218-")) for r in gone],
                                                       _rows218(uid)),
       ([("WARNING", "panel.push_alerts", "push subscription removed: its endpoint is not a push service's", False)],
        0))


def _s218_deactivate_delete():
    pusher = _rig218()
    a, d = _user218("p218_deact", servers=(P9_GS,)), _user218("p218_del")
    _subscribe218(a, _browser218(81))
    _subscribe218(d, _browser218(82))
    with _p9.app_context():
        gid = _db218.session.get(_U218, a).groups[0].id
    r = _p9_client(P9_ADMIN).post("/users/%d/edit" % a, data={"display_name": "p218_deact", "groups": [str(gid)]})
    gone = _rows218(a)
    rd = _p9_client(P9_ADMIN).post("/users/%d/delete" % d)
    with _p9.app_context():
        orphans = _PS218.query.filter_by(user_id=d).count()
    check("lifecycle: deactivating an account (the users edit form) drops its devices; deleting one does too",
          r.status_code == 302 and gone == 0 and rd.status_code == 302 and orphans == 0,
          repr((r.status_code, gone, rd.status_code, orphans)))
    with _p9.app_context():           # a row left behind any other way: the send itself refuses
        u = _db218.session.get(_U218, a)
        b = _browser218(83)
        _pa218.subscribe(u, b.sub, "x")
        _db218.session.commit()
    pusher.sent.clear()
    _nt218.notify("server_down", "Server offline", "x", server=_NS218(id=P9_GS))
    _p9_drain()
    eq("lifecycle: an inactive account is pushed nothing even with a device on file", pusher.to(b), [])


# ── 5. sign-out ──────────────────────────────────────────────────────────────────────────────────
def _s218_signout():
    # A sign-out ends that account's every legacy cookie (the auth_epoch bump), so each case signs out
    # its own account.
    uid, other, plain_u, stop_u = (_user218(n) for n in ("p218_out", "p218_out2", "p218_out3", "p218_out4"))
    b, bo, bs = _browser218(91), _browser218(92), _browser218(93)
    _subscribe218(uid, b)
    _subscribe218(other, bo)
    _subscribe218(stop_u, bs)
    page = _p9_client(uid).get("/account/signout").get_data(as_text=True)
    check("sign-out page: lists this account's device hashes (never an endpoint), and the stop-alerts choice",
          _pa218.endpoint_hash(b.sub["endpoint"]) in page and _pa218.endpoint_hash(bo.sub["endpoint"]) not in page
          and b.sub["endpoint"] not in page and 'name="stop_alerts"' in page, page[:120])
    keep = _p9_client(uid).post("/logout", data={"push_endpoint": b.sub["endpoint"]})
    check("sign-out: alerts kept by default: Clear-Site-Data is cookies only (storage would remove the service "
          "worker), and the device stays", keep.headers.get("Clear-Site-Data") == '"cookies"' and _rows218(uid) == 1,
          repr(keep.headers.get("Clear-Site-Data")))
    foreign = _p9_client(plain_u).post("/logout", data={"push_endpoint": bo.sub["endpoint"], "stop_alerts": "1"})
    plain = _p9_client(other).post("/logout")
    check("sign-out: another account's endpoint or none at all: the full clear, and nobody's device touched",
          foreign.headers.get("Clear-Site-Data") == '"cookies", "storage"' and _rows218(other) == 1
          and plain.headers.get("Clear-Site-Data") == '"cookies", "storage"', repr(foreign.headers.get("Clear-Site-Data")))
    since = _last218()
    stop = _p9_client(stop_u).post("/logout", data={"push_endpoint": bs.sub["endpoint"], "stop_alerts": "1"})
    check("sign-out: 'Stop alerts on this device' removes it, audits it and clears the site's storage too",
          stop.headers.get("Clear-Site-Data") == '"cookies", "storage"' and _rows218(stop_u) == 0
          and len(_audit218("push_unsubscribe", since)) == 1, repr(stop.headers.get("Clear-Site-Data")))


def _s218_pages():
    uid = _user218("p218_page")
    r = _p9_client(uid).get("/account")
    page = r.get_data(as_text=True)
    check("account page: the alerts card carries the VAPID public key and the service worker under static/push/",
          r.status_code == 200 and 'id="sec-push"' in page and 'data-key="%s"' % _wp218.vapid_public_key() in page
          and "/static/push/sw.js" in page and 'data-scope="/static/push/"' in page, repr(r.status_code))
    # part12's app does not install app.py's header hook; read the policy app.py builds (as part214 does).
    with open(_os218.path.join(REPO_ROOT, "panel", "install", "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    csp = src[src.index("    def _csp():"):src.index("    @app.after_request")]
    check("csp: the page policy has worker-src 'self' (the alerts service worker), and no other worker-src",
          csp.count("worker-src") == 1 and "worker-src 'self'; " in csp, csp[-300:])


try:
    for _fn218 in (_s218_rfc8291_vector, _s218_vapid, _s218_endpoints, _s218_send_guard, _s218_subscribe_route,
                   _s218_takeover, _s218_device_cap, _s218_remove_and_off, _s218_test_route, _s218_choices_route,
                   _s218_account_change, _s218_gone_and_failures, _s218_gone_refused, _s218_deactivate_delete, _s218_signout,
                   _s218_pages):
        _p9_arm(who="part218")
        _rig218()       # every push POST stubbed, whichever check runs: none may leave the machine
        try:
            _fn218()
        finally:
            _p9_drain()
            _p9_restore_all()
    _p9_arm(who="part218")
    _rig218()
    try:
        _s218_send_time_checks(*_s218_audience())
    finally:
        _p9_drain()
        _p9_restore_all()
finally:
    _p9_restore_all()
    _pa218.reset_tests()
    with _p9.app_context():
        for _uid218 in _IDS218:
            _PS218.query.filter_by(user_id=_uid218).delete()
            _u218 = _db218.session.get(_U218, _uid218)
            if _u218 is not None:
                for _g218 in list(_u218.groups):
                    _db218.session.delete(_g218)
                _db218.session.delete(_u218)
        for _g218 in _G218.query.filter(_G218.name.like("p218-%")).all():
            _db218.session.delete(_g218)
        _db218.session.commit()

check("part218: nothing reached a real transport", len(_P9_TRIPPED) == _trips218, repr(_P9_TRIPPED[_trips218:]))
