"""Part 232 of the unit suite: the operator's own certificate for the panel's built-in HTTPS.

* The check (tls_own.check) refuses an unreadable certificate, a passphrase-protected key, a key that
  is not the certificate's and an expired certificate, and notes (never refuses) a short RSA key, a
  SHA-1 signature, a panel address the certificate does not cover, a self-signed certificate, a chain
  with no intermediate, and a certificate given after its CA (which is put first).
* Settings > HTTPS certificate, through the real routes: a paste is written to data/ssl (the key 0600)
  re-encoded from what was parsed, recorded as the operator's, audited and loaded by a restart; a
  refused paste writes nothing and does not restart; a viewer is refused; going back to the built-in
  certificate needs the box ticked.
* Let's Encrypt, through the route and the REAL helper verb (tls-le-copy, run in-process against a
  scratch /etc/letsencrypt): the copy is put in place, the staging copies are gone; the helper refuses
  a file outside the certificate's own directories, a file root does not own, anything that is not
  PEM of the expected kind, and a data/ssl that is a link. An unknown name says so.
* The daily refresh loads a renewed certificate (a later notAfter) and restarts, leaves the same one
  alone, and runs at most once a day and only when switched on.
* The self-signed generator keeps a certificate marked as the operator's even when it is self-signed;
  the expiry alert for a Let's Encrypt one points at certbot.

HOW IT RUNS. Through part12's Flask app with its transport tripwire armed; config.json is a dict here,
data/ssl and /etc/letsencrypt are scratch directories, and the restart is a recorder.
"""
import datetime as _dt232
import importlib.machinery as _mach232
import importlib.util as _ilu232
import io as _io232
import os
import shutil as _sh232
import stat as _st232
import sys
import tempfile as _tmp232
from pathlib import Path as _Path232
from types import SimpleNamespace as _NS232

from cryptography import x509 as _x232
from cryptography.hazmat.primitives import hashes as _h232, serialization as _s232
from cryptography.hazmat.primitives.asymmetric import ec as _ec232, rsa as _rsa232
from cryptography.x509.oid import NameOID as _N232

from unit.part01 import check, eq
from unit.part05 import _helper_path
from unit.part12 import (P9_ADMIN, P9_VIEWER, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_patch,
                         _p9_restore_all)
from panel.ops import system_ops as _so232
from panel.routes import tls_cert as _route232
from panel.services import certs as _certs232, tls_own as _own232

_trips232 = len(_P9_TRIPPED)
_NOW232 = _dt232.datetime.now(_dt232.timezone.utc)
_TMP232 = _Path232(_tmp232.mkdtemp(prefix="lgsm-unit-232-"))
_SSL232 = _TMP232 / "data" / "ssl"
_LE232 = _TMP232 / "letsencrypt"
_CFG232 = {}
_RESTARTS232 = []
_spec232 = _ilu232.spec_from_loader("ph_tls232", _mach232.SourceFileLoader("ph_tls232", _helper_path))
_ph232 = _ilu232.module_from_spec(_spec232)
_spec232.loader.exec_module(_ph232)


def _cert232(cn, key, signer=None, signer_name=None, days=90, san=("panel.example.com",), algo=None):
    name = _x232.Name([_x232.NameAttribute(_N232.COMMON_NAME, cn)])
    b = (_x232.CertificateBuilder().subject_name(name).issuer_name(signer_name or name)
         .public_key(key.public_key()).serial_number(_x232.random_serial_number())
         .not_valid_before(_NOW232 - _dt232.timedelta(days=2))
         .not_valid_after(_NOW232 + _dt232.timedelta(days=days)))
    if san:
        b = b.add_extension(_x232.SubjectAlternativeName([_x232.DNSName(s) for s in san]), critical=False)
    return b.sign(signer or key, algo or _h232.SHA256())


def _pem232(*certs):
    return b"".join(c.public_bytes(_s232.Encoding.PEM) for c in certs)


def _key232(key, pw=None):
    enc = _s232.BestAvailableEncryption(pw) if pw else _s232.NoEncryption()
    return key.private_bytes(_s232.Encoding.PEM, _s232.PrivateFormat.TraditionalOpenSSL, enc)


_CA_KEY232 = _ec232.generate_private_key(_ec232.SECP256R1())
_CA232 = _cert232("Unit 232 CA", _CA_KEY232, days=3650, san=())
_LEAF_KEY232 = _ec232.generate_private_key(_ec232.SECP256R1())
_LEAF232 = _cert232("panel.example.com", _LEAF_KEY232, _CA_KEY232, _CA232.subject)
_GOOD_CHAIN232, _GOOD_KEY232 = _pem232(_LEAF232, _CA232), _key232(_LEAF_KEY232)
_NAMES232 = ["panel.example.com"]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The check: what is refused, what is only noted
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _refusals232():
    other = _ec232.generate_private_key(_ec232.SECP256R1())
    expired = _cert232("panel.example.com", _LEAF_KEY232, _CA_KEY232, _CA232.subject, days=-1)
    got = {
        "unreadable": _own232.check(b"-----BEGIN CERTIFICATE-----\nnope\n", _GOOD_KEY232).refusal,
        "passphrase": _own232.check(_GOOD_CHAIN232, _key232(_LEAF_KEY232, b"unit232pass")).refusal,
        "mismatch": _own232.check(_GOOD_CHAIN232, _key232(other)).refusal,
        "expired": _own232.check(_pem232(expired, _CA232), _GOOD_KEY232).refusal,
    }
    eq("own cert: an unreadable certificate, a passphrase key, a key that is not the certificate's and an expired "
       "certificate are refused, each saying why",
       {k: (v.split(" ")[1:4]) for k, v in got.items()},
       {"unreadable": ["certificate", "could", "not"], "passphrase": ["private", "key", "is"],
        "mismatch": ["private", "key", "does"], "expired": ["certificate", "expired", "on"]})


def _notes232():
    rsa_key = _rsa232.generate_private_key(public_exponent=65537, key_size=1024)
    weak = _cert232("panel.example.com", rsa_key, _CA_KEY232, _CA232.subject)
    c_weak = _own232.check(_pem232(weak, _CA232), _key232(rsa_key), _NAMES232)
    eq("own cert: RSA under 2048 bits is noted, not refused", (c_weak.refusal, [n.split(".")[0] for n in c_weak.notes]),
       ("", ["The key is RSA 1024 bits"]))
    # cryptography no longer signs with SHA-1, so the signature is described rather than made.
    sha1 = _own232._hash_notes(_NS232(signature_hash_algorithm=_NS232(name="sha1")))
    eq("own cert: a SHA-1 signature is noted (OWASP: SHA-256 or stronger)", [n.split(".")[0] for n in sha1],
       ["The certificate is signed with SHA1"])
    c_self = _own232.check(_pem232(_cert232("x", _LEAF_KEY232, san=("other.example.org",))), _GOOD_KEY232, _NAMES232)
    eq("own cert: a self-signed certificate that does not cover the panel's address is put in with two notes",
       (c_self.refusal, [n[:40] for n in c_self.notes]),
       ("", ["The certificate does not cover panel.exa", "The certificate is self-signed, so brows"]))
    c_alone = _own232.check(_pem232(_LEAF232), _GOOD_KEY232, ["a.panel.example.com", "panel.example.com"])
    eq("own cert: a CA-signed certificate given without its chain is noted, and a name it lacks is named",
       [n[:46] for n in c_alone.notes],
       ["The certificate does not cover a.panel.example", "Only the server certificate was given. Paste t"])
    c_order = _own232.check(_pem232(_CA232, _LEAF232), _GOOD_KEY232, _NAMES232)
    eq("own cert: a key matching the second certificate puts that one first, and says so",
       (c_order.refusal, c_order.notes, c_order.chain[0] == _LEAF232, c_order.cert_pem() == _GOOD_CHAIN232),
       ("", ["The server certificate was not first in the file; it has been put first."], True, True))
    wild = _cert232("example.com", _LEAF_KEY232, _CA_KEY232, _CA232.subject, san=("*.example.com",))
    eq("own cert: a wildcard covers one left-most label only",
       [_own232.covers(wild, n) for n in ("panel.example.com", "a.b.example.com", "example.com")],
       [True, False, False])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The routes: paste, refusal, viewer, back to the built-in certificate
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _arm232():
    _p9_arm(who="part232")
    for mod in (_own232, _route232):
        _p9_patch(mod, "load_config", lambda: dict(_CFG232))
        _p9_patch(mod, "update_config", lambda mutate: mutate(_CFG232))
    _p9_patch(_certs232, "load_config", lambda: dict(_CFG232))
    _p9_patch(_certs232, "SSL_DIR", _SSL232)
    _p9_patch(_so232, "restart_panel", lambda delay_seconds=2: (_RESTARTS232.append(delay_seconds), (True, "ok"))[1])


def _files232():
    return sorted(p.name for p in _SSL232.iterdir()) if _SSL232.is_dir() else []


def _read232(name):
    path = _SSL232 / name
    return path.read_bytes() if path.is_file() else b""


def _post232(uid, url, data, base="http://localhost"):
    """(status, the flashes the route left) for a POST through part12's app."""
    with _p9_client(uid) as c:
        r = c.post(url, data=data, base_url=base)
        with c.session_transaction() as sess:
            return r.status_code, [m for _c, m in sess.get("_flashes", [])]


def _paste232():
    _CFG232.clear()
    _RESTARTS232.clear()
    code, said = _post232(P9_ADMIN, "/settings/tls/paste", {"cert_pem": _GOOD_CHAIN232.decode(),
                                                            "key_pem": _GOOD_KEY232.decode()})
    key_mode = _st232.S_IMODE(os.stat(_SSL232 / "key.pem").st_mode) if (_SSL232 / "key.pem").exists() else None
    check("own cert: a pasted pair is written to data/ssl, the key 0600 and re-encoded, the chain leaf first",
          (code, _files232(), key_mode, _read232("cert.pem") == _GOOD_CHAIN232,
           _read232("key.pem").startswith(b"-----BEGIN PRIVATE KEY-----"))
          == (302, ["cert.pem", "key.pem"], 0o600, True, True), repr((code, said, _files232(), key_mode)))
    eq("own cert: the paste is recorded as the operator's, audited, and loaded by one restart",
       (_CFG232.get("tls_cert_source"), _p9_audit("tls_cert_install").detail[:24], _RESTARTS232),
       ("own", "own: panel.example.com, ", [2]))


def _paste_refused232():
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _CFG232.clear()
    _RESTARTS232.clear()
    other = _key232(_ec232.generate_private_key(_ec232.SECP256R1()))
    r = _p9_client(P9_ADMIN).post("/settings/tls/paste", data={"cert_pem": _GOOD_CHAIN232.decode(),
                                                             "key_pem": other.decode()})
    v = _p9_client(P9_VIEWER).post("/settings/tls/paste", data={"cert_pem": _GOOD_CHAIN232.decode(),
                                                              "key_pem": _GOOD_KEY232.decode()})
    eq("own cert: a key that is not the certificate's writes nothing and restarts nothing; a viewer is refused",
       (r.status_code, _files232(), _RESTARTS232, _CFG232.get("tls_cert_source"), v.status_code in (302, 403),
        _p9_audit("tls_cert_refused").success), (302, [], [], None, True, False))


def _remove232():
    _CFG232.update({"tls_cert_source": "own"})
    _SSL232.mkdir(parents=True, exist_ok=True)
    (_SSL232 / "cert.pem").write_bytes(_GOOD_CHAIN232)
    _RESTARTS232.clear()
    unticked = _p9_client(P9_ADMIN).post("/settings/tls/remove", data={})
    kept = (_files232(), _CFG232.get("tls_cert_source"), list(_RESTARTS232))
    ticked = _p9_client(P9_ADMIN).post("/settings/tls/remove", data={"confirm": "on"})
    eq("own cert: going back to the built-in certificate needs the box ticked; then the pair goes, the mark is "
       "cleared and the panel restarts", (unticked.status_code, kept, ticked.status_code, _files232(),
                                          "tls_cert_source" in _CFG232, _RESTARTS232),
       (302, (["cert.pem"], "own", []), 302, [], False, [2]))


def _page232():
    _CFG232.clear()
    _CFG232["tls_cert_source"] = "letsencrypt"
    _CFG232["tls_le_name"] = "panel.example.com"
    _SSL232.mkdir(parents=True, exist_ok=True)
    (_SSL232 / "cert.pem").write_bytes(_GOOD_CHAIN232)
    from panel.routes import admin_notifications as _an232
    _p9_patch(_an232, "load_config", lambda: dict(_CFG232))
    html = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    eq("own cert: Settings shows whose certificate is in use, its issuer and the three forms",
       ['id="sec-tls"' in html, "Let's Encrypt certificate <code>panel.example.com</code>" in html,
        "Unit 232 CA" in html, html.count('action="/settings/tls/'), "OWASP: a well-known CA" in html],
       [True, True, True, 3, True])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Let's Encrypt through the real helper verb
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _le_tree232(name, chain=_GOOD_CHAIN232, key=_GOOD_KEY232):
    """The layout certbot makes: live/<name>/x.pem -> ../../archive/<name>/x1.pem."""
    arch, live = _LE232 / "archive" / name, _LE232 / "live" / name
    _sh232.rmtree(arch, ignore_errors=True)
    _sh232.rmtree(live, ignore_errors=True)
    arch.mkdir(parents=True)
    live.mkdir(parents=True)
    for fname, data in (("fullchain", chain), ("privkey", key)):
        (arch / (fname + "1.pem")).write_bytes(data)
        os.symlink("../../archive/%s/%s1.pem" % (name, fname), live / (fname + ".pem"))


def _helper_verb232(verb, args, timeout=30, merge_stderr=True):
    """system_ops._run_verb as the helper answers it: the real do_tls_le_copy, in this process."""
    saved = (sys.stdout, sys.stderr, sys.stdin)
    sys.stdout, sys.stderr, sys.stdin = _io232.StringIO(), _io232.StringIO(), _io232.StringIO("")
    try:
        rc = _ph232.main(["panel-helper", verb] + list(args))
        return sys.stdout.getvalue(), sys.stderr.getvalue(), rc
    finally:
        sys.stdout, sys.stderr, sys.stdin = saved


def _arm_helper232(owner=None):
    _p9_patch(_ph232, "TLS_LE_ROOT", str(_LE232))
    _p9_patch(_ph232, "TLS_LE_OWNER", os.getuid() if owner is None else owner)
    _p9_patch(_ph232, "panel_conf", lambda: {"data_dir": str(_TMP232 / "data")})
    _p9_patch(_so232, "_run_verb", _helper_verb232)


def _le_route232():
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _CFG232.clear()
    _RESTARTS232.clear()
    _le_tree232("panel.example.com")
    _arm_helper232()
    r = _p9_client(P9_ADMIN).post("/settings/tls/letsencrypt", data={"le_name": "panel.example.com",
                                                                   "le_autorenew": "on"})
    eq("own cert: Let's Encrypt through the helper is checked and put in place, the staging copies gone, the "
       "name and auto-renew recorded, and the panel restarts",
       (r.status_code, _files232(), _read232("cert.pem") == _GOOD_CHAIN232,
        _CFG232.get("tls_cert_source"), _CFG232.get("tls_le_name"), _CFG232.get("tls_le_autorenew"), _RESTARTS232),
       (302, ["cert.pem", "key.pem"], True, "letsencrypt", "panel.example.com", True, [2]))
    _RESTARTS232.clear()
    with _p9_client(P9_ADMIN) as c:
        c.post("/settings/tls/letsencrypt", data={"le_name": "missing.example.com"})
        with c.session_transaction() as s:
            said = [m for _c, m in s.get("_flashes", [])]
    eq("own cert: an unknown Let's Encrypt name says so and changes nothing",
       (said[:1], _RESTARTS232, _CFG232.get("tls_le_name")),
       ([_own232.LE_NOT_FOUND % "missing.example.com"], [], "panel.example.com"))


def _helper_refusals232():
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _SSL232.mkdir(parents=True)
    name = "bad.example.com"
    _le_tree232(name)
    outside = _TMP232 / "elsewhere.pem"
    outside.write_bytes(_GOOD_KEY232)
    os.unlink(_LE232 / "live" / name / "privkey.pem")
    os.symlink(str(outside), _LE232 / "live" / name / "privkey.pem")
    got = {"outside": _helper_verb232("tls-le-copy", [name])[1:]}
    _le_tree232(name, key=b"root:x:0:0:root:/root:/bin/bash\n")
    got["not PEM"] = _helper_verb232("tls-le-copy", [name])[1:]
    _le_tree232(name, chain=_GOOD_CHAIN232 + _GOOD_KEY232)
    got["key in the chain"] = _helper_verb232("tls-le-copy", [name])[1:]
    _le_tree232(name)
    _p9_patch(_ph232, "TLS_LE_OWNER", os.getuid() + 1)
    got["not root's"] = _helper_verb232("tls-le-copy", [name])[1:]
    _p9_patch(_ph232, "TLS_LE_OWNER", os.getuid())
    refused = ("tls-le-copy: not a Let's Encrypt certificate this verb copies\n", 1)
    eq("own cert: the helper refuses a key outside the certificate's directories, a file that is not PEM of its "
       "kind, and one its owner rule does not allow", got, {k: refused for k in got})
    eq("own cert: nothing was staged by a refused copy", _files232(), [])


def _helper_links232():
    name = "panel.example.com"
    _le_tree232(name)
    target = _TMP232 / "victim.txt"
    target.write_bytes(b"untouched")
    for left in _own232.LE_STAGED:     # a refused copy above must not have left any (checked there)
        if os.path.lexists(_SSL232 / left):
            os.unlink(_SSL232 / left)
    os.symlink(str(target), _SSL232 / "le-privkey.pem")
    out, _err, rc = _helper_verb232("tls-le-copy", [name])
    staged = _SSL232 / "le-privkey.pem"
    eq("own cert: a staging name planted as a link is replaced, never written through",
       (rc, out, target.read_bytes(), staged.is_symlink(), _st232.S_IMODE(staged.lstat().st_mode)),
       (0, "COPIED", b"untouched", False, 0o600))
    _own232._read_staged()
    _sh232.rmtree(_SSL232)
    (_TMP232 / "ssl-real").mkdir(exist_ok=True)
    os.symlink(str(_TMP232 / "ssl-real"), _SSL232)
    linked = _helper_verb232("tls-le-copy", [name])
    eq("own cert: a data/ssl that is a link is refused, nothing written through it",
       (linked[2], os.listdir(_TMP232 / "ssl-real")), (1, []))
    os.unlink(_SSL232)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The daily refresh, the self-signed generator, the expiry text
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _renew232():
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _SSL232.mkdir(parents=True)
    (_SSL232 / "cert.pem").write_bytes(_GOOD_CHAIN232)
    (_SSL232 / "key.pem").write_bytes(_GOOD_KEY232)
    _CFG232.clear()
    _CFG232.update({"tls_cert_source": "letsencrypt", "tls_le_name": "panel.example.com"})
    _RESTARTS232.clear()
    _le_tree232("panel.example.com")
    _own232._RENEW["at"] = 0.0
    same = _own232.maybe_renew({"BOOT_TLS": True}, now=10 * 86400.0)
    newer = _cert232("panel.example.com", _LEAF_KEY232, _CA_KEY232, _CA232.subject, days=120)
    _le_tree232("panel.example.com", chain=_pem232(newer, _CA232))
    early = _own232.maybe_renew({"BOOT_TLS": True}, now=10.5 * 86400.0)
    renewed = _own232.maybe_renew({"BOOT_TLS": True}, now=11 * 86400.0)
    eq("own cert: the daily refresh leaves the same certificate alone, waits a day, then loads a renewed one "
       "and restarts", (same, early, renewed, _read232("cert.pem") == _pem232(newer, _CA232),
                        _RESTARTS232, _files232()),
       ("same", "", "renewed", True, [2], ["cert.pem", "key.pem"]))
    _CFG232["tls_le_autorenew"] = False
    off = _own232.maybe_renew({"BOOT_TLS": True}, now=30 * 86400.0)
    _CFG232["tls_le_autorenew"] = True
    proxied = _own232.maybe_renew({"BOOT_TLS": False}, now=30 * 86400.0)
    eq("own cert: no refresh with auto-renew off, or while a proxy terminates TLS", (off, proxied), ("", ""))


def _generator232():
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _SSL232.mkdir(parents=True)
    cert_path, key_path = str(_SSL232 / "cert.pem"), str(_SSL232 / "key.pem")
    rsa_key = _rsa232.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_self = _cert232("mine.example.org", rsa_key, san=("mine.example.org",))
    results = []
    for marked in ("own", ""):
        (_SSL232 / "cert.pem").write_bytes(_pem232(rsa_self))
        (_SSL232 / "key.pem").write_bytes(_key232(rsa_key))
        _CFG232.clear()
        _CFG232.update({"tls_cert_source": marked, "tls_cert_sha256": _certs232.fingerprint(rsa_self)})
        before = (_SSL232 / "cert.pem").read_bytes()
        _certs232._ensure_self_signed_cert(cert_path, key_path, "panel.example.com")
        results.append((_SSL232 / "cert.pem").read_bytes() == before)
    (_SSL232 / "cert.pem").write_bytes(_pem232(rsa_self))
    _CFG232.update({"tls_cert_source": "own", "tls_cert_sha256": "0" * 64})
    _certs232._ensure_self_signed_cert(cert_path, key_path, "panel.example.com")
    results.append((_SSL232 / "cert.pem").read_bytes() == _pem232(rsa_self))
    eq("own cert: the self-signed generator keeps a self-signed certificate marked as the operator's, still "
       "replaces an unmarked RSA one, and one whose mark names another certificate (a restored config)",
       results, [True, False, False])
    eq("own cert: the expiry alert for a Let's Encrypt certificate points at certbot; a pasted one at Settings",
       ["certbot renew --dry-run" in _certs232._expiry_text(9, True, "letsencrypt"),
        "Settings > HTTPS certificate" in _certs232._expiry_text(9, True, "own")], [True, True])


def _hsts232():
    import time as _time232
    import app as _app232
    from panel.security import headers as _hdr232
    _sh232.rmtree(_SSL232, ignore_errors=True)
    _SSL232.mkdir(parents=True)
    (_SSL232 / "cert.pem").write_bytes(_GOOD_CHAIN232)
    (_SSL232 / "key.pem").write_bytes(_GOOD_KEY232)
    _CFG232.clear()
    _CFG232.update({"tls_cert_source": "own", "tls_installed_at": 1000})
    _p9_patch(_app232, "DATA_DIR", _TMP232 / "data")
    boot = _NS232(config={})
    args = _app232._boot_ssl_args(boot, {"use_https": True, "bind_host": "0.0.0.0"}, "0.0.0.0", 5000)
    rec = boot.config.get("BOOT_TLS_OWN") or {}
    eq("own cert: the boot records the operator's CA-signed certificate it serves, for HSTS",
       (bool(args), rec.get("until") == _LEAF232.not_valid_after_utc, rec.get("since")), (True, True, 1000))
    rec = rec if "until" in rec else {"until": _LEAF232.not_valid_after_utc, "since": 0}   # failed above
    now = _time232.time()
    fresh, old = dict(rec, since=int(now) - 86400), dict(rec, since=int(now) - 40 * 86400)
    eq("own cert: HSTS on own TLS is one day for 30 days after the certificate was put in (and for one put in by "
       "hand), then two years; none without a CA-signed record or after its date",
       [_certs232.own_tls_hsts(r, now) for r in (fresh, old, dict(rec, since=0), None)]
       + [_certs232.own_tls_hsts(old, _LEAF232.not_valid_after_utc.timestamp() + 1)],
       [_certs232.HSTS_ROLLOUT, _hdr232.HSTS, _certs232.HSTS_ROLLOUT, "", ""])
    (_SSL232 / "cert.pem").write_bytes(_pem232(_cert232("x", _LEAF_KEY232)))
    eq("own cert: a self-signed certificate never gets HSTS, marked as the operator's or not",
       _certs232.own_cert_until((str(_SSL232 / "cert.pem"),)), None)
    with open(_app232.__file__, encoding="utf-8") as fh:
        src = fh.read()
    check("own cert: app.py's response headers send own_tls_hsts's value for the boot's record",
          'own = request.is_secure and self_tls and own_tls_hsts(app.config.get("BOOT_TLS_OWN"))' in src
          and 'setdefault("Strict-Transport-Security", own or _sec_headers.HSTS)' in src)


try:
    _refusals232()
    _notes232()
    _arm232()
    _paste232()
    _paste_refused232()
    _remove232()
    _page232()
    _le_route232()
    _helper_refusals232()
    _helper_links232()
    _renew232()
    _generator232()
    _hsts232()
finally:
    _p9_restore_all()
    _own232._RENEW["at"] = 0.0
    _sh232.rmtree(_TMP232, ignore_errors=True)
check("own cert: nothing in this part reached a real transport (part12's tripwire)", len(_P9_TRIPPED) == _trips232)
