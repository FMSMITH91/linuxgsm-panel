"""Part 313 of the unit suite: a website domain's own certificate, Cloudflare in front, and the site page's fixes.

1. The per-host certificate choice nothing read (website_proxy.origin_tls) is gone: an older database's column is
   dropped at start, and the proxy settings no longer carry it.
"""
import datetime as _dt313
import importlib.machinery as _mach313
import importlib.util as _ilu313
import io as _io313
import json as _json313
import os
import shutil as _shutil313
import socket as _socket313
import tempfile as _tf313
from contextlib import redirect_stderr as _rerr313, redirect_stdout as _rout313
from types import SimpleNamespace as _NS313

from cryptography import x509 as _x509_313
from cryptography.hazmat.primitives import hashes as _hashes313, serialization as _ser313
from cryptography.hazmat.primitives.asymmetric import ec as _ec313, rsa as _rsa313
from cryptography.x509.oid import NameOID as _OID313
from flask import g as _g313
from sqlalchemy import inspect as _inspect313, text as _text313

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from unit.part301 import _COMMON301, _list_sa301, _node301, _ran301, _site_ad301, _site_cu301
from panel.core.clock import utcnow as _utcnow313
from panel.core.config import decrypt_secret as _dec313, encrypt_secret as _enc313
from panel.db import models as _models313
from panel.db.models import (AuditLog as _Audit313, Group as _Group313, RemoteServer as _Remote313, User as _User313,
                             Website as _Site313, WebsiteDomain as _Dom313, db as _db313)
from panel.ops.ssh_manager import websites as _sw313
from panel.routes import os_updates as _osu313
from panel.routes import websites as _w313
from panel.routes import websites_domains as _wd313
from panel.routes import websites_proxy as _wpr313
from panel.security import auth as _auth313
from panel.services import notifications as _notif313
from panel.services import tls_own as _own313
from panel.services import website_certs as _wcert313
from panel.services import website_dns as _dns313
from panel.services import websites as _ws313
from panel.services import websites_proxy as _wp313

_ROWS313 = {"remotes": [], "users": [], "groups": []}
_HOST_IP313 = "11.22.33.55"
_SAVED2FA313 = []
_NOW313 = _dt313.datetime.now(_dt313.timezone.utc)


# ── certificates, made here ───────────────────────────────────────────────────────────────────────
def _name313(cn, ou=None):
    attrs = [_x509_313.NameAttribute(_OID313.COMMON_NAME, cn)]
    if ou:
        attrs.append(_x509_313.NameAttribute(_OID313.ORGANIZATIONAL_UNIT_NAME, ou))
    return _x509_313.Name(attrs)


def _ec_key313():
    return _ec313.generate_private_key(_ec313.SECP256R1())


_CA_KEY313 = _ec_key313()
_CA_NAME313 = _name313("P313 Test CA")


def _cert313(key, names, start=-1, days=90, issuer_key=None, issuer=None, cn=None):
    """A leaf for `names` (subjectAltName), valid from `start` days from now for `days` days, signed by the test CA."""
    issuer_key = issuer_key or _CA_KEY313
    b = (_x509_313.CertificateBuilder().subject_name(_name313(cn or (names[0] if names else "none")))
         .issuer_name(issuer or _CA_NAME313).public_key(key.public_key()).serial_number(_x509_313.random_serial_number())
         .not_valid_before(_NOW313 + _dt313.timedelta(days=start))
         .not_valid_after(_NOW313 + _dt313.timedelta(days=start + days)))
    if names:
        b = b.add_extension(_x509_313.SubjectAlternativeName([_x509_313.DNSName(n) for n in names]), critical=False)
    return b.sign(issuer_key, _hashes313.SHA256())


def _ca_pem313():
    b = (_x509_313.CertificateBuilder().subject_name(_CA_NAME313).issuer_name(_CA_NAME313)
         .public_key(_CA_KEY313.public_key()).serial_number(1).not_valid_before(_NOW313 - _dt313.timedelta(days=10))
         .not_valid_after(_NOW313 + _dt313.timedelta(days=900)))
    return b.sign(_CA_KEY313, _hashes313.SHA256()).public_bytes(_ser313.Encoding.PEM).decode()


def _pem313(cert):
    return cert.public_bytes(_ser313.Encoding.PEM).decode()


def _keypem313(key, password=None):
    enc = _ser313.BestAvailableEncryption(password) if password else _ser313.NoEncryption()
    return key.private_bytes(_ser313.Encoding.PEM, _ser313.PrivateFormat.PKCS8, enc).decode()


_DOMAIN313 = "shop.p313.example.org"
_KEY313 = _ec_key313()
_CHAIN313 = _pem313(_cert313(_KEY313, [_DOMAIN313])) + _ca_pem313()
_KEYPEM313 = _keypem313(_KEY313)


# ── the app's rows ────────────────────────────────────────────────────────────────────────────────
class _Client313:
    """A test client for `uid` that never reuses another request's signed-in user (part300's reason)."""

    def __init__(self, uid):
        self.c = _p9_client(uid)

    def get(self, *a, **k):
        _g313.pop("_login_user", None)
        return self.c.get(*a, **k)

    def post(self, *a, **k):
        _g313.pop("_login_user", None)
        return self.c.post(*a, **k)


def _host313(name):
    r = _Remote313(name=name, host="198.51.100.%d" % (len(_ROWS313["remotes"]) + 60), port=22, username="u",
                   auth_method="key", auth_credential="", is_local=False, public_ip=_HOST_IP313)
    _db313.session.add(r)
    _db313.session.commit()
    _ROWS313["remotes"].append(r.id)
    return r


def _site313(remote, name, domains=(), enabled=False):
    """A site with `domains` [(name, verified, dns_state)], its proxy token encrypted as the panel keeps it."""
    s = _Site313(remote_id=remote.id, name=name, kind="static", state="running", enabled=enabled)
    _db313.session.add(s)
    _db313.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    s.proxy_secret = _enc313("t" * 40)
    for i, (dom, verified, state) in enumerate(domains):
        _db313.session.add(_Dom313(website_id=s.id, domain=dom, is_primary=i == 0, dns_state=state,
                                   verified_at=_dt313.datetime(2026, 1, 1) if verified else None))
    _db313.session.commit()
    return s


def _user313(name, perms, sites=(), customer=False):
    g = _Group313(name="p313-" + name, description="", is_default=False, is_customer=customer)
    g.set_permissions(list(perms))
    g.websites.extend(sites)
    u = _User313(username="p313-" + name, password_hash=os.urandom(8).hex(), display_name=name,
                 is_superadmin=False, is_active=True)
    u.groups.append(g)
    _db313.session.add_all([g, u])
    _db313.session.commit()
    _ROWS313["users"].append(u.id)
    _ROWS313["groups"].append(g.id)
    return u


def _super313():
    u = _User313(username="p313-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db313.session.add(u)
    _db313.session.commit()
    _ROWS313["users"].append(u.id)
    return u


def _dom313(site, name):
    _db313.session.expire_all()
    return _Dom313.query.filter_by(website_id=site.id, domain=name).first()


class _Applied313:
    """The host stand-ins: every proxy apply recorded with the files website-proxy-apply would get."""

    def __init__(self):
        self.applies, self.fail = [], []

    def proxy_apply(self, remote, text, sites=(), proxy=None, start_it=False):
        files = _json313.loads(_sw313.apply_doc(text, sites, proxy))["files"]
        self.applies.append({"text": text, "files": files})
        if self.fail:
            return False, self.fail.pop(0)
        return True, _sw313.OK_APPLIED


def _stub_host313():
    rec = _Applied313()
    for name in ("ports_apply", "proxy_stop", "proxy_status", "site_probe"):
        _p9_patch(_sw313, name, lambda *a, **k: (True, ""))
    _p9_patch(_sw313, "proxy_apply", rec.proxy_apply)
    _SAVED2FA313.append(_p9.config.get("WEBSITES_CUSTOMER_2FA", True))
    _p9.config["WEBSITES_CUSTOMER_2FA"] = False
    return rec


def _resolver313(answers):
    def getaddrinfo(host, *_a, **_k):
        got = answers.get(host)
        if not got:
            raise _socket313.gaierror("no such name")
        return [(None, None, None, "", (a, 0)) for a in got]
    return _NS313(getaddrinfo=getaddrinfo, gaierror=_socket313.gaierror, SOCK_STREAM=_socket313.SOCK_STREAM)


def _cf_address313():
    """An address inside the first IPv4 range of Cloudflare's preset (the signed catalog's list)."""
    net = next(n for n in _dns313.cdn_networks() if n.version == 4)
    return str(net.network_address + 7)


# ── 1. origin_tls is gone ─────────────────────────────────────────────────────────────────────────
def _columns313(table):
    return {c["name"] for c in _inspect313(_db313.engine).get_columns(table)}


def _s1_origin_tls(_st, _rec):
    if "origin_tls" not in _columns313("website_proxy"):
        _db313.session.execute(_text313("ALTER TABLE website_proxy ADD COLUMN origin_tls VARCHAR(12) NOT NULL "
                                        "DEFAULT 'letsencrypt'"))
        _db313.session.commit()
    before = _columns313("website_proxy")
    _models313._run_light_migrations()
    after = _columns313("website_proxy")
    eq("origin_tls: an older database's website_proxy.origin_tls (a choice nothing read) is dropped at start; the "
       "table's other columns stay (control)",
       ("origin_tls" in before, "origin_tls" in after, {"exposure_mode", "tunnel_token_enc", "origin_pull_mtls"} <= after),
       (True, False, True))
    _models313._run_light_migrations()
    eq("origin_tls: a second start finds nothing to drop and changes nothing (control)", _columns313("website_proxy"), after)
    row = _w313.proxy_row(_st.host.id)
    eq("origin_tls: the proxy settings no longer carry it", "origin_tls" in _wpr313.proxy_json(row), False)


# ── 2. one site block per certificate source ─────────────────────────────────────────────────────
def _ns_dom313(name, did, mode="acme", pem="", key=""):
    return _NS313(domain=name, is_primary=did == 1, id=did, verified_at=_dt313.datetime(2026, 1, 1), cert_mode=mode,
                  own_cert_pem=pem, own_key_secret=key)


def _ns_site313(domains):
    return _NS313(id=31, name="mixed", kind="static", account="ws31", port=20031, enabled=True, proxy_secret="x",
                  domains=domains, max_body_mb=8, static_cache=False, custom_rules="[]", page_cache=False,
                  page_cache_ttl=300, access_log=False, raw_proxy_snippet="")


def _heads313(text):
    """Each site block's address line and its tls line."""
    lines = text.split("\n")
    return [(ln, lines[i + 1].strip()) for i, ln in enumerate(lines) if ln.endswith(" {") and not ln.startswith(("\t", "{",
                                                                                                                 "http"))]


# ── 3. the helper prunes certificate files no configuration names ────────────────────────────────
_HSPEC313 = _ilu313.spec_from_loader("panel_helper_p313", _mach313.SourceFileLoader(
    "panel_helper_p313", os.path.join(_root, "tools", "panel-helper")))
_H313 = _ilu313.module_from_spec(_HSPEC313)
_HSPEC313.loader.exec_module(_H313)


def _plain_write313(path, data, _mode, _uid=0, _gid=0):
    with open(path, "wb") as fh:
        fh.write(data)


def _apply_in_tree313(started_rc):
    """do_website_proxy_apply over a scratch tree holding stale files: (rc, the certificate folder after)."""
    d = _tf313.mkdtemp(prefix="p313-helper-")
    names = ("WEB_PROXY_BIN", "WEB_PROXY_ETC", "WEB_PROXY_CERTS", "WEB_PROXY_CONF", "pwd", "_web_write", "_web_listen_ok",
             "_web_validated", "_web_start")
    saved = {n: getattr(_H313, n) for n in names}
    try:
        certs = os.path.join(d, "etc", "certs")
        os.makedirs(certs)
        for name in ("old.p313.example.org.crt", "old.p313.example.org.key", "notes.txt"):
            with open(os.path.join(certs, name), "w", encoding="utf-8") as fh:
                fh.write("x")
        open(os.path.join(d, "caddy"), "wb").close()
        _H313.WEB_PROXY_BIN, _H313.WEB_PROXY_ETC = os.path.join(d, "caddy"), os.path.join(d, "etc")
        _H313.WEB_PROXY_CERTS, _H313.WEB_PROXY_CONF = certs, os.path.join(d, "etc", "Caddyfile")
        _H313.pwd = _NS313(getpwnam=lambda n: _NS313(pw_uid=990, pw_gid=990))
        _H313._web_write, _H313._web_validated = _plain_write313, lambda text, pw: True
        _H313._web_listen_ok = lambda text, pw: (text, ["203.0.113.7"])
        _H313._web_start = lambda old, pw: started_rc
        doc = _json313.dumps({"caddyfile": _H313.WEB_CONF_HEAD + ": p313\n",
                              "files": {"b.p313.example.org.crt": _CHAIN313, "b.p313.example.org.key": _KEYPEM313}})
        with _rout313(_io313.StringIO()), _rerr313(_io313.StringIO()):
            rc = _H313.do_website_proxy_apply(["reload"], doc)
        return rc, sorted(os.listdir(certs))
    finally:
        for n, v in saved.items():
            setattr(_H313, n, v)
        _shutil313.rmtree(d, ignore_errors=True)


# ── 4. your own certificate through the route ────────────────────────────────────────────────────
def _post_cert313(client, site, dom, **body):
    return client.post("/websites/%d/domains/cert" % site.id, json=dict({"id": dom.id}, **body))


def _refusals313():
    """(label, cert PEM, key PEM) each check_for_domain refuses."""
    other_key = _ec_key313()
    return [
        ("a key that is not the certificate's", _CHAIN313, _keypem313(other_key)),
        ("a passphrase key", _CHAIN313, _keypem313(_KEY313, b"p313-phrase")),
        ("an expired certificate", _pem313(_cert313(_KEY313, [_DOMAIN313], start=-100, days=10)), _KEYPEM313),
        ("a certificate not valid yet", _pem313(_cert313(_KEY313, [_DOMAIN313], start=5, days=90)), _KEYPEM313),
        ("another domain's certificate", _pem313(_cert313(_KEY313, ["shop.p313.example.net"])), _KEYPEM313),
        ("a wildcard one label too deep", _pem313(_cert313(_KEY313, ["*.example.org"])), _KEYPEM313),
        ("no subjectAltName", _pem313(_cert313(_KEY313, [], cn=_DOMAIN313)), _KEYPEM313),
        ("malformed PEM", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", _KEYPEM313),
        ("oversize input", _CHAIN313 + "x" * 70000, _KEYPEM313),
    ]


def _notes_for313(st, cert, key):
    r = _post_cert313(_Client313(st.cust.id), st.a, _dom313(st.a, _DOMAIN313), mode="own", cert=cert, key=key)
    return r.status_code, " | ".join(_p9_json(r).get("notes") or [])


_HASH_NOTES313 = _own313._hash_notes


# ── setup and run ─────────────────────────────────────────────────────────────────────────────────
def _state313():
    host = _host313("p313-host")
    _w313.proxy_row(host.id).installed_version = "2.10.2"     # a site goes online only where the web proxy is
    a = _site313(host, "p313-a", [(_DOMAIN313, True, "matching")], enabled=True)
    b = _site313(host, "p313-b", [("other.p313.example.org", True, "matching")])
    c = _site313(host, "p313-c", [("cdn.p313.example.org", True, "cdn")])
    W = _auth313
    st = _NS313(host=host, a=a, b=b, c=c, su=_super313())
    st.cust = _user313("cust", [W.VIEW_WEBSITES, W.MANAGE_WEBSITE], [a], customer=True)
    st.viewer = _user313("viewer", [W.VIEW_WEBSITES], [a], customer=True)
    st.cust_cdn = _user313("admin-c", [W.VIEW_WEBSITES, W.MANAGE_WEBSITE, W.MANAGE_WEBSITES], [c])
    return st


def _cleanup313():
    _db313.session.rollback()
    for model, ids in ((_User313, _ROWS313["users"]), (_Group313, _ROWS313["groups"]), (_Remote313, _ROWS313["remotes"])):
        for i in ids:
            row = _db313.session.get(model, i)
            if row is not None:
                _db313.session.delete(row)
    _db313.session.commit()


def _ran313(step, st, rec):
    """Run one section: None when it ran to the end, else the traceback."""
    import traceback
    try:
        step(st, rec)
        _ran313.last = ""
        return None
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db313.session.rollback()
        _ran313.last = traceback.format_exc()[-1500:]
        return _ran313.last


_ran313.last = ""
_trips313 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part313")
        _rec313 = _stub_host313()
        _st313 = _state313()
        for _step313 in (_s1_origin_tls,):
            check("part313: %s ran to the end" % _step313.__name__, _ran313(_step313, _st313, _rec313) is None, _ran313.last)
        eq("part313: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips313:], [])
    finally:
        _p9_restore_all()
        _p9.config["WEBSITES_CUSTOMER_2FA"] = (_SAVED2FA313 or [True])[0]
        _w313._STATUS.clear()
        _wd313._CERTS_AT.clear()
        _wcert313._ALERTED.clear()
        _wd313._MISSING_SINCE.clear()
        _dns313._LOCAL.update(at=None, addrs=set())
        _cleanup313()
