"""Part 300 of the unit suite: the websites' routes: files, SFTP folders, domains, backups and databases (builder W3).

1. Scope: every /websites/<site_id> route answers 404 to a user with no grant on that site and for a
   site that does not exist, a customer reaches their own site only, and the site's audit rows carry
   its id.
2. Files: the file manager runs as the site's account, held to the document root by its text and by
   where a path resolves on the host (real bash over a scratch home), and counts against the disk.
3. Archives: zip-slip, absolute names, links, devices, a zip bomb, too many entries and a total past
   the free disk are refused before the host sees anything; a plain archive unpacks as the account.
4. Domains and DNS: the allow-list, the panel's own and taken names, and a DNS check with stand-in
   resolvers that refuses private answers; a site goes online only when DNS matches (superadmin aside).
5. SFTP: a site's folder is listed only for a user holding EDIT_WEBSITE_FILES on it, rooted at its
   document root.
6. Secrets: the tunnel token and an app's environment are stored encrypted and never come back or
   reach an audit row; the proxy settings are superadmin only and refuse a bad network.
7. One-click apps: a failing step undoes the finished ones in reverse and leaves no site; a finished
   install shows its admin password once.
8. Backups: an archive holding a link or a path outside the document root is refused on restore.

HOW IT RUNS. part12's app and its database; every host call is a stand-in (ssh_manager.websites, the
proxy renderer, the account guard) and the file operations run in real bash with /home/ws<id> moved
under a scratch folder. Nothing reaches a host (part12's tripwire is armed).
"""
import io as _io300
import json as _json300
import os as _os300
import shutil as _shutil300
import socket as _socket300
import subprocess as _sp300  # nosec B404 - bash runs the panel's own shell text over a scratch home
import tarfile as _tar300
import tempfile as _tmp300
import zipfile as _zf300
from types import SimpleNamespace as _NS300

from flask import g as _g300

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core.config import decrypt_secret as _dec300
from panel.db.models import (AuditLog as _Audit300, GameDatabase as _GDB300, Group as _Group300,
                             RemoteServer as _Remote300, User as _User300, Website as _Site300,
                             WebsiteProxy as _Proxy300, db as _db300)
from panel.ops.ssh_manager import _core as _core300
from panel.ops.ssh_manager import websites as _sw300
from panel.routes import websites as _w300
from panel.routes import websites_apps as _wapps300
from panel.routes import websites_backups as _wbk300
from panel.routes import websites_files as _wfr300
from panel.security import auth as _auth300
from panel.services import sftp_broker as _br300
from panel.services import website_backup as _wb300
from panel.services import website_dns as _dns300
from panel.services import website_files as _wf300
from panel.services import websites as _svc300
from panel.services import websites_proxy as _wp300

_TREE300 = _tmp300.mkdtemp(prefix="lgsm-unit-p300-")
_ROWS300 = {"remotes": [], "users": [], "groups": []}
_HOST_IP300 = "11.22.33.44"


class _Inline300:
    """threading.Thread stand-in: runs its target at start(), in the caller."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}
        self.daemon = daemon

    def start(self):
        self._t(*self._a, **self._k)


def _bash300(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
    """shell_as_game_user, run by real bash with /home/<user> moved under this part's tree."""
    feed = None
    if stdin_text is not None:
        feed = stdin_text if isinstance(stdin_text, (bytes, str)) else b"".join(
            c if isinstance(c, bytes) else c.encode() for c in stdin_text)
        feed = feed.encode() if isinstance(feed, str) else feed
    text = sh.replace("/home/%s" % user, _TREE300 + "/home/%s" % user)
    if "~" in text or "/home/%s" % user not in sh:
        return "", "part300: refusing a command that does not name the scratch home", 99
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp300.run(["bash", "-c", text], input=feed, capture_output=True, timeout=timeout,  # nosec B603 B607
                   check=False)
    return r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), r.returncode


class _Client300:
    """A test client for `uid` that never reuses another request's signed-in user.

    The part runs inside one app context, which every request shares, and flask-login keeps the user
    it loaded in that context's `g`: without dropping it, each request would run as the first one's user.
    """

    def __init__(self, uid):
        self.c = _p9_client(uid)

    def get(self, *a, **k):
        _g300.pop("_login_user", None)
        return self.c.get(*a, **k)

    def post(self, *a, **k):
        _g300.pop("_login_user", None)
        return self.c.post(*a, **k)


def _home300(site):
    return _TREE300 + "/home/" + site.account


def _docroot300(site):
    return _home300(site) + "/site/html"


def _stub_host300():
    """Every host call a stand-in that succeeds, recorded; files in real bash; no thread started."""
    calls = []

    def rec(name, result=(True, "ok")):
        def fn(*a, **k):
            calls.append((name, a[1].id if len(a) > 1 and hasattr(a[1], "id") else None))
            return result
        return fn
    for name in ("install", "start", "stop", "remove", "site_probe", "proxy_install", "proxy_apply",
                 "proxy_stop", "proxy_status", "ports_apply", "tunnel_apply", "egress_guard", "quota_set",
                 "php_apply", "php_effective", "cache_purge", "app_build", "env_apply", "app_install_step",
                 "app_undo_step"):
        _p9_patch(_sw300, name, rec(name))
    _p9_patch(_wp300, "render", lambda sites, proxy=None: "# %d sites" % len(sites))
    _p9_patch(_wp300, "rules_problems", lambda rules: [])
    _p9_patch(_svc300, "php_ini_problems", lambda text: [] if "extension" not in text else ["no extension="])
    for mod in (_wfr300, _wbk300):
        _p9_patch(mod, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_core300, "shell_as_game_user", _bash300)
    _p9_patch(_w300, "threading", _NS300(Thread=_Inline300))
    from panel.routes import databases as _dbr300
    _p9_patch(_dbr300, "host_state", lambda remote, may_probe=False: ("unknown", None, {}))
    return calls


def _host300(name, public_ip=_HOST_IP300):
    r = _Remote300(name=name, host="198.51.100.%d" % (len(_ROWS300["remotes"]) + 30), port=22, username="u",
                   auth_method="key", auth_credential="", is_local=False, public_ip=public_ip)
    _db300.session.add(r)
    _db300.session.commit()
    _ROWS300["remotes"].append(r.id)
    return r


def _site300(remote, name, kind="static", **kw):
    s = _Site300(remote_id=remote.id, name=name, kind=kind, state="running", **kw)
    _db300.session.add(s)
    _db300.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db300.session.commit()
    _shutil300.rmtree(_home300(s), ignore_errors=True)
    _os300.makedirs(_docroot300(s))
    _os300.makedirs(_home300(s) + "/panel-websites")
    return s


def _user300(name, perms, sites=(), customer=False, hosts=()):
    g = _Group300(name="p300-" + name, description="", is_default=False, is_customer=customer)
    g.set_permissions(list(perms))
    g.websites.extend(sites)
    g.servers.extend(hosts)
    u = _User300(username="p300-" + name, password_hash=_os300.urandom(8).hex(), display_name=name,
                 is_superadmin=False, is_active=True)
    u.groups.append(g)
    _db300.session.add_all([g, u])
    _db300.session.commit()
    _ROWS300["users"].append(u.id)
    _ROWS300["groups"].append(g.id)
    return u


def _super300():
    u = _User300(username="p300-super", password_hash=_os300.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db300.session.add(u)
    _db300.session.commit()
    _ROWS300["users"].append(u.id)
    return u


# ── 1. Scope ────────────────────────────────────────────────────────────────────────────────────
def _site_rules300():
    """(rule, method) of every /websites/<site_id> route."""
    out = []
    for rule in _p9.url_map.iter_rules():
        if "<int:site_id>" in rule.rule:
            for m in sorted((rule.methods or set()) - {"HEAD", "OPTIONS"}):
                out.append((rule.rule, m))
    return out


def _call300(client, rule, method, site_id):
    url = rule.replace("<int:site_id>", str(site_id)).replace("<int:db_id>", "1")
    return client.get(url) if method == "GET" else client.post(url, json={"confirm": "x", "name": "x", "path": ""})


def _s1_scope(st):
    rules = _site_rules300()
    check("scope: the website routes were found to check (at least 40 per-site routes)", len(rules) >= 40,
          "found %d" % len(rules))
    cust = _Client300(st.cust_a.id)
    leaks = [(r, m, resp.status_code) for r, m in rules
             for resp in (_call300(cust, r, m, st.b.id),) if resp.status_code != 404]
    eq("scope: a customer of site A gets 404 from every per-site route of site B", leaks, [])
    gone = [(r, m, resp.status_code) for r, m in rules
            for resp in (_call300(_Client300(st.su.id), r, m, 10 ** 8),) if resp.status_code != 404]
    eq("scope: every per-site route answers 404 for a site that does not exist, even to a superadmin", gone, [])
    nogrant = _Client300(st.nobody.id)
    leaks2 = [(r, m) for r, m in rules if _call300(nogrant, r, m, st.a.id).status_code != 404]
    eq("scope: a user holding every website permission through a group with no sites gets 404 everywhere",
       leaks2, [])
    ok = cust.get("/api/websites/%d" % st.a.id)
    eq("scope: the customer still reaches their own site (control)", (ok.status_code, (_p9_json(ok).get("site") or {}).get("name")),
       (200, st.a.name))
    listed = [s["name"] for s in _p9_json(cust.get("/api/websites")).get("sites", [])]
    eq("scope: the customer's list holds their site only, with no admin fields", (listed, "mem_mb" in str(
        _p9_json(cust.get("/api/websites")))), ([st.a.name], False))
    view_only = _Client300(st.viewer_a.id)
    eq("scope: VIEW_WEBSITES alone does not start a site (404), MANAGE_WEBSITE does (200)",
       (view_only.post("/websites/%d/start" % st.a.id).status_code,
        cust.post("/websites/%d/start" % st.a.id).status_code), (404, 200))
    row = _Audit300.query.filter_by(action="website_start").order_by(_Audit300.id.desc()).first()
    eq("scope: the start's audit row names the site and carries its id (website_id)",
       (row.target, row.website_id, row.username), (st.a.name, st.a.id, st.cust_a.username))


# ── 2. Files ────────────────────────────────────────────────────────────────────────────────────
def _s2_files(st):
    c = _Client300(st.cust_a.id)
    base = "/websites/%d/files/" % st.a.id
    up = c.post(base + "upload", data={"path": "", "file": (_io300.BytesIO(b"<?php echo 1;"), "index.php")},
                content_type="multipart/form-data")
    eq("files: an upload lands in the document root as the site's file (control)",
       (up.status_code, open(_docroot300(st.a) + "/index.php", "rb").read()), (200, b"<?php echo 1;"))
    out = c.post(base + "upload", data={"path": "../panel-websites", "file": (_io300.BytesIO(b"x"), "site.json")},
                 content_type="multipart/form-data")
    eq("files: an upload to ../panel-websites is refused by its text (400) and writes nothing",
       (out.status_code, _os300.listdir(_home300(st.a) + "/panel-websites")), (400, []))
    _os300.symlink("../../panel-websites", _docroot300(st.a) + "/conf")
    save = c.post(base + "save", json={"path": "conf/site.json", "content": "{}"})
    listing = c.get(base + "list?path=conf")
    eq("files (real bash): a save and a listing through a link out of the document root are refused on the "
       "host, and nothing is written there",
       (_p9_json(save).get("success"), listing.status_code, _os300.listdir(_home300(st.a) + "/panel-websites")),
       (False, 400, []))
    _os300.unlink(_docroot300(st.a) + "/conf")
    eq("files: deleting or renaming the document root itself is refused",
       (c.post(base + "delete", json={"path": ""}).status_code, c.post(base + "rename", json={"path": "/", "name": "x"}).status_code),
       (400, 400))
    _os300.makedirs(_docroot300(st.a) + "/sub")
    lst = _p9_json(c.get(base + "list?path="))
    eq("files: the listing shows the document root's own entries, its path relative to it (control)",
       (lst.get("path"), sorted(e["name"] for e in lst.get("entries", []))), ("", ["index.php", "sub"]))
    st.a.disk_mb = 1
    _db300.session.commit()
    big = c.post(base + "upload", data={"path": "", "file": (_io300.BytesIO(b"z" * (2 * 1024 * 1024)), "big.bin")},
                 content_type="multipart/form-data")
    eq("files: an upload larger than the site's free disk is refused and not written",
       (big.status_code in (413, 507), _os300.path.exists(_docroot300(st.a) + "/big.bin")), (True, False))
    st.a.disk_mb = 2048
    _db300.session.commit()
    _p9_patch(_wfr300, "game_account_write_refusal", lambda *a, **k: "that account can become root")
    held = c.post(base + "mkdir", json={"path": "", "name": "held"})
    eq("files: a site account the host says can become root is never written as (409, nothing made)",
       (held.status_code, _os300.path.exists(_docroot300(st.a) + "/held")), (409, False))
    _p9_patch(_wfr300, "game_account_write_refusal", lambda *a, **k: None)


# ── 3. Archives ─────────────────────────────────────────────────────────────────────────────────
def _zip300(entries):
    buf = _io300.BytesIO()
    with _zf300.ZipFile(buf, "w", _zf300.ZIP_DEFLATED) as z:
        for name, data, mode in entries:
            info = _zf300.ZipInfo(name)
            info.external_attr = mode << 16
            info.compress_type = _zf300.ZIP_DEFLATED
            z.writestr(info, data)
    buf.seek(0)
    return buf


def _tgz300(members):
    buf = _io300.BytesIO()
    with _tar300.open(fileobj=buf, mode="w:gz") as t:
        for name, typ, data in members:
            info = _tar300.TarInfo(name)
            info.type = typ
            if typ == _tar300.SYMTYPE or typ == _tar300.LNKTYPE:
                info.linkname = "/etc/passwd"
            info.size = len(data)
            t.addfile(info, _io300.BytesIO(data) if typ == _tar300.REGTYPE else None)
    buf.seek(0)
    return buf


def _refused300(fh, room=10 ** 9):
    """The refusal sentence, or None when the archive was taken (or the check crashed instead of refusing)."""
    try:
        out, _n = _wf300.repack(fh, room)
    except _wf300.ArchiveRefused as exc:
        return str(exc)
    except Exception:  # noqa: BLE001 - a crash is not a refusal: the page would get a 500, not the sentence
        return None
    out.close()
    return None


def _s3_archives(st):
    reg, sym = 0o100644, 0o120777
    cases = {
        "zip-slip": _zip300([("../evil.php", b"x", reg)]),
        "absolute": _zip300([("/etc/cron.d/x", b"x", reg)]),
        "zip symlink": _zip300([("link", b"/etc/passwd", sym)]),
        "tar symlink": _tgz300([("link", _tar300.SYMTYPE, b"")]),
        "tar hardlink": _tgz300([("hard", _tar300.LNKTYPE, b"")]),
        "tar device": _tgz300([("dev", _tar300.CHRTYPE, b"")]),
        "tar fifo": _tgz300([("fifo", _tar300.FIFOTYPE, b"")]),
        "tar dotdot": _tgz300([("a/../../b", _tar300.REGTYPE, b"x")]),
        "bomb": _zip300([("zeros.bin", b"\0" * (8 * 1024 * 1024), reg)]),
        "not an archive": _io300.BytesIO(b"hello, not an archive at all"),
    }
    got = {k: _refused300(v) is not None for k, v in cases.items()}
    eq("archives: zip-slip, an absolute name, zip and tar links, a hard link, a device, a fifo, '..', a zip "
       "bomb and a non-archive are each refused", [k for k, v in got.items() if not v], [])
    eq("archives: an archive unpacking to more than the free disk is refused",
       _refused300(_zip300([("a.bin", _os300.urandom(4096), reg)]), room=1024) is not None, True)
    saved = _wf300.MAX_ENTRIES
    _wf300.MAX_ENTRIES = 3
    try:
        many = _refused300(_zip300([("f%d" % i, b"x", reg) for i in range(5)]))
    finally:
        _wf300.MAX_ENTRIES = saved
    eq("archives: more entries than the cap are refused", many is not None, True)
    ok = _zip300([("wp/", b"", 0o40755), ("wp/index.php", b"<?php", reg), ("wp/a/b/c.txt", b"deep", reg)])
    c = _Client300(st.cust_a.id)
    r = c.post("/websites/%d/files/extract" % st.a.id, data={"path": "", "file": (ok, "site.zip")},
               content_type="multipart/form-data")
    eq("archives (real bash): a plain zip unpacks into the document root with its folders (control)",
       (r.status_code, open(_docroot300(st.a) + "/wp/a/b/c.txt", "rb").read()), (200, b"deep"))
    bad = c.post("/websites/%d/files/extract" % st.a.id, data={"path": "", "file": (_zip300([("../evil.php", b"x", reg)]),
                                                                                   "evil.zip")},
                 content_type="multipart/form-data")
    eq("archives: through the route a zip-slip archive is refused (422) and nothing lands beside the "
       "document root", (bad.status_code, _os300.path.exists(_home300(st.a) + "/site/evil.php")), (422, False))
    row = _Audit300.query.filter_by(action="website_files_extract", success=False).order_by(_Audit300.id.desc()).first()
    check("archives: the refusal is audited against the site", row is not None and row.website_id == st.a.id)


# ── 4. Domains and DNS ──────────────────────────────────────────────────────────────────────────
def _resolver300(answers):
    def getaddrinfo(host, *_a, **_k):
        got = answers.get(host)
        if not got:
            raise _socket300.gaierror("no such name")
        return [(None, None, None, "", (a, 0)) for a in got]
    return _NS300(getaddrinfo=getaddrinfo, gaierror=_socket300.gaierror, SOCK_STREAM=_socket300.SOCK_STREAM)


def _s4_domains(st):
    eq("dns: classify refuses private, loopback, link-local, tailnet and mapped-private answers",
       [_dns300.classify([a], {_HOST_IP300}) for a in ("10.0.0.5", "127.0.0.1", "169.254.1.1", "100.100.1.1",
                                                       "::ffff:192.168.1.1", "fe80::1")], ["private"] * 6)
    eq("dns: matching, mismatch and no answer (controls)",
       [_dns300.classify([_HOST_IP300], {_HOST_IP300}), _dns300.classify(["11.22.33.45"], {_HOST_IP300}),
        _dns300.classify([], {_HOST_IP300})], ["matching", "mismatch", "failed"])
    c = _Client300(st.cust_a.id)
    add = "/websites/%d/domains/add" % st.a.id
    bad = [c.post(add, json={"domain": d}).status_code for d in ("10.0.0.1", "*.example.org", "localhost",
                                                                 "a.internal", "x.ts.net", "nodot", "a..b.org")]
    eq("domains: an IP, a wildcard, reserved names and malformed names are refused (400)", bad, [400] * 7)
    _p9_patch(_dns300, "socket", _resolver300({"shop.example.org": [_HOST_IP300], "lan.example.org": ["192.168.0.9"]}))
    got = _p9_json(c.post(add, json={"domain": "Shop.Example.Org"}))
    eq("domains: a public name is stored lowercase and its DNS checked as matching (control)",
       (got.get("success"), got.get("domain"), got.get("dns_state")), (True, "shop.example.org", "matching"))
    lan = _p9_json(c.post(add, json={"domain": "lan.example.org"}))
    eq("domains: a name resolving to a private address is marked private", lan.get("dns_state"), "private")
    taken = _Client300(st.su.id).post("/websites/%d/domains/add" % st.b.id, json={"domain": "shop.example.org"})
    eq("domains: a name another site has is refused (409)", taken.status_code, 409)
    from panel.core import config as _cfg300
    _cfg300.update_config(lambda cfg: cfg.update(site_domain="panel.example.org:8443"))
    own = _Client300(st.su.id).post("/websites/%d/domains/add" % st.b.id, json={"domain": "panel.example.org"})
    eq("domains: the panel's own name is refused (409)", own.status_code, 409)
    _cfg300.update_config(lambda cfg: cfg.pop("site_domain", None))
    admin = _Client300(st.admin.id)
    refused = admin.post("/websites/%d/enable" % st.a.id)
    eq("online: a site with a domain whose DNS is private does not go online for an administrator (409)",
       (refused.status_code, _db300.session.get(_Site300, st.a.id).enabled), (409, False))
    _db300.session.expire_all()
    over = _Client300(st.su.id).post("/websites/%d/enable" % st.a.id)
    _db300.session.expire_all()
    row = _Audit300.query.filter_by(action="website_enable").order_by(_Audit300.id.desc()).first()
    eq("online: a superadmin may put it online anyway, and the audit row says DNS did not match",
       (over.status_code, _db300.session.get(_Site300, st.a.id).enabled, "not matching" in (row.detail if row else "")),
       (200, True, True))
    _Client300(st.su.id).post("/websites/%d/disable" % st.a.id)


# ── 5. SFTP ─────────────────────────────────────────────────────────────────────────────────────
def _s5_sftp(st):
    with _p9.test_request_context("/"):
        mine = _br300.site_folders(_db300.session.get(_User300, st.cust_a.id))
        none = _br300.site_folders(_db300.session.get(_User300, st.viewer_a.id))
        clash = _br300.site_folders(_db300.session.get(_User300, st.cust_a.id), taken={st.a.name: object()})
    eq("sftp: a customer with EDIT_WEBSITE_FILES on site A gets site A's folder only; a viewer gets none",
       (sorted(mine), sorted(none)), ([st.a.name], []))
    eq("sftp: a site folder whose name a game server's folder has is renamed, not merged",
       sorted(clash), ["%s (website)" % st.a.name])
    d = _br300.describe_site(st.a)
    eq("sftp: the folder is rooted at the site's document root, as its own account, with a website sid",
       (d["home"], d["user"], d["sid"]), ("/home/%s/site/html" % st.a.account, st.a.account, "w%d" % st.a.id))


# ── 6. Secrets ──────────────────────────────────────────────────────────────────────────────────
def _s6_secrets(st):
    token = "p300-tunnel-value-" + "q" * 24
    url = "/websites/proxy/settings?remote_id=%d" % st.host.id
    eq("proxy settings: an administrator below superadmin is refused",
       _Client300(st.admin.id).post(url, json={"exposure_mode": "tunnel"}).status_code in (302, 403, 404), True)
    su = _Client300(st.su.id)
    bad = su.post(url, json={"exposure_mode": "restricted", "allow_cidrs": ["203.0.113.0/24", "not-a-net"]})
    eq("proxy settings: a bad network in the allow list is refused and nothing is stored",
       (bad.status_code, _Proxy300.query.filter_by(remote_id=st.host.id).first() is None
        or _Proxy300.query.filter_by(remote_id=st.host.id).first().exposure_mode), (400, "public"))
    good = su.post("/websites/proxy/settings", json={"host_id": st.host.id, "exposure": {
        "exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": token}})
    row = _Proxy300.query.filter_by(remote_id=st.host.id).first()
    audit = _Audit300.query.filter_by(action="website_proxy_settings").order_by(_Audit300.id.desc()).first()
    eq("proxy settings: the tunnel token is stored encrypted, never echoed and never in the audit row",
       (good.status_code, row.exposure_mode, token in (row.tunnel_token_enc or ""), _dec300(row.tunnel_token_enc),
        token in good.get_data(as_text=True), token in (audit.detail or ""), _p9_json(good)["proxy"]["tunnel_token_set"]),
       (200, "tunnel", False, token, False, False, True))
    app_site = _site300(st.host, "p300-node", kind="app")
    st.cust_a.groups[0].websites.append(app_site)
    _db300.session.commit()
    c = _Client300(st.cust_a.id)
    env = {"GREETING": "hello-p300-value", "NODE_ENV": "production"}
    url = "/websites/%d/app" % app_site.id
    saved = c.post(url, json={"env": env})
    kept = c.post(url, json={"env": {"GREETING": None}, "env_remove": ["NODE_ENV"]})
    _db300.session.expire_all()
    stored = _db300.session.get(_Site300, app_site.id).env_enc
    rows = _Audit300.query.filter_by(action="website_app", website_id=app_site.id).all()
    names = (_p9_json(c.get("/api/websites/%d" % app_site.id)).get("app") or {}).get("env_names")
    eq("app env: values are stored encrypted, a null keeps the saved value, a removal drops one, only names "
       "come back, and no value reaches an audit row",
       (saved.status_code, kept.status_code, "hello-p300-value" in stored, _json300.loads(_dec300(stored)), names,
        any("hello-p300-value" in (a.detail or "") for a in rows)),
       (200, 200, False, {"GREETING": "hello-p300-value"}, ["GREETING"], False))
    eq("app env: a name that is not a variable name, or a value with a newline, is refused",
       [c.post(url, json={"env": e}).status_code for e in ({"BAD-NAME": "x"}, {"OK": "a\nb"})], [400, 400])
    eq("app settings: someone who runs the site but does not administer it cannot change its start command (404)",
       c.post(url, json={"start_command": "node evil.js"}).status_code, 404)
    opts = su.post("/websites/proxy/settings", json={"options": {"hsts_max_age": 300, "tls_min": "1.0"}})
    fine = su.post("/websites/proxy/settings", json={"options": {"hsts_max_age": 300, "tls_min": "1.3", "require_2fa": False}})
    from panel.core.config import load_config as _lc300
    eq("global options: a TLS minimum other than 1.2 or 1.3 is refused; an HSTS age under OWASP's is saved "
       "(a note on the page, never a block); the customers' 2FA switch is the key the sign-in guard reads",
       (opts.status_code, fine.status_code, _lc300().get("websites_hsts_max_age"), _lc300().get("websites_tls_min"),
        _lc300().get("websites_customer_2fa")), (400, 200, 300, "1.3", False))
    from panel.core import config as _cfg300
    _cfg300.update_config(lambda cfg: [cfg.pop(k, None) for k in list(cfg) if k.startswith("websites_")])


# ── 7. One-click apps ───────────────────────────────────────────────────────────────────────────
def _s7_apps(st, calls):
    from panel.services import websites_catalog as _cat300
    _p9_patch(_cat300, "recipes", lambda: {"wordpress": {"kind": "wordpress", "version": "6.8.3"}})
    steps = [{"name": "download", "type": "download-verify-unpack"}, {"name": "db", "type": "create-database"},
             {"name": "config", "type": "render-config"}, {"name": "install", "type": "run-in-container"}]
    _p9_patch(_svc300, "recipe_steps", lambda recipe: [dict(s) for s in steps])
    from panel.routes import databases_sites as _ds300
    made = []

    def fake_create(site, slug):
        row = _GDB300(remote_id=site.remote_id, website_id=site.id, name="ws%d_%s" % (site.id, slug), secret="")
        _db300.session.add(row)
        _db300.session.commit()
        made.append(row.name)
        return True, "made", row, "db-pw-p300"

    def fake_drop(site, row):
        _db300.session.delete(row)
        _db300.session.commit()
        return True, "dropped"
    _p9_patch(_ds300, "create_for", fake_create)
    _p9_patch(_ds300, "drop", fake_drop)
    seen_secrets = []

    def step(remote, site, s):
        seen_secrets.append(sorted((s.get("secrets") or {}).keys()))
        return (False, "the installer failed") if s["name"] == "install" else (True, "ok")
    _p9_patch(_sw300, "app_install_step", step)
    undone = []
    _p9_patch(_sw300, "app_undo_step", lambda remote, site, s: undone.append(s["name"]) or (True, "ok"))
    del calls[:]
    su = _Client300(st.su.id)
    form = {"app": "wordpress", "name": "p300-wp", "remote_id": st.host.id, "admin_user": "siteowner",
            "admin_email": "owner@example.org"}
    r = su.post("/websites/install-app", json=form)
    _db300.session.expire_all()
    eq("apps: a failing step undoes the finished ones in reverse (config, download), drops the database, "
       "removes the container and account, and leaves no site row",
       (r.status_code, undone, _GDB300.query.filter(_GDB300.name.like("ws%_app")).count(),
        ("remove", _p9_json(r).get("id")) in calls, _Site300.query.filter_by(name="p300-wp").count()),
       (200, ["config", "download"], 0, True, 0))
    check("apps: the admin password reached the install steps (secrets on the step, for stdin)",
          ["admin_email", "admin_password", "admin_user"] in seen_secrets or any(
              "admin_password" in s for s in seen_secrets), repr(seen_secrets))
    _p9_patch(_sw300, "app_install_step", lambda remote, site, s: (True, "ok"))
    r2 = su.post("/websites/install-app", json=dict(form, name="p300-wp2"))
    sid = _p9_json(r2).get("id")
    pw = _p9_json(r2).get("password") or ""
    status = su.get("/api/websites/%d" % sid)
    rows = _Audit300.query.filter(_Audit300.website_id == sid).all()
    eq("apps: the generated admin password is in the starting answer only (no-store), never in the site's "
       "status or an audit row; the install reads as done",
       (len(pw) >= 20, r2.headers.get("Cache-Control"), pw in status.get_data(as_text=True),
        any(pw in (a.detail or "") for a in rows), (_p9_json(status).get("install") or {}).get("state")),
       (True, "no-store", False, False, "done"))
    weak = su.post("/websites/install-app", json=dict(form, name="p300-wp3", admin_password="short"))
    typed = su.post("/websites/install-app", json=dict(form, name="p300-wp4", admin_password="a-typed-password-p300"))
    eq("apps: a typed admin password under 15 characters is refused; a typed one is never echoed back",
       (weak.status_code, typed.status_code, _p9_json(typed).get("password")), (400, 200, ""))


# ── 8. Backups ──────────────────────────────────────────────────────────────────────────────────
def _s8_backups(st):
    lines = ['-rw-r--r-- u/u 5 2026-11-26 10:00 "site/html/index.php"',
             'drwxr-xr-x u/u 0 2026-11-26 10:00 "site/html/"',
             'lrwxrwxrwx u/u 0 2026-11-26 10:00 "site/html/x" -> "/etc/passwd"',
             '-rw-r--r-- u/u 5 2026-11-26 10:00 "site/panel-websites/site.json"',
             '-rw-r--r-- u/u 5 2026-11-26 10:00 "site/html/../../.ssh/authorized_keys"',
             'hrw-r--r-- u/u 0 2026-11-26 10:00 "site/html/h" link to "site/html/index.php"']
    eq("backups: a restore accepts plain files and folders under site/html and refuses a link, a hard link, "
       "a path outside it and '..'", [_wb300.entry_problem(ln) is None for ln in lines],
       [True, True, False, False, False, False])
    _os300.makedirs(_home300(st.b) + "/site/backups", exist_ok=True)
    name = "backup-20261126-100000.tar.gz"
    with _tar300.open(_home300(st.b) + "/site/backups/" + name, "w:gz") as t:
        info = _tar300.TarInfo("site/html/evil")
        info.type, info.linkname = _tar300.SYMTYPE, "/etc/passwd"
        t.addfile(info)
    open(_docroot300(st.b) + "/keep.txt", "w").write("kept")
    r = _Client300(st.su.id).post("/websites/%d/backups/restore" % st.b.id, json={"name": name})
    eq("backups (real tar): restoring a backup holding a link is refused (422) and the document root is "
       "left as it was", (r.status_code, sorted(_os300.listdir(_docroot300(st.b)))), (422, ["keep.txt"]))
    made = _Client300(st.su.id).post("/websites/%d/backups/create" % st.b.id)
    listed = _p9_json(_Client300(st.su.id).get("/websites/%d/backups/list" % st.b.id)).get("backups", [])
    eq("backups (real tar): back up now makes a .tar.gz of the document root, listed newest first (control)",
       (made.status_code, len(listed) >= 2 and listed[0]["name"] > listed[-1]["name"]), (200, True))
    good = listed[0]["name"]
    _os300.remove(_docroot300(st.b) + "/keep.txt")
    back = _Client300(st.su.id).post("/websites/%d/backups/restore" % st.b.id, json={"name": good})
    eq("backups (real tar): restoring it puts the file back (control)",
       (back.status_code, open(_docroot300(st.b) + "/keep.txt").read()), (200, "kept"))


# ── 9. Every sentence the routes say is translated ─────────────────────────────────────────────
# The argument each call takes its viewer's sentence in (acted's fifth is the audit row's detail, in English).
_SAYS300 = {"say": 1, "done": 1, "acted": 3, "Sentence": 0, "tr": 0}


def _sentences300():
    """The sentences the website modules show: S_* constants, and literals handed to say/done/Sentence/tr."""
    import ast
    from unit import REPO_ROOT
    files = [_os300.path.join(REPO_ROOT, "panel", d, f) for d in ("routes", "services")
             for f in sorted(_os300.listdir(_os300.path.join(REPO_ROOT, "panel", d)))
             if f.startswith(("websites", "website_")) or f == "databases_sites.py"]
    out = set()
    for path in files:
        for n in ast.walk(ast.parse(open(path, encoding="utf-8").read())):
            if (isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
                    and any(isinstance(t, ast.Name) and t.id.startswith("S_") for t in n.targets)):
                out.add(n.value.value)
            elif isinstance(n, ast.Call) and getattr(n.func, "attr", getattr(n.func, "id", "")) in _SAYS300:
                at = _SAYS300[getattr(n.func, "attr", getattr(n.func, "id", ""))]
                arg = n.args[at] if len(n.args) > at else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and " " in arg.value:
                    out.add(arg.value)
    return files, {t for t in out if "%" not in t}


def _s9_i18n(_st):
    from unit import REPO_ROOT
    files, said = _sentences300()
    missing = {}
    for lang in ("es", "fr"):
        keys = set()
        folder = _os300.path.join(REPO_ROOT, "panel", "translations", lang)
        for f in _os300.listdir(folder):
            if f.endswith(".json"):
                keys |= set(_json300.load(open(_os300.path.join(folder, f), encoding="utf-8")))
        missing[lang] = sorted(t for t in said if t not in keys)
    check("i18n: the website modules' sentences were found to check (a floor, not an inventory)",
          len(files) >= 14 and len(said) >= 70, "%d files, %d sentences" % (len(files), len(said)))
    eq("i18n: every sentence the website routes say is in the es and fr catalogs", missing, {"es": [], "fr": []})


def _state300():
    host = _host300("p300-host")
    a, b = _site300(host, "p300-a", kind="php"), _site300(host, "p300-b")
    W = _auth300
    st = _NS300(host=host, a=a, b=b, su=_super300())
    st.cust_a = _user300("cust", [W.VIEW_WEBSITES, W.EDIT_WEBSITE_FILES, W.MANAGE_WEBSITE], [a], customer=True)
    st.viewer_a = _user300("viewer", [W.VIEW_WEBSITES], [a], customer=True)
    st.nobody = _user300("nobody", list(W.WEBSITES_PAGE_PERMS))
    st.admin = _user300("admin", [W.VIEW_WEBSITES, W.MANAGE_WEBSITES, W.MANAGE_WEBSITE], [a, b])
    return st


def _cleanup300():
    _db300.session.rollback()
    for model, ids in ((_User300, _ROWS300["users"]), (_Group300, _ROWS300["groups"]), (_Remote300, _ROWS300["remotes"])):
        for i in ids:
            row = _db300.session.get(model, i)
            if row is not None:
                _db300.session.delete(row)
    _db300.session.commit()
    _shutil300.rmtree(_TREE300, ignore_errors=True)


def _ran300(step, st, calls):
    """Run one section: None when it ran to the end, else the traceback (kept in _ran300.last)."""
    import traceback
    try:
        if step is _s7_apps:
            step(st, calls)
        else:
            step(st)
        _ran300.last = ""
        return None
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db300.session.rollback()
        _ran300.last = traceback.format_exc()[-1500:]
        return _ran300.last


_ran300.last = ""
_trips300 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part300")
        _calls300 = _stub_host300()
        _st300 = _state300()
        for _step300 in (_s1_scope, _s2_files, _s3_archives, _s4_domains, _s5_sftp, _s6_secrets, _s7_apps,
                         _s8_backups, _s9_i18n):
            check("part300: %s ran to the end" % _step300.__name__, _ran300(_step300, _st300, _calls300) is None,
                  _ran300.last)
        eq("part300: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips300:], [])
    finally:
        _p9_restore_all()
        _w300._STATUS.clear()
        _wapps300._JOBS.clear()
        _cleanup300()
