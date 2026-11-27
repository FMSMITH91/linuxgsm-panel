"""Part 321 of the unit suite: CI's apt step, the tunnel's closed ports, a stopped database server, website bans.

1. CI: the unit legs' apt step takes the runner image's own packages.microsoft.com source out of apt's list before
   `apt-get update` (that repository answered 403 and failed the whole leg), and only that source; the step's own
   loop is run over a scratch sources folder.
2. Tunnel mode closes ports 80 and 443 whatever becomes of the tunnel: a token the provider refuses ended the apply
   before its firewall step, and the public rules stayed open while the saved mode said tunnel. The answer says so.
3. A database server the panel set up and that stopped since: an app install and a site's database create ask the
   host again instead of trusting the row's "ready" (up to 10 minutes old), so they are refused with the Start
   button's entry before anything is made, and the add dialog's list shows that entry at once.
5. One certificate per SITE: pasted once, used for each of the site's domains it covers (a name and its wildcard
   both), the others kept automatic with the reason; a domain added later that it covers uses it; one Back to
   automatic; the proxy serves the covered names from one block with one pair of files; per-domain certificates of
   before move to their site (data migration 5).
6. Blocked visitors (fail2ban for the websites, the ban kept inside the web proxy): every site block refuses an
   address in the deny list first, by the proxy's own client_ip (the trusted-proxy rules), and sends only the watched
   requests (sign-in POSTs, scanner paths, the site's denied paths) to the security log, tagged; nothing else is
   logged. The helper's jails read that tag and the visitor's address, never a CDN's: a client banned behind
   Cloudflare gets its deny entry, a Cloudflare address never does. Public mode adds the firewall ban. A site's list
   shows only its own, Unblock lifts one (audited), every ban event is audited, and the host card's settings carry
   OWASP's words with a note outside them.
4. WordPress's Site Health page cache test answers from the web proxy's real state: each proxy apply writes, into
   every WordPress site's files, whether the configuration it runs caches that site's pages (and for how long), and
   the loopback plugin replaces WordPress's own test (which looks for caching headers on requests that never pass
   the proxy) with one reading that word. The page cache's block also takes away the empty Cache-Control header the
   cache module put on a page whose site sent none, and only that one.

HOW IT RUNS. part12's app and its database for the routes; every host call at ssh_manager's seams (part12's
tripwire is armed, so nothing reaches a host). The workflow is read as text (part06's run-block reader).
"""
import os
import shutil as _shutil321
import subprocess as _sp321  # nosec B404 - bash over the workflow's own loop, in a scratch folder
import tempfile as _tf321
from types import SimpleNamespace as _NS321

from flask import g as _g321

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg321
from panel.core.clock import utcnow as _utcnow321
from panel.db.models import (HostDatabaseServer as _HDS321, RemoteServer as _Remote321, User as _User321,
                             Website as _Site321, WebsiteDomain as _Dom321, WebsiteProxy as _Proxy321, db as _db321)
from panel.ops.ssh_manager import databases as _dbs321
from panel.ops.ssh_manager import websites as _sw321
from panel.routes import databases as _dbr321
from panel.routes import websites as _w321
from panel.routes import websites_apps as _wapps321
from panel.routes import websites_view as _wview321

_TOKEN321 = "k" * 40
_ROWS321 = {"sites": [], "remotes": [], "users": []}
_REC321 = {"ports": [], "apply": []}
# The sentence a failed tunnel-mode apply ends with, pinned as written (a revert of the fix has no such name).
_CLOSED321 = "Ports 80 and 443 are closed: in tunnel mode visitors come in only through the tunnel."
_REAL_APPLY321 = _sw321.proxy_apply      # the real apply for section 4; section 2's seams stub it
_STOPPED321 = {"state": "unsupported", "detail": "stopped", "flavor": "mariadb"}


class _Client321:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.get(*a, **k)


class _Inline321:
    """threading.Thread that runs its target at start(), in the caller's thread."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


def _rows321():
    r = _Remote321(name="p321-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.121")
    su = _User321(username="p321-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db321.session.add_all([r, su])
    _db321.session.commit()
    _ROWS321["remotes"].append(r.id)
    _ROWS321["users"].append(su.id)
    return _NS321(host=r, su=su)


def _site321(st, name, kind="static", **kw):
    extra = {"php_version": "8.4"} if kind in ("php", "wordpress") else {}
    s = _Site321(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg321.encrypt_secret(_TOKEN321), **dict(extra, **kw))
    _db321.session.add(s)
    _db321.session.flush()
    s.account, s.port = "ws%d" % s.id, 20500 + s.id % 400
    _db321.session.add(_Dom321(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow321(), dns_state="matching"))
    _db321.session.commit()
    _ROWS321["sites"].append(s.id)
    return s


# ── 1. CI: apt without the runner image's Microsoft source ────────────────────────────────────────
_APT_STEP321 = "Install zsh and systemd-journal-remote"


def _apt_body321():
    with open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8") as fh:
        return _wf_run_block(fh.read(), _APT_STEP321)


def _apt_loop321(body):
    """The step's lines from its `for src in` loop to its `done`, or "" when it has none."""
    lines = body.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("for src in /etc/apt/sources.list.d/")), None)
    if start is None:
        return ""
    end = next((i for i in range(start, len(lines)) if lines[i].strip() == "done"), None)
    return "\n".join(lines[start:end + 1]) + "\n" if end is not None else ""


def _s1_ci():
    body = _apt_body321()
    code = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    upd = next((i for i, ln in enumerate(code) if "apt-get update" in ln), -1)
    loop_at = next((i for i, ln in enumerate(code) if ln.startswith("for src in /etc/apt/sources.list.d/")), -1)
    eq("CI (ci.yml, the unit legs' apt step): a loop over apt's source files runs BEFORE `apt-get update`",
       (loop_at >= 0, upd >= 0, 0 <= loop_at < upd), (True, True, True))
    d = _tf321.mkdtemp(prefix="lgsm-unit-p321-apt-")
    try:
        src, aside = os.path.join(d, "sources.list.d"), os.path.join(d, "aside")
        os.makedirs(src)
        os.makedirs(aside)
        files = {"microsoft-prod.list": "deb [arch=amd64,armhf,arm64] https://packages.microsoft.com/ubuntu/24.04/prod "
                                        "noble main\n",
                 "azure-cli.sources": "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\n",
                 "ubuntu.sources": "Types: deb\nURIs: http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\n",
                 "esm.list": "deb https://esm.ubuntu.com/apps/ubuntu noble-apps-security main\n"}
        for name, text in files.items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        loop = _apt_loop321(body).replace("/etc/apt/sources.list.d", src).replace("sudo ", "")
        r = _sp321.run(["bash", "-c", loop], env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": aside},
                       capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607 - bash, fixed
        got = (r.returncode, sorted(os.listdir(src)), sorted(os.listdir(aside)))
    finally:
        _shutil321.rmtree(d, ignore_errors=True)
    eq("CI (the step's own loop, run over a scratch sources folder): every source file naming packages.microsoft.com "
       "(one-line and deb822) is moved out of apt's list; the Ubuntu archive's and Ubuntu Pro's stay (control)",
       got, (0, ["esm.list", "ubuntu.sources"], ["azure-cli.sources", "microsoft-prod.list"]))


# ── 2. Tunnel mode closes the public ports ────────────────────────────────────────────────────────
def _seams321(tunnel_answer):
    def ports(remote, proxy, enabled):
        _REC321["ports"].append((proxy.exposure_mode, _sw321.wanted_rules(proxy, enabled)))
        return True, _sw321.OK_PORTS

    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC321["apply"].append(text)
        return True, _sw321.OK_APPLIED
    _p9_patch(_sw321, "ports_apply", ports)
    _p9_patch(_sw321, "proxy_apply", apply)
    _p9_patch(_sw321, "proxy_stop", lambda *a, **k: (True, _sw321.OK_PROXY_STOPPED))
    _p9_patch(_sw321, "tunnel_apply", lambda *a, **k: tunnel_answer)


def _save321(st, exposure):
    _REC321["ports"], _REC321["apply"] = [], []
    r = _Client321(st.su.id).post("/websites/proxy/settings", json={"host_id": st.host.id, "exposure": exposure})
    row = _Proxy321.query.filter_by(remote_id=st.host.id).first()
    _db321.session.refresh(row)
    return r, row


def _s2_tunnel(st):
    _site321(st, "p321-tun", enabled=True)
    _seams321((True, _sw321.OK_TUNNEL))
    r, _row = _save321(st, {"exposure_mode": "public"})
    eq("tunnel ports (control, POST /websites/proxy/settings in public mode): ports 80 and 443 open to everyone, the "
       "proxy applied, no word of closed ports",
       (r.status_code, _REC321["ports"], len(_REC321["apply"]), _CLOSED321 in (_p9_json(r).get("message") or "")),
       (200, [("public", [(None, "80"), (None, "443")])], 1, False))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r, row = _save321(st, {"exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": "t" * 60})
    msg = _p9_json(r).get("message") or ""
    eq("tunnel ports (POST /websites/proxy/settings to tunnel mode with a token the provider refuses): the public "
       "rules are taken away all the same (the firewall wants none in tunnel mode), the answer says why it failed AND "
       "that the ports are closed, and last_error keeps the tunnel's own sentence alone",
       (r.status_code, _REC321["ports"], msg.startswith(_sw321.TUNNEL_REFUSED), msg.endswith(_CLOSED321),
        row.exposure_mode, row.last_error),
       (502, [("tunnel", [])], True, True, "tunnel", _sw321.TUNNEL_REFUSED))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r = _Client321(st.su.id).post("/websites/proxy/apply", json={"host_id": st.host.id})
    eq("tunnel ports (POST /websites/proxy/apply in tunnel mode, the token still refused): the ports are closed again "
       "and the answer says so", (r.status_code, [m for m, _w in _REC321["ports"]][-1:],
                                  (_p9_json(r).get("message") or "").endswith(_CLOSED321)),
       (502, ["tunnel"], True))


# ── 3. A database server stopped since it was set up ──────────────────────────────────────────────
def _hds321(st):
    hd = _HDS321(remote_id=st.host.id, flavor="mariadb", version="11.8.3-MariaDB", installed_by_panel=True,
                 auth_mode="socket", port=3306, checked_at=_dbr321._now())
    _db321.session.add(hd)
    _db321.session.commit()
    return hd


def _install_form321(st, name):
    return {"app": "wordpress", "name": name, "remote_id": st.host.id, "admin_user": "siteowner",
            "admin_email": "owner@example.org", "domain": "%s.example.org" % name}


def _s3_db_stopped(st):
    _hds321(st)
    _dbr321._PROBES.pop(st.host.id, None)
    asked, answers = [], [dict(_STOPPED321)]
    _p9_patch(_dbs321, "probe", lambda remote: asked.append(remote.id) or (answers.pop(0) if answers else
                                                                           {"state": "ready"}))
    _p9_patch(_wapps321, "_worker", lambda app, sid, uid, secrets: None)
    _p9_patch(_w321, "threading", _NS321(Thread=_Inline321))
    eq("stopped database (before: the row checked a minute ago): the add dialog's list, which never probes, reads it "
       "ready", (_wview321.database_missing(st.host), asked), (None, []))
    su = _Client321(st.su.id)
    r = su.post("/websites/install-app", json=_install_form321(st, "p321-wp"))
    body = _p9_json(r)
    made = _Site321.query.filter_by(remote_id=st.host.id, name="p321-wp").first()
    if made is not None:
        _ROWS321["sites"].append(made.id)
    eq("stopped database (POST /websites/install-app, WordPress, the server stopped since its row was checked): the "
       "host is asked again, and the install is refused before anything is made with the entry the Start button "
       "fixes",
       (r.status_code, asked, made is None, [(m.get("key"), m.get("host_id")) for m in body.get("missing") or []]),
       (409, [st.host.id], True, [("database-stopped", st.host.id)]))
    eq("stopped database (the add dialog's list after it, which does not probe): the newer probe's word wins over the "
       "row, so the Start button shows at once, not 10 minutes later",
       ((_wview321.database_missing(st.host) or {}).get("key"), asked), ("database-stopped", [st.host.id]))
    created = []
    _p9_patch(_dbs321, "create", lambda *a, **k: created.append(a[2]) or (True, "created"))
    site = _site321(st, "p321-dbsite", kind="php")
    answers[:] = [dict(_STOPPED321)]
    r = su.post("/websites/%d/databases/add" % site.id, json={"name": "app"})
    eq("stopped database (POST /websites/<id>/databases/add): asked again, refused with nothing created on the "
       "host, and the answer carries the Start button's entry",
       (r.status_code, created, [m.get("key") for m in _p9_json(r).get("missing") or []]),
       (502, [], ["database-stopped"]))
    answers[:] = [{"state": "ready", "flavor": "mariadb", "version": "11.8.3-MariaDB"}]
    r = su.post("/websites/install-app", json=_install_form321(st, "p321-wp2"))
    made = _Site321.query.filter_by(remote_id=st.host.id, name="p321-wp2").first()
    if made is not None:
        _ROWS321["sites"].append(made.id)
    eq("stopped database (control: the server started again, the host answers ready): the install starts, and the "
       "dialog's list reads ready", (r.status_code, made is not None, _wview321.database_missing(st.host)),
       (200, True, None))


# ── 4. The page cache, as WordPress's Site Health and the response headers see it ──────────────────
def _s4_render(st):
    from panel.services import websites_proxy as _wp
    wp = _site321(st, "p321-wpc", kind="wordpress", enabled=True, page_cache=True, page_cache_ttl=300)
    plain = _site321(st, "p321-wpn", kind="wordpress", enabled=True, page_cache=False)
    on = _wp.render([wp, plain], None, {"cache_build": True}, secret_of=lambda s: _TOKEN321)
    off = _wp.render([wp, plain], None, {"cache_build": False}, secret_of=lambda s: _TOKEN321)
    blocks = {sid: on.split("# site %d (" % sid)[1].split("\n}\n")[0] for sid in (wp.id, plain.id)}
    strip = ["\theader {", "\t\t-Cache-Control", '\t\tmatch header Cache-Control ""', "\t}"]
    eq("page cache headers (render): a site whose pages the proxy caches has a header block that takes away a "
       "Cache-Control header only when it is empty (as the response leaves); a site without the cache has none, and "
       "no default Cache-Control is set anywhere (that would change what is stored)",
       ("\n".join(strip) in blocks[wp.id], "\n".join(strip) in blocks[plain.id], "default_cache_control" in on),
       (True, False, False))
    eq("page cache state (cached_sites over the rendered text): the cached site with its TTL; nothing when the proxy "
       "has no cache module, though the site's switch is on", (_wp.cached_sites(on), _wp.cached_sites(off)),
       ({wp.id: 300}, {}))
    return wp, plain


def _s4_apply(st):
    from panel.ops.ssh_manager import _core as _smcore
    from panel.routes import _shared as _shared321
    wp, plain = _s4_render(st)
    static = _site321(st, "p321-wps", kind="static", enabled=True)
    writes = []

    def shell(server, user, sh, timeout=30, stdin_text=None, **k):
        writes.append((user, stdin_text or ""))
        return "", "", 0
    _p9_patch(_sw321, "ports_apply", lambda *a, **k: (True, _sw321.OK_PORTS))
    _p9_patch(_sw321, "proxy_apply", _REAL_APPLY321)
    _p9_patch(_sw321, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "applied=yes"))
    _p9_patch(_sw321, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=2.11.9\nactive=active\n"
                                                                  "cache=yes\n"))
    _p9_patch(_smcore, "shell_as_game_user", shell)
    _p9_patch(_shared321, "game_account_write_refusal", lambda remote, user, *a, **k: None)
    _p9_patch(_wview321, "proxy_options", lambda: {"cache_build": True})
    _sw321._PAGE_CACHE_NOTED.clear()

    def written():
        import base64
        out = {}
        for user, stdin in writes:
            for line in stdin.splitlines():
                path, b64 = line.split(" ", 1)
                out[(user, path)] = base64.b64decode(b64).decode()
        writes[:] = []
        return out
    from panel.services import websites as _ws321
    ok, _said = _w321.reconcile_proxy(st.host)
    first = written()
    eq("page cache state (reconcile_proxy -> proxy_apply, the proxy built with the cache): each WordPress site's "
       "files get the state the applied configuration gives it (on with its TTL, off); a static site gets nothing",
       (ok, first), (True, {(wp.account, _ws321.PAGE_CACHE_FILE): "on 300\n",
                            (plain.account, _ws321.PAGE_CACHE_FILE): "off\n"}))
    ok, _said = _w321.reconcile_proxy(st.host)
    eq("page cache state (the same apply again): nothing is written when nothing changed", (ok, written()), (True, {}))
    wp.page_cache = False
    _db321.session.commit()
    ok, _said = _w321.reconcile_proxy(st.host)
    eq("page cache state (the site's page cache turned off, applied): its file says off", (ok, written()),
       (True, {(wp.account, _ws321.PAGE_CACHE_FILE): "off\n"}))
    for s in (wp, plain, static):
        s.enabled = False
    _db321.session.commit()


def _s4_plugin():
    from panel.services import websites as _ws321
    php = _ws321.loopback_plugin()
    test_fn = php[php.find("function lgsm_panel_site_status_tests"):] if "lgsm_panel_site_status_tests" in php else ""
    eq("Site Health (the loopback plugin): WordPress's own page cache test (async, header-based) is taken out and a "
       "direct one under the same key answers from the file the panel writes (/run/panel/page-cache, read-only in "
       "the container); no header is made up",
       ("add_filter( 'site_status_tests', 'lgsm_panel_site_status_tests' );" in php,
        "unset( $tests['async']['page_cache'] );" in test_fn,
        "$tests['direct']['page_cache'] = array( 'label' => __( 'Page cache' ), 'test' => 'lgsm_panel_page_cache_test' );"
        in test_fn, "define( 'LGSM_PANEL_PAGE_CACHE_FILE', '/run/panel/page-cache' );" in php,
        "'status'      => $on ? 'good' : 'recommended'," in php, "header(" in php.replace("wp_remote_retrieve_header(", "")),
       (True, True, True, True, True, False))
    eq("Site Health (the file the plugin reads): one of the files the panel writes for a site, and a new files "
       "revision so installed WordPress sites are offered Update for the new plugin",
       (_ws321.PAGE_CACHE_FILE in _ws321.FILE_NAMES, _ws321.PAGE_CACHE_FILE, _ws321.SITE_FILES_REV),
       (True, "site/conf/panel/page-cache", "files-7"))


# ── 5. One certificate per site ────────────────────────────────────────────────────────────────────
def _pem321(names, days=90):
    """A self-signed P-256 certificate for `names` (subjectAltName) and its key, as PEM text."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def _sc_site321(st, name, extra):
    site = _site321(st, name)
    for d in extra:
        _db321.session.add(_Dom321(website_id=site.id, domain=d, verified_at=_utcnow321(), dns_state="matching"))
    _db321.session.commit()
    _db321.session.refresh(site)
    return site


def _modes321(site):
    _db321.session.expire_all()
    site = _db321.session.get(_Site321, site.id)
    return {d.domain: (d.cert_mode, bool(d.own_cert_pem), bool(d.own_key_secret)) for d in site.domains}


def _api_domains321(su, site):
    got = _p9_json(su.get("/api/websites/%d" % site.id))
    doms = (got.get("site") or {}).get("domains") or got.get("domains") or []
    return {d.get("domain"): d for d in doms}


def _s5_site_cert(st):
    import json
    from panel.services import websites_proxy as _wp
    from panel.routes import websites_domains as _wd
    site = _sc_site321(st, "p321c", ["www.p321c.example.org", "p321c.example.net"])
    pem, key = _pem321(["p321c.example.org", "*.p321c.example.org"])
    su = _Client321(st.su.id)
    r = su.post("/websites/%d/cert" % site.id, json={"mode": "own", "cert": pem, "key": key})
    body = _p9_json(r)
    modes = _modes321(site)
    site = _db321.session.get(_Site321, site.id)
    eq("site certificate (POST /websites/<id>/cert, one paste for a name and its wildcard): both names use the site's "
       "certificate (no copy of their own), the other domain stays automatic and the answer says why, the pair is "
       "stored once on the site, and the key never comes back",
       (r.status_code, modes, bool(site.own_cert_pem) and bool(site.own_key_secret),
        any(n.startswith("p321c.example.net stays automatic") for n in body.get("notes") or []),
        "PRIVATE KEY" in r.get_data(as_text=True), sorted((body.get("site_cert") or {}).get("domains") or [])),
       (200, {"p321c.example.org": ("site", False, False), "www.p321c.example.org": ("site", False, False),
              "p321c.example.net": ("acme", False, False)}, True, True, False,
        ["p321c.example.org", "www.p321c.example.org"]))
    site.enabled = True
    text = _wp.render([site], None, {}, secret_of=lambda s: _TOKEN321)
    doc = json.loads(_sw321.apply_doc(text, [site], None))
    site.enabled = False
    _db321.session.commit()
    stem = "site-%d" % site.id
    eq("site certificate (render and the apply's files): the covered names share ONE block naming the site's one pair "
       "of files, sent once; the uncovered name keeps its automatic block",
       ("p321c.example.org, www.p321c.example.org {\n\ttls /etc/lgsm-web-proxy/certs/%s.crt "
        "/etc/lgsm-web-proxy/certs/%s.key {" % (stem, stem) in text, "p321c.example.net {\n\ttls {" in text,
        sorted(doc["files"])), (True, True, [stem + ".crt", stem + ".key"]))
    rows = _api_domains321(su, site)
    eq("site certificate (GET /api/websites/<id>): the covered domains say they use the site's certificate, the "
       "uncovered one is automatic with the reason on its line",
       ((rows.get("www.p321c.example.org") or {}).get("cert_mode"),
        ((rows.get("p321c.example.net") or {}).get("cert_uncovered") or "").startswith("p321c.example.net stays automatic")),
       ("site", True))
    _p9_patch(_wd._dns, "check", lambda domain, remote: ("mismatch", [], []))
    r = su.post("/websites/%d/domains/add" % site.id, json={"domain": "shop.p321c.example.org"})
    eq("site certificate (POST .../domains/add of a name the certificate covers): the new domain uses the site's "
       "certificate at once; its DNS state is its own (not verified, so not served yet)",
       (r.status_code, _modes321(site).get("shop.p321c.example.org")), (200, ("site", False, False)))
    su.post("/websites/%d/domains/add" % site.id, json={"domain": "blog.p321c.example.net"})
    eq("site certificate (control: a later name it does not cover): automatic", _modes321(site).get(
        "blog.p321c.example.net"), ("acme", False, False))
    r = su.post("/websites/%d/cert" % site.id, json={"mode": "acme"})
    site = _db321.session.get(_Site321, site.id)
    eq("site certificate (Back to automatic, one action for the site): every domain automatic, the site's pair gone",
       (r.status_code, sorted(set(m for m, _p, _k in _modes321(site).values())), site.own_cert_pem,
        site.own_key_secret), (200, ["acme"], "", ""))
    other_pem, other_key = _pem321(["elsewhere.example.com"])
    r = su.post("/websites/%d/cert" % site.id, json={"mode": "own", "cert": other_pem, "key": other_key})
    eq("site certificate (a certificate that covers none of the site's domains): refused, nothing stored",
       (r.status_code, _db321.session.get(_Site321, site.id).own_cert_pem), (400, ""))


def _s5_migration(st):
    import importlib
    from panel.core.config import encrypt_secret
    models = importlib.import_module("panel.db.models")
    site = _sc_site321(st, "p321m", ["www.p321m.example.org", "p321m.example.net"])
    pem, key = _pem321(["p321m.example.org", "*.p321m.example.org"])
    lone_pem, lone_key = _pem321(["p321m.example.net"])
    for d in site.domains:
        mine = d.domain == "p321m.example.net"
        d.cert_mode, d.cert_state = "own", "own"
        d.own_cert_pem = lone_pem if mine else pem
        d.own_key_secret = encrypt_secret(lone_key if mine else key)
    _db321.session.commit()
    models._site_certs_from_domains()
    _db321.session.commit()
    after = _modes321(site)
    site = _db321.session.get(_Site321, site.id)
    models._site_certs_from_domains()
    _db321.session.commit()
    eq("site certificate (data migration 5): the chain most of a site's domains held moves to the site once, those "
       "domains point at it; a domain with a different chain keeps its own; running it again changes nothing",
       (after, site.own_cert_pem == pem, bool(site.own_key_secret), _modes321(site)),
       ({"p321m.example.org": ("site", False, False), "www.p321m.example.org": ("site", False, False),
         "p321m.example.net": ("own", True, True)}, True, True, after))
    eq("site certificate (data migration 5 is listed, numbered after the ones before it)",
       [m.__name__ for m, _mark in models._DATA_MIGRATIONS][-1:] + [models._DATA_MIGRATIONS[-1][1]],
       ["_site_certs_from_domains", "PRAGMA user_version = 5"])


# ── 6. Blocked visitors ──────────────────────────────────────────────────────────────────────────
def _helper321():
    import importlib.machinery as _mach
    import importlib.util as _ilu
    spec = _ilu.spec_from_loader("panel_helper_p321", _mach.SourceFileLoader(
        "panel_helper_p321", os.path.join(_root, "tools", "panel-helper")))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H321 = _helper321()
_CF_ADDR321 = "173.245.48.10"        # inside Cloudflare's published 173.245.48.0/20
_VISITOR321 = "198.51.100.77"


def _proxy321(st, mode="public", presets=(), guard=None):
    import json
    row = _w321.proxy_row(st.host.id)
    row.exposure_mode, row.allow_presets = mode, json.dumps(sorted(presets))
    row.guard = json.dumps(guard if guard is not None else {})
    _db321.session.commit()
    return row


def _s6_render(st):
    from panel.services import websites_proxy as _wp
    site = _site321(st, "p321g", enabled=True, custom_rules='[{"type": "deny", "path": "/private*"}]')
    logged = _site321(st, "p321gl", enabled=True, access_log=True)
    row = _proxy321(st, "restricted", ["cloudflare"])
    text = _wp.render([site, logged], row, {}, secret_of=lambda s: _TOKEN321)
    block = text.split("# site %d (" % site.id)[1].split("\n}\n")[0]
    lblock = text.split("# site %d (" % logged.id)[1].split("\n}\n")[0]
    first = block.split("\n")[5:10]
    eq("guard (render, a host with blocking on): the deny list's 403 is ordered first and is the block's first matcher, "
       "by the proxy's own client_ip (the address the trusted-proxy rules decided: a CDN's header only from the CDN)",
       ("\torder error first" in text, first, "client_ip_headers CF-Connecting-IP" in text),
       (True, ["\t@lgsmdeny file {", "\t\troot /etc/lgsm-web-proxy/deny", "\t\ttry_files {client_ip}", "\t}",
               "\terror @lgsmdeny 403"], True))
    eq("guard (render): sign-in POSTs (WordPress, Drupal, MyBB, phpBB, SMF), scanner paths and the site's own denied "
       "paths go to the security log tagged login or scan; with no access log of its own every other request is "
       "skipped by every logger, and the security log keeps no path, query or header",
       ("\tlog_append @lgsmlogin lgsm login" in block, "\tlog_append @lgsmscan lgsm scan" in block,
        "/private*" in block.split("@lgsmscan path ")[1].split("\n")[0], "\tlog_skip @lgsmquiet" in block,
        "\t\toutput file /var/log/lgsm-web-proxy/security.log {" in block,
        all("\t\t\t%s delete" % f in block for f in ("request>uri", "request>headers", "request>remote_ip"))),
       (True, True, True, True, True, True))
    eq("guard (render, a site with its own access log): its logger is named and a watched request goes to both; "
       "nothing is skipped; the catch-alls log nothing",
       ("\tlog lgsmacc%d_0 {" % logged.id in lblock, "\tlog_name @lgsmlogin lgsmsec%d_0 lgsmacc%d_0" % (logged.id, logged.id)
        in lblock, "log_skip @lgsmquiet" in lblock, text.count("\tlog_skip\n\tabort")), (True, True, False, 2))
    _proxy321(st, "public", [], {"enabled": False})
    off = _wp.render([site, logged], row, {}, secret_of=lambda s: _TOKEN321)
    eq("guard (render, control: blocking off on the host, or no host row): none of its lines",
       [w for w in ("order error first", "@lgsmdeny", "lgsmsec", "log_skip") if w in off or w in _wp.render(
           [site], None, {}, secret_of=lambda s: _TOKEN321)], [])
    for s_ in (site, logged):
        s_.enabled = False
    _db321.session.commit()


def _line321(ip, tag, host="p321g.example.org"):
    import json
    return json.dumps({"level": "info", "ts": "2026-11-27T10:00:00.000Z", "logger": "http.log.access.lgsmsec5_0",
                       "msg": "handled request", "request": {"client_ip": ip, "method": "POST", "host": host},
                       "status": 200, "lgsm": tag}, separators=(",", ":"))


def _s6_jails(st):
    import re
    from panel.services import websites_guard as _wg
    from panel.ops.ssh_manager import websites as _smw
    row = _proxy321(st, "restricted", ["cloudflare"])
    doc = _smw.guard_doc(row)
    g = _H321.web_guard_doc(doc)
    jails = _H321.web_guard_jails(g, ["203.0.113.5/32"])
    ignore = jails.split("ignoreip = ")[1].split("\n")[0].split()
    eq("guard (the apply's document -> the jails): a CDN host's jails never ban a Cloudflare network, the tailnet, the "
       "loopback or the host's own address, and ban inside the proxy only (no firewall ban behind a CDN)",
       ("173.245.48.0/20" in ignore, "100.64.0.0/10" in ignore, "127.0.0.0/8" in ignore, "203.0.113.5/32" in ignore,
        "iptables-multiport" in jails, jails.count("action = lgsm-web-deny[name=")), (True, True, True, True, False, 2))
    pub = _H321.web_guard_jails(_H321.web_guard_doc(_smw.guard_doc(_proxy321(st, "public"))), [])
    eq("guard (control, public mode): each jail also bans at the firewall on 80 and 443",
       pub.count('iptables-multiport[name=lgsm-web-'), 2)
    rx = _H321.web_guard_filter("login").split("failregex = ")[1].split("\n")[0]
    rx = re.compile(rx.replace("<ADDR>", "(?P<ip>[0-9a-fA-F:.]+)"))
    hits = [(m.group("ip") if m else None) for m in (rx.search(_line321(_VISITOR321, "login")),
                                                       rx.search(_line321(_VISITOR321, "scan")))]
    eq("guard (the login filter over a security log line): the visitor's address is taken from client_ip of a line "
       "tagged login; a line tagged scan is the other jail's", hits, [_VISITOR321, None])
    bad = {"a number out of range": dict(doc, login=0), "an extra key": dict(doc, action="x"),
           "a network with a zone": dict(doc, never=["fe80::1%eth0"]), "a command": dict(doc, never=["1.2.3.4; id"])}
    refused = []
    for name, d in bad.items():
        try:
            _H321.web_guard_doc(d)
        except ValueError:
            refused.append(name)
    eq("guard (helper): a guard document with a number out of range, an unknown key or anything but networks in its "
       "never list is refused whole", sorted(refused), sorted(bad))
    eq("guard (settings): OWASP's words for each field, a note when blocking or the growing ban is off, none at the "
       "defaults", (sorted(_wg.OWASP_TEXT), sorted(_wg.owasp_notes(_wg.settings({"enabled": False, "increment": False}))),
                    _wg.owasp_notes(_wg.settings("{}"))),
       (["bantime", "findtime", "increment", "login", "maxtime", "scan"], ["enabled", "increment"], {}))


def _guard_tree321(d):
    """The helper's guard paths moved into scratch folder `d`, its writes as the current account."""
    import pwd as _pwd
    me = _pwd.getpwuid(os.getuid())
    paths = {"WEB_DENY_DIR": os.path.join(d, "deny"), "WEB_GUARD_NEVER": os.path.join(d, "guard-never"),
             "WEB_GUARD_EVENTS": os.path.join(d, "guard-events"), "WEB_LOG_DIR": os.path.join(d, "log"),
             "WEB_SECURITY_LOG": os.path.join(d, "log", "security.log"), "WEB_F2B_DIR": d,
             "WEB_GUARD_JAIL_FILE": os.path.join(d, "jail.conf"), "WEB_GUARD_FILTER_FILE": os.path.join(d, "%s.conf"),
             "WEB_GUARD_ACTION_FILE": os.path.join(d, "action.conf")}

    def write(path, data, mode, uid=0, gid=0):
        with open(path, "wb") as fh:
            fh.write(data)
    stubs = dict(paths, pwd=_NS321(getpwnam=lambda n: me), _web_write=write, _web_own_nets=lambda: ["203.0.113.5/32"],
                 _web_owned_dir=lambda path, mode, uid, gid: os.makedirs(path, exist_ok=True),
                 _run_quiet=lambda argv, timeout=60, **k: (0, ""))
    saved = {k: getattr(_H321, k) for k in stubs}
    for k, v in stubs.items():
        setattr(_H321, k, v)
    return saved, me


def _quiet321(fn, *a):
    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


def _s6_ban(st):
    """A client banned behind Cloudflare gets its deny entry, which the proxy reads by client_ip; Cloudflare never."""
    from panel.ops.ssh_manager import websites as _smw
    d = _tf321.mkdtemp(prefix="lgsm-unit-p321-guard-")
    saved, me = _guard_tree321(d)
    try:
        row = _proxy321(st, "restricted", ["cloudflare"])
        _quiet321(_H321._web_guard_apply, _H321.web_guard_doc(_smw.guard_doc(row)), me)
        with open(_H321.WEB_SECURITY_LOG, "a", encoding="utf-8") as fh:
            fh.write(_line321(_VISITOR321, "login") + "\n")
        ban = _quiet321(_H321.do_website_guard_ban, [_VISITOR321, "lgsm-web-login", "600"], "")
        cdn = _quiet321(_H321.do_website_guard_ban, [_CF_ADDR321, "lgsm-web-login", "600"], "")
        own = _quiet321(_H321.do_website_guard_ban, ["203.0.113.5", "lgsm-web-scan", "600"], "")
        deny = sorted(os.listdir(_H321.WEB_DENY_DIR))
        with open(os.path.join(_H321.WEB_DENY_DIR, _VISITOR321), encoding="ascii") as fh:
            entry = _H321.web_guard_entry(fh.read())
        listed = _quiet321(_H321.do_website_guard_list, ["0"], "")[1]
        unban = _quiet321(_H321.do_website_guard_unban, [_VISITOR321, "lgsm-web-login"], "")
        after = sorted(os.listdir(_H321.WEB_DENY_DIR))
    finally:
        for k, v in saved.items():
            setattr(_H321, k, v)
        _shutil321.rmtree(d, ignore_errors=True)
    eq("guard (helper, behind Cloudflare): fail2ban's ban of the visitor makes the deny entry the proxy's file matcher "
       "finds by that client_ip (the site it attacked named from the security log); a ban of a Cloudflare address or "
       "of the host's own is refused and no entry is made",
       (ban, cdn, own, deny, (entry or {}).get("host"), (entry or {}).get("jail")),
       ((0, "ban=yes\n"), (1, "ban=refused\n"), (1, "ban=refused\n"), [_VISITOR321], "p321g.example.org",
        "lgsm-web-login"))
    eq("guard (helper): the list prints the entry and its numbered ban event; fail2ban's unban takes the entry away",
       (("ban=%s lgsm-web-login" % _VISITOR321) in listed, ("event=1 " in listed and " ban %s " % _VISITOR321 in listed),
        unban, after), (True, True, (0, "unban=yes\n"), []))


def _s6_routes(st):
    import time
    from panel.db.models import AuditLog as _Audit321
    from panel.routes import websites_guard as _rg
    site = _site321(st, "p321b")
    other_ip, now = "192.0.2.44", int(time.time())
    entries = [{"ip": _VISITOR321, "jail": "lgsm-web-login", "at": now, "until": now + 600, "host": "p321b.example.org"},
               {"ip": other_ip, "jail": "lgsm-web-scan", "at": now, "until": now + 600, "host": "elsewhere.example.org"}]
    events = [(7, now, "ban", _VISITOR321, "lgsm-web-login", "p321b.example.org"),
              (8, now, "unban", other_ip, "lgsm-web-scan", "elsewhere.example.org")]
    asked, released = [], []
    _p9_patch(_sw321, "guard_list", lambda remote, after=0: asked.append(after) or (True, (list(entries),
                                                                                           [e for e in events if e[0] > after])))
    _p9_patch(_sw321, "guard_release", lambda remote, ip: released.append(ip) or (True, _sw321.OK_RELEASED))
    _rg._set_cursor(st.host.id, 0)
    su = _Client321(st.su.id)
    before = _Audit321.query.filter(_Audit321.action.in_(("website_ban", "website_unban"))).count()
    r = su.get("/websites/%d/blocked" % site.id)
    body = _p9_json(r)
    rows = _Audit321.query.filter(_Audit321.action.in_(("website_ban", "website_unban"))).count() - before
    eq("blocked visitors (GET /websites/<id>/blocked): only the addresses banned while asking for this site's names, "
       "with why and until when; the new ban events are audited (one row each) and read again from the last one",
       (r.status_code, [e.get("ip") for e in body.get("entries") or []], (body.get("entries") or [{}])[0].get("reason"),
        rows, asked), (200, [_VISITOR321], "Too many sign-in attempts", 2, [0]))
    su.get("/websites/%d/blocked" % site.id)
    eq("blocked visitors (the next read): no event audited twice", (asked[-1], _Audit321.query.filter(
        _Audit321.action.in_(("website_ban", "website_unban"))).count() - before), (8, 2))
    r = su.post("/websites/%d/blocked/unban" % site.id, json={"ip": other_ip})
    eq("blocked visitors (Unblock of an address another site's attack banned): refused, nothing lifted",
       (r.status_code, released), (404, []))
    r = su.post("/websites/%d/blocked/unban" % site.id, json={"ip": _VISITOR321})
    row = _Audit321.query.filter_by(action="website_unban", website_id=site.id).order_by(_Audit321.id.desc()).first()
    eq("blocked visitors (POST /websites/<id>/blocked/unban): the host lifts the address, audited with who asked",
       (r.status_code, released, bool(row) and "unblocked by hand" in (row.detail or "")), (200, [_VISITOR321], True))


def _s6_settings(st):
    import json
    _seams321((True, _sw321.OK_TUNNEL))
    su = _Client321(st.su.id)
    _proxy321(st, "public")
    r = su.post("/websites/proxy/settings", json={"host_id": st.host.id, "guard": {
        "enabled": True, "login": "8", "scan": "2", "findtime": "15", "bantime": "20", "maxtime": "48",
        "increment": False, "allow": ["203.0.113.0/24", "2001:db8::1"]}})
    row = _Proxy321.query.filter_by(remote_id=st.host.id).first()
    _db321.session.refresh(row)
    g = (_p9_json(r).get("proxy") or {}).get("guard") or {}
    eq("guard settings (POST /websites/proxy/settings {guard}): stored in seconds, the card reads minutes and hours, "
       "OWASP's words and the note for a ban that does not grow, applied",
       (r.status_code, json.loads(row.guard)["findtime"], json.loads(row.guard)["maxtime"], g.get("bantime"),
        sorted(g.get("notes") or {}), bool((g.get("owasp") or {}).get("bantime")), g.get("allow")),
       (200, 900, 172800, 20, ["increment"], True, ["2001:db8::1/128", "203.0.113.0/24"]))
    r = su.post("/websites/proxy/settings", json={"host_id": st.host.id, "guard": {"login": "0", "allow": ["nope"]}})
    eq("guard settings (out of range, not a network): refused with the field named, nothing stored",
       (r.status_code, json.loads(_Proxy321.query.filter_by(remote_id=st.host.id).first().guard)["login"]), (400, 8))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup321():
    _db321.session.rollback()
    remotes = _ROWS321["remotes"] or [0]
    sites = set(_ROWS321["sites"]) | {s.id for s in _Site321.query.filter(_Site321.remote_id.in_(remotes)).all()}
    from panel.db.models import GameDatabase as _GDB321
    _GDB321.query.filter(_GDB321.remote_id.in_(remotes)).delete(synchronize_session=False)
    for d in _Dom321.query.filter(_Dom321.website_id.in_(sorted(sites) or [0])).all():
        _db321.session.delete(d)
    for model in (_Proxy321, _HDS321):
        for p in model.query.filter(model.remote_id.in_(remotes)).all():
            _db321.session.delete(p)
    for model, ids in ((_Site321, sorted(sites)), (_User321, _ROWS321["users"]), (_Remote321, _ROWS321["remotes"])):
        for i in ids:
            row = _db321.session.get(model, i)
            if row is not None:
                _db321.session.delete(row)
    _db321.session.commit()
    for rid in _ROWS321["remotes"]:
        _dbr321._PROBES.pop(rid, None)


def _ran321(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran321.last)."""
    import traceback
    try:
        step(*args)
        _ran321.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        from flask import has_app_context
        if has_app_context():
            _db321.session.rollback()
        _ran321.last = traceback.format_exc()[-1500:]
        return False


_ran321.last = ""
_trips321 = len(_P9_TRIPPED)
for _sec321 in (_s1_ci, _s4_plugin):
    check("part321: %s ran to the end" % _sec321.__name__, _ran321(_sec321), _ran321.last)
with _p9.app_context():
    try:
        _p9_arm(who="part321")
        _st321 = _rows321()
        for _sec321 in (_s2_tunnel, _s3_db_stopped, _s4_apply, _s5_site_cert, _s5_migration, _s6_render, _s6_jails,
                        _s6_ban, _s6_routes, _s6_settings):
            check("part321: %s ran to the end" % _sec321.__name__, _ran321(_sec321, _st321), _ran321.last)
        eq("part321: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips321:], [])
    finally:
        _p9_restore_all()
        _w321._STATUS.clear()
        _sw321._PAGE_CACHE_NOTED.clear()
        _cleanup321()
