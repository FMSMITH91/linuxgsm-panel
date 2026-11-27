"""Part 316 of the unit suite: the websites' proxy, exposure, settings, files and page fixes of the journey review.

1. The site's own gate (Apache) lets a request its .htaccess rewrote through: WordPress sends every path that is not
   a file (robots.txt, a missing favicon, pretty links) to index.php as an internal redirect, after the gate's
   header was removed, and the gate refused it (AH01630 for real visitors). The proxy token is never rotated by an
   action, and the token in the site's config is the one the proxy sends.
2. The site's log lines: refused requests are counted, not listed; a failed site's alert gets its last lines.
3. Tunnel mode serves a site's domains without the DNS rule, and says HTTPS comes from the tunnel.
4. The proxy's Security settings are applied when saved, and put back when the proxy refuses them.
5. Purge cache empties one site's cache through the cache's API without a restart, once a minute at most, and only
   while the page cache is on and built.
6. Last backup, the site's last log lines and Update read real data; Update is offered when the image or the
   files' revision changed.
7. The Files tab: an upload over an existing name offers Replace; sizes in human units; the SFTP pointer.
8. Settings saves restart the site only when a limit changed; limit fields match the server, refusals name labels.
9. Who sees what: controls the server refuses a customer are read-only with the reason; the Performance tab fills
   its values in force; the proxy card names Caddy and lists Cloudflare's networks; its status and apply buttons.
10. The customer invite uses the panel's site domain; the firewall line reads ufw; restore keeps a stopped site
    stopped; a PHP version that left the catalog stays in the select with a note; the dead domains route is gone.
11. Tunnel mode beside a domain's own certificate and the certificate watch: no operator's key is sent to the host,
    no domain is called failed for a certificate the proxy never asks for, the Domains tab shows the tunnel's
    state, a host without the web proxy is still refused, and Put online names no domain as unanswered.

HOW IT RUNS. part12's app and its database. ssh_manager.websites' seams answer for the host and record what the
routes ask of it; nothing reaches a host (part12's tripwire is armed). The pages run in node over part301's harness.
"""
import base64 as _b64316
import importlib.machinery as _mach316
import importlib.util as _ilu316
import json as _json316
import os
import re as _re316
from types import SimpleNamespace as _NS316

from flask import g as _g316

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part301 import _COMMON301, _node301, _page301
from panel.core import config as _cfg316
from panel.db.models import (RemoteServer as _Remote316, User as _User316, Website as _Site316,
                             WebsiteDomain as _Dom316, WebsiteProxy as _Proxy316, db as _db316)
from panel.ops.ssh_manager import websites as _sw316
from panel.routes import websites as _w316
from panel.routes import websites_domains as _wd316
from panel.routes import websites_proxy as _wpr316
from panel.routes import websites_settings as _wset316
from panel.routes import websites_view as _wv316
from panel.services import website_files as _wf316
from panel.services import websites as _ws316
from panel.services import websites_proxy as _wp316

_TOKEN316 = "t" * 40
_HSPEC316 = _ilu316.spec_from_loader("panel_helper_p316", _mach316.SourceFileLoader(
    "panel_helper_p316", os.path.join(_root, "tools", "panel-helper")))
_H316 = _ilu316.module_from_spec(_HSPEC316)
_HSPEC316.loader.exec_module(_H316)
_ROWS316 = {"sites": [], "remotes": [], "users": []}
_REC316 = {"apply": [], "install": [], "helper": [], "start": []}
_REAL_APPLY316 = _sw316.proxy_apply      # the real apply (its doc) for section 11; _seams316 stubs it


class _Client316:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g316.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g316.pop("_login_user", None)
        return self.c.get(*a, **k)


def _j(resp):
    return resp.get_json(silent=True) or {}


def _customer316():
    """A user with no group at all: the pages' "runs the site, does not administer it" viewer. -> id."""
    u = _User316(username="p316-cust", password_hash=os.urandom(8).hex(), is_superadmin=False, is_active=True)
    _db316.session.add(u)
    _db316.session.commit()
    _ROWS316["users"].append(u.id)
    return u.id


def _rows316():
    r = _Remote316(name="p316-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.76")
    su = _User316(username="p316-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db316.session.add_all([r, su])
    _db316.session.commit()
    _ROWS316["remotes"].append(r.id)
    _ROWS316["users"].append(su.id)
    return _NS316(host=r, su=su)


def _site316(st, name, kind="php", verified=True, **kw):
    extra = {"php_version": "8.4"} if kind in _ws316.KINDS_PHP else {}
    s = _Site316(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg316.encrypt_secret(_TOKEN316), **dict(extra, **kw))
    _db316.session.add(s)
    _db316.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    from panel.core.clock import utcnow
    _db316.session.add(_Dom316(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=utcnow() if verified else None, dns_state="matching" if verified else "mismatch"))
    _db316.session.commit()
    _ROWS316["sites"].append(s.id)
    return s


def _proxy316(st, mode="public", **kw):
    row = _Proxy316.query.filter_by(remote_id=st.host.id).first() or _Proxy316(remote_id=st.host.id)
    row.exposure_mode, row.installed_version = mode, "2.11.9"
    for k, v in kw.items():
        setattr(row, k, v)
    _db316.session.add(row)
    _db316.session.commit()
    return row


def _bundle_conf(stdin, name):
    """The file `name` (a path ending) out of a site's install bundle (`<path> <base64>` lines)."""
    for line in (stdin or "").splitlines():
        path, _sp, data = line.partition(" ")
        if path.endswith(name):
            return _b64316.b64decode(data).decode("utf-8")
    return ""


def _seams316():
    """The host at ssh_manager.websites' seams: installs build the real bundle, applies and helpers are recorded."""
    def install(remote, site, db=None, start_it=True, restart=True):
        stdin, _image, refused = _sw316._site_bundle(site, (1005, 1005), {"splice": True, "cpu_delegated": True}, db)
        _REC316["install"].append((site.id, stdin or "", refused))
        return (False, refused) if refused else (True, _sw316.OK_STARTED)

    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC316["apply"].append(text)
        return _REC316.get("apply_answer") or (True, _sw316.OK_APPLIED)

    def helper(remote, verb, args=(), timeout=120, doc=None):
        _REC316["helper"].append((verb, list(args), doc))
        return True, "purged=yes"
    _p9_patch(_sw316, "install", install)
    _p9_patch(_sw316, "proxy_apply", apply)
    _p9_patch(_sw316, "_helper", helper)
    _p9_patch(_sw316, "ports_apply", lambda *a, **k: (True, _sw316.OK_PORTS))
    _p9_patch(_sw316, "proxy_stop", lambda *a, **k: (True, "stopped"))
    _p9_patch(_sw316, "tunnel_apply", lambda *a, **k: (True, _sw316.OK_TUNNEL))
    _p9_patch(_sw316, "quota_set", lambda *a, **k: (True, _sw316.OK_QUOTA))
    _p9_patch(_sw316, "start", lambda remote, site, restart=False: (_REC316["start"].append(site.id) or True, "started"))
    _p9_patch(_sw316, "stop", lambda remote, site: (True, "stopped"))
    _p9_patch(_sw316, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=2.11.9\nactive=active\n"
                                                                  "cache=%s\n" % _REC316.get("cache", "no")))
    _p9_patch(_sw316, "site_probe", lambda remote, site: (True, _probe_text316()))
    _p9_patch(_sw316, "site_logs", lambda remote, site: (True, _REC316.get("logs", "")))


def _probe_text316():
    """The recorded probe facts as probe_sh prints them (key=value lines), the text site_probe answers."""
    return "".join("%s=%s\n" % kv for kv in (_REC316.get("probe") or {}).items())


def _reset316(**kw):
    for k in ("apply", "install", "helper", "start"):
        _REC316[k] = []
    for k in ("apply_answer", "cache", "probe", "logs"):
        _REC316.pop(k, None)
    _REC316.update(kw)
    _w316._STATUS.clear()


# ── 1. the gate ───────────────────────────────────────────────────────────────────────────────────
def _gate_denies(conf, headers, env):
    """Whether Apache's <Location "/"> <If> in `conf` refuses a request with these headers and environment.

    The expression is the conf's own: every clause `%{HTTP:name} != 'v'` or `%{ENV:name} != 'v'`, joined by &&;
    the request is refused when all hold. Headers are what the request carries when the authorization runs; the
    environment is the request's (Apache sets REDIRECT_STATUS on an internal redirect to the status of the request
    it came from; a client cannot set it).
    """
    m = _re316.search(r'<Location "/">\s*<If "([^"]+)">\s*Require all denied', conf)
    if not m:
        return None
    for clause in m.group(1).split("&&"):
        c = _re316.fullmatch(r"\s*%\{(HTTP|ENV):([A-Za-z0-9_-]+)\} != '([^']*)'\s*", clause)
        if not c:
            return None
        have = (headers if c.group(1) == "HTTP" else env).get(c.group(2), "")
        if have == c.group(3):
            return False
    return True


def _s1_gate(st):
    site = _site316(st, "p316-gate", kind="wordpress", app_recipe="wordpress")
    _reset316()
    r = _Client316(st.su.id).post("/websites/%d/update-image" % site.id)
    conf = _bundle_conf((_REC316["install"] or [(0, "", None)])[-1][1], "apache.conf")
    tok = {"X-Panel-Proxy-Token": _TOKEN316}
    cases = {"through the proxy, a file that is there": (tok, {}),
             "through the proxy, rewritten to index.php (the header removed in fixups)": ({}, {"REDIRECT_STATUS": "200"}),
             "on the loopback port with no token": ({}, {}),
             "no token, then the error page after the refusal": ({}, {"REDIRECT_STATUS": "403"}),
             "a REDIRECT_STATUS header sent by the client": ({"REDIRECT_STATUS": "200"}, {}),
             "a wrong token": ({"X-Panel-Proxy-Token": "x" * 40}, {})}
    got = {k: _gate_denies(conf, h, e) for k, (h, e) in cases.items()}
    eq("gate (POST /websites/<id>/update-image, the Apache config it writes): a request WordPress's .htaccess rewrote "
       "to index.php is served (it was refused with AH01630: real visitors' robots.txt, favicon and pretty links); a "
       "request that did not come through the proxy is refused, the error page after a refusal included",
       (r.status_code, got),
       (200, {"through the proxy, a file that is there": False,
              "through the proxy, rewritten to index.php (the header removed in fixups)": False,
              "on the loopback port with no token": True, "no token, then the error page after the refusal": True,
              "a REDIRECT_STATUS header sent by the client": True, "a wrong token": True}))
    _s1_token(st, site)


def _s1_token(st, site):
    su = _Client316(st.su.id)
    _proxy316(st)            # Put online refuses a host without the web proxy installed
    _reset316()
    for verb, body in (("enable", {}), ("settings", {"limits": {"mem_mb": site.mem_mb + 64}, "customer_note": "n"}),
                       ("update-image", {}), ("disable", {}), ("enable", {})):
        su.post("/websites/%d/%s" % (site.id, verb), json=body)
    _db316.session.expire_all()
    row = _db316.session.get(_Site316, site.id)
    proxy_tokens = {m for text in _REC316["apply"] for m in _re316.findall(r'header_up X-Panel-Proxy-Token "([^"]+)"', text)}
    conf_tokens = {m for _i, stdin, _r in _REC316["install"]
                   for m in _re316.findall(r"!= '([A-Za-z0-9_-]{32,})'", _bundle_conf(stdin, "apache.conf"))}
    eq("gate token: Put online, a Settings save that reinstalls, Update and Take offline never rotate the site's proxy "
       "token; the token the proxy sends is the one in the site's own config",
       (_cfg316.decrypt_secret(row.proxy_secret), proxy_tokens, conf_tokens, len(_REC316["install"]) >= 2),
       (_TOKEN316, {_TOKEN316}, {_TOKEN316}, True))


# ── 2. log lines ──────────────────────────────────────────────────────────────────────────────────
def _s2_logs(st):
    site = _site316(st, "p316-logs")
    denied = "\n".join("[authz_core:error] [client 203.0.113.%d] AH01630: client denied by server configuration: "
                       "/var/www/html/server-status" % (i % 250) for i in range(300))
    _reset316(logs="site line one\n" + denied + "\nsite line two\n")
    got = _j(_Client316(st.su.id).get("/websites/%d/logs" % site.id)).get("lines")
    eq("logs (GET /websites/<id>/logs): 300 refused requests are one counted line, never listed; the site's own lines "
       "stay", got, ["site line one", "site line two", _w316.S_DENIED.replace("{n}", "300")])
    site.state = "failed"
    _db316.session.commit()
    failed = _j(_Client316(st.su.id).get("/api/websites/%d" % site.id)).get("logs")
    site.state = "running"
    _db316.session.commit()
    _reset316(logs="x\n")
    running = _j(_Client316(st.su.id).get("/api/websites/%d" % site.id)).get("logs")
    eq("logs (GET /api/websites/<id>): a failed site's alert gets its last log lines (it always said 'No log lines "
       "yet'); a running site's answer asks the host for none (control)",
       (failed, running), (["site line one", "site line two", _w316.S_DENIED.replace("{n}", "300")], []))


# ── 3. tunnel mode ────────────────────────────────────────────────────────────────────────────────
def _s3_tunnel(st):
    site = _site316(st, "p316-tun", verified=False)
    su = _Client316(st.su.id)
    seen = {}
    for mode in ("public", "tunnel"):
        _proxy316(st, mode, tunnel_provider="cloudflare", tunnel_token_enc=_cfg316.encrypt_secret("x" * 40))
        site.enabled = False
        _db316.session.commit()
        _reset316()
        su.post("/websites/%d/enable" % site.id)
        text = (_REC316["apply"] or [""])[-1]
        lines = text.split("\n")
        seen[mode] = ("http://p316-tun.example.org {" in lines, "p316-tun.example.org {" in lines)
    eq("tunnel (POST /websites/<id>/enable): in tunnel mode the site's domain is served though its DNS points at "
       "the tunnel's provider (no check can pass there); in public mode an unchecked domain is still left out",
       seen, {"public": (False, False), "tunnel": (True, False)})
    real = _w316.current_user
    _w316.current_user = _NS316(is_superadmin=False)
    try:
        refused = {m: (_proxy316(st, m) and _w316.online_refusal(site)) for m in ("public", "tunnel")}
    finally:
        _w316.current_user = real
    eq("tunnel (online_refusal, an administrator below superadmin): the DNS rule does not apply in tunnel mode; it "
       "still does in public mode", (bool(refused["public"]), refused["tunnel"]), (True, None))
    _proxy316(st, "tunnel")
    body = _j(su.get("/api/websites/%d" % site.id))
    listed = [s for s in _j(su.get("/api/websites")).get("sites", []) if s.get("id") == site.id]
    eq("tunnel (GET /api/websites/<id> and the list): the domain says HTTPS comes from the tunnel, never 'Certificate "
       "pending' for good, and the page gets the service address to route in Cloudflare",
       ((body.get("domains") or [{}])[0].get("cert_state"), body.get("tunnel"), listed[0].get("cert_state")),
       ("tunnel", {"service": "http://localhost:%d" % _wp316.TUNNEL_PORT}, "tunnel"))
    _proxy316(st, "public")
    site.enabled = False
    _db316.session.commit()


def _s3_page():
    page = _page301("website.html", _CUST316, site=_NS316(id=7, name="shop", kind="php"), can_manage=True,
                    can_files=False, site_admin=False)
    dom = {"id": 1, "domain": "shop.example.org", "is_primary": True, "dns_state": "mismatch", "cert_state": "tunnel"}
    got = {}
    for tunnel in (None, {"service": "http://localhost:19080"}):
        site = {"success": True, "site": {"id": 7, "name": "shop", "kind": "php", "state": "running"}, "domains": [dom],
                "dns": {"a": ["198.51.100.7"]}, "tunnel": tunnel}
        got[bool(tunnel)] = _node301(page, _COMMON301 + ["website_site.js"], r"""
  for (let i = 0; i < 4; i++) await tick();
  return {tunnel: !$('wd-tunnel').hidden, records: !$('wd-dns').hidden, svc: $('wd-tunnel-service').textContent,
          cert: $('wd-list').textContent.indexOf('HTTPS by the tunnel (Cloudflare)') >= 0};
""", routes={"/api/websites/7": site})
    eq("tunnel (Domains tab): the A-record table gives way to the Public Hostname instruction with the service "
       "address, and the domain says HTTPS by the tunnel; outside tunnel mode the records table shows (control)",
       got, {True: {"tunnel": True, "records": False, "svc": "http://localhost:19080", "cert": True},
             False: {"tunnel": False, "records": True, "svc": "", "cert": True}})


# ── 4. Security settings applied ──────────────────────────────────────────────────────────────────
def _s4_options(st):
    site = _site316(st, "p316-opts", enabled=True)
    su = _Client316(st.su.id)
    _cfg316.update_config(lambda c: c.update(websites_acme_staging=True))
    _reset316()
    r = su.post("/websites/proxy/options", json={"options": {"acme_staging": False}})
    text = (_REC316["apply"] or [""])[-1]
    eq("Security settings (POST /websites/proxy/options): turning the test service off is applied to the running "
       "proxy at once (the domain warning tells the owner to do exactly this), and the page is told so",
       (r.status_code, len(_REC316["apply"]), "acme-staging" in text, _j(r).get("message")),
       (200, 1, False, _wpr316.S_APPLIED))
    _reset316(apply_answer=(False, "the proxy said no"))
    r = su.post("/websites/proxy/options", json={"options": {"acme_staging": True, "hsts_max_age": 600}})
    cfg = _cfg316.load_config()
    eq("Security settings: a proxy that refuses the new configuration leaves nothing saved (the previous values put "
       "back) and the page gets the reason",
       (r.status_code, cfg.get("websites_acme_staging"), cfg.get("websites_hsts_max_age"),
        "the proxy said no" in (_j(r).get("message") or "")), (502, False, None, True))
    _reset316()
    r = su.post("/websites/proxy/options", json={"options": {"max_sites": 4}})
    eq("Security settings: a value the proxy does not read (sites per customer) saves without touching the proxy "
       "(control)", (r.status_code, len(_REC316["apply"])), (200, 0))
    bad = su.post("/websites/proxy/options", json={"options": {"pids": 5}})
    eq("Security settings: a refused number names the field as the card labels it, not its key",
       _j(bad).get("message"), "Processes per site must be a whole number from 32 to 32768.")
    site.enabled = False
    _db316.session.commit()
    _cfg316.update_config(lambda c: [c.pop(k, None) for k in list(c) if k.startswith("websites_")])


# ── 5. purge ──────────────────────────────────────────────────────────────────────────────────────
def _s5_render():
    site = _NS316(id=1, name="a", enabled=True, port=20001, max_body_mb=8, page_cache=True, page_cache_ttl=300,
                  static_cache=False, access_log=False, raw_proxy_snippet="", custom_rules="[]",
                  domains=[_NS316(domain="a.example.org", is_primary=True, id=1, verified_at=1, cert_mode="acme")])
    lines = {c: [ln.strip() for ln in _wp316.render([site], None, {"cache_build": c}, secret_of=lambda s: _TOKEN316)
                 .split("\n")] for c in (True, False)}
    eq("purge (the proxy's configuration): with the page cache on, the admin API listens only on a unix socket in "
       "the proxy's runtime folder, mode 0200, and the cache's API is on; with it off, no admin API at all",
       ([ln for ln in lines[True] if ln.startswith("admin")], "souin" in lines[True],
        [ln for ln in lines[False] if ln.startswith("admin")], "souin" in lines[False]),
       (["admin unix//run/lgsm-web-proxy/admin.sock|0200"], True, ["admin off"], False))
    unit = _H316.WEB_PROXY_UNIT_TEXT.split("\n")
    eq("purge (the proxy's unit): it gets its runtime folder for the socket, owner-only",
       [ln for ln in unit if ln.startswith("RuntimeDirectory")], ["RuntimeDirectory=lgsm-web-proxy", "RuntimeDirectoryMode=0700"])


def _s5_helper():
    sent = []
    _p9_patch(_H316, "_web_admin_purge", lambda pattern: sent.append(pattern) or True)
    rc = _H316.do_website_proxy_apply(["purge"], _json316.dumps({"purge": ["a.example.org", "www.a.example.org"]}))
    refused = [_H316.do_website_proxy_apply(["purge"], doc) for doc in (
        _json316.dumps({"purge": ["a.example.org/../x"]}), _json316.dumps({"purge": []}),
        _json316.dumps({"purge": ["a.example.org"], "caddyfile": "x"}))]
    eq("purge (helper verb website-proxy-apply purge): one PURGE per domain of the cache's keys naming it as the host, "
       "its dots literal, nothing restarted; a document that is not a list of domain names is refused",
       (rc, sent, refused), (0, [".*-a[.]example[.]org-/.*", ".*-www[.]a[.]example[.]org-/.*"], [2, 2, 2]))
    check_arg = _H316.VERBS["website-proxy-apply"][0][0]
    took = []
    for arg in ("purge", "restart"):
        try:
            took.append(check_arg(arg))
        except ValueError:
            took.append(None)
    from panel.security import privileged_websites as _pw
    table = _pw.argv(ValueError, _H316.v_choice)
    eq("purge (the helper's and the panel's argument check): purge is taken; the restart that emptied the cache by "
       "restarting the shared proxy is refused", (took, table["website-proxy-apply"][0][0]("purge")), (["purge", None], "purge"))


def _s5_route(st):
    site = _site316(st, "p316-purge", page_cache=True)
    su = _Client316(st.su.id)
    url = "/websites/%d/cache/purge" % site.id
    _cfg316.update_config(lambda c: c.update(websites_cache_build=True))
    _wset316._PURGED.clear()
    _reset316(cache="yes")
    first = su.post(url)
    again = su.post(url)
    helper = [h for h in _REC316["helper"] if h[0] == "website-proxy-apply"]
    eq("purge (POST /websites/<id>/cache/purge): the helper is asked to purge this site's domains, never to restart "
       "the proxy; a second press within a minute is refused (429)",
       (first.status_code, [(v, a, _json316.loads(d) if d else d) for v, a, d in helper], again.status_code),
       (200, [("website-proxy-apply", ["purge"], {"purge": ["p316-purge.example.org"]})], 429))
    _wset316._PURGED.clear()
    _reset316(cache="no")
    unbuilt = su.post(url)
    site.page_cache = False
    _db316.session.commit()
    off = su.post(url)
    eq("purge: refused with the reason while the host's proxy has no page cache build, and while the site's page "
       "cache is off", (unbuilt.status_code, _j(unbuilt).get("message"), off.status_code, _j(off).get("message")),
       (409, _wset316.S_PURGE_NOT_BUILT, 409, _wset316.S_PURGE_OFF))
    _cfg316.update_config(lambda c: c.pop("websites_cache_build", None))


# ── 6. Last backup, Update ────────────────────────────────────────────────────────────────────────
def _s6_overview(st):
    site = _site316(st, "p316-ov")
    su = _Client316(st.su.id)
    got = []
    for probe in ({"last_backup": 1764201600}, {}, None):
        _reset316(probe=probe)
        if probe is None:
            _p9_patch(_sw316, "site_probe", lambda remote, site: (False, "no answer"))
        got.append(_j(su.get("/api/websites/%d" % site.id)).get("site", {}).get("last_backup"))
    _p9_patch(_sw316, "site_probe", lambda remote, site: (True, _probe_text316()))
    eq("Last backup (GET /api/websites/<id>): the newest backup's time the host reports; '' when it reports none "
       "('None yet'); null when it could not be read (a dash, never 'None yet')",
       got, ["2025-11-27 00:00 UTC", "", None])
    _p9_patch(_ws316, "image_for", lambda s: "localhost/lgsm-site-php:8.4-aaaa")
    fresh = _j(su.get("/api/websites/%d" % site.id))["site"]["image"]["update_available"]
    su.post("/websites/%d/update-image" % site.id)
    _db316.session.expire_all()
    done = _j(su.get("/api/websites/%d" % site.id))["site"]["image"]
    _p9_patch(_ws316, "image_for", lambda s: "localhost/lgsm-site-php:8.4-bbbb")
    newer = _j(su.get("/api/websites/%d" % site.id))["site"]["image"]["update_available"]
    eq("Update (GET /api/websites/<id>): offered to a site installed before the panel recorded its image; not after "
       "Update recorded it; offered again when the signed catalog's image changes",
       (fresh, done["update_available"], done["name"], newer), (True, False, "lgsm-site-php", True))


# ── 8. Settings saves ─────────────────────────────────────────────────────────────────────────────
def _s8_settings(st):
    site = _site316(st, "p316-set")
    su = _Client316(st.su.id)
    same = {k: getattr(site, k) for k in _w316.LIMITS}
    _reset316()
    su.post("/websites/%d/settings" % site.id, json={"limits": dict(same, backup_keep=7), "customer_note": "note",
                                                     "access_log": False})
    note_only = len(_REC316["install"])
    _reset316()
    su.post("/websites/%d/settings" % site.id, json={"limits": dict(same, mem_mb=same["mem_mb"] + 64)})
    eq("Settings (POST /websites/<id>/settings): a save that changes only the note (the form sends every limit) "
       "does not reinstall and restart the site; a changed limit does (control)",
       (note_only, len(_REC316["install"])), (0, 1))
    bad = su.post("/websites/%d/settings" % site.id, json={"limits": {"pids": 16}})
    eq("Settings: a refused limit is named as the form labels it, not by its key",
       _j(bad).get("message"), "Processes must be a whole number from 32 to 32768.")


def _s8_bounds():
    def bounds(path, ids):
        with open(os.path.join(_root, "panel", "templates", path), encoding="utf-8") as fh:
            text = fh.read()
        out = {}
        for key, el in ids.items():
            m = _re316.search(r'id="%s"[^>]*min="([0-9]+)" max="([0-9]+)"' % el, text)
            out[key] = (int(m.group(1)), int(m.group(2))) if m else None
        return out
    site_ids = {"mem_mb": "wset-mem", "cpu_milli": "wset-cpu", "pids": "wset-pids", "disk_mb": "wset-disk",
                "max_body_mb": "wset-body"}
    opt_ids = {"mem_mb": "wp-mem", "cpu_milli": "wp-cpu", "pids": "wp-pids", "disk_mb": "wp-disk",
               "max_body_mb": "wp-body", "max_sites": "wp-max-sites", "hsts_max_age": "wp-hsts", "access_log_days": "wp-log-days"}
    eq("limits: every limit field on the site's Settings tab and on the Security settings card allows exactly what "
       "the server accepts",
       (bounds("_website_settings.html", site_ids), bounds("_website_proxy.html", opt_ids)),
       ({k: _w316.LIMITS[k] for k in site_ids}, {k: _wv316.OPTIONS[k][1:] for k in opt_ids}))


# ── 7 and 9. the pages ────────────────────────────────────────────────────────────────────────────
def _s7_upload():
    page = _page301("website.html", _CUST316, site=_NS316(id=7, name="shop", kind="php"), can_manage=True,
                    can_files=True, site_admin=False)
    site = {"success": True, "site": {"id": 7, "name": "shop", "kind": "php", "state": "running"}, "domains": []}
    scenario = r"""
  for (let i = 0; i < 4; i++) await tick();
  $('wf-upload').files = [{name: 'index.php'}];
  window.wsFilesUpload();
  for (let i = 0; i < 6; i++) await tick();
  const msg = $('wf-msg').textContent, btn = $('wf-msg').querySelector('button');
  if (btn) window.wsFilesReplace();
  for (let i = 0; i < 6; i++) await tick();
  const ups = calls.filter(function (c) { return c[1].indexOf('/files/upload') >= 0; }).length;
  return {msg: msg, replace: !!btn, ups: ups, size: [WS.size(512), WS.size(3480), WS.size(52428800), WS.size(null)]};
"""
    exists = {"success": False, "exists": True, "message": "A file with that name is already there."}
    got = _node301(page, _COMMON301 + ["website_site.js", "website_files.js"], scenario,
                   routes={"/api/websites/7": site, "/websites/7/files/upload": exists,
                           "/websites/7/files/list": {"success": True, "path": "", "entries": []}})
    eq("Files (upload over an existing name): the end says 0 of 1 uploaded and which file is already there, never "
       "'Upload finished', and offers Replace, which sends it again",
       (got.get("msg"), got.get("replace"), got.get("ups")),
       ("0 of 1 files uploaded. Already there: index.php.  Replace them", True, 2))
    eq("sizes: files and backups read in human units", got.get("size"), ["512 B", "3.4 KB", "50 MB", ""])
    ok = _node301(page, _COMMON301 + ["website_site.js", "website_files.js"], scenario,
                  routes={"/api/websites/7": site, "/websites/7/files/upload": {"success": True},
                          "/websites/7/files/list": {"success": True, "path": "", "entries": []}})
    eq("Files: a plain upload ends with 1 of 1 uploaded and no Replace (control)",
       (ok.get("msg"), ok.get("replace")), ("1 of 1 files uploaded.", False))
    with open(os.path.join(_root, "panel", "templates", "_website_files.html"), encoding="utf-8") as fh:
        text = fh.read()
    eq("Files: the tab names the upload cap the app enforces and points to SFTP on the Account page",
       ("config.MAX_CONTENT_LENGTH" in text, "#sec-sftp" in text), (True, True))


_PERF316 = r"""
  for (let i = 0; i < 4; i++) await tick();
  window.wsTab('performance');
  const out = {mem: $('wperf-op-mem').value, reval: $('wperf-op-reval').value, ttl: $('wperf-ttl').disabled,
               purge: $('wperf-purge').disabled, why: $('wperf-page-why').hidden ? '' : $('wperf-page-why').textContent,
               obj: $('wperf-obj').disabled, objWho: !$('wperf-obj-who').hidden,
               ver: $('wphp-version').disabled, verWho: !$('wphp-version-who').hidden,
               de: $('wphp-display_errors').checked, sel: $('wphp-version').options.map(function (o) { return o.textContent; }),
               eol: $('wphp-eol').hidden ? '' : $('wphp-eol').textContent, adv: $('wphp-adv-sum').textContent};
  return out;
"""


def _perf_answer(**perf):
    base = {"opcache": True, "opcache_memory_mb": 128, "opcache_revalidate_s": 2, "object_cache": False,
            "page_cache": False, "page_cache_ttl": 300, "static_cache": True, "page_cache_ready": True, "page_cache_why": ""}
    php = {"versions": [{"version": "8.4", "eol": False}, {"version": "8.1", "eol": True}], "version": "8.1",
           "settings": {"display_errors": "Off", "memory_limit": "256M"}, "custom": "a = 1\n; c\nb = 2", "eol_note": "N"}
    return {"success": True, "site": {"id": 7, "name": "shop", "kind": "php", "state": "running"}, "domains": [],
            "perf": dict(base, **perf), "php": php, "rules": []}


def _s9_perf():
    who = {}
    for role, uid, admin in (("customer", _CUST316, False), ("admin", None, True)):
        from unit.part12 import P9_ADMIN
        page = _page301("website.html", uid or P9_ADMIN, site=_NS316(id=7, name="shop", kind="php"), can_manage=True,
                        can_files=False, site_admin=admin)
        who[role] = _node301(page, _COMMON301 + ["website_site.js", "website_tuning.js"], _PERF316,
                             routes={"/api/websites/7": _perf_answer()})
    c, a = who["customer"], who["admin"]
    eq("Performance and PHP tabs (a fresh site): OPcache's memory and check interval show the values in force, and "
       "display_errors saved as Off shows off (the text 'Off' had turned the switch on)",
       (c.get("mem"), c.get("reval"), c.get("de")), ("128", "2", False))
    eq("who (someone who runs the site but does not administer it): the PHP version and the object cache are shown "
       "read-only with who can change them; an administrator's are not (control)",
       ((c.get("ver"), c.get("verWho"), c.get("obj"), c.get("objWho")), (a.get("ver"), a.get("verWho"), a.get("obj"), a.get("objWho"))),
       ((True, True, True, True), (False, False, False, False)))
    eq("PHP: a version that left the catalog stays selected, marked, with the end-of-support note; the folded "
       "Advanced box says how many settings it holds",
       (c.get("sel"), c.get("eol"), c.get("adv")), (["8.4", "8.1 (end of support)"], "N", "Advanced php.ini: 2 settings"))
    states = {}
    for name, perf in (("off", {}), ("unbuilt", {"page_cache": True, "page_cache_ready": False, "page_cache_why": "W"}),
                       ("ready", {"page_cache": True})):
        got = _node301(page, _COMMON301 + ["website_site.js", "website_tuning.js"], _PERF316,
                       routes={"/api/websites/7": _perf_answer(**perf)})
        states[name] = (got.get("ttl"), got.get("purge"), got.get("why"))
    eq("page cache: Keep pages for and Purge cache stay in view but disabled, with the reason, while the page cache "
       "is off and while the host's proxy lacks it; enabled when it is on and built (control)",
       states, {"off": (True, True, "Turn the page cache on first."), "unbuilt": (True, True, "W"),
                "ready": (False, False, "")})


def _s9_egress():
    from unit.part12 import P9_ADMIN
    got = {}
    for who, uid in (("admin", _CUST316), ("super", P9_ADMIN)):
        page = _page301("website.html", uid, site=_NS316(id=7, name="shop", kind="php"), can_manage=True,
                        can_files=False, site_admin=True)
        got[who] = _node301(page, _COMMON301 + ["website_site.js"], r"""
  for (let i = 0; i < 4; i++) await tick();
  window.wsSettingsSave({preventDefault: function () {}});
  for (let i = 0; i < 4; i++) await tick();
  const sent = calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return c[2]; })[0] || {};
  return {shown: !!$('wset-egress'), disabled: !!($('wset-egress') && $('wset-egress').disabled),
          on: !!($('wset-egress') && $('wset-egress').checked), sends: 'full_egress' in sent};
""", routes={"/api/websites/7": {"success": True, "site": {"id": 7, "name": "shop", "kind": "php", "state": "running",
                                                        "full_egress": True, "limits": {}}, "domains": []},
             "/websites/7/settings": {"success": True}})
    eq("Settings (an administrator below superadmin): the site's full internet access is shown with its state, "
       "read-only, never hidden, and a save does not send it; a superadmin's switch is live (control)",
       got, {"admin": {"shown": True, "disabled": True, "on": True, "sends": False},
             "super": {"shown": True, "disabled": False, "on": True, "sends": True}})


def _s9_perf_server(st):
    site = _site316(st, "p316-perf")
    su = _Client316(st.su.id)
    perf = _j(su.get("/api/websites/%d" % site.id)).get("perf") or {}
    php = (_j(su.get("/api/websites/%d" % site.id)).get("php") or {}).get("settings") or {}
    r = su.post("/websites/%d/performance" % site.id, json={"opcache_memory_mb": ""})
    eq("Performance (GET /api/websites/<id>, a site that saved nothing): OPcache's values in force (128 MB, 2 s) and "
       "the PHP form's (memory_limit 256M), never empty; a Save with an empty value is refused, nothing written",
       (perf.get("opcache_memory_mb"), perf.get("opcache_revalidate_s"), php.get("memory_limit"), r.status_code,
        _db316.session.get(_Site316, site.id).php_settings in ("{}", "", None)), (128, 2, "256M", 400, True))


def _s9_proxy_card():
    from unit.part301 import _LIST301, _list_sa301
    info = {"cloudflare": {"ranges": ["173.245.48.0/20", "2400:cb00::/32"], "issued": "2026-11-20"}}
    answer = dict(_LIST301, proxies=[{"host_id": 1, "host_name": "h", "installed": True, "version": "2.11.9",
                                      "exposure_mode": "restricted", "allow_cidrs": [], "allow_presets": ["cloudflare"],
                                      "preset_info": info, "tunnel_service": "http://localhost:19080"}], options={})
    got = _node301(_list_sa301, _COMMON301 + ["websites.js", "websites_proxy.js"], r"""
  for (let i = 0; i < 4; i++) await tick();
  window.wsProxyStatus(); window.wsProxyApply();
  for (let i = 0; i < 4; i++) await tick();
  return {state: $('wp-state').textContent, sum: $('wp-cf-sum').textContent, ranges: $('wp-cf-ranges').textContent,
          src: $('wp-cf-src').textContent, svc: $('wp-tunnel-service').textContent,
          top: !!$('ws-proxy-open'), opts: $('wp-opts-sum').textContent,
          hits: calls.map(function (c) { return c[0] + ' ' + c[1].split('?')[0]; })};
""", routes={"/api/websites": answer, "/websites/proxy/status": {"status_ok": True, "status": {"version": "2.11.9", "active": "active"}},
             "/websites/proxy/apply": {"success": True}})
    eq("proxy card: it names the proxy (Caddy and its version), lists every Cloudflare network the preset admits with "
       "the catalog's date, gives the tunnel's service address, and the Websites page has a button to it at the top",
       (got.get("state"), got.get("sum"), got.get("ranges"), "2026-11-20" in (got.get("src") or ""), got.get("svc"),
        got.get("top"), got.get("opts")),
       ("Web proxy: Caddy 2.11.9, installed.", "Cloudflare's networks (2)", "173.245.48.0/202400:cb00::/32", True,
        "http://localhost:19080", True, "Security settings: 17 settings"))
    eq("proxy card: Check the web proxy and Apply again reach the two routes that had no button",
       [h for h in got.get("hits", []) if "/proxy/" in h], ["GET /m/websites/proxy/status", "POST /m/websites/proxy/apply"])


# ── 10. the rest ──────────────────────────────────────────────────────────────────────────────────
def _forget_domain316(cfg):
    cfg.pop("site_domain", None)


def _s10_rest(st):
    su = _Client316(st.su.id)
    site = _site316(st, "p316-rest")
    site.state = "stopped"
    _db316.session.commit()
    _cfg316.update_config(lambda c: c.update(site_domain="panel.example.org"))
    try:
        from panel.routes import websites_customers as _wc
        with _p9.test_request_context("/websites/customers/add", base_url="https://100.64.0.9:5000"):
            link, note = _wc.invite_link("tok")
        _cfg316.update_config(lambda c: c.update(site_domain=""))
        with _p9.test_request_context("/websites/customers/add", base_url="https://100.64.0.9:5000"):
            here, note2 = _wc.invite_link("tok")
    finally:
        _cfg316.update_config(_forget_domain316)
    eq("customer invite: the link uses the panel's site domain (with the panel's port), not the address the "
       "administrator happens to use; without one it says which address the customer must reach",
       (link.split("/invite")[0], note, here.split("/invite")[0], note2),
       ("https://panel.example.org:5000", _wc.S_INVITE_AT.replace("{address}", "panel.example.org:5000"),
        "https://100.64.0.9:5000", _wc.S_INVITE_HERE.replace("{address}", "100.64.0.9:5000")))
    _s10_more(st, su, site)


def _s10_more(st, su, site):
    """The firewall line, a restore of a stopped site, the disk-full sentence and the removed domains route."""
    _wv316._FIREWALL.clear()
    from panel.ops.ssh_manager import firewall as _fw
    _p9_patch(_fw, "remote_ufw_status", lambda remote: {"installed": True, "enabled": False})
    site.enabled = True
    _db316.session.commit()
    off = (_j(su.get("/api/websites")).get("ports") or {}).get("firewall")
    _wv316._FIREWALL.clear()
    _p9_patch(_fw, "remote_ufw_status", lambda remote: {"installed": True, "enabled": True})
    on = (_j(su.get("/api/websites")).get("ports") or {}).get("firewall")
    site.enabled = False
    _db316.session.commit()
    eq("firewall line (GET /api/websites): the host's ufw is read, so 'Firewall is off' can show (it was always "
       "unknown)", (off, on), ("off", "on"))
    from panel.routes import websites_backups as _wb
    from panel.services import website_backup as _wbs
    _p9_patch(_wbs, "check_archive", lambda *a: "")
    _p9_patch(_wbs, "restore", lambda *a: (True, "restored"))
    _p9_patch(_wb, "make_backup", lambda s: (True, "ok", "safety.tar.gz"))
    from panel.routes import databases_sites as _ds
    _p9_patch(_ds, "restore_after_backup", lambda s: (True, ""))
    _reset316()
    with _p9.test_request_context("/"):
        from flask_login import login_user
        login_user(_db316.session.get(_User316, st.su.id))
        _wb._restore(site, "backup-20261127-000000.tar.gz")
        stopped = list(_REC316["start"])
        site.state = "running"
        _wb._restore(site, "backup-20261127-000000.tar.gz")
    eq("restore: a stopped site stays stopped, as its page says; a running one is started again (control)",
       (stopped, _REC316["start"]), ([], [site.id]))
    eq("disk full: the sentence says backups count and an administrator can raise the limit",
       ("backups count" in _wf316.S_DISK_FULL, "raise its disk limit" in _wf316.S_DISK_FULL), (True, True))
    r = su.get("/websites/%d/domains" % site.id)
    eq("the domains route with no button is gone (the page reads the domains from /api/websites/<id>)",
       r.status_code in (404, 405), True)


# ── 11. tunnel mode beside the own certificate and the certificate watch ──────────────────────────
def _own_pem316(domain):
    """A self-signed P-256 certificate for `domain` and its key, as PEM text."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def _s11_enable(st):
    from panel.core.clock import utcnow
    site = _site316(st, "p316-own")
    dom = site.domains[0]
    pem, key = _own_pem316(dom.domain)
    dom.cert_mode, dom.cert_state, dom.own_cert_pem, dom.own_key_secret = "own", "own", pem, _cfg316.encrypt_secret(key)
    _db316.session.add(_Dom316(website_id=site.id, domain="www.p316-own.example.org", dns_state="mismatch"))
    _db316.session.commit()
    _p9_patch(_wd316._dns, "check", lambda domain, remote: ("mismatch", [], []))
    _p9_patch(_sw316, "proxy_apply", _REAL_APPLY316)
    su, got = _Client316(st.su.id), {}
    try:
        for mode in ("public", "tunnel"):
            _proxy316(st, mode)
            site.enabled = False
            _db316.session.commit()
            _reset316()
            said = _j(su.post("/websites/%d/enable" % site.id)).get("message", "")
            docs = [doc for verb, _a, doc in _REC316["helper"] if verb == "website-proxy-apply"]
            got[mode] = (sorted(_json316.loads(docs[0])["files"]) if docs else None, "does not answer on" in said)
    finally:
        _seams316()
    eq("tunnel + own certificate (POST /websites/<id>/enable): in tunnel mode no operator's certificate or key is "
       "sent to the host (the configuration names none) and no domain is called unanswered; in public mode the own "
       "certificate's files are sent and the unchecked www domain is named (control)",
       got, {"public": (["p316-own.example.org.crt", "p316-own.example.org.key"], True), "tunnel": ([], False)})
    real = _w316.current_user
    _w316.current_user = _NS316(is_superadmin=True)
    try:
        row = _proxy316(st, "tunnel")
        row.installed_version = ""
        _db316.session.commit()
        why = _w316.online_refusal(site)
    finally:
        _w316.current_user = real
    eq("tunnel (online_refusal): a host in tunnel mode without the web proxy is still refused, with the install link",
       getattr(why, "template", None), _w316.S_NO_PROXY_SUPER)
    _proxy316(st, "public")
    site.enabled = True
    dom.verified_at = dom.verified_at or utcnow()
    _db316.session.commit()
    return site


def _s11_watch(st, site):
    from panel.core.clock import utcnow
    su = _Client316(st.su.id)
    www = [d for d in site.domains if d.domain.startswith("www.")][0]
    www.verified_at, www.dns_state, www.cert_state, www.cert_error = utcnow(), "cdn", "pending", ""
    _db316.session.commit()
    got = {}
    for mode in ("public", "tunnel"):
        _proxy316(st, mode)
        www.cert_state, www.cert_error = "pending", "timeout"      # a reason the proxy gave before
        _db316.session.commit()
        _wd316._MISSING_SINCE[www.domain] = _wd316.time.monotonic() - _wd316.CERT_MISSING_AFTER - 5
        su.get("/websites/proxy/status?host_id=%d" % st.host.id)
        _db316.session.expire_all()
        doms = {d["domain"]: d for d in _j(su.get("/api/websites/%d" % site.id)).get("domains", [])}
        own, cdn = doms.get(site.domains[0].domain, {}), doms.get(www.domain, {})
        got[mode] = (_db316.session.get(_Dom316, www.id).cert_state, bool(cdn.get("cert_error")),
                     bool(cdn.get("cdn_note")), cdn.get("cert_state"), own.get("cert_state"),
                     (own.get("own_cert") or {}).get("names"))
    eq("tunnel + certificate watch (GET /websites/proxy/status, then /api/websites/<id>): in tunnel mode a served "
       "domain without a certificate is not called failed (the proxy asks for none), and the Domains tab shows the "
       "tunnel's state with no certificate error (not even one stored before) or Cloudflare certificate note, an own "
       "certificate's facts kept; in public mode it is failed after the wait, with the error and the note (control)",
       got, {"public": ("failed", True, True, "failed", "own", [site.domains[0].domain]),
             "tunnel": ("pending", False, False, "tunnel", "tunnel", [site.domains[0].domain])})
    site.enabled = False
    _db316.session.commit()
    _proxy316(st, "public")


def _s11_merged(st):
    _s11_watch(st, _s11_enable(st))


def _s11_page():
    page = _page301("website.html", _CUST316, site=_NS316(id=7, name="shop", kind="php"), can_manage=True,
                    can_files=False, site_admin=False)
    got = {}
    for state in ("tunnel", "own"):
        dom = {"id": 1, "domain": "shop.example.org", "is_primary": True, "dns_state": "cdn", "cert_state": state,
               "cert_mode": "own", "own_cert": {"issuer": "Example Origin CA"}}
        site = {"success": True, "site": {"id": 7, "name": "shop", "kind": "php", "state": "running"}, "domains": [dom],
                "dns": {}, "tunnel": {"service": "http://localhost:19080"} if state == "tunnel" else None}
        got[state] = _node301(page, _COMMON301 + ["website_site.js"], r"""
  for (let i = 0; i < 4; i++) await tick();
  const t = $('wd-list').textContent;
  return {tunnel: t.indexOf('HTTPS by the tunnel (Cloudflare)') >= 0, own: t.indexOf('Your own certificate') >= 0,
          issuer: t.indexOf('Example Origin CA') >= 0};
""", routes={"/api/websites/7": site})
    eq("tunnel + own certificate (Domains tab): in tunnel mode a domain with its own certificate says HTTPS by the "
       "tunnel, not the certificate the proxy is not serving; outside it, Your own certificate and its issuer (control)",
       got, {"tunnel": {"tunnel": True, "own": False, "issuer": False},
             "own": {"tunnel": False, "own": True, "issuer": True}})


# ── running the sections ──────────────────────────────────────────────────────────────────────────
def _cleanup316_children(sites):
    for d in _Dom316.query.filter(_Dom316.website_id.in_(sorted(sites) or [0])).all():
        _db316.session.delete(d)
    for p in _Proxy316.query.filter(_Proxy316.remote_id.in_(_ROWS316["remotes"] or [0])).all():
        _db316.session.delete(p)


def _cleanup316():
    _db316.session.rollback()
    sites = set(_ROWS316["sites"]) | {s.id for s in _Site316.query.filter(
        _Site316.remote_id.in_(_ROWS316["remotes"] or [0])).all()}
    _cleanup316_children(sites)
    for model, ids in ((_Site316, sorted(sites)), (_User316, _ROWS316["users"]), (_Remote316, _ROWS316["remotes"])):
        for i in ids:
            row = _db316.session.get(model, i)
            if row is not None:
                _db316.session.delete(row)
    _db316.session.commit()
    _cfg316.update_config(lambda c: [c.pop(k, None) for k in list(c) if k.startswith("websites_")])


def _ran316(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran316.last)."""
    import traceback
    try:
        step(*args)
        _ran316.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db316.session.rollback()
        _ran316.last = traceback.format_exc()[-1500:]
        return False


_ran316.last = ""
_trips316 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part316")
        _seams316()
        _st316 = _rows316()
        _CUST316 = _customer316()
        for _sec316 in (_s1_gate, _s2_logs, _s3_tunnel, _s4_options, _s5_route, _s6_overview, _s8_settings,
                        _s9_perf_server, _s10_rest, _s11_merged):
            check("part316: %s ran to the end" % _sec316.__name__, _ran316(_sec316, _st316), _ran316.last)
        for _sec316 in (_s3_page, _s5_render, _s5_helper, _s8_bounds, _s7_upload, _s9_perf, _s9_egress, _s9_proxy_card,
                        _s11_page):
            check("part316: %s ran to the end" % _sec316.__name__, _ran316(_sec316), _ran316.last)
        eq("part316: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips316:], [])
    finally:
        _p9_restore_all()
        _w316._STATUS.clear()
        _wset316._PURGED.clear()
        _wv316._FIREWALL.clear()
        _cleanup316()
