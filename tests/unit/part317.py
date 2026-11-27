"""Part 317 of the unit suite: a website's own gate lets a request its .htaccess rewrote through, and Update reaches it.

1. The gate (Apache, PHP kinds): WordPress's .htaccess sends every path that is not a file (robots.txt, a missing
   favicon, pretty links, the REST API) to index.php as an internal redirect. The gate's header is removed in the
   fixup phase, so that redirect reached the gate without it and was refused (AH01630 for real visitors). The gate
   now passes an internal redirect whose request passed (REDIRECT_STATUS=200); a request that did not come through
   the proxy is still refused, the error page after a refusal included. The token is never rotated by an action.
2. Update: a site installed with an older revision of the files the panel writes (or before the panel recorded it)
   is offered Update on its Overview; Update installs it again with the new gate and records the revision; an
   install that left a running site alone (the object cache switched) records nothing, as its server was not
   restarted.

HOW IT RUNS. part12's app and its database. ssh_manager.websites' seams answer for the host and record what the
routes ask of it; nothing reaches a host (part12's tripwire is armed).
"""
import base64 as _b64317
import os
import re as _re317

from flask import g as _g317

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg317
from panel.db.models import (RemoteServer as _Remote317, User as _User317, Website as _Site317,
                             WebsiteDomain as _Dom317, WebsiteProxy as _Proxy317, db as _db317)
from panel.ops.ssh_manager import websites as _sw317
from panel.routes import websites as _w317
from panel.services import websites as _ws317

_TOKEN317 = "g" * 40
_IMAGE317 = "localhost/lgsm-site-php:8.4-aaaa"
_ROWS317 = {"sites": [], "remotes": [], "users": []}
_REC317 = {"apply": [], "install": []}


class _Client317:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g317.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g317.pop("_login_user", None)
        return self.c.get(*a, **k)


def _rows317():
    r = _Remote317(name="p317-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.77")
    su = _User317(username="p317-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db317.session.add_all([r, su])
    _db317.session.commit()
    _ROWS317["remotes"].append(r.id)
    _ROWS317["users"].append(su.id)
    return r, su


def _site317(host, name, **kw):
    s = _Site317(remote_id=host.id, name=name, kind="wordpress", app_recipe="wordpress", state="running",
                 php_version="8.4", proxy_secret=_cfg317.encrypt_secret(_TOKEN317), **kw)
    _db317.session.add(s)
    _db317.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    from panel.core.clock import utcnow
    _db317.session.add(_Dom317(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=utcnow(), dns_state="matching"))
    _db317.session.commit()
    _ROWS317["sites"].append(s.id)
    return s


def _bundle_conf(stdin, name):
    """The file `name` (a path ending) out of a site's install bundle (`<path> <base64>` lines)."""
    for line in (stdin or "").splitlines():
        path, _sp, data = line.partition(" ")
        if path.endswith(name):
            return _b64317.b64decode(data).decode("utf-8")
    return ""


def _seams317():
    """The host at ssh_manager.websites' seams: installs build the real bundle; proxy applies are recorded."""
    def install(remote, site, db=None, start_it=True, restart=True):
        stdin, _image, refused = _sw317._site_bundle(site, (1005, 1005), {"splice": True, "cpu_delegated": True}, db)
        _REC317["install"].append((site.id, stdin or "", refused))
        return (False, refused) if refused else (True, _sw317.OK_STARTED)

    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC317["apply"].append(text)
        return True, _sw317.OK_APPLIED
    _p9_patch(_sw317, "install", install)
    _p9_patch(_sw317, "proxy_apply", apply)
    _p9_patch(_sw317, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, ""))
    _p9_patch(_sw317, "ports_apply", lambda *a, **k: (True, _sw317.OK_PORTS))
    _p9_patch(_sw317, "proxy_stop", lambda *a, **k: (True, "stopped"))
    _p9_patch(_sw317, "tunnel_apply", lambda *a, **k: (True, _sw317.OK_TUNNEL))
    _p9_patch(_sw317, "quota_set", lambda *a, **k: (True, _sw317.OK_QUOTA))
    _p9_patch(_sw317, "start", lambda remote, site, restart=False: (True, "started"))
    _p9_patch(_sw317, "stop", lambda remote, site: (True, "stopped"))
    _p9_patch(_sw317, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=2.11.9\nactive=active\n"))
    _p9_patch(_sw317, "site_probe", lambda remote, site: (True, {}))
    _p9_patch(_sw317, "site_logs", lambda remote, site: (True, ""))
    _p9_patch(_ws317, "image_for", lambda s: _IMAGE317)


def _reset317():
    _REC317["apply"], _REC317["install"] = [], []
    _w317._STATUS.clear()


# ── 1. the gate ───────────────────────────────────────────────────────────────────────────────────
def _gate_denies(conf, headers, env):
    """Whether Apache's <Location "/"> <If> in `conf` refuses a request with these headers and environment.

    The expression is the conf's own: every clause `%{HTTP:name} != 'v'` or `%{ENV:name} != 'v'`, joined by &&;
    the request is refused when all hold. Headers are what the request carries when the authorization runs; the
    environment is the request's (Apache sets REDIRECT_STATUS on an internal redirect to the status of the request
    it came from; a client cannot set it). None when the conf has no such gate or a clause of another form.
    """
    m = _re317.search(r'<Location "/">\s*<If "([^"]+)">\s*Require all denied', conf)
    if not m:
        return None
    for clause in m.group(1).split("&&"):
        c = _re317.fullmatch(r"\s*%\{(HTTP|ENV):([A-Za-z0-9_-]+)\} != '([^']*)'\s*", clause)
        if not c:
            return None
        have = (headers if c.group(1) == "HTTP" else env).get(c.group(2), "")
        if have == c.group(3):
            return False
    return True


def _s1_gate(host, su):
    site = _site317(host, "p317-gate")
    _reset317()
    r = _Client317(su.id).post("/websites/%d/update-image" % site.id)
    conf = _bundle_conf((_REC317["install"] or [(0, "", None)])[-1][1], "apache.conf")
    tok = {"X-Panel-Proxy-Token": _TOKEN317}
    cases = {"through the proxy, a file that is there": (tok, {}),
             "through the proxy, rewritten to index.php (the header removed in fixups)": ({}, {"REDIRECT_STATUS": "200"}),
             "on the loopback port with no token": ({}, {}),
             "no token, then the error page after the refusal": ({}, {"REDIRECT_STATUS": "403"}),
             "a REDIRECT_STATUS header sent by the client": ({"REDIRECT_STATUS": "200"}, {}),
             "a wrong token": ({"X-Panel-Proxy-Token": "x" * 40}, {})}
    got = {k: _gate_denies(conf, h, e) for k, (h, e) in cases.items()}
    eq("part317 gate (POST /websites/<id>/update-image, the Apache config it writes): a request WordPress's .htaccess "
       "rewrote to index.php is served (robots.txt, the favicon, pretty links, the REST API); a request that did not "
       "come through the proxy is refused, the error page after a refusal included",
       (r.status_code, got),
       (200, {"through the proxy, a file that is there": False,
              "through the proxy, rewritten to index.php (the header removed in fixups)": False,
              "on the loopback port with no token": True, "no token, then the error page after the refusal": True,
              "a REDIRECT_STATUS header sent by the client": True, "a wrong token": True}))
    _s1_token(su, site)


def _s1_token(su, site):
    c = _Client317(su.id)
    proxy = _Proxy317.query.filter_by(remote_id=site.remote_id).first() or _Proxy317(remote_id=site.remote_id)
    proxy.installed_version = "2.11.9"      # Put online refuses a host without the web proxy installed
    _db317.session.add(proxy)
    _db317.session.commit()
    _reset317()
    for verb, body in (("enable", {}), ("settings", {"limits": {"mem_mb": site.mem_mb + 64}, "customer_note": "n"}),
                       ("update-image", {}), ("disable", {}), ("enable", {})):
        c.post("/websites/%d/%s" % (site.id, verb), json=body)
    _db317.session.expire_all()
    row = _db317.session.get(_Site317, site.id)
    proxy_tokens = {m for text in _REC317["apply"] for m in _re317.findall(r'header_up X-Panel-Proxy-Token "([^"]+)"', text)}
    conf_tokens = {m for _i, stdin, _r in _REC317["install"]
                   for m in _re317.findall(r"!= '([A-Za-z0-9_-]{32,})'", _bundle_conf(stdin, "apache.conf"))}
    eq("part317 gate token: Put online, a Settings save that reinstalls, Update and Take offline never rotate the "
       "site's proxy token; the token the proxy sends is the one in the site's own config",
       (_cfg317.decrypt_secret(row.proxy_secret), proxy_tokens, conf_tokens, len(_REC317["install"]) >= 2),
       (_TOKEN317, {_TOKEN317}, {_TOKEN317}, True))


# ── 2. Update reaches a site installed with the old gate ─────────────────────────────────────────
def _offered(c, site_id):
    _w317._STATUS.clear()
    _db317.session.expire_all()
    return (c.get("/api/websites/%d" % site_id).get_json(silent=True) or {}).get("site", {}).get("image", {})


def _s2_update(host, su):
    c = _Client317(su.id)
    unrecorded = _site317(host, "p317-old")
    files1 = _site317(host, "p317-files1", image_key="files-1", image_digest=_IMAGE317)
    before = (_offered(c, unrecorded.id).get("update_available"), _offered(c, files1.id).get("update_available"))
    page = c.get("/websites/%d" % files1.id).get_data(as_text=True)
    _reset317()
    r = c.post("/websites/%d/update-image" % files1.id)
    conf = _bundle_conf((_REC317["install"] or [(0, "", None)])[-1][1], "apache.conf")
    after = _offered(c, files1.id)
    row = _db317.session.get(_Site317, files1.id)
    eq("part317 Update (GET /api/websites/<id>, the Overview, POST update-image): a site installed before the panel "
       "recorded its files and one on files-1 are offered Update, its button is on the Overview; Update writes the new "
       "gate, keeps the token, records the revision and is no longer offered",
       (before, 'id="ws-update"' in page, r.status_code,
        _gate_denies(conf, {}, {"REDIRECT_STATUS": "200"}), _gate_denies(conf, {}, {}),
        _cfg317.decrypt_secret(row.proxy_secret), row.image_key, after.get("update_available"), after.get("name")),
       ((True, True), True, 200, False, True, _TOKEN317, _ws317.SITE_FILES_REV, False, "lgsm-site-php"))
    _p9_patch(_ws317, "image_for", lambda s: "localhost/lgsm-site-php:8.4-bbbb")
    newer = _offered(c, files1.id).get("update_available")
    _p9_patch(_ws317, "image_for", lambda s: _IMAGE317)
    cache = _site317(host, "p317-cache", image_key="files-1", image_digest=_IMAGE317)
    ok, _said = _w317.install_site(cache, restart=False)
    _db317.session.expire_all()
    left = _db317.session.get(_Site317, cache.id)
    eq("part317 Update: offered again when the signed catalog's image changes; an install that left a running site "
       "alone (the object cache switched, restart=False) records nothing and the site is still offered Update",
       (newer, ok, left.image_key, _offered(c, cache.id).get("update_available")), (True, True, "files-1", True))


def _cleanup317():
    _db317.session.rollback()
    sites = set(_ROWS317["sites"]) | {s.id for s in _Site317.query.filter(
        _Site317.remote_id.in_(_ROWS317["remotes"] or [0])).all()}
    for d in _Dom317.query.filter(_Dom317.website_id.in_(sorted(sites) or [0])).all():
        _db317.session.delete(d)
    for p in _Proxy317.query.filter(_Proxy317.remote_id.in_(_ROWS317["remotes"] or [0])).all():
        _db317.session.delete(p)
    for model, ids in ((_Site317, sorted(sites)), (_User317, _ROWS317["users"]), (_Remote317, _ROWS317["remotes"])):
        for i in ids:
            row = _db317.session.get(model, i)
            if row is not None:
                _db317.session.delete(row)
    _db317.session.commit()


def _ran317(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran317.last)."""
    import traceback
    try:
        step(*args)
        _ran317.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db317.session.rollback()
        _ran317.last = traceback.format_exc()[-1500:]
        return False


_ran317.last = ""
_trips317 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part317")
        _seams317()
        _host317, _su317 = _rows317()
        for _sec317 in (_s1_gate, _s2_update):
            check("part317: %s ran to the end" % _sec317.__name__, _ran317(_sec317, _host317, _su317), _ran317.last)
        eq("part317: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips317:], [])
    finally:
        _p9_restore_all()
        _w317._STATUS.clear()
        _cleanup317()
