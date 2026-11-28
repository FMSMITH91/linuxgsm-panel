"""Part 331 of the unit suite: websites in a folder of a domain (example.org/forums) beside the one at its root.

1. The address model: a folder's shape (validation.website_folder / website_address), (domain, folder) unique, the
   path column held to that shape, and the migration that frees an older database's one-site-per-domain UNIQUE.
2. Who may add which address (POST /websites/<id>/domains/add with a folder): a folder goes on a domain one of the
   user's sites already has on the same host; folders never nest; a site has one folder; a one-click app's folder is
   chosen at install; a static site moved into a folder has its own server written again.
3. The proxy: one block per shared domain, a handle per folder (longest first) before the root's, the prefix kept,
   in public and tunnel mode; the guard's paths, rules and page cache under the folder; loggers on the block.
4. The guard maps a ban to the site by domain and folder (the helper's lgsm_folder, the routes' Blocked list).
5. The apps and the sites' own servers under a folder: each recipe's base URL and cookie path, Apache's Alias,
   nginx's alias, the installer's loopback paths.
6. The pages: the site's address, Open site, the Domains tab's folder form and its OWASP note, es/fr.

HOW IT RUNS. Through part12's app (its tripwire armed): routes by the test client with the host calls stubbed, the
render and the recipes by the functions the routes and the install job call, the helper loaded from its file.
"""
import ast as _ast331
import json as _json331
import os
import tempfile as _tf331
from types import SimpleNamespace as _NS331

import sqlalchemy as _sa331
from flask import g as _g331
from sqlalchemy.exc import IntegrityError as _IntegrityError331

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg331
from panel.core import validation as _val331
from panel.core.clock import utcnow as _utcnow331
from panel.db import models as _models331
from panel.db.models import (AuditLog as _Audit331, Group as _Group331, RemoteServer as _Remote331, User as _User331,
                             Website as _Site331, WebsiteDomain as _Dom331, WebsiteProxy as _Proxy331, db as _db331)
from panel.ops.ssh_manager import websites as _sw331
from panel.routes import websites as _w331
from panel.routes import websites_domains as _wd331
from panel.routes import websites_guard as _wg331
from panel.security import auth as _auth331
from panel.services import website_folders as _wf331
from panel.services import websites as _ws331
from panel.services import websites_catalog as _wcat331
from panel.services import websites_proxy as _wp331
from panel.services import websites_recipes as _wr331

_ROWS331 = {"sites": [], "remotes": [], "users": [], "groups": []}
_TOKEN331 = "q" * 40
_DOM331 = "p331.example.org"


def _client331(uid):
    _g331.pop("_login_user", None)
    return _p9_client(uid)


def _remote331(name, ip):
    r = _Remote331(name=name, host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip=ip, timezone="UTC")
    _db331.session.add(r)
    _db331.session.commit()
    _ROWS331["remotes"].append(r.id)
    return r


def _site331(remote, name, kind="static", state="running", address=None, **kw):
    s = _Site331(remote_id=remote.id, name=name, kind=kind, state=state, enabled=kw.pop("enabled", False),
                 proxy_secret=_cfg331.encrypt_secret(_TOKEN331), **kw)
    _db331.session.add(s)
    _db331.session.flush()
    s.account, s.port = "ws%d" % s.id, 20400 + s.id % 500
    if address is not None:
        dom, _s, folder = address.partition("/")
        _db331.session.add(_Dom331(website_id=s.id, domain=dom, path="/" + folder if folder else "", is_primary=True,
                                   verified_at=_utcnow331(), dns_state="matching"))
    _db331.session.commit()
    _ROWS331["sites"].append(s.id)
    return s


def _user331(name, sites):
    """An ordinary (not customer) account whose group may run exactly `sites`."""
    g = _Group331(name="g-" + name, description="", is_default=False, is_customer=False)
    g.set_permissions([_auth331.VIEW_WEBSITES, _auth331.MANAGE_WEBSITE])
    g.websites.extend(sites)
    u = _User331(username=name, password_hash=os.urandom(8).hex(), display_name=name, is_superadmin=False,
                 is_active=True, totp_enabled=True)
    u.groups.append(g)
    _db331.session.add_all([g, u])
    _db331.session.commit()
    _ROWS331["users"].append(u.id)
    _ROWS331["groups"].append(g.id)
    return u


def _rows331(site):
    _db331.session.expire_all()
    return sorted((d.domain, d.path) for d in _db331.session.get(_Site331, site.id).domains)


# ── 1. The address model ─────────────────────────────────────────────────────────────────────────
def _s1_shape():
    f = _val331.website_folder
    eq("folders (validation.website_folder): one spelling per folder, nested segments kept, the root is ''",
       (f("forums"), f("/Forums/"), f("/a/b_c-1"), f(""), f("/")), ("/forums", "/forums", "/a/b_c-1", "", ""))
    eq("folders (refused: a dot, .., a space, a query, an empty segment, longer than 64)",
       [f(x) for x in ("/a.b", "/../x", "/a b", "/a?x", "/a//b", "/" + "a" * 64)], [None] * 6)
    eq("site addresses (validation.website_address): a domain alone, or a domain and its folder; a bad part refused",
       (_val331.website_address("Example.org/Forums"), _val331.website_address("example.org"),
        _val331.website_address("example.org/a.php"), _val331.website_address("10.0.0.1/forums")),
       (("example.org", "/forums"), ("example.org", ""), None, None))
    o = _val331.folders_overlap
    eq("folders overlap when equal or one holds the other, by whole segments; the root holds none",
       (o("/forums", "/forums/old"), o("/forums/old", "/forums"), o("/forums", "/forumsx"), o("", "/forums")),
       (True, True, False, False))


def _s1_model(host):
    s = _site331(host, "p331model")
    bad = []
    for path in ("forums", "/Forums", "/a/../b", "/forums/"):
        try:
            _Dom331(website_id=s.id, domain="m." + _DOM331, path=path)
            bad.append(None)
        except ValueError:
            bad.append("refused")
    eq("the path column holds only a canonical folder (the model's validator)", bad, ["refused"] * 4)
    other = _site331(host, "p331model2")
    _db331.session.add_all([_Dom331(website_id=s.id, domain="m." + _DOM331, path=""),
                            _Dom331(website_id=other.id, domain="m." + _DOM331, path="/shop")])
    _db331.session.commit()
    _db331.session.add(_Dom331(website_id=other.id, domain="m." + _DOM331, path="/shop"))
    try:
        _db331.session.commit()
        dup = "stored"
    except _IntegrityError331:
        _db331.session.rollback()
        dup = "refused"
    eq("(domain, folder) is unique: one domain at a root and in a folder of another site; the same address twice is "
       "refused by the table", (_rows331(s), _rows331(other), dup),
       ([("m." + _DOM331, "")], [("m." + _DOM331, "/shop")], "refused"))


def _old_table_sql(engine):
    """website_domain's CREATE TABLE as a version before folders made it: a UNIQUE on domain alone."""
    sql = str(_sa331.schema.CreateTable(_Dom331.__table__).compile(engine))
    new = "CONSTRAINT uq_website_domain_address UNIQUE (domain, path)"
    assert new in sql, sql
    return sql.replace(new, "UNIQUE (domain)")


def _insert331(engine, site_id):
    """Store a folder address of the old row's domain: "stored", or "refused" by a UNIQUE."""
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("INSERT INTO website_domain (website_id, domain, path, is_primary, cert_mode) "
                                 "VALUES (%d, 'old.%s', '/forums', 0, 'acme')" % (site_id, _DOM331))
        return "stored"
    except _IntegrityError331:
        return "refused"


def _s1_migration():
    tmp = _tf331.mkdtemp(prefix="p331-")
    engine = _sa331.create_engine("sqlite:///%s" % os.path.join(tmp, "old.db"))
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(_old_table_sql(engine))
            conn.exec_driver_sql("INSERT INTO website_domain (id, website_id, domain, path, is_primary, cert_mode) "
                                 "VALUES (7, 1, 'old.%s', '', 1, 'acme')" % _DOM331)
        with engine.connect() as conn:
            before = _models331.domain_unique_alone(conn, "website_domain")
        real = _models331.db
        _models331.db = _NS331(engine=engine)
        try:
            _models331._free_shared_domains()
            _models331._free_shared_domains()       # the second start finds nothing to do
        finally:
            _models331.db = real
        with engine.connect() as conn:
            after = _models331.domain_unique_alone(conn, "website_domain")
        folder, again = _insert331(engine, 2), _insert331(engine, 3)
        with engine.connect() as conn:
            rows = conn.exec_driver_sql("SELECT id, domain, path FROM website_domain ORDER BY id").fetchall()
    finally:
        engine.dispose()
        for name in os.listdir(tmp):
            os.unlink(os.path.join(tmp, name))
        os.rmdir(tmp)
    eq("migration (_free_shared_domains on a database made before folders): the one-site-per-domain UNIQUE is gone, "
       "the row keeps its id, a folder of the same domain is stored, the same address twice is still refused",
       (before, after, folder, [tuple(r) for r in rows], again),
       (True, False, "stored", [(7, "old." + _DOM331, ""), (8, "old." + _DOM331, "/forums")], "refused"))
    fn = next(n for n in _ast331.walk(_ast331.parse(open(_models331.__file__).read()))
              if isinstance(n, _ast331.FunctionDef) and n.name == "_run_light_migrations")
    calls = {c.func.id for c in _ast331.walk(fn) if isinstance(c, _ast331.Call) and isinstance(c.func, _ast331.Name)}
    check("migration: every start runs it (_run_light_migrations calls _free_shared_domains)",
          "_free_shared_domains" in calls, sorted(calls))


# ── 2. Who may add which address ─────────────────────────────────────────────────────────────────
def _add331(uid, site, **form):
    r = _client331(uid).post("/websites/%d/domains/add" % site.id, json=form)
    return r.status_code, _p9_json(r).get("message") or ""


def _s2_routes(host, other_host, su):
    _p9_patch(_wd331._dns, "check", lambda domain, remote: ("matching", ["198.51.100.31"], []))
    installs = []
    _p9_patch(_sw331, "install", lambda remote, site, db=None, start_it=True, restart=True, progress=None:
              installs.append((site.id, start_it)) or (True, "ok"))
    root = _site331(host, "p331root", address=_DOM331)
    forum = _site331(host, "p331forum")
    ok = _add331(su.id, forum, domain=_DOM331, folder="Forums")
    eq("folder (POST .../domains/add with a folder, a superadmin): stored as the canonical folder; the static site, "
       "running with no address before, has its own server written again for it and restarted",
       (ok[0], _rows331(forum), installs), (200, [(_DOM331, "/forums")], [(forum.id, True)]))
    del installs[:]
    plain = _site331(host, "p331plain")
    eq("folder (control: a whole domain on an empty site writes nothing again)",
       (_add331(su.id, plain, domain="plain." + _DOM331)[0], installs), (200, []))
    nest = _site331(host, "p331nest")
    _site331(host, "p331deep", address=_DOM331 + "/docs/v1")
    eq("folder (refused: inside another site's folder, holding one, the same address typed as domain/folder)",
       (_add331(su.id, nest, domain=_DOM331, folder="forums/old"), _add331(su.id, nest, domain=_DOM331, folder="docs"),
        _add331(su.id, nest, domain=_DOM331 + "/forums")),
       ((409, _wf331.S_OVERLAP.format(domain=_DOM331, folder="/forums")),
        (409, _wf331.S_OVERLAP.format(domain=_DOM331, folder="/docs/v1")), (409, _wf331.S_TAKEN)))
    _add331(su.id, root, domain="x." + _DOM331)
    eq("folder (refused: a second folder on a site that has one; a root domain on a site in a folder)",
       (_add331(su.id, forum, domain="x." + _DOM331, folder="blog")[0], _add331(su.id, forum, domain="y." + _DOM331)),
       (409, (409, _wf331.S_ONE_FOLDER.format(where="/forums"))))
    far = _site331(other_host, "p331far")
    eq("folder (refused: the domain is served on another host)", _add331(su.id, far, domain=_DOM331, folder="far"),
       (409, _wf331.S_OTHER_HOST))
    eq("folder (refused in words: a bad folder, an empty one from the folder form)",
       (_add331(su.id, nest, domain=_DOM331, folder="a.php"), _add331(su.id, nest, domain=_DOM331, folder="")),
       ((400, _wd331.S_BAD_FOLDER), (400, _wd331.S_FOLDER_NEEDED)))
    app = _site331(host, "p331app", kind="wordpress", app_recipe="wordpress")
    eq("folder (refused: a one-click app installed at a root keeps its address; its folder is chosen at install)",
       _add331(su.id, app, domain=_DOM331, folder="wp"), (409, _wf331.S_APP_FOLDER))
    _s2_tenants(host, root, nest)


def _s2_tenants(host, root, nest):
    mine = _site331(host, "p331mine")
    tenant = _user331("p331-tenant", [mine])
    owner = _user331("p331-owner", [mine, root])
    lone = _site331(host, "p331lone", address="lone.%s/docs" % _DOM331)
    with _p9.test_request_context():
        offered = _wf331.host_domains(tenant, mine, lambda sid: _auth331.MANAGE_WEBSITE)
        offered_owner = _wf331.host_domains(owner, mine, lambda sid: _auth331.MANAGE_WEBSITE)
    eq("the folder form's domains: only those held by sites the viewer manages on the host",
       (offered, _DOM331 in offered_owner, "lone." + _DOM331 in offered_owner), ([], True, False))
    eq("folder (refused to someone who manages no site holding the domain; a domain used nowhere gets the same answer)",
       (_add331(tenant.id, mine, domain=_DOM331, folder="shop"), _add331(tenant.id, mine, domain="none." + _DOM331,
                                                                           folder="shop")),
       ((409, _wf331.S_NOT_YOURS), (409, _wf331.S_NOT_YOURS)))
    eq("folder (control: someone who manages the site at the domain's root adds a folder of it)",
       (_add331(owner.id, mine, domain=_DOM331, folder="shop")[0], _rows331(mine)), (200, [(_DOM331, "/shop")]))
    eq("root (refused to someone who manages none of the folder sites on a domain with no root site)",
       _add331(owner.id, mine, domain=lone.domains[0].domain), (409, _wf331.S_DOMAIN_TAKEN))
    del nest


# ── 3. The proxy ─────────────────────────────────────────────────────────────────────────────────
class _P331:
    origin_pull_mtls = False
    custom_trusted = False

    def __init__(self, mode, guard):
        self.exposure_mode, self.guard = mode, _json331.dumps({"enabled": guard})

    def presets(self):
        return []

    def cidrs(self):
        return []

    def url_nets(self):
        return []


def _row331(rid, domain, path="", site=None):
    return _NS331(id=rid, domain=domain, path=path, is_primary=True, verified_at=_utcnow331(), cert_mode="acme",
                  own_cert_pem="", own_key_secret="", website=site, address=domain + path)


def _fake_site331(sid, name, rows, **kw):
    s = _NS331(id=sid, name=name, port=20500 + sid, enabled=True, proxy_secret="x", max_body_mb=64, static_cache=False,
               custom_rules=kw.get("rules", "[]"), page_cache=kw.get("cache", False), page_cache_ttl=120,
               access_log=kw.get("log", False), raw_proxy_snippet="", own_cert_pem="", own_key_secret="")
    s.domains = rows
    return s


def _sites331():
    rules = _json331.dumps([{"type": "deny", "path": "/private"}, {"type": "redirect", "from": "/old", "to": "/new",
                                                                    "code": 301}])
    return [_fake_site331(1, "main", [_row331(1, "a." + _DOM331), _row331(2, "www.a." + _DOM331)]),
            _fake_site331(2, "wiki", [_row331(3, "a." + _DOM331, "/wiki")]),
            _fake_site331(3, "forum", [_row331(4, "a." + _DOM331, "/community/forums")], rules=rules, cache=True,
                          log=True),
            _fake_site331(4, "docs", [_row331(5, "b." + _DOM331, "/docs")])]


def _render331(mode="public", guard=False, cache=False):
    return _wp331.render(_sites331(), _P331(mode, guard), {"cache_build": cache}, secret_of=lambda s: _TOKEN331)


def _block331(text, head):
    start = text.index(head)
    return text[start:text.index("\n}\n", start) + 2]


def _s3_render():
    text = _render331()
    a = _block331(text, "# domain a.%s" % _DOM331)
    order = [a.index(m) for m in ("@lgsmfolder3 path /community/forums /community/forums/*", "handle @lgsmfolder3 {",
                                  "@lgsmfolder2 path /wiki /wiki/*", "handle @lgsmfolder2 {", "# site 1 (main)\n\thandle {")]
    eq("render (a domain with sites in folders): one block for it, the longest folder first, each folder matched with "
       "and below it, the root site's handle last; the root site's other domain keeps its own block",
       (order == sorted(order), "a.%s {" % _DOM331 in a, "www.a.%s {" % _DOM331 in text,
        ("a.%s, " % _DOM331) in text or (", a.%s {" % _DOM331) in text),
       (True, True, True, False))
    check("render (the prefix is kept: a folder's handle proxies the whole path, no strip)",
          "uri strip_prefix" not in a and "handle_path" not in a and "127.0.0.1:20503 {" in a, a[:400])
    b = _block331(text, "# domain b.%s" % _DOM331)
    check("render (a domain with no site at its root answers 404 outside its folders)",
          "\thandle {\n\t\trespond 404\n\t}" in b, b)
    eq("render (a folder site's rules and page cache are its folder's paths)",
       ("@deny0 path /community/forums/private" in a, 'redir /community/forums/old "/community/forums/new" 301' in a),
       (True, True))
    cached = _render331(cache=True)
    eq("render (page cache: the bypass paths are under the folder; the cache's state reads the folder site's ttl)",
       ("not path /community/forums/wp-admin*" in cached, _wp331.cached_sites(cached)), (True, {3: 120}))
    tunnel = _render331("tunnel")
    check("render (tunnel mode: the same block in plain HTTP on the loopback, no certificate)",
          "http://a.%s {" % _DOM331 in tunnel and "handle @lgsmfolder3 {" in tunnel
          and "tls {" not in _block331(tunnel, "# domain a.%s" % _DOM331), tunnel[-1500:])
    plain = _wp331.render(_sites331()[:1], _P331("public", False), {}, secret_of=lambda s: _TOKEN331)
    check("render (control: no site in a folder, no handle and no shared block)",
          "handle" not in plain and "websites in folders" not in plain and "a.%s, www.a.%s {" % (_DOM331, _DOM331) in plain,
          plain[-800:])


def _s3_guard():
    text = _render331("public", guard=True)
    a = _block331(text, "# domain a.%s" % _DOM331)
    handle = a[a.index("handle @lgsmfolder3 {"):a.index("# site 2 (wiki)")]
    eq("render with the guard (a folder site's watched paths are its folder's, its watched requests carry the folder)",
       ("path /community/forums/wp-login.php" in handle, "log_append @lgsmlogin lgsm_folder /community/forums" in handle,
        "\t\tpath /wp-login.php" in handle),
       (True, True, False))
    eq("render with the guard (the loggers are defined on the block, never inside a handle; each handle names its own)",
       ("\tlog lgsmsec3_" in a.split("# site 3")[0], "\t\tlog lgsmsec" in handle, "log_name @lgsmlogin lgsmsec3_" in handle),
       (True, False, True))
    root = a[a.index("# site 1 (main)\n\thandle {"):]
    check("render with the guard (control: the root site's paths and tags are the domain's own)",
          "\t\t\tpath /wp-login.php /xmlrpc.php" in root and "lgsm_folder" not in root, root[:600])


# ── 4. The guard's mapping ───────────────────────────────────────────────────────────────────────
def _helper331():
    import importlib.machinery as _mach
    import importlib.util as _ilu
    spec = _ilu.spec_from_loader("panel_helper_p331", _mach.SourceFileLoader(
        "panel_helper_p331", os.path.join(_root, "tools", "panel-helper")))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _s4_helper():
    h = _helper331()
    tight = {"separators": (",", ":")}      # as the proxy writes its JSON lines
    line = _json331.dumps({"client_ip": "203.0.113.9", "request": {"host": "a.%s" % _DOM331}, "lgsm": "login",
                           "lgsm_folder": "/forums"}, **tight)
    root = _json331.dumps({"client_ip": "203.0.113.9", "request": {"host": "a.%s" % _DOM331}, "lgsm": "login"}, **tight)
    bad = _json331.dumps({"client_ip": "203.0.113.9", "request": {"host": "a.%s" % _DOM331}, "lgsm": "login",
                          "lgsm_folder": "/../etc"}, **tight)
    site = "a.%s/forums" % _DOM331
    eq("helper (a ban's site): the folder a watched request carries joins its host; none, or one of another shape, "
       "leaves the host alone", (h.web_guard_host([line], "203.0.113.9", "login"),
                                 h.web_guard_host([root], "203.0.113.9", "login"),
                                 h.web_guard_host([bad], "203.0.113.9", "login")),
       (site, "a." + _DOM331, "a." + _DOM331))
    entry = h.web_guard_entry(h.web_guard_entry_text("lgsm-web-login", 10, 20, site))
    events = h.web_guard_events_after([h.web_guard_event_line(3, 10, "ban", "203.0.113.9", "lgsm-web-login", site)], 0)
    eq("helper (a deny entry and an event naming a folder site read back)", ((entry or {}).get("host"), events[0][5]),
       (site, site))


def _s4_routes(host, su):
    root = _db331.session.get(_Site331, _site_id331("p331root"))
    forum = _db331.session.get(_Site331, _site_id331("p331forum"))
    out = ("ban=203.0.113.7 lgsm-web-login 1700000000 1700000600 %s/forums\n"
           "ban=203.0.113.8 lgsm-web-scan 1700000000 1700000600 %s\n" % (_DOM331, _DOM331))
    _p9_patch(_sw331, "guard_list", lambda remote, after=0: (True, _sw331.parse_guard_list(out)))
    got_f = _p9_json(_client331(su.id).get("/websites/%d/blocked" % forum.id))
    got_r = _p9_json(_client331(su.id).get("/websites/%d/blocked" % root.id))
    eq("Blocked visitors (GET .../blocked): a ban made in a folder is that folder site's, named by its address; the "
       "domain's own ban is the root site's",
       ([(e["ip"], e["site"]) for e in got_f.get("entries", [])], [(e["ip"], e["site"]) for e in got_r.get("entries", [])]),
       ([("203.0.113.7", "%s/forums" % _DOM331)], [("203.0.113.8", "")]))
    with _p9.test_request_context():
        eq("ban audit (_site_of): the event's site by domain and folder", (
            getattr(_wg331._site_of(host, "%s/forums" % _DOM331), "id", None), getattr(_wg331._site_of(host, _DOM331),
                                                                                      "id", None)), (forum.id, root.id))


def _site_id331(name):
    return _Site331.query.filter(_Site331.name == name, _Site331.remote_id.in_(_ROWS331["remotes"])).first().id


# ── 5. The apps and the sites' own servers ───────────────────────────────────────────────────────
def _values331(site, recipe_name, kind):
    recipe = _wcat331.recipe(recipe_name)
    step = next(s for s in recipe["steps"] if s["type"] == kind)
    _step, values = _sw331._step_values(site, dict(step, secrets={"admin_user": "admin331", "admin_email":
                                                                  "a@p331.example.org", "admin_password": "x" * 16}))
    return recipe, step, dict(values, _uid="1000", _gid="1000", _network="none")


def _s5_recipes(host):
    folder = _site331(host, "p331bb", kind="php", state="creating", address=_DOM331 + "/board", app_recipe="phpbb")
    rootsite = _site331(host, "p331bbroot", kind="php", state="creating", address="bb." + _DOM331, app_recipe="phpbb")
    recipe, step, values = _values331(folder, "phpbb", "render-config")
    _sh, yml = _wr331.step_sh(folder.account, folder, step, values, recipe, _TOKEN331)
    _r, step_r, values_r = _values331(rootsite, "phpbb", "render-config")
    _sh_r, yml_r = _wr331.step_sh(rootsite.account, rootsite, step_r, values_r, recipe, _TOKEN331)
    eq("phpBB in a folder (its install's config): script_path is the folder; at a root it is /",
       ('script_path: "/board"' in yml, 'script_path: "/"' in yml_r), (True, True))
    cookie = next(s for s in recipe["steps"] if s["type"] == "run-in-container" and "cookie_path" in s["argv"])
    sh, _in = _wr331.step_sh(folder.account, folder, cookie, values, recipe, _TOKEN331)
    check("phpBB in a folder: its cookie path is set to the folder", "config:set cookie_path /board/" in sh, sh[-300:])
    recipe, step, values = _values331(folder, "mybb", "drive-web-installer")
    sh, _in = _wr331.step_sh(folder.account, folder, step, values, recipe, _TOKEN331)
    eq("MyBB in a folder (its web installer): the pages under the folder, bburl and cookie path the folder's",
       ("http://127.0.0.1:%d/board/install/index.php" % folder.port in sh, "cookiepath=/board/" in sh,
        "bburl=https://%s/board" % _DOM331 in sh), (True, True, True))
    recipe, step, values = _values331(folder, "smf", "drive-web-installer")
    sh, _in = _wr331.step_sh(folder.account, folder, step, values, recipe, _TOKEN331)
    smf_cookie = any(s["type"] == "run-in-container" and "localCookies" in " ".join(s["argv"]) for s in recipe["steps"])
    eq("SMF in a folder: boardurl is the folder's address, and its cookies follow it (localCookies)",
       ("boardurl=https://%s/board" % _DOM331 in sh, smf_cookie), (True, True))
    _r, _st, wp_values = _values331(folder, "wordpress", "run-in-container")
    eq("WordPress in a folder: its address (siteurl and home, from which it sets its cookie paths) names the folder; "
       "at a root it does not", (wp_values["site_url"], _values331(rootsite, "wordpress", "run-in-container")[2][
                                     "site_url"]), ("https://%s/board" % _DOM331, "https://bb.%s" % _DOM331))
    recipe, step, values = _values331(folder, "phpbb", "verify-install")
    sh, _in = _wr331.step_sh(folder.account, folder, step, values, recipe, _TOKEN331)
    check("verify-install in a folder: the page is fetched under the folder",
          "http://127.0.0.1:%d/board/index.php" % folder.port in sh, sh[-400:])


def _s5_servers(host):
    php = _db331.session.get(_Site331, _site_id331("p331bb"))
    static = _site331(host, "p331st", address=_DOM331 + "/static")
    plain = _site331(host, "p331st2", address="st." + _DOM331)
    ids, image = (1000, 1000), "x/n@sha256:" + "7" * 64
    conf = _ws331.site_files(php, ids, "none", _TOKEN331, image=image)[_ws331.CONF + "/apache.conf"]
    nginx = _ws331.site_files(static, ids, "none", _TOKEN331, image=image)[_ws331.CONF + "/nginx.conf"]
    root_nginx = _ws331.site_files(plain, ids, "none", _TOKEN331, image=image)[_ws331.CONF + "/nginx.conf"]
    eq("the site's own server in a folder: Apache aliases the folder to its files; nginx serves the folder from them "
       "(dot files still refused first); at a root neither",
       ("    Alias /board /var/www/html" in conf, "    location /static/ {\n        alias /usr/share/nginx/html/;" in nginx,
        "location ~ /\\. {" in nginx, "alias" in root_nginx), (True, True, True, False))


# ── 6. The pages ─────────────────────────────────────────────────────────────────────────────────
def _s6_pages(host, su):
    forum = _db331.session.get(_Site331, _site_id331("p331forum"))
    forum.enabled = True
    _db331.session.commit()
    _p9_patch(_sw331, "site_probe", lambda remote, site: (False, "not reached"))
    _p9_patch(_sw331, "proxy_status", lambda remote, proxy=None: (False, "not reached"))
    got = _p9_json(_client331(su.id).get("/api/websites/%d" % forum.id))
    dom = (got.get("domains") or [{}])[0]
    eq("the site's page (GET /api/websites/<id>): its address with the folder, the shared-origin line, Open site goes "
       "to the folder, the folder form offers the host's domains",
       (dom.get("address"), dom.get("shared_note"), got.get("site", {}).get("open_url"),
        _DOM331 in (got.get("folder_domains") or [])),
       ("%s/forums" % _DOM331, _wf331.SHARED_NOTE.format(domain=_DOM331, sub="forums." + _DOM331),
        "https://%s/forums/" % _DOM331, True))
    from panel.routes import websites_view as _wv331
    _p9_patch(_wv331, "_firewall", lambda remotes: "unknown")
    listed = {s["id"]: s for s in _p9_json(_client331(su.id).get("/api/websites")).get("sites", [])}
    eq("the Websites list: the site's full address", listed.get(forum.id, {}).get("domain"), "%s/forums" % _DOM331)
    page = _client331(su.id).get("/websites/%d" % forum.id).get_data(as_text=True)
    eq("the Domains tab: the folder form beside Add domain, with OWASP's recommendation beside it",
       ('id="wd-folder"' in page, "Add a folder on a domain you already have" in page,
        "OWASP recommends a separate subdomain for each app (forums.example.org)" in page), (True, True, True))


def _s6_i18n():
    from panel.core import i18n as _i18n331
    keys = [_wf331.S_TAKEN, _wf331.S_NOT_YOURS, _wf331.S_OTHER_HOST, _wf331.S_OVERLAP, _wf331.S_ONE_FOLDER,
            _wf331.S_APP_FOLDER, _wf331.WHERE_ROOT, _wf331.SHARED_NOTE, _wd331.S_BAD_FOLDER, _wd331.S_FOLDER_NEEDED,
            _wd331.S_MOVED_FAILED]
    missing = [(lang, k) for lang in ("es", "fr") for k in keys if k not in _i18n331.catalog(lang)]
    eq("es/fr: every sentence of the folder work is translated", missing, [])


# ── running ──────────────────────────────────────────────────────────────────────────────────────
def _cleanup331():
    _db331.session.rollback()
    remotes = _ROWS331["remotes"] or [0]
    sites = sorted(set(_ROWS331["sites"]) | {s.id for s in _Site331.query.filter(_Site331.remote_id.in_(remotes))})
    _Audit331.query.filter(_Audit331.website_id.in_(sites or [0])).delete(synchronize_session=False)
    _Audit331.query.filter(_Audit331.remote_id.in_(remotes)).delete(synchronize_session=False)
    for row in (_Dom331.query.filter(_Dom331.website_id.in_(sites or [0])).all()
                + _Proxy331.query.filter(_Proxy331.remote_id.in_(remotes)).all()):
        _db331.session.delete(row)
    for model, ids in ((_User331, _ROWS331["users"]), (_Group331, _ROWS331["groups"]), (_Site331, sites),
                       (_Remote331, _ROWS331["remotes"])):
        for i in ids:
            got = _db331.session.get(model, i)
            if got is not None:
                _db331.session.delete(got)
    _db331.session.commit()
    for sid in sites:
        _w331.forget_status(sid)


def _ran331(step, *args):
    """Run one section: True when it ran to the end, else None (the traceback kept in _ran331.last)."""
    import traceback
    try:
        step(*args)
        _ran331.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db331.session.rollback()
        _ran331.last = traceback.format_exc()[-1500:]
        return None


_ran331.last = ""
_trips331 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part331")
        _host331 = _remote331("p331-host", "198.51.100.31")
        _far331 = _remote331("p331-far", "198.51.100.32")
        _su331 = _User331(username="p331-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
        _db331.session.add(_su331)
        _db331.session.commit()
        _ROWS331["users"].append(_su331.id)
        for _sec331, _args331 in ((_s1_shape, ()), (_s1_model, (_host331,)), (_s1_migration, ()),
                                  (_s2_routes, (_host331, _far331, _su331)), (_s3_render, ()), (_s3_guard, ()),
                                  (_s4_helper, ()), (_s4_routes, (_host331, _su331)), (_s5_recipes, (_host331,)),
                                  (_s5_servers, (_host331,)), (_s6_pages, (_host331, _su331)), (_s6_i18n, ())):
            check("part331: %s ran to the end" % _sec331.__name__, _ran331(_sec331, *_args331), _ran331.last)
        eq("part331: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips331:], [])
    finally:
        _p9_restore_all()
        _cleanup331()
