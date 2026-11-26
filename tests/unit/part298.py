"""Part 298 of the unit suite: websites' core: models, permissions, tenancy and the per-site access check.

1. The website permissions exist, none is in any group by default, and a customer group may hold only
   the customer set.
2. The tables: a site, its domains and its host's proxy row, the data-layer refusals of a bad name,
   account, port, domain or exposure mode, and a host removed taking its sites with it.
3. site_for: a superadmin reaches every site; anyone else only a site their group holds the permission
   on, and no access answers 404 exactly as no site does.

HOW IT RUNS. part12's app and its database, rows made and removed here; nothing reaches a host.
"""
import ast as _ast298
import inspect as _inspect298
import os as _os298
import sqlite3 as _sqlite298
import textwrap as _tw298

from flask import Flask as _Flask298
from werkzeug.exceptions import NotFound as _NotFound298

from unit.part01 import check, eq
from unit.part12 import P9_LOCAL, _p9, _p9_arm, _p9_client, _p9_restore_all
from panel.db import at_rest as _at_rest298, models as _models298
from panel.db.models import (AuditLog as _Audit298, Group as _Group298, RemoteServer as _Remote298,
                             User as _User298, Website as _Site298, WebsiteDomain as _Dom298,
                             WebsiteProxy as _Proxy298, db as _db298)
from panel.security import auth as _auth298
from panel.services import websites_access as _wa298


def _host298(name):
    """A remote host row (no transport is ever opened for it). -> id."""
    r = _Remote298(name=name, host="198.51.100.%d" % (len(name) % 200 + 1), port=22, username="u",
                   auth_method="key", auth_credential="", is_local=False)
    _db298.session.add(r)
    _db298.session.flush()
    return r.id


def _site298(remote_id, name, port):
    s = _Site298(remote_id=remote_id, name=name, kind="static")
    _db298.session.add(s)
    _db298.session.flush()
    s.account, s.port = "ws%d" % s.id, port
    _db298.session.flush()
    return s


def _user298(name, perms, sites=(), customer=False):
    g = _Group298(name="g-" + name, description="", is_default=False, is_customer=customer)
    g.set_permissions(list(perms))
    g.websites.extend(sites)
    u = _User298(username=name, password_hash=_os298.urandom(8).hex(), display_name=name,
                 is_superadmin=False, is_active=True)
    u.groups.append(g)
    _db298.session.add_all([g, u])
    _db298.session.flush()
    return u


def _reaches298(user, site_id, perm):
    """site_for's answer: the site's id, or 404."""
    try:
        return _wa298.site_for(user, site_id, perm).id
    except _NotFound298:
        return 404


# ── 1. Permissions ──────────────────────────────────────────────────────────────────────────────────
_wperms298 = (_auth298.VIEW_WEBSITES, _auth298.EDIT_WEBSITE_FILES, _auth298.MANAGE_WEBSITE,
              _auth298.CREATE_WEBSITES, _auth298.MANAGE_WEBSITES)
check("websites: the five website permissions are grantable and described, and open the Websites page",
      all(p in _auth298.ALL_PERMISSIONS and _auth298.ALL_PERMISSIONS[p] for p in _wperms298)
      and set(_auth298.WEBSITES_PAGE_PERMS) == set(_wperms298), repr(_wperms298))
eq("websites: a customer group may hold the per-site and create permissions, never MANAGE_WEBSITES",
   sorted(_auth298.CUSTOMER_PERMS), sorted(set(_wperms298) - {_auth298.MANAGE_WEBSITES}))

# ── 2 and 3. Tables and site_for ────────────────────────────────────────────────────────────────────
with _p9.app_context():
    try:
        _h298 = _host298("p298-host")
        _a298 = _site298(_h298, "p298-a", 20981)
        _b298 = _site298(_h298, "p298-b", 20982)
        _db298.session.add(_Dom298(website_id=_a298.id, domain="p298.example.org", is_primary=True))
        _db298.session.add(_Proxy298(remote_id=_h298))
        _db298.session.flush()
        check("websites: a site, its domain and its host's proxy row are stored, the account and port as set",
              _a298.account == "ws%d" % _a298.id and _a298.primary_domain.domain == "p298.example.org"
              and _Proxy298.query.filter_by(remote_id=_h298).one().exposure_mode == "public",
              repr((_a298.account, _a298.port)))
        _bad298 = []
        for _kw in ({"name": "Bad Name"}, {"kind": "perl"}, {"account": "root"}, {"port": 22},
                    {"state": "odd"}, {"php_version": "8; rm"}, {"custom_rules": "{}"},
                    {"runtime": "No de"}, {"app_port": 80}, {"start_command": "npm start\nrm -rf /"},
                    {"app_recipe": "../wp"}, {"install_steps_done": "{}"}):
            try:
                _Site298(**dict({"remote_id": _h298, "name": "ok"}, **_kw))
            except ValueError:
                continue
            _bad298.append(_kw)
        for _cls, _kw in ((_Dom298, {"domain": "10.0.0.1"}), (_Dom298, {"domain": "*.example.org"}),
                          (_Dom298, {"domain": "x.localhost"}), (_Proxy298, {"exposure_mode": "open"}),
                          (_Proxy298, {"allow_cidrs": '["10.0.0.1/8"]'})):
            try:
                _cls(**_kw)
            except ValueError:
                continue
            _bad298.append(_kw)
        check("websites: the models refuse a bad name, kind, account, port, state, PHP version, rules shape, "
              "domain (IP, wildcard, reserved) and exposure mode or allow list", not _bad298, repr(_bad298))
        _su298 = _User298(username="p298-su", password_hash=_os298.urandom(8).hex(), is_superadmin=True, is_active=True)
        _cust298 = _user298("p298-cust", [_auth298.VIEW_WEBSITES, _auth298.MANAGE_WEBSITE], [_a298], True)
        _none298 = _user298("p298-none", [_auth298.VIEW_WEBSITES])
        eq("websites: site_for gives a superadmin every site, a customer their own, and 404 for another's "
           "site, a permission they lack, a missing id and an out-of-range id",
           [_reaches298(_su298, _b298.id, _auth298.MANAGE_WEBSITES),
            _reaches298(_cust298, _a298.id, _auth298.MANAGE_WEBSITE),
            _reaches298(_cust298, _b298.id, _auth298.VIEW_WEBSITES),
            _reaches298(_cust298, _a298.id, _auth298.EDIT_WEBSITE_FILES),
            _reaches298(_none298, _a298.id, _auth298.VIEW_WEBSITES),
            _reaches298(_cust298, 10 ** 9, _auth298.VIEW_WEBSITES),
            _reaches298(_cust298, 2 ** 64, _auth298.VIEW_WEBSITES)],
           [_b298.id, _a298.id, 404, 404, 404, 404, 404])
        _db298.session.delete(_db298.session.get(_Remote298, _h298))
        _db298.session.flush()
        eq("websites: a host removed takes its sites, their domains and its proxy row with it",
           (_Site298.query.filter_by(remote_id=_h298).count(), _Dom298.query.filter_by(website_id=_a298.id).count(),
            _Proxy298.query.filter_by(remote_id=_h298).count()), (0, 0, 0))
    finally:
        _db298.session.rollback()


# ── 4-9. Tenancy through the routes: group edits, group reach, customers' 2FA, the audit log ──────────
def _commit_user298(name, groups, totp=True):
    u = _User298(username=name, password_hash=_os298.urandom(8).hex(), display_name=name,
                 is_superadmin=False, is_active=True, totp_enabled=totp)
    u.groups.extend(groups)
    _db298.session.add(u)
    return u


def _group298(name, perms, sites=(), hosts=(), customer=False):
    g = _Group298(name=name, description="", is_default=False, is_customer=customer)
    g.set_permissions(list(perms))
    g.websites.extend(sites)
    g.servers.extend(_db298.session.get(_Remote298, h) for h in hosts)
    _db298.session.add(g)
    return g


def _perms_of298(gid):
    with _p9.app_context():
        g = _db298.session.get(_Group298, gid)
        return sorted(g.get_permissions()), sorted(r.id for r in g.servers)


_T298 = {}
_XHR298 = {"X-Requested-With": "XMLHttpRequest"}
_made298 = {"users": [], "groups": [], "sites": [], "hosts": []}
try:
    _p9_arm(who="part298")
    with _p9.app_context():
        _h = _host298("p298-tenancy")
        _sa = _site298(_h, "p298-ta", 20983)
        _sb = _site298(_h, "p298-tb", 20984)
        _sl = _site298(P9_LOCAL, "p298-tl", 20985)
        _w = _auth298
        _cg = _group298("customer-p298", [_w.VIEW_WEBSITES, _w.MANAGE_WEBSITE], [_sa], customer=True)
        _dg = _group298("p298-deleg", [_w.MANAGE_GROUPS, _w.MANAGE_USERS, _w.VIEW_SERVERS, _w.VIEW_WEBSITES,
                                       _w.MANAGE_WEBSITE, _w.VIEW_LOGS], [_sa], [_h])
        _og = _group298("p298-other", [_w.VIEW_WEBSITES], [_sb])
        _og3 = _group298("p298-same", [_w.VIEW_WEBSITES], [_sa])
        _ha = _group298("p298-hostadmin", [_w.MANAGE_WEBSITES], [_sl], [_h, P9_LOCAL])
        _g1 = _group298("p298-pair-1", [_w.VIEW_WEBSITES], [_sa])
        _g2 = _group298("p298-pair-2", [_w.MANAGE_WEBSITE], [_sb])
        _cust = _commit_user298("p298-cust", [_cg], totp=False)
        _plain = _commit_user298("p298-plain", [_og], totp=False)
        _deleg = _commit_user298("p298-deleg", [_dg])
        _hadm = _commit_user298("p298-hadm", [_ha])
        _pair = _commit_user298("p298-pair", [_g1, _g2])
        _samey = _commit_user298("p298-samey", [_og3])
        _db298.session.commit()
        _ids = {k: v.id for k, v in dict(cust=_cust, plain=_plain, deleg=_deleg, hadm=_hadm, pair=_pair, samey=_samey,
                                         cg=_cg, dg=_dg, og=_og, og3=_og3, ha=_ha, g1=_g1, g2=_g2,
                                         sa=_sa, sb=_sb, sl=_sl).items()}
        _ids["h"] = _h
        _made298["users"] = [_ids[k] for k in ("cust", "plain", "deleg", "hadm", "pair", "samey")]
        _made298["groups"] = [_ids[k] for k in ("cg", "dg", "og", "og3", "ha", "g1", "g2")]
        _made298["sites"] = [_ids[k] for k in ("sa", "sb", "sl")]
        _made298["hosts"] = [_h]

    def _reach_as298(uid, sid, perm):
        return _reaches298(_db298.session.get(_User298, uid), sid, perm)

    with _p9.app_context():
        _T298["hostgrant"] = [_reach_as298(_ids["hadm"], _ids["sa"], _w.MANAGE_WEBSITES),
                              _reach_as298(_ids["hadm"], _ids["sl"], _w.MANAGE_WEBSITES)]
    eq("websites: MANAGE_WEBSITES reaches a site through a whole-host grant, but never a site on the panel's own "
       "host for anyone below a superadmin (404), even granted per site", _T298["hostgrant"], [_ids["sa"], 404])
    with _p9.app_context():
        _T298["pair"] = [_reach_as298(_ids["pair"], _ids["sa"], _w.VIEW_WEBSITES),
                         _reach_as298(_ids["pair"], _ids["sa"], _w.MANAGE_WEBSITE),
                         _reach_as298(_ids["pair"], _ids["sb"], _w.MANAGE_WEBSITE)]
    eq("websites: the permission and the site are paired per group: may see A and run B is not may run A",
       _T298["pair"], [_ids["sa"], 404, _ids["sb"]])

    # A delegated group admin edits the customer group: website permissions are kept, a server
    # permission and a host are not; the same edit on an ordinary group keeps both (control).
    _D = _p9_client(_ids["deleg"])
    _form = {"name": "customer-p298", "description": "",
             "permissions": [_w.VIEW_WEBSITES, _w.MANAGE_WEBSITE, _w.VIEW_SERVERS], "servers": [str(_h)]}
    _T298["cust_edit"] = (_D.post("/groups/%d/edit" % _ids["cg"], data=_form, headers=_XHR298).status_code, _perms_of298(_ids["cg"]))
    _form3 = dict(_form, name="p298-same")
    _T298["plain_edit"] = (_D.post("/groups/%d/edit" % _ids["og3"], data=_form3, headers=_XHR298).status_code,
                           _perms_of298(_ids["og3"]))
    eq("websites: a delegated admin's edit of a customer group keeps its website permissions and drops a "
       "server permission and a host", _T298["cust_edit"][1],
       (sorted([_w.MANAGE_WEBSITE, _w.VIEW_WEBSITES]), []))
    eq("websites: ...while the same edit of an ordinary group gives it both (control)", _T298["plain_edit"][1],
       (sorted([_w.MANAGE_WEBSITE, _w.VIEW_SERVERS, _w.VIEW_WEBSITES]), [_h]))

    # Group reach: a group granting a site the delegate cannot reach is not theirs to edit (403); one
    # granting a site they can reach with the same permission is (control: 200/302).
    _T298["reach_other"] = _D.post("/groups/%d/edit" % _ids["og"],
                                   data={"name": "p298-other", "permissions": [_w.VIEW_WEBSITES]},
                                   headers=_XHR298).status_code
    _T298["reach_other_perms"] = _perms_of298(_ids["og"])
    check("websites: a delegated admin cannot edit a group whose site they cannot reach (403, unchanged), as "
          "for a host they were not granted", _T298["reach_other"] == 403
          and _T298["reach_other_perms"] == ([_w.VIEW_WEBSITES], []), repr(_T298))
    check("websites: ...and could edit the group whose site they reach (control)",
          _T298["plain_edit"][0] in (200, 302), repr(_T298["plain_edit"]))

    # Customers set up 2FA before anything else; an ordinary account without 2FA is not held (control),
    # nor a customer once a superadmin turns the setting off.
    _rc = _p9_client(_ids["cust"]).get("/api/servers", headers=_XHR298)
    _rp = _p9_client(_ids["plain"]).get("/api/servers", headers=_XHR298)
    _saved2fa = _p9.config.get("WEBSITES_CUSTOMER_2FA", True)
    try:
        _p9.config["WEBSITES_CUSTOMER_2FA"] = False
        _ro = _p9_client(_ids["cust"]).get("/api/servers", headers=_XHR298)
    finally:
        _p9.config["WEBSITES_CUSTOMER_2FA"] = _saved2fa
    eq("websites: a customer without 2FA is held at 2FA setup (403, X-2FA-Setup-Required); an ordinary account "
       "is not, nor the customer with the setting off",
       [(_rc.status_code, _rc.headers.get("X-2FA-Setup-Required")), _rp.headers.get("X-2FA-Setup-Required"),
        _ro.headers.get("X-2FA-Setup-Required")], [(403, "1"), None, None])

    # The audit log: a viewer reads the rows about a site they can reach, never another site's.
    with _p9.test_request_context("/"):
        for _k in ("sa", "sb"):
            _auth298.log_website_action(None, _db298.session.get(_Site298, _ids[_k]), "website_start",
                                        detail="p298-row-" + _k)
    with _p9.app_context():
        _T298["audit_ids"] = sorted((r.detail, r.target, r.website_id) for r in _Audit298.query.filter(
            _Audit298.detail.like("p298-row-s%")))
    eq("websites: log_website_action records the site a row is about, by name and by id", _T298["audit_ids"],
       [("p298-row-sa", "p298-ta", _ids["sa"]), ("p298-row-sb", "p298-tb", _ids["sb"])])
    _logs = _D.get("/logs?action=website_start").get_data(as_text=True)
    check("websites: the audit log shows a viewer the rows about a site they hold a website permission on, "
          "and not another site's", "p298-row-sa" in _logs and "p298-row-sb" not in _logs,
          repr(("p298-row-sa" in _logs, "p298-row-sb" in _logs)))

    # A user admin cannot take over (here: delete) an account that reaches a site they cannot; one that
    # reaches only their own sites they can (control).
    _T298["del_other"] = _D.post("/users/%d/delete" % _ids["plain"], headers=_XHR298).status_code
    _T298["del_same"] = _D.post("/users/%d/delete" % _ids["samey"], headers=_XHR298).status_code
    with _p9.app_context():
        _T298["left"] = [_db298.session.get(_User298, _ids[k]) is not None for k in ("plain", "samey")]
    eq("websites: a delegated user admin cannot delete an account holding a site they cannot reach; they can "
       "delete one whose sites they hold (control)", (_T298["del_other"], _T298["left"]), (400, [True, False]))
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _model, _key in ((_User298, "users"), (_Group298, "groups"), (_Site298, "sites"), (_Remote298, "hosts")):
            for _rid in _made298[_key]:
                _row = _db298.session.get(_model, _rid)
                if _row is not None:
                    _db298.session.delete(_row)
        _db298.session.commit()


# ── 10. Every /websites route goes through site_for ──────────────────────────────────────────────────
# Read from each view's OWN body (as rbac_test does), by AST, never by text: a route that takes a site id
# must call site_for; one that takes none (the list, Add, customers, the proxy) must call visible_sites,
# can_create or can_open_page, or be superadmin-only.
_SITE_CALLS298 = {"site_for"}
_LIST_CALLS298 = {"site_for", "visible_sites", "can_create", "can_open_page", "create_target"}


def _calls298(fn):
    """The names of every function the view `fn` calls in its own body (decorators unwrapped)."""
    while getattr(fn, "__wrapped__", None) is not None:
        fn = fn.__wrapped__
    tree = _ast298.parse(_tw298.dedent(_inspect298.getsource(fn)))
    return {getattr(n.func, "attr", None) or getattr(n.func, "id", None)
            for n in _ast298.walk(tree) if isinstance(n, _ast298.Call)}


def _route_gaps298(app):
    """(routes read, [the /websites routes that skip the check, with what they call])."""
    read, gaps = 0, []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith(("/websites", "/api/websites")):
            continue
        read += 1
        view = app.view_functions[rule.endpoint]
        if getattr(view, "_required_perms", None) == (_auth298.SUPER_ADMIN,):
            continue
        want = _SITE_CALLS298 if rule.arguments else _LIST_CALLS298
        if not want & _calls298(view):
            gaps.append(rule.rule)
    return read, gaps


_read298, _gaps298 = _route_gaps298(_p9)
check("websites: every /websites route checks access in its own body: site_for for a route with a site id, "
      "the scoped list or the create check otherwise, or superadmin-only", not _gaps298,
      "%d read; skipping: %r" % (_read298, _gaps298))
_fake298 = _Flask298("p298_fake")


@_fake298.route("/websites/<int:site_id>/stop", methods=["POST"])
def _p298_guarded(site_id):
    return _wa298.site_for(None, site_id, _auth298.MANAGE_WEBSITE).name


@_fake298.route("/websites/<int:site_id>/start", methods=["POST"])
def _p298_open(site_id):
    return str(site_id)


@_fake298.route("/websites")
def _p298_list():
    return str(len(_wa298.visible_sites(None).all()))


@_fake298.route("/websites/add", methods=["POST"])
def _p298_add():
    return "added"


eq("websites: ...the route check names a site route without site_for and a list route without a scoped "
   "query, and passes the guarded ones (control)", sorted(_route_gaps298(_fake298)[1]),
   ["/websites/<int:site_id>/start", "/websites/add"])

# ── 11. Upgrades, secrets at rest, defaults ──────────────────────────────────────────────────────────
# The columns added to tables an older panel already has: each has a light migration whose DDL adds it,
# with the default an existing row needs, to a table of the old shape.
_NEWCOLS298 = {("group", "is_customer"): 0, ("group", "max_sites"): 3, ("game_database", "website_id"): None,
               ("audit_log", "website_id"): None}
_mig298 = {}
_con298 = _sqlite298.connect(":memory:")
try:
    for _t in sorted({_t for _t, _c in _NEWCOLS298}):
        _con298.execute('CREATE TABLE "%s" (id INTEGER PRIMARY KEY)' % _t)
        _con298.execute('INSERT INTO "%s" (id) VALUES (1)' % _t)  # nosec B608 - the model's own table names
    for (_t, _c) in _NEWCOLS298:
        _ddl = _models298._LIGHT_MIGRATIONS.get((_t, _c))
        if _ddl is None:
            _mig298[(_t, _c)] = "no entry"
            continue
        _con298.execute(_ddl)
        _mig298[(_t, _c)] = _con298.execute('SELECT "%s" FROM "%s" WHERE id = 1' % (_c, _t)).fetchone()[0]  # nosec B608 - the model's own table names
finally:
    _con298.close()
eq("websites: every column added to an existing table has a light migration that adds it to an older "
   "database, with the value an existing row needs", _mig298, _NEWCOLS298)
with _p9.app_context():
    _cols298 = set(_at_rest298._text_columns())
_secret_cols298 = {("website", "id", "proxy_secret"), ("website", "id", "object_cache_secret"),
                   ("website", "id", "env_enc"), ("website_domain", "id", "own_key_secret"),
                   ("website_proxy", "id", "tunnel_token_enc")}
check("websites: the proxy token, object-cache password, app environment, own certificate key and tunnel "
      "token are columns the re-encryption pass rewrites under the current key",
      _secret_cols298 <= _cols298, repr(sorted(_secret_cols298 - _cols298)))
# The default group and the panel's upgrade steps are made in models.py: none names a website permission.
_msrc298 = _inspect298.getsource(_models298)
check("websites: no group the panel makes itself (the default group, an upgrade step) is given a website "
      "permission", not [p for p in _wperms298 if '"%s"' % p in _msrc298] and '"view_console"' in _msrc298,
      repr([p for p in _wperms298 if '"%s"' % p in _msrc298]))

# ── 12. Domains, customer groups, the create quota and the page ──────────────────────────────────────
# The domain and customer routes are built on these (part300 drives them through the routes).
_q298 = {}
with _p9.test_request_context("/"):
    try:
        _hq = _host298("p298-quota")
        _sq = _site298(_hq, "p298-q", 20986)
        _so = _site298(_hq, "p298-q-other", 20987)
        _db298.session.add(_Dom298(website_id=_so.id, domain="taken.p298.example.org"))
        _db298.session.flush()
        _q298["bad"] = _wa298.domain_refusal("10.0.0.1", _sq)[0]
        _q298["panel"] = _wa298.domain_refusal("Panel.P298.example.org", _sq, ("panel.p298.example.org",))[0]
        _q298["taken"] = _wa298.domain_refusal("taken.p298.example.org", _sq)[0]
        _q298["ok"] = _wa298.domain_refusal("new.p298.example.org", _sq)[0]
        for _i in range(_wa298.DOMAIN_ADDS_PER_HOUR):
            _db298.session.add(_Audit298(action="website_domain_add", target="p298-q", website_id=_sq.id, success=True))
        _db298.session.flush()
        _q298["rate"] = _wa298.domain_refusal("rate.p298.example.org", _sq)
        _db298.session.query(_Audit298).filter(_Audit298.website_id == _sq.id).delete()
        for _i in range(_wa298.MAX_DOMAINS_PER_SITE):
            _db298.session.add(_Dom298(website_id=_sq.id, domain="d%d.p298.example.org" % _i))
        _db298.session.flush()
        _db298.session.refresh(_sq)
        _q298["cap"] = _wa298.domain_refusal("six.p298.example.org", _sq)
        _cgq = _wa298.make_customer_group("p298-q", [_sq], [_auth298.VIEW_WEBSITES, _auth298.CREATE_WEBSITES,
                                                           _auth298.MANAGE_USERS], max_sites=2)
        _uq = _user298("p298-q-cust", [], ())
        _uq.groups = [_cgq]
        _db298.session.flush()
        _q298["group"] = (_cgq.name, _cgq.is_customer, sorted(_cgq.get_permissions()))
        _q298["create_room"] = (_wa298.can_create(_uq), _wa298.create_target(_uq) is _cgq, _wa298.is_customer(_uq),
                                _wa298.can_open_page(_uq))
        _cgq.websites.append(_so)
        _db298.session.flush()
        from flask import g as _g298
        _g298.__dict__.pop("_websites_access_cache", None)
        _q298["create_full"] = (_wa298.can_create(_uq), _wa298.create_target(_uq))
        _nob = _user298("p298-q-nobody", [_auth298.VIEW_SERVERS])
        _q298["page_nobody"] = _wa298.can_open_page(_nob)
    finally:
        _db298.session.rollback()
eq("websites: a domain is refused for its shape, for being the panel's own name, and for being taken; a new "
   "one is accepted, lowercased", [_q298.get(k) for k in ("bad", "panel", "taken", "ok")],
   [None, None, None, "new.p298.example.org"])
check("websites: ...and refused past the hourly rate and past the per-site cap, each with its sentence",
      _q298["rate"][0] is None and "last hour" in str(_q298["rate"][1])
      and _q298["cap"][0] is None and "the most one site may have" in str(_q298["cap"][1]), repr(_q298))
eq("websites: a customer group is customer-<name>, marked a customer group, and holds only the customer "
   "permissions asked for (MANAGE_USERS dropped)", _q298["group"],
   ("customer-p298-q", True, sorted([_auth298.CREATE_WEBSITES, _auth298.VIEW_WEBSITES])))
eq("websites: a customer with CREATE_WEBSITES may add a site while the group has room (and it would join "
   "that group), opens the page, and is a customer; with the group full, may not",
   (_q298["create_room"], _q298["create_full"], _q298["page_nobody"]),
   ((True, True, True, True), (False, None), False))
