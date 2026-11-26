"""Part 298 of the unit suite: websites' core: models, permissions, tenancy and the per-site access check.

1. The website permissions exist, none is in any group by default, and a customer group may hold only
   the customer set.
2. The tables: a site, its domains and its host's proxy row, the data-layer refusals of a bad name,
   account, port, domain or exposure mode, and a host removed taking its sites with it.
3. site_for: a superadmin reaches every site; anyone else only a site their group holds the permission
   on, and no access answers 404 exactly as no site does.

HOW IT RUNS. part12's app and its database, rows made and removed here; nothing reaches a host.
"""
import os as _os298

from werkzeug.exceptions import NotFound as _NotFound298

from unit.part01 import check, eq
from unit.part12 import _p9
from panel.db.models import (Group as _Group298, RemoteServer as _Remote298, User as _User298,
                             Website as _Site298, WebsiteDomain as _Dom298, WebsiteProxy as _Proxy298,
                             db as _db298)
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
