"""Who may reach which website: the tenant boundary of the Websites tab.

A website is reached through a GROUP: the user must hold the permission asked for through a group that
has the site in `group_websites` (Group.websites). The permission and the site are paired per group,
so a user in one group that may run site A and another that may only see site B cannot run site B.
MANAGE_WEBSITES alone is also honoured through a whole-host grant (Group.servers) of an ordinary,
non-customer group, as host grants work for game servers; never on the panel's own host, whose
public ports only a superadmin opens (auth.get_host_remote's rule). A superadmin reaches every site.

A customer is a user in a customer group (Group.is_customer): nobody below a superadmin can give such
a group a permission outside auth.CUSTOMER_PERMS, a host or a game server (auth._grantable_perms,
routes/groups._apply_group_reach), nor join a group whose sites they cannot reach themselves
(auth._group_within_reach reads held_pairs), so a customer reaches their own sites and nothing else.

site_for is the one access check every /websites route makes. No access and no such site both answer
404, so a customer cannot learn which ids exist (OWASP Insecure Direct Object Reference Prevention
Cheat Sheet, "Mitigation"; Multi-Tenant Security Cheat Sheet, "Preventing Cross-Tenant Data Access";
Authorization Cheat Sheet, "Deny by Default" and "Validate the Permissions on Every Request").
"""
from datetime import timedelta

from flask import abort
from sqlalchemy import or_

from panel.core import i18n
from panel.core.clock import utcnow
from panel.core.validation import website_domain
from panel.db.models import (AuditLog, Group, RemoteServer, Website, WebsiteDomain, db, group_websites,
                             user_groups)
from panel.security import auth as _auth
from panel.security.auth import (CREATE_WEBSITES, CUSTOMER_PERMS, EDIT_WEBSITE_FILES, MANAGE_WEBSITE,
                                 MANAGE_WEBSITES, R17C_MAX_ROW_ID, VIEW_WEBSITES, WEBSITES_PAGE_PERMS)

# The permissions site_for and visible_sites answer for. CREATE_WEBSITES is not one: it is about
# adding a site, not reaching one (can_create).
SITE_PERMS = frozenset((VIEW_WEBSITES, EDIT_WEBSITE_FILES, MANAGE_WEBSITE, MANAGE_WEBSITES))
# Quotas: domains per site, and domain additions per site per hour (certificate authorities limit
# issuance per registered domain; Let's Encrypt's own limits are well above these).
MAX_DOMAINS_PER_SITE = 5
DOMAIN_ADDS_PER_HOUR = 3
CUSTOMER_GROUP_PREFIX = "customer-"

DOMAIN_CAP_REACHED = "This website already has {n} domains, the most one site may have."
DOMAIN_RATE_REACHED = "{n} domains were added to this website in the last hour. Try again later."
DOMAIN_INVALID = ("That is not a domain name a website can use: lowercase letters, digits and hyphens, at least "
                  "one dot, no IP address, no wildcard and no local name.")
DOMAIN_TAKEN = "That domain is already used by a website on this panel."
DOMAIN_PANEL = "That is the panel's own address, which is never served as a website."


def _signed_in(user):
    """Whether `user` is a signed-in account with an id (anonymous and half-built users are not)."""
    return bool(getattr(user, "is_authenticated", False)) and getattr(user, "id", None) is not None


def _groups(user):
    """The user's groups with their websites and host grants loaded (three queries, memoised per request)."""
    from flask import g as _flask_g, has_app_context
    from sqlalchemy.orm import selectinload
    key = ("_websites_groups", user.id)
    cache = _flask_g.__dict__.setdefault("_websites_access_cache", {}) if has_app_context() else {}
    if key not in cache:
        cache[key] = (Group.query.join(user_groups, user_groups.c.group_id == Group.id)
                      .filter(user_groups.c.user_id == user.id)
                      .options(selectinload(Group.websites), selectinload(Group.servers)).all())
    return cache[key]


def _local_host_ids():
    """The ids of the rows that are the panel's own machine (is_local, or the local transport)."""
    return {rid for (rid,) in db.session.query(RemoteServer.id).filter(
        or_(RemoteServer.is_local.is_(True), RemoteServer.auth_method == "local"))}


def _scopes(user):
    """{perm: (site ids, host ids)} for every site permission `user` holds, from one read of their groups.

    MANAGE_WEBSITES never reaches a site on the panel's own host for anyone but a superadmin (the caller
    handles superadmins), whether the grant is per site or per host.
    """
    out = {p: (set(), set()) for p in SITE_PERMS}
    for g in _groups(user):
        for perm in set(g.get_permissions()) & SITE_PERMS:
            out[perm][0].update(w.id for w in g.websites or [])
            if perm == MANAGE_WEBSITES and not g.is_customer:
                out[perm][1].update(r.id for r in g.servers or [])
    _off_panel_host(*out[MANAGE_WEBSITES])
    return out


def _off_panel_host(sites, hosts):
    """Take the panel's own host, and every site on it, out of a MANAGE_WEBSITES scope (in place)."""
    if not sites and not hosts:
        return
    local = _local_host_ids()
    hosts -= local
    if sites:
        sites &= {i for (i,) in db.session.query(Website.id).filter(
            Website.id.in_(sorted(sites)), ~Website.remote_id.in_(sorted(local)))}


def _scope(user, perm):
    """(site ids, host ids) `user` holds `perm` on, or None for every site (a superadmin)."""
    if perm not in SITE_PERMS:
        raise ValueError("not a per-site website permission: %r" % (perm,))
    if getattr(user, "is_superadmin", False):
        return None
    if not _signed_in(user):
        return set(), set()
    return _scopes(user)[perm]


def _query_for(scope):
    """The Website query a scope from _scope allows."""
    q = Website.query.order_by(Website.id)
    if scope is None:
        return q
    site_ids, host_ids = scope
    if not site_ids and not host_ids:
        return q.filter(db.false())
    return q.filter(or_(Website.id.in_(sorted(site_ids)), Website.remote_id.in_(sorted(host_ids))))


def visible_sites(user, perm=VIEW_WEBSITES):
    """The Website rows `user` holds `perm` on, by id (a query; .all() it)."""
    return _query_for(_scope(user, perm))


def site_for(user, site_id, perm):
    """The Website `site_id` when `user` holds `perm` on it; abort(404) otherwise, exactly as for no site.

    `site_id` comes from the URL (an int route converter), never from a form field. A refusal and a
    missing site are one answer, so the response is no oracle for which ids exist.
    """
    if isinstance(site_id, bool) or not isinstance(site_id, int) or not 0 < site_id <= R17C_MAX_ROW_ID:
        abort(404)
    site = visible_sites(user, perm).filter(Website.id == site_id).first()
    if site is None:
        abort(404)
    return site


def held_pairs(user):
    """The (permission, site id) pairs `user` holds, one per site permission; None for a superadmin."""
    if getattr(user, "is_superadmin", False):
        return None
    if not _signed_in(user):
        return set()
    out = set()
    for perm, scope in sorted(_scopes(user).items()):
        if scope[1]:
            ids = [i for (i,) in _query_for(scope).with_entities(Website.id)]
        else:
            ids = scope[0]
        out.update((perm, sid) for sid in ids)
    return out


def group_pairs(group):
    """The (permission, site id) pairs `group` grants through group_websites."""
    perms = set(group.get_permissions()) & SITE_PERMS
    return {(p, w.id) for p in perms for w in group.websites or []}


def reachable_site_ids(user):
    """The ids of the sites `user` holds any site permission on; None for a superadmin (every site)."""
    pairs = held_pairs(user)
    return None if pairs is None else {sid for _p, sid in pairs}


def create_target(user):
    """The customer group a site `user` adds would join (the first with CREATE_WEBSITES and room), or None."""
    if not _signed_in(user):
        return None
    for g in _groups(user):
        if g.is_customer and CREATE_WEBSITES in g.get_permissions() \
                and len(g.websites or []) < max(0, int(g.max_sites or 0)):
            return g
    return None


def can_create(user):
    """Whether `user` may add a website at all (the Add button).

    A superadmin, a non-customer group holding MANAGE_WEBSITES, or a customer group holding
    CREATE_WEBSITES with room under its max_sites (create_target).
    """
    if getattr(user, "is_superadmin", False):
        return True
    if not _signed_in(user):
        return False
    return any(MANAGE_WEBSITES in g.get_permissions() and not g.is_customer for g in _groups(user)) \
        or create_target(user) is not None


def can_open_page(user):
    """Whether the Websites page (and its sidebar entry) is for `user`: a site to reach, or one to add."""
    if getattr(user, "is_superadmin", False):
        return True
    if not _signed_in(user):
        return False
    # Through the module, at call time: a name bound at import would keep whatever stood there then.
    if not _auth.get_user_permissions(user) & set(WEBSITES_PAGE_PERMS):
        return False
    return can_create(user) or bool(held_pairs(user))


def is_customer(user):
    """Whether `user` is a customer: a non-superadmin in at least one customer group."""
    if getattr(user, "is_superadmin", False) or not _signed_in(user):
        return False
    return any(g.is_customer for g in _groups(user))


def customer_grantable(perms):
    """`perms` cut to what a customer group may hold (auth.CUSTOMER_PERMS)."""
    return set(perms) & CUSTOMER_PERMS


def make_customer_group(label, sites, perms, max_sites=3):
    """A new customer group named customer-<label> holding `perms` (cut to the customer set) on `sites`.

    Added to the session, not committed: the caller makes the account and writes the audit row in the
    same step. The caller has checked `label` (validation.group_name_problem) and that the name is free.
    """
    group = Group(name=CUSTOMER_GROUP_PREFIX + label, description="", is_default=False, is_customer=True,
                  max_sites=max(0, int(max_sites)))
    group.set_permissions(sorted(customer_grantable(perms)))
    group.websites = list(sites)
    db.session.add(group)
    return group


def site_group_ids(site):
    """The ids of the groups `site` is granted to (for the SFTP listing and the customers card)."""
    return {gid for (gid,) in db.session.query(group_websites.c.group_id)
            .filter(group_websites.c.website_id == site.id)}


def domain_quota_refusal(site):
    """The sentence refusing another domain on `site` (the per-site cap, or the hourly rate), or None.

    The rate counts the site's successful website_domain_add audit rows of the last hour, so removing
    and re-adding a domain still counts.
    """
    if len(site.domains or []) >= MAX_DOMAINS_PER_SITE:
        return i18n.tr(DOMAIN_CAP_REACHED, n=MAX_DOMAINS_PER_SITE)
    recent = AuditLog.query.filter(AuditLog.website_id == site.id, AuditLog.action == "website_domain_add",
                                   AuditLog.success.is_(True),
                                   AuditLog.timestamp >= utcnow() - timedelta(hours=1)).count()
    if recent >= DOMAIN_ADDS_PER_HOUR:
        return i18n.tr(DOMAIN_RATE_REACHED, n=DOMAIN_ADDS_PER_HOUR)
    return None


def domain_refusal(text, site, panel_names=()):
    """(domain, None) when `text` may be added to `site`, else (None, the sentence refusing it).

    The domain's shape (validation.website_domain), then the panel's own names (`panel_names`: its
    configured domain and host name, compared lowercase), then whether any site already has it (the
    unique constraint is the backstop), then the site's cap and hourly rate (domain_quota_refusal).
    Whether its DNS points at the host is a separate check that never connects to it.
    """
    domain = website_domain(text)
    if domain is None:
        return None, i18n.tr(DOMAIN_INVALID)
    if domain in {str(n).strip().lower().rstrip(".") for n in panel_names if n}:
        return None, i18n.tr(DOMAIN_PANEL)
    if WebsiteDomain.query.filter_by(domain=domain).first() is not None:
        return None, i18n.tr(DOMAIN_TAKEN)
    quota = domain_quota_refusal(site)
    return (None, quota) if quota else (domain, None)
