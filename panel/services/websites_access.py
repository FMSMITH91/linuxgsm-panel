"""Who may reach which website: the tenant boundary of the Websites tab.

A website is reached through a GROUP: the user must hold the permission asked for through a group that
has the site in `group_websites` (Group.websites). The permission and the site are paired per group,
so a user in one group that may run site A and another that may only see site B cannot run site B.
MANAGE_WEBSITES alone is also honoured through a whole-host grant (Group.servers) of an ordinary,
non-customer group, as host grants work for game servers; never on the panel's own host, whose
public ports only a superadmin opens (auth.get_host_remote's rule). A superadmin reaches every site.

A customer is a user in a customer group (Group.is_customer): nobody below a superadmin can give such
a group a permission outside auth.CUSTOMER_PERMS, a host or a game server, so a customer reaches their
own sites and nothing else (customer_grantable, customer_object_refusal).

site_for is the one access check every /websites route makes. No access and no such site both answer
404, so a customer cannot learn which ids exist (OWASP Insecure Direct Object Reference Prevention
Cheat Sheet, "Mitigation"; Authorization Cheat Sheet, "Deny by Default" and "Validate the Permissions
on Every Request").
"""
from datetime import timedelta

from flask import abort
from sqlalchemy import or_

from panel.core.clock import utcnow
from panel.db.models import AuditLog, Group, RemoteServer, Website, db, group_websites, user_groups
from panel.security.auth import (CREATE_WEBSITES, CUSTOMER_PERMS, EDIT_WEBSITE_FILES, MANAGE_WEBSITE,
                                 MANAGE_WEBSITES, R17C_MAX_ROW_ID, VIEW_WEBSITES, WEBSITES_PAGE_PERMS,
                                 get_user_permissions)

# The permissions site_for and visible_sites answer for. CREATE_WEBSITES is not one: it is about
# adding a site, not reaching one (can_create).
SITE_PERMS = frozenset((VIEW_WEBSITES, EDIT_WEBSITE_FILES, MANAGE_WEBSITE, MANAGE_WEBSITES))
# Quotas (brief defaults, admin-editable where they are settings): domains per site, and domain
# additions per site per hour (Let's Encrypt limits issuance per registered domain).
MAX_DOMAINS_PER_SITE = 5
DOMAIN_ADDS_PER_HOUR = 3


def _groups(user):
    """The user's groups with their websites and host grants loaded in one query each."""
    from sqlalchemy.orm import selectinload
    return (Group.query.join(user_groups, user_groups.c.group_id == Group.id)
            .filter(user_groups.c.user_id == user.id)
            .options(selectinload(Group.websites), selectinload(Group.servers)).all())


def _local_host_ids():
    """The ids of the rows that are the panel's own machine (is_local, or the local transport)."""
    return {rid for (rid,) in db.session.query(RemoteServer.id).filter(
        or_(RemoteServer.is_local.is_(True), RemoteServer.auth_method == "local"))}


def _scope(user, perm):
    """(site ids, host ids) `user` holds `perm` on, or None for every site (a superadmin)."""
    if perm not in SITE_PERMS:
        raise ValueError("not a per-site website permission: %r" % (perm,))
    if getattr(user, "is_superadmin", False):
        return None
    if not getattr(user, "is_authenticated", False) or getattr(user, "id", None) is None:
        return set(), set()
    site_ids, host_ids = set(), set()
    for g in _groups(user):
        if perm not in g.get_permissions():
            continue
        site_ids |= {w.id for w in g.websites or []}
        if perm == MANAGE_WEBSITES and not g.is_customer:
            host_ids |= {r.id for r in g.servers or []}
    if perm == MANAGE_WEBSITES:
        local = _local_host_ids()
        host_ids -= local
        if site_ids:
            site_ids = {i for (i,) in db.session.query(Website.id).filter(
                Website.id.in_(sorted(site_ids)), ~Website.remote_id.in_(sorted(local)))}
    return site_ids, host_ids


def visible_sites(user, perm=VIEW_WEBSITES):
    """The Website rows `user` holds `perm` on, by id (a query; .all() it)."""
    scope = _scope(user, perm)
    q = Website.query.order_by(Website.id)
    if scope is None:
        return q
    site_ids, host_ids = scope
    if not site_ids and not host_ids:
        return q.filter(db.false())
    return q.filter(or_(Website.id.in_(sorted(site_ids)), Website.remote_id.in_(sorted(host_ids))))


def site_for(user, site_id, perm):
    """The Website `site_id` when `user` holds `perm` on it; abort(404) otherwise, exactly as for no site.

    `site_id` comes from the URL (an int route converter), never from a form field. A refusal and a
    missing site are one answer, so the response is no oracle for which ids exist.
    """
    if isinstance(site_id, bool) or not isinstance(site_id, int) or not 0 < site_id <= R17C_MAX_ROW_ID:
        abort(404)
    sid = site_id
    site = visible_sites(user, perm).filter(Website.id == sid).first()
    if site is None:
        abort(404)
    return site


def can_create(user):
    """Whether `user` may add a website at all (the Add button).

    A superadmin, a non-customer group holding MANAGE_WEBSITES, or a customer group holding
    CREATE_WEBSITES with room under its max_sites (create_target).
    """
    if getattr(user, "is_superadmin", False):
        return True
    if not getattr(user, "is_authenticated", False):
        return False
    return any(MANAGE_WEBSITES in g.get_permissions() and not g.is_customer for g in _groups(user)) \
        or create_target(user) is not None


def create_target(user):
    """The customer group a site `user` adds would join (the first with CREATE_WEBSITES and room), or None."""
    if not getattr(user, "is_authenticated", False) or getattr(user, "id", None) is None:
        return None
    for g in _groups(user):
        if g.is_customer and CREATE_WEBSITES in g.get_permissions() \
                and len(g.websites or []) < max(0, int(g.max_sites or 0)):
            return g
    return None


def can_open_page(user):
    """Whether the Websites page (and its sidebar entry) is for `user`: a site to reach, or one to add."""
    if getattr(user, "is_superadmin", False):
        return True
    if not getattr(user, "is_authenticated", False):
        return False
    held = get_user_permissions(user) & set(WEBSITES_PAGE_PERMS)
    if not held:
        return False
    return can_create(user) or any(visible_sites(user, p).first() is not None for p in sorted(held & SITE_PERMS))


DOMAIN_CAP_REACHED = "This website already has {n} domains, the most one site may have."
DOMAIN_RATE_REACHED = "{n} domains were added to this website in the last hour. Try again later."


def domain_quota_refusal(site):
    """The sentence refusing another domain on `site` (the per-site cap, or the hourly rate), or None.

    The rate counts the site's successful website_domain_add audit rows of the last hour, so removing
    and re-adding a domain still counts: certificate authorities limit issuance per registered domain.
    """
    from panel.core import i18n
    if len(site.domains or []) >= MAX_DOMAINS_PER_SITE:
        return i18n.tr(DOMAIN_CAP_REACHED, n=MAX_DOMAINS_PER_SITE)
    recent = AuditLog.query.filter(AuditLog.website_id == site.id, AuditLog.action == "website_domain_add",
                                   AuditLog.success.is_(True),
                                   AuditLog.timestamp >= utcnow() - timedelta(hours=1)).count()
    if recent >= DOMAIN_ADDS_PER_HOUR:
        return i18n.tr(DOMAIN_RATE_REACHED, n=DOMAIN_ADDS_PER_HOUR)
    return None


def site_group_ids(site):
    """The ids of the groups `site` is granted to (for a customer's audit view and the SFTP listing)."""
    return {gid for (gid,) in db.session.query(group_websites.c.group_id)
            .filter(group_websites.c.website_id == site.id)}


def customer_grantable(perms):
    """`perms` cut to what a customer group may hold (auth.CUSTOMER_PERMS)."""
    return set(perms) & CUSTOMER_PERMS
