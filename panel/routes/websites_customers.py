"""Add a customer: a customer group scoped to chosen sites, and a one-time invite link into it, in one step.

A customer is an ordinary panel account whose only group is a customer group (Group.is_customer):
it holds website permissions only (auth.CUSTOMER_PERMS, cut by websites_access.customer_grantable)
and reaches only the sites in the group (group_websites). Whoever adds one needs MANAGE_WEBSITES on
EVERY site they grant (site_for each, 404 otherwise) and a recent sign-in proof (step-up); they can
grant no permission they lack themselves, and no host or game server (OWASP Authorization Cheat
Sheet, "Enforce Least Privileges", "Deny by Default"). The invite carries no credential: the customer
opens it once and chooses their own name and password, as every invite does (Invite.mint); the link
and its second code are shown once and only their hashes are stored. One audit row per site granted.
"""
from flask import jsonify, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.clock import utcnow
from panel.core.validation import website_name_problem
from panel.db.models import Group, Invite, db
from panel.routes import websites as _w
from panel.security.account_guard import step_up_required
from panel.security.auth import (CREATE_WEBSITES, EDIT_WEBSITE_FILES, MANAGE_WEBSITE, MANAGE_WEBSITES, VIEW_WEBSITES,
                                 has_permission)
from panel.services import websites_access as _wa

DEFAULT_PERMS = (VIEW_WEBSITES, EDIT_WEBSITE_FILES, MANAGE_WEBSITE)
S_NAME = "A customer name is 1 to 32 lowercase letters, digits and hyphens."
S_TAKEN = "A group with that name already exists."
S_NO_SITES = "Choose at least one website for the customer."
S_TOO_MANY_INVITES = "There are already {n} invite links that still work. Revoke some before making another."


def _site_ids(data):
    raw = data.get("sites")
    raw = raw if isinstance(raw, list) else str(raw or "").split(",")
    out = []
    for v in raw[:50]:
        try:
            out.append(int(str(v).strip()))
        except ValueError:
            continue
    return sorted(set(out))


def _perms(data):
    asked = data.get("permissions")
    asked = asked if isinstance(asked, list) else list(DEFAULT_PERMS)
    keep = _wa.customer_grantable(p for p in asked if isinstance(p, str))
    return sorted(p for p in keep if current_user.is_superadmin or has_permission(current_user, p))


def _max_sites(data, held, perms):
    """How many sites the new customer group may have.

    A group that may add its own sites (CREATE_WEBSITES) gets the number the card sends, else the superadmin's
    "Sites per customer" setting (websites_max_sites); one that may not is held to the sites it is given, so no
    quota line promises sites it cannot add. Never fewer than the sites given, never more than 100.
    """
    if CREATE_WEBSITES not in perms:
        return held
    from panel.routes.websites_view import options
    try:
        n = int(str(data.get("max_sites", "")).strip())
    except ValueError:
        n = options()["max_sites"]
    return max(held, min(n, 100))


def _make(name, perms, sites, max_sites):
    group = _wa.make_customer_group(name, sites, perms, max_sites)
    db.session.flush()
    inv, token = Invite.mint(current_user, group_ids=[group.id], note="customer %s" % name)
    code, inv.code_hash = Invite.new_code()
    db.session.add(inv)
    db.session.commit()
    return group, token, code


S_INVITE_AT = "The customer opens this link at {address}, the panel's site domain. They must be able to reach the panel there."
S_INVITE_HERE = ("The customer opens this link at {address}, the address you are using now, because the panel has no site "
                 "domain in Settings. Check that they can reach the panel there (a tailnet-only address cannot be reached "
                 "from outside it).")


def invite_link(token):
    """(the invite's address, the sentence saying where the customer opens it).

    The panel's site domain (Settings) when one is set, with the port the panel answers on unless the domain names
    its own; else the address the administrator reached the panel by, said plainly, since a customer may not reach
    that one (a tailnet-only panel).
    """
    from urllib.parse import urlsplit, urlunsplit
    from panel.core.config import load_config
    from panel.core.origins import _host_port
    # nosemgrep: python.flask.security.audit.flask-url-for-external-true.flask-url-for-external-true
    link = url_for("redeem_invite", token=token, _external=True)
    url = urlsplit(link)
    domain = _host_port(load_config().get("site_domain"))
    if not domain:
        return link, i18n.tr(S_INVITE_HERE, address=url.netloc)
    host, port = domain[0], domain[1] or url.port
    host = "[%s]" % host if ":" in host else host
    netloc = "%s:%d" % (host, port) if port else host
    return urlunsplit(url._replace(netloc=netloc)), i18n.tr(S_INVITE_AT, address=netloc)


def register(app):
    """The add-a-customer route."""
    @app.route("/websites/customers/add", methods=["POST"])
    @login_required
    @step_up_required
    def website_customer_add():
        data = _w.body()
        sites = [_wa.site_for(current_user, sid, MANAGE_WEBSITES) for sid in _site_ids(data)]
        name = _w.field(data, "name").lower()
        if website_name_problem(name):
            return _w.say(400, S_NAME)
        if not sites:
            return _w.say(400, S_NO_SITES)
        if Group.query.filter_by(name=_wa.CUSTOMER_GROUP_PREFIX + name).first() is not None:
            return _w.say(409, S_TAKEN)
        live = Invite.query.filter(Invite.used_at.is_(None), Invite.revoked_at.is_(None),
                                   Invite.expires_at > utcnow()).count()
        if live >= Invite.MAX_LIVE:
            return _w.say(409, i18n.Sentence(S_TOO_MANY_INVITES, n=live))
        perms = _perms(data)
        group, token, code = _make(name, perms, sites, _max_sites(data, len(sites), perms))
        for site in sites:
            _w.audit(site, "website_customer_add", "customer group %s (%s), invite made" % (group.name, ", ".join(perms)))
        link, where = invite_link(token)
        resp = jsonify({"success": True, "group_id": group.id, "invite": link, "invite_note": where, "code": code,
                        "message": i18n.tr("Customer added. Send them the invite link and its code; both are shown once.")})
        resp.headers["Cache-Control"] = "no-store"
        return resp
