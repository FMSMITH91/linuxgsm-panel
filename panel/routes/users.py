"""User administration.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template)
from flask_login import (current_user, login_required)
from panel.db.models import (Group, Invite, User)
from panel.security.auth import (MANAGE_USERS, permission_required)


def register(app):
    @app.route("/users")
    @login_required
    @permission_required(MANAGE_USERS)
    def manage_users():
        from sqlalchemy.orm import selectinload
        # The page prints each user's groups, so lazily this costs one query per user (108 queries
        # for 100 accounts). selectinload folds them into a single extra statement.
        users = User.query.options(selectinload(User.groups)).all()
        groups = Group.query.all()
        # Outstanding invites, newest first — superadmin-only in the template. Only a superadmin
        # can mint or revoke one, and the list is how you notice a link you no longer want live.
        # Bounded: used and expired ones accumulate forever otherwise, and the useful part of the
        # list is what is still redeemable.
        invites = []
        if current_user.is_superadmin:
            invites = Invite.query.order_by(Invite.created_at.desc()).limit(25).all()
            # An invite whose creator has been offboarded no longer works (see
            # Invite.authority_intact). Showing it as "Active" would be a lie about a link someone
            # may be waiting on, so resolve the creators — ONE extra query for the whole page, not
            # one per row — and let the template say so.
            _cids = {i.created_by_id for i in invites if i.created_by_id}
            _creators = ({u.id: u for u in User.query.filter(User.id.in_(_cids)).all()}
                         if _cids else {})
            for _i in invites:
                _i.authority_ok = _i.authority_intact(_creators.get(_i.created_by_id))
        return render_template("manage_users.html", users=users, groups=groups, invites=invites)
