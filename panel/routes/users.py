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
        return render_template("manage_users.html", users=users, groups=groups, invites=invites)
