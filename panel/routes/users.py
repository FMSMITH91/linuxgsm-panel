"""User administration.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template)
from flask_login import (login_required)
from panel.db.models import (Group, User)
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
        return render_template("manage_users.html", users=users, groups=groups)
