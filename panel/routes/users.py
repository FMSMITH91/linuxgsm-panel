"""User administration.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template)
from flask_login import (current_user, login_required)
from sqlalchemy import (or_)
from panel.core.clock import (utcnow)
from panel.db.models import (Group, Invite, User)
from panel.security.auth import (MANAGE_USERS, grantable_groups, permission_required)


def register(app):
    @app.route("/users")
    @login_required
    @permission_required(MANAGE_USERS)
    def manage_users():
        from sqlalchemy.orm import selectinload
        # The page prints each user's groups, so lazily this costs one query per user (108 queries
        # for 100 accounts). selectinload folds them into a single extra statement.
        users = User.query.options(selectinload(User.groups)).all()
        # Only the groups THIS admin can actually grant. The modals rendered a checkbox for every
        # group on the panel, but add_user/edit_user run the submitted list through
        # grantable_groups, which drops any group whose permissions or host/server reach is not a
        # subset of the actor's — and then answer "User 'bob' created." with no mention of the
        # drop. A delegated MANAGE_USERS admin ticked two groups, saw success, and the account
        # landed in none of them. Same helper as the write path, so the form now offers exactly
        # what the POST will accept; superadmins still see everything, since grantable_groups
        # short-circuits for them. Mirrors manage_groups, which scopes its host and server lists
        # for the same reason. selectinload because grantable_groups reads .servers and
        # .game_servers per group — lazily that is two queries per group.
        groups = Group.query.options(selectinload(Group.servers),
                                     selectinload(Group.game_servers)).all()
        _grantable = {g.id for g in grantable_groups([g.id for g in groups])}
        groups = [g for g in groups if g.id in _grantable]
        # Outstanding invites, newest first — superadmin-only in the template. Only a superadmin
        # can mint or revoke one, and the list is how you notice a link you no longer want live.
        # Bounded: used and expired ones accumulate forever otherwise, and the useful part of the
        # list is what is still redeemable.
        invites = []
        if current_user.is_superadmin:
            # The bound has to be a bound over REDEEMABLE invites. It used to be `.limit(25)` over
            # every row whatever its state, so 25 newer used/expired/revoked links pushed a live
            # one off the page — and this list is the only place the Revoke button is rendered
            # (revoke_invite is linked from nowhere else), so a misdirected link stayed usable for
            # its whole TTL with no way to stop it. Same three conditions Invite.is_usable tests.
            # ONE `now` for both halves: two calls would let a row expiring between them land in
            # both lists, or in neither.
            _now = utcnow()
            _live = (Invite.query
                     .filter(Invite.used_at.is_(None), Invite.revoked_at.is_(None),
                             Invite.expires_at > _now)
                     .order_by(Invite.created_at.desc()).limit(25).all())
            # ...plus a short tail of finished ones, for context only: they carry no action.
            _done = (Invite.query
                     .filter(or_(Invite.used_at.isnot(None), Invite.revoked_at.isnot(None),
                                 Invite.expires_at <= _now))
                     .order_by(Invite.created_at.desc()).limit(10).all())
            invites = sorted(_live + _done,
                             key=lambda i: (i.created_at or _now), reverse=True)
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
