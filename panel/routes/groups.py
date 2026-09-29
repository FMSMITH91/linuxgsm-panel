"""Permission groups and their server grants.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template, request)
from flask_login import (current_user, login_required)
from panel.db.models import (Group, Invite, RemoteServer, User, db)
from panel.security.auth import (ALL_PERMISSIONS, MANAGE_GROUPS, SUPER_ADMIN, _grantable_perms,
    _group_within_reach, _my_group_reach, accessible_remote_ids, get_user_permissions,
    get_user_servers, grantable_object_ids, log_action, permission_required)
from panel.services import (notifications)
from panel.core.clock import utcnow
from panel.core.http import (_form_err, _form_ok)
from panel.core.validation import group_name_problem
from app import (_selected_game_servers, _selected_remotes)


def register(app):
    @app.route("/groups")
    @login_required
    @permission_required(MANAGE_GROUPS)
    def manage_groups():
        # Eager-load what the template renders per group — its members, its host grants and its
        # per-server grants. All three are lazy relationships, so the plain .all() cost THREE
        # queries per group: 16 at two groups, 190 at sixty. selectinload makes it three in total.
        from sqlalchemy.orm import selectinload
        #
        # ...and each member's OWN groups plus every group's custom commands, which is what
        # _manageable_group_ids reads to decide Edit/Delete per group. The members' groups are the
        # same rows as `groups`, so this adds two queries, not one per member.
        groups = (Group.query.options(selectinload(Group.users).selectinload(User.groups),
                                      selectinload(Group.servers),
                                      selectinload(Group.game_servers),
                                      selectinload(Group.custom_commands)).all())
        all_perms = ALL_PERMISSIONS
        # ...and which of them THIS admin may actually toggle: the same set _grantable_perms will
        # accept. Every permission in the table was rendered as an ordinary tick box to a
        # delegated MANAGE_GROUPS admin, and the write path honours none outside this set — a
        # requested one is dropped, and one the group already holds is PRESERVED whatever the box
        # says. So the control was inert in both directions, and the un-tick case was worse than
        # inert: unticking "Open a shell on a host" on a group that held it answered "Group 'X'
        # updated." and revoked nothing, while every member kept a root shell on every host the
        # group reaches. Rendered disabled and still ticked (manage_groups.html) rather than
        # hidden — the group's real power stays visible to whoever is auditing it, and a disabled
        # box is not submitted, which is exactly what the preserve rule already assumes.
        grantable_perms = (set(all_perms) if current_user.is_superadmin else
                           (get_user_permissions(current_user) - {SUPER_ADMIN}) & set(all_perms))
        # Only what THIS admin can actually grant. MANAGE_GROUPS is delegable to a non-superadmin
        # whose own access is a subset of hosts, and the page listed every host and every game
        # server on the panel to them — names, and a tick box beside each. The write path already
        # refuses the ones outside their scope (grantable_object_ids, below), so ticking one did
        # nothing and said nothing: the grant silently did not happen. Same two helpers as the
        # write path, so the form offers exactly what the POST will accept.
        _my_remotes = accessible_remote_ids(current_user)
        all_servers = get_user_servers(current_user)
        _remotes = RemoteServer.query.all()   # ONE query, filtered twice below — not two
        all_remotes = [r for r in _remotes if r.id in _my_remotes]
        # The per-server tick boxes are bucketed BY HOST, and bucketing them by _my_remotes alone
        # (whole-host grants) meant a server reachable through an INDIVIDUAL grant, on a host the
        # editor has no grant for, got no box anywhere on the page — while its id is in the write
        # path's allow-set all the same ({g.id for g in get_user_servers}). grantable_object_ids
        # preserves only the ids OUTSIDE that set, so an unrendered-but-allowed id is neither
        # requested nor preserved: an edit that changed only the description revoked it, silently.
        # The name="servers" host list stays bound to _my_remotes, since that IS its own allow-set.
        _game_host_ids = _my_remotes | {gs.remote_id for gs in all_servers if gs.remote_id}
        all_game_hosts = [r for r in _remotes if r.id in _game_host_ids]
        return render_template("manage_groups.html", groups=groups,
                               # Passed on BOTH paths — for a superadmin it is every id. A name the
                               # route never passed is Jinja's Undefined, falsy, and the template
                               # would quietly take Edit and Delete away from everyone.
                               manageable_ids=_manageable_group_ids(groups),
                               all_perms=all_perms, grantable_perms=grantable_perms,
                               all_servers=all_servers, all_remotes=all_remotes,
                               all_game_hosts=all_game_hosts,
                               # Both lists above are already filtered to what THIS admin may
                               # grant, so their empty states cannot say "none configured yet" —
                               # that is a claim about the install, and it was made to a delegated
                               # admin on a panel full of hosts. This is what tells them apart.
                               any_remotes=bool(_remotes))




    @app.route("/groups/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def add_group():
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        # Non-empty, and nothing a terminal would act on: the recovery CLI prints group names
        # (Aikido 745379084).
        _nerr = group_name_problem(name)
        if _nerr:
            return _form_err(_nerr, "manage_groups")

        existing = Group.query.filter_by(name=name).first()
        if existing:
            return _form_err(f"Group '{name}' already exists.", "manage_groups")

        group = Group(name=name, description=description)
        group.set_permissions(_grantable_perms(request.form.getlist("permissions")))
        # Same filter as edit_group: a new group must not be able to grant hosts or servers its
        # creator cannot reach, or the escalation is just one extra click away.
        group.servers = _selected_remotes(grantable_object_ids(
            {int(i) for i in request.form.getlist("servers") if i.isdecimal()},
            set(), accessible_remote_ids(current_user)))
        group.game_servers = _selected_game_servers(grantable_object_ids(
            {int(i) for i in request.form.getlist("game_servers") if i.isdecimal()},
            set(), {g.id for g in get_user_servers(current_user)}))

        db.session.add(group)
        db.session.commit()
        log_action(current_user, "add_group", target=name)
        notifications.notify("account_change", "Permission group created",
                             "%s created the group '%s'." % (current_user.username, name))
        return _form_ok(f"Group '{name}' created.", "manage_groups")

    @app.route("/groups/<int:group_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def edit_group(group_id):
        group = Group.query.get_or_404(group_id)
        _refused = _refuse_unmanageable(group, "edit_group",
                                        "only a superadmin can change it.")
        if _refused is not None:
            return _refused
        new_name = (request.form.get("name") or group.name or "").strip() or group.name
        # Group.name is unique=True, so a rename onto an existing name raises IntegrityError at
        # commit — a 500 for what is just a typo. add_group has always checked this; the edit path
        # never did.
        if _rename_taken(group, new_name):
            return _form_err(f"Group '{new_name}' already exists.", "manage_groups")
        # Checked only when the name CHANGES, as a user rename is: a group stored before the check
        # existed can still have its permissions edited.
        _nerr = group_name_problem(new_name) if new_name != group.name else None
        if _nerr:
            return _form_err(_nerr, "manage_groups")
        group.name = new_name
        group.description = (request.form.get("description") or group.description or "").strip()
        group.set_permissions(_grantable_perms(request.form.getlist("permissions"),
                                               group.get_permissions()))
        _apply_group_reach(group)

        db.session.commit()
        log_action(current_user, "edit_group", target=group.name)
        notifications.notify("account_change", "Permission group changed",
                             "%s edited the group '%s' (permissions/access)." % (current_user.username, group.name))
        return _form_ok(f"Group '{group.name}' updated.", "manage_groups")

    @app.route("/groups/<int:group_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def delete_group(group_id):
        group = Group.query.get_or_404(group_id)
        # The default group is the one every new account and every invite starts pre-ticked with
        # (manage_users.html checks the box for it), and models.py creates it at setup. Only the
        # TEMPLATE refused to delete it — manage_groups.html hides the button behind
        # `{% if not group.is_default %}` — so a direct POST to this route deleted it anyway and
        # left the install with no default for anyone created afterwards. A guard that lives only
        # in the markup is not a guard.
        if group.is_default:
            log_action(current_user, "delete_group", target=group.name, success=False,
                       detail="refused: the default group cannot be deleted")
            return _form_err("The default group can't be deleted — every new account and invite "
                             "starts in it.", "manage_groups")
        # The SAME rule the edit path enforces, from the same helper. A delete strips every member
        # of what the group grants, so a delegated admin must be able to administer each of them —
        # and the group itself must lie within their reach on all four axes. The hand-rolled
        # check this replaces compared permissions, hosts and servers and left out custom
        # commands, so a group made for a superadmin-authored `exec {}` was deletable by anyone
        # holding its permissions (Aikido 745378983).
        _refused = _refuse_unmanageable(group, "delete_group",
                                        "only a superadmin can delete it.")
        if _refused is not None:
            return _refused
        # The membership clear used to be a loop over group.users calling user.groups.remove(group)
        # — and User.groups back-populates Group.users, so every removal shortened the very list
        # being iterated and the loop visited every OTHER member. It was never a bug: SQLAlchemy
        # deletes a parent's secondary-table rows for it, which was checked by removing
        # `group.users = []` and watching the association rows go anyway. So the loop was doing no
        # work while reading as though it were what made the delete safe. The assignments stay as
        # the explicit statement of what a deleted group releases; the loop does not.
        _gname = group.name   # read before the delete: the instance is gone after the commit
        group.users = []
        group.servers = []
        group.game_servers = []
        group.custom_commands = []
        db.session.delete(group)
        db.session.commit()
        log_action(current_user, "delete_group", target=_gname)
        # add_group and edit_group both notify; the DESTRUCTIVE path did not, so an operator
        # subscribed to account_change saw a group created and edited and never saw it deleted.
        notifications.notify("account_change", "Permission group deleted",
                             "%s deleted the group '%s'." % (current_user.username, _gname))
        return _form_ok(f"Group '{_gname}' deleted.", "manage_groups")


def _manageable_group_ids(groups):
    """The ids among `groups` that current_user may edit or delete: every one, for a superadmin.

    _grantable_perms and grantable_object_ids decide WHICH permissions and hosts a delegated
    admin may toggle; nothing decided WHOSE. edit_group took any group id, and a permission added
    to any group applies on every host its members reach through ANY group, because permissions
    are flat. So an admin scoped to hostA gave tenant B's viewers use_terminal on hostB, stripped
    tenant B's admins, and — through the default group, which holds every account and no hosts,
    so it is within almost anyone's reach — gave the whole install a shell in one POST (Aikido
    745379016). /users refuses the same change to the same people: can_administer_user.

    A non-superadmin may manage a group only when all three hold:
      (a) the group itself lies within their reach (_group_within_reach: permissions, hosts,
          custom commands and servers);
      (b) they could administer every member but themselves and superadmins (whom a group change
          does not move). An account's reach is the union of its groups', so "every group of
          theirs is within my reach" is exactly can_administer_user's subset test, answered from
          the groups already loaded instead of four queries per member;
      (c) no live invite names the group together with one outside their reach — its future
          member is someone they could not administer either, and a superadmin's invite is not
          re-checked against its minter at redemption.
    """
    if current_user.is_superadmin:
        return {g.id for g in groups}
    reach = _my_group_reach(current_user)
    _within = {}

    def _in_reach(g):
        if g.id not in _within:
            _within[g.id] = _group_within_reach(g, reach)
        return _within[g.id]

    def _member_ok(u):
        return u.is_superadmin or u.id == current_user.id or all(_in_reach(mg) for mg in u.groups)

    _invited = _invited_beside_out_of_reach(_in_reach)
    return {g.id for g in groups
            if _in_reach(g) and g.id not in _invited and all(_member_ok(u) for u in g.users)}


def _invited_beside_out_of_reach(in_reach):
    """Ids of the groups a live invite names together with a group `in_reach` refuses."""
    live = _live_group_invites()
    rows = _groups_by_id({gid for inv in live for gid in inv.groups_wanted})
    out = set()
    for inv in live:
        named = [rows[gid] for gid in inv.groups_wanted if gid in rows]
        if not all(map(in_reach, named)):
            out.update(g.id for g in named)
    return out


def _groups_by_id(ids):
    """{id: Group} for `ids`, in one query (none for no ids)."""
    if not ids:
        return {}
    return {g.id: g for g in Group.query.filter(Group.id.in_(ids)).all()}


def _live_group_invites():
    """The unused, unrevoked, unexpired invites that name groups and do not grant superadmin."""
    live = Invite.query.filter(Invite.used_at.is_(None), Invite.revoked_at.is_(None),
                               Invite.expires_at > utcnow()).all()
    # A superadmin invite's account holds everything, whatever its groups grant.
    return [inv for inv in live if inv.groups_wanted and not inv.grants_superadmin]


def _refuse_unmanageable(group, action, why):
    """Refuse (403, audited) when current_user may not edit or delete `group`; None when they may."""
    if group.id in _manageable_group_ids([group]):
        return None
    log_action(current_user, action, target=group.name, success=False,
               detail="refused: the group, a member of it, or a live invite naming it reaches "
                      "beyond the caller")
    return _form_err("That group, or someone in it, has access you don't hold — " + why,
                     "manage_groups", code=403)


def _rename_taken(group, new_name):
    """Whether renaming `group` to `new_name` would land on another group's name."""
    return new_name != group.name and Group.query.filter_by(name=new_name).first() is not None


def _apply_group_reach(group):
    """Set the hosts and servers `group` grants from the form, keeping only what the editor may grant."""
    # Filtered like the permission list edit_group sets, and for the same reason. These two lines
    # took any id the form supplied, so a delegated MANAGE_GROUPS admin scoped to one host
    # could grant their own group every host and server in the install — permissions unchanged,
    # so the escalation test still passed, while can_access_remote/can_access_server started
    # returning True for everything.
    _keep_r = grantable_object_ids({int(i) for i in request.form.getlist("servers") if i.isdecimal()},
                                   {r.id for r in (group.servers or [])},
                                   accessible_remote_ids(current_user))
    _keep_g = grantable_object_ids({int(i) for i in request.form.getlist("game_servers") if i.isdecimal()},
                                   {g.id for g in (group.game_servers or [])},
                                   {g.id for g in get_user_servers(current_user)})
    group.servers = _selected_remotes(_keep_r)
    group.game_servers = _selected_game_servers(_keep_g)
