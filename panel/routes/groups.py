"""Permission groups and their server grants.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template, request)
from flask_login import (current_user, login_required)
from panel.db.models import (GameServer, Group, RemoteServer, db)
from panel.security.auth import (ALL_PERMISSIONS, MANAGE_GROUPS, _grantable_perms,
    accessible_remote_ids, get_user_servers, grantable_object_ids, log_action,
    permission_required)
from panel.services import (notifications)
from panel.core.http import (_form_err, _form_ok)
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
        groups = (Group.query.options(selectinload(Group.users),
                                      selectinload(Group.servers),
                                      selectinload(Group.game_servers)).all())
        all_perms = ALL_PERMISSIONS
        all_servers = GameServer.query.all()
        all_remotes = RemoteServer.query.all()
        return render_template("manage_groups.html", groups=groups,
                               all_perms=all_perms, all_servers=all_servers,
                               all_remotes=all_remotes)




    @app.route("/groups/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def add_group():
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            return _form_err("Group name is required.", "manage_groups")

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
        new_name = (request.form.get("name") or group.name or "").strip() or group.name
        # Group.name is unique=True, so a rename onto an existing name raises IntegrityError at
        # commit — a 500 for what is just a typo. add_group has always checked this; the edit path
        # never did.
        if new_name != group.name and Group.query.filter_by(name=new_name).first():
            return _form_err(f"Group '{new_name}' already exists.", "manage_groups")
        group.name = new_name
        group.description = (request.form.get("description") or group.description or "").strip()
        group.set_permissions(_grantable_perms(request.form.getlist("permissions"),
                                               group.get_permissions()))
        # Filtered like the permission list above it, and for the same reason. These two lines
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
        # Remove from all users
        for user in group.users:
            user.groups.remove(group)
        group.users = []
        group.servers = []
        group.game_servers = []
        group.custom_commands = []
        db.session.delete(group)
        db.session.commit()
        log_action(current_user, "delete_group", target=group.name)
        return _form_ok(f"Group '{group.name}' deleted.", "manage_groups")
