"""Permission groups and their server grants.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template, request)
from flask_login import (current_user, login_required)
from panel.db.models import (GameServer, Group, RemoteServer, db)
from panel.security.auth import (ALL_PERMISSIONS, MANAGE_GROUPS, _grantable_perms, log_action,
    permission_required)
from panel.services import (notifications)
from app import (_form_err, _form_ok, _selected_game_servers, _selected_remotes)


def register(app):
    @app.route("/groups")
    @login_required
    @permission_required(MANAGE_GROUPS)
    def manage_groups():
        groups = Group.query.all()
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
        group.servers = _selected_remotes(request.form.getlist("servers"))
        group.game_servers = _selected_game_servers(request.form.getlist("game_servers"))

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
        group.servers = _selected_remotes(request.form.getlist("servers"))
        group.game_servers = _selected_game_servers(request.form.getlist("game_servers"))

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
