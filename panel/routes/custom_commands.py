"""Superadmin-defined game commands handed to groups.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.db.models import (CUSTOM_ARG_DEFAULT_PATTERN, CustomCommand, GlobalBan, Group, db)
from panel.ops.ssh_manager import (_sanitize_steamid)
from panel.security.auth import (log_action, superadmin_required)
import threading
from panel.core.http import (_form_err, _form_ok)
from app import (_CUSTOM_CMD_ENGINES, _assign_command_groups, _custom_cmd_form,
    _fan_out_global_ban, _sync_global_bans, _valve_game_servers, load_game_list)


def register(app):
    @app.route("/global-bans")
    @login_required
    @superadmin_required
    def global_bans_page():
        bans = GlobalBan.query.order_by(GlobalBan.created_at.desc()).all()
        return render_template("global_bans.html", bans=bans,
                               valve_count=len(_valve_game_servers()))

    @app.route("/global-bans/add", methods=["POST"])
    @login_required
    @superadmin_required
    def global_bans_add():
        sid = _sanitize_steamid(request.form.get("steamid", ""))
        if not sid:
            flash("Enter a valid SteamID — e.g. STEAM_0:1:12345 or [U:1:24691].", "danger")
            return redirect(url_for("global_bans_page"))
        if GlobalBan.query.filter_by(steamid=sid).first():
            flash("%s is already on the global ban list." % sid, "info")
            return redirect(url_for("global_bans_page"))
        gb = GlobalBan(steamid=sid, player_name=request.form.get("player_name", "").strip()[:80],
                       reason=request.form.get("reason", "").strip()[:200],
                       created_by=current_user.username)
        db.session.add(gb)
        db.session.commit()
        log_action(current_user, "global_ban_add", target=sid, detail=gb.reason)
        threading.Thread(target=lambda: _fan_out_global_ban(app, sid, unban=False), daemon=True).start()
        # Not "Banned across all Source servers" — the fan-out has not run yet and a stopped or
        # unreachable server will not receive it. The audit log records what actually landed.
        flash("Banning %s — applying it to every Source server now; see the audit log for the "
              "result." % sid, "success")
        return redirect(url_for("global_bans_page"))

    @app.route("/global-bans/<int:ban_id>/delete", methods=["POST"])
    @login_required
    @superadmin_required
    def global_bans_delete(ban_id):
        gb = GlobalBan.query.get_or_404(ban_id)
        sid = gb.steamid
        db.session.delete(gb)
        db.session.commit()
        log_action(current_user, "global_ban_remove", target=sid)
        threading.Thread(target=lambda: _fan_out_global_ban(app, sid, unban=True), daemon=True).start()
        flash("Removed %s — lifting it on every Source server now; see the audit log for the "
              "result." % sid, "success")
        return redirect(url_for("global_bans_page"))

    @app.route("/global-bans/sync", methods=["POST"])
    @login_required
    @superadmin_required
    def global_bans_sync():
        threading.Thread(target=lambda: _sync_global_bans(app), daemon=True).start()
        log_action(current_user, "global_ban_sync", target="all Source servers")
        flash("Re-applying every global ban to all running Source servers…", "success")
        return redirect(url_for("global_bans_page"))

    @app.route("/commands")
    @login_required
    @superadmin_required
    def manage_commands():
        commands = CustomCommand.query.order_by(CustomCommand.name).all()
        groups = Group.query.order_by(Group.name).all()
        games = load_game_list()
        return render_template("manage_commands.html", commands=commands, groups=groups,
                               engines=_CUSTOM_CMD_ENGINES, games=games,
                               default_pattern=CUSTOM_ARG_DEFAULT_PATTERN)

    @app.route("/commands/add", methods=["POST"])
    @login_required
    @superadmin_required
    def add_command():
        fields, err = _custom_cmd_form()
        if err:
            return _form_err(err, "manage_commands")
        cmd = CustomCommand(created_by=current_user.username, **fields)
        db.session.add(cmd)
        db.session.flush()          # get cmd.id before wiring the group associations
        _assign_command_groups(cmd)
        db.session.commit()
        log_action(current_user, "add_custom_command", target=cmd.name, detail=cmd.command_template[:120])
        return _form_ok(f"Command '{cmd.name}' created.", "manage_commands")

    @app.route("/commands/<int:cmd_id>/edit", methods=["POST"])
    @login_required
    @superadmin_required
    def edit_command(cmd_id):
        cmd = CustomCommand.query.get_or_404(cmd_id)
        fields, err = _custom_cmd_form(cmd)
        if err:
            return _form_err(err, "manage_commands")
        for k, v in fields.items():
            setattr(cmd, k, v)
        _assign_command_groups(cmd)
        db.session.commit()
        log_action(current_user, "edit_custom_command", target=cmd.name, detail=cmd.command_template[:120])
        return _form_ok(f"Command '{cmd.name}' updated.", "manage_commands")

    @app.route("/commands/<int:cmd_id>/delete", methods=["POST"])
    @login_required
    @superadmin_required
    def delete_command(cmd_id):
        cmd = CustomCommand.query.get_or_404(cmd_id)
        cmd.groups = []
        name = cmd.name
        db.session.delete(cmd)
        db.session.commit()
        log_action(current_user, "delete_custom_command", target=name)
        return _form_ok(f"Command '{name}' deleted.", "manage_commands")
