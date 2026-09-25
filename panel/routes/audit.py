"""The audit log viewer: filtering, sorting and pagination over AuditLog.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template, request)
from flask_login import (current_user, login_required)
from panel.db.models import (AuditLog, LOCAL_HOST_LABEL, RemoteServer, db)
from panel.security.auth import (VIEW_LOGS, accessible_remote_ids, get_user_servers,
                                 permission_required)
from sqlalchemy import (and_, desc, or_, true)

# Rows about ACCOUNTS rather than servers or hosts: sign-ins (with the address and, for a failure,
# whatever was typed into the username box — where people paste passwords), invites, users,
# groups, tokens and 2FA. A delegated viewer sees their own and nobody else's, whatever the target.
_ACCOUNT_ACTIONS = frozenset({
    "login", "login_failed", "login_blocked", "api_token_blocked", "logout", "password_changed",
    "2fa_enabled", "2fa_disabled", "2fa_backup_code_used", "account_display_name",
    "api_token_generate", "api_token_revoke", "add_user", "edit_user", "delete_user",
    "rename_user", "revoke_session", "revoke_sessions", "invite_created", "invite_revoked",
    "invite_redeemed", "add_group", "edit_group", "delete_group", "otp_nag_dismissed",
    "ui_layout_reset",
})


def _like_prefix(name):
    """A LIKE pattern matching targets written as "<name>:<detail>" (a host's port or rule)."""
    return name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ":%"


def audit_scope(user):
    """The AuditLog rows `user` may read, as a filter — or None for every row (a superadmin).

    view_logs was install-wide. A group holding it with one server in scope read the whole trail:
    other servers' console commands (`rcon_password …` is a console command), every admin's
    sign-in address, and the attempted username of every failed login. A delegated viewer now
    sees their OWN rows, plus rows whose target is a game server they can access or a host they
    were granted — never an account row of anyone else's, and never the panel host's own
    administration (LOCAL_HOST_LABEL: backups, self-update, binding)."""
    if user.is_superadmin:
        return None
    server_names = {gs.name for gs in get_user_servers(user) if gs.name}
    remote_ids = accessible_remote_ids(user)
    remote_names = ({r.name for r in RemoteServer.query.filter(RemoteServer.id.in_(remote_ids))
                     if r.name} if remote_ids else set())
    about = []
    if server_names:
        about.append(AuditLog.target.in_(sorted(server_names)))
    if remote_names:
        about.append(AuditLog.target.in_(sorted(remote_names)))
        about.extend(AuditLog.target.like(_like_prefix(n), escape="\\")
                     for n in sorted(remote_names))
    theirs = AuditLog.user_id == user.id
    if not about:
        return theirs
    return or_(theirs, and_(or_(*about),
                            AuditLog.target != LOCAL_HOST_LABEL,
                            ~AuditLog.action.in_(sorted(_ACCOUNT_ACTIONS))))


def register(app):
    @app.route("/logs")
    @login_required
    @permission_required(VIEW_LOGS)
    def view_logs():
        # Clamped at BOTH ends. type=int rejects "abc" and paginate(error_out=False) clamps a
        # page below 1, but nothing clamped it above: (page-1)*50 for page=184467440737095518
        # overflows SQLite's INTEGER and /logs answers a bare 500 (a page route, so the JSON
        # errorhandler does not even dress it up).
        page = max(1, min(request.args.get("page", 1, type=int) or 1, 10_000_000))
        per_page = 50
        q = (request.args.get("q") or "").strip()
        f_action = (request.args.get("action") or "").strip()
        f_user = (request.args.get("user") or "").strip()
        f_status = (request.args.get("status") or "").strip()   # "" | ok | fail
        sort = request.args.get("sort", "timestamp")
        direction = "asc" if request.args.get("dir") == "asc" else "desc"

        scope = audit_scope(current_user)
        query = AuditLog.query if scope is None else AuditLog.query.filter(scope)
        if q:
            like = f"%{q}%"
            query = query.filter(or_(AuditLog.target.ilike(like),
                                     AuditLog.detail.ilike(like),
                                     AuditLog.username.ilike(like)))
        if f_action:
            query = query.filter(AuditLog.action == f_action)
        if f_user:
            query = query.filter(AuditLog.username == f_user)
        if f_status == "ok":
            query = query.filter(AuditLog.success.is_(True))
        elif f_status == "fail":
            query = query.filter(AuditLog.success.is_(False))

        sort_cols = {"timestamp": AuditLog.timestamp, "username": AuditLog.username,
                     "action": AuditLog.action, "target": AuditLog.target}
        col = sort_cols.get(sort, AuditLog.timestamp)
        query = query.order_by(col.asc() if direction == "asc" else desc(col))

        logs = query.paginate(page=page, per_page=per_page, error_out=False)

        # Distinct values for the filter dropdowns (cheap on an indexed/small table) — from the
        # SAME scope as the rows. The user list was every AuditLog.username install-wide, which
        # includes each failed login's attempted username.
        _where = scope if scope is not None else true()
        actions = [r[0] for r in db.session.query(AuditLog.action).filter(_where)
                   .distinct().order_by(AuditLog.action).all() if r[0]]
        users = [r[0] for r in db.session.query(AuditLog.username).filter(_where)
                 .distinct().order_by(AuditLog.username).all() if r[0]]

        return render_template(
            "logs.html", logs=logs, actions=actions, users=users,
            # Whose sign-in addresses this viewer may see: a superadmin, everyone's; anyone else,
            # only their own rows' (another admin's address is not in a moderator's remit).
            show_all_ips=bool(current_user.is_superadmin),
            filters={"q": q, "action": f_action, "user": f_user,
                     "status": f_status, "sort": sort, "dir": direction})
