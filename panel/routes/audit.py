"""The audit log viewer: filtering, sorting and pagination over AuditLog.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (render_template, request)
from flask_login import (login_required)
from panel.db.models import (AuditLog, db)
from panel.security.auth import (VIEW_LOGS, permission_required)
from sqlalchemy import (desc, or_)


def register(app):
    @app.route("/logs")
    @login_required
    @permission_required(VIEW_LOGS)
    def view_logs():
        page = request.args.get("page", 1, type=int)
        per_page = 50
        q = (request.args.get("q") or "").strip()
        f_action = (request.args.get("action") or "").strip()
        f_user = (request.args.get("user") or "").strip()
        f_status = (request.args.get("status") or "").strip()   # "" | ok | fail
        sort = request.args.get("sort", "timestamp")
        direction = "asc" if request.args.get("dir") == "asc" else "desc"

        query = AuditLog.query
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

        # Distinct values for the filter dropdowns (cheap on an indexed/small table).
        actions = [r[0] for r in db.session.query(AuditLog.action)
                   .distinct().order_by(AuditLog.action).all() if r[0]]
        users = [r[0] for r in db.session.query(AuditLog.username)
                 .distinct().order_by(AuditLog.username).all() if r[0]]

        return render_template(
            "logs.html", logs=logs, actions=actions, users=users,
            filters={"q": q, "action": f_action, "user": f_user,
                     "status": f_status, "sort": sort, "dir": direction})
