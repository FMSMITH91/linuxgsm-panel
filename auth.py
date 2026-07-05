"""Authentication and permission management."""
import functools
import hashlib
import json
import secrets
import uuid
from datetime import datetime
from functools import wraps

import bcrypt
from flask import flash, g, redirect, request, session, url_for
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

from models import AuditLog, Group, Group as GroupModel, User, db

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."


# ─── Permission constants ─────────────────────────────────────
VIEW_SERVERS = "view_servers"
VIEW_CONSOLE = "view_console"
SEND_COMMAND = "send_command"
RESTART_SERVER = "restart_server"
START_SERVER = "start_server"
STOP_SERVER = "stop_server"
UPDATE_SERVER = "update_server"
INSTALL_SERVER = "install_server"
UNINSTALL_SERVER = "uninstall_server"
MANAGE_SERVERS = "manage_servers"       # Add/remove game servers
MANAGE_REMOTES = "manage_remotes"       # Add/edit/remove remote VPS nodes
MANAGE_USERS = "manage_users"           # Add/edit/remove users
MANAGE_GROUPS = "manage_groups"         # Add/edit/remove groups and permissions
VIEW_LOGS = "view_logs"
SUPER_ADMIN = "super_admin"             # All permissions, bypass all checks

ALL_PERMISSIONS = {
    VIEW_SERVERS: "View server status list",
    VIEW_CONSOLE: "View live console output",
    SEND_COMMAND: "Send commands to game server console",
    RESTART_SERVER: "Restart game servers",
    START_SERVER: "Start game servers",
    STOP_SERVER: "Stop game servers",
    UPDATE_SERVER: "Update game servers",
    INSTALL_SERVER: "Install new game servers",
    UNINSTALL_SERVER: "Uninstall game servers",
    MANAGE_SERVERS: "Add/remove game server instances",
    MANAGE_REMOTES: "Add/edit/delete remote VPS nodes",
    MANAGE_USERS: "Manage user accounts",
    MANAGE_GROUPS: "Manage groups and permissions",
    VIEW_LOGS: "View audit logs",
    SUPER_ADMIN: "Full system administrator access (bypasses all checks)",
}

SERVER_ACTIONS = ["restart", "start", "stop", "update", "install", "uninstall"]
ACTION_PERMISSION_MAP = {
    "restart": RESTART_SERVER,
    "start": START_SERVER,
    "stop": STOP_SERVER,
    "update": UPDATE_SERVER,
    "monitor": VIEW_CONSOLE,
    "install": INSTALL_SERVER,
    "uninstall": UNINSTALL_SERVER,
}


# ─── Helpers ──────────────────────────────────────────────────

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def generate_api_token():
    return secrets.token_hex(32)


# ─── Two-factor auth (TOTP) ───────────────────────────────────
def generate_totp_secret():
    """A fresh base32 TOTP secret (what a new authenticator enrolment gets)."""
    import pyotp
    return pyotp.random_base32()


def totp_provisioning_uri(secret, username, issuer="LinuxGSM Panel"):
    """otpauth:// URI to encode in the enrolment QR code."""
    import pyotp
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret, code):
    """True if `code` is valid for `secret` now (±1 step for clock skew)."""
    import pyotp
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip().replace(" ", ""), valid_window=1)
    except Exception:
        return False


def get_user_permissions(user):
    """Get all permissions for a user (union of all their groups + superadmin)."""
    if user.is_superadmin:
        return set(ALL_PERMISSIONS.keys())

    perms = set()
    for group in user.groups or []:
        perms.update(group.get_permissions())
    return perms


def get_user_servers(user):
    """Get game servers a user has access to (superadmin = all)."""
    from models import GameServer
    if user.is_superadmin:
        return GameServer.query.all()

    server_ids = set()
    for group in user.groups or []:
        for s in group.servers or []:
            server_ids.add(s.id)

    # Now get all game servers belonging to those remote servers
    return GameServer.query.filter(GameServer.remote_id.in_(list(server_ids))).all()


def has_permission(user, perm):
    """Check if user has a specific permission."""
    if user.is_superadmin:
        return True
    return perm in get_user_permissions(user)


def can_access_server(user, game_server_id):
    """Check if user can access a specific game server."""
    if user.is_superadmin:
        return True
    from models import GameServer
    gs = GameServer.query.get(game_server_id)
    if not gs:
        return False
    for group in user.groups or []:
        for rs in group.servers or []:
            if rs.id == gs.remote_id:
                return True
    return False


def can_access_remote(user, remote_id):
    """Check if user can manage a specific remote host. Access is granted per host
    through group membership — the SAME model as game-server access — so having the
    MANAGE_REMOTES permission alone is not enough; the remote must be in one of the
    user's groups. Superadmin = all."""
    if user.is_superadmin:
        return True
    try:
        rid = int(remote_id)
    except (TypeError, ValueError):
        return False
    for group in user.groups or []:
        for rs in group.servers or []:
            if rs.id == rid:
                return True
    return False


def accessible_remote_ids(user):
    """Set of remote-host ids the user may manage (all of them for a superadmin)."""
    from models import RemoteServer
    if user.is_superadmin:
        return {r.id for r in RemoteServer.query.all()}
    ids = set()
    for group in user.groups or []:
        for rs in group.servers or []:
            ids.add(rs.id)
    return ids


# ─── Decorators ───────────────────────────────────────────────

def permission_required(*perms):
    """Decorator: require one of the listed permissions to access a route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.is_superadmin:
                return f(*args, **kwargs)
            user_perms = get_user_permissions(current_user)
            if not any(p in user_perms for p in perms):
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def server_access_required(f):
    """Decorator: require access to the specific server referenced in the route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        server_id = kwargs.get("server_id")
        if server_id and not can_access_server(current_user, server_id):
            flash("You do not have access to that server.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


# ─── Initialization ────────────────────────────────────────────

def init_auth(app):
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


# ─── Audit Logging ─────────────────────────────────────────────

def client_ip():
    """Real client IP of the connected user.

    The panel usually sits behind Tailscale Serve (127.0.0.1:5000), which sets
    X-Forwarded-For with the caller's tailnet IP. We only trust that header when the
    request actually arrived from the LOCAL proxy (loopback). On a direct connection
    (the panel also supports binding 0.0.0.0:5000), X-Forwarded-For is fully
    attacker-controlled — trusting it there would let a client forge audit-log IPs and
    rotate the login-throttle key to defeat the brute-force limit. So in that case we
    use the real socket address instead."""
    if not request:
        return ""
    remote = request.remote_addr or ""
    if remote in ("127.0.0.1", "::1"):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # First hop is the original client; the rest are proxies.
            return xff.split(",")[0].strip()
        xr = request.headers.get("X-Real-IP", "")
        if xr:
            return xr.strip()
    return remote


def log_action(user, action, target="", detail="", success=True):
    """Write an audit log entry."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "system",
        action=action,
        target=target,
        detail=detail,
        ip_address=client_ip(),
        success=success,
    )
    db.session.add(entry)
    db.session.commit()
