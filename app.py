"""LinuxGSM Panel - Full Game Server Administration Panel.

Routes:
  GET  /                    -> Dashboard (server overview)
  GET  /login               -> Login page
  GET  /setup               -> Initial setup wizard (multi-step)
  POST /setup               -> Process setup steps
  GET  /server/<id>         -> Single server detail + console
  POST /server/<id>/action  -> Execute server action (start/stop/restart/update)
  POST /server/<id>/command -> Send console command
  GET  /servers/manage      -> Manage game servers on a remote
  POST /servers/install     -> Install a new game server
  POST /servers/uninstall   -> Uninstall a game server
  GET  /remotes             -> Manage remote VPS connections
  POST /remotes/add         -> Add a remote VPS
  POST /remotes/<id>/edit   -> Edit remote VPS
  POST /remotes/<id>/delete -> Remove remote VPS
  POST /remotes/<id>/test   -> Test remote VPS connection
  GET  /users               -> User management (admin)
  POST /users/add           -> Add user
  POST /users/<id>/edit     -> Edit user
  POST /users/<id>/delete   -> Delete user
  GET  /groups              -> Group management (admin)
  POST /groups/add          -> Add group
  POST /groups/<id>/edit    -> Edit group (permissions + server access)
  POST /groups/<id>/delete  -> Delete group
  GET  /logs                -> Audit log viewer
  GET  /api/servers         -> JSON server list
  GET  /api/server/<id>     -> JSON server status
  GET  /api/console/<id>    -> JSON console log (recent lines)
  POST /api/command/<id>    -> JSON send command
  WebSocket /console/<id>   -> Live console streaming
"""
import json
import os
import re
import subprocess
import threading
import time
import uuid
from types import SimpleNamespace
from datetime import datetime
from functools import wraps
from pathlib import Path

# Suppress eventlet deprecation (cosmetic only, panel works fine)
import warnings as _w
_w.filterwarnings("ignore", category=DeprecationWarning)

import eventlet
eventlet.monkey_patch()

del _w

from flask import (
    Flask, Response, abort, flash, g, get_flashed_messages, jsonify,
    redirect, render_template, request, session, url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

from auth import (
    ALL_PERMISSIONS, SERVER_ACTIONS, ACTION_PERMISSION_MAP,
    can_access_server, can_access_remote, accessible_remote_ids,
    check_password, client_ip, generate_api_token,
    generate_totp_secret, totp_provisioning_uri, verify_totp,
    get_user_permissions, get_user_servers, hash_password,
    has_permission, init_auth, log_action, login_manager,
    permission_required, server_access_required,
    INSTALL_SERVER, UNINSTALL_SERVER, MANAGE_SERVERS,
    MANAGE_REMOTES, MANAGE_USERS, MANAGE_GROUPS, VIEW_LOGS,
    SUPER_ADMIN, VIEW_SERVERS, VIEW_CONSOLE, SEND_COMMAND,
    RESTART_SERVER, START_SERVER, STOP_SERVER, UPDATE_SERVER,
)
from config import (
    DATA_DIR, DB_PATH, get_secret_key, load_config, save_config,
    encrypt_secret, decrypt_secret, is_encrypted,
)
from models import (
    AuditLog, GameServer, Group, RemoteServer, SetupState, User, db, init_db,
)
from ssh_manager import (
    close_connection, get_connection, list_linuxgsm_servers,
    run_command, run_interactive, ssh_test_connection,
    get_server_status, run_as_game_user, send_console_command,
    list_server_commands, server_live_metrics, remote_public_ip, remote_live_metrics,
    host_specs, pro_status, pro_attach, pro_service, pro_detach,
    set_autostart, get_autostart, install_game_cron, set_daily_restart,
    install_game_dependencies, parse_missing_deps, detect_game_port, detect_game_ports,
    lgsm_read_config, lgsm_write_config, lgsm_game_config,
    browse_dir, read_file, write_file, upload_file, delete_path,
    remote_ufw_delete_rule, remote_set_public_ssh, remote_public_ssh_status,
    remote_ufw_status, remote_ufw_open_port, remote_ufw_close_port,
    remote_ufw_allow_game_port, remote_ufw_close_game_port,
    remote_ufw_allow_game_ports, remote_ufw_close_by_name,
    port_in_use, check_port_open,
    remote_os_check_updates, remote_os_run_updates,
    remote_reboot, remote_uptime,
    remote_bootstrap_vps,
    remote_check_tailscale, remote_install_tailscale,
    remote_bootstrap_tailscale, remote_migrate_to_tailscale, remote_tailscale_up_url,
    remote_tailscale_finalize,
    remote_ufw_close_port_22,
)
import tailscale_integration as ts
import system_ops as so


def _read_version():
    """Panel version from the VERSION file next to this module (bumped per release)."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")) as f:
            return f.read().strip() or "0.0.0"
    except Exception:
        return "0.0.0"


PANEL_VERSION = _read_version()

# In-memory registry of running/finished VPS bootstrap jobs, keyed by remote_id.
# Populated by the async bootstrap runner and read by the status endpoint. Both
# live in the same (single) panel process, so a plain dict + lock is sufficient.
_bootstrap_jobs = {}
_bootstrap_lock = threading.Lock()

# Live game-server install progress, keyed by GameServer id (same process, so a
# plain dict + lock is fine). Read by /api/server/<id>/install-status.
_install_jobs = {}
_install_lock = threading.Lock()

# LinuxGSM commands the panel is willing to run from a button. Interactive /
# install / destructive commands (console, debug, send, install, auto-install,
# skeleton, developer, sponsor, mods-install, mods-remove, fastdl) are excluded.
RUNNABLE_ACTIONS = {
    "start", "stop", "restart", "monitor", "update", "validate", "backup",
    "details", "check-update", "force-update", "update-lgsm", "mods-update",
    "postdetails", "test-alert",
}
# Long-running ones run in the background so the HTTP request returns immediately.
LONG_ACTIONS = {"update", "validate", "backup", "force-update", "mods-update"}
# Read-only ones: show their output back to the user.
READONLY_ACTIONS = {"monitor", "details", "check-update", "postdetails", "test-alert"}

# The game dropdown is built from LinuxGSM's own serverlist.csv (every supported
# game). For all entries the server name is exactly "{shortname}server", so the
# install just uses that — no per-game mapping needed.
_GAME_LIST_CACHE = {"games": None}


def load_game_list():
    """All LinuxGSM-supported games, from the bundled lgsm/data/serverlist.csv.
    Returns a sorted list of {"shortname", "name"}."""
    if _GAME_LIST_CACHE["games"] is not None:
        return _GAME_LIST_CACHE["games"]
    import csv
    games = []
    path = Path(__file__).parent / "lgsm" / "data" / "serverlist.csv"
    try:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                sn = (row.get("shortname") or "").strip()
                name = (row.get("gamename") or "").strip()
                if sn and name:
                    games.append({"shortname": sn, "name": name})
        games.sort(key=lambda g: g["name"].lower())
    except Exception:
        games = []
    _GAME_LIST_CACHE["games"] = games
    return games

# ─── App Factory ──────────────────────────────────────────────

class PrefixMiddleware:
    """WSGI middleware that handles sub-path mounts (Tailscale Serve, reverse proxy).
    Fixes both incoming PATH_INFO and outgoing Location redirect headers."""
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix.rstrip("/")

    def __call__(self, environ, start_response):
        cfg = load_config()
        # Priority: X-Forwarded-Prefix header (Tailscale Serve), then config
        prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "")
        if not prefix:
            mount = cfg.get("tailscale_mount", "")
            if mount and mount != "/":
                prefix = mount
            else:
                prefix = self.prefix

        prefix = prefix.rstrip("/")

        if prefix:
            environ["SCRIPT_NAME"] = prefix
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith(prefix):
                environ["PATH_INFO"] = path_info[len(prefix):]

        def _start_response(status, headers, *args):
            # Rewrite outgoing Location headers so redirects include the prefix
            if prefix:
                for i, (k, v) in enumerate(headers):
                    if k.lower() == "location" and v.startswith("/") and not v.startswith(prefix):
                        headers[i] = (k, prefix + v)
            return start_response(status, headers, *args)

        return self.app(environ, _start_response)


# ── Strict input validation ───────────────────────────────────────────────
# These values become LinuxGSM shortnames, Linux usernames, home-directory paths and
# arguments to shell commands run as root during install. LinuxGSM shortnames are
# lowercase alphanumeric; a game-server instance name becomes a Linux user. Rejecting
# anything outside a safe charset here is what prevents shell/command injection into
# the install pipeline (a user with INSTALL_SERVER must NOT be able to run arbitrary
# root commands on a host).
GAME_TYPE_RE = re.compile(r"^[a-z0-9]{1,32}$")
INSTANCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")   # valid Linux username shape
LINUX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")     # for linuxgsm_user / ssh user

# Lightweight in-memory login throttle (single-process eventlet app). Blocks an IP
# after too many failed logins within the window — a basic brute-force speed bump.
_LOGIN_FAILS = {}
_LOGIN_FAILS_LOCK = threading.Lock()
LOGIN_MAX_FAILS = 8
LOGIN_WINDOW = 300  # seconds

MIN_PASSWORD_LEN = 10
import string as _string
_PW_SYMBOLS = set(_string.punctuation)


def password_problem(pw):
    """Return a human error if the password is too weak, else None.
    Requires: length, lower, upper, digit, and a symbol."""
    if not pw or len(pw) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if not any(c.islower() for c in pw):
        return "Password must include a lowercase letter."
    if not any(c.isupper() for c in pw):
        return "Password must include an uppercase letter."
    if not any(c.isdigit() for c in pw):
        return "Password must include a number."
    if not any(c in _PW_SYMBOLS for c in pw):
        return "Password must include a symbol (e.g. !@#$%)."
    return None


def _int_or(value, default):
    """Parse an int from untrusted form input, falling back to default instead of
    raising (a bad value like an empty or non-numeric port must not 500 the page)."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def create_app():
    app = Flask(__name__)
    cfg = load_config()
    app.config["SECRET_KEY"] = get_secret_key()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_NAME"] = "lgpanel_session"
    app.config["PERMANENT_SESSION_LIFETIME"] = cfg.get("session_lifetime_hours", 24) * 3600

    # Cookie path must cover the mount point — always use root to be safe
    # since we don't know the final mount until after setup
    app.config["SESSION_COOKIE_PATH"] = "/"

    # Session-cookie hardening. HttpOnly keeps JS from reading it; Secure keeps it to
    # HTTPS (the panel is served over HTTPS via Tailscale Serve); SameSite=Lax stops a
    # cross-site page from sending the cookie on a POST, which mitigates CSRF on the
    # form endpoints (the JSON API additionally requires an application/json body).
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Secure defaults ON once the panel is served over HTTPS — via Tailscale Serve, or
    # a reverse proxy once a site_domain is configured. OFF during first-run setup over
    # plain http://host:5000 so login still works. Override with cookie_secure.
    _https_ready = bool(cfg.get("tailscale_setup_done", False)) or bool((cfg.get("site_domain") or "").strip())
    app.config["SESSION_COOKIE_SECURE"] = cfg.get("cookie_secure", _https_ready)


    # Store mount prefix in app config so templates can access it
    app.config["_MOUNT_PREFIX"] = mount = cfg.get("tailscale_mount", "/")

    # Initialize extensions
    init_auth(app)
    init_db(app)

    # CSRF protection for every state-changing request. Forms carry a hidden token
    # (auto-injected in base.html); the JSON API sends it as an X-CSRFToken header
    # (a global fetch wrapper adds it). Defense-in-depth on top of the SameSite=Lax
    # session cookie. Tests disable it via WTF_CSRF_ENABLED=False.
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)  # token valid for the session
    CSRFProtect(app)

    # ── Security response headers ──
    # unsafe-inline is required because the UI uses inline <script>/<style> and onclick
    # handlers throughout; combined with Jinja auto-escaping it's still defense-in-depth
    # (blocks loading scripts from arbitrary external origins). CDN = jsdelivr only.
    # CDNs actually loaded by the UI: jsdelivr (Bootstrap, icons, Chart.js) and
    # cdnjs (the Socket.IO client for the live console).
    _CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; base-uri 'self'; object-src 'none'"
    )

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", _CSP)
        # Only advertise HSTS when the request actually came in over HTTPS (directly or
        # via a proxy that sets X-Forwarded-Proto), never over plain HTTP.
        if request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    # One-time: encrypt any legacy plaintext secrets/PII already in the DB
    # (remote SSH credentials, and user email addresses).
    with app.app_context():
        try:
            from models import RemoteServer, User
            changed = False
            for r in RemoteServer.query.all():
                if r.auth_credential and not is_encrypted(r.auth_credential) \
                        and r.auth_method in ("password", "key"):
                    r.auth_credential = encrypt_secret(r.auth_credential)
                    changed = True
            for u in User.query.all():
                if u.email and not is_encrypted(u.email):
                    u.email = encrypt_secret(u.email)
                    changed = True
            if changed:
                db.session.commit()
        except Exception:
            db.session.rollback()

    # Optional audit-log retention. Off by default (keep everything — audit history
    # shouldn't vanish by surprise). Set "audit_log_retention_days" in config.json to a
    # positive number to prune older entries on startup so the table can't grow forever.
    with app.app_context():
        try:
            days = int(cfg.get("audit_log_retention_days", 0) or 0)
            if days > 0:
                from datetime import datetime, timedelta
                from models import AuditLog
                cutoff = datetime.utcnow() - timedelta(days=days)
                deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
                if deleted:
                    db.session.commit()
        except Exception:
            db.session.rollback()

    # Register blueprints/routes
    register_routes(app)
    register_template_filters(app)
    register_context_processors(app)

    # Always apply the prefix middleware. It resolves the mount per-request from the
    # X-Forwarded-Prefix header (sent by Tailscale Serve) or the config, and is a no-op
    # when there is no prefix. Applying it unconditionally means a sub-path mount like
    # /lgsm works immediately — including during first-run setup — without needing a
    # restart after the config is written.
    app.wsgi_app = PrefixMiddleware(app.wsgi_app)

    return app


# ─── Template Filters ─────────────────────────────────────────

def register_template_filters(app):
    @app.template_filter("datetime")
    def format_datetime(dt):
        if dt:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return "Never"

    @app.template_filter("permlabel")
    def permission_label(perm):
        return ALL_PERMISSIONS.get(perm, perm)


# ─── Context Processors ───────────────────────────────────────

def register_context_processors(app):
    @app.context_processor
    def inject_globals():
        cfg = load_config()
        # Get Tailscale info for URL injection
        tailscale_url = None
        try:
            ts_info = ts.get_tailscale_info()
            if ts_info.dns_name:
                tailscale_url = f"https://{ts_info.dns_name}"
        except Exception:
            pass
        # Non-local remotes for the SYSTEM nav (one management link per remote VPS).
        nav_remotes = []
        try:
            if getattr(current_user, "is_authenticated", False) and (
                current_user.is_superadmin or "manage_remotes" in get_user_permissions(current_user)
            ):
                nav_remotes = (RemoteServer.query.filter_by(is_local=False)
                               .order_by(RemoteServer.name).all())
        except Exception:
            nav_remotes = []
        return {
            "site_title": cfg.get("site_title", "LinuxGSM Panel"),
            "current_year": datetime.utcnow().year,
            "tailscale_url": tailscale_url,
            "mount_prefix": app.config.get("_MOUNT_PREFIX", "/"),
            "panel_version": PANEL_VERSION,
            "nav_remotes": nav_remotes,
            "has_permission": lambda perm: (
                current_user.is_superadmin
                or perm in get_user_permissions(current_user)
            ) if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated else False,
        }


# ─── Routes ───────────────────────────────────────────────────

def register_routes(app):

    # ── Helpers ─────────────────────────────────────────────
    def get_remote(remote_id):
        """Fetch a remote AND enforce per-host access. MANAGE_REMOTES grants the
        ability to manage remotes, but only the ones in the user's groups — the same
        per-host scoping game servers get. Superadmin sees all. Every remote-scoped
        route goes through here, so a direct API call to another remote's id is a 403."""
        r = RemoteServer.query.get_or_404(remote_id)
        if not can_access_remote(current_user, remote_id):
            abort(403)
        return r

    def resolve_free_port(remote, remote_id, desired):
        """Find a free port at/after `desired` on a remote. A port is considered
        taken if another panel game server on the same remote uses it (each reserves
        port and port+1 for the query port) or if it's currently listening on the
        remote host. Returns (port, changed)."""
        occupied = set()
        for e in GameServer.query.filter_by(remote_id=remote_id).all():
            occupied.add(e.port)
            occupied.add(e.port + 1)
        p = desired
        for _ in range(200):
            if p not in occupied and (p + 1) not in occupied and not port_in_use(remote, p):
                break
            p += 1
        return p, (p != desired)

    def get_game(server_id):
        return GameServer.query.get_or_404(server_id)

    # ── Setup Wizard ────────────────────────────────────────
    def is_setup_complete():
        """Check if setup wizard has been completed."""
        state = SetupState.query.filter_by(complete=True).first()
        cfg = load_config()
        return state is not None and cfg.get("setup_complete", False)

    @app.before_request
    def check_setup():
        """Redirect to setup if not complete (except for setup pages and static).
        Until setup is finished there are no users, so every other page — including
        the login page and the dashboard root — funnels into the setup wizard."""
        # The wizard's own AJAX lives under /api/setup/* — it must NOT be redirected to
        # /setup or the JS gets an HTML redirect instead of JSON ("Could not check
        # Tailscale status"). Those endpoints self-guard with _setup_open() (403 once
        # setup is done), so exempting them here is safe.
        if request.path.startswith("/static/") or request.path == "/setup" \
                or request.path.startswith("/setup/") or request.path.startswith("/api/setup/"):
            return
        if not is_setup_complete():
            return redirect("/setup")

    @app.route("/setup", methods=["GET", "POST"])
    def setup_wizard():
        # SECURITY: the setup wizard has NO authentication (it must be reachable on a
        # fresh install to create the first admin). Once setup is finished it is
        # PERMANENTLY LOCKED for both GET and POST. Previously only GET was blocked, so
        # an unauthenticated POST /setup with step=admin_user could create a brand-new
        # superadmin (or step=welcome could rewrite bind_host/port). Lock everything.
        if is_setup_complete():
            return redirect(url_for("login"))

        state = SetupState.query.first()
        if not state:
            state = SetupState(step="welcome", data="{}")
            db.session.add(state)
            db.session.commit()

        current_step = state.step
        data = json.loads(state.data or "{}")
        cfg = load_config()

        if request.method == "POST":
            step = request.form.get("step", "welcome")

            if step == "welcome":
                # Step 1: Site settings
                cfg["site_title"] = request.form.get("site_title", "LinuxGSM Panel")
                cfg["site_domain"] = request.form.get("site_domain", "")
                cfg["port"] = _int_or(request.form.get("port"), 5000)
                cfg["bind_host"] = request.form.get("bind_host", "0.0.0.0")
                save_config(cfg)
                data["site_configured"] = True
                state.step = "admin_user"
                state.data = json.dumps(data)
                db.session.commit()
                return redirect("/setup")

            elif step == "admin_user":
                # Defence in depth: the setup wizard only ever creates the FIRST admin.
                # If a superadmin already exists, refuse (belt-and-suspenders behind the
                # is_setup_complete lock above).
                if User.query.filter_by(is_superadmin=True).first():
                    return redirect(url_for("login"))
                # Step 2: Create admin user
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                confirm = request.form.get("confirm_password", "")
                email = request.form.get("email", "").strip()

                if not username or len(username) < 3:
                    flash("Username must be at least 3 characters.", "danger")
                elif password_problem(password):
                    flash(password_problem(password), "danger")
                elif password != confirm:
                    flash("Passwords do not match.", "danger")
                else:
                    existing = User.query.filter_by(username=username).first()
                    if existing:
                        flash("Username already exists.", "danger")
                    else:
                        admin = User(
                            username=username,
                            password_hash=hash_password(password),
                            email=encrypt_secret(email) if email else None,
                            display_name=username,
                            is_superadmin=True,
                            is_active=True,
                        )
                        db.session.add(admin)
                        # Add to Everyone group
                        everyone = Group.query.filter_by(name="Everyone").first()
                        if everyone:
                            admin.groups.append(everyone)
                        db.session.commit()
                        data["admin_created"] = True
                        state.step = "tailscale"
                        state.data = json.dumps(data)
                        db.session.commit()
                        return redirect("/setup")

            elif step == "tailscale":
                # The interactive install/connect/serve runs via /api/setup/tailscale/*;
                # this POST (Continue or Skip) just advances the wizard.
                state.step = "remote_server"
                state.data = json.dumps(data)
                db.session.commit()
                return redirect("/setup")

            elif step == "remote_server":
                action = request.form.get("action", "skip")
                if action == "add":
                    name = request.form.get("name", "").strip()
                    host = request.form.get("host", "").strip()
                    ssh_user = request.form.get("ssh_user", "root").strip()
                    ssh_port = _int_or(request.form.get("ssh_port"), 22)
                    auth_method = request.form.get("auth_method", "key")
                    credential = request.form.get("credential", "").strip()
                    sudo_enabled = request.form.get("sudo_enabled") == "on"
                    lgsm_user = request.form.get("lgsm_user", "").strip()

                    if not name or not host:
                        flash("Name and host are required.", "danger")
                    else:
                        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential)
                        if not success:
                            flash(f"Connection test failed: {msg}", "danger")
                        else:
                            remote = RemoteServer(
                                name=name, host=host, port=ssh_port,
                                username=ssh_user, auth_method=auth_method,
                                auth_credential=encrypt_secret(credential),
                                sudo_enabled=sudo_enabled,
                                linuxgsm_user=lgsm_user,
                                is_online=True,
                                last_seen=datetime.utcnow(),
                            )
                            db.session.add(remote)
                            db.session.commit()
                            flash(f"Remote '{name}' added successfully!", "success")
                            data["remote_added"] = True
                            state.data = json.dumps(data)

                if action == "skip" or request.form.get("done") == "1":
                    state.step = "complete"
                    state.complete = True
                    state.data = json.dumps(data)
                    cfg["setup_complete"] = True
                    save_config(cfg)  # Save FIRST, before Tailscale attempt
                    # Auto-configure Tailscale Serve if available
                    if cfg.get("tailscale_auto_setup", True):
                        try:
                            ts_info = ts.get_tailscale_info()
                            if ts_info.running and ts_info.dns_name:
                                mount = "/lgsm"
                                serve_info = ts_info.serve_config
                                root_taken = False
                                if serve_info and serve_info.get("services"):
                                    for svc in serve_info["services"]:
                                        for route in svc.get("routes", []):
                                            if route.get("mount") == "/":
                                                root_taken = True
                                                break
                                if not root_taken:
                                    mount = cfg.get("tailscale_mount", "/")
                                ts.setup_tailscale_serve(
                                    port=cfg.get("port", 5000),
                                    mount=mount,
                                    funnel=cfg.get("tailscale_use_funnel", False),
                                )
                                cfg["tailscale_mount"] = mount
                                cfg["tailscale_setup_done"] = True
                                save_config(cfg)
                        except Exception:
                            pass
                    db.session.commit()
                    flash("Setup complete! You can now log in.", "success")
                    return redirect("/setup")

                state.data = json.dumps(data)
                db.session.commit()

            return redirect("/setup")

        # GET request - render the current step
        step_templates = {
            "welcome": "setup_welcome.html",
            "admin_user": "setup_admin.html",
            "tailscale": "setup_tailscale.html",
            "remote_server": "setup_remote.html",
            "complete": "setup_complete.html",
        }
        tmpl = step_templates.get(state.step, "setup_welcome.html")
        ts_info = ts.get_tailscale_info()
        return render_template(tmpl, step=state.step, data=data, config=cfg, ts=ts_info)

    # ── Setup-only Tailscale endpoints ─────────────────────────
    # No login exists yet during setup, so these are unauthenticated BUT usable ONLY
    # while setup is unfinished (they're a no-op/forbidden once complete, same as the
    # wizard itself). They operate on THIS host only.
    def _setup_open():
        return not is_setup_complete()

    @app.route("/api/setup/tailscale/status")
    def api_setup_ts_status():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        info = ts.get_tailscale_info(force_refresh=True)
        serve_url = next((s.get("url") for s in (info.serve_config or {}).get("services", [])), None)
        return jsonify({
            "installed": info.installed, "running": info.running,
            "dns_name": info.dns_name, "ips": info.tailscale_ips,
            "serve_url": serve_url,
            "https_url": (f"https://{info.dns_name}" if info.dns_name else None),
        })

    @app.route("/api/setup/tailscale/install", methods=["POST"])
    def api_setup_ts_install():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        ok, log = ts.install_tailscale_local()
        return jsonify({"success": ok, "log": log})

    @app.route("/api/setup/tailscale/up", methods=["POST"])
    def api_setup_ts_up():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        ok, res = ts.tailscale_up_local(enable_ssh=True)
        if not ok:
            return jsonify({"success": False, "message": res})
        if res == "ALREADY_CONNECTED":
            return jsonify({"success": True, "connected": True})
        return jsonify({"success": True, "connected": False, "auth_url": res})

    @app.route("/api/setup/tailscale/serve", methods=["POST"])
    def api_setup_ts_serve():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        cfg = load_config()
        port = cfg.get("port", 5000)
        mount = cfg.get("tailscale_mount", "/") or "/"
        ok, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=False)
        if not ok:
            return jsonify({"success": False, "message": msg})
        info = ts.get_tailscale_info(force_refresh=True)
        cfg["tailscale_setup_done"] = True
        cfg["tailscale_mount"] = mount
        cfg["bind_host"] = "127.0.0.1"   # Serve proxies to localhost; go tailnet-only
        if info.dns_name and not cfg.get("site_domain"):
            cfg["site_domain"] = info.dns_name
        save_config(cfg)
        return jsonify({"success": True, "message": msg,
                        "url": (f"https://{info.dns_name}" if info.dns_name else None)})

    # ── Authentication Routes ──────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/")

        if request.method == "POST":
            ip = client_ip() or "unknown"
            now = time.time()
            # Brute-force throttle: drop stale failures, block if too many remain.
            with _LOGIN_FAILS_LOCK:
                fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
                _LOGIN_FAILS[ip] = fails
                blocked = len(fails) >= LOGIN_MAX_FAILS
            if blocked:
                log_action(None, "login_blocked", detail=f"rate-limited {ip}", success=False)
                flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
                return render_template("login.html")

            def _fail(msg, **kw):
                with _LOGIN_FAILS_LOCK:
                    _LOGIN_FAILS.setdefault(ip, []).append(now)
                flash(msg, "danger")
                return render_template("login.html", **kw)

            def _succeed(user, remember):
                with _LOGIN_FAILS_LOCK:
                    _LOGIN_FAILS.pop(ip, None)   # clear on success
                for k in ("_2fa_pending", "_2fa_at", "_2fa_remember"):
                    session.pop(k, None)
                login_user(user, remember=remember)
                user.last_login = datetime.utcnow()
                db.session.commit()
                log_action(user, "login", detail=f"User logged in from {ip}")
                # Open-redirect-safe: only allow same-site relative paths in ?next=.
                next_page = request.args.get("next", "/")
                if not next_page.startswith("/") or next_page.startswith("//"):
                    next_page = "/"
                return redirect(next_page)

            # ── Step 2: the 2FA code for a login that passed the password step ──
            pending_id = session.get("_2fa_pending")
            if pending_id and request.form.get("totp_code"):
                if now - session.get("_2fa_at", 0) > 300:   # prompt expires after 5 min
                    session.pop("_2fa_pending", None)
                    flash("The two-factor prompt expired — please log in again.", "danger")
                    return render_template("login.html")
                u = User.query.get(pending_id)
                if u and u.is_active and u.totp_enabled and \
                        verify_totp(u.totp_secret_plain, request.form.get("totp_code", "")):
                    return _succeed(u, bool(session.get("_2fa_remember")))
                return _fail("Invalid authentication code.", two_factor=True)

            # ── Step 1: username + password ──
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            remember = request.form.get("remember") == "on"

            user = User.query.filter_by(username=username).first()
            if user and user.is_active and check_password(password, user.password_hash):
                if user.totp_enabled and user.totp_secret_plain:
                    session["_2fa_pending"] = user.id
                    session["_2fa_at"] = now
                    session["_2fa_remember"] = remember
                    return render_template("login.html", two_factor=True)
                return _succeed(user, remember)
            return _fail("Invalid username or password.")

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        # POST-only so it can't be triggered cross-site via a GET (e.g. <img src=…/logout>).
        log_action(current_user, "logout", detail="User logged out")
        logout_user()
        flash("You have been logged out.", "info")
        return redirect("/login")

    # ── Account / Two-factor auth ───────────────────────────
    def _qr_svg(data):
        """Render `data` as an inline SVG QR code (no PIL needed)."""
        import io
        import qrcode
        import qrcode.image.svg
        qr = qrcode.QRCode(box_size=9, border=2, image_factory=qrcode.image.svg.SvgPathImage)
        qr.add_data(data)
        qr.make(fit=True)
        buf = io.BytesIO()
        qr.make_image().save(buf)
        return buf.getvalue().decode()

    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html")

    @app.route("/account/2fa/enable", methods=["GET", "POST"])
    @login_required
    def account_2fa_enable():
        if current_user.totp_enabled:
            flash("Two-factor authentication is already enabled.", "info")
            return redirect(url_for("account"))
        if request.method == "POST":
            secret = session.get("_2fa_setup_secret", "")
            if secret and verify_totp(secret, request.form.get("totp_code", "")):
                current_user.totp_secret = encrypt_secret(secret)
                current_user.totp_enabled = True
                db.session.commit()
                session.pop("_2fa_setup_secret", None)
                log_action(current_user, "2fa_enabled", target=current_user.username)
                flash("Two-factor authentication is now enabled.", "success")
                return redirect(url_for("account"))
            flash("That code didn't match — check your device's time and try again.", "danger")
        # (Re)issue a pending secret for this enrolment attempt.
        secret = session.get("_2fa_setup_secret") or generate_totp_secret()
        session["_2fa_setup_secret"] = secret
        uri = totp_provisioning_uri(secret, current_user.username)
        return render_template("account_2fa.html", secret=secret, qr_svg=_qr_svg(uri))

    @app.route("/account/2fa/disable", methods=["POST"])
    @login_required
    def account_2fa_disable():
        if not check_password(request.form.get("password", ""), current_user.password_hash):
            flash("Password incorrect — two-factor authentication was not changed.", "danger")
            return redirect(url_for("account"))
        current_user.totp_enabled = False
        current_user.totp_secret = None
        db.session.commit()
        log_action(current_user, "2fa_disabled", target=current_user.username)
        flash("Two-factor authentication disabled.", "success")
        return redirect(url_for("account"))

    # ── Dashboard ──────────────────────────────────────────
    @app.route("/")
    @login_required
    def index():
        if not is_setup_complete():
            return redirect("/setup")

        remotes = RemoteServer.query.all()
        remote_count = RemoteServer.query.filter_by(is_local=False).count()
        servers = get_user_servers(current_user)
        uperms = get_user_permissions(current_user)
        can_control = current_user.is_superadmin or bool(
            {START_SERVER, STOP_SERVER, RESTART_SERVER} & uperms
        )
        return render_template("dashboard.html", remotes=remotes, servers=servers,
                               server_list=servers, can_control=can_control,
                               remote_count=remote_count)

    # ── Server Detail + Console ────────────────────────────
    @app.route("/server/<int:server_id>")
    @login_required
    @server_access_required
    def server_detail(server_id):
        gs = get_game(server_id)
        remote = gs.remote

        # Render fast: no SSH on the render path. Live status, console output and
        # per-game metrics all stream in asynchronously (websocket + /stats + /console
        # polling), so the page appears instantly instead of waiting on the remote.
        console_lines = []

        # Available actions based on permissions
        user_perms = get_user_permissions(current_user)
        is_sa = current_user.is_superadmin

        def _can(perm):
            return is_sa or perm in user_perms

        # Order matters — this is the on-screen button order. Start, Stop, Restart,
        # Update reads most naturally (lifecycle order).
        actions = []
        if _can(START_SERVER):
            actions.append(("start", "Start"))
        if _can(STOP_SERVER):
            actions.append(("stop", "Stop"))
        if _can(RESTART_SERVER):
            actions.append(("restart", "Restart"))
        if _can(UPDATE_SERVER):
            actions.append(("update", "Update"))

        # Use the cached LinuxGSM command list (populated at install time). If it's
        # somehow empty, the sidebar's refresh button repopulates it on demand — we
        # never block the page render on an SSH call to fetch it.
        all_commands = gs.get_commands()

        # Extra maintenance commands (beyond start/stop/restart/update) this game
        # supports and the user is allowed to run.
        maint_perm = {
            "monitor": VIEW_CONSOLE, "details": VIEW_CONSOLE, "check-update": VIEW_CONSOLE,
            "postdetails": VIEW_CONSOLE, "test-alert": VIEW_CONSOLE,
            "validate": UPDATE_SERVER, "backup": UPDATE_SERVER, "force-update": UPDATE_SERVER,
            "update-lgsm": UPDATE_SERVER, "mods-update": UPDATE_SERVER,
        }
        core = {"start", "stop", "restart", "update"}
        maintenance = [
            {"cmd": c["cmd"], "desc": c["desc"]}
            for c in all_commands
            if c["cmd"] in maint_perm and c["cmd"] not in core and _can(maint_perm[c["cmd"]])
        ]

        can_send_command = _can(SEND_COMMAND)
        can_autostart = _can(RESTART_SERVER)

        # Public address players connect to. For the LOCAL panel host, remote.host is
        # 127.0.0.1 (loopback SSH), so resolve/cache the real public IP instead.
        if not remote.public_ip:
            try:
                ip = remote_public_ip(remote)
                if ip:
                    remote.public_ip = ip
                    db.session.commit()
            except Exception:
                pass
        public_host = remote.public_ip or ("" if remote.is_local else remote.host)

        return render_template("server_detail.html", server=gs, remote=remote,
                               console_lines=console_lines, actions=actions,
                               maintenance=maintenance, all_commands=all_commands,
                               can_send_command=can_send_command,
                               can_autostart=can_autostart, public_host=public_host)

    def _perm_for_action(action):
        """Which permission an action requires (core actions have specific perms;
        read-only commands need VIEW_CONSOLE; the rest need UPDATE_SERVER)."""
        p = ACTION_PERMISSION_MAP.get(action)
        if p is None:
            p = VIEW_CONSOLE if action in READONLY_ACTIONS else UPDATE_SERVER
        return p

    def _run_action(gs, remote, action, actor):
        """Execute a whitelisted action (permission already checked).
        Returns (ok, message). Long actions run in the background."""
        if action in LONG_ACTIONS:
            _bg_action(gs.id, remote.id, gs.short_name, action, gs.lgsm_name)
            log_action(actor, f"{action}_server", target=gs.name)
            return True, f"'{action}' started — watch the live console for progress."
        timeout = 90 if action == "restart" else 60
        out, err, rc = run_as_game_user(remote, gs.short_name, f"{action} 2>&1", timeout=timeout, selfname=gs.lgsm_name)
        # Strip ALL ANSI/CSI escape sequences (colors end in 'm', but LinuxGSM also
        # emits erase-line "\x1b[K" etc.), plus collapse whitespace for a clean message.
        def _clean(s):
            s = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", s or "")
            return re.sub(r"[ \t]{2,}", " ", s)
        log_action(actor, f"{action}_server", target=gs.name, success=(rc == 0), detail=_clean(out)[-400:])
        clean = _clean((out or "") + "\n" + (err or "")).strip()
        if action in READONLY_ACTIONS:
            return True, f"{action}: {clean[:600] or 'no output'}"
        if rc == 0:
            return True, f"'{action}' succeeded for '{gs.name}'."
        # Surface WHY it failed — pull the most relevant LinuxGSM line.
        reason = ""
        for line in reversed(clean.splitlines()):
            low = line.lower()
            if any(k in low for k in ("fail", "unable", "error", "missing", "not found", "no such")):
                reason = line.strip()
                break
        if not reason and clean.splitlines():
            reason = clean.splitlines()[-1].strip()
        return False, f"'{action}' failed for '{gs.name}': {reason[:280] or 'unknown — check the console'}"

    @app.route("/server/<int:server_id>/action", methods=["POST"])
    @login_required
    @server_access_required
    def server_action(server_id):
        gs = get_game(server_id)
        action = request.form.get("action", "")
        if action not in RUNNABLE_ACTIONS:
            flash(f"Unknown or unsupported action: {action}", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action(action)):
            flash(f"You don't have permission to run '{action}'.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        try:
            ok, msg = _run_action(gs, gs.remote, action, current_user)
            flash(msg, "info" if (action in LONG_ACTIONS or action in READONLY_ACTIONS) else ("success" if ok else "warning"))
        except Exception as e:
            log_action(current_user, f"{action}_server", target=gs.name, detail=str(e), success=False)
            flash(f"Action failed: {e}", "danger")
        return redirect(url_for("server_detail", server_id=server_id))

    @app.route("/api/server/<int:server_id>/action", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_action(server_id):
        """JSON action endpoint for inline controls (dashboard/lists) — no reload."""
        gs = get_game(server_id)
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or "").strip()
        if action not in RUNNABLE_ACTIONS:
            return jsonify({"success": False, "message": f"Unsupported action: {action}"}), 400
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action(action)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            ok, msg = _run_action(gs, gs.remote, action, current_user)
            return jsonify({"success": ok, "message": msg})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/server/<int:server_id>/autostart", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_autostart(server_id):
        """Toggle auto-start on boot (manages the game user's @reboot crontab)."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, RESTART_SERVER):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        data = request.get_json(silent=True) or {}
        enabled = bool(data.get("enabled"))
        try:
            ok, detail = set_autostart(gs.remote, gs.short_name, enabled, gs.lgsm_name)
            if ok:
                gs.autostart = enabled
                db.session.commit()
                log_action(current_user, "set_autostart", target=gs.name, detail=str(enabled))
                return jsonify({"success": True, "enabled": enabled})
            return jsonify({"success": False, "message": detail or "Failed to update crontab"}), 500
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/server/<int:server_id>/daily-restart", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_daily_restart(server_id):
        """Toggle the daily restart-when-empty schedule for this server."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, RESTART_SERVER):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        enabled = bool((request.get_json(silent=True) or {}).get("enabled"))
        try:
            ok, detail = set_daily_restart(gs.remote, gs.short_name, gs.lgsm_name,
                                           gs.game_type, gs.port, enabled)
            if ok:
                gs.daily_restart = enabled
                db.session.commit()
                log_action(current_user, "set_daily_restart", target=gs.name, detail=str(enabled))
                return jsonify({"success": True, "enabled": enabled})
            return jsonify({"success": False, "message": detail or "Failed to update schedule"}), 500
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    def _bg_action(server_id, remote_id, short_name, action, selfname=None):
        """Run a long LinuxGSM command in the background (green thread)."""
        _app = app

        def _run():
            try:
                with _app.app_context():
                    remote = RemoteServer.query.get(remote_id)
                    if not remote:
                        return
                    out, err, rc = run_as_game_user(remote, short_name, f"{action} 2>&1", timeout=1800, selfname=selfname)
                    gs = GameServer.query.get(server_id)
                    from auth import log_action as _log
                    _log(None, f"{action}_complete", target=gs.name if gs else short_name,
                         success=(rc == 0), detail=(out or err or "")[-300:])
            except Exception as e:
                print(f"bg action error: {e}", flush=True)

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/server/<int:server_id>/refresh-commands", methods=["POST"])
    @login_required
    @server_access_required
    def refresh_server_commands(server_id):
        gs = get_game(server_id)
        try:
            cmds = list_server_commands(gs.remote, gs.short_name, gs.lgsm_name)
            gs.set_commands(cmds)
            db.session.commit()
            flash(f"Loaded {len(cmds)} commands for '{gs.name}'.", "success")
        except Exception as e:
            flash(f"Could not load commands: {e}", "danger")
        return redirect(url_for("server_detail", server_id=server_id))

    @app.route("/server/<int:server_id>/command", methods=["POST"])
    @login_required
    @server_access_required
    def server_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        cmd_text = request.form.get("command", "").strip()

        if not cmd_text:
            flash("No command entered.", "warning")
            return redirect(url_for("server_detail", server_id=server_id))

        # Permission check
        if not current_user.is_superadmin and not has_permission(current_user, SEND_COMMAND):
            flash("You don't have permission to send commands.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))

        try:
            # LinuxGSM runs each instance in a tmux session owned by its own user.
            out, err, rc = send_console_command(remote, gs.short_name, cmd_text, timeout=10, selfname=gs.lgsm_name)
            if rc != 0:
                flash("Cannot send command: server console (tmux) not accessible. Is the server running?", "warning")
                return redirect(url_for("server_detail", server_id=server_id))
            log_action(current_user, "send_command", target=gs.name, detail=cmd_text, success=True)
            flash(f"Command sent: {cmd_text}", "success")

        except Exception as e:
            log_action(current_user, "send_command", target=gs.name, detail=f"{cmd_text} - {e}", success=False)
            flash(f"Failed to send command: {e}", "danger")

        return redirect(url_for("server_detail", server_id=server_id))

    # ── Manage Game Servers ────────────────────────────────
    @app.route("/servers/manage")
    @login_required
    @permission_required(MANAGE_SERVERS, INSTALL_SERVER)
    def manage_servers():
        remotes = RemoteServer.query.all()
        all_servers = GameServer.query.all()
        return render_template("manage_servers.html", remotes=remotes,
                               all_servers=all_servers, games=load_game_list())

    @app.route("/servers/add", methods=["POST"])
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def install_game_server():
        remote_id = request.form.get("remote_id", type=int)
        game_type = request.form.get("game_type", "").strip().lower()
        server_name = request.form.get("server_name", "").strip()
        port = request.form.get("port", "27015").strip()
        remote = get_remote(remote_id)

        # SECURITY: game_type and server_name become Linux users / paths / root shell
        # arguments during install — validate strictly to prevent command injection.
        if not GAME_TYPE_RE.match(game_type) or game_type not in {g["shortname"] for g in load_game_list()}:
            flash("Invalid or unknown game type.", "danger")
            return redirect(url_for("manage_servers"))
        if server_name:
            server_name = server_name.lower()
            if not INSTANCE_NAME_RE.match(server_name):
                flash("Server name must be lowercase letters, numbers, - or _ and start with "
                      "a letter (it becomes a Linux user on the host).", "danger")
                return redirect(url_for("manage_servers"))

        # Canonical LinuxGSM server name — always "{shortname}server".
        lgsm_name = f"{game_type}server"
        short_name = server_name or lgsm_name

        # Best-effort default port per game for the install form. This is only a
        # pre-install HINT — after install the panel reads LinuxGSM's real port(s)
        # via `details` and opens every one, so an imperfect default self-corrects.
        KNOWN_PORTS = {
            # Source engine — default 27015
            "gmod": 27015, "cs": 27015, "css": 27015, "cs2": 27015, "csgo": 27015,
            "tf2": 27015, "hl2dm": 27015, "hldm": 27015, "hldms": 27015, "dods": 27015,
            "ins": 27015, "insurgency": 27015, "nmrih": 27015, "l4d": 27015, "l4d2": 27015,
            "zps": 27015, "fof": 27015, "gesource": 27015, "cscz": 27015, "tfc": 27015,
            "ns": 27015, "ricochet": 27015, "dmc": 27015, "sfc": 27015, "bb2": 27015,
            "unturned": 27015, "bt": 27015,
            # Call of Duty — 28960
            "cod": 28960, "coduo": 28960, "cod2": 28960, "cod4": 28960, "codwaw": 28960,
            # Minecraft family
            "mc": 25565, "pmc": 25565, "spigot": 25565, "paper": 25565, "bukkit": 25565,
            "mcbe": 19132, "mcb": 19132,
            # Survival / sandbox
            "rust": 28015, "sdtd": 26900, "7d2d": 26900, "valheim": 2456, "vh": 2456,
            "ark": 7777, "pz": 16261, "projectzomboid": 16261, "terraria": 7777,
            "tshock": 7777, "factorio": 34197, "avorion": 27000, "eco": 3000, "vs": 42420,
            # Mil-sim / shooters
            "arma3": 2302, "squad": 7787, "mordhau": 7777, "kf": 7707, "kf2": 7777,
            "q2": 27910, "q3": 27960, "ql": 27960, "et": 27960, "etl": 27960, "rtcw": 27960,
            "xonotic": 26000, "ut99": 7777, "ut2k4": 7777,
            # Voice / misc
            "mumble": 64738, "ts3": 9987, "samp": 7777, "mta": 22003, "openttd": 3979,
        }
        if not port or port == "27015":
            port = str(KNOWN_PORTS.get(game_type, 27015))
        try:
            desired_port = int(port)
        except (TypeError, ValueError):
            desired_port = KNOWN_PORTS.get(game_type, 27015)

        # Port-conflict handling: auto-pick the next free port if taken.
        final_port, port_changed = resolve_free_port(remote, remote_id, desired_port)

        # Reject a duplicate instance name on the same remote.
        if GameServer.query.filter_by(short_name=short_name, remote_id=remote_id).first():
            flash(f"A server named '{short_name}' already exists on this remote.", "danger")
            return redirect(url_for("manage_servers"))

        # Create the DB row up-front in the "installing" state, then run the WHOLE
        # install in a background job with live step-by-step progress (polled by the
        # Game Servers page — mirrors the VPS bootstrap progress). The route returns
        # immediately so the browser never waits on the long download.
        gs = GameServer(
            remote_id=remote_id, name=server_name or short_name, short_name=short_name,
            game_type=game_type, game_display=game_type, port=final_port,
            installed=False, status="installing",
        )
        db.session.add(gs)
        db.session.commit()

        with _install_lock:
            _install_jobs[gs.id] = {
                "status": "running", "step": 0, "total": 8, "step_name": "Queued",
                "message": "", "log": [], "started": time.time(), "updated": time.time(),
                "name": gs.name,
            }
        _run_install_job(gs.id, remote_id, short_name, game_type, lgsm_name, final_port)

        log_action(current_user, "install_server", target=gs.name,
                   detail=f"Type: {game_type}, port: {final_port}")
        port_note = (f" (port {desired_port} was busy — using {final_port})" if port_changed else "")
        flash(f"Installing {short_name} on port {final_port}{port_note}. "
              f"Progress is shown live below.", "success")
        return redirect(url_for("manage_servers"))

    def _run_install_job(gs_id, remote_id, short_name, game_type, lgsm_name, final_port):
        """Full game-server install as a tracked background job with step progress.
        Steps (8): user → LinuxGSM → deps → game files → config → port/firewall →
        autostart → start. Progress is streamed into _install_jobs[gs_id]."""
        _app = app

        def _p(step, name, status="running", message=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is None:
                    return
                j["step"], j["step_name"], j["status"], j["updated"] = step, name, status, time.time()
                if message:
                    j["message"] = message
                j["log"].append(f"[{step}/{j['total']}] {name}")

        def _fail(name, detail=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                cur = j["step"] if j else 0
            _p(cur, name, status="failed", message=detail)

        def _finish(msg):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is not None:
                    j["status"], j["step"] = "done", j["total"]
                    j["step_name"], j["message"], j["updated"] = "Complete", msg, time.time()

        def _run():
            try:
                from models import db, RemoteServer, GameServer
                with _app.app_context():
                    remote = RemoteServer.query.get(remote_id)
                    gs = GameServer.query.get(gs_id)
                    if not remote or not gs:
                        return

                    # 1. User account (clean any half-finished leftover first).
                    _p(1, "Preparing user account")
                    chk, _, _ = run_command(remote, f"test -x /home/{short_name}/linuxgsm.sh && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in chk:
                        run_command(remote, f"userdel -r {short_name} 2>/dev/null; rm -rf /home/{short_name} 2>/dev/null; echo done", timeout=15, sudo=True)
                    idout, _, _ = run_command(remote, f"id {short_name} 2>/dev/null && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in idout:
                        run_command(remote, f"useradd -m -s /bin/bash {short_name} 2>&1", timeout=15, sudo=True)
                        time.sleep(0.3)

                    # 2. Download & set up LinuxGSM (canonical script name).
                    _p(2, "Downloading LinuxGSM")
                    install_cmd = (f"sudo -u {short_name} bash -c 'cd /home/{short_name} && "
                                   f"wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh && "
                                   f"bash linuxgsm.sh {lgsm_name}' 2>&1")
                    out = err = ""; rc = -1
                    for attempt in range(10):
                        out, err, rc = run_command(remote, install_cmd, timeout=300, sudo=False)
                        if "unknown user" not in (out + err):
                            break
                        time.sleep(0.5 * (attempt + 1))
                    if "Unknown game server" in out:
                        _fail("Invalid game type", f"'{game_type}' is not a valid LinuxGSM shortname."); return
                    if rc != 0:
                        _fail("LinuxGSM setup failed", (out or err)[-300:]); return

                    # 3. System dependencies (as root — the game user has no sudo).
                    _p(3, "Installing dependencies")
                    try:
                        install_game_dependencies(remote, game_type)
                    except Exception:
                        pass

                    # 4. Download the game server files (the long step).
                    _p(4, "Downloading game server files (this can take a while)")
                    auto = f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} auto-install' 2>&1"
                    out, err, rc = run_command(remote, auto, timeout=1800, sudo=False)
                    missing = parse_missing_deps((out or "") + "\n" + (err or ""))
                    if missing:
                        try:
                            install_game_dependencies(remote, game_type, extra=" ".join(missing))
                            out, err, rc = run_command(remote, auto, timeout=1800, sudo=False)
                        except Exception:
                            pass
                    if rc != 0:
                        gs.installed = False; gs.status = "offline"; db.session.commit()
                        _fail("Game install failed", (out or err)[-300:]); return
                    gs.installed = True; db.session.commit()

                    # 5. Configure: cache command list + maintenance cron + Minecraft EULA.
                    _p(5, "Configuring server")
                    try:
                        cmds = list_server_commands(remote, short_name, gs.lgsm_name)
                        if cmds:
                            gs.set_commands(cmds); db.session.commit()
                            try:
                                install_game_cron(remote, short_name, gs.lgsm_name, {c["cmd"] for c in cmds})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    if gs.game_type in ("mc", "mcbe", "pmc", "spigot", "paper"):
                        try:
                            run_command(remote, f"sudo -u {short_name} bash -c \"echo 'eula=true' > /home/{short_name}/serverfiles/eula.txt 2>/dev/null; true\"", timeout=15, sudo=False)
                        except Exception:
                            pass

                    # 6. Sync to LinuxGSM's real port(s) and open ALL of them (many
                    #    games need game+query+rcon+etc., not just the main port).
                    _p(6, "Detecting ports & opening firewall")
                    try:
                        info = detect_game_ports(remote, short_name, gs.lgsm_name)
                        real_port = info.get("game_port")
                        if real_port and real_port != gs.port:
                            old_port = gs.port; gs.port = real_port; db.session.commit()
                            try:
                                remote_ufw_close_game_port(remote, old_port)
                            except Exception:
                                pass
                        to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
                        remote_ufw_allow_game_ports(remote, to_open, short_name)
                    except Exception:
                        pass

                    # 7. Enable autostart-on-boot by default.
                    _p(7, "Enabling autostart on boot")
                    try:
                        set_autostart(remote, short_name, True, gs.lgsm_name)
                    except Exception:
                        pass

                    # 8. Start the server.
                    _p(8, "Starting server")
                    try:
                        _, _, s_rc = run_as_game_user(remote, short_name, "start 2>&1", timeout=120, selfname=gs.lgsm_name)
                        gs.status = "online" if s_rc == 0 else "offline"; db.session.commit()
                    except Exception:
                        pass

                    _finish(f"{short_name} installed")
                    from auth import log_action as _log
                    _log(None, "install_complete", target=gs.name, success=True)
            except Exception as e:
                with _install_lock:
                    j = _install_jobs.get(gs_id)
                    if j is not None:
                        j["status"], j["message"], j["updated"] = "failed", str(e), time.time()
                print(f"install job error: {e}", flush=True)

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/servers/<int:server_id>/delete", methods=["POST"])
    @login_required
    @permission_required(UNINSTALL_SERVER)
    def uninstall_server(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        short_name = gs.short_name
        game_port = gs.port

        try:
            # Close ALL of this server's firewall rules (multi-port games tag every
            # rule with the server name), then also the legacy single-port cleanup.
            fw_note = ""
            try:
                count, _ = remote_ufw_close_by_name(remote, short_name)
                remote_ufw_close_game_port(remote, game_port)
                if count > 0:
                    fw_note = f" {count} firewall rule(s) removed."
            except Exception:
                pass

            # Remove LinuxGSM user and home
            out, err, rc = run_command(
                remote, f"userdel -r -f {short_name} 2>&1; echo 'DONE'", timeout=30, sudo=True
            )
            log_action(current_user, "uninstall_server", target=gs.name, success=(rc == 0))

            # Remove from DB
            db.session.delete(gs)
            db.session.commit()
            flash(f"Server '{gs.name}' uninstalled.{fw_note}", "success")

        except Exception as e:
            log_action(current_user, "uninstall_server", target=gs.name, detail=str(e), success=False)
            flash(f"Uninstall failed: {e}", "danger")

        return redirect(url_for("manage_servers"))

    @app.route("/servers/<int:server_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    def edit_server(server_id):
        gs = get_game(server_id)
        gs.name = request.form.get("name", gs.name)
        gs.port = _int_or(request.form.get("port"), gs.port)
        gs.game_display = request.form.get("game_display", gs.game_display)
        db.session.commit()
        flash(f"Server '{gs.name}' updated.", "success")
        return redirect(url_for("manage_servers"))

    # ── Remote Server Management ───────────────────────────
    @app.route("/remotes")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def manage_remotes():
        # Only actual remote VPSes — the panel's own host is managed under
        # System → Panel Server, not here. Non-superadmins only see remotes their
        # groups grant (consistent with the per-host access enforced in get_remote).
        remotes = RemoteServer.query.filter_by(is_local=False).order_by(RemoteServer.name).all()
        if not current_user.is_superadmin:
            allowed = accessible_remote_ids(current_user)
            remotes = [r for r in remotes if r.id in allowed]
        return render_template("manage_remotes.html", remotes=remotes,
                               tailscale_installed=ts.get_tailscale_info().installed)

    @app.route("/remotes/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def add_remote():
        name = request.form.get("name", "").strip()
        host = request.form.get("host", "").strip()
        ssh_user = request.form.get("ssh_user", "root").strip()
        ssh_port = _int_or(request.form.get("ssh_port"), 22)
        auth_method = request.form.get("auth_method", "key")
        credential = request.form.get("credential", "").strip()
        sudo_enabled = request.form.get("sudo_enabled") == "on"
        lgsm_user = request.form.get("lgsm_user", "").strip()
        is_local = request.form.get("is_local") == "1"

        if not name:
            flash("Name is required.", "danger")
            return redirect(url_for("manage_remotes"))

        # SECURITY: these reach `sudo -u <user>` / SSH command construction — validate
        # to a safe Linux-username charset so they can't inject shell commands.
        if lgsm_user and not LINUX_USER_RE.match(lgsm_user):
            flash("LinuxGSM user must be a valid Linux username (lowercase letters, numbers, - or _).", "danger")
            return redirect(url_for("manage_remotes"))
        if ssh_user and not LINUX_USER_RE.match(ssh_user):
            flash("SSH user must be a valid Linux username.", "danger")
            return redirect(url_for("manage_remotes"))

        if is_local:
            remote = RemoteServer(
                name=name, host="127.0.0.1", port=22,
                username="local", auth_method="local",
                auth_credential="", sudo_enabled=True,
                linuxgsm_user=lgsm_user,
                is_local=True, is_online=True,
                last_seen=datetime.utcnow(),
            )
            db.session.add(remote)
            db.session.commit()
            log_action(current_user, "add_local_remote", target=name)
            flash(f"Local server '{name}' added! You can now install game servers on this machine.", "success")
            return redirect(url_for("manage_remotes"))

        if not host:
            flash("Host is required.", "danger")
            return redirect(url_for("manage_remotes"))

        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential)
        if not success:
            flash(f"Connection test failed: {msg}", "danger")
            return redirect(url_for("manage_remotes"))

        remote = RemoteServer(
            name=name, host=host, port=ssh_port,
            username=ssh_user, auth_method=auth_method,
            auth_credential=encrypt_secret(credential),
            sudo_enabled=sudo_enabled, linuxgsm_user=lgsm_user,
            is_online=True, last_seen=datetime.utcnow(),
        )
        db.session.add(remote)
        db.session.commit()
        log_action(current_user, "add_remote", target=name, detail=f"{ssh_user}@{host}")

        # Auto-run the "Prepare & Secure" bootstrap unless opted out. Progress shows
        # inline on the remote's card and survives closing the page.
        auto_bootstrap = request.form.get("auto_bootstrap", "on") == "on"
        if auto_bootstrap:
            opts = {
                "set_timezone": request.form.get("timezone", "UTC") or "UTC",
                "enable_ufw": True, "install_lgsm_deps": True,
                "username": lgsm_user, "install_fail2ban": True, "do_reboot": True,
            }
            started, _ = _begin_bootstrap(remote.id, opts, current_user.id)
            flash(f"Remote '{name}' added. Preparing & securing it now — watch the progress on its card."
                  if started else f"Remote '{name}' added.", "success")
        else:
            flash(f"Remote '{name}' added successfully!", "success")
        return redirect(url_for("manage_remotes"))

    @app.route("/remotes/<int:remote_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def edit_remote(remote_id):
        remote = get_remote(remote_id)
        new_user = request.form.get("ssh_user", remote.username)
        new_lgsm = request.form.get("lgsm_user", remote.linuxgsm_user)
        # SECURITY: validate the username fields (reach `sudo -u <user>` / SSH commands).
        if new_user and not LINUX_USER_RE.match(new_user):
            flash("SSH user must be a valid Linux username.", "danger")
            return redirect(url_for("manage_remotes"))
        if new_lgsm and not LINUX_USER_RE.match(new_lgsm):
            flash("LinuxGSM user must be a valid Linux username.", "danger")
            return redirect(url_for("manage_remotes"))
        remote.name = request.form.get("name", remote.name)
        remote.host = request.form.get("host", remote.host)
        remote.port = _int_or(request.form.get("ssh_port"), remote.port)
        remote.username = new_user
        remote.auth_method = request.form.get("auth_method", remote.auth_method)
        # Credential: the edit form leaves it blank to keep the current one; a new
        # value is (re)encrypted before storage.
        new_cred = request.form.get("credential", "").strip()
        if new_cred:
            remote.auth_credential = encrypt_secret(new_cred)
        remote.sudo_enabled = request.form.get("sudo_enabled") == "on"
        remote.linuxgsm_user = new_lgsm
        db.session.commit()
        log_action(current_user, "edit_remote", target=remote.name)
        flash(f"Remote '{remote.name}' updated.", "success")
        return redirect(url_for("manage_remotes"))

    @app.route("/remotes/<int:remote_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def delete_remote(remote_id):
        remote = get_remote(remote_id)
        name = remote.name
        # Delete associated game servers
        GameServer.query.filter_by(remote_id=remote_id).delete()
        # Delete group associations
        group_servers_table = db.Table(
            "group_servers", db.metadata, autoload_with=db.engine
        )
        db.session.execute(
            group_servers_table.delete().where(
                group_servers_table.c.server_id == remote_id
            )
        )
        db.session.delete(remote)
        db.session.commit()
        close_connection(remote)
        log_action(current_user, "delete_remote", target=name)
        flash(f"Remote '{name}' deleted.", "success")
        return redirect(url_for("manage_remotes"))

    @app.route("/remotes/<int:remote_id>/test", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def test_remote(remote_id):
        remote = get_remote(remote_id)
        success, msg = ssh_test_connection(
            remote.host, remote.port, remote.username,
            remote.auth_method, decrypt_secret(remote.auth_credential)
        )
        if success:
            flash(f"Connection to {remote.name} successful!", "success")
            remote.is_online = True
        else:
            flash(f"Connection failed: {msg}", "danger")
            remote.is_online = False
        remote.last_seen = datetime.utcnow()
        db.session.commit()
        return redirect(url_for("manage_remotes"))

    # ── User Management ────────────────────────────────────
    @app.route("/users")
    @login_required
    @permission_required(MANAGE_USERS)
    def manage_users():
        users = User.query.all()
        groups = Group.query.all()
        return render_template("manage_users.html", users=users, groups=groups)

    @app.route("/users/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def add_user():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        display_name = request.form.get("display_name", username).strip()
        is_superadmin = request.form.get("is_superadmin") == "on"
        group_ids = request.form.getlist("groups")

        if not username or len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return redirect(url_for("manage_users"))
        pw_err = password_problem(password)
        if pw_err:
            flash(pw_err, "danger")
            return redirect(url_for("manage_users"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists.", "danger")
            return redirect(url_for("manage_users"))

        user = User(
            username=username,
            password_hash=hash_password(password),
            email=encrypt_secret(email) if email else None,
            display_name=display_name,
            is_superadmin=is_superadmin,
        )
        # Add to selected groups
        for gid in group_ids:
            group = Group.query.get(int(gid))
            if group:
                user.groups.append(group)

        db.session.add(user)
        db.session.commit()
        log_action(current_user, "add_user", target=username)
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("manage_users"))

    @app.route("/users/<int:user_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def edit_user(user_id):
        user = User.query.get_or_404(user_id)
        user.display_name = (request.form.get("display_name") or user.display_name or "").strip()
        _new_email = request.form.get("email", "").strip()
        user.email = encrypt_secret(_new_email) if _new_email else None
        user.is_active = request.form.get("is_active") == "on"
        user.is_superadmin = request.form.get("is_superadmin") == "on"

        # Update password if provided
        password = request.form.get("password", "")
        if password:
            pw_err = password_problem(password)
            if pw_err:
                flash(pw_err, "danger")
                return redirect(url_for("manage_users"))
            user.password_hash = hash_password(password)

        # Admin reset of a user's 2FA (for when they lose their authenticator).
        if request.form.get("reset_2fa") == "on" and user.totp_enabled:
            user.totp_enabled = False
            user.totp_secret = None
            log_action(current_user, "2fa_reset", target=user.username)

        # Update groups
        group_ids = {int(gid) for gid in request.form.getlist("groups")}
        user.groups = [Group.query.get(gid) for gid in group_ids if Group.query.get(gid)]

        db.session.commit()
        log_action(current_user, "edit_user", target=user.username)
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("manage_users"))

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        if user.is_superadmin and User.query.filter_by(is_superadmin=True).count() <= 1:
            flash("Cannot delete the last superadmin.", "danger")
            return redirect(url_for("manage_users"))
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_action(current_user, "delete_user", target=username)
        flash(f"User '{username}' deleted.", "success")
        return redirect(url_for("manage_users"))

    # ── Group Management ───────────────────────────────────
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

    def _selected_remotes(server_ids):
        """Resolve submitted remote ids to RemoteServer rows, skipping anything
        malformed or unknown. A group grants access per *remote* (host), which
        covers every game server on it — see auth.can_access_server."""
        out = []
        seen = set()
        for sid in server_ids:
            try:
                rid = int(sid)
            except (TypeError, ValueError):
                continue
            if rid in seen:
                continue
            rs = RemoteServer.query.get(rid)
            if rs:
                seen.add(rid)
                out.append(rs)
        return out

    @app.route("/groups/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def add_group():
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("Group name is required.", "danger")
            return redirect(url_for("manage_groups"))

        existing = Group.query.filter_by(name=name).first()
        if existing:
            flash(f"Group '{name}' already exists.", "danger")
            return redirect(url_for("manage_groups"))

        group = Group(name=name, description=description)
        group.set_permissions(request.form.getlist("permissions"))
        group.servers = _selected_remotes(request.form.getlist("servers"))

        db.session.add(group)
        db.session.commit()
        log_action(current_user, "add_group", target=name)
        flash(f"Group '{name}' created.", "success")
        return redirect(url_for("manage_groups"))

    @app.route("/groups/<int:group_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_GROUPS)
    def edit_group(group_id):
        group = Group.query.get_or_404(group_id)
        group.name = (request.form.get("name") or group.name or "").strip() or group.name
        group.description = (request.form.get("description") or group.description or "").strip()
        group.set_permissions(request.form.getlist("permissions"))
        group.servers = _selected_remotes(request.form.getlist("servers"))

        db.session.commit()
        log_action(current_user, "edit_group", target=group.name)
        flash(f"Group '{group.name}' updated.", "success")
        return redirect(url_for("manage_groups"))

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
        db.session.delete(group)
        db.session.commit()
        log_action(current_user, "delete_group", target=group.name)
        flash(f"Group '{group.name}' deleted.", "success")
        return redirect(url_for("manage_groups"))

    # ── Audit Logs ──────────────────────────────────────────
    @app.route("/logs")
    @login_required
    @permission_required(VIEW_LOGS)
    def view_logs():
        page = request.args.get("page", 1, type=int)
        per_page = 50
        logs = AuditLog.query.order_by(desc(AuditLog.timestamp)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        return render_template("logs.html", logs=logs)

    # ── Tailscale Integration ───────────────────────────────
    @app.route("/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def tailscale_page():
        """Tailscale status and management page."""
        info = ts.get_tailscale_info(force_refresh=request.args.get("refresh") == "1")
        cfg = load_config()
        suggestion = ts.suggest_best_bind(cfg.get("port", 5000))
        return render_template("tailscale.html", info=info, config=cfg, suggestion=suggestion)

    @app.route("/api/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale():
        """JSON endpoint with live Tailscale info."""
        info = ts.get_tailscale_info(force_refresh=True)
        cfg = load_config()
        suggestion = ts.suggest_best_bind(cfg.get("port", 5000))
        return jsonify({
            "installed": info.installed,
            "running": info.running,
            "version": info.version,
            "hostname": info.hostname,
            "dns_name": info.dns_name,
            "tailscale_ips": info.tailscale_ips,
            "magic_dns_enabled": info.magic_dns_enabled,
            "funnel_enabled": info.funnel_enabled,
            "peer_count": len(info.peers),
            "serve": info.serve_config,
            "suggestion": suggestion,
        })

    @app.route("/api/tailscale/serve", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)  # Infrastructure management
    def api_tailscale_serve():
        """Enable/disable Tailscale Serve for the panel."""
        data = request.get_json(silent=True) or {}
        action = data.get("action", "enable")
        mount = data.get("mount", "/")
        funnel = data.get("funnel", False)
        port = load_config().get("port", 5000)

        if action == "enable":
            success, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=funnel)
            if success:
                cfg = load_config()
                cfg["tailscale_setup_done"] = True
                cfg["tailscale_use_funnel"] = funnel
                cfg["tailscale_mount"] = mount
                save_config(cfg)
                log_action(current_user, "tailscale_serve_enable", detail=msg)
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "message": msg}), 500

        elif action == "disable":
            success, msg = ts.disable_tailscale_serve(mount=mount)
            if success:
                log_action(current_user, "tailscale_serve_disable", detail=msg)
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "message": msg}), 500

        return jsonify({"success": False, "message": f"Unknown action: {action}"}), 400

    @app.route("/api/tailscale/check-peer", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale_check_peer():
        """Check if a host is reachable on the tailnet."""
        data = request.get_json(silent=True) or {}
        host = data.get("host", "")
        if not host:
            return jsonify({"success": False, "message": "Host required"}), 400
        result = ts.check_peer_reachability(host)
        is_ts = ts.is_tailscale_ip(host)
        return jsonify({
            "success": True,
            "host": host,
            "reachable": result["reachable"],
            "latency_ms": result["latency_ms"],
            "is_tailscale_ip": is_ts,
        })

    # ── Server Management (local) ──────────────────────────
    @app.route("/server-management")
    @login_required
    @permission_required(SUPER_ADMIN)
    def server_management():
        """Panel host management. The panel host is just the local remote, so it uses
        the SAME template (and endpoints) as a remote server — only the panel-specific
        extras (self-update, its own Tailscale SSH controls) differ, keyed on is_local."""
        local = RemoteServer.query.filter_by(is_local=True).first()
        if local is None:
            # Fresh install that never added the panel host as a manageable server —
            # create it so the panel can manage itself with the unified UI.
            local = RemoteServer(
                name="Panel Server", host="127.0.0.1", port=22, username="local",
                auth_method="local", auth_credential="", sudo_enabled=True,
                linuxgsm_user="", is_local=True, is_online=True,
                last_seen=datetime.utcnow(),
            )
            db.session.add(local)
            db.session.commit()
        status = so.get_server_status()
        return render_template("remote_manage.html", remote=local, status=status)

    @app.route("/api/server-management")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_server_management():
        """JSON status for server management dashboard."""
        return jsonify(so.get_server_status())

    @app.route("/api/server-management/specs")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_server_management_specs():
        """Static hardware/OS specs for the panel host."""
        local = RemoteServer.query.filter_by(is_local=True).first()
        if local is None:
            # Panel host wasn't added as a manageable remote — gather specs anyway
            # via a lightweight local-only stand-in.
            local = SimpleNamespace(is_local=True, auth_method="local",
                                    sudo_enabled=False, linuxgsm_user="")
        return jsonify(host_specs(local))

    @app.route("/api/server-management/live")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_server_management_live():
        """Realtime per-core + overall CPU and RAM/swap for the live bar graphs."""
        return jsonify(so.live_metrics())

    @app.route("/api/server-management/ufw-allow-tailscale", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_ufw_allow_tailscale():
        """Allow traffic on the Tailscale interface via UFW."""
        success, msg = so.ufw_allow_tailscale()
        if success:
            log_action(current_user, "ufw_allow_tailscale", detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/ts-ssh-enable", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_ts_ssh_enable():
        """Enable Tailscale SSH."""
        success, msg = so.tailscale_ssh_enable()
        if success:
            log_action(current_user, "tailscale_ssh_enable", detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/ts-ssh-disable", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_ts_ssh_disable():
        """Disable Tailscale SSH."""
        success, msg = so.tailscale_ssh_disable()
        if success:
            log_action(current_user, "tailscale_ssh_disable", detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/panel/update-status")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_panel_update_status():
        """Is the LinuxGSM Panel itself behind its GitHub repo? (git-based check)"""
        force = request.args.get("force") in ("1", "true", "yes")
        try:
            return jsonify(so.panel_update_status(force=force))
        except Exception as e:
            return jsonify({"git": False, "update_available": False,
                            "current_version": so.panel_version(), "message": str(e)})

    @app.route("/api/panel/update", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_panel_update():
        """Pull the latest panel code and restart (one-click self-update)."""
        success, msg = so.panel_self_update()
        log_action(current_user, "panel_self_update", detail=msg, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/server-management/os-update-check")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_os_update_check():
        """Check for available OS updates."""
        result = so.os_update_available()
        return jsonify(result)

    @app.route("/api/server-management/os-update-run", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_os_update_run():
        """Run apt upgrade."""
        success, msg = so.os_run_update()
        if success:
            log_action(current_user, "os_update_run", detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/os-update-log")
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_os_update_log():
        """Get recent apt history."""
        return jsonify(so.os_update_log())

    @app.route("/api/server-management/reboot", methods=["POST"])
    @login_required
    @permission_required(SUPER_ADMIN)
    def api_server_reboot():
        """Reboot the server."""
        data = request.get_json(silent=True) or {}
        delay = data.get("delay", 5)
        success, msg = so.server_reboot(delay)
        if success:
            log_action(current_user, "server_reboot", detail=f"delay={delay}s")
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    # ── Remote VPS Management (port/OS) ────────────────────
    @app.route("/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_firewall(remote_id):
        """Remote VPS firewall management page."""
        remote = get_remote(remote_id)
        status = remote_ufw_status(remote)
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        return render_template("remote_firewall.html", remote=remote, status=status, games=games)

    @app.route("/api/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall(remote_id):
        remote = get_remote(remote_id)
        return jsonify(remote_ufw_status(remote))

    @app.route("/api/remote/<int:remote_id>/firewall/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_open(remote_id):
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_open_port(remote, int(port), proto, data.get("comment", ""))
        log_action(current_user, "remote_port_open", target=f"{remote.name}:{port}/{proto}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/close", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_close(remote_id):
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_close_port(remote, int(port), proto)
        log_action(current_user, "remote_port_close", target=f"{remote.name}:{port}/{proto}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/delete-rule", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_delete_rule(remote_id):
        """Delete a UFW rule by its number (the reliable way to remove any rule)."""
        remote = get_remote(remote_id)
        num = (request.get_json(silent=True) or {}).get("num")
        success, msg = remote_ufw_delete_rule(remote, num)
        log_action(current_user, "remote_ufw_delete_rule", target=f"{remote.name}:#{num}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/ssh-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_status(remote_id):
        remote = get_remote(remote_id)
        try:
            st = remote_public_ssh_status(remote)
            st["auth_method"] = remote.auth_method
            return jsonify(st)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/ssh-mode", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_mode(remote_id):
        """Set public SSH via UFW: allow / limit / off (tailnet-only)."""
        remote = get_remote(remote_id)
        mode = (request.get_json(silent=True) or {}).get("mode", "")
        success, msg = remote_set_public_ssh(remote, mode)
        log_action(current_user, "remote_ssh_mode", target=f"{remote.name}:{mode}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/game-port/<int:port>/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES, INSTALL_SERVER)
    def api_remote_game_port_open(remote_id, port):
        remote = get_remote(remote_id)
        gs = GameServer.query.filter_by(remote_id=remote_id, port=port).first()
        count, msg = remote_ufw_allow_game_port(remote, port, gs.short_name if gs else "Game")
        success = count >= 1
        log_action(current_user, "game_port_open", target=f"{remote.name}:{port}", success=success)
        return jsonify({"success": success, "message": msg, "rules_added": count})

    @app.route("/api/server/<int:server_id>/sync-ports", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_sync_ports(server_id):
        """Detect ALL of a game server's ports from LinuxGSM and open every one in the
        firewall (game/query/rcon/etc.). Also re-syncs the stored port. Fixes servers
        that were installed before multi-port support, or whose ports changed."""
        gs = get_game(server_id)
        if not (current_user.is_superadmin or has_permission(current_user, MANAGE_REMOTES)
                or has_permission(current_user, INSTALL_SERVER)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            info = detect_game_ports(gs.remote, gs.short_name, gs.lgsm_name)
            gp = info.get("game_port")
            if gp and gp != gs.port:
                gs.port = gp
                db.session.commit()
            to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
            opened, msg = remote_ufw_allow_game_ports(gs.remote, to_open, gs.short_name)
            log_action(current_user, "sync_ports", target=gs.name, detail=str(to_open), success=True)
            return jsonify({"success": True, "message": f"Ports {', '.join(map(str, to_open)) or '—'} opened.",
                            "ports": info.get("ports", []), "open_ports": to_open, "game_port": gp})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/live-stats")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_live_stats(remote_id):
        """Real-time CPU, RAM, disk, uptime from the remote VPS."""
        remote = get_remote(remote_id)
        try:
            return jsonify({"success": True, **remote_uptime(remote)})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/uptime")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_uptime(remote_id):
        remote = get_remote(remote_id)
        return jsonify(remote_uptime(remote))

    @app.route("/api/remote/<int:remote_id>/check-updates")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_check_updates(remote_id):
        remote = get_remote(remote_id)
        count = remote_os_check_updates(remote)
        return jsonify({"count": count})

    @app.route("/api/remote/<int:remote_id>/run-updates", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_run_updates(remote_id):
        remote = get_remote(remote_id)
        success, msg = remote_os_run_updates(remote)
        log_action(current_user, "remote_os_update", target=remote.name, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/reboot", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot(remote_id):
        remote = get_remote(remote_id)
        success, msg = remote_reboot(remote)
        log_action(current_user, "remote_reboot", target=remote.name)
        return jsonify({"success": success, "message": msg})

    @app.route("/remote/<int:remote_id>/manage")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_manage(remote_id):
        """Rich management page for a remote server — live per-core resources plus
        OS updates, reboot and firewall — the same experience as the Panel Server."""
        remote = get_remote(remote_id)
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        return render_template("remote_manage.html", remote=remote, games=games)

    @app.route("/api/remote/<int:remote_id>/specs")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_specs(remote_id):
        """Static hardware/OS specs for a remote host (loaded once, not polled)."""
        remote = get_remote(remote_id)
        return jsonify(host_specs(remote))

    # ── Ubuntu Pro (works for the panel host too, via its local remote id) ──
    @app.route("/api/remote/<int:remote_id>/pro-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_status(remote_id):
        return jsonify(pro_status(get_remote(remote_id)))

    @app.route("/api/remote/<int:remote_id>/pro-attach", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_attach(remote_id):
        remote = get_remote(remote_id)
        token = (request.get_json(silent=True) or {}).get("token", "")
        ok, msg = pro_attach(remote, token)
        # NOTE: the token is deliberately never logged.
        log_action(current_user, "pro_attach", target=remote.name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/pro-service", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_service(remote_id):
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        service = (data.get("service") or "").strip()
        action = (data.get("action") or "").strip()
        ok, msg = pro_service(remote, service, action)
        log_action(current_user, f"pro_{action or 'service'}", target=remote.name,
                   detail=service, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/pro-detach", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_detach(remote_id):
        remote = get_remote(remote_id)
        ok, msg = pro_detach(remote)
        log_action(current_user, "pro_detach", target=remote.name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/live")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_live(remote_id):
        """Realtime per-core + overall CPU and RAM/swap for a remote's live bars."""
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_live_metrics(remote))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Remote Tailscale Bootstrap Routes ──────────────────
    @app.route("/api/remote/<int:remote_id>/tailscale-check")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_check(remote_id):
        """Check if Tailscale is installed/running on the remote VPS."""
        remote = get_remote(remote_id)
        try:
            status = remote_check_tailscale(remote)
            return jsonify({"success": True, **status})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-up", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_up(remote_id):
        """Start `tailscale up` and return a browser login URL (no auth key needed)."""
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        try:
            ok, result = remote_tailscale_up_url(
                remote,
                enable_ssh=data.get("enable_ssh", True),
                advertise_routes=data.get("advertise_routes", "").strip(),
            )
            log_action(current_user, "remote_tailscale_up", target=remote.name, success=ok)
            if not ok:
                return jsonify({"success": False, "message": result}), 500
            if result == "ALREADY_CONNECTED":
                return jsonify({"success": True, "connected": True})
            return jsonify({"success": True, "connected": False, "url": result})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-finalize", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_finalize(remote_id):
        """After a node joins the tailnet, allow tailscale0 in UFW and report status."""
        remote = get_remote(remote_id)
        try:
            status, log = remote_tailscale_finalize(remote)
            return jsonify({
                "success": True, "running": status.get("running", False),
                "tailscale_ip": status.get("tailscale_ip", ""),
                "dns_name": status.get("dns_name", ""), "log": log,
            })
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-install", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_install(remote_id):
        """Install Tailscale on the remote VPS."""
        remote = get_remote(remote_id)
        try:
            success, msg, log = remote_install_tailscale(remote)
            log_action(current_user, "remote_tailscale_install", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg, "log": log})
        except Exception as e:
            return jsonify({"success": False, "message": str(e), "log": ""}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-bootstrap", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_bootstrap(remote_id):
        """Authenticate and configure Tailscale on the remote VPS.
        Requires a Tailscale pre-auth key.
        """
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        auth_key = data.get("auth_key", "").strip()
        enable_ssh = data.get("enable_ssh", True)
        advertise_routes = data.get("advertise_routes", "").strip()

        if not auth_key:
            return jsonify({"success": False, "message": "Auth key is required. Get one at https://login.tailscale.com/admin/keys"}), 400

        try:
            success, msg, log = remote_bootstrap_tailscale(
                remote, auth_key=auth_key,
                enable_ssh=enable_ssh,
                advertise_routes=advertise_routes,
            )
            log_action(current_user, "remote_tailscale_bootstrap", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg, "log": log})
        except Exception as e:
            return jsonify({"success": False, "message": str(e), "log": ""}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-migrate", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_migrate(remote_id):
        """After bootstrapping, migrate the RemoteServer record to use Tailscale SSH."""
        remote = get_remote(remote_id)
        try:
            new_host, status = remote_migrate_to_tailscale(remote)
            if not new_host:
                return jsonify({"success": False, "message": "Tailscale is not running on the remote"}), 400

            old_host = remote.host
            remote.host = new_host
            remote.auth_method = "tailscale"
            remote.auth_credential = ""
            remote.port = 22
            db.session.commit()
            close_connection(remote)

            log_action(current_user, "remote_tailscale_migrate",
                       target=remote.name,
                       detail=f"{old_host} -> {new_host} (Tailscale SSH)")
            return jsonify({
                "success": True,
                "message": f"Migrated to Tailscale SSH: {new_host}",
                "old_host": old_host,
                "new_host": new_host,
                "tailscale_ip": status.get("tailscale_ip", ""),
                "dns_name": status.get("dns_name", ""),
            })
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    # ── Close port 22 after Tailscale ───────────────────────
    @app.route("/api/remote/<int:remote_id>/close-port-22", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_close_port_22(remote_id):
        remote = get_remote(remote_id)
        try:
            success, msg = remote_ufw_close_port_22(remote)
            log_action(current_user, "remote_close_port_22", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    # ── Remote VPS Bootstrap Route (async, with live progress) ──
    @app.route("/api/remote/<int:remote_id>/bootstrap", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap(remote_id):
        """Kick off a fresh-VPS bootstrap in the background: updates, essential
        packages, UFW, SSH hardening, swap, fail2ban, LinuxGSM user, then reboot.
        Returns immediately; poll /bootstrap-status for live progress."""
        remote = get_remote(remote_id)
        data = request.get_json(silent=True) or {}
        opts = {
            "set_timezone": data.get("timezone", "UTC"),
            "enable_ufw": data.get("enable_ufw", True),
            "install_lgsm_deps": data.get("install_lgsm_deps", True),
            "username": data.get("lgsm_user", ""),
            "install_fail2ban": data.get("install_fail2ban", True),
            "do_reboot": data.get("reboot", True),
        }
        started, msg = _begin_bootstrap(remote_id, opts, current_user.id)
        if not started:
            return jsonify({"success": False, "message": msg}), 409
        return jsonify({"success": True, "started": True})

    @app.route("/api/remote/<int:remote_id>/bootstrap-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap_status(remote_id):
        """Live status of an in-progress (or just-finished) bootstrap job."""
        with _bootstrap_lock:
            job = _bootstrap_jobs.get(remote_id)
            if not job:
                return jsonify({"status": "none"})
            # Auto-expire a finished job after a while so the completed/failed card
            # doesn't linger (or re-trigger) forever across page visits.
            if job["status"] in ("done", "failed") and (time.time() - job.get("updated", job["started"])) > 900:
                _bootstrap_jobs.pop(remote_id, None)
                return jsonify({"status": "none"})
            pct = int(job["step"] / job["total"] * 100) if job.get("total") else 0
            return jsonify({
                "status": job["status"],
                "step": job["step"],
                "total": job["total"],
                "percent": pct,
                "step_name": job["step_name"],
                "message": job.get("message", ""),
                "log": job["log"][-200:],
                "elapsed": int(time.time() - job["started"]),
            })

    @app.route("/api/remote/<int:remote_id>/bootstrap-dismiss", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap_dismiss(remote_id):
        """Clear a finished (done/failed) bootstrap job so its card goes away."""
        with _bootstrap_lock:
            job = _bootstrap_jobs.get(remote_id)
            if job and job["status"] in ("done", "failed"):
                _bootstrap_jobs.pop(remote_id, None)
        return jsonify({"success": True})

    def _start_bootstrap_job(remote_id, opts, actor_id):
        """Run remote_bootstrap_vps in a background (green) thread, streaming
        progress into the _bootstrap_jobs registry for the status endpoint."""
        _app = app

        def _progress(step, total, name, status):
            with _bootstrap_lock:
                job = _bootstrap_jobs.get(remote_id)
                if job is None:
                    return
                job["step"] = step
                job["total"] = total
                job["step_name"] = name
                job["updated"] = time.time()
                if status in ("running", "rebooting", "done"):
                    # keep top-level status "running" until finally done/failed
                    job["status"] = "rebooting" if status == "rebooting" else job["status"]
                job["log"].append(f"[{step}/{total}] {name}" if total else name)

        def _run():
            try:
                with _app.app_context():
                    remote = RemoteServer.query.get(remote_id)
                    if not remote:
                        raise RuntimeError("Remote no longer exists")
                    success, msg, log = remote_bootstrap_vps(remote, progress=_progress, **opts)
                    if success:
                        remote.is_online = True
                        remote.last_seen = datetime.utcnow()
                        db.session.commit()
                    from auth import log_action as _log
                    _log(None, "remote_vps_bootstrap", target=remote.name, detail=msg, success=success)
                    with _bootstrap_lock:
                        job = _bootstrap_jobs.get(remote_id)
                        if job is not None:
                            job["status"] = "done" if success else "failed"
                            job["step_name"] = "Complete" if success else "Failed"
                            job["message"] = msg
                            job["updated"] = time.time()
            except Exception as e:
                with _bootstrap_lock:
                    job = _bootstrap_jobs.get(remote_id)
                    if job is not None:
                        job["status"] = "failed"
                        job["message"] = str(e)
                        job["log"].append(f"ERROR: {e}")
                        job["updated"] = time.time()

        threading.Thread(target=_run, daemon=True).start()

    def _begin_bootstrap(remote_id, opts, actor_id):
        """Seed the job registry and start the background bootstrap. Returns
        (started, message). Refuses if one is already running for this remote."""
        with _bootstrap_lock:
            existing = _bootstrap_jobs.get(remote_id)
            if existing and existing.get("status") in ("running", "rebooting"):
                return False, "A bootstrap is already running for this server."
            _bootstrap_jobs[remote_id] = {
                "status": "running", "step": 0, "total": 0,
                "step_name": "Starting…", "log": [], "message": "",
                "started": time.time(), "updated": time.time(),
            }
        _start_bootstrap_job(remote_id, opts, actor_id)
        return True, "Bootstrap started."

    # ── API Routes ──────────────────────────────────────────
    @app.route("/api/servers")
    @login_required
    def api_servers():
        servers = get_user_servers(current_user)
        # Refresh live status efficiently: one listening-port scan per remote,
        # then match each game server's port (instead of an SSH call per server).
        by_remote = {}
        for gs in servers:
            if gs.remote_id:
                by_remote.setdefault(gs.remote_id, []).append(gs)
        changed = False
        for gslist in by_remote.values():
            remote = gslist[0].remote
            try:
                out, _, _ = run_command(remote, "ss -H -lntu 2>/dev/null | awk '{print $5}'", timeout=8, sudo=True)
                ports = set()
                for addr in (out or "").split():
                    if ":" in addr:
                        p = addr.rsplit(":", 1)[1]
                        if p.isdigit():
                            ports.add(int(p))
                for gs in gslist:
                    st = "online" if gs.port in ports else "offline"
                    if gs.status != st:
                        gs.status = st
                        changed = True
                # Resolve+cache the remote's public IP once for the connect address.
                if not remote.public_ip:
                    try:
                        ip = remote_public_ip(remote)
                        if ip:
                            remote.public_ip = ip
                            changed = True
                    except Exception:
                        pass
            except Exception:
                pass
        if changed:
            db.session.commit()

        data = []
        for gs in servers:
            r = gs.remote
            host = (r.public_ip if r else "") or (r.host if (r and not r.is_local) else "")
            data.append({
                "id": gs.id,
                "name": gs.name,
                "short_name": gs.short_name,
                "game_type": gs.game_type,
                "port": gs.port,
                "status": gs.status,
                "installed": gs.installed,
                "remote_name": r.name if r else "",
                "connect": f"{host}:{gs.port}" if host else "",
            })
        return jsonify(data)

    @app.route("/api/server/<int:server_id>")
    @login_required
    @server_access_required
    def api_server_status(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        try:
            status = get_server_status(remote, gs)
            gs.status = status
            db.session.commit()
        except Exception as e:
            status = "error"

        # Try to get player counts
        player_count = 0
        max_players = 0
        try:
            out, err, rc = run_command(
                remote,
                f"cat {gs.console_log} 2>/dev/null "
                f"| grep -c 'ClientConnect\\|Player connected' || echo '0'",
                timeout=10
            )
            # Simple player count heuristic
            for line in reversed(out.split("\n") if out else []):
                if "players" in line.lower() and "has" in line.lower():
                    m = re.search(r'(\d+)\s+of\s+(\d+)', line)
                    if m:
                        player_count = int(m.group(1))
                        max_players = int(m.group(2))
                        break
        except Exception:
            pass

        return jsonify({
            "id": gs.id,
            "name": gs.name,
            "short_name": gs.short_name,
            "game_type": gs.game_type,
            "port": gs.port,
            "status": status,
            "installed": gs.installed,
            "player_count": player_count,
            "max_players": max_players,
            "remote": gs.remote.name if gs.remote else "",
        })

    @app.route("/api/server/<int:server_id>/stats")
    @login_required
    @server_access_required
    def api_server_stats(server_id):
        """Fast live metrics for polling: VPS CPU/RAM/disk/uptime + the game's RAM
        and a port-based online check + the public connect address."""
        gs = get_game(server_id)
        remote = gs.remote
        try:
            m = server_live_metrics(remote, gs.short_name, gs.port)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        status = "online" if (m.get("port_open") or m.get("game_procs")) else "offline"
        changed = False
        if gs.status != status:
            gs.status = status
            changed = True
        # Resolve + cache the remote's public IP once (for the connect address).
        if not remote.public_ip:
            try:
                ip = remote_public_ip(remote)
                if ip:
                    remote.public_ip = ip
                    changed = True
            except Exception:
                pass
        if changed:
            db.session.commit()

        host = remote.public_ip or (remote.host if not remote.is_local else "")
        return jsonify({
            "status": status,
            "connect": f"{host}:{gs.port}" if host else f":{gs.port}",
            "public_ip": remote.public_ip,
            "port": gs.port,
            "metrics": m,
        })

    @app.route("/api/server/<int:server_id>/install-status")
    @login_required
    @server_access_required
    def api_server_install_status(server_id):
        """Live step-by-step progress of a game-server install (mirrors bootstrap)."""
        with _install_lock:
            j = _install_jobs.get(server_id)
            if not j:
                return jsonify({"status": "none"})
            if j["status"] in ("done", "failed") and (time.time() - j.get("updated", j["started"])) > 900:
                _install_jobs.pop(server_id, None)
                return jsonify({"status": "none"})
            pct = int(j["step"] / j["total"] * 100) if j.get("total") else 0
            return jsonify({
                "status": j["status"], "step": j["step"], "total": j["total"], "percent": pct,
                "step_name": j["step_name"], "message": j.get("message", ""),
                "log": j["log"][-100:], "elapsed": int(time.time() - j["started"]),
            })

    @app.route("/api/server/<int:server_id>/install-dismiss", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_install_dismiss(server_id):
        """Clear a finished install job so its progress card goes away."""
        with _install_lock:
            j = _install_jobs.get(server_id)
            if j and j["status"] in ("done", "failed"):
                _install_jobs.pop(server_id, None)
        return jsonify({"success": True})

    # ── Config editor + file browser (per game server) ─────────
    def _can_manage_files():
        return current_user.is_superadmin or has_permission(current_user, MANAGE_SERVERS)

    @app.route("/server/<int:server_id>/files")
    @login_required
    @server_access_required
    def server_files(server_id):
        """Config editor + live file browser for a game server."""
        gs = get_game(server_id)
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        return render_template("server_files.html", server=gs, remote=gs.remote)

    @app.route("/api/server/<int:server_id>/config", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_config(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                return jsonify(lgsm_read_config(gs.remote, gs.short_name, gs.lgsm_name))
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        data = request.get_json(silent=True) or {}
        try:
            if data.get("raw") is not None:
                rel = f"lgsm/config-lgsm/{gs.lgsm_name}/{gs.lgsm_name}.cfg"
                ok, msg = write_file(gs.remote, gs.short_name, rel, data["raw"])
            else:
                ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, data.get("settings") or {})
            log_action(current_user, "edit_config", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/server/<int:server_id>/game-config")
    @login_required
    @server_access_required
    def api_server_game_config(server_id):
        """The game's own server config file (detected via LinuxGSM details)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            return jsonify(lgsm_game_config(gs.remote, gs.short_name, gs.lgsm_name))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/server/<int:server_id>/browse")
    @login_required
    @server_access_required
    def api_server_browse(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            result = browse_dir(gs.remote, gs.short_name, request.args.get("path", ""), gs.lgsm_name)
            if result is None:
                return jsonify({"error": "Invalid path"}), 400
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/server/<int:server_id>/file", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_file(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            content, err = read_file(gs.remote, gs.short_name, request.args.get("path", ""))
            if err:
                return jsonify({"error": err}), 400
            return jsonify({"content": content, "path": request.args.get("path", "")})
        data = request.get_json(silent=True) or {}
        rel = data.get("path", "")
        try:
            ok, msg = write_file(gs.remote, gs.short_name, rel, data.get("content", ""))
            log_action(current_user, "edit_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/server/<int:server_id>/delete-path", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_delete_path(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        rel = (request.get_json(silent=True) or {}).get("path", "")
        try:
            ok, msg = delete_path(gs.remote, gs.short_name, rel, gs.lgsm_name)
            log_action(current_user, "delete_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/server/<int:server_id>/upload", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_upload(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        reldir = request.form.get("path", "")
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify({"success": False, "message": "No file provided"}), 400
        data = f.read()
        if len(data) > 50 * 1024 * 1024:
            return jsonify({"success": False, "message": "File too large (max 50 MB)"}), 400
        try:
            ok, msg = upload_file(gs.remote, gs.short_name, reldir, f.filename, data)
            log_action(current_user, "upload_file", target=gs.name, detail=f"{reldir}/{f.filename}", success=ok)
            return jsonify({"success": ok, "message": msg or ("Uploaded" if ok else "Failed"), "name": f.filename})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/console/<int:server_id>")
    @login_required
    @server_access_required
    def api_console(server_id):
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, VIEW_CONSOLE):
            return jsonify({"error": "Permission denied", "lines": []}), 403
        remote = gs.remote
        try:
            log_path = gs.console_log
            out, err, rc = run_command(remote, f"tail -100 {log_path} 2>/dev/null", timeout=15)
            lines = out.split("\n") if rc == 0 else []
        except Exception:
            lines = []
        return jsonify({"lines": lines})

    @app.route("/api/command/<int:server_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_send_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        data = request.get_json(silent=True) or {}
        cmd_text = data.get("command", "").strip()

        if not cmd_text:
            return jsonify({"error": "No command provided"}), 400

        if not current_user.is_superadmin and not has_permission(current_user, SEND_COMMAND):
            return jsonify({"error": "Permission denied"}), 403

        try:
            out, err, rc = send_console_command(remote, gs.short_name, cmd_text, timeout=10, selfname=gs.lgsm_name)
            log_action(current_user, "send_command", target=gs.name, detail=cmd_text, success=(rc == 0))
            if rc != 0:
                return jsonify({"error": "Console (tmux) not accessible. Is the server running?"}), 502
            return jsonify({"success": True, "command": cmd_text})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── WebSocket Console ───────────────────────────────────
    def _socketio_cors():
        """Origins allowed to open the console WebSocket. Explicit config wins; else,
        once the panel has a domain (served via Tailscale Serve/nginx), lock to that
        origin instead of "*". Falls back to "*" only for plain IP:port access, where
        there's no fixed origin to pin to. (join_console also requires an authenticated
        session, and the SameSite=Lax cookie stops a cross-site page carrying it.)"""
        cfg = load_config()
        explicit = cfg.get("socketio_cors_origins")
        if explicit:
            return explicit
        dom = (cfg.get("site_domain") or "").strip()
        if dom:
            return ["https://%s" % dom, "http://%s" % dom]
        return "*"

    socketio = SocketIO(app, cors_allowed_origins=_socketio_cors(), async_mode="eventlet")

    # Track which sockets are viewing which server console, so the poller only
    # polls consoles that someone is actually watching (idle = ~0% CPU).
    _console_viewers = {}  # server_id -> set of socket session ids
    _viewers_lock = threading.Lock()

    @socketio.on("join_console")
    def on_join_console(data):
        server_id = data.get("server_id")
        if not server_id:
            return
        # Enforce the SAME access control as the HTTP console routes: the socket must
        # belong to a logged-in user who has access to this specific server AND holds
        # VIEW_CONSOLE. Without this, any socket could stream any server's console.
        if (not current_user.is_authenticated
                or not can_access_server(current_user, server_id)
                or not (current_user.is_superadmin or has_permission(current_user, VIEW_CONSOLE))):
            emit("console_output", {"server_id": server_id,
                                    "data": "[access denied — you don't have permission to view this console]"})
            return
        join_room(f"console_{server_id}")
        with _viewers_lock:
            _console_viewers.setdefault(server_id, set()).add(request.sid)

    @socketio.on("leave_console")
    def on_leave_console(data):
        server_id = data.get("server_id")
        if server_id:
            leave_room(f"console_{server_id}")
            with _viewers_lock:
                if server_id in _console_viewers:
                    _console_viewers[server_id].discard(request.sid)
                    if not _console_viewers[server_id]:
                        del _console_viewers[server_id]

    @socketio.on("disconnect")
    def on_console_disconnect():
        # A browser that closed without leave_console must still stop the poller.
        with _viewers_lock:
            for sid_set in list(_console_viewers.values()):
                sid_set.discard(request.sid)
            for k in [k for k, v in _console_viewers.items() if not v]:
                del _console_viewers[k]

    # Console polling thread — streams new console output to WebSocket viewers.
    def console_poller():
        last_positions = {}
        while True:
            try:
                with _viewers_lock:
                    active_ids = list(_console_viewers.keys())
                if active_ids:
                    with app.app_context():
                        for server_id in active_ids:
                            gs = GameServer.query.get(server_id)
                            if not gs or not gs.remote:
                                continue
                            remote = gs.remote
                            try:
                                log_path = gs.console_log
                                size_out, _, _ = run_command(
                                    remote, f"stat -c%s {log_path} 2>/dev/null || echo 0", timeout=5
                                )
                                try:
                                    current_size = int(size_out.strip())
                                except ValueError:
                                    continue
                                last_pos = last_positions.get(server_id, 0)
                                if current_size < last_pos:  # log rotated/truncated
                                    last_pos = 0
                                if current_size > last_pos:
                                    if last_pos == 0:
                                        last_positions[server_id] = current_size
                                        continue
                                    diff = min(current_size - last_pos, 65536)  # cap 64KB/poll
                                    # tail -c +N | head -c diff: two reads, not one-per-byte.
                                    out, _, _ = run_command(
                                        remote,
                                        f"tail -c +{last_pos + 1} {log_path} 2>/dev/null | head -c {diff}",
                                        timeout=5,
                                    )
                                    if out:
                                        socketio.emit("console_output",
                                                      {"server_id": server_id, "data": out},
                                                      room=f"console_{server_id}")
                                    last_positions[server_id] = current_size
                            except Exception:
                                pass
            except Exception:
                pass
            time.sleep(2)

    # Start the console poller thread
    poller_thread = threading.Thread(target=console_poller, daemon=True)
    poller_thread.start()

    # Make socketio accessible from app
    app.socketio = socketio
    return app


# ─── Main Entry Point ──────────────────────────────────────────

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="eventlet")
    app = create_app()
    cfg = load_config()
    port = cfg.get("port", 5000)
    host = (cfg.get("bind_host") or "").strip()
    if not host:
        # Not explicitly configured: bind where the panel is actually reachable —
        # 127.0.0.1 if Tailscale Serve is up to proxy to it, otherwise 0.0.0.0 so the
        # first-run setup wizard is reachable over the network on a plain VPS.
        try:
            host = ts.suggest_best_bind(port).get("bind_host") or "0.0.0.0"
        except Exception:
            host = "0.0.0.0"
    print(f"LinuxGSM Panel starting on {host}:{port}")
    print(f"Open http://{host}:{port} in your browser")

    # Show Tailscale URL if available
    try:
        ts_info = ts.get_tailscale_info()
        if ts_info.dns_name:
            print(f"\n  🌐 Tailscale: https://{ts_info.dns_name}")
            if ts_info.funnel_enabled:
                print(f"  🌍 Funnel (public): https://{ts_info.dns_name}")
        elif ts_info.tailscale_ips:
            print(f"\n  🌐 Tailscale IP: http://{ts_info.tailscale_ips[0]}:{port}")
    except Exception:
        pass

    app.socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
