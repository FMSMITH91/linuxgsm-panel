"""Authentication and permission management."""
import hmac
import re
import secrets
import threading
import time
from panel.core.clock import utcnow
from functools import wraps
from urllib.parse import quote

import base64
import bcrypt
import hashlib
from flask import abort, current_app, flash, jsonify, redirect, request, url_for
from flask_login import LoginManager, current_user

from panel.db.models import AuditLog, GameServer, RemoteServer, User, db

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."


# ─── Permission constants ─────────────────────────────────────
VIEW_SERVERS = "view_servers"
VIEW_CONSOLE = "view_console"
SEND_COMMAND = "send_command"
MODERATE_SERVER = "moderate_server"     # Umbrella: kick + ban + announce (grants all three below)
KICK_PLAYER = "kick_player"             # Kick players from the server
BAN_PLAYER = "ban_player"               # Ban players from the server
SAY_SERVER = "say_server"               # Announce a message in-game
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
SUPER_ADMIN = "super_admin"   # NOT grantable: superadmin is User.is_superadmin, the flag.
                              # Kept only so an old stored group permission can be recognised
                              # and stripped; see strip_legacy_superadmin_grants().

ALL_PERMISSIONS = {
    VIEW_SERVERS: "View server status list",
    VIEW_CONSOLE: "View live console output",
    SEND_COMMAND: "Send commands to game server console",
    MODERATE_SERVER: "Moderate players — all of kick, ban & announce",
    KICK_PLAYER: "Kick players from a server",
    BAN_PLAYER: "Ban players from a server",
    SAY_SERVER: "Announce a message in-game",
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
}

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

# bcrypt takes at most 72 BYTES and ignores the rest. That is not a policy we chose and not one a
# person can see: it is a property of the algorithm. Left alone it produced two bad outcomes here.
#
#   * Setting a longer password 500'd. password_problem() has a minimum and no maximum, so a
#     104-character password passed every strength rule and then bcrypt 5.0 raised ValueError out
#     of hash_password, uncaught.
#   * Anyone who set one while bcrypt 4.x was installed is locked out NOW. 4.x truncated silently,
#     so the stored hash is of the first 72 bytes; 5.0 raises instead, check_password catches it
#     and returns False, and a correct password reads as "wrong password" with nothing to explain
#     it. requirements.txt asked for >=4.1 before it pinned 5.0.0, so that window was real.
#
# Hashing the password with SHA-256 first makes bcrypt's input a fixed 44 bytes whatever the
# password is, so length stops being a limit at all — the only bound left is the request body,
# which MAX_CONTENT_LENGTH already caps. base64, not raw digest: a raw digest can contain a NUL,
# and bcrypt stops at one.
_SHA256_PREFIX = "sha256$"


def _prehash(password):
    """SHA-256 of the password, base64'd — a fixed 44 bytes for bcrypt, whatever came in.

    CodeQL flags this as py/weak-sensitive-data-hashing and it is a false positive: SHA-256 is not
    the password hash here, it is a LENGTH NORMALISER. Its output has exactly two consumers,
    bcrypt.hashpw and bcrypt.checkpw below — it is never stored, compared or returned — so the
    credential at rest is bcrypt(sha256(pw)), salted, at cost 12. That is the standard bcrypt
    pre-hash (Django and passlib's bcrypt_sha256 do the same thing for the same reason). The query
    sees sha256(password) and stops before the bcrypt call.

    Alert 441 is dismissed on that basis. Dismissals are keyed to the path, so if this function
    ever moves the alert reopens at the new location — re-read this note, and the two call sites,
    before dismissing it again."""
    return base64.b64encode(hashlib.sha256((password or "").encode("utf-8")).digest())


def hash_password(password):
    """Hash a password of ANY length. Stored as `sha256$<bcrypt>` so check_password can tell the
    two schemes apart — a bare `$2b$...` row is a legacy hash of the raw password."""
    return _SHA256_PREFIX + bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode()


def check_password(password, password_hash):
    """Verify a password against either hash format. Returns False (never raises) if the stored
    hash is missing or malformed, so a bad DB row can't 500 the login."""
    stored = (password_hash or "").strip()
    if not stored:
        return False
    try:
        if stored.startswith(_SHA256_PREFIX):
            return bcrypt.checkpw(_prehash(password), stored[len(_SHA256_PREFIX):].encode())
        # Legacy: bcrypt over the raw password.
        raw = (password or "").encode("utf-8")
        if len(raw) <= 72:
            return bcrypt.checkpw(raw, stored.encode())
        # Over 72 bytes against a legacy hash: whatever wrote it truncated to 72 (that is what
        # bcrypt 4.x did), so compare the same 72 bytes rather than refusing. This is the line
        # that lets an account stranded by the 4.x -> 5.0 upgrade sign in again — and it accepts
        # nothing a 4.x panel would not have accepted from the same person.
        return bcrypt.checkpw(raw[:72], stored.encode())
    except (ValueError, TypeError):
        return False


def needs_rehash(password_hash):
    """True if the stored hash is the legacy format, so a caller can quietly upgrade it after a
    successful sign-in. The password is unchanged, so this is a re-encoding, not a reset."""
    return not (password_hash or "").startswith(_SHA256_PREFIX)


# A bcrypt hash of a random throwaway value. Comparing against it when a login's
# username doesn't exist (or is inactive) makes that path spend the same time as a
# real password check — bcrypt is deliberately slow, so skipping it would otherwise
# leak, by timing, whether an account exists (username enumeration).
#
# Computed LAZILY (a single bcrypt hash is ~400ms) so it doesn't add that to every panel
# start/restart. init_auth() pre-warms it in the background, so it's ready before the first
# login without either delaying startup or making that first login abnormally slow.
_DUMMY_BCRYPT_HASH = None


def _dummy_hash():
    global _DUMMY_BCRYPT_HASH
    if _DUMMY_BCRYPT_HASH is None:
        # hash_password, not a bare bcrypt call: the timing this exists to equalise must be the
        # timing of the REAL path, prehash included.
        _DUMMY_BCRYPT_HASH = hash_password(secrets.token_hex(16))
    return _DUMMY_BCRYPT_HASH


def dummy_password_check(password):
    """Run a throwaway bcrypt compare to equalize login timing for a nonexistent or
    inactive user. Always returns False."""
    check_password(password, _dummy_hash())
    return False


# Unambiguous alphabet (no 0/O/1/l/I) so hand-typed backup codes don't get confused.
_BACKUP_CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"


def generate_backup_codes(n=8, length=10):
    """Generate `n` human-friendly one-time 2FA backup codes, formatted xxxxx-xxxxx.
    Returned in plaintext ONCE — only their bcrypt hashes are stored (User.set_backup_codes)."""
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(_BACKUP_CODE_ALPHABET) for _ in range(length))
        codes.append(raw[:length // 2] + "-" + raw[length // 2:])
    return codes


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


def verify_totp_step(secret, code):
    """The TOTP timestep `code` matches for `secret` (this step, or one either side for clock
    skew) — or None if it matches none of them.

    verify_totp() answers only yes/no, which is not enough to stop a replay: the same code stays
    valid for ~90 seconds, so a code observed once (a phishing proxy, a shoulder-surf, a leaked
    log) works again for the rest of its window. Returning WHICH step matched gives the caller
    something to record, so it can refuse a step it has already accepted.

    compare_digest rather than ==: the comparison is against a freshly derived code, so a timing
    difference here leaks digits of a code that is still live."""
    import pyotp
    entered = str(code or "").strip().replace(" ", "")
    if not secret or not entered:
        return None
    try:
        totp = pyotp.TOTP(secret)
        now = int(time.time())
        for delta in (0, -1, 1):
            t = now + delta * totp.interval
            if hmac.compare_digest(str(totp.at(t)), entered):
                return t // totp.interval
    except Exception:
        return None
    return None


def get_user_permissions(user):
    """Get all permissions for a user (union of all their groups + superadmin)."""
    if user.is_superadmin:
        return set(ALL_PERMISSIONS.keys())

    perms = set()
    for group in user.groups or []:
        perms.update(group.get_permissions())
    return perms


def _groups_with_grants(user, commands=False):
    """This user's groups, with their host and game-server grants ALREADY LOADED.

    Group.servers and Group.game_servers are lazy relationships, so walking `user.groups` and
    touching them fires one query PER GROUP — two, here, one for each collection. That is an N+1
    on a dimension nothing was watching: tools/perf_bench.py sweeps SERVERS and holds groups at
    five, so the cost stayed invisible while /api/dashboard/metrics — which the dashboard POLLS —
    went from 9 queries for a user in 2 groups to 125 for a user in 60.

    Same fix, and the same reasoning, as the joinedload/selectinload already on get_user_servers'
    own query below: eager-load the collections so the count is flat. This changes only HOW the
    rows are fetched, never WHICH — the caller's logic is untouched, which matters because these
    two functions decide access.
    """
    from flask import has_app_context
    if not has_app_context():
        # No app context means no session to query with — a unit test holding a plain User, or a
        # worker outside one. `user.groups` is whatever the object already carries, which is
        # exactly what this function read before it started issuing a query, so the callers see
        # what they always saw. Missing this cost a CI cycle: the unit suite crashed on import at
        # the first can_access_remote() against an in-memory User.
        return list(user.groups or [])
    from panel.db.models import Group, user_groups
    from sqlalchemy.orm import selectinload
    # Memoised for the life of the app context. Both properties are needed and they pull opposite
    # ways: eager-loading kills the per-GROUP N+1, but re-running the query on every call
    # reintroduces the cost per CALL — and these helpers are called in loops (allowed_custom_commands
    # per command, the bulk action and the global-ban port per server). `user.groups` used to get
    # this for free, because a lazy relationship caches on the instance once loaded; that is the
    # property being preserved here, not a new trick.
    #
    # No staleness beyond what the session already has: a re-query inside the same session returns
    # the same identity-mapped rows. Scoped to the app context, so a background sweep that opens
    # its own gets its own, and nothing survives the request.
    _cache_key = ("_gwg", getattr(user, "id", None), bool(commands))
    _cache = None
    try:
        from flask import g as _flask_g
        _cache = _flask_g.__dict__.setdefault("_groups_with_grants_cache", {})
        if _cache_key in _cache:
            return _cache[_cache_key]
    except (RuntimeError, AttributeError):
        _cache = None          # outside an app context (a CLI or a worker) — just query
    opts = [selectinload(Group.servers), selectinload(Group.game_servers)]
    if commands:
        # Only the custom-command callers ask for this. Left out by default because the dashboard
        # poll goes through here and does not read it — one wasted query per request, every few
        # seconds, for a collection nobody looks at.
        opts.append(selectinload(Group.custom_commands))
    rows = (Group.query.join(user_groups, user_groups.c.group_id == Group.id)
            .filter(user_groups.c.user_id == user.id)
            .options(*opts).all())
    if _cache is not None:
        _cache[_cache_key] = rows
    return rows


def get_user_servers(user):
    """Get game servers a user has access to (superadmin = all)."""
    from panel.db.models import GameServer
    from sqlalchemy.orm import joinedload, selectinload
    # Eager-load each server's remote in the SAME query. Callers (dashboard, /api/servers) all
    # read gs.remote per server; without this, accessing it lazily fires one query per remote
    # (e.g. 50 extra queries at 50 hosts on every status poll).
    # Tags likewise: they render per row, so lazily they cost one query per server. selectinload
    # (not joinedload) because it is a many-to-many — one extra query total, no row multiplication.
    q = GameServer.query.options(joinedload(GameServer.remote),
                                 selectinload(GameServer.tags))
    if user.is_superadmin:
        return q.all()

    from sqlalchemy import or_
    remote_ids = set()   # whole-host grants (group.servers)
    game_ids = set()     # individual game-server grants (group.game_servers)
    for group in _groups_with_grants(user):
        for s in group.servers or []:
            remote_ids.add(s.id)
        for g in group.game_servers or []:
            game_ids.add(g.id)

    if not remote_ids and not game_ids:
        return []
    # A game server is visible if its host is granted OR the server itself is granted.
    return q.filter(or_(GameServer.remote_id.in_(list(remote_ids)),
                        GameServer.id.in_(list(game_ids)))).all()


def has_permission(user, perm):
    """Check if user has a specific permission."""
    if user.is_superadmin:
        return True
    return perm in get_user_permissions(user)


def can_access_server(user, game_server_id):
    """Check if user can access a specific game server. Access is granted either at the HOST
    level (the server's remote is in one of the user's groups) or at the individual GAME-SERVER
    level (the server itself is assigned to one of the user's groups). Superadmin = all."""
    if user.is_superadmin:
        return True
    from panel.db.models import GameServer
    gs = db.session.get(GameServer, game_server_id)
    if not gs:
        return False
    for group in _groups_with_grants(user):
        for rs in group.servers or []:          # whole-host grant
            if rs.id == gs.remote_id:
                return True
        for g in group.game_servers or []:      # individual game-server grant
            if g.id == gs.id:
                return True
    return False


_MODERATION_PERM = {"kick": KICK_PLAYER, "ban": BAN_PLAYER, "say": SAY_SERVER}


def can_moderate_action(user, action):
    """Whether `user` may perform a moderation `action` ('kick' | 'ban' | 'say'). Full console
    access (SEND_COMMAND) or the umbrella MODERATE_SERVER grant every action; otherwise the
    matching granular permission (kick_player / ban_player / say_server) is required. This does
    NOT check server access — pair it with can_access_server / @server_access_required."""
    if user.is_superadmin:
        return True
    perms = get_user_permissions(user)
    if SEND_COMMAND in perms or MODERATE_SERVER in perms:
        return True
    needed = _MODERATION_PERM.get(action)
    return bool(needed) and needed in perms


def _custom_command_scope_matches(cmd, game_server):
    """True if custom command `cmd` applies to `game_server` (all games / a game engine / one
    specific game_type)."""
    scope = cmd.scope_type or "all"
    if scope == "all":
        return True
    if scope == "game":
        return game_server.game_type == cmd.scope_value
    if scope == "engine":
        from panel.ops.ssh_manager import game_engine   # lazy: avoid import cycle at module load
        return game_engine(game_server.game_type) == cmd.scope_value
    return False


def can_run_custom_command(user, cmd, game_server):
    """Whether `user` may run custom command `cmd` on `game_server`: the command must be enabled,
    in scope for that game, on a server the user can access, and — for non-superadmins — assigned
    to one of the user's groups. The command TEMPLATE is superadmin-authored; only the argument
    is user-supplied and is validated separately before substitution."""
    if not cmd or not cmd.enabled:
        return False
    if not _custom_command_scope_matches(cmd, game_server):
        return False
    if not can_access_server(user, game_server.id):
        return False
    if user.is_superadmin:
        return True
    for group in _groups_with_grants(user, commands=True):
        for c in (group.custom_commands or []):
            if c.id == cmd.id:
                return True
    return False


def allowed_custom_commands(user, game_server):
    """The list of CustomCommand rows `user` may run on `game_server` (superadmin sees every
    enabled, in-scope command; others see only those assigned to their groups)."""
    from panel.db.models import CustomCommand
    out = []
    seen = set()
    if user.is_superadmin:
        candidates = CustomCommand.query.filter_by(enabled=True).all()
    else:
        candidates = []
        for group in _groups_with_grants(user, commands=True):
            candidates.extend(group.custom_commands or [])
    for cmd in candidates:
        if cmd.id in seen:
            continue
        if can_run_custom_command(user, cmd, game_server):
            seen.add(cmd.id)
            out.append(cmd)
    return out


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
    for group in _groups_with_grants(user):
        for rs in group.servers or []:
            if rs.id == rid:
                return True
    return False


def accessible_remote_ids(user):
    """Set of remote-host ids the user may manage (all of them for a superadmin)."""
    from panel.db.models import RemoteServer
    if user.is_superadmin:
        return {r.id for r in RemoteServer.query.all()}
    ids = set()
    for group in _groups_with_grants(user):
        for rs in group.servers or []:
            ids.add(rs.id)
    return ids


# ─── Decorators ───────────────────────────────────────────────

def _denial_wants_json():
    """True when the caller can only make sense of a JSON denial.

    These decorators used to flash + 302 unconditionally. For an in-page fetch that is worse than
    useless: it follows the redirect, gets 200 text/html, JSON-parsing fails, and the caller's
    fallback turns a REFUSED action into a success toast. Several routes worked around it with an
    inline check returning jsonify(...), 403 — this makes the decorators do the same thing, so the
    workaround stops being necessary."""
    if (request.path or "").startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True            # base.html's fetch wrapper sets this on every in-page fetch
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return True            # an API client with a stale token; a login page means nothing to it
    return "application/json" in (request.headers.get("Accept") or "")


def _deny(message, code):
    """A denial in the shape the caller can read: JSON for fetch/API, flash + redirect for a real
    browser navigation. A 401 also carries X-Auth-Required, the flag the page's fetch wrapper
    watches for — "not signed in" is the one denial the whole tab has to react to, not just the
    one widget that asked."""
    if _denial_wants_json():
        resp = jsonify({"success": False, "message": message})
        resp.status_code = code
        if code == 401:
            resp.headers["X-Auth-Required"] = "1"
        return resp
    flash(message, "danger")
    return redirect(url_for("login") if code == 401 else url_for("index"))


def permission_required(*perms):
    """Decorator: require one of the listed permissions to access a route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return _deny("Please sign in to continue.", 401)
            if current_user.is_superadmin:
                return f(*args, **kwargs)
            user_perms = get_user_permissions(current_user)
            if not any(p in user_perms for p in perms):
                return _deny("You do not have permission to do that.", 403)
            return f(*args, **kwargs)
        # Recorded so rbac_test can tell a SUPER_ADMIN-only route (which needs no per-server check,
        # because a superadmin can reach every server) from one that merely holds a permission.
        decorated_function._required_perms = tuple(perms)
        return decorated_function
    return decorator


def superadmin_required(f):
    """Decorator: require the is_superadmin FLAG.

    Replaces @permission_required(SUPER_ADMIN). That form also passed for anyone whose GROUP granted
    a "super_admin" permission, while every other superadmin gate — the nav, /users, the settings
    pages — tests the flag. The result was an account with real power (settings, notification
    credentials, host reboot) and no way to see or reach most of it."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return _deny("Please sign in to continue.", 401)
        if not current_user.is_superadmin:
            return _deny("That area is for administrators only.", 403)
        return f(*args, **kwargs)
    decorated_function._required_perms = (SUPER_ADMIN,)   # rbac_test reads this
    return decorated_function


def server_access_required(f):
    """Decorator: require access to the specific server referenced in the route.

    A permission alone is NOT a grant for every server — get_game() is a bare get_or_404 — so any
    route taking <int:server_id> needs this as well as its permission decorator. rbac_test asserts
    that structurally via the marker below, which is why the marker exists rather than each route
    being probed one at a time (probing a destructive route on a real install would fire it)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return _deny("Please sign in to continue.", 401)
        server_id = kwargs.get("server_id")
        if server_id is not None and not can_access_server(current_user, server_id):
            return _deny("You do not have access to that server.", 403)
        return f(*args, **kwargs)
    decorated_function._checks_server_access = True
    return decorated_function


# ─── Initialization ────────────────────────────────────────────

def init_auth(app):
    login_manager.init_app(app)
    # Pre-compute the login-timing dummy hash (~400ms bcrypt) so it's ready before the first login
    # WITHOUT adding it to startup or to the first failed-login timing. Run it on a real worker
    # thread via eventlet's tpool so the deliberately-slow hash doesn't block the event hub (a plain
    # green thread would, since bcrypt never yields). Falls back to a daemon thread off eventlet.
    def _warm():
        try:
            from eventlet import tpool
            tpool.execute(_dummy_hash)
        except Exception:
            _dummy_hash()
    try:
        import eventlet
        eventlet.spawn_n(_warm)
    except Exception:
        threading.Thread(target=_warm, daemon=True).start()
    # Session protection mode comes from app.config["SESSION_PROTECTION"] (set in
    # create_app from config, default "strong"). "strong" ties the session to a hash
    # of the client IP + User-Agent and drops it if either changes — so a cookie stolen
    # and replayed from a different machine is rejected (most effective on a direct
    # bind or behind a proxy with trust_proxy, where the real client IP is visible).

    @login_manager.user_loader
    def load_user(user_id):
        # The id is "<user_id>:<auth_epoch>[:<session_sid>]" (see User.get_id). Reject the cookie if
        # the epoch no longer matches (sign-out-everywhere / password change bump auth_epoch — a
        # GLOBAL revoke), or if it carries a session sid that's no longer in the registry (a SINGLE
        # device was revoked). A missing sid = a legacy cookie from before per-session tracking;
        # accepted on the epoch alone until the user next logs in and is issued a sid.
        s = str(user_id)
        if ":" not in s:
            # Legacy cookie issued before epochs existed — accept by plain id (one-time, until they
            # next log in and get an epoch-tagged cookie).
            legacy = db.session.get(User, int(s)) if s.isdecimal() else None
            return legacy if (legacy is not None and legacy.is_active) else None   # see below
        parts = s.split(":")
        uid, epoch = parts[0], parts[1]
        sid = parts[2] if len(parts) > 2 and parts[2] else None
        if not uid.isdecimal():
            return None
        user = db.session.get(User, int(uid))
        if user is None or str(user.auth_epoch or 0) != epoch:
            return None
        # Belt to flask-login's braces, NOT the thing that makes deactivation work. What makes it
        # work today is subtle enough to be worth writing down: this model is
        # `class User(UserMixin, db.Model)` with `is_active` declared as a Column, and
        # UserMixin.is_authenticated is `return self.is_active` (flask_login/mixins.py:17) — so
        # overriding the column silently overrides is_authenticated too, and @login_required
        # already refuses a deactivated account. Verified by running it, not by reading it.
        #
        # That is a load-bearing coincidence between a mixin property and a column name. If the
        # model ever declares its own is_authenticated, or drops UserMixin for a plain object, the
        # coupling disappears with no error anywhere and every open session of every deactivated
        # account starts working again — for up to remember_days, refreshed on each use. This line
        # is what keeps that from being silent, and it costs an attribute read.
        if not user.is_active:
            return None
        if sid:
            try:
                from panel.db.models import UserSession
                sess = UserSession.query.filter_by(sid=sid, user_id=user.id).first()
                if sess is None:
                    return None                       # this device's session was revoked
                now = utcnow()
                if sess.is_expired(now):
                    # The login has been idle past its cookie's life. The Flask session cookie is
                    # already rejected by its own signed max_age, but flask-login's "remember me"
                    # cookie carries no timestamp at all — so without this check a remember cookie
                    # captured months ago still logged straight in. Drop the row as well: an expired
                    # session is not a session, and leaving it listed on the account page as active
                    # is exactly the wrong thing to tell someone checking for intruders.
                    try:
                        db.session.delete(sess)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()   # the sweep can wait; the rejection cannot
                    return None
                user._sid = sid                       # keep it so get_id re-embeds it on cookie refresh
                if not sess.last_seen or (now - sess.last_seen).total_seconds() > 300:
                    sess.last_seen = now              # throttled "last active" update (~5 min)
                    db.session.commit()
            except Exception:
                db.session.rollback()
                # DENY this request. The handler used to fall through to `return user`, which
                # skipped BOTH checks above it — the revoked-device check and the remember-cookie
                # expiry — so a database error authenticated a cookie that had been revoked. For a
                # revocation check, "I could not look" has to mean no.
                #
                # The old comment feared locking a valid user out. It does not: load_user runs per
                # REQUEST and this returns None for this one only. The session cookie is untouched,
                # so a transient lock costs a redirect to the login page, not a logout — whereas
                # the other direction costs a revoked device staying live for as long as the
                # database is unhappy. Logged at warning, because a database that cannot answer
                # this is something the operator should see.
                try:
                    current_app.logger.warning(
                        "load_user: could not verify session %s — denying this request",
                        (sid or "")[:8], exc_info=True)
                except Exception:
                    pass          # logging must never be what turns a deny into a 500
                return None
        return user

    @login_manager.unauthorized_handler
    def _unauthorized():
        """What an unauthenticated request gets back.

        flask-login's default is always a redirect to /login. For a browser navigation that is
        right. For the panel's in-page fetches it is not: the redirect is followed, the login
        PAGE comes back with status 200, and the caller then tries to parse a chunk of HTML as
        JSON — which is why, once a cookie expired, a page left open didn't bounce to the login
        screen, it just threw errors on every click. Answer those callers with a machine-readable
        401 instead, flagged by a header so the client can redirect the whole tab in one place.
        """
        if _denial_wants_json():
            resp = jsonify({"success": False, "error": "auth_required",
                            "message": "Your session has expired — please log in again."})
            resp.status_code = 401
            resp.headers["X-Auth-Required"] = "1"
            resp.headers["Cache-Control"] = "no-store"
            return resp
        flash(login_manager.login_message, "info")
        target = url_for(login_manager.login_view)
        # Come back to the page they were on. Only a same-site path, rebuilt from what matched —
        # never the raw value — so this can't become an open redirect (same shape as /login's).
        nxt = request.full_path if request.method == "GET" else ""
        nxt = nxt[:-1] if nxt.endswith("?") else nxt
        # Same charset /login itself will accept back, so the round trip actually survives.
        m = re.fullmatch(r"/(?:[A-Za-z0-9._~\-]+/?)*(?:\?[A-Za-z0-9._~\-=&%]*)?", nxt or "")
        if m and not nxt.startswith(target):
            target += "?next=" + quote(m.group(0), safe="")
        return redirect(target)

    @login_manager.request_loader
    def load_user_from_request(req):
        """Authenticate an API client via `Authorization: Bearer <token>` (for scripts/bots), so the
        REST API is usable without a browser session. The token authenticates AS its owner and
        inherits exactly that user's RBAC permissions — nothing more. Returns None for a normal
        request so flask-login falls back to the session cookie (user_loader).

        Failed attempts are throttled per IP. /login has had a throttle for a long time; this
        path — the panel's OTHER way in — had none, so an attacker could try tokens as fast as
        the network allowed, and nothing anywhere recorded that it was happening."""
        header = req.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        ip = client_ip() or "unknown"
        if _token_auth_blocked(ip):
            # Return None rather than aborting: a blocked IP simply gets no token identity, and
            # flask-login still falls back to the session cookie — so throttling the token path
            # never locks a logged-in human out of the UI from the same address.
            return None
        user = User.by_api_token(header[7:].strip())
        _token_auth_record(ip, ok=user is not None)
        return user


# ─── API-token brute-force throttle ───────────────────────────────────────────────────────────
# /login has been throttled for a long time; the bearer-token path had nothing, and it is the
# panel's other way in. Tokens are 192 bits, so guessing one is not realistic — but that is a
# property of the token length, not of this code, and an unthrottled authentication endpoint is
# still one. It also stops the panel being a free CPU sink: every attempt costs a SHA-256 and a
# database lookup.
#
# Deliberately more generous than the login limit (20 vs 8): a legitimate script with a stale
# token retries in a loop, and locking it out after 8 would turn a config mistake into an outage.
_TOKEN_FAILS = {}
_TOKEN_FAILS_LOCK = threading.Lock()
TOKEN_MAX_FAILS = 20
TOKEN_WINDOW = 300      # seconds


def _token_auth_blocked(ip):
    """True when this IP has failed too many token authentications recently."""
    now = time.time()
    with _TOKEN_FAILS_LOCK:
        # Prune whole IPs whose failures have aged out. Without this the map grows one entry per
        # IP that ever mistyped a token — the same leak the login throttle had to fix.
        for k in [k for k, v in _TOKEN_FAILS.items() if not v or now - v[-1] >= TOKEN_WINDOW]:
            del _TOKEN_FAILS[k]
        recent = [t for t in _TOKEN_FAILS.get(ip, []) if now - t < TOKEN_WINDOW]
        if recent:
            _TOKEN_FAILS[ip] = recent
        return len(recent) >= TOKEN_MAX_FAILS


def _token_auth_record(ip, ok):
    """Record the outcome of a token authentication: clear the counter on success, count a miss."""
    with _TOKEN_FAILS_LOCK:
        if ok:
            _TOKEN_FAILS.pop(ip, None)
        else:
            _TOKEN_FAILS.setdefault(ip, []).append(time.time())


# ─── Audit Logging ─────────────────────────────────────────────

def client_ip():
    """Real client IP of the connected user.

    This value keys the login throttle, the API-token throttle, the audit log, data/auth.log
    (which the panel-login fail2ban jail parses) and the 7-day auto-block counts. If a client can
    choose it, none of those work: password guessing is unlimited, and every ban lands on whatever
    address the attacker named instead.

    WHOM to trust and WHAT to read are two different questions, and only the first was being
    asked. The answer to the second was X-Forwarded-For's FIRST hop — the one element of that
    header a client always controls, because a proxy can only append to its right. Measured
    through the real /login with the README's own deployment (`trust_proxy: true` behind nginx):
    twenty failed logins from one client, each with a different X-Forwarded-For, were never
    rate-limited and left twenty separate throttle keys. With a constant value the same loop
    blocked at attempt 8, which is LOGIN_MAX_FAILS working exactly as designed.

    So:

      * X-Real-IP first. `proxy_set_header` REPLACES, so a proxy that sets it has overwritten
        anything the client sent — it is the one header in the README's nginx block, and the one
        value in it that the proxy actually chose.
      * then the LAST X-Forwarded-For hop, not the first. That is what the nearest trusted proxy
        appended (`$proxy_add_x_forwarded_for`, Tailscale Serve, Caddy); everything to its left
        came from further out and may be invented.
      * and neither unless the request reached us from a proxy at all — loopback, or trust_proxy
        set, in which case the ORIGINAL socket peer is used to decide, because ProxyFix has by
        then already rewritten request.remote_addr from the header we are trying to judge.

    A `trust_proxy` install that also accepts direct connections (binding 0.0.0.0 alongside the
    proxy) still trusts these headers from anyone who reaches the port — bind loopback, or put the
    proxy on the only reachable address."""
    if not request:
        return ""
    remote = request.remote_addr or ""
    # ProxyFix stores what it overwrote; without it this is just remote_addr.
    peer = (request.environ.get("werkzeug.proxy_fix.orig") or {}).get("REMOTE_ADDR") or remote
    behind_proxy = peer in ("127.0.0.1", "::1")
    if not behind_proxy:
        try:
            behind_proxy = bool(current_app.config.get("_TRUST_PROXY"))
        except Exception:
            behind_proxy = False     # outside an app context: trust nothing
    if behind_proxy:
        xr = (request.headers.get("X-Real-IP") or "").strip()
        if xr:
            return xr
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[-1].strip()
    return remote


def log_action(user, action, target="", detail="", success=True, actor=None):
    """Write an audit log entry. `actor` overrides the recorded username — used for a failed login,
    where there's no authenticated user but we still want the ATTEMPTED username in the User column."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=actor if actor else (user.username if user else "system"),
        action=action,
        target=target,
        detail=detail,
        ip_address=client_ip(),
        success=success,
    )
    db.session.add(entry)
    db.session.commit()


def strip_legacy_superadmin_grants():
    """Remove a stored "super_admin" group permission left over from when it was grantable.

    Nothing consults it any more, so this changes no access — it stops a stale string sitting in the
    permissions JSON where the Groups UI can no longer show or untick it, and where a future
    has_permission(user, SUPER_ADMIN) would silently start honouring it again. Returns how many
    groups were cleaned; best-effort and never fatal at startup."""
    from panel.db.models import Group
    cleaned = 0
    try:
        for group in Group.query.all():
            perms = group.get_permissions()
            if SUPER_ADMIN in perms:
                group.set_permissions([p for p in perms if p != SUPER_ADMIN])
                cleaned += 1
        if cleaned:
            db.session.commit()
    except Exception:
        db.session.rollback()
    return cleaned


# ── Route-level access helpers ───────────────────────────────────────────────────────────────
# These lived as closures inside app.register_routes, which put the panel's access checks in the
# web layer while every function they call — has_permission, can_access_remote,
# get_user_permissions, ALL_PERMISSIONS — already lived here. They are the rules, not the
# routing, so they belong beside their siblings.
#
# The underscore-prefixed names are kept exactly as they were on purpose: renaming them to a
# public form would touch 137 call sites in app.py and bury a pure move inside a rename. That
# is a separate, mechanical follow-up.
READONLY_ACTIONS = {"monitor", "details", "check-update", "postdetails", "test-alert"}


def get_remote(remote_id):
    """Fetch a remote AND enforce per-host access. MANAGE_REMOTES grants the
    ability to manage remotes, but only the ones in the user's groups — the same
    per-host scoping game servers get. Superadmin sees all. Every remote-scoped
    route goes through here, so a direct API call to another remote's id is a 403."""
    r = RemoteServer.query.get_or_404(remote_id)
    if not can_access_remote(current_user, remote_id):
        abort(403)
    return r


def get_game(server_id):
    # db.get_or_404, not Model.query.get_or_404: the Query.get* family is the legacy API and is
    # deprecated in Flask-SQLAlchemy 3.1 / SQLAlchemy 2.0. Same behaviour, same 404.
    return db.get_or_404(GameServer, server_id)


def _can_edit_tags():
    """Tag writes need MANAGE_SERVERS. Checked INLINE rather than with @permission_required,
    because that decorator flashes and redirects — which a fetch().then(r => r.json()) can only
    see as unparseable HTML."""
    return current_user.is_superadmin or has_permission(current_user, MANAGE_SERVERS)


def _can_manage_files():
    return current_user.is_superadmin or has_permission(current_user, MANAGE_SERVERS)


def _perm_for_action(action):
    """Which permission an action requires (core actions have specific perms;
    read-only commands need VIEW_CONSOLE; the rest need UPDATE_SERVER)."""
    p = ACTION_PERMISSION_MAP.get(action)
    if p is None:
        p = VIEW_CONSOLE if action in READONLY_ACTIONS else UPDATE_SERVER
    return p


def grantable_groups(requested_ids, existing=()):
    """The groups a user may be left in after an edit, safely.

    The sibling of _grantable_perms, and it closes the same escalation from the other side.
    _grantable_perms stops a delegated MANAGE_GROUPS admin giving a group a permission they do not
    hold — but MANAGE_USERS let them simply JOIN a group that already holds it, by editing their
    own account and ticking the box. `is_superadmin` was guarded; group membership was not, and
    get_user_permissions unions group permissions on every request, so the next request carried
    the new privileges.

    A superadmin may assign anything. Anyone else may only assign a group whose permissions are a
    SUBSET of their own — so membership can never be a route to a permission they lack — and groups
    already on the user are PRESERVED, so an edit by a less-privileged admin cannot silently strip
    someone's access (the same preserve-don't-strip rule _grantable_perms follows).
    """
    from panel.db.models import Group
    requested = {g for g in (db.session.get(Group, i) for i in requested_ids) if g is not None}
    existing = set(existing or ())
    if current_user.is_superadmin:
        return list(requested)
    mine = get_user_permissions(current_user)
    # Permissions AND object reach. The subset test covered Group.permissions only, while
    # can_access_server unions Group.servers (whole-host grants) and Group.game_servers — so a
    # group whose permissions you already hold, but which carries a host you were never granted,
    # passed this check and handed you that host on the next request. The permission set was
    # unchanged, which is why the existing escalation tests stayed green. grantable_object_ids
    # closes the same gap from the group-editing side; this is the membership side.
    mine_remotes = set(accessible_remote_ids(current_user))
    mine_servers = {gs.id for gs in get_user_servers(current_user)}

    def _within_my_reach(g):
        if not set(g.get_permissions()) <= mine:
            return False
        if not {r.id for r in (g.servers or [])} <= mine_remotes:
            return False
        return {s.id for s in (g.game_servers or [])} <= mine_servers

    keepable = {g for g in requested if _within_my_reach(g)}
    return list(keepable | (existing - {g for g in existing if _within_my_reach(g)}))


def can_administer_user(actor, target):
    """Whether `actor` may edit or delete `target`.

    MANAGE_USERS was a single gate. Holding it let you edit EVERY non-superadmin account —
    including one whose permissions you do not have — and the edit form's own branches then hand
    you the account: reset_password mints a new one and _form_credential shows it to you, and
    reset_2fa clears their second factor. One request took over a more-privileged peer.

    That walks straight around _grantable_perms and grantable_groups, which exist precisely to
    stop a delegated admin acquiring permissions they lack. They guard the grant; this guards the
    other route to the same place, which is to become someone who already has them.

    The rule is theirs, applied to the target as a whole: a non-superadmin may only administer an
    account whose permissions are a SUBSET of their own. Editing yourself is always allowed —
    your own permissions are trivially a subset of your own, but say it outright so a future
    change to get_user_permissions cannot lock someone out of their own account page."""
    if getattr(actor, "is_superadmin", False):
        return True
    if getattr(target, "is_superadmin", False):
        return False
    if actor.id == target.id:
        return True
    return set(get_user_permissions(target)) <= set(get_user_permissions(actor))


def grantable_object_ids(requested_ids, existing_ids, allowed_ids):
    """The object ids (hosts, or game servers) a group may be left granting after an edit.

    Same shape and same reason as grantable_groups: /groups/<id>/edit set group.servers and
    group.game_servers from the submitted ids with no check that the editor could reach those
    objects, while the permission list beside it was carefully filtered. A delegated group admin
    scoped to one host could therefore grant their own group every host in the install — the
    permissions were unchanged, so the existing escalation test still passed, but can_access_server
    and can_access_remote then returned True for everything.

    A superadmin may grant anything. Anyone else may only grant what they can already reach, and
    ids already on the group are preserved.
    """
    requested, existing = set(requested_ids), set(existing_ids or ())
    if current_user.is_superadmin:
        return requested
    return (requested & set(allowed_ids)) | (existing - set(allowed_ids))


def _grantable_perms(requested, existing=()):
    """Compute a group's permission set after an edit, safely. A superadmin can set any
    real permission. Anyone else (a delegated MANAGE_GROUPS user) can only toggle the
    permissions they themselves hold — and never SUPER_ADMIN — so they can't escalate
    their own privileges by editing a group they belong to. Permissions already on the
    group that they can't grant are PRESERVED (so an edit can't silently strip them)."""
    requested = set(requested) & set(ALL_PERMISSIONS.keys())
    if current_user.is_superadmin:
        return list(requested)
    grantable = get_user_permissions(current_user) - {SUPER_ADMIN}
    return list((set(existing) - grantable) | (requested & grantable))
