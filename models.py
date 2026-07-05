"""Database models for LinuxGSM Panel."""
import json
import re
import bcrypt
from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import validates

db = SQLAlchemy()

# Identifiers that get interpolated into remote shell commands (Linux usernames, the
# LinuxGSM instance/game name, paths like `/home/<user>/<selfname>`). They're validated
# at the route layer on input, but enforcing the safe charset here — at the data layer —
# makes it a hard guarantee no code path can ever store a value that could break out of a
# shell command, regardless of how the row is written. Empty is allowed (optional fields).
_SHELL_IDENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_shell_ident(key, value):
    if value and not _SHELL_IDENT_RE.match(value):
        raise ValueError("%s contains characters not allowed in a shell identifier: %r"
                         % (key, value))
    return value

# Association table: group -> permission strings
group_permissions = db.Table(
    "group_permissions",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("permission", db.String(128), primary_key=True),
)

# Association table: group -> accessible servers
group_servers = db.Table(
    "group_servers",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("server_id", db.Integer, db.ForeignKey("remote_server.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    display_name = db.Column(db.String(120), default="")
    is_superadmin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    api_token = db.Column(db.String(64), unique=True, nullable=True)
    totp_secret = db.Column(db.Text, nullable=True)      # TOTP secret, encrypted at rest
    totp_enabled = db.Column(db.Boolean, default=False)  # 2FA active for this user
    auth_epoch = db.Column(db.Integer, default=0, nullable=False)  # bump to revoke all sessions
    backup_codes = db.Column(db.Text, default="")   # JSON list of bcrypt-hashed one-time 2FA backup codes
    groups = db.relationship("Group", secondary="user_groups", back_populates="users")

    @staticmethod
    def _norm_code(code):
        # Compare codes case-insensitively and ignore the display dashes/spaces.
        return (code or "").strip().lower().replace("-", "").replace(" ", "")

    def set_backup_codes(self, plain_codes):
        """Store one-time 2FA backup codes as bcrypt hashes (the plaintext is shown to
        the user once and never persisted)."""
        self.backup_codes = json.dumps([
            bcrypt.hashpw(self._norm_code(c).encode(), bcrypt.gensalt()).decode()
            for c in plain_codes
        ])

    def use_backup_code(self, code):
        """If `code` matches an unused backup code, consume it (one-time) and return
        True. Caller must commit."""
        code = self._norm_code(code)
        if not code or not self.backup_codes:
            return False
        try:
            hashes = json.loads(self.backup_codes)
        except (ValueError, TypeError):
            return False
        for h in hashes:
            try:
                if bcrypt.checkpw(code.encode(), h.encode()):
                    hashes.remove(h)
                    self.backup_codes = json.dumps(hashes)
                    return True
            except (ValueError, TypeError):
                continue
        return False

    @property
    def backup_codes_remaining(self):
        try:
            return len(json.loads(self.backup_codes or "[]"))
        except (ValueError, TypeError):
            return 0

    def get_id(self):
        # Embed a session epoch in the login id. Bumping auth_epoch (on password
        # change, or "sign out everywhere") makes every existing session/remember
        # cookie for this user stop matching — i.e. instantly revoked. flask-login
        # stores this in the cookie and hands it back to the user_loader each request.
        return "%d:%d" % (self.id, self.auth_epoch or 0)

    @property
    def email_display(self):
        """Decrypted email for display (stored encrypted at rest)."""
        from config import decrypt_secret
        return decrypt_secret(self.email) if self.email else ""

    @property
    def totp_secret_plain(self):
        """The decrypted TOTP secret (stored encrypted at rest), or ''."""
        from config import decrypt_secret
        return decrypt_secret(self.totp_secret) if self.totp_secret else ""


user_groups = db.Table(
    "user_groups",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(256), default="")
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship("User", secondary=user_groups, back_populates="groups")
    servers = db.relationship("RemoteServer", secondary=group_servers, back_populates="groups")
    permissions = db.Column(db.Text, default="[]")  # JSON list of permission strings

    def get_permissions(self):
        return set(json.loads(self.permissions or "[]"))

    def set_permissions(self, perms):
        self.permissions = json.dumps(list(perms))

    def has_permission(self, perm):
        return perm in self.get_permissions()


class RemoteServer(db.Model):
    """A remote VPS running LinuxGSM servers."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(64), nullable=False)
    auth_method = db.Column(db.String(16), default="key")  # key, password, tailscale, or local
    auth_credential = db.Column(db.Text, default="")  # password or key path
    sudo_enabled = db.Column(db.Boolean, default=False)
    linuxgsm_user = db.Column(db.String(64), default="")  # LinuxGSM user account on remote
    is_local = db.Column(db.Boolean, default=False)  # True = this machine, run commands locally
    public_ip = db.Column(db.String(45), default="")  # cached public IP (for connect address)

    @validates("username", "linuxgsm_user")
    def _validate_ident(self, key, value):
        return _validate_shell_ident(key, value)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    host_key = db.Column(db.Text, default="")     # pinned SSH host key ("keytype base64"); TOFU
    stats_cache = db.Column(db.Text, default="")  # last live stats (JSON: cpu_percent/memory/disk/uptime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    groups = db.relationship("Group", secondary=group_servers, back_populates="servers")
    games = db.relationship("GameServer", back_populates="remote", cascade="all, delete-orphan")

    @property
    def display_name(self):
        """User-facing name. The local host is always shown as 'Panel Server' so the
        label is consistent with the nav and the Panel Server management page,
        regardless of whatever name was typed when it was added."""
        return "Panel Server" if self.is_local else self.name

    @property
    def display_host(self):
        """Address to show for this host. The local host's stored host is 127.0.0.1
        (loopback SSH), which is meaningless to a user — show the public IP instead."""
        if self.is_local:
            return self.public_ip or ""
        return self.host

    @property
    def cached_stats(self):
        """Last known live stats (cpu_percent/memory/disk/uptime) as a dict, or None.
        Rendered on page load so the card shows real numbers immediately instead of a
        spinner; the background poll only repaints when a value actually changes."""
        if not self.stats_cache:
            return None
        try:
            return json.loads(self.stats_cache)
        except (ValueError, TypeError):
            return None

    def update_cached_stats(self, stats):
        """Persist a fresh stats dict, keeping only the display fields."""
        keep = {k: stats.get(k) for k in ("cpu_percent", "memory", "disk", "uptime")}
        self.stats_cache = json.dumps(keep)

    @property
    def host_key_fingerprint(self):
        """SHA256 fingerprint of the pinned SSH host key (OpenSSH format), or "" if none
        is pinned yet. Shown so the operator can eyeball what they're trusting."""
        if not self.host_key:
            return ""
        try:
            import base64
            import hashlib
            parts = self.host_key.split()
            raw = base64.b64decode(parts[1] if len(parts) > 1 else parts[0])
            digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            keytype = parts[0] if len(parts) > 1 else "key"
            return "%s SHA256:%s" % (keytype, digest)
        except Exception:
            return ""


# LinuxGSM shortnames whose game clients honor the steam://connect/<ip>:<port>
# URI — Source and GoldSrc engine servers. Clicking such a link launches the game
# and joins the server directly. Games without a reliable URI scheme (CoD,
# Minecraft, Rust, ARK, …) are intentionally absent so callers fall back to a
# plain copyable ip:port instead of offering a button that would do nothing.
STEAM_CONNECT_GAMES = frozenset({
    # Source engine
    "gmod", "css", "cs2", "csgo", "tf2", "hl2dm", "dods", "l4d", "l4d2",
    "ins", "insurgency", "nmrih", "zps", "fof", "gesource", "bb2",
    # GoldSrc engine
    "cs", "cscz", "tfc", "dmc", "ns", "ricochet", "hldm", "ahl",
})


class GameServer(db.Model):
    """A single game server instance managed by LinuxGSM."""
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, db.ForeignKey("remote_server.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    short_name = db.Column(db.String(64), nullable=False)  # e.g. "gmodserver"
    game_type = db.Column(db.String(64), nullable=False)  # e.g. "gmod", "mc", "cod"
    game_display = db.Column(db.String(120), default="")
    port = db.Column(db.Integer, nullable=False)
    query_port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(32), default="offline")
    installed = db.Column(db.Boolean, default=False)
    autostart = db.Column(db.Boolean, default=True)
    daily_restart = db.Column(db.Boolean, default=False)  # daily restart when empty of players
    commands = db.Column(db.Text, default="[]")  # JSON list of {cmd, short, desc} from LinuxGSM
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    remote = db.relationship("RemoteServer", back_populates="games")

    @validates("short_name", "game_type")
    def _validate_ident(self, key, value):
        # short_name -> the Linux user; game_type -> the LinuxGSM script name (lgsm_name).
        # Both are interpolated into remote shell commands, so pin them to a safe charset.
        return _validate_shell_ident(key, value)

    def get_commands(self):
        try:
            return json.loads(self.commands or "[]")
        except (ValueError, TypeError):
            return []

    def set_commands(self, cmds):
        self.commands = json.dumps(cmds)

    def connect_uri(self, host):
        """One-click join URI for clients that support one, else "".

        Source/GoldSrc games use steam://connect/<ip>:<port>, which launches the
        game and joins the server. `host` is the already-resolved public IP or
        hostname (validated upstream); we only ever interpolate it plus the
        integer port, so there is nothing shell/HTML-injectable here. Returns ""
        for games with no scheme so the UI shows a copyable ip:port instead."""
        if host and self.game_type in STEAM_CONNECT_GAMES:
            return f"steam://connect/{host}:{self.port}"
        return ""

    # Alias for compatibility
    @property
    def server_type(self):
        return self.game_type

    @property
    def server_user(self):
        return self.short_name

    @property
    def lgsm_name(self):
        """The LinuxGSM script/instance name — ALWAYS '{game_type}server' (e.g.
        'codserver'), regardless of the custom instance name. Only the Ubuntu user
        (short_name) is renamed; the LinuxGSM command stays canonical, otherwise
        LinuxGSM can't find its game data."""
        return f"{self.game_type}server"

    @property
    def server_script(self):
        return f"/home/{self.short_name}/{self.lgsm_name}"

    @property
    def console_log(self):
        """LinuxGSM console log path: /home/<user>/log/console/<lgsm_name>-console.log
        (the file is named after the script/selfname, not the user)."""
        return f"/home/{self.short_name}/log/console/{self.lgsm_name}-console.log"


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    username = db.Column(db.String(80), default="", index=True)
    action = db.Column(db.String(128), nullable=False, index=True)
    target = db.Column(db.String(255), default="")
    detail = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(45), default="")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=True)


class SetupState(db.Model):
    """Tracks multi-step setup progress."""
    id = db.Column(db.Integer, primary_key=True)
    step = db.Column(db.String(64), default="welcome")
    complete = db.Column(db.Boolean, default=False)
    data = db.Column(db.Text, default="{}")  # JSON blob


def _run_light_migrations():
    """Add columns that may be missing on databases created by older versions.
    SQLAlchemy's create_all() never ALTERs existing tables, so do it by hand."""
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
    wanted = {
        ("game_server", "commands"): "ALTER TABLE game_server ADD COLUMN commands TEXT DEFAULT '[]'",
        ("game_server", "daily_restart"): "ALTER TABLE game_server ADD COLUMN daily_restart BOOLEAN DEFAULT 0",
        ("remote_server", "public_ip"): "ALTER TABLE remote_server ADD COLUMN public_ip VARCHAR(45) DEFAULT ''",
        ("remote_server", "stats_cache"): "ALTER TABLE remote_server ADD COLUMN stats_cache TEXT DEFAULT ''",
        ("remote_server", "host_key"): "ALTER TABLE remote_server ADD COLUMN host_key TEXT DEFAULT ''",
        ("user", "totp_secret"): "ALTER TABLE user ADD COLUMN totp_secret TEXT",
        ("user", "totp_enabled"): "ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0",
        ("user", "auth_epoch"): "ALTER TABLE user ADD COLUMN auth_epoch INTEGER DEFAULT 0",
        ("user", "backup_codes"): "ALTER TABLE user ADD COLUMN backup_codes TEXT DEFAULT ''",
    }
    for (table, col), ddl in wanted.items():
        if table in existing and col not in existing[table]:
            db.session.execute(text(ddl))
    # Indexes the audit-log filters/sort rely on. create_all() adds these on a fresh DB,
    # but never to an already-existing table — so add them here (idempotent) to keep the
    # /logs page fast as the table grows. Names match SQLAlchemy's ix_<table>_<col>.
    if "audit_log" in existing:
        for col in ("action", "username"):
            db.session.execute(text(
                f"CREATE INDEX IF NOT EXISTS ix_audit_log_{col} ON audit_log ({col})"))
    db.session.commit()


def init_db(app):
    db.init_app(app)
    with app.app_context():
        # WAL lets readers and a writer work concurrently (default rollback journal
        # blocks readers during a write) — fewer "database is locked" stalls under the
        # eventlet workers. It's a persistent DB-level setting, so run it once here.
        try:
            db.session.execute(text("PRAGMA journal_mode=WAL"))
        except Exception:
            db.session.rollback()
        db.create_all()
        _run_light_migrations()
        # Create default group if not exists
        default_group = Group.query.filter_by(name="Everyone").first()
        if not default_group:
            default_group = Group(name="Everyone", description="All authenticated users", is_default=True)
            default_group.set_permissions({"view_servers", "view_console"})
            db.session.add(default_group)
            db.session.commit()
