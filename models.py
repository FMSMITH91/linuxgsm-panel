"""Database models for LinuxGSM Panel."""
import json
import logging
import re
import bcrypt
from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import validates

db = SQLAlchemy()
_log = logging.getLogger("panel.models")

# Identifiers that get interpolated into remote shell commands (Linux usernames, the
# LinuxGSM instance/game name, paths like `/home/<user>/<selfname>`). They're validated
# at the route layer on input, but enforcing the safe charset here — at the data layer —
# makes it a hard guarantee no code path can ever store a value that could break out of a
# shell command, regardless of how the row is written. Empty is allowed (optional fields).
# Must start with a letter/digit/underscore — never a dash or dot. A leading dash would let
# a stored identifier be mis-parsed as an option by tools it's passed to (e.g. `ssh user@host`
# → `-oProxyCommand=…`); a leading dot risks hidden-file/relative-path confusion.
_SHELL_IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


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

# Association table: group -> accessible hosts (grants every game server on that host)
group_servers = db.Table(
    "group_servers",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("server_id", db.Integer, db.ForeignKey("remote_server.id"), primary_key=True),
)

# Association table: group -> individually-assigned game servers. Finer than group_servers
# (which grants a whole host): a user may access a game server if its host is in the group's
# `servers` OR the server itself is in the group's `game_servers`. See auth.can_access_server.
group_game_servers = db.Table(
    "group_game_servers",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("game_server_id", db.Integer, db.ForeignKey("game_server.id"), primary_key=True),
)

# Association table: group -> custom commands the group is allowed to run
group_custom_commands = db.Table(
    "group_custom_commands",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("custom_command_id", db.Integer, db.ForeignKey("custom_command.id"), primary_key=True),
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
    language = db.Column(db.String(5), default="en")  # UI language: en / es / fr
    # A superadmin without 2FA sees a nag banner; this remembers a permanent "don't remind me".
    otp_nag_dismissed = db.Column(db.Boolean, default=False, nullable=False)
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

    # ── API token (Bearer auth for scripts/bots; inherits the user's RBAC) ──
    def generate_api_token(self):
        """Mint a new API token: return the plaintext (shown to the user ONCE) and store only its
        SHA-256 hash, so a leaked DB never yields a working token. Replaces any existing token."""
        import hashlib
        import secrets
        token = "lgsm_" + secrets.token_hex(24)
        self.api_token = hashlib.sha256(token.encode()).hexdigest()
        return token

    def revoke_api_token(self):
        self.api_token = None

    @property
    def has_api_token(self):
        return bool(self.api_token)

    @staticmethod
    def by_api_token(token):
        """The ACTIVE user whose token hashes to `token`, or None. Lookup is by the unique hash
        index — an unknown token simply misses."""
        import hashlib
        if not token:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        return User.query.filter_by(api_token=digest, is_active=True).first()


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
    game_servers = db.relationship("GameServer", secondary=group_game_servers,
                                   back_populates="groups")
    custom_commands = db.relationship("CustomCommand", secondary=group_custom_commands,
                                      back_populates="groups")
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
    pro_cache = db.Column(db.Text, default="")    # last Ubuntu Pro status (JSON: {data, ts}); rarely changes
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
    def connect_host(self):
        """The PUBLIC address to hand players for a game connect string — the resolved public IP
        when known, else the address the host was added with. For a Tailscale-managed remote,
        `host` is a tailnet-only MagicDNS name players can't reach, so the public IP must win.
        (public_ip is resolved and cached by the /api/servers poll that every server list runs.)"""
        return self.public_ip or self.display_host

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
    def cached_pro(self):
        """Last known Ubuntu Pro status as {"data": {...}, "ts": epoch}, or None. Served/rendered
        instantly so the page never re-spawns the slow `pro status` client just to show a state that
        only changes through the panel (attach/detach/service, which refresh this)."""
        if not self.pro_cache:
            return None
        try:
            return json.loads(self.pro_cache)
        except (ValueError, TypeError):
            return None

    def update_pro_cache(self, data):
        """Persist a fresh Ubuntu Pro status dict with a timestamp (survives restarts)."""
        from datetime import datetime as _dt
        self.pro_cache = json.dumps({"data": data, "ts": int(_dt.utcnow().timestamp())})

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

# LinuxGSM game_types with NO `update` command (not SteamCMD-based — LinuxGSM omits update from
# their menu). Used to hide the Update action even before a server's command list is fetched.
_NO_UPDATE_GAMES = frozenset({"cod", "coduo", "cod2", "cod4", "codwaw"})


class GameServer(db.Model):
    """A single game server instance managed by LinuxGSM."""
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, db.ForeignKey("remote_server.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    short_name = db.Column(db.String(64), nullable=False)  # e.g. "gmodserver"
    game_type = db.Column(db.String(64), nullable=False)  # e.g. "gmod", "mc", "cod"
    game_display = db.Column(db.String(120), default="")
    port = db.Column(db.Integer, nullable=False)
    query_port = db.Column(db.Integer, nullable=True)
    query_type = db.Column(db.String(40), nullable=True)  # gamedig type override (else GAMEDIG_TYPE map)
    status = db.Column(db.String(32), default="offline")
    installed = db.Column(db.Boolean, default=False)
    autostart = db.Column(db.Boolean, default=True)
    daily_restart = db.Column(db.Boolean, default=False)  # daily restart when empty of players
    notify_when_empty = db.Column(db.Boolean, default=False)  # one-shot: alert once this server hits 0 players
    peak_players = db.Column(db.Integer, default=0)  # highest player count seen (for the new-record alert)
    restart_pending = db.Column(db.Boolean, default=False)  # a mod change needs a restart to load it
    backup_pending = db.Column(db.Boolean, default=False)   # queued to back up once players leave
    stop_pending = db.Column(db.Boolean, default=False)     # queued to stop once players leave
    commands = db.Column(db.Text, default="[]")  # JSON list of {cmd, short, desc} from LinuxGSM
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    remote = db.relationship("RemoteServer", back_populates="games")
    groups = db.relationship("Group", secondary=group_game_servers, back_populates="game_servers")

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

    @property
    def supports_update(self):
        """True if this game exposes LinuxGSM's `update` command. The fetched command list is
        authoritative; before it's been fetched (empty) we assume yes, EXCEPT for games known to
        lack update (the Call of Duty family isn't SteamCMD-based), so their Update button is
        correctly hidden even on a freshly imported server whose commands aren't populated yet."""
        cmds = {c.get("cmd") for c in self.get_commands()}
        if cmds:
            return "update" in cmds
        return self.game_type not in _NO_UPDATE_GAMES

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


# Default validation for a custom-command argument: a single token with no shell/tmux
# metacharacters (no spaces, quotes, ;, $, backticks, newlines), so substituting it into a
# superadmin-authored template and sending the result to `tmux send-keys` can never break out
# of the intended command. A superadmin may set a stricter per-command pattern.
CUSTOM_ARG_DEFAULT_PATTERN = r"^[A-Za-z0-9_.\-]{1,64}$"

# The single placeholder a command template may contain for the operator-supplied value.
CUSTOM_ARG_PLACEHOLDER = "{}"


class CustomCommand(db.Model):
    """A superadmin-defined game console command that can be handed to specific groups.

    The template is authored by a superadmin (trusted). It may contain a single `{}`
    placeholder for one value the operator fills in at run time; that value is validated
    against `argument_pattern` (default CUSTOM_ARG_DEFAULT_PATTERN) before being substituted,
    so a mod who is given the command can't inject additional console/shell commands through it.
    `scope_*` limits which servers the command applies to (all / a game engine / one game_type)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)               # button label
    command_template = db.Column(db.String(500), nullable=False)  # e.g. "map {}" or "say Restarting"
    argument_label = db.Column(db.String(80), default="")     # shown by the input when templated
    argument_pattern = db.Column(db.String(200), default="")  # optional regex; "" -> default
    scope_type = db.Column(db.String(16), default="all")      # all | engine | game
    scope_value = db.Column(db.String(64), default="")        # engine name or game_type when scoped
    enabled = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    groups = db.relationship("Group", secondary=group_custom_commands,
                             back_populates="custom_commands")

    @property
    def has_argument(self):
        return CUSTOM_ARG_PLACEHOLDER in (self.command_template or "")

    def effective_pattern(self):
        """The regex an operator-supplied argument must match. Falls back to the safe default."""
        return self.argument_pattern or CUSTOM_ARG_DEFAULT_PATTERN


class GlobalBan(db.Model):
    """A SteamID banned across EVERY Source/GoldSrc (valve-engine) server on every host — ban a
    cheater once and they're gone everywhere. Applied through each server's own console
    (`banid 0 <id>; writeid`), so it uses the game's native ban list and persists across restarts."""
    id = db.Column(db.Integer, primary_key=True)
    steamid = db.Column(db.String(48), unique=True, nullable=False)   # canonical STEAM_x:y:z or [U:x:y]
    player_name = db.Column(db.String(80), default="")               # optional label, for reference
    reason = db.Column(db.String(200), default="")
    created_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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


class MetricSample(db.Model):
    """A periodic snapshot of one game server's live figures (game CPU%, RAM MB, player count) for the
    history charts. Written by the metrics-history sampler (~1/min) and pruned after ~14 days. No FK —
    orphans from an uninstalled server just age out — so it stays cheap to write."""
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, index=True, nullable=False)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    cpu = db.Column(db.Float, default=0.0)          # game CPU %
    ram_mb = db.Column(db.Integer, default=0)       # game RAM MB
    players = db.Column(db.Integer, nullable=True)  # None = unknown at sample time


class HostSample(db.Model):
    """A periodic snapshot of one host's whole-VPS figures (CPU%, RAM%, disk%) for the history charts."""
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, index=True, nullable=False)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    cpu = db.Column(db.Float, default=0.0)
    ram_pct = db.Column(db.Float, default=0.0)
    disk_pct = db.Column(db.Float, default=0.0)


def _run_light_migrations():
    """Add columns that may be missing on databases created by older versions.
    SQLAlchemy's create_all() never ALTERs existing tables, so do it by hand."""
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
    wanted = {
        ("game_server", "commands"): "ALTER TABLE game_server ADD COLUMN commands TEXT DEFAULT '[]'",
        ("game_server", "query_type"): "ALTER TABLE game_server ADD COLUMN query_type VARCHAR(40)",
        ("game_server", "daily_restart"): "ALTER TABLE game_server ADD COLUMN daily_restart BOOLEAN DEFAULT 0",
        ("game_server", "notify_when_empty"): "ALTER TABLE game_server ADD COLUMN notify_when_empty BOOLEAN DEFAULT 0",
        ("game_server", "peak_players"): "ALTER TABLE game_server ADD COLUMN peak_players INTEGER DEFAULT 0",
        ("game_server", "restart_pending"): "ALTER TABLE game_server ADD COLUMN restart_pending BOOLEAN DEFAULT 0",
        ("game_server", "backup_pending"): "ALTER TABLE game_server ADD COLUMN backup_pending BOOLEAN DEFAULT 0",
        ("game_server", "stop_pending"): "ALTER TABLE game_server ADD COLUMN stop_pending BOOLEAN DEFAULT 0",
        ("remote_server", "public_ip"): "ALTER TABLE remote_server ADD COLUMN public_ip VARCHAR(45) DEFAULT ''",
        ("remote_server", "stats_cache"): "ALTER TABLE remote_server ADD COLUMN stats_cache TEXT DEFAULT ''",
        ("remote_server", "pro_cache"): "ALTER TABLE remote_server ADD COLUMN pro_cache TEXT DEFAULT ''",
        ("remote_server", "host_key"): "ALTER TABLE remote_server ADD COLUMN host_key TEXT DEFAULT ''",
        ("user", "totp_secret"): "ALTER TABLE user ADD COLUMN totp_secret TEXT",
        ("user", "totp_enabled"): "ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0",
        ("user", "auth_epoch"): "ALTER TABLE user ADD COLUMN auth_epoch INTEGER DEFAULT 0",
        ("user", "backup_codes"): "ALTER TABLE user ADD COLUMN backup_codes TEXT DEFAULT ''",
        ("user", "language"): "ALTER TABLE user ADD COLUMN language VARCHAR(5) DEFAULT 'en'",
        ("user", "otp_nag_dismissed"): "ALTER TABLE user ADD COLUMN otp_nag_dismissed BOOLEAN DEFAULT 0",
        ("user", "api_token"): "ALTER TABLE user ADD COLUMN api_token VARCHAR(64)",
    }
    for (table, col), ddl in wanted.items():
        if table in existing and col not in existing[table]:
            db.session.execute(text(ddl))
    # Indexes the audit-log filters/sort rely on. create_all() adds these on a fresh DB but
    # never to an already-existing table — so (re)create the model's own declared indexes
    # here, idempotently, to keep the /logs page fast as the table grows. Driving this off the
    # ORM's Index metadata (with checkfirst) instead of hand-written DDL keeps it
    # injection-free by construction — no table/column name is ever interpolated into SQL.
    if "audit_log" in existing:
        for ix in AuditLog.__table__.indexes:
            ix.create(db.engine, checkfirst=True)
    # game_server.remote_id: every dashboard/status query filters or joins on it, so index it
    # (create_all only adds it to a fresh DB; add it to existing installs here, idempotently).
    if "game_server" in existing:
        for ix in GameServer.__table__.indexes:
            ix.create(db.engine, checkfirst=True)
    db.session.commit()


def database_stats():
    """Size of the DB file + its WAL sidecar (bytes) and the audit_log row count —
    the numbers that tell you whether the DB is growing and worth optimizing."""
    import os
    from config import DB_PATH

    def _sz(p):
        try:
            return os.path.getsize(p)
        except OSError:
            return 0

    path = str(DB_PATH)
    try:
        rows = db.session.execute(text("SELECT COUNT(*) FROM audit_log")).scalar()
        rows = int(rows) if rows is not None else 0
    except Exception:
        db.session.rollback()
        rows = None
    return {"size": _sz(path), "wal_size": _sz(path + "-wal"), "audit_rows": rows}


def _run_maintenance(path):
    """Blocking sqlite maintenance over one short-lived autocommit connection.
    Checkpoint + ANALYZE are cheap and reliable and run first; VACUUM needs an
    exclusive lock, so it's best-effort — skipped (not fatal) if the DB is busy.
    Returns True if VACUUM actually ran."""
    import sqlite3
    con = sqlite3.connect(path, timeout=20, isolation_level=None)  # autocommit
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # merge + trim the WAL
        con.execute("ANALYZE")                           # refresh planner stats
        try:
            con.execute("VACUUM")                        # compact (needs exclusive lock)
            return True
        except sqlite3.OperationalError:
            return False   # busy — checkpoint + ANALYZE already succeeded
    finally:
        con.close()


def optimize_database():
    """Reclaim space + refresh stats: WAL checkpoint + ANALYZE (reliable) plus a
    best-effort VACUUM. Returns (ok, message, {"before","after","freed"} bytes).
    Never raises — any failure yields (False, friendly message)."""
    import os
    from config import DB_PATH
    path = str(DB_PATH)

    def _size():
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    before = _size()
    # End this request's read transaction (permission checks read the DB) so it
    # doesn't block VACUUM. commit() releases the lock; we deliberately DON'T call
    # db.session.remove() — the caller still uses the session (audit log) after this.
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    # sqlite3 is a blocking C call. Under eventlet (the panel's runtime) that would
    # freeze the whole event loop, and if a greenlet holds a DB lock VACUUM can't get
    # its own. Run the maintenance in a real worker thread via eventlet.tpool so the
    # hub keeps turning and lock holders can release. Direct call under tests.
    vacuumed = False
    try:
        try:
            import eventlet.patcher
            if eventlet.patcher.is_monkey_patched("thread"):
                from eventlet import tpool
                vacuumed = tpool.execute(_run_maintenance, path)
            else:
                vacuumed = _run_maintenance(path)
        except ImportError:
            vacuumed = _run_maintenance(path)
    except Exception:
        _log.exception("database optimize failed")
        return (False, "Database optimize failed — see the panel logs.",
                {"before": before, "after": before, "freed": 0})

    after = _size()
    msg = ("Database optimized." if vacuumed else
           "Checkpointed the WAL and refreshed stats — VACUUM was deferred because the "
           "database was busy; run it again in a moment to compact.")
    return True, msg, {"before": before, "after": after, "freed": max(0, before - after)}


def _silent_remove(p):
    """Delete a path if present, ignoring 'already gone' / permission races. For
    throwaway temp and stale WAL/SHM files where a failed remove isn't worth
    surfacing."""
    import os
    try:
        os.remove(p)
    except OSError:
        return   # nothing to clean up (missing or not removable) — not an error


def _db_quick_check(path):
    """True if the SQLite file passes PRAGMA quick_check (i.e. not corrupt). A
    missing/empty file counts as healthy — a fresh DB will just be created. Any
    open/read error (a malformed image, "file is not a database", I/O error from a
    bad drive) counts as NOT healthy."""
    import os
    import sqlite3
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return True
    try:
        con = sqlite3.connect(path, timeout=10)
        try:
            row = con.execute("PRAGMA quick_check").fetchone()
            return bool(row) and row[0] == "ok"
        finally:
            con.close()
    except sqlite3.DatabaseError:
        return False


def _ensure_db_healthy(path=None):
    """Self-heal the database against on-disk corruption (bad drive, power loss).

    Runs BEFORE the ORM opens the DB. If the live DB is healthy, refresh a rolling
    known-good backup (SQLite's online backup — consistent even mid-write). If it's
    corrupt, restore that backup — moving the corrupt file aside first so nothing is
    destroyed — so the panel comes back on the last good data instead of failing to
    boot. Best-effort: it never raises, so it can't itself block startup."""
    import os
    import shutil
    import sqlite3
    import time as _t
    from config import DB_PATH
    path = path or str(DB_PATH)
    backup = path + ".backup"
    try:
        if _db_quick_check(path):
            # Healthy — refresh the rolling backup via the online backup API.
            if os.path.exists(path) and os.path.getsize(path) > 0:
                tmp = backup + ".tmp"
                src = dst = None
                ok_copy = False
                try:
                    src = sqlite3.connect(path, timeout=10)
                    dst = sqlite3.connect(tmp)
                    with dst:
                        src.backup(dst)
                    ok_copy = True
                except sqlite3.DatabaseError:
                    ok_copy = False   # source unreadable mid-copy — keep the existing backup
                finally:
                    for _c in (dst, src):
                        if _c is not None:
                            try:
                                _c.close()
                            except sqlite3.Error:
                                _log.debug("connection already broken — nothing to close", exc_info=True)
                # Swap the temp copy in only after the handles are closed (Windows won't
                # rename an open file) and only if the copy actually completed.
                if ok_copy:
                    os.replace(tmp, backup)
                else:
                    _silent_remove(tmp)
            return
        # Corrupt — always move the bad file aside (preserved for forensics/recovery,
        # never deleted), then either restore the last good backup or let the app
        # build a fresh DB. Either way the panel starts instead of crash-looping.
        aside = "%s.corrupt-%d" % (path, int(_t.time()))
        try:
            os.replace(path, aside)
        except OSError:
            _log.debug("couldn't move it (perms) — fall through; a fresh DB gets created", exc_info=True)
        # Drop the corrupt DB's stale WAL/SHM so they aren't replayed over a new file.
        for ext in ("-wal", "-shm"):
            _silent_remove(path + ext)
        if os.path.exists(backup) and _db_quick_check(backup):
            _log.error("database at %s is corrupt — restored last good backup "
                       "(corrupt copy saved to %s)", path, aside)
            shutil.copy2(backup, path)
        else:
            _log.error("database at %s is corrupt and no healthy backup exists — moved "
                       "it aside (%s) so the panel can start fresh; use the recovery "
                       "tool if you need to salvage its data", path, aside)
    except Exception:
        _log.exception("database self-heal check failed (continuing startup)")


def init_db(app):
    _ensure_db_healthy()   # self-heal on-disk corruption before the ORM opens the file
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
