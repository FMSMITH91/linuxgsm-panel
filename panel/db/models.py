"""Database models for LinuxGSM Panel."""
import json
import logging
import re
import bcrypt
from panel.core.clock import utcnow
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import validates

db = SQLAlchemy()
_log = logging.getLogger("panel.models")


class EncryptedString(db.TypeDecorator):
    """A column that is ciphertext in the database and plaintext in Python.

    Used for values that are neither secrets (already encrypted) nor identifiers the panel has to
    query on — a stolen panel.db should not also be a map of the machines it manages: hostnames,
    SSH usernames, public IPs, pinned host keys, and the IP/user-agent of every session.

    A TypeDecorator rather than the `_display` property pattern used for email/totp_secret, and
    deliberately so. That pattern needs every read site changed, and there are 23 of these across
    the SSH path; ONE missed decryption means the panel tries to open a connection to
    "enc:v1:gAAAAA...". Here no call site can get it wrong, because none of them change.

    Only safe for columns nothing filters, orders or groups by: encryption is randomised (a fresh
    IV per write), so the same hostname produces different bytes every time and a WHERE clause
    could never match. Verified by AST scan before adopting this — every query on a name like
    `username` belongs to User, never RemoteServer. AuditLog.ip_address is deliberately NOT one of
    these: the brute-force counter filters on it.

    Legacy plaintext rows keep working — decrypt_secret() passes an unencrypted value straight
    through — so an upgrade cannot lock anyone out of their own hosts while the migration runs."""

    impl = db.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or value == "":
            return value
        from panel.core.config import encrypt_secret
        return encrypt_secret(str(value))

    def process_result_value(self, value, dialect):
        if value is None or value == "":
            return value
        from panel.core.config import decrypt_secret
        return decrypt_secret(value)

# How many previous passwords an account may not go straight back to. Each one costs a bcrypt
# comparison (~0.2s at cost 12) on a password change, so this is a small number on purpose — it
# stops the "change it, then change it back" cycle, which is what it is for, rather than trying to
# be an archive.
PASSWORD_HISTORY_LEN = 3

# Identifiers that get interpolated into remote shell commands (Linux usernames, the
# LinuxGSM instance/game name, paths like `/home/<user>/<selfname>`). They're validated
# at the route layer on input, but enforcing the safe charset here — at the data layer —
# makes it a hard guarantee no code path can ever store a value that could break out of a
# shell command, regardless of how the row is written. Empty is allowed (optional fields).
# Must start with a letter/digit/underscore — never a dash or dot. A leading dash would let
# a stored identifier be mis-parsed as an option by tools it's passed to (e.g. `ssh user@host`
# → `-oProxyCommand=…`); a leading dot risks hidden-file/relative-path confusion.
# Bounded at 64 to match the column width. SQLite does NOT enforce VARCHAR length, so without
# the {0,63} here a 10KB "username" stores happily and then gets interpolated into every
# remote command built for that server.
_SHELL_IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


def _validate_shell_ident(key, value):
    if value and not _SHELL_IDENT_RE.match(value):
        raise ValueError("%s contains characters not allowed in a shell identifier: %r"
                         % (key, value))
    return value


# TCP/UDP's actual range. Enforced HERE, at the data layer, for the same reason the shell charset
# above is: a port stored on a row is later opened in the firewall, written into a LinuxGSM config,
# compared against the host's listening ports, and bound by the panel's own listener. Route-level
# checks are what the panel already had, and two of the four route-level checks were missing — the
# game-server install form took `int(port)` from a request with no bounds at all, and the setup
# wizard wrote its result straight to config.json. A @validates hook cannot be forgotten by the
# next route that assigns a port.
#
# The same caveat as _validate_shell_ident applies: this fires on ASSIGNMENT, never on rows loaded
# from the database, so a row written before it existed still reaches the code that uses it. It
# closes the door going forward; it does not retro-clean an old database.
_MIN_PORT, _MAX_PORT = 1, 65535


def _validate_port(key, value):
    if value is None or value == "":
        return value                    # optional columns (query_port) may legitimately be unset
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError("%s must be a number, got %r" % (key, value))
    if not (_MIN_PORT <= n <= _MAX_PORT):
        raise ValueError("%s must be between %d and %d, got %d" % (key, _MIN_PORT, _MAX_PORT, n))
    return n

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


# Layout keys User.ui_prefs may hold. Whitelisted on BOTH read and write so a key retired in a
# later version stops taking effect immediately, and a hand-edited blob can't smuggle anything in:
#   host_order    [remote_id, ...]            dashboard host-card order
#   server_order  {"remote_id": [game_server_id, ...]}   row order inside each host card
#   panels        {"<region>": ["<panel key>", ...]}     order of the panels in a region
#   hidden        {"<region>": ["<panel key>", ...]}     panels the user collapsed out of a region
UI_PREF_KEYS = frozenset({"host_order", "server_order", "panels", "hidden"})


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # NOT unique: every writer stores encrypt_secret(email) and Fernet uses a fresh IV per write,
    # so two accounts with the same address produce different ciphertext and the constraint never
    # fired. Demonstrated — two rows, one address, both committed. The column is also unindexable
    # for the same reason (EncryptedString's own docstring: "only safe for columns nothing filters,
    # orders or groups by"), and nothing looks a user up by email. If uniqueness is ever wanted it
    # needs a separate deterministic email_hash (HMAC) column carrying the index.
    email = db.Column(db.String(120), nullable=True)
    display_name = db.Column(db.String(120), default="")
    is_superadmin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    api_token = db.Column(db.String(64), unique=True, nullable=True)
    totp_secret = db.Column(db.Text, nullable=True)      # TOTP secret, encrypted at rest
    totp_enabled = db.Column(db.Boolean, default=False)  # 2FA active for this user
    auth_epoch = db.Column(db.Integer, default=0, nullable=False)  # bump to revoke all sessions
    backup_codes = db.Column(db.Text, default="")   # JSON list of bcrypt-hashed one-time 2FA backup codes
    # The last PASSWORD_HISTORY_LEN passwords this account has finished with, newest first, as
    # bcrypt hashes — the same thing stored for the current one, so history reveals nothing the
    # user table did not already hold. Kept so "change your password" cannot be satisfied by
    # putting back the one you just left, which is what a person does when they are asked to
    # change a password they did not want to change.
    password_history = db.Column(db.Text, default="")
    # Highest TOTP timestep already accepted for this user. A code stays valid for ~90s (the step
    # plus one either side for clock skew), so "is this code valid" alone lets an observed code be
    # replayed for the rest of that window. Recording the step makes each one single-use.
    last_totp_step = db.Column(db.Integer, default=0, nullable=False)
    language = db.Column(db.String(5), default="en")  # UI language: en / es / fr
    # A superadmin without 2FA sees a nag banner; this remembers a permanent "don't remind me".
    otp_nag_dismissed = db.Column(db.Boolean, default=False, nullable=False)
    # This account's password was set by someone ELSE — an admin created the account, or reset its
    # password — so it is a handover credential, not a secret. It has been read off one screen and
    # relayed through chat or spoken aloud, and the admin who generated it still knows it. Set then,
    # cleared the moment the account holder chooses their own; while it is set, every request but
    # the change-password page is refused, so the window where a password two people know is a
    # working login is as short as the user's first sign-in.
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    # This user's own UI layout (host/server order), JSON. Personal and never queried, so it rides
    # on the row instead of its own table — reading it costs no extra query. An ABSENT key means
    # "use the default layout", so there is exactly one fallback path in the renderer.
    ui_prefs = db.Column(db.Text, default="{}")
    groups = db.relationship("Group", secondary="user_groups", back_populates="users")

    def get_ui_prefs(self):
        """This user's saved UI layout, or {}. A NULL column (ALTER-added on an upgraded install),
        a corrupt blob, or a key we no longer honour must fall back to the default layout rather
        than raise into a page render."""
        try:
            prefs = json.loads(self.ui_prefs or "{}")
        except (ValueError, TypeError):
            return {}
        if not isinstance(prefs, dict):
            return {}
        return {k: v for k, v in prefs.items() if k in UI_PREF_KEYS}

    def set_ui_pref(self, key, value):
        """Set one whitelisted layout key, or clear it with value=None (which restores the
        default, since absent IS the default). Caller commits."""
        if key not in UI_PREF_KEYS:
            return
        prefs = self.get_ui_prefs()
        if value is None:
            prefs.pop(key, None)
        else:
            prefs[key] = value
        self.ui_prefs = json.dumps(prefs)

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

    def set_password(self, new_hash):
        """Replace the password hash, remembering the one being replaced.

        Every caller that changes an EXISTING account's password goes through here, so the history
        cannot be maintained in one place and forgotten in another — that is the whole reason this
        is a method and not two lines at each call site. Caller still commits."""
        old_hash = (self.password_hash or "").strip()
        if old_hash:
            try:
                history = json.loads(self.password_history or "[]")
                if not isinstance(history, list):
                    history = []
            except (ValueError, TypeError):
                history = []
            # Newest first, de-duped, then trimmed. A hash that is already in the list would
            # otherwise push a genuinely older one out without adding anything.
            history = [old_hash] + [h for h in history if isinstance(h, str) and h != old_hash]
            self.password_history = json.dumps(history[:PASSWORD_HISTORY_LEN])
        self.password_hash = new_hash

    def password_reused(self, candidate):
        """True if `candidate` is this account's current password or one of its last few.

        EXPENSIVE — up to PASSWORD_HISTORY_LEN + 1 bcrypt comparisons at cost 12, which is a few
        hundred milliseconds each. Call it LAST, after every free check has already rejected what
        it can, and only where a human picked the password: a generated one is random, and paying
        a second of hashing to rule out a collision that will not happen is not a trade worth
        making."""
        if not candidate:
            return False
        try:
            history = json.loads(self.password_history or "[]")
            if not isinstance(history, list):
                history = []
        except (ValueError, TypeError):
            history = []
        # check_password, NOT bcrypt.checkpw: hashes are stored as `sha256$<bcrypt>` now, and a
        # raw checkpw against one raises, which this loop would swallow as "not a match" — reuse
        # detection would quietly stop detecting anything. Deferred import because auth.py imports
        # this module; models.py already defers panel.core.config the same way.
        from panel.security.auth import check_password
        for h in [self.password_hash] + history:
            if not isinstance(h, str) or not h:
                continue
            if check_password(candidate, h):   # never raises; handles both hash formats
                return True
        return False

    @property
    def backup_codes_remaining(self):
        try:
            return len(json.loads(self.backup_codes or "[]"))
        except (ValueError, TypeError):
            return 0

    def get_id(self):
        # Login id = "<user_id>:<auth_epoch>[:<session_sid>]". Bumping auth_epoch (password change /
        # "sign out everywhere") makes every existing cookie stop matching — a global revoke. The
        # optional per-login sid (set on this object at login, kept by the loader) ties the cookie to
        # one UserSession row so a SINGLE device can be revoked by deleting that row. flask-login
        # stores this whole string in the cookie and hands it back to user_loader each request.
        base = "%d:%d" % (self.id, self.auth_epoch or 0)
        sid = getattr(self, "_sid", None)
        return base + ":" + sid if sid else base

    @property
    def email_display(self):
        """Decrypted email for display (stored encrypted at rest)."""
        from panel.core.config import decrypt_secret
        return decrypt_secret(self.email) if self.email else ""

    @property
    def totp_secret_plain(self):
        """The decrypted TOTP secret (stored encrypted at rest), or ''."""
        from panel.core.config import decrypt_secret
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
    created_at = db.Column(db.DateTime, default=utcnow)
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


# What the local host is called everywhere a person reads it — the nav, the management page, and
# the audit log's Target column. Defined once so those cannot drift: the log used to leave Target
# blank for panel-host actions while the identical action taken through remote management filled
# it in, which read as "some rows just don't have a target".
LOCAL_HOST_LABEL = "Panel Server"


class RemoteServer(db.Model):
    """A remote VPS running LinuxGSM servers."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    host = db.Column(EncryptedString, nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(EncryptedString, nullable=False)
    auth_method = db.Column(db.String(16), default="key")  # key, password, tailscale, or local
    auth_credential = db.Column(db.Text, default="")  # password or key path
    sudo_enabled = db.Column(db.Boolean, default=False)
    linuxgsm_user = db.Column(EncryptedString, default="")  # LinuxGSM user account on remote
    is_local = db.Column(db.Boolean, default=False)  # True = this machine, run commands locally
    public_ip = db.Column(EncryptedString, default="")  # cached public IP (for connect address)
    # The host's OWN clock, as an IANA name ("Etc/UTC", "America/Chicago"). Cron fires on this,
    # not on the panel's clock and not on the viewer's — so without it "daily at 5am" was a number
    # with no meaning attached, and on a VPS bootstrapped to UTC (which is the panel's own default)
    # it silently meant 11pm for someone in US Central. Learned from the host, refreshed lazily;
    # "" means not yet read, which the UI shows as unknown rather than guessing UTC.
    timezone = db.Column(db.String(64), default="")

    @validates("username", "linuxgsm_user")
    def _validate_ident(self, key, value):
        return _validate_shell_ident(key, value)

    @validates("port")
    def _validate_ssh_port(self, key, value):
        return _validate_port(key, value)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    host_key = db.Column(EncryptedString, default="")   # pinned SSH host key ("keytype base64"); TOFU
    stats_cache = db.Column(db.Text, default="")  # last live stats (JSON: cpu_percent/memory/disk/uptime)
    pro_cache = db.Column(db.Text, default="")    # last Ubuntu Pro status (JSON: {data, ts}); rarely changes
    created_at = db.Column(db.DateTime, default=utcnow)
    groups = db.relationship("Group", secondary=group_servers, back_populates="servers")
    games = db.relationship("GameServer", back_populates="remote", cascade="all, delete-orphan")

    @property
    def display_name(self):
        """User-facing name. The local host is always shown as 'Panel Server' so the
        label is consistent with the nav and the Panel Server management page,
        regardless of whatever name was typed when it was added."""
        return LOCAL_HOST_LABEL if self.is_local else self.name

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
        self.pro_cache = json.dumps({"data": data, "ts": int(utcnow().timestamp())})

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
            # validate=True: the lenient default DISCARDS characters outside the base64 alphabet, so
            # a corrupted pin like "ssh-rsa ***" decoded to b"" and printed the sha256 of nothing —
            # a confident-looking fingerprint for a key that isn't there, which is the opposite of
            # what an operator eyeballing this needs.
            raw = base64.b64decode(parts[1] if len(parts) > 1 else parts[0], validate=True)
            if not raw:
                return ""
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
    # "HH:MM" in the HOST's local time — which is exactly what the crontab line says, so the panel
    # and the box can never disagree about it. The UI converts to and from the viewer's clock.
    daily_restart_at = db.Column(db.String(5), default="05:00")
    notify_when_empty = db.Column(db.Boolean, default=False)  # one-shot: alert once this server hits 0 players
    peak_players = db.Column(db.Integer, default=0)  # highest player count seen (for the new-record alert)
    restart_pending = db.Column(db.Boolean, default=False)  # a mod change needs a restart to load it
    backup_pending = db.Column(db.Boolean, default=False)   # queued to back up once players leave
    stop_pending = db.Column(db.Boolean, default=False)     # queued to stop once players leave
    commands = db.Column(db.Text, default="[]")  # JSON list of {cmd, short, desc} from LinuxGSM
    created_at = db.Column(db.DateTime, default=utcnow)
    remote = db.relationship("RemoteServer", back_populates="games")
    groups = db.relationship("Group", secondary=group_game_servers, back_populates="game_servers")
    # Install-wide labels. Eager-loaded where it's rendered in a loop (see get_user_servers) —
    # lazily it is one query per server and the dashboard has an asserted query budget.
    tags = db.relationship("ServerTag", secondary="game_server_tags", back_populates="servers")

    @validates("short_name", "game_type")
    def _validate_ident(self, key, value):
        # short_name -> the Linux user; game_type -> the LinuxGSM script name (lgsm_name).
        # Both are interpolated into remote shell commands, so pin them to a safe charset.
        return _validate_shell_ident(key, value)

    @validates("port", "query_port")
    def _validate_ports(self, key, value):
        return _validate_port(key, value)

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
    created_at = db.Column(db.DateTime, default=utcnow)
    groups = db.relationship("Group", secondary=group_custom_commands,
                             back_populates="custom_commands")

    @property
    def has_argument(self):
        return CUSTOM_ARG_PLACEHOLDER in (self.command_template or "")

    def effective_pattern(self):
        """The regex an operator-supplied argument must match. Falls back to the safe default."""
        return self.argument_pattern or CUSTOM_ARG_DEFAULT_PATTERN


# The tag-name rule, shared with the routes so a request can be rejected with THIS fixed message
# instead of echoing the exception back — returning str(exc) to a client is how raw internals leak
# into API responses (CodeQL py/stack-trace-exposure), and this codebase's rule is never to do it.
TAG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,31}\Z")
TAG_NAME_HELP = ("A tag name must start with a letter or number and use only letters, numbers, "
                 "spaces, dots, hyphens or underscores (up to 32 characters).")


class ServerTag(db.Model):
    """An install-wide label for grouping game servers (e.g. "PvE", "modded", "production").

    Shared by every user rather than per-user: a tag describes the SERVER, and tag-driven bulk
    actions and notification routing only mean anything against one common vocabulary. Editing is
    gated on MANAGE_SERVERS; reading is not. Which tags a user is FILTERING by is a separate,
    personal thing — deliberately not persisted at all (see dashboard.html), so it is not a
    UI_PREF_KEY and set_ui_pref would silently ignore it."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    color = db.Column(db.String(7), default="")   # "#rrggbb", or "" for the default chip colour
    notify = db.Column(db.Boolean, default=True)  # False = suppress alerts for servers with this tag
    created_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=utcnow)
    servers = db.relationship("GameServer", secondary="game_server_tags", back_populates="tags")

    @validates("name")
    def _validate_tag_name(self, key, value):
        # A tag name is rendered into HTML, used as a filter key, and shown in alert text. Pin the
        # charset at the DATA layer so no route can store one that needs escaping to be safe.
        if value is not None and not TAG_NAME_RE.match(value or ""):
            raise ValueError(TAG_NAME_HELP)
        return value


# Association: which install-wide tags a game server carries.
game_server_tags = db.Table(
    "game_server_tags",
    db.Column("tag_id", db.Integer, db.ForeignKey("server_tag.id"), primary_key=True),
    db.Column("game_server_id", db.Integer, db.ForeignKey("game_server.id"), primary_key=True),
)


class GlobalBan(db.Model):
    """A SteamID banned across EVERY Source/GoldSrc (valve-engine) server on every host — ban a
    cheater once and they're gone everywhere. Applied through each server's own console
    (`banid 0 <id>; writeid`), so it uses the game's native ban list and persists across restarts."""
    id = db.Column(db.Integer, primary_key=True)
    steamid = db.Column(db.String(48), unique=True, nullable=False)   # canonical STEAM_x:y:z or [U:x:y]
    player_name = db.Column(db.String(80), default="")               # optional label, for reference
    reason = db.Column(db.String(200), default="")
    created_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    username = db.Column(db.String(80), default="", index=True)
    action = db.Column(db.String(128), nullable=False, index=True)
    target = db.Column(db.String(255), default="")
    detail = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(45), default="")
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    success = db.Column(db.Boolean, default=True)


class Invite(db.Model):
    """A one-time link that lets a person create their OWN account.

    The alternative it replaces: an admin invents a username, the panel generates a password, and
    that password gets relayed over chat or email — a credential that is in a third place from the
    moment it exists. An invite carries no credential. The person opens it once, picks their own
    username and password, and the link dies.

    Only the SHA-256 of the token is stored, like the API token above, so a leaked database yields
    no usable invite. What the invite GRANTS (groups, superadmin) is decided by the person who
    created it and frozen here — the invitee chooses their name and password and nothing else,
    because anything else would be a privilege they awarded themselves.
    """
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    used_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    # What the account will get. Frozen at creation, never read from the invitee's form.
    # Revocation is its own timestamp, not a reuse of used_at: "somebody redeemed this" and
    # "the person who sent it took it back" are different facts, and collapsing them would make the
    # list lie about what happened to a link.
    revoked_at = db.Column(db.DateTime, nullable=True)
    grants_superadmin = db.Column(db.Boolean, default=False)
    group_ids = db.Column(db.Text, default="[]")
    note = db.Column(db.String(120), default="")

    INVITE_TTL_HOURS = 48

    @staticmethod
    def mint(creator, hours=None, superadmin=False, group_ids=(), note=""):
        """Create an invite and return (invite, plaintext_token). The token is shown ONCE."""
        import hashlib
        import secrets
        from datetime import timedelta      # module-level datetime import is `utcnow` only
        token = secrets.token_urlsafe(32)          # 256 bits — not guessable, not enumerable
        inv = Invite(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_by_id=getattr(creator, "id", None),
            expires_at=utcnow() + timedelta(hours=int(hours or Invite.INVITE_TTL_HOURS)),
            grants_superadmin=bool(superadmin),
            group_ids=json.dumps(sorted({int(g) for g in group_ids})),
            note=(note or "")[:120],
        )
        return inv, token

    @staticmethod
    def by_token(token):
        """The invite for `token`, used or not, or None. Callers must check is_usable."""
        import hashlib
        if not token:
            return None
        return Invite.query.filter_by(
            token_hash=hashlib.sha256(token.encode()).hexdigest()).first()

    @property
    def is_usable(self):
        """Unused and unexpired. Both halves matter: a used invite must not be reusable, and an
        old one must not be usable forever if a link leaks out of someone's inbox."""
        return (self.used_at is None and self.revoked_at is None
                and (self.expires_at or utcnow()) > utcnow())

    def authority_intact(self, creator):
        """True if the person who minted this still holds the authority it encodes.

        An invite is a delegation, and a delegation cannot outlive the authority behind it. Without
        this, an admin who is offboarded — demoted, deactivated, deleted — leaves live invites
        behind for up to the 30-day maximum TTL, and whoever holds one still gets the account they
        promised, up to and including SUPERADMIN. Demonstrated before it was fixed.

        `creator` is the User row (or None if the account is gone). A missing creator fails closed:
        the row is deleted or the id dangles, and either way nobody is standing behind the invite.
        An invite with no creator recorded at all (created_by_id NULL — only fixtures do that) is
        left alone, because there is no authority to have lapsed."""
        if self.created_by_id is None:
            return True
        if creator is None or not creator.is_active:
            return False
        # Granting superadmin needs the grantor to STILL be one. A demoted admin's outstanding
        # invite must not keep handing out the rank they themselves lost.
        return creator.is_superadmin if self.grants_superadmin else True

    @property
    def state(self):
        """One word for the list. Order matters: a link that was redeemed AND has since expired is
        still 'used' — what happened to it is the interesting fact, not the clock."""
        if self.used_at is not None:
            return "used"
        if self.revoked_at is not None:
            return "revoked"
        if (self.expires_at or utcnow()) <= utcnow():
            return "expired"
        return "active"

    @property
    def groups_wanted(self):
        try:
            v = json.loads(self.group_ids or "[]")
            return [int(x) for x in v] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []


class SetupState(db.Model):
    """Tracks multi-step setup progress."""
    id = db.Column(db.Integer, primary_key=True)
    step = db.Column(db.String(64), default="welcome")
    complete = db.Column(db.Boolean, default=False)
    data = db.Column(db.Text, default="{}")  # JSON blob


class MetricSample(db.Model):
    """A periodic snapshot of one game server's live figures (game CPU%, RAM MB, player count) for the
    history charts. Written by the metrics-history sampler (~1/min) and pruned after ~14 days.

    No FK, so the write stays cheap — but the orphans do NOT "just age out" harmlessly, which is
    what this used to say. SQLite hands a deleted row's id straight to the next INSERT (plain
    INTEGER PRIMARY KEY = rowid, no AUTOINCREMENT), so for up to 14 days a freshly-installed
    server whose id was recycled shows the DELETED server's CPU, RAM and player counts on its
    history chart — silently wrong data on the page an operator uses to decide whether a box is
    overloaded. The after_delete listener at the bottom of this module clears them with the row,
    which is the same rule the per-remote caches and panel_state already follow."""
    # The history charts ask "one server, last 7 (or 1) days, in time order" — server_id AND ts
    # together. With only the two single-column indexes SQLite picked server_id and then sorted
    # the whole 14-day slice in a temp B-tree to satisfy ORDER BY. Measured on 806k rows (40
    # servers x 14 days at the real 1/min cadence): 3.6ms -> 2.5ms, and the temp sort disappears.
    # The single-column ts index STAYS — _prune_metric_samples deletes on `ts < cutoff` alone.
    __table_args__ = (db.Index("ix_metric_sample_server_ts", "server_id", "ts"),)
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, index=True, nullable=False)
    ts = db.Column(db.DateTime, default=utcnow, index=True)
    cpu = db.Column(db.Float, default=0.0)          # game CPU %
    ram_mb = db.Column(db.Integer, default=0)       # game RAM MB
    players = db.Column(db.Integer, nullable=True)  # None = unknown at sample time


class HostSample(db.Model):
    """A periodic snapshot of one host's whole-VPS figures (CPU%, RAM%, disk%) for the history charts.

    Cleared when the host row is deleted — see MetricSample for why aging out is not enough."""
    # Same (id, ts) shape as MetricSample, and this one was worse: with far fewer distinct hosts
    # than servers, SQLite preferred the ts index and scanned half the table before filtering
    # remote_id. Measured on 100k rows: 7.7ms -> 2.7ms, a 2.8x improvement on the same query the
    # history endpoint runs beside the metric one.
    __table_args__ = (db.Index("ix_host_sample_remote_ts", "remote_id", "ts"),)
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, index=True, nullable=False)
    ts = db.Column(db.DateTime, default=utcnow, index=True)
    cpu = db.Column(db.Float, default=0.0)
    ram_pct = db.Column(db.Float, default=0.0)
    disk_pct = db.Column(db.Float, default=0.0)


class UserSession(db.Model):
    """One active login (a device/browser). The random `sid` is embedded in the login cookie
    (User.get_id) and checked on every request, so a session can be listed and revoked INDIVIDUALLY
    from the account page — deleting the row makes that one cookie fail the loader, without touching
    the others. (Signing out *everywhere* still bumps User.auth_epoch, which invalidates them all.)"""
    __tablename__ = "user_session"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    sid = db.Column(db.String(64), unique=True, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    ip = db.Column(EncryptedString, default="")
    user_agent = db.Column(EncryptedString, default="")
    # Which cookie is keeping this login alive, because the two expire on very different clocks:
    # a plain login rides the Flask session cookie (PERMANENT_SESSION_LIFETIME, hours), a
    # "remember me" login also gets flask-login's remember cookie (REMEMBER_COOKIE_DURATION, days).
    # Without knowing which, the row cannot say when the login actually died.
    remember = db.Column(db.Boolean, default=False, nullable=False)
    user = db.relationship("User", backref=db.backref(
        "login_sessions", lazy="dynamic", cascade="all, delete-orphan"))

    def idle_limit(self):
        """Seconds this login may sit idle before its cookie is certainly dead."""
        return session_idle_limits()[1 if self.remember else 0]

    def is_expired(self, now=None):
        """True once no cookie for this login can still authenticate.

        Both cookies are refreshed on use, so it is idle time — not age — that kills them, and
        `last_seen` is the panel's record of that. The registry used to prune only at 45 days,
        so the account page listed logins that had expired days or weeks earlier as "active":
        alarming to read, and impossible to act on, since revoking one revokes nothing.
        """
        last = self.last_seen or self.created_at
        if last is None:
            return False
        return ((now or utcnow()) - last).total_seconds() > self.idle_limit()


# `last_seen` is only written every ~5 minutes (the throttle in load_user), so it can lag real
# activity by that much. Add it to every expiry window rather than cutting a live session short.
SESSION_LAST_SEEN_GRACE = 300


def session_idle_limits():
    """(plain, remember) idle seconds after which a login's cookie can no longer be valid.

    Read live from app.config — the same values the cookies themselves are issued with, and which
    the settings page can change at runtime — so the registry and the browser never disagree. A
    "remember me" login survives the shorter session-cookie window because the remember cookie
    signs it straight back in, hence the max().
    """
    from datetime import timedelta
    from flask import current_app

    def _secs(value, fallback):
        if isinstance(value, timedelta):
            return value.total_seconds()
        try:
            return float(value)
        except (TypeError, ValueError):
            return fallback

    try:
        cfg = current_app.config
    except RuntimeError:      # no app context (a CLI/maintenance caller) — use the shipped defaults
        cfg = {}
    plain = _secs(cfg.get("PERMANENT_SESSION_LIFETIME"), 8 * 3600) + SESSION_LAST_SEEN_GRACE
    remember = _secs(cfg.get("REMEMBER_COOKIE_DURATION"), 3 * 86400) + SESSION_LAST_SEEN_GRACE
    return plain, max(plain, remember)


def prune_expired_sessions(user_id=None):
    """Delete session rows whose cookies have expired. Scoped to one user when given.

    Returns the number of rows removed. Best-effort: a failure here must never break the request
    that happened to trigger the sweep.
    """
    from datetime import timedelta
    from sqlalchemy import and_, or_
    plain, remember = session_idle_limits()
    now = utcnow()
    q = UserSession.query
    if user_id is not None:
        q = q.filter(UserSession.user_id == user_id)
    q = q.filter(or_(
        and_(UserSession.remember.is_(True), UserSession.last_seen < now - timedelta(seconds=remember)),
        and_(UserSession.remember.isnot(True), UserSession.last_seen < now - timedelta(seconds=plain)),
    ))
    try:
        n = q.delete(synchronize_session=False)
        db.session.commit()
        return n
    except Exception:
        db.session.rollback()
        return 0


# Columns that are ciphertext at rest. Named here so the migration and its test agree on one list.
ENCRYPTED_AT_REST_COLUMNS = {
    "remote_server": ("host", "username", "linuxgsm_user", "public_ip", "host_key"),
    "user_session": ("ip", "user_agent"),
}


def encrypt_at_rest_columns():
    """Encrypt any rows in ENCRYPTED_AT_REST_COLUMNS still stored as plaintext. Returns the number
    of rows rewritten. Idempotent, and safe to call on every startup.

    A function rather than inline startup code so it can be tested — and it is genuinely
    load-bearing: an ordinary save does NOT convert a legacy row, because SQLAlchemy writes only
    the columns that changed. Editing a host's port would leave its hostname in plaintext forever.

    type_coerce is the whole trick. Reading these columns normally hands back the DECRYPTED value,
    so "is it already encrypted?" would be answered by the decryptor and always say yes; and
    assigning that same value back changes nothing SQLAlchemy can see, so no UPDATE would be
    emitted. Coercing to Text bypasses the TypeDecorator's result processing and yields the raw
    stored bytes, which is the only place the question can be asked. The write then goes through
    the TYPED column, so the plaintext is encrypted on its way back in.

    Built with SQLAlchemy Core rather than formatted SQL strings: the table and column names come
    from the constant above and were never attacker-controlled, but SQL assembled by string
    formatting is worth avoiding on sight — and Core expresses this more clearly anyway."""
    from sqlalchemy import Text as _SAText, select, type_coerce, update
    from panel.core.config import is_encrypted
    targets = [(RemoteServer, ENCRYPTED_AT_REST_COLUMNS["remote_server"]),
               (UserSession, ENCRYPTED_AT_REST_COLUMNS["user_session"])]
    touched = 0
    for model, cols in targets:
        tbl = model.__table__
        raw_cols = [type_coerce(tbl.c[c], _SAText).label(c) for c in cols]
        for row in db.session.execute(select(tbl.c.id, *raw_cols)).fetchall():
            values = {c: getattr(row, c) for c in cols
                      if getattr(row, c) and not is_encrypted(getattr(row, c))}
            if values:
                # Through the typed column: process_bind_param does the encrypting.
                db.session.execute(update(tbl).where(tbl.c.id == row.id).values(**values))
                touched += 1
    if touched:
        db.session.commit()
    return touched

def _anonymise_ip(ip):
    """Reduce an IP to its network prefix: 203.0.113.77 -> 203.0.113.0/24, 2001:db8::1 -> /64.

    Keeps what an audit trail is actually read for — "the same network, again" — while dropping
    the part that identifies one household or one person. The "/24" is not decoration: it makes
    an already-anonymised row identifiable in SQL, so this can skip them instead of rewriting
    every old row on every startup.

    Anything that will not parse as an IP returns "" rather than being kept. A value that got in
    without being an address is not something to preserve on the off-chance."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network("%s/%d" % (addr, prefix), strict=False))


def anonymise_audit_ips(days):
    """Reduce audit IPs older than `days` to their network prefix. Returns rows changed.

    Cannot affect login throttling: the brute-force counter looks back LOGIN_WINDOW, which is 300
    SECONDS, so it never reads a row old enough for this to touch."""
    # Coerce FIRST. config.json is hand-editable and "90" (quoted) is an easy thing to write;
    # comparing a str to an int raises TypeError, the caller in app.py swallows it with a bare
    # except, and the control then silently never runs while the config still says it is on. A
    # privacy control that fails quietly is worse than one that is off, because nobody looks.
    try:
        days = int(days)
    except (TypeError, ValueError):
        _log.warning("audit_ip_retention_days is not a number (%r); IP ageing is disabled", days)
        return 0
    if days <= 0:
        return 0
    from datetime import timedelta
    cutoff = utcnow() - timedelta(days=days)
    rows = (AuditLog.query
            .filter(AuditLog.timestamp < cutoff, AuditLog.ip_address != "",
                    AuditLog.ip_address.isnot(None),
                    ~AuditLog.ip_address.like("%/%"))     # already reduced -> skip
            .all())
    for r in rows:
        r.ip_address = _anonymise_ip(r.ip_address)
    if rows:
        db.session.commit()
    return len(rows)


def _run_light_migrations():
    """Add columns that may be missing on databases created by older versions.
    SQLAlchemy's create_all() never ALTERs existing tables, so do it by hand."""
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
    wanted = {
        ("game_server", "commands"): "ALTER TABLE game_server ADD COLUMN commands TEXT DEFAULT '[]'",
        ("game_server", "daily_restart_at"):
            "ALTER TABLE game_server ADD COLUMN daily_restart_at VARCHAR(5) DEFAULT '05:00'",
        ("game_server", "query_type"): "ALTER TABLE game_server ADD COLUMN query_type VARCHAR(40)",
        ("game_server", "daily_restart"): "ALTER TABLE game_server ADD COLUMN daily_restart BOOLEAN DEFAULT 0",
        ("game_server", "notify_when_empty"): "ALTER TABLE game_server ADD COLUMN notify_when_empty BOOLEAN DEFAULT 0",
        ("game_server", "peak_players"): "ALTER TABLE game_server ADD COLUMN peak_players INTEGER DEFAULT 0",
        ("game_server", "restart_pending"): "ALTER TABLE game_server ADD COLUMN restart_pending BOOLEAN DEFAULT 0",
        ("game_server", "backup_pending"): "ALTER TABLE game_server ADD COLUMN backup_pending BOOLEAN DEFAULT 0",
        ("game_server", "stop_pending"): "ALTER TABLE game_server ADD COLUMN stop_pending BOOLEAN DEFAULT 0",
        ("invite", "revoked_at"): "ALTER TABLE invite ADD COLUMN revoked_at DATETIME",
        ("remote_server", "public_ip"): "ALTER TABLE remote_server ADD COLUMN public_ip VARCHAR(45) DEFAULT ''",
        ("remote_server", "stats_cache"): "ALTER TABLE remote_server ADD COLUMN stats_cache TEXT DEFAULT ''",
        ("remote_server", "pro_cache"): "ALTER TABLE remote_server ADD COLUMN pro_cache TEXT DEFAULT ''",
        ("remote_server", "host_key"): "ALTER TABLE remote_server ADD COLUMN host_key TEXT DEFAULT ''",
        ("remote_server", "timezone"):
            "ALTER TABLE remote_server ADD COLUMN timezone VARCHAR(64) DEFAULT ''",
        ("user", "totp_secret"): "ALTER TABLE user ADD COLUMN totp_secret TEXT",
        ("user", "totp_enabled"): "ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0",
        ("user", "auth_epoch"): "ALTER TABLE user ADD COLUMN auth_epoch INTEGER DEFAULT 0",
        ("user", "backup_codes"): "ALTER TABLE user ADD COLUMN backup_codes TEXT DEFAULT ''",
        ("user", "language"): "ALTER TABLE user ADD COLUMN language VARCHAR(5) DEFAULT 'en'",
        ("user", "otp_nag_dismissed"): "ALTER TABLE user ADD COLUMN otp_nag_dismissed BOOLEAN DEFAULT 0",
        ("user", "api_token"): "ALTER TABLE user ADD COLUMN api_token VARCHAR(64)",
        ("user", "ui_prefs"): "ALTER TABLE user ADD COLUMN ui_prefs TEXT DEFAULT '{}'",
        ("user", "last_totp_step"): "ALTER TABLE user ADD COLUMN last_totp_step INTEGER DEFAULT 0",
        # DEFAULT 0: every account that already exists chose its own password, or has been using
        # whatever it was given for long enough that a forced change on upgrade would be a surprise
        # rather than a protection. The flag only ever starts true for a password set from now on.
        ("user", "must_change_password"):
            "ALTER TABLE user ADD COLUMN must_change_password BOOLEAN DEFAULT 0 NOT NULL",
        # Empty on upgrade: the panel never stored past passwords, so there is no history to
        # backfill. It starts filling on the next change each account makes.
        ("user", "password_history"): "ALTER TABLE user ADD COLUMN password_history TEXT DEFAULT ''",
        # DEFAULT 1, unlike the model's default of False, and only here: this DDL runs once, on
        # an install that already has session rows, and its DEFAULT exists solely to backfill
        # them. Guessing "remembered" for those is the kind guess — the expiry sweep then gives
        # them the LONGER window, so nobody is signed out by the upgrade itself; a plain session
        # that is really dead lingers in the list a few days and then goes. Guessing the other way
        # signs out every remember-me login the first time they idle for an afternoon. New rows
        # never see this default: every insert goes through the ORM, which always supplies the
        # real value.
        ("user_session", "remember"):
            "ALTER TABLE user_session ADD COLUMN remember BOOLEAN DEFAULT 1 NOT NULL",
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
    # The history tables' (id, ts) composites — same reason as above: create_all() adds them to a
    # fresh DB only, so an upgraded install would keep the slow plans forever without this.
    for _model in (MetricSample, HostSample):
        if _model.__tablename__ in existing:
            for ix in _model.__table__.indexes:
                ix.create(db.engine, checkfirst=True)
    db.session.commit()


def database_stats():
    """Size of the DB file + its WAL sidecar (bytes) and the audit_log row count —
    the numbers that tell you whether the DB is growing and worth optimizing."""
    import os
    from panel.core.config import DB_PATH

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
    from panel.core.config import DB_PATH
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
    from panel.core.config import DB_PATH
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


# ── A deleted row must not leave its history behind ───────────────────────────────────────────
# MetricSample and HostSample carry no FK (deliberately — see MetricSample), so nothing removed
# their rows when a server or host was deleted, and SQLite then handed the id to the next INSERT.
# Measured: delete a game server with 3 samples, add another that takes the same id, and
# /api/server/<id>/history returned the deleted server's 99% CPU and 31 players.
#
# Done as a listener rather than in the delete routes, for the reason game.py's version already
# gives: the invariant belongs where the row goes away, not at each of the places that remove one.
# The DELETE goes through the flush's own connection, so it is part of the same transaction — a
# rolled-back delete does not lose the samples.
def _register_sample_pruning():
    from sqlalchemy import event

    def _prune(model, column):
        def _handler(_mapper, connection, target):
            try:
                connection.execute(model.__table__.delete().where(column == target.id))
            except Exception:
                _log.debug("sample prune failed for a deleted row", exc_info=True)
        return _handler

    event.listen(GameServer, "after_delete", _prune(MetricSample, MetricSample.server_id))
    event.listen(RemoteServer, "after_delete", _prune(HostSample, HostSample.remote_id))

    # An invite must die with the account that minted it. authority_intact() resolves the creator
    # with db.session.get(User, created_by_id) and fails closed when it is gone — but user.id is a
    # bare INTEGER PRIMARY KEY, so SQLite hands the freed rowid to the very NEXT account created.
    # The creator is then not missing; it is a different person, and the check says yes. Offboard
    # an admin and create their replacement and the dead invite is live again, for an ordinary
    # account as soon as the new one is active — and for a SUPERADMIN invite as soon as the
    # replacement is promoted, which is exactly what happens in that scenario. manage_users lists
    # the resurrected invite as "Active". revoked_at already exists and is_usable already honours
    # it, so stamping it is enough and no rowid can undo it.
    @event.listens_for(User, "after_delete")
    def _revoke_invites_of_deleted_user(_mapper, connection, target):
        try:
            connection.execute(Invite.__table__.update()
                               .where(Invite.created_by_id == target.id)
                               .where(Invite.revoked_at.is_(None))
                               .values(revoked_at=utcnow()))
        except Exception:
            _log.debug("revoking a deleted user's invites failed", exc_info=True)

    # AuditLog.user_id is a FK with no cascade, this app never sets PRAGMA foreign_keys, and the
    # rowid is recycled — so after a delete the column pointed at whoever took the freed id.
    # Verified: alice's rows read back as bob's. No render path joins on it today (they all use
    # the denormalised `username`, which is the auditable fact and is MEANT to outlive the
    # account), so this is a foot-gun rather than a live defect — for the next feature that does
    # join, "show this user's activity" would hand bob alice's history. Nulled rather than
    # deleted: the entries must survive, only the pointer must not lie.
    @event.listens_for(User, "after_delete")
    def _detach_audit_rows_of_deleted_user(_mapper, connection, target):
        try:
            connection.execute(AuditLog.__table__.update()
                               .where(AuditLog.user_id == target.id)
                               .values(user_id=None))
        except Exception:
            _log.debug("detaching a deleted user's audit rows failed", exc_info=True)

    # A host's game servers go with it, and remotes.py deletes them in BULK — which bypasses the
    # ORM, so the per-server listener above never fires for them. Clear their samples by
    # subquery on the host id instead of relying on that cascade.
    @event.listens_for(RemoteServer, "after_delete")
    def _prune_host_game_samples(_mapper, connection, target):
        try:
            connection.execute(MetricSample.__table__.delete().where(
                MetricSample.server_id.in_(
                    db.select(GameServer.id).where(GameServer.remote_id == target.id))))
        except Exception:
            _log.debug("game-server sample prune failed for a deleted host", exc_info=True)


_register_sample_pruning()


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
