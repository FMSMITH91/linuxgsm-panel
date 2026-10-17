"""Configuration management for LinuxGSM Panel."""
import base64
import copy
import json
import logging
import os
import tempfile
import threading
from pathlib import Path

_log = logging.getLogger("panel.config")

# The panel checkout, NOT this file's directory: config.py lives in panel/core/ now, so
# Path(__file__).parent would put data/ (database, secret key, credential key, TLS certs)
# under panel/core/ and quietly abandon the real one. See panel/__init__.py.
from panel import REPO_ROOT as HERE
DATA_DIR = HERE / "data"
CONFIG_FILE = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "panel.db"
SECRET_FILE = DATA_DIR / "secret_key"

DATA_DIR.mkdir(parents=True, exist_ok=True)
try:
    # Owner-only: no other local user can even enter data/, so the DB, keys, backups and config
    # inside are unreachable by another unprivileged account on the box (defence in depth against a
    # compromised co-tenant / service). Runs on every import so existing installs get tightened too.
    # 0o700 IS the least-privilege setting here (owner-only rwx; a dir needs the owner execute bit to
    # be traversable) — the Semgrep insecure-file-permissions heuristic misreads the literal.
    os.chmod(DATA_DIR, 0o700)  # nosemgrep
except OSError:
    _log.debug("could not chmod data dir to 0700", exc_info=True)

DEFAULT_CONFIG = {
    "site_title": "LinuxGSM Panel",
    "site_domain": "",
    "login_tagline": "",       # subtitle under the site name on the login page ("" = built-in default)
    "accent_color": "",        # brand accent as #RRGGBB ("" = built-in green); validated before use
    "default_language": "en",  # UI language new users start in; always a concrete language code
    "setup_complete": False,
    "port": 5000,
    "bind_host": "",   # empty = auto (127.0.0.1 if Tailscale can proxy, else 0.0.0.0)
    "session_lifetime_hours": 8,    # idle session timeout (sliding, refreshed each request)
    "remember_days": 3,             # "remember me" cookie lifetime
    "ssh_timeout": 10,
    "session_protection": "strong", # flask-login: "strong" | "basic" | null (IP+UA session binding)
    "use_https": True,              # serve self-signed HTTPS by default (unless Tailscale/proxy does TLS)
    "trust_proxy": False,           # behind a reverse proxy (Caddy/nginx/Cloudflare Tunnel)? trust X-Forwarded-*
    "tailscale_auto_setup": True,       # Auto-configure Tailscale Serve on first start
    "tailscale_use_funnel": False,       # Expose panel publicly via Tailscale Funnel
    "tailscale_mount": "/",              # URL mount point (usually "/" or "/lgsm-panel")
    "tailscale_setup_done": False,       # Whether Tailscale Serve has been configured
    # Days after which an audit entry's IP is reduced to its network prefix. The row itself is
    # KEPT — the security history is the point of the log — only the part that identifies a
    # household or a person goes. 90 is a default, not a standard: it is long enough to
    # investigate an incident found late and short enough that the table is not an indefinite
    # record of where each admin was. 0 disables it and keeps full IPs forever.
    "audit_ip_retention_days": 90,
}


# Cache the parsed config keyed by the file's (mtime, size). load_config() is called
# a few times per request; this avoids re-reading + re-parsing the JSON every time,
# while an mtime/size change (from save_config or an external edit) transparently
# refreshes it. Each call returns a DEEP copy, so a caller that edits a nested section
# in place (notifications._drop_master_switch does exactly that) mutates its own copy
# and not the shared cache — a plain dict.update() only copies the top level, which
# left an unsaved edit visible to every later reader if the subsequent write failed.
# The config is a few dozen small keys, so the copy is not worth optimising away.
_cfg_cache = {"key": None, "data": {}}
# Serialises config writes (and read-modify-write via update_config) so concurrent writers can't
# lose each other's updates or race on the temp file. Re-entrant so update_config can call save.
_write_lock = threading.RLock()


class ConfigUnreadable(Exception):
    """config.json EXISTS but could not be read or parsed into an object, so a write was refused.

    Its own exception because the only safe response is to leave the file alone. Every writer
    here is read-modify-write, and a read of an unusable file returns bare DEFAULT_CONFIG; saving
    that replaced the operator's config with the defaults plus one key — the encrypted backup
    passphrase, the login whitelist, the notification tokens, the bind and the port all gone, on
    the next background tick after one trailing comma in a hand edit.
    """


class UnreadableConfig(dict):
    """The defaults load_config() hands back when config.json is THERE but unusable.

    A dict like any other, so every reader keeps working on defaults exactly as before. What it
    adds is provenance that travels with the value: save_config refuses to write one back, and a
    caller that must not act on defaults (the backup passphrase, the health check) can ask
    is_unreadable() instead of reading "not configured" out of a file it could not read. Carried
    on the value rather than re-checked on disk, because the read that failed may have been a
    transient OSError that a second look would not see.
    """


def is_unreadable(cfg):
    """True when `cfg` came from a config.json that exists but could not be read."""
    return isinstance(cfg, UnreadableConfig)


def config_unreadable():
    """True when config.json EXISTS on disk now but does not parse into an object.

    Not "load_config would return defaults": a host with no config.json yet is a normal state and
    defaults really are the answer there.
    """
    try:
        with open(CONFIG_FILE) as f:
            return not isinstance(json.load(f), dict)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True


def autoblock_host_ids(raw):
    """config.json's autoblock_hosts as a set of remote ids; empty for anything not a list of ints.

    config.json is hand-editable, and `set(5)` or `set([[1]])` raised TypeError out of every
    caller — the hourly loop (which died of it), the Security tab, the toggle. The panel itself
    only ever writes a sorted list of ints, so anything else in it is not an id it stored.
    """
    if not isinstance(raw, list):
        return set()
    return {h for h in raw if isinstance(h, int) and not isinstance(h, bool)}


def _r13a_cfg_text(cfg, key, default=""):
    """config.json's `key` when it holds a string, else `default`.

    For a text setting read on every request or at boot (the mount, the bind, the tagline, the
    site domain). The panel only ever writes strings there, but config.json is hand-editable, and
    `(5 or "").strip()` raised AttributeError out of every page, the socket handshake or the boot
    itself. Not a string: not a value the panel stored, so it reads as unset.
    """
    value = cfg.get(key, default)
    return value if isinstance(value, str) else default


def _r15a_cfg_int(value, default):
    """A number setting read from config.json, as an int; `default` when it is not one.

    The same hand-edit class as _r13a_cfg_text, for numbers. Python's json reads `Infinity` and
    `1e400` as float('inf'), and int() of that raises OverflowError, which an
    `except (TypeError, ValueError)` lets through: the Backups page, the Settings page and the
    auto-block pass each answered 500 or stopped for good. A JSON boolean is refused too: int(True)
    is 1, so a hand-edited `true` read as a one-attempt auto-block threshold or a one-day backup
    retention. The panel only ever writes a number there, so anything else reads as unset.
    """
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


# The on/off settings, read everywhere as `bool(cfg.get(k))` or `if cfg.get(k):`. config.json is
# hand-editable and the README tells people to set `trust_proxy` there; a quoted "false" is a
# non-empty string, so it read as ON (a panel trusting X-Forwarded-For from anyone, a reboot
# restoring servers the operator said to leave stopped). load_config hands every reader a bool.
# cookie_secure is the one docs/https.md tells operators to set by hand: a quoted "false" reached
# Flask as a string, Werkzeug wrote `Secure=false`, and a browser treats ANY Secure attribute as
# Secure, so a plain-HTTP panel looped back to /login. It has no DEFAULT_CONFIG entry on purpose:
# an unreadable value is dropped and create_app falls back to the computed _https_ready answer.
_R16A_FLAG_KEYS = ("setup_complete", "use_https", "trust_proxy", "tailscale_auto_setup",
                   "tailscale_use_funnel", "tailscale_setup_done", "backup_enabled",
                   "reboot_restore_no_autostart", "cookie_secure")
_R16A_FLAG_WORDS = {"true": True, "yes": True, "on": True, "1": True,
                    "false": False, "no": False, "off": False, "0": False, "": False}


def _r16a_flags(config):
    """Make each on/off setting in `config` a bool, in place; one it cannot read takes its default.

    A real bool is kept. "false"/"no"/"off"/"0" (any case) and 0 (or 0.0) are False, their
    opposites True. int() first: str(0.0) is "0.0", no word, so a hand-written 0.0 took the default.
    Anything else is as if unset: DEFAULT_CONFIG's value, or no key (the reader's own default).
    """
    for key in _R16A_FLAG_KEYS:
        if key not in config or isinstance(config[key], bool):
            continue
        v = config[key]
        word = v.strip().lower() if isinstance(v, str) else (str(int(v)) if v in (0, 1) else None)
        if word in _R16A_FLAG_WORDS:
            config[key] = _R16A_FLAG_WORDS[word]
        elif key in DEFAULT_CONFIG:
            config[key] = DEFAULT_CONFIG[key]
        else:
            del config[key]
    return config


def _r26a_port(config):
    """Make config["port"] the port the panel binds, in place, so every reader agrees with it.

    The boot's own reading (app.py's `_port_or(..., 5000)`). A hand-edited 0, 70000, -1 or `true` made the boot bind 5000 while everything else read the raw
    value: fail2ban's login jail went to port 0, the firewall guard stopped protecting the rule for
    the port the panel really listens on (a plain delete on the only way in), the Tailscale steps
    asked the helper for a port it does not publish, and the debug report said "restart pending"
    for good. Lazily imported: validation imports i18n, which imports Flask.
    """
    from panel.core.validation import _port_or
    config["port"] = _port_or(config.get("port"), DEFAULT_CONFIG["port"])
    return config


def _r29a_whitelist(config):
    """Make config["security_whitelist"] a list of strings, in place, when the key is there.

    Every reader iterates it (`list(cfg.get(...) or [])`, banlist, the monitor), and config.json is
    hand-editable: `"security_whitelist": "203.0.113.5"` read as the characters '2', '0', '3', ...,
    none of which is an address, so fail2ban, every remote's jail, the auto-block and the Funnel
    ban gate all dropped the operator's own address without a word; the next Settings add then
    wrote those characters back as entries. A string is plainly one entry, as trusted_proxies
    reads it (auth._trusted_proxy_networks); any other non-list is no entry; a non-string item in
    a list names no address and is dropped.
    """
    if "security_whitelist" not in config:
        return config
    value = config["security_whitelist"]
    if isinstance(value, str):
        value = [value] if value.strip() else []
    elif not isinstance(value, list):
        value = []
    config["security_whitelist"] = [w for w in value if isinstance(w, str)]
    return config


def load_config():
    config = dict(DEFAULT_CONFIG)
    try:
        st = CONFIG_FILE.stat()
        key = (st.st_mtime_ns, st.st_size)
        if _cfg_cache["key"] != key:
            with open(CONFIG_FILE) as f:
                loaded = json.load(f)
            # A file that is VALID JSON but not an object is as unusable as a truncated one, and
            # config.json is explicitly hand-editable ("a file a human can hand-edit"). The except
            # below catches a malformed file; it does not catch `null`, `[1,2,3]`, `"hello"` or
            # `123`, each of which parses fine and then blows up inside dict.update — a TypeError
            # or ValueError out of a function on every request path and in every background
            # poller. Measured: a truncated file degrades to defaults, a stray `null` raises.
            # Rejected at PARSE time so it falls into the same defaults path, cache dropped so a
            # corrected file is picked up on the next call.
            if not isinstance(loaded, dict):
                raise ValueError("config.json is %s, not an object" % type(loaded).__name__)
            _cfg_cache["data"] = loaded
            _cfg_cache["key"] = key
        config.update(copy.deepcopy(_cfg_cache["data"]))
        _r16a_flags(config)
        _r26a_port(config)
        _r29a_whitelist(config)
    except FileNotFoundError:
        _cfg_cache["key"] = None   # no config.json yet: defaults ARE the configuration
    except (json.JSONDecodeError, ValueError, OSError):
        _cfg_cache["key"] = None   # unreadable/not-an-object → defaults, drop stale cache
        return UnreadableConfig(config)   # ...marked, so nothing writes them back over the file
    return config


def save_config(config):
    # Write atomically: a crash or a concurrent read must never see a half-written
    # config.json (a truncated file makes load_config() fall back to DEFAULTS, which
    # would lose setup_complete/port/etc. and boot the panel back to the setup wizard).
    # A UNIQUE temp file per write (mkstemp) means two concurrent writers never clobber a shared
    # temp; the lock serialises the replace. fsync + os.replace = atomic on the same FS.
    with _write_lock:
        # Refuse to replace a config.json that could not be read. The dict being saved was built
        # from defaults — either it says so itself (is_unreadable), or the file is unparseable on
        # disk right now, in which case no caller can have read it. The file is left exactly as
        # it is, so a hand-edit mistake stays a one-character fix instead of a lost config.
        if is_unreadable(config) or config_unreadable():
            _log.error("config.json exists but could not be read; refusing to overwrite it "
                       "with defaults — fix or restore %s", CONFIG_FILE)
            raise ConfigUnreadable("config.json exists but could not be read; it was not "
                                   "overwritten — fix or restore it")
        fd, tmp = tempfile.mkstemp(dir=str(CONFIG_FILE.parent), prefix=".config-", suffix=".tmp")
        os.close(fd)   # we only wanted a unique name; reopen by path (avoids eventlet fd wrapping)
        try:
            with open(tmp, "w") as f:
                json.dump(config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, CONFIG_FILE)
            tmp = None
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    _log.debug("save_config: temp cleanup failed", exc_info=True)
        _cfg_cache["key"] = None   # force a re-read on the next load_config()


def update_config(mutator):
    """Atomically read-modify-write config under the write lock.

    The lock means concurrent writers (HTTP handlers + background worker threads) can't lose each
    other's changes. `mutator(cfg)` mutates the dict in place. Returns the saved config.
    """
    with _write_lock:
        cfg = load_config()
        if is_unreadable(cfg):
            # Before the mutator, not only in save_config: a mutator can copy the dict, and the
            # copy would no longer carry the mark.
            raise ConfigUnreadable("config.json exists but could not be read; it was not "
                                   "overwritten — fix or restore it")
        mutator(cfg)
        save_config(cfg)
        return cfg


def set_config_keys(cfg, **changes):
    """Write `changes` to config.json under the write lock, and into the caller's `cfg` too.

    For a route that read the config, then spent time on a subprocess or SSH (which yields to
    other greenlets), then saved. save_config(cfg) wrote back the WHOLE dict it had read, so a key
    a background writer committed in that window — a game backup's clock, the announced panel
    update — was silently reverted. Only the keys this caller changed are written, onto the file
    as it is now; `cfg` is updated as well because the caller goes on reading it.
    """
    cfg.update(changes)

    def _apply(fresh):
        fresh.update(changes)
    return update_config(_apply)


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        _log.debug("_chmod600: ignored non-fatal error", exc_info=True)


def _create_key_once(path, gen_bytes):
    """Create `path` (mode 0600) containing gen_bytes() EXACTLY once.

    That holds even if several threads or processes race to create it on a fresh install. O_EXCL
    makes the create atomic: only one caller wins; everyone else gets FileExistsError and falls
    through to read the winner's key. This prevents two callers each generating a different key
    and clobbering the other — which, for cred_key, would silently make already-encrypted secrets
    undecryptable.

    The file APPEARS WITH ITS CONTENT, the way ensure_setup_token's does: written to a private
    temp file, then hard-linked into place (which, like O_EXCL, fails when the name exists). The
    O_EXCL create made the name first and wrote the key after, so a racer that lost the create and
    re-read at once read an EMPTY file — and on a fresh install there is exactly that race: the
    installer runs `manage.py setup-token` (create_app -> get_secret_key) while the service starts.
    The loser took "" as its Flask SECRET_KEY (no session could be signed for the life of that
    process) or handed Fernet an empty key (ValueError on every credential save). A crash between
    the create and the write left the same empty file behind for good; an empty file is therefore
    replaced here — nothing can have been signed or encrypted with an empty key.
    """
    path = str(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")   # 0600, owner only
    try:
        try:
            os.write(fd, gen_bytes())
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)
        except FileExistsError:
            _cfg_replace_if_empty(tmp, path)
        except OSError:
            # No hard links on this filesystem: the O_EXCL create as before — still create-once,
            # with the empty-read window back, which such a filesystem cannot avoid.
            _cfg_create_excl(tmp, path)
    finally:
        _cfg_unlink_key_tmp(tmp)


def _cfg_replace_if_empty(tmp, path):
    """_create_key_once lost the link race: take the name over only if the winner's file is EMPTY."""
    try:
        empty = os.path.getsize(path) == 0
    except OSError:
        empty = False
    if empty:
        os.replace(tmp, path)


def _cfg_create_excl(tmp, path):
    """_create_key_once without hard links: O_EXCL-create `path` (0600) and copy `tmp` into it."""
    try:
        xfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return      # someone else created it first; the caller re-reads it
    try:
        with open(tmp, "rb") as src:
            os.write(xfd, src.read())
        os.fsync(xfd)
    finally:
        os.close(xfd)


def _cfg_unlink_key_tmp(tmp):
    """Remove _create_key_once's temp file; gone already means it was renamed into place."""
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass            # renamed into place
    except OSError:
        _log.debug("_create_key_once: temp file not removed", exc_info=True)


def _key_missing(path):
    """True when a key file is absent or EMPTY (see _create_key_once for how an empty one arises)."""
    try:
        return os.path.getsize(path) == 0
    except OSError:
        return True


def get_secret_key():
    if _key_missing(SECRET_FILE):
        import secrets
        _create_key_once(SECRET_FILE, lambda: secrets.token_hex(32).encode())
    _chmod600(SECRET_FILE)  # tighten perms on existing installs too
    with open(SECRET_FILE) as f:
        return f.read().strip()


# ── The first-run wizard's one-time setup token ──
# Until the first admin exists the wizard is the whole panel, and it used to be open to whoever
# reached the port first — a default install opens that port itself. The operator is the one person
# who can read this host's data dir (the installer runs in their terminal), so the wizard answers
# only to a browser that has shown the token in this file. `manage.py setup-token` writes it and the
# installer prints the link carrying it; the app deletes it once the first admin exists. See
# app._setup_owner_ok for the gate itself.
SETUP_TOKEN_FILE = DATA_DIR / "setup_token"


def read_setup_token():
    """The current setup token, or "" when there is none (or it cannot be read).

    "" is never a token: the gate compares only when this is non-empty, so an unreadable file
    locks the wizard rather than opening it.
    """
    try:
        return SETUP_TOKEN_FILE.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return ""


def ensure_setup_token():
    """Return the setup token, creating data/setup_token (0600) first when there is none.

    The file appears with its content already in it: written to a private temp file and then
    hard-linked into place, which fails when the name exists. So two creators at once (the service
    and `manage.py setup-token`, which the installer runs) agree on ONE token, and nobody ever reads
    a half-written one. A file that exists but is empty or unreadable is replaced.
    """
    tok = read_setup_token()
    if tok:
        return tok
    import secrets
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".setup_token.")   # 0600, owner only
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secrets.token_urlsafe(24) + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, SETUP_TOKEN_FILE)
        except FileExistsError:
            if not read_setup_token():          # there, but empty or unreadable: replace it
                os.replace(tmp, SETUP_TOKEN_FILE)
        except OSError:
            # A filesystem without hard links: an atomic rename instead. It can replace a token a
            # concurrent creator has just written, which only means the one printed last is valid.
            os.replace(tmp, SETUP_TOKEN_FILE)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass            # already renamed into place
        except OSError:
            _log.debug("ensure_setup_token: temp file not removed", exc_info=True)
    return read_setup_token()


def remove_setup_token():
    """Delete the setup token; it is single-use. Returns whether one was there."""
    try:
        SETUP_TOKEN_FILE.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        _log.warning("could not delete %s; delete it by hand", SETUP_TOKEN_FILE, exc_info=True)
        return False


# ── Encryption for secrets stored in the DB (remote SSH passwords/key paths) ──
CRED_KEY_FILE = DATA_DIR / "cred_key"
_ENC_PREFIX = "enc:v1:"


def _cred_fernet():
    from cryptography.fernet import Fernet
    # Create-once (atomic, race-safe): two concurrent first-time credential saves must not each
    # generate a different key and clobber the other — that would leave the first-saved secret
    # encrypted with a key the file no longer holds, i.e. permanently undecryptable.
    if _key_missing(CRED_KEY_FILE):
        _create_key_once(CRED_KEY_FILE, Fernet.generate_key)
    return Fernet(CRED_KEY_FILE.read_bytes().strip())


def encrypt_secret(plaintext):
    """Encrypt a secret (SSH password / key path) for storage in panel.db.

    Encrypted so a leaked DB file doesn't hand over every remote's credentials. Empty stays empty.
    The key lives in data/cred_key (chmod 600), separate from the Flask secret_key so rotating the
    session key never orphans stored creds.
    """
    if not plaintext:
        return ""
    if is_encrypted(plaintext):
        return plaintext
    return _ENC_PREFIX + _cred_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(value):
    """Decrypt a stored secret.

    Legacy plaintext values (no prefix) are returned as-is so existing installs keep working until
    migrated.
    """
    if not value:
        return ""
    if is_encrypted(value):
        try:
            return _cred_fernet().decrypt(value[len(_ENC_PREFIX):].encode()).decode()
        except Exception:
            return ""
    return value


def _is_fernet_token(blob):
    """True if `blob` is STRUCTURALLY a Fernet token. Deliberately does NOT use the key.

    A decrypt-based check would be stronger but is the wrong trade here: with cred_key missing or
    rotated, every real ciphertext would read as plaintext, and the startup migration in app.py
    would re-encrypt it under a NEW key — destroying any chance of recovering it by restoring the
    original key. Structure is knowable without the key; decryptability is not.

    Fernet layout: 0x80 | 8-byte timestamp | 16-byte IV | AES-CBC ciphertext (16-byte blocks) |
    32-byte HMAC, base64url-encoded. 57 = 1 + 8 + 16 + 32, i.e. everything but the ciphertext.
    """
    try:
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    except Exception:
        return False
    return len(raw) >= 57 and raw[0] == 0x80 and (len(raw) - 57) % 16 == 0


def is_encrypted(value):
    """True only for something encrypt_secret() actually produced.

    The prefix alone is NOT enough. A secret that itself starts with "enc:v1:" was taken for
    ciphertext and stored verbatim — in plaintext, by the one function whose job is to prevent
    that — and then decrypted to "" forever, so the credential was both exposed and broken.
    Requiring the remainder to be shaped like a Fernet token closes that, and makes decrypt_secret
    hand such a value back unchanged (it is legacy plaintext) instead of losing it.
    """
    return (bool(value) and value.startswith(_ENC_PREFIX)
            and _is_fernet_token(value[len(_ENC_PREFIX):]))


def harden_data_permissions():
    """Tighten filesystem permissions on the data dir and every file in it that holds secrets.

    Idempotent — call it on every startup so existing installs are locked down too. The
    0700 on data/ is the real guard (another local user can't enter it at all); the per-file 0600s
    are defence in depth for the case a file is ever copied out of the dir. Best-effort: a chmod
    failure (e.g. odd filesystem) is logged, never fatal.
    """
    targets = [(DATA_DIR, 0o700), (DB_PATH, 0o600), (CONFIG_FILE, 0o600),
               (SECRET_FILE, 0o600), (CRED_KEY_FILE, 0o600), (SETUP_TOKEN_FILE, 0o600),
               # SQLite's WAL/SHM side files carry the same rows as the DB.
               (Path(str(DB_PATH) + "-wal"), 0o600), (Path(str(DB_PATH) + "-shm"), 0o600),
               # ...and so do the rolling known-good backup and any copy moved aside after
               # corruption. models._ensure_db_healthy creates both with sqlite3.connect / copy2,
               # i.e. at the process umask (0644 on a stock box) — every password hash and every
               # encrypted credential in the panel, in a file nothing was tightening.
               (Path(str(DB_PATH) + ".backup"), 0o600)]
    # The aside copies are timestamped, so they need a glob rather than a fixed name.
    targets += [(p, 0o600) for p in DATA_DIR.glob("panel.db.corrupt-*")]
    for path, mode in targets:
        try:
            if path.exists():
                os.chmod(path, mode)
        except OSError:
            _log.debug("harden_data_permissions: chmod %s failed", path, exc_info=True)
