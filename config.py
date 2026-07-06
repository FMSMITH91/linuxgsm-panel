"""Configuration management for LinuxGSM Panel."""
import json
import logging
import os
import tempfile
import threading
from pathlib import Path

_log = logging.getLogger("panel.config")

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"
CONFIG_FILE = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "panel.db"
SECRET_FILE = DATA_DIR / "secret_key"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_CONFIG = {
    "site_title": "LinuxGSM Panel",
    "site_domain": "",
    "instance_id": "",
    "setup_complete": False,
    "port": 5000,
    "bind_host": "",   # empty = auto (127.0.0.1 if Tailscale can proxy, else 0.0.0.0)
    "session_lifetime_hours": 8,    # idle session timeout (sliding, refreshed each request)
    "remember_days": 3,             # "remember me" cookie lifetime
    "ssh_timeout": 10,
    "session_protection": "strong", # flask-login: "strong" | "basic" | null (IP+UA session binding)
    "use_https": True,              # serve self-signed HTTPS by default (unless Tailscale/proxy does TLS)
    "trust_proxy": False,           # behind a reverse proxy (Caddy/nginx/Cloudflare Tunnel)? trust X-Forwarded-*
    "sudo_enabled": False,
    "tailscale_auto_setup": True,       # Auto-configure Tailscale Serve on first start
    "tailscale_use_funnel": False,       # Expose panel publicly via Tailscale Funnel
    "tailscale_mount": "/",              # URL mount point (usually "/" or "/lgsm-panel")
    "tailscale_setup_done": False,       # Whether Tailscale Serve has been configured
}


# Cache the parsed config keyed by the file's (mtime, size). load_config() is called
# a few times per request; this avoids re-reading + re-parsing the JSON every time,
# while an mtime/size change (from save_config or an external edit) transparently
# refreshes it. Values are scalars and each call returns a fresh dict, so callers
# can't mutate the cache.
_cfg_cache = {"key": None, "data": {}}
# Serialises config writes (and read-modify-write via update_config) so concurrent writers can't
# lose each other's updates or race on the temp file. Re-entrant so update_config can call save.
_write_lock = threading.RLock()


def load_config():
    config = dict(DEFAULT_CONFIG)
    try:
        st = CONFIG_FILE.stat()
        key = (st.st_mtime_ns, st.st_size)
        if _cfg_cache["key"] != key:
            with open(CONFIG_FILE) as f:
                _cfg_cache["data"] = json.load(f)
            _cfg_cache["key"] = key
        config.update(_cfg_cache["data"])
    except (json.JSONDecodeError, OSError):
        _cfg_cache["key"] = None   # missing/unreadable → defaults, and drop stale cache
    return config


def save_config(config):
    # Write atomically: a crash or a concurrent read must never see a half-written
    # config.json (a truncated file makes load_config() fall back to DEFAULTS, which
    # would lose setup_complete/port/etc. and boot the panel back to the setup wizard).
    # A UNIQUE temp file per write (mkstemp) means two concurrent writers never clobber a shared
    # temp; the lock serialises the replace. fsync + os.replace = atomic on the same FS.
    with _write_lock:
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
    """Atomically read-modify-write config under the write lock, so concurrent writers (HTTP
    handlers + background worker threads) can't lose each other's changes. `mutator(cfg)` mutates
    the dict in place. Returns the saved config."""
    with _write_lock:
        cfg = load_config()
        mutator(cfg)
        save_config(cfg)
        return cfg


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        _log.debug("_chmod600: ignored non-fatal error", exc_info=True)


def get_secret_key():
    if SECRET_FILE.exists():
        _chmod600(SECRET_FILE)  # tighten perms on existing installs too
        with open(SECRET_FILE) as f:
            return f.read().strip()
    import secrets
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(key)
    _chmod600(SECRET_FILE)
    return key


# ── Encryption for secrets stored in the DB (remote SSH passwords/key paths) ──
CRED_KEY_FILE = DATA_DIR / "cred_key"
_ENC_PREFIX = "enc:v1:"


def _cred_fernet():
    from cryptography.fernet import Fernet
    if CRED_KEY_FILE.exists():
        key = CRED_KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        with open(CRED_KEY_FILE, "wb") as f:
            f.write(key)
        _chmod600(CRED_KEY_FILE)
    return Fernet(key)


def encrypt_secret(plaintext):
    """Encrypt a secret (SSH password / key path) for storage in panel.db so a leaked
    DB file doesn't hand over every remote's credentials. Empty stays empty. The key
    lives in data/cred_key (chmod 600), separate from the Flask secret_key so rotating
    the session key never orphans stored creds."""
    if not plaintext:
        return ""
    if plaintext.startswith(_ENC_PREFIX):
        return plaintext
    return _ENC_PREFIX + _cred_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(value):
    """Decrypt a stored secret. Legacy plaintext values (no prefix) are returned as-is
    so existing installs keep working until migrated."""
    if not value:
        return ""
    if value.startswith(_ENC_PREFIX):
        try:
            return _cred_fernet().decrypt(value[len(_ENC_PREFIX):].encode()).decode()
        except Exception:
            return ""
    return value


def is_encrypted(value):
    return bool(value) and value.startswith(_ENC_PREFIX)
