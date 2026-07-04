"""Configuration management for LinuxGSM Panel."""
import json
import os
from pathlib import Path

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
    "bind_host": "127.0.0.1",
    "session_lifetime_hours": 24,
    "ssh_timeout": 10,
    "sudo_enabled": False,
    "tailscale_auto_setup": True,       # Auto-configure Tailscale Serve on first start
    "tailscale_use_funnel": False,       # Expose panel publicly via Tailscale Funnel
    "tailscale_mount": "/",              # URL mount point (usually "/" or "/lgsm-panel")
    "tailscale_setup_done": False,       # Whether Tailscale Serve has been configured
}


def load_config():
    config = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                loaded = json.load(f)
                config.update(loaded)
        except (json.JSONDecodeError, OSError):
            pass
    return config


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


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
