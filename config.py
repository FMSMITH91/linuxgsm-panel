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


def get_secret_key():
    if SECRET_FILE.exists():
        with open(SECRET_FILE) as f:
            return f.read().strip()
    import secrets
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(key)
    return key
