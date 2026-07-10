"""Proactive admin notifications to Telegram and/or Discord.

The panel already lets you configure a game's own LinuxGSM alerts; this is the panel telling YOU, the
admin, when something needs attention — a server dropped, a host went unreachable, a backup failed, a
super admin signed in, an IP was banned, a disk is filling up.

Best-effort and non-blocking: a send happens on a background thread and a failure is logged and
swallowed, never propagated to the caller (an alert must never break the action that triggered it).
Secrets (the bot token, the webhook URL) are Fernet-encrypted at rest via config.encrypt_secret.
"""
import json
import logging
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

from config import load_config, save_config, encrypt_secret, decrypt_secret

_log = logging.getLogger("notifications")

# Events an admin can toggle, in display order: key -> (label, default_on).
EVENTS = {
    "server_down":        ("A game server goes offline unexpectedly", True),
    "server_up":          ("A game server comes back online", False),
    "remote_unreachable": ("A remote host becomes unreachable", True),
    "remote_recovered":   ("A remote host comes back", True),
    "backup_failed":      ("A backup fails", True),
    "admin_login":        ("A super admin signs in", True),
    "ip_banned":          ("fail2ban bans an IP on the panel login", False),
    "disk_low":           ("A host's disk is running low", True),
}

# A Discord webhook MUST live on Discord — never let an admin-set (or tampered) URL become an SSRF
# probe into internal services. Telegram uses the fixed api.telegram.org host, so it needs no such
# host check, but its token is format-validated so it can't rewrite the request path.
_DISCORD_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")
_TG_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")


# ── config read/write ──────────────────────────────────────────
def _cfg():
    return load_config().get("notifications") or {}


def event_enabled(cfg, key):
    events = cfg.get("events") or {}
    return bool(events.get(key, EVENTS.get(key, ("", False))[1]))


def settings_for_form():
    """Current settings with secrets masked (so the token/webhook are never re-sent to the browser)."""
    cfg = _cfg()
    tg = cfg.get("telegram") or {}
    dc = cfg.get("discord") or {}
    return {
        "enabled": cfg.get("enabled", True),
        "telegram": {"enabled": bool(tg.get("enabled")), "chat_id": tg.get("chat_id") or "",
                     "has_token": bool(tg.get("token"))},
        "discord": {"enabled": bool(dc.get("enabled")), "has_webhook": bool(dc.get("webhook"))},
        "events": {k: event_enabled(cfg, k) for k in EVENTS},
    }


def save_settings(*, enabled, telegram, discord, events):
    """Persist settings, encrypting secrets. `telegram`/`discord` secrets that come in as None mean
    'keep the stored value' (the form never round-trips the real secret back)."""
    cur = _cfg()
    cur_tg = cur.get("telegram") or {}
    cur_dc = cur.get("discord") or {}
    tg_token = cur_tg.get("token") if telegram.get("token") is None else encrypt_secret(telegram["token"])
    dc_webhook = cur_dc.get("webhook") if discord.get("webhook") is None else encrypt_secret(discord["webhook"])
    cfg = load_config()
    cfg["notifications"] = {
        "enabled": bool(enabled),
        "telegram": {"enabled": bool(telegram.get("enabled")),
                     "chat_id": (telegram.get("chat_id") or "").strip()[:64], "token": tg_token or ""},
        "discord": {"enabled": bool(discord.get("enabled")), "webhook": dc_webhook or ""},
        "events": {k: bool(events.get(k, EVENTS[k][1])) for k in EVENTS},
    }
    save_config(cfg)


# ── senders ────────────────────────────────────────────────────
def _valid_discord_webhook(url):
    try:
        p = urllib.parse.urlparse(url or "")
    except (ValueError, TypeError):
        return False
    return p.scheme == "https" and p.hostname in _DISCORD_HOSTS and "/api/webhooks/" in p.path


def _post(url, data, headers):
    """POST bytes to a validated https URL; True on a 2xx. Never raises."""
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "linuxgsm-panel", **headers})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - https, host/format validated
            return 200 <= resp.getcode() < 300
    except (urllib.error.URLError, OSError, ValueError):
        _log.debug("notification POST failed", exc_info=True)
        return False


def send_telegram(token, chat_id, text):
    """Send a Telegram message. The token is format-validated so it can't rewrite the request path;
    chat_id + text are urlencoded into the body."""
    if not token or not chat_id or not _TG_TOKEN_RE.match(token):
        return False
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4000],
                                   "disable_web_page_preview": "true"}).encode()
    return _post(url, body, {"Content-Type": "application/x-www-form-urlencoded"})


def send_discord(webhook, text):
    """Send a Discord webhook message. The URL must be a discord.com webhook (SSRF guard)."""
    if not _valid_discord_webhook(webhook):
        if webhook:
            _log.warning("discord webhook rejected: not a discord.com /api/webhooks/ URL")
        return False
    return _post(webhook, json.dumps({"content": text[:1900]}).encode(), {"Content-Type": "application/json"})


# ── public API ─────────────────────────────────────────────────
def notify(event_key, title, body=""):
    """Fire an alert for `event_key` to every enabled channel, in the background. No-op when
    notifications (or this event) are off, or no channel is configured. Never raises."""
    try:
        cfg = _cfg()
        if not cfg.get("enabled", True) or not event_enabled(cfg, event_key):
            return
        text = "🎮 LinuxGSM Panel — %s" % title + (("\n%s" % body) if body else "")
        tg = cfg.get("telegram") or {}
        dc = cfg.get("discord") or {}

        def _go():
            try:
                if tg.get("enabled"):
                    send_telegram(decrypt_secret(tg.get("token") or ""), (tg.get("chat_id") or "").strip(), text)
                if dc.get("enabled"):
                    send_discord(decrypt_secret(dc.get("webhook") or ""), text)
            except Exception:
                _log.debug("notify send failed", exc_info=True)
        threading.Thread(target=_go, daemon=True).start()
    except Exception:
        _log.debug("notify failed to dispatch", exc_info=True)


def test_send(kind):
    """Synchronously send a test message to one channel. (ok, message)."""
    cfg = _cfg()
    text = "🎮 LinuxGSM Panel — test alert. If you can read this, notifications are working."
    if kind == "telegram":
        tg = cfg.get("telegram") or {}
        token, chat = decrypt_secret(tg.get("token") or ""), (tg.get("chat_id") or "").strip()
        if not token or not chat:
            return False, "Set the bot token and chat ID first (and Save)."
        if not _TG_TOKEN_RE.match(token):
            return False, "That bot token isn't in the expected format."
        return (True, "Test message sent.") if send_telegram(token, chat, text) \
            else (False, "Telegram rejected it — double-check the token and chat ID.")
    if kind == "discord":
        wh = decrypt_secret((cfg.get("discord") or {}).get("webhook") or "")
        if not wh:
            return False, "Set the webhook URL first (and Save)."
        if not _valid_discord_webhook(wh):
            return False, "That doesn't look like a Discord webhook URL."
        return (True, "Test message sent.") if send_discord(wh, text) \
            else (False, "Discord rejected it — double-check the webhook URL.")
    return False, "Unknown channel."
