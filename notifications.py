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
    "server_empty":       ("A server you flagged has emptied (per-server, set on its page)", True),
    "server_full":        ("A game server hits its player cap", False),
    "server_peak":        ("A game server sets a new player-count record", False),
    "remote_unreachable": ("A remote host becomes unreachable", True),
    "remote_recovered":   ("A remote host comes back", True),
    "high_load":          ("A host's CPU or memory is sustained high", True),
    "disk_low":           ("A host's disk is running low", True),
    "auto_reboot":        ("A host auto-reboots once empty (reboot-when-empty)", True),
    "backup_failed":      ("A backup fails", True),
    "update_available":   ("A panel update is available", True),
    "cert_expiring":      ("The panel's TLS certificate is expiring soon", True),
    "admin_login":        ("A super admin signs in", True),
    "admin_bruteforce":   ("A super admin account is being brute-forced", True),
    "account_change":     ("A user is created or a group's permissions change", True),
    "ip_banned":          ("fail2ban bans an IP on the panel login", False),
    "ban_spike":          ("A burst of fail2ban bans (attack wave)", True),
}

# A Discord webhook MUST live on Discord — never let an admin-set (or tampered) URL become an SSRF
# probe into internal services. Telegram uses the fixed api.telegram.org host, so it needs no such
# host check, but its token is format-validated so it can't rewrite the request path.
# A Discord webhook is parsed into its <id>/<token> and the request URL is then rebuilt from a
# CONSTANT host, so the host the panel connects to is never taken from user input (no SSRF). The id
# and token are charset-bounded, so the path can't traverse either.
_DISCORD_WEBHOOK_RE = re.compile(
    r"^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d{5,25})/([\w-]{1,120})$")
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
                     "has_token": bool(tg.get("token")), "accept_commands": bool(tg.get("accept_commands"))},
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
                     "chat_id": (telegram.get("chat_id") or "").strip()[:64], "token": tg_token or "",
                     "accept_commands": bool(telegram.get("accept_commands"))},
        "discord": {"enabled": bool(discord.get("enabled")), "webhook": dc_webhook or ""},
        "events": {k: bool(events.get(k, EVENTS[k][1])) for k in EVENTS},
    }
    save_config(cfg)


# ── senders ────────────────────────────────────────────────────
# Both request URLs the panel builds use one of these CONSTANT-host prefixes (Telegram's is a fixed
# literal; a Discord webhook is rebuilt onto discord.com below). _post re-checks the URL against them
# right before the request as an SSRF barrier — no user/admin-supplied value decides the host.
_ALLOWED_PREFIXES = ("https://api.telegram.org/", "https://discord.com/api/webhooks/")


def _discord_api_url(webhook):
    """Canonical https://discord.com/api/webhooks/<id>/<token> rebuilt from a validated webhook URL,
    or None if it isn't one. The host is a constant literal and the id/token are charset-checked, so
    nothing user-supplied controls where the request goes."""
    m = _DISCORD_WEBHOOK_RE.match(webhook or "")
    return "https://discord.com/api/webhooks/%s/%s" % (m.group(1), m.group(2)) if m else None


def _valid_discord_webhook(url):
    return _DISCORD_WEBHOOK_RE.match(url or "") is not None


def _post(url, data, headers):
    """POST to a validated https URL. Returns (ok, reason): ok is True on a 2xx. `reason` is a FIXED
    word describing the outcome — 'sent' / 'rejected' (the provider answered with an error status) /
    'unreachable' (couldn't connect) / 'blocked' (host not allow-listed). It carries no data read
    back from the response, so this can never become an SSRF exfiltration sink. Never raises."""
    # SSRF barrier at the sink: the URL must start with one of our known-provider prefixes, so a
    # user/admin-supplied URL can never make this request hit an internal or arbitrary host.
    if not (url or "").startswith(_ALLOWED_PREFIXES):
        return False, "blocked"
    # NOTE (reviewed): CodeQL flags py/partial-ssrf here because a URL path segment (the Telegram bot
    # token / Discord webhook token) originates from a request. It is a false positive — the request
    # HOST is a hardcoded constant (built above from _ALLOWED_PREFIXES), and every path segment is
    # charset-validated (_TG_TOKEN_RE / _DISCORD_WEBHOOK_RE: only [A-Za-z0-9_-] and digits, no '/' or
    # '.'), so the path cannot traverse or redirect. The request can only ever reach the intended
    # provider's API endpoint.
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "linuxgsm-panel", **headers})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - https, host-allowlisted
            return (200 <= resp.getcode() < 300), "sent"
    except urllib.error.HTTPError:      # the provider answered with a 4xx/5xx
        return False, "rejected"
    except (urllib.error.URLError, OSError, ValueError):
        _log.debug("notification POST failed", exc_info=True)
        return False, "unreachable"


def send_telegram(token, chat_id, text):
    """Send a Telegram message. Returns (ok, detail). The token is format-validated so it can't
    rewrite the request path; chat_id + text are urlencoded into the body."""
    if not token or not _TG_TOKEN_RE.match(token):
        return False, "the bot token is missing or malformed"
    if not chat_id:
        return False, "the chat ID is missing"
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4000],
                                   "disable_web_page_preview": "true"}).encode()
    ok, reason = _post(url, body, {"Content-Type": "application/x-www-form-urlencoded"})
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach api.telegram.org — check the host's outbound network / firewall."
    return False, ("Telegram rejected it — the bot token or chat ID is wrong, or you haven't messaged "
                   "the bot yet. Re-copy the token from @BotFather, use your numeric ID from "
                   "@userinfobot, and press Start in the bot's chat.")


def telegram_get_updates(token, offset=None, timeout=25):
    """Long-poll Telegram for incoming messages (bot command input). Returns a list of update dicts
    (possibly empty) or None on error/timeout/conflict. SSRF-safe: the host is the fixed
    api.telegram.org literal and the token is format-validated, so nothing user-supplied decides
    where the request goes — only the JSON `result` array is read back. Never raises."""
    if not token or not _TG_TOKEN_RE.match(token):
        return None
    params = {"timeout": int(timeout)}
    if offset is not None:
        params["offset"] = int(offset)
    url = "https://api.telegram.org/bot%s/getUpdates?%s" % (token, urllib.parse.urlencode(params))
    if not url.startswith("https://api.telegram.org/"):   # SSRF barrier: constant-host prefix
        return None
    # NOTE (reviewed): as with _post, CodeQL may flag py/partial-ssrf because the bot token is a URL
    # path segment sourced from config. The HOST is the hardcoded api.telegram.org literal and the
    # token is charset-validated (_TG_TOKEN_RE: digits + [A-Za-z0-9_-], no '/' or '.'), so the path
    # can't traverse — the request can only ever reach Telegram's getUpdates endpoint.
    req = urllib.request.Request(url, headers={"User-Agent": "linuxgsm-panel"})
    try:
        with urllib.request.urlopen(req, timeout=timeout + 10) as resp:  # nosec B310 - https, host-literal
            data = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
        return (data.get("result") or []) if data.get("ok") else None
    except (urllib.error.URLError, OSError, ValueError):
        _log.debug("telegram getUpdates failed", exc_info=True)
        return None


# The bot's command menu — what Telegram shows when you type '/'. Keep in sync with the commands
# _handle_telegram_command actually handles.
TG_COMMANDS = [
    ("update", "Update the panel to the latest version"),
    ("status", "Panel version + server counts"),
    ("servers", "Per-server status + player counts"),
    ("help", "Show the command list"),
]


def telegram_set_commands(token, clear=False):
    """Register the bot's command list with Telegram (setMyCommands) so typing '/' pops the command
    menu — or clear it when commands are turned off. Best-effort; returns True on success. SSRF-safe:
    goes through _post, whose host allow-list already covers api.telegram.org, and the token is
    format-validated."""
    if not token or not _TG_TOKEN_RE.match(token):
        return False
    cmds = [] if clear else [{"command": c, "description": d} for c, d in TG_COMMANDS]
    body = json.dumps({"commands": cmds}).encode()
    ok, _reason = _post("https://api.telegram.org/bot%s/setMyCommands" % token, body,
                        {"Content-Type": "application/json"})
    return ok


def send_discord(webhook, text):
    """Send a Discord webhook message. Returns (ok, detail). The URL is rebuilt onto a constant host
    from the validated webhook id/token, so the request can only ever go to Discord."""
    url = _discord_api_url(webhook)
    if not url:
        return False, "that isn't a valid discord.com webhook URL"
    ok, reason = _post(url, json.dumps({"content": text[:1900]}).encode(),
                       {"Content-Type": "application/json"})
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach discord.com — check the host's outbound network."
    return False, "Discord rejected it — the webhook URL is wrong or was deleted."


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


def test_send(kind, token=None, chat_id=None, webhook=None):
    """Synchronously send a test message to one channel. Uses the values passed from the form when
    given (so you can test BEFORE saving), else the saved config. (ok, message) — message carries the
    provider's actual error on failure."""
    cfg = _cfg()
    text = "🎮 LinuxGSM Panel — test alert. If you can read this, notifications are working."
    if kind == "telegram":
        tg = cfg.get("telegram") or {}
        tok = (token or "").strip() or decrypt_secret(tg.get("token") or "")
        chat = ((chat_id or "").strip() or (tg.get("chat_id") or "")).strip()
        if not tok:
            return False, "Enter the bot token first."
        if not _TG_TOKEN_RE.match(tok):
            return False, "That bot token isn't in the expected format (like 123456789:AA…)."
        if not chat:
            return False, "Enter the chat ID first. Message your bot once, then use your numeric chat ID."
        ok, detail = send_telegram(tok, chat, text)
        return (True, "Test message sent — check Telegram.") if ok \
            else (False, "Telegram error: %s" % (detail or "unknown"))
    if kind == "discord":
        wh = (webhook or "").strip() or decrypt_secret((cfg.get("discord") or {}).get("webhook") or "")
        if not wh:
            return False, "Enter the webhook URL first."
        if not _valid_discord_webhook(wh):
            return False, "That doesn't look like a Discord webhook URL."
        ok, detail = send_discord(wh, text)
        return (True, "Test message sent — check Discord.") if ok \
            else (False, "Discord error: %s" % (detail or "unknown"))
    return False, "Unknown channel."
