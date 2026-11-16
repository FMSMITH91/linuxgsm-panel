"""Link an account to its own Telegram chat, so the panel's bot sends that account its alerts there.

HOW A LINK IS MADE. The Account page asks for a one-time code (new_code) and opens the panel's bot in
Telegram as https://t.me/<bot>?start=<code>; pressing Start sends the bot "/start <code>" from the
person's own private chat. Whichever reads that message first claims the code for that chat: the
command bot's long poll when it is running (bots/telegram._tg_route_update), or, when it is not, a
read the Account page asks for while it waits (check_pending). The code is the proof: 128 random
bits, kept only as its SHA-256, good for CODE_TTL seconds and once (OWASP Forgot Password Cheat Sheet,
"URL Tokens": random, single-use, short-lived, stored hashed). Only a private chat can claim one, so a
group never receives one person's alerts.

WHAT A LINKED CHAT GETS. The same alerts, with the same short text, that the account's browsers get
(push_alerts decides who gets what, at send time). The chat can send no commands: the command bot
still answers only the chat on the Notifications page.
"""
import hashlib
import secrets
import threading
import time

from panel.core.config import decrypt_secret

CODE_TTL = 600                 # seconds a link code stays good
CODES_MAX = 5                  # codes one account may ask for per CODE_TTL
_PENDING = {}                  # sha256(code) -> (user id, expiry)
_ASKED = {}                    # user id -> [times codes were made]
_LOCK = threading.Lock()


def _digest(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def bot_token():
    """The panel's bot token when the Telegram channel is on and has one, else ""."""
    from panel.services import notifications
    tg = notifications._cfg().get("telegram") or {}
    return decrypt_secret(tg.get("token") or "") if tg.get("enabled") else ""


def new_code(user_id, now=None):
    """A fresh one-time code for `user_id`, or None when it asked for CODES_MAX within CODE_TTL."""
    now = time.time() if now is None else now
    with _LOCK:
        for d in [d for d, (_u, exp) in _PENDING.items() if exp <= now]:
            del _PENDING[d]
        asked = [t for t in _ASKED.get(user_id, []) if t > now - CODE_TTL]
        if len(asked) >= CODES_MAX:
            _ASKED[user_id] = asked
            return None
        _ASKED[user_id] = asked + [now]
        code = secrets.token_urlsafe(16)          # 22 characters of [A-Za-z0-9_-]: a valid start payload
        _PENDING[_digest(code)] = (user_id, now + CODE_TTL)
        return code


def claim(code, chat_id, chat_type, now=None):
    """The user id a valid, unexpired, unused `code` was made for, now spent; None otherwise.

    Only from a private chat with a numeric id: a group or channel claims nothing.
    """
    now = time.time() if now is None else now
    chat_id = str(chat_id or "")
    if chat_type != "private" or not (chat_id.isascii() and chat_id.lstrip("-").isdecimal()) or not code or len(code) > 64:
        return None
    with _LOCK:
        hit = _PENDING.pop(_digest(code), None)
    if hit is None or hit[1] <= now:
        return None
    return hit[0]


def start_payload(text):
    """The code in a "/start <code>" message (also "/start@bot <code>"), or ""."""
    parts = (text or "").strip().split()
    if len(parts) != 2 or parts[0].split("@", 1)[0] != "/start":
        return ""
    return parts[1]


def link(app, user_id, chat_id):
    """Store `chat_id` as `user_id`'s Telegram chat, audited and told to the account. True on success."""
    from panel.db.models import User, db
    from panel.security.auth import log_action
    with app.app_context():
        user = db.session.get(User, user_id)
        if user is None or not user.is_active:
            return False
        user.telegram_chat = str(chat_id)
        db.session.commit()
        log_action(user, "telegram_link", target=user.username, detail="Telegram chat linked for alerts")
        return True


def handle_update(app, token, msg):
    """A polled message: when it is "/start <valid code>" from a private chat, link it and say so. True if handled."""
    from panel.services import notifications
    code = start_payload(msg.get("text"))
    if not code:
        return False
    chat = msg.get("chat") or {}
    uid = claim(code, chat.get("id"), chat.get("type"))
    if uid is None or not link(app, uid, chat.get("id")):
        return False
    notifications.send_telegram(token, str(chat.get("id")),
                                "Linked. This chat now gets your panel alerts. Unlink it from your Account page.")
    return True


def check_pending(app):
    """Read the bot's waiting messages once and link any that carry a code. Only while its long poll is off.

    The command bot's poll confirms each message it reads, so when it runs it does the linking itself
    and a second reader would race it (Telegram answers a second poller 409).
    """
    from panel.services import notifications
    from panel.services.bots import telegram as tgbot
    token, _chat, state = tgbot._tg_settings()
    if state == "on" or not token:
        return 0
    updates = notifications.telegram_get_updates(token, offset=None, timeout=0) or []
    n = 0
    for upd in updates:
        if handle_update(app, token, upd.get("message") or {}):
            n += 1
    return n


def reset():
    """Forget every pending code and request count (tests)."""
    with _LOCK:
        _PENDING.clear()
        _ASKED.clear()
