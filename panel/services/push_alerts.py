"""The panel's alerts on a user's own browsers and phones, as Web Push notifications.

notifications.notify() hands every alert here as well as to the panel-wide channels, and log_action
hands the changes to an account's own security (account_notices) here too, so "your password was
changed" reaches the person whose password it is, even signed out, even with the panel tab closed.

WHO GETS WHAT, decided when the push is SENT, not when it was queued (OWASP Authorization Cheat Sheet,
"Validate the Permissions on Every Request", "Deny by Default"): an active account, with the event
among the ones it chose, and allowed to see what the event is about: a game server it can access
(can_access_server), a host it was granted (can_access_remote), and anything panel-wide (backups,
updates, sign-ins, bans, other accounts) superadmins only. An account removed from a server's group,
deactivated or deleted between the alert and the send gets nothing.

WHAT A PUSH SAYS: what a lock screen may show. The event's short title and the server's or host's
name; never an address, a player, a username of someone else, a token or anything read from a file.
The panel-wide channels keep their fuller text; a push is a pointer back into the panel, and clicking
it opens the page the alert is about.

Sends run on one background thread fed by a bounded queue (the request or monitor pass that raised the
alert never waits on a push service), and a burst for one device is folded into a single notification.
"""
import hashlib
import logging
import queue
import threading
import time
from collections import deque

from panel.core import i18n
from panel.core.clock import utcnow
from panel.services import webpush

# Under "panel", like the panel's other modules: that is the logger debug_report/errors.py gives the
# journal (WARNING and up), the debug-report counter and the opt-in debug log. A logger outside it has
# no handler, so its INFO lines went nowhere and its WARNINGs only reached Python's last-resort print.
_log = logging.getLogger("panel.push_alerts")

SERVER_EVENTS = frozenset({"server_down", "server_up", "server_empty", "server_full", "server_peak"})
HOST_EVENTS = frozenset({"remote_unreachable", "remote_recovered", "high_load", "disk_low"})
MY_ACCOUNT = "my_account"
MY_ACCOUNT_LABEL = "A change to your own account's security (password, two-factor, API token, a new alert device)"
# The important ones, on until the user says otherwise: a crash, a host gone, an attack, an account change.
DEFAULT_EVENTS = frozenset({"server_down", "remote_unreachable", "admin_bruteforce", "account_locked",
                            "credential_change", "ban_spike", MY_ACCOUNT})
_URGENT = frozenset({"server_down", "remote_unreachable", "admin_bruteforce", "account_locked", "ban_spike",
                     MY_ACCOUNT})

DEVICE_MAX = 10                 # alert devices one account may have
TEST_MAX, TEST_WINDOW = 3, 600  # test alerts per account per ten minutes
TTL_ALERT = 6 * 3600            # how long a push service holds an alert for a device that is offline
TTL_TEST = 600
_FOLD_AT = 3                    # more alerts than this for one device in one batch: one summary instead
_NAME_MAX = 60

# (title, body) per event; {server} / {host} are the object's name. Each sentence is in the catalogs.
_TEXT = {
    "server_down": ("Server offline", "{server} went offline unexpectedly."),
    "server_up": ("Server back online", "{server} is back online."),
    "server_empty": ("Server is empty", "{server} has no players now."),
    "server_full": ("Server full", "{server} is full."),
    "server_peak": ("New player record", "{server} set a new player record."),
    "remote_unreachable": ("Host unreachable", "{host} stopped responding."),
    "remote_recovered": ("Host back online", "{host} is responding again."),
    "high_load": ("Host under load", "{host} is under sustained load."),
    "disk_low": ("Disk running low", "{host} is running low on disk space."),
    "auto_reboot": ("Host auto-rebooting", ""),
    "host_reboot": ("Host reboot", ""),
    "backup_failed": ("Backup failed", ""),
    "update_available": ("Panel update available", ""),
    "os_updates": ("OS updates waiting", ""),
    "cert_expiring": ("TLS certificate expiring", ""),
    "admin_login": ("Super admin signed in", ""),
    "admin_bruteforce": ("A super admin account is being brute-forced", ""),
    "account_change": ("A user or group changed", ""),
    "credential_change": ("Administrator account changed", ""),
    "account_locked": ("Sign-ins paused for an account", ""),
    "twofa_enforced": ("Two-factor setup required", ""),
    "ip_banned": ("IP banned on the panel login", ""),
    "ban_spike": ("Login attack in progress", ""),
}
_OPEN_PANEL = "Open the panel for details."
_ACCOUNT_TITLE = "Your account changed"
_TEST_TITLE = "Test alert"
_TEST_BODY = "Alerts reach this device."
_FOLDED_TITLE = "{n} alerts"
# The page a panel-wide alert opens, relative to the panel's root.
_PAGE = {"update_available": "settings", "backup_failed": "server-management", "admin_login": "logs",
         "admin_bruteforce": "logs", "account_locked": "logs", "ip_banned": "logs", "ban_spike": "logs",
         "account_change": "users", "credential_change": "logs", "twofa_enforced": "users"}

_QUEUE_MAX = 200
_BATCH_MAX = 50
_queue = queue.Queue(maxsize=_QUEUE_MAX)
_lock = threading.Lock()
_sender = [False]
_APP = [None]
_TESTS = {}
_TESTS_LOCK = threading.Lock()


def register(app):
    """Remember the app the sender opens its database context in (the routes call this)."""
    _APP[0] = app


def endpoint_hash(endpoint):
    """The SHA-256 hex digest a subscription is found by (PushSubscription.endpoint_hash)."""
    return hashlib.sha256(str(endpoint or "").encode("utf-8")).hexdigest()


# ── what a user may choose ────────────────────────────────────────────────────────────────────────
def available_events(user):
    """[(key, label)] of the alerts `user` could be pushed: every event for a superadmin, else theirs."""
    from panel.services.notifications import EVENTS
    out = [(MY_ACCOUNT, MY_ACCOUNT_LABEL)]
    if user.is_superadmin:
        return out + [(k, v[0]) for k, v in EVENTS.items()]
    from panel.security.auth import accessible_remote_ids
    hosts = bool(accessible_remote_ids(user))
    return out + [(k, v[0]) for k, v in EVENTS.items()
                  if k in SERVER_EVENTS or (hosts and k in HOST_EVENTS)]


def chosen_events(user):
    """The event keys `user` chose to be pushed (DEFAULT_EVENTS until they choose)."""
    try:
        saved = user.get_ui_prefs().get("push_events")
    except Exception:  # noqa: BLE001 - a bad blob is the default, never a failed send
        saved = None
    if not isinstance(saved, list):
        return set(DEFAULT_EVENTS)
    return {k for k in saved if isinstance(k, str)}


def save_events(user, keys):
    """Store the subset of `keys` that `user` may choose. Caller commits."""
    allowed = [k for k, _label in available_events(user)]
    want = {k for k in (keys or []) if isinstance(k, str)}
    user.set_ui_pref("push_events", [k for k in allowed if k in want])


# ── subscriptions ─────────────────────────────────────────────────────────────────────────────────
def parse_subscription(data):
    """(endpoint, p256dh, auth) from a browser's PushSubscription JSON, or (None, why)."""
    if not isinstance(data, dict):
        return None, "That isn't a push subscription."
    endpoint = data.get("endpoint")
    keys = data.get("keys") if isinstance(data.get("keys"), dict) else {}
    if webpush.parse_endpoint(endpoint) is None:
        return None, "This browser's push service isn't one the panel sends to."
    p256dh = webpush.b64url_decode(keys.get("p256dh"))
    auth = webpush.b64url_decode(keys.get("auth"))
    if p256dh is None or auth is None or len(auth) != 16 or len(p256dh) != 65 or not _on_curve(p256dh):
        return None, "This browser's push keys aren't usable."
    return (endpoint, webpush.b64url(p256dh), webpush.b64url(auth)), ""


def _on_curve(raw):
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        return False
    return True


# subscribe()'s answer when the endpoint is another active account's and the request does not prove it
# holds that subscription. The route tells it from other refusals by this exact text (409, audited).
TAKEN = ("This browser's alerts belong to another account. Sign in as that account and turn them off "
         "there (or remove the device from its Account page), then try again.")


def subscribe(user, data, label):
    """Store (or refresh) this browser's subscription for `user`. -> (row, error message).

    An endpoint already stored for another ACTIVE account moves only when the request proves it holds
    that very subscription: its p256dh key and auth secret match the stored ones (see _holds). A
    browser re-posting its own subscription always sends the same keys, so a second account turning
    alerts on in the same browser still can; knowing the endpoint URL alone (a leaked capability)
    cannot take another account's alerts away. An endpoint left by a deactivated or deleted account
    is free. Caller commits and audits; a refusal of this kind answers TAKEN.
    """
    from panel.db.models import PushSubscription, db
    parsed, why = parse_subscription(data)
    if parsed is None:
        return None, why
    endpoint, p256dh, auth = parsed
    digest = endpoint_hash(endpoint)
    row = PushSubscription.query.filter_by(endpoint_hash=digest).first()
    if row is not None and row.user_id != user.id and _owner_active(row) and not _holds(row, p256dh, auth):
        return None, TAKEN
    others = PushSubscription.query.filter(PushSubscription.user_id == user.id,
                                           PushSubscription.endpoint_hash != digest).count()
    if others >= DEVICE_MAX:
        return None, i18n.tr("You already have {n} alert devices. Remove one first.", n=DEVICE_MAX)
    if row is None:
        row = PushSubscription(endpoint_hash=digest, endpoint=endpoint)
        db.session.add(row)
    row.user_id, row.p256dh, row.auth, row.label = user.id, p256dh, auth, (label or "")[:80]
    return row, ""


def _owner_active(row):
    """Whether the account holding `row` exists and is active (a deactivated or deleted one's is free)."""
    from panel.db.models import User, db
    owner = db.session.get(User, row.user_id)
    return owner is not None and bool(owner.is_active)


def _holds(row, p256dh, auth):
    """Whether the posted browser keys are the stored ones: proof the request holds that subscription.

    The auth secret is 16 random bytes the browser made and only this panel was given; it is never
    shown to anyone, so an attacker with the endpoint URL alone cannot produce it. Compared in
    constant time.
    """
    import hmac
    return (hmac.compare_digest(str(row.p256dh or ""), p256dh)
            and hmac.compare_digest(str(row.auth or ""), auth))


def find(user, endpoint):
    """`user`'s subscription for `endpoint`, or None."""
    from panel.db.models import PushSubscription
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > webpush.ENDPOINT_MAX:
        return None
    return PushSubscription.query.filter_by(endpoint_hash=endpoint_hash(endpoint), user_id=user.id).first()


def drop_user(user_id):
    """Delete every subscription of an account (deactivated). Caller commits."""
    from panel.db.models import PushSubscription
    PushSubscription.query.filter_by(user_id=user_id).delete(synchronize_session=False)


def test_allowed(user_id, now=None):
    """Whether `user_id` may send another test alert now (TEST_MAX per TEST_WINDOW); counts it if so."""
    now = time.monotonic() if now is None else now
    with _TESTS_LOCK:
        times = _TESTS.setdefault(user_id, deque())
        while times and now - times[0] > TEST_WINDOW:
            times.popleft()
        if len(times) >= TEST_MAX:
            return False
        times.append(now)
        return True


def reset_tests():
    """Forget every test-alert count (for the unit suite)."""
    with _TESTS_LOCK:
        _TESTS.clear()


def card(user):
    """What the Account page's alerts card shows: the key, this account's devices and its choices."""
    from panel.db.models import PushSubscription
    from panel.security import account_guard
    rows = user.push_subscriptions.order_by(PushSubscription.id).all()
    chosen = chosen_events(user)
    return {"key": webpush.vapid_public_key(), "reauth": account_guard.step_up_needed(),
            "devices": [{"id": r.id, "label": r.label or "", "hash": r.endpoint_hash,
                         "created": r.created_at, "last": r.last_success} for r in rows],
            "events": [(k, label, k in chosen) for k, label in available_events(user)],
            "max": DEVICE_MAX,
            "telegram": _telegram_card(user)}


def _telegram_card(user):
    """The Telegram part of the card: whether the panel's bot can link chats, and whether this account has one."""
    from panel.services import telegram_link
    return {"available": bool(telegram_link.bot_token()), "linked": bool(user.telegram_chat)}


# ── queueing (callers: notifications.notify, auth.log_action, the test route) ─────────────────────
def queue_event(event_key, server_id=None, remote_id=None):
    """Queue one alert for every device allowed and wanting it. Never raises."""
    _put(("event", event_key, server_id, remote_id))


def note_audit(action, target, success):
    """log_action's hook: a change to an account's own security pushes to that account's devices."""
    from panel.security.account_notices import _CHANGES
    if action in _CHANGES and (success or action == "login_locked") and target:
        _put(("account", action, str(target)))


def queue_test(user_id):
    """Queue a test alert to every device of `user_id`."""
    _put(("test", user_id))


def _put(item):
    if _APP[0] is None:
        return
    try:
        _queue.put_nowait(item)
    except queue.Full:
        _log.warning("push queue is full (%d waiting); an alert was dropped", _QUEUE_MAX)
        return
    with _lock:
        if _sender[0]:
            return
        _sender[0] = True
    try:
        threading.Thread(target=_drain, daemon=True, name="push-alerts").start()
    except Exception:  # noqa: BLE001 - an alert must never break the action that raised it
        with _lock:
            _sender[0] = False
        _log.debug("push sender could not start", exc_info=True)


def _take():
    with _lock:
        items = []
        while len(items) < _BATCH_MAX:
            try:
                items.append(_queue.get_nowait())
            except queue.Empty:
                break
        if not items:
            _sender[0] = False
        return items


def _drain():
    """The sender thread: deliver batches until the queue is empty, then stand down."""
    while True:
        items = _take()
        if not items:
            return
        app = _APP[0]
        try:
            with app.app_context():
                try:
                    deliver(items)
                finally:
                    from panel.db.models import db
                    db.session.remove()
        except Exception:  # noqa: BLE001 - the sender must keep the queue it owns moving
            _log.warning("push delivery failed", exc_info=True)


def flush(timeout=10.0):
    """Wait until every queued push has been handed to its push service; True when that happened."""
    end = time.monotonic() + max(0.0, float(timeout))
    while True:
        with _lock:
            if _queue.empty() and not _sender[0]:
                return True
        if time.monotonic() >= end:
            return False
        time.sleep(0.05)


# ── deciding, writing and sending (in the sender's app context) ───────────────────────────────────
def may_see(user, event_key, server_id, remote_id):
    """Whether `user` may be told about this event NOW (deny by default)."""
    from panel.security.auth import can_access_remote, can_access_server
    if not user.is_active:
        return False
    if event_key in SERVER_EVENTS:
        return server_id is not None and can_access_server(user, server_id)
    if event_key in HOST_EVENTS:
        return remote_id is not None and can_access_remote(user, remote_id)
    return bool(user.is_superadmin)


def _names(server_id, remote_id):
    """(server name, host name, page) for the object an event is about, from the database now."""
    from panel.db.models import GameServer, RemoteServer, db
    gs = db.session.get(GameServer, server_id) if server_id is not None else None
    rs = db.session.get(RemoteServer, remote_id) if remote_id is not None else None
    if gs is not None:
        return str(gs.name or "")[:_NAME_MAX], "", "server/%d" % gs.id
    if rs is not None:
        page = "server-management" if rs.is_local else "remote/%d/manage" % rs.id
        return "", str(rs.display_name or "")[:_NAME_MAX], page
    return "", "", ""


def _say(lang, text, **vals):
    return i18n.fill(i18n.translate(lang, text), **vals) if text else ""


def _event_note(lang, event_key, server_id, remote_id):
    """(title, body, page, urgent) for an event, in `lang`."""
    title, body = _TEXT.get(event_key, (event_key, ""))
    server, host, page = _names(server_id, remote_id)
    filled = _say(lang, body, server=server or "?", host=host or "?") if body else _say(lang, _OPEN_PANEL)
    return _say(lang, title), filled, page or _PAGE.get(event_key, ""), event_key in _URGENT


def _plan(items):
    """{user id: [(title, body, page, urgent, ttl)]} for a batch, each user checked as described above."""
    from panel.db.models import PushSubscription, User
    holders = {u.id: u for u in User.query.join(PushSubscription, PushSubscription.user_id == User.id).all()}
    # A linked Telegram chat is a device too (telegram_link). The column is ciphertext, which no query
    # can test, so the accounts are read and checked here; a panel has tens of accounts, not thousands.
    holders.update({u.id: u for u in User.query.filter(User.id.notin_(list(holders) or [0])).all()
                    if u.telegram_chat})
    plan = {}
    for item in items:
        for uid, note in _PLANNERS[item[0]](holders, item):
            plan.setdefault(uid, []).append(note)
    return plan, holders


def _plan_test(holders, item):
    """A test alert: to its own account's devices, while that account is active."""
    u = holders.get(item[1])
    if u is None or not u.is_active:
        return []
    return [(u.id, (_say(u.language, _TEST_TITLE), _say(u.language, _TEST_BODY), "account", False, TTL_TEST))]


def _plan_account(holders, item):
    """A change to an account's own security: to that account's devices, if it wants them."""
    from panel.security.account_notices import _CHANGES
    u = next((h for h in holders.values() if h.username == item[2]), None)
    if u is None or not u.is_active or MY_ACCOUNT not in chosen_events(u):
        return []
    return [(u.id, (_say(u.language, _ACCOUNT_TITLE), _say(u.language, _CHANGES[item[1]][0]), "account", True,
                    TTL_ALERT))]


def _plan_event(holders, item):
    """A panel alert: to every holder who chose it and may see what it is about."""
    _, key, server_id, remote_id = item
    out = []
    for u in holders.values():
        if key in chosen_events(u) and may_see(u, key, server_id, remote_id):
            title, body, page, urgent = _event_note(u.language, key, server_id, remote_id)
            out.append((u.id, (title, body, page, urgent, TTL_ALERT)))
    return out


_PLANNERS = {"test": _plan_test, "account": _plan_account, "event": _plan_event}


def _fold(lang, notes):
    """One notification for a device's batch: the note itself, or a summary past _FOLD_AT."""
    if len(notes) <= _FOLD_AT:
        return notes
    titles = [n[0] for n in notes]
    body = ", ".join(titles[:4]) + ("…" if len(titles) > 4 else "")
    return [(_say(lang, _FOLDED_TITLE, n=len(notes)), body, "", any(n[3] for n in notes),
             max(n[4] for n in notes))]


def deliver(items):
    """Send a batch: decide who gets what, then one POST per note per device. Never raises past here."""
    import json as _json
    from panel.db.models import PushSubscription, db
    plan, holders = _plan(items)
    for uid, notes in plan.items():
        lang = holders[uid].language
        for title, body, page, urgent, ttl in _fold(lang, notes):
            payload = _json.dumps({"title": title, "body": body, "url": page},
                                  ensure_ascii=False).encode("utf-8")
            for row in PushSubscription.query.filter_by(user_id=uid).all():
                try:
                    _send_one(row, payload, ttl, "high" if urgent else "normal")
                except Exception:  # noqa: BLE001 - one device must not stop the others
                    _log.warning("push to one device failed", exc_info=True)
            _send_telegram(holders[uid], title, body)
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001 - a lost "last delivered" time is not a lost alert
        db.session.rollback()
        _log.debug("recording push results failed", exc_info=True)


def _send_telegram(user, title, body):
    """The note to `user`'s linked Telegram chat, by the panel's bot: the same short text as a push."""
    chat = user.telegram_chat or ""
    if not chat:
        return
    from panel.services import notifications, telegram_link
    token = telegram_link.bot_token()
    if not token:
        return
    ok, _why = notifications.send_telegram(token, chat, "%s\n%s" % (title, body) if body else title)
    if not ok:
        _log.warning("alert to a linked Telegram chat was not delivered")


# A push service's answer that means the subscription is gone (RFC 8030 7.3: 404/410), or that the
# row can never be sent to again (its endpoint no longer passes the allow-list, its keys unreadable).
_GONE = frozenset({404, 410, -1, -3})


def _log_gone(label, status):
    """The journal line for a removed subscription: the service's fixed label and an int, nothing else.

    WARNING, so it reaches the journal (debug_report/errors.py gives "panel" a WARNING handler): a
    device that stops getting alerts is worth a line. Never the endpoint, the keys or the payload.
    """
    if status > 0:
        _log.warning("push subscription removed: %s answered HTTP %d (the browser dropped it)", label, status)
    elif status == -1:
        # No service label to name: the stored endpoint no longer passes the allow-list at all.
        _log.warning("push subscription removed: its endpoint is not a push service's (-1)")
    else:
        _log.warning("push subscription removed: its %s keys can no longer be used (%d)", label, status)


def _send_one(row, payload, ttl, urgency):
    """One device: send, and record what came back on the row (deleted when the service says gone)."""
    from panel.db.models import db
    p256dh = webpush.b64url_decode(row.p256dh or "") or b""
    auth = webpush.b64url_decode(row.auth or "") or b""
    status, label = webpush.send(row.endpoint or "", p256dh, auth, payload, ttl, urgency)
    if 200 <= status < 300:
        row.last_success = utcnow()
    elif status in _GONE:
        _log_gone(label, status)
        db.session.delete(row)
    elif status == -2:
        _log.warning("push to %s refused: its name resolved to a non-public address", label)
    elif status == 0:
        _log.warning("push to %s failed: no answer", label)
    else:
        _log.warning("push to %s rejected: HTTP %d", label, status)
