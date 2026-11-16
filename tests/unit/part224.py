"""Part 224 of the unit suite: what leaves the panel about people (the privacy fixes).

* Chat alerts (Telegram, Discord, ntfy) carry what happened, not who or from where, unless the
  Notifications page's "Include details" switch is on; the switch is saved by the form and shown with
  its recommended value. Driven through the real callers (the fail2ban ban watcher, a sign-in alert)
  and the real queue and sender, with only the provider POST stubbed.
* The bots' console replies mask players' addresses under the same switch.
* ntfy without an access token: the page warns and offers a long random topic.
Every route runs on part12's app with its transport tripwire armed.
"""
import app as _app224
from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_drain, _p9_patch, _p9_patch_sm,
                         _p9_restore_all, _p9_threading, _P9Thread)
from panel.services import chat_privacy as _cp224
from panel.services import console_secrets as _cs224
from panel.services import notifications as _nt224
from panel.services.bots import commands as _cmd224

_trips224 = len(_P9_TRIPPED)
_IP224 = "203.0.113.9"


# ── 1. chat alerts minimal by default ────────────────────────────────────────────────────────────
def _rig_send224(notif_cfg):
    """Stub the providers and run the alert sender in-line; the list every sent text lands in."""
    sent = []
    _p9_patch(_nt224, "_cfg", lambda: notif_cfg)
    _p9_patch(_nt224, "_push", lambda *a: None)
    _p9_patch(_nt224, "threading", _p9_threading(_P9Thread))
    _p9_patch(_nt224, "send_telegram", lambda tok, chat, text: sent.append(("telegram", text)) or (True, ""))
    _p9_patch(_nt224, "send_discord", lambda hook, text: sent.append(("discord", text)) or (True, ""))
    _p9_patch(_nt224, "send_ntfy", lambda srv, topic, tok, text: sent.append(("ntfy", text)) or (True, ""))
    return sent


def _chat_cfg224(include):
    cfg = {"telegram": {"enabled": True, "chat_id": "1"}, "discord": {"enabled": True},
           "ntfy": {"enabled": True, "topic": "t"}, "events": {"ip_banned": True, "admin_login": True}}
    if include is not None:
        cfg["include_details"] = include
    return cfg


def _ban_alert224(include):
    """The texts the ban watcher's alert reached each channel with, under this setting."""
    sent = _rig_send224(_chat_cfg224(include))
    _app224._f2b_record_events(_p9, (_IP224,), ())
    _p9_drain()
    _p9_restore_all()
    _p9_arm(who="part224")
    return sent


def _chat_alerts224():
    upgraded, on = _ban_alert224(None), _ban_alert224(True)
    eq("chat alerts: a ban reaches Telegram, Discord and ntfy WITHOUT the banned address on a config "
       "that never set the switch (an upgraded panel), pointing at the Audit log instead",
       ([n for n, _t in upgraded], any(_IP224 in t for _n, t in upgraded),
        all(_cp224.BRIEF_BODY in t for _n, t in upgraded)),
       (["telegram", "discord", "ntfy"], False, True))
    eq("chat alerts: with \"Include details\" on, the same ban carries the address (control)",
       all(_IP224 in t for _n, t in on) and len(on) == 3, True)
    sent = _rig_send224(_chat_cfg224(False))
    _nt224.notify("admin_login", "Super admin signed in", "alice signed in from %s" % _IP224)
    _nt224.notify("server_down", "Server offline", "p9-cs on host went offline")
    _p9_drain()
    texts = " | ".join(t for _n, t in sent)
    eq("chat alerts: a sign-in alert names neither the account nor the address; a server alert keeps "
       "its server name (not a person)",
       ("alice" in texts, _IP224 in texts, "p9-cs on host went offline" in texts), (False, False, True))


def _details_form224():
    stored = {}
    _p9_patch(_nt224, "update_config", lambda fn: fn(stored))
    _p9_patch(_nt224, "_cfg", lambda: dict(stored.get("notifications") or {}))
    c = _p9_client(P9_ADMIN)
    c.post("/notifications/save", data={"telegram_chat_id": "1", "include_details": "on"})
    on = (stored.get("notifications") or {}).get("include_details")
    page_on = c.get("/notifications").get_data(as_text=True)
    c.post("/notifications/save", data={"telegram_chat_id": "1"})
    off = (stored.get("notifications") or {}).get("include_details")
    page_off = c.get("/notifications").get_data(as_text=True)
    eq("chat alerts: the form saves \"Include details\" on and off; the page shows the recommended value "
       "always and the outside-the-recommendation note only while it is on",
       (on, off, 'name="include_details"' in page_off, "Recommended: off — Telegram, Discord and ntfy" in page_off,
        "sign-in addresses, usernames and banned IPs are sent" in page_on,
        "sign-in addresses, usernames and banned IPs are sent" in page_off),
       (True, False, True, True, True, False))


def _bot_console224():
    line = "Client \"bob\" connected (%s:27005) on 1.2.3 at 12:34:56 from 2001:db8::7" % _IP224
    _p9_patch_sm("capture_console", lambda *a, **k: (line, "", 0))
    _p9_patch(_cs224, "mask_for", lambda gs, text: text)
    got = {}
    for include in (None, True):
        _p9_patch(_cmd224, "load_config", lambda inc=include: {"notifications": _chat_cfg224(inc)})
        got[include] = _cmd224._console_text(_p9, "p9-cs")
    eq("bots: a console reply masks the players' IPv4 and IPv6 addresses by default, keeping the name, "
       "the version and the clock time; with \"Include details\" on it keeps them (control)",
       (_IP224 in got[None], "2001:db8::7" in got[None], "bob" in got[None], "1.2.3 at 12:34:56" in got[None],
        _IP224 in got[True] and "2001:db8::7" in got[True]),
       (False, False, True, True, True))


def _ntfy_warning224():
    _p9_patch(_nt224, "_cfg", lambda: {"ntfy": {"enabled": True, "topic": "alerts"}})
    c = _p9_client(P9_ADMIN)
    bare = c.get("/notifications").get_data(as_text=True)
    _p9_patch(_nt224, "_cfg", lambda: {"ntfy": {"enabled": True, "topic": "alerts", "token": "enc"}})
    tokened = c.get("/notifications").get_data(as_text=True)
    topic = _cp224.suggested_topic()
    eq("ntfy: without an access token the page warns that a guessed topic is readable and offers a random "
       "topic; with a token it does not; the suggestion is a valid, long topic",
       ("anyone who guesses the topic can read these alerts" in bare, 'data-action="useSuggestedTopic"' in bare,
        "anyone who guesses the topic can read these alerts" in tokened,
        bool(_nt224._NTFY_TOPIC_RE.match(topic)), len(topic) >= 30, topic != _cp224.suggested_topic()),
       (True, True, False, True, True, True))


try:
    for _fn224 in (_chat_alerts224, _details_form224, _bot_console224, _ntfy_warning224):
        _p9_arm(who="part224")
        try:
            _fn224()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()

check("part224: nothing reached a real transport", len(_P9_TRIPPED) == _trips224, repr(_P9_TRIPPED[_trips224:]))
