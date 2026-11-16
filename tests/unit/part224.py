"""Part 224 of the unit suite: what leaves the panel about people (the privacy fixes).

* Chat alerts (Telegram, Discord, ntfy) carry what happened, not who or from where, unless the
  Notifications page's "Include details" switch is on; the switch is saved by the form and shown with
  its recommended value. Driven through the real callers (the fail2ban ban watcher, a sign-in alert)
  and the real queue and sender, with only the provider POST stubbed.
* The bots' console replies mask players' addresses under the same switch.
* ntfy without an access token: the page warns and offers a long random topic.
* Public-IP lookups: the host's own public address asks no third party; one service at most; a
  failing lookup is retried once a day, not every five minutes.
* Audit ageing reduces the addresses inside an entry's text too, on the same rule as the IP column.
Every route runs on part12's app with its transport tripwire armed.
"""
from datetime import timedelta as _td224
from types import SimpleNamespace as _NS224

import app as _app224
from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST2, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_drain, _p9_patch,
                         _p9_patch_sm, _p9_queue, _p9_restore_all, _p9_set_host, _p9_sh, _p9_threading, _P9Thread)
from panel.core.clock import utcnow as _utcnow224
from panel.db import models as _models224
from panel.ops.ssh_manager import _core as _core224
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


# A stored token's stand-in: the page only asks whether one is set (no real credential).
_SET_TOKEN224 = "stored-value-stand-in"


def _ntfy_warning224():
    _p9_patch(_nt224, "_cfg", lambda: {"ntfy": {"enabled": True, "topic": "alerts"}})
    c = _p9_client(P9_ADMIN)
    bare = c.get("/notifications").get_data(as_text=True)
    _p9_patch(_nt224, "_cfg", lambda: {"ntfy": {"enabled": True, "topic": "alerts", "token": _SET_TOKEN224}})
    tokened = c.get("/notifications").get_data(as_text=True)
    topic = _cp224.suggested_topic()
    eq("ntfy: without an access token the page warns that a guessed topic is readable and offers a random "
       "topic; with a token it does not; the self-hosting how-to is linked either way; the suggestion is a "
       "valid, long topic",
       ("anyone who guesses the topic can read these alerts" in bare, 'data-action="useSuggestedTopic"' in bare,
        "anyone who guesses the topic can read these alerts" in tokened, "/docs/NTFY-SELF-HOST.md" in tokened,
        bool(_nt224._NTFY_TOPIC_RE.match(topic)), len(topic) >= 30, topic != _cp224.suggested_topic()),
       (True, True, False, True, True, True, True))


def _push_note224():
    page = _p9_client(P9_ADMIN).get("/account").get_data(as_text=True)
    eq("push: the Account page's alerts card says who relays a push (Google, Microsoft, Apple or Mozilla, by browser) "
       "and that ntfy uses no web push",
       ('id="push-relay-note"' in page, "(Google, Microsoft, Apple or Mozilla)" in page),
       (True, True))


# ── 3. public-IP lookups ─────────────────────────────────────────────────────────────────────────
def _pubip_asked224(route_src, answer):
    """(result, commands run) for remote_public_ip on a host whose default route leaves from `route_src`."""
    asked = []

    def _rc(server, cmd, timeout=30, sudo=None, stdin_text=None):
        asked.append(cmd)
        return ((route_src if "route get" in cmd else answer), "", 0)
    _p9_patch(_core224, "run_command", _rc)
    srv = _NS224(id=-22401, name="p224", host="p224.example.invalid", is_local=False)
    _core224._gamedig_host_cache.pop(srv.id, None)
    try:
        return _core224.remote_public_ip(srv), asked
    finally:
        _core224._gamedig_host_cache.pop(srv.id, None)


def _pubip_sources224():
    own, own_asked = _pubip_asked224("1.2.3.4", "1.2.3.5")
    nat, nat_asked = _pubip_asked224("10.0.0.5", "1.2.3.4")
    eq("public IP: a host whose own address is public answers with it and asks no third party; behind NAT "
       "one service answers, and ifconfig.me is never asked",
       (own, any("ipify" in c or "opendns" in c for c in own_asked), nat, sum("ipify" in c for c in nat_asked),
        any("ifconfig.me" in c for c in own_asked + nat_asked)),
       ("1.2.3.4", False, "1.2.3.4", 1, False))


def _pubip_daily224():
    clock = {"t": 1_000_000.0}
    _p9_patch(_p9_sh, "time", _NS224(time=lambda: clock["t"]))
    _p9_patch(_p9_sh, "threading", _p9_threading(_P9Thread))
    _p9_patch(_p9_sh, "remote_public_ip", lambda r: "")        # every lookup fails
    _p9_set_host(P9_HOST2, public_ip=None)
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)
    del _p9_queue[:]
    queued = []
    for step in (0, 6 * 60, 23 * 3600, 25 * 3600):
        clock["t"] = 1_000_000.0 + step
        _p9_sh._maybe_resolve_public_ip(_p9, P9_HOST2)
        queued.append(len(_p9_queue))
        _p9_drain()
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)
    eq("public IP: a lookup that keeps failing is tried again after a day, not after five minutes "
       "(asked at 0, 6 min, 23 h, 25 h)", queued, [1, 0, 0, 1])


# ── 4. audit text ages like the IP column ────────────────────────────────────────────────────────
def _audit_text224():
    now = _utcnow224()
    seed = (("login", "", "User logged in from 203.0.113.7", 200), ("fail2ban_ban", "198.51.100.9", "", 200),
            ("login_locked", "bob", "paused (last from 2001:db8:1:2:3:4:5:6)", 200),
            ("login", "", "User logged in from 203.0.113.8", 1))
    ids = []
    with _p9.app_context():
        for action, target, detail, age in seed:
            row = _models224.AuditLog(username="p224", action=action, target=target, detail=detail,
                                      ip_address="", timestamp=now - _td224(days=age))
            _models224.db.session.add(row)
            _models224.db.session.commit()
            ids.append(row.id)
        try:
            first = _models224.anonymise_audit_ips(90)
            again = _models224.anonymise_audit_ips(90)
            got = [(r.target, r.detail) for r in (_models224.db.session.get(_models224.AuditLog, i) for i in ids)]
        finally:
            for i in ids:
                row = _models224.db.session.get(_models224.AuditLog, i)
                if row is not None:
                    _models224.db.session.delete(row)
            _models224.db.session.commit()
    eq("audit: past the 90 days the addresses inside an entry's detail and target are reduced to their "
       "network like the IP column; a recent entry keeps its address; a second run changes nothing",
       (got, first >= 3, again),
       ([("", "User logged in from 203.0.113.0/24"), ("198.51.100.0/24", ""),
         ("bob", "paused (last from 2001:db8:1:2::/64)"), ("", "User logged in from 203.0.113.8")], True, 0))


# The test-send uses the typed (or stored) tokens, so it takes the step-up confirm like the save does.
def _s224_test_send_step_up():
    import time as _t224
    from unit.part12 import _p9_json
    _p9.config["STEP_UP_MINUTES"] = 10
    c = _p9_client(P9_ADMIN)
    with c.session_transaction() as sess:
        sess["_auth_at"] = _t224.time() - 3600
    r = c.post("/api/notifications/test", json={"channel": "ntfy"})
    eq("notifications test-send: from a sign-in past the step-up window it answers the confirm 403",
       (r.status_code, r.headers.get("X-Reauth-Required"), _p9_json(r).get("error")), (403, "1", "reauth_required"))


try:
    for _fn224 in (_chat_alerts224, _details_form224, _bot_console224, _ntfy_warning224, _push_note224, _pubip_sources224,
                   _pubip_daily224, _audit_text224, _s224_test_send_step_up):
        _p9_arm(who="part224")
        try:
            _fn224()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()

check("part224: nothing reached a real transport", len(_P9_TRIPPED) == _trips224, repr(_P9_TRIPPED[_trips224:]))
