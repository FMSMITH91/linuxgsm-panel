"""Part 13 of the unit suite. Imported for its side effects.

Behaviour coverage for five modules the other parts reach only in passing: the admin notifier
(panel/services/notifications.py), the interactive terminal (panel/ops/terminal_session.py), the
monitor loop (panel/services/monitoring.py), the SSH/local transport core
(panel/ops/ssh_manager/_core.py) and app.py: its helpers, what create_app does at boot, and the
loops its supervisor runs.

Every check asserts what the code DID — what it returned, what it would have sent, what it wrote,
what it refused — never merely that it ran. The recurring subject is the one this codebase keeps
relearning: a read that FAILED must not come back looking like a healthy empty answer.

House rules this part keeps (see part01 and tests/unit_test.py):
  * nothing touches the network, SSH or a real host command — every transport is stubbed at the
    name the code under test resolves at call time, and put back in a `finally`;
  * the monitor's database is an in-memory SQLite bound to a throwaway Flask app, never data/;
  * the panel-state maps the monitor prunes are snapshotted and restored, so nothing this part
    does leaks into a later check;
  * no `sudo -u <account>` command string is asserted here: those builders are held by parts
    07-09 (GHSA-hh39-76g3-wxcx), so _core's coverage here is the transport and what it carries;
  * create_app runs (section F) only with its database, data dir and auth log pointed into a temp
    dir, and with threads recorded rather than started.
"""
import collections as _collections10
import fcntl
import json as _json10
import logging
import os
import pty
import signal
import socket
import struct
import sys as _sys10_mod
import termios
import threading
import time
import urllib.error
import urllib.parse
from types import SimpleNamespace as NS

from unit.part01 import (_sm_core, check, eq)  # noqa: F401,E402


class _Stop10(Exception):
    """Raised by a stubbed sleep to end a `while True` loop after the pass under test."""


class _LogCap10(logging.Handler):
    """Collects the formatted messages a logger emits while it is attached."""

    def __init__(self):
        logging.Handler.__init__(self)
        self.msgs = []
        self.warned = []        # the messages logged at WARNING or above

    def emit(self, rec):
        # A record whose arguments do not fit its format is kept as its raw parts, so the check
        # reading it FAILS by name instead of the formatting error ending the whole part.
        try:
            msg = rec.getMessage()
        except Exception:
            msg = "<unformattable %r %% %r>" % (rec.msg, rec.args)
        self.msgs.append(msg)
        # Kept apart because the level is the point for some of these: the panel configures no
        # logging, so only WARNING and above reaches the journal (logging.lastResort). A failure
        # "logged" at DEBUG or INFO is a failure nobody will ever see.
        if rec.levelno >= logging.WARNING:
            self.warned.append(msg)


def _cap10(name):
    h = _LogCap10()
    lg = logging.getLogger(name)
    lg.addHandler(h)
    _prev = lg.level
    lg.setLevel(logging.DEBUG)
    return h, (lambda: (lg.removeHandler(h), lg.setLevel(_prev)))


def _try10(fn, *a, **k):
    """Call fn, and on an exception return ("RAISED", repr) instead of raising.

    A check can then report it by name instead of the exception taking the rest of this part (and
    the tally) with it.
    """
    try:
        return fn(*a, **k)
    except Exception as e:           # reported by the check that reads it
        return ("RAISED", repr(e))


# ══════════════════════════════════════════════════════════════════════════════════════════════
# A. panel/services/notifications.py
# ══════════════════════════════════════════════════════════════════════════════════════════════
from panel.services import notifications as _n10  # noqa: E402

# The module binds load_config/update_config by name; give it an in-memory config for this whole
# section so nothing here reads or writes the run's config.json.
_n10_store = {}
_n10_saved = {k: getattr(_n10, k) for k in ("load_config", "update_config", "_OPENER", "threading")}
_n10_urlopen_saved = _n10.urllib.request.urlopen


def _n10_update(fn):
    fn(_n10_store)


class _Resp10:
    def __init__(self, code=200, body=b""):
        self._code, self._body = code, body

    def getcode(self):
        return self._code

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener10:
    """Records every request _post would have sent, and answers with `outcome`."""

    def __init__(self, outcome=200):
        self.outcome, self.reqs = outcome, []

    def open(self, req, timeout=None):
        self.reqs.append(req)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _Resp10(self.outcome)


def _hdr10(req, name):
    """A header off a urllib Request whatever case urllib normalised its name to."""
    return dict((k.lower(), v) for k, v in req.header_items()).get(name.lower())


try:
    _n10.load_config = lambda: _n10_store
    _n10.update_config = _n10_update

    # ── thresholds: clamped per key, garbage falls back to the default ─────────────────────────
    _n10_store["notifications"] = {"thresholds": {"disk_pct": 150, "load_pct": "lots",
                                                  "mem_pct": 10, "load_mins": 0}}
    eq("notify thresholds: each key is clamped to ITS OWN range, junk falls back to the default",
       _n10.get_thresholds(), {"disk_pct": 99, "load_pct": 200, "mem_pct": 50, "load_mins": 1})

    # ── the settings form never receives a stored secret ───────────────────────────────────────
    _n10_store["notifications"] = {
        "telegram": {"enabled": True, "chat_id": "42", "token": "ENC-tg"},
        "discord": {"webhook": "ENC-wh", "bot_token": "", "channel_id": "123456"},
        "ntfy": {"enabled": True, "topic": "alerts", "token": "ENC-nt"},
        "events": {"server_up": True, "server_down": False}}
    _form10 = _n10.settings_for_form()
    _flat10 = _json10.dumps(_form10)
    check("notify form: a stored secret is reported as present, never sent back to the browser",
          _form10["telegram"]["has_token"] and _form10["discord"]["has_webhook"]
          and _form10["ntfy"]["has_token"] and not _form10["discord"]["has_bot_token"]
          and "ENC-" not in _flat10,
          _flat10[:300])
    check("notify form: an unset ntfy server shows the public default, and events keep their "
          "stored value over the default",
          _form10["ntfy"]["server"] == _n10.NTFY_DEFAULT_SERVER
          and _form10["events"]["server_up"] is True and _form10["events"]["server_down"] is False
          and _form10["events"]["disk_low"] is True,
          repr(_form10["events"]))

    # ── save_settings: None keeps the stored secret, a new one is encrypted ────────────────────
    _n10_store["notifications"] = {
        "telegram": {"token": "KEEP-tg"}, "discord": {"webhook": "KEEP-wh", "bot_token": "KEEP-bt"},
        "ntfy": {"enabled": True, "server": "https://ntfy.example.org", "topic": "keepme",
                 "token": _n10.encrypt_secret("tk_keep")},
        "thresholds": {"disk_pct": 80}}
    _n10.save_settings(telegram={"enabled": 1, "chat_id": "  " + "9" * 80 + " ", "token": None},
                       discord={"enabled": 0, "webhook": "https://discord.com/api/webhooks/1/x",
                                "bot_token": None, "channel_id": " 555 "},
                       events={"server_up": 1},
                       thresholds={"disk_pct": "nope", "mem_pct": "70", "load_pct": ""})
    _saved10 = _n10_store["notifications"]
    check("notify save: a secret submitted as None keeps the stored value",
          _saved10["telegram"]["token"] == "KEEP-tg" and _saved10["discord"]["bot_token"] == "KEEP-bt",
          repr(_saved10["telegram"]))
    check("notify save: a NEW secret is stored encrypted, and decrypts back to what was typed",
          _saved10["discord"]["webhook"] not in ("", "https://discord.com/api/webhooks/1/x")
          and _n10.decrypt_secret(_saved10["discord"]["webhook"]) == "https://discord.com/api/webhooks/1/x",
          repr(_saved10["discord"]["webhook"])[:80])
    check("notify save: ntfy=None (a caller that does not manage ntfy) keeps the configured channel",
          _saved10["ntfy"]["enabled"] is True and _saved10["ntfy"]["topic"] == "keepme"
          and _saved10["ntfy"]["server"] == "https://ntfy.example.org"
          and _n10.decrypt_secret(_saved10["ntfy"]["token"]) == "tk_keep",
          repr(_saved10["ntfy"]))
    check("notify save: a junk threshold keeps the current value; a real one is clamped in; a "
          "blank one is not a submission",
          _saved10["thresholds"]["disk_pct"] == 80 and _saved10["thresholds"]["mem_pct"] == 70
          and _saved10["thresholds"]["load_pct"] == 200,
          repr(_saved10["thresholds"]))
    check("notify save: the chat and channel ids are trimmed and length-capped",
          _saved10["telegram"]["chat_id"] == "9" * 64 and _saved10["discord"]["channel_id"] == "555",
          repr((_saved10["telegram"]["chat_id"], _saved10["discord"]["channel_id"])))
    check("notify save: an event the form did not send keeps its DEFAULT, not False",
          _saved10["events"]["server_up"] is True and _saved10["events"]["disk_low"] is True
          and _saved10["events"]["ip_banned"] is False,
          repr(_saved10["events"]))
    # ...and the Discord channel id is capped, not only trimmed. The save above sends " 555 ", which
    # no cap can change, so the "length-capped" check held with the [:32] removed.
    _n10.save_settings(telegram={}, discord={"channel_id": " " + "5" * 40 + " "}, events={})
    check("notify save: a Discord channel id is capped at 32 characters, as the chat id is at 64",
          _n10_store["notifications"]["discord"]["channel_id"] == "5" * 32,
          repr(_n10_store["notifications"]["discord"]["channel_id"]))

    # ── migrate_master_switch: an explicit OFF survives the switch's removal ───────────────────
    _n10_store["notifications"] = {"enabled": False, "telegram": {"enabled": True},
                                   "discord": {"enabled": True}}
    _n10.migrate_master_switch()
    check("notify migration: a master switch that was OFF disables both channels and is removed",
          "enabled" not in _n10_store["notifications"]
          and _n10_store["notifications"]["telegram"]["enabled"] is False
          and _n10_store["notifications"]["discord"]["enabled"] is False,
          repr(_n10_store["notifications"]))
    _mig_calls10 = []
    _n10.update_config = lambda fn: _mig_calls10.append(fn)
    _n10.migrate_master_switch()
    check("notify migration: once the key is gone it writes nothing at all",
          _mig_calls10 == [], "update_config called %d time(s)" % len(_mig_calls10))
    _n10.update_config = _n10_update

    # ── _post: the allow-list is enforced at the sink, and nothing reaches the wire past it ────
    _op10 = _Opener10()
    _n10._OPENER = _op10
    check("notify _post: a URL off the provider allow-list is BLOCKED and never requested",
          _n10._post("https://evil.example/api/", b"x", {}) == (False, "blocked") and not _op10.reqs,
          "%d request(s) made" % len(_op10.reqs))
    check("notify _post: the ntfy exception admits only https://host/topic",
          _n10._post("http://ntfy.example/t", b"x", {}, allow_configured_host=True)
          == (False, "blocked")
          and _n10._post("https://ntfy.example/t/x", b"x", {}, allow_configured_host=True)
          == (False, "blocked") and not _op10.reqs,
          "%d request(s) made" % len(_op10.reqs))
    _ok10 = _n10._post("https://ntfy.example:8443/t", b"body", {"X-A": "1"},
                       allow_configured_host=True, provider="ntfy")
    check("notify _post: an allowed ntfy URL is POSTed, with the panel's User-Agent",
          _ok10 == (True, "sent") and len(_op10.reqs) == 1
          and _op10.reqs[0].get_method() == "POST"
          and _hdr10(_op10.reqs[0], "User-Agent") == "linuxgsm-panel"
          and _hdr10(_op10.reqs[0], "X-A") == "1",
          repr(_ok10))
    _n10._OPENER = _Opener10(302)
    check("notify _post: a non-2xx answer is not 'sent' as success",
          _n10._post("https://api.telegram.org/botX/sendMessage", b"", {}) == (False, "sent"),
          "a 302 read as ok")
    _cap_h10, _cap_off10 = _cap10("notifications")
    try:
        _n10._OPENER = _Opener10(urllib.error.HTTPError("https://discord.com/api/x", 401,
                                                        "no", {}, None))
        _rej10 = _n10._post("https://discord.com/api/webhooks/1/x", b"", {}, provider="discord")
        _n10._OPENER = _Opener10(urllib.error.URLError("nope"))
        _unr10 = _n10._post("https://discord.com/api/webhooks/1/x", b"", {}, provider="discord")
    finally:
        _cap_off10()
    check("notify _post: a provider's HTTP error is 'rejected' and LOGGED with its status",
          _rej10 == (False, "rejected")
          and any("rejected by discord: HTTP 401" in m for m in _cap_h10.warned),
          repr((_rej10, _cap_h10.msgs)))
    check("notify _post: a connection failure is 'unreachable', logged by type and not by URL",
          _unr10 == (False, "unreachable")
          and any("URLError" in m for m in _cap_h10.msgs)
          and not any("discord.com/api/webhooks" in m for m in _cap_h10.msgs),
          repr(_cap_h10.msgs))

    # ── senders: each maps _post's fixed reason words onto its own operator-facing text ───────
    _TG10 = "123456789:" + "A" * 30
    _WH10 = "https://discordapp.com/api/webhooks/123456/tok-EN_1"

    def _sender10(outcome, fn, *a):
        op = _Opener10(outcome)
        _n10._OPENER = op
        return fn(*a), op.reqs

    check("notify telegram: a malformed token and a missing chat id are refused before sending",
          _n10.send_telegram("nope", "1", "hi")[0] is False
          and "malformed" in _n10.send_telegram("nope", "1", "hi")[1]
          and _n10.send_telegram(_TG10, "", "hi") == (False, "the chat ID is missing"),
          "")
    (_r10, _q10) = _sender10(200, _n10.send_telegram, _TG10, "-100 42", "x" * 5000)
    _body10 = urllib.parse.parse_qs(_q10[0].data.decode()) if _q10 else {}
    check("notify telegram: sends to the rebuilt bot URL with the chat id and a capped text",
          _r10 == (True, "") and _q10
          and _q10[0].full_url == "https://api.telegram.org/bot%s/sendMessage" % _TG10
          and _body10.get("chat_id") == ["-100 42"] and len(_body10.get("text", [""])[0]) == 4000,
          repr(_r10))
    _unr_tg10 = _sender10(urllib.error.URLError("x"), _n10.send_telegram, _TG10, "1", "hi")[0]
    _rej_tg10 = _sender10(urllib.error.HTTPError("u", 400, "bad", {}, None),
                          _n10.send_telegram, _TG10, "1", "hi")[0]
    check("notify telegram: unreachable and rejected are told apart for the operator",
          _unr_tg10[0] is False and "api.telegram.org" in _unr_tg10[1]
          and _rej_tg10[0] is False and "rejected" in _rej_tg10[1],
          repr((_unr_tg10, _rej_tg10)))

    check("notify discord: a webhook off discord.com is refused before sending",
          _n10.send_discord("https://evil.example/api/webhooks/123456/x", "hi")
          == (False, "that isn't a valid discord.com webhook URL"), "")
    (_r10, _q10) = _sender10(204, _n10.send_discord, _WH10, "@everyone hello")
    _dj10 = _json10.loads(_q10[0].data) if _q10 else {}
    check("notify discord: posts to the CONSTANT discord.com host with every mention disabled",
          _r10 == (True, "") and _q10
          and _q10[0].full_url == "https://discord.com/api/webhooks/123456/tok-EN_1"
          and _dj10.get("allowed_mentions") == {"parse": []}
          and _dj10.get("content") == "@everyone hello",
          repr(_dj10))
    _unr_dc10 = _sender10(urllib.error.URLError("x"), _n10.send_discord, _WH10, "hi")[0]
    _rej_dc10 = _sender10(urllib.error.HTTPError("u", 404, "gone", {}, None),
                          _n10.send_discord, _WH10, "hi")[0]
    check("notify discord: unreachable and rejected are told apart",
          "couldn't reach discord.com" in _unr_dc10[1] and "webhook URL is wrong" in _rej_dc10[1],
          repr((_unr_dc10, _rej_dc10)))

    check("notify ntfy: a server with a path or a topic with a slash is refused before sending",
          _n10.send_ntfy("https://ntfy.sh/x", "t", "", "hi")[0] is False
          and _n10.send_ntfy("https://ntfy.sh", "a/b", "", "hi")[0] is False, "")
    check("notify ntfy: an access token with characters ntfy never uses is refused",
          _n10.send_ntfy("https://ntfy.sh", "t", "tk\r\nX-Evil: 1", "hi")
          == (False, "that access token has characters ntfy tokens don't use."), "")
    (_r10, _q10) = _sender10(200, _n10.send_ntfy, "https://ntfy.example/", "alerts", " tk_1 ", "hi")
    check("notify ntfy: the token rides in a Bearer header, never the URL; a trailing slash is ok",
          _r10 == (True, "") and _q10 and _q10[0].full_url == "https://ntfy.example/alerts"
          and _hdr10(_q10[0], "Authorization") == "Bearer tk_1"
          and "tk_1" not in _q10[0].full_url,
          repr(_r10))
    _nt_unr10 = _sender10(urllib.error.URLError("x"), _n10.send_ntfy, "https://ntfy.sh", "t", "", "m")[0]
    _nt_rej10 = _sender10(urllib.error.HTTPError("u", 403, "no", {}, None),
                          _n10.send_ntfy, "https://ntfy.sh", "t", "", "m")[0]
    _real_post10 = _n10._post
    _n10._post = lambda *a, **k: (False, "blocked")
    try:
        _nt_blk10 = _n10.send_ntfy("https://ntfy.sh", "t", "", "m")
    finally:
        _n10._post = _real_post10
    check("notify ntfy: unreachable, rejected and blocked each get their own explanation",
          "couldn't reach that ntfy server" in _nt_unr10[1] and "reserved" in _nt_rej10[1]
          and "refused before sending" in _nt_blk10[1],
          repr((_nt_unr10, _nt_rej10, _nt_blk10)))

    # ── Telegram reads: a failed read is None, not an empty inbox ──────────────────────────────
    _urls10 = []

    def _urlopen10(payload):
        def _f(req, timeout=None):
            _urls10.append(req.full_url)
            if isinstance(payload, BaseException):
                raise payload
            return _Resp10(200, payload)
        return _f

    _n10.urllib.request.urlopen = _urlopen10(b'{"ok": true, "result": [{"update_id": 7}]}')
    _upd10 = _n10.telegram_get_updates(_TG10, offset=8, timeout=1)
    check("notify telegram updates: a good read returns the result list, asking from the offset",
          _upd10 == [{"update_id": 7}] and _urls10 and "offset=8" in _urls10[-1]
          and _urls10[-1].startswith("https://api.telegram.org/bot%s/getUpdates?" % _TG10),
          repr((_upd10, _urls10[-1:])))
    _n10.urllib.request.urlopen = _urlopen10(b'{"ok": false, "description": "Conflict"}')
    _upd_bad10 = _n10.telegram_get_updates(_TG10, timeout=1)
    _n10.urllib.request.urlopen = _urlopen10(urllib.error.URLError("down"))
    _upd_down10 = _n10.telegram_get_updates(_TG10, timeout=1)
    check("notify telegram updates: a refused or failed poll is None, never an empty list",
          _upd_bad10 is None and _upd_down10 is None
          and _n10.telegram_get_updates("bad-token") is None,
          repr((_upd_bad10, _upd_down10)))
    _n10.urllib.request.urlopen = _urlopen10(b'{"ok": true, "result": {"username": "panelbot"}}')
    _me10 = _n10.telegram_get_me(_TG10)
    _n10.urllib.request.urlopen = _urlopen10(b'{"ok": true, "result": {}}')
    _me_none10 = _n10.telegram_get_me(_TG10)
    # A refusal is not an answer, whatever else came back with it.
    _n10.urllib.request.urlopen = _urlopen10(b'{"ok": false, "result": {"username": "stale"}}')
    _me_refused10 = _n10.telegram_get_me(_TG10)
    _n10.urllib.request.urlopen = _urlopen10(b"not json")
    _me_bad10 = _n10.telegram_get_me(_TG10)
    check("notify telegram getMe: the bot's name, or None when it could not be read",
          _me10 == "panelbot" and _me_none10 is None and _me_bad10 is None
          and _me_refused10 is None
          and _n10.telegram_get_me("") is None,
          repr((_me10, _me_none10, _me_bad10)))
    _n10.urllib.request.urlopen = _n10_urlopen_saved

    (_cl10, _q10) = _sender10(200, _n10.telegram_set_commands, _TG10, True)
    (_set10, _q2_10) = _sender10(200, _n10.telegram_set_commands, _TG10)
    check("notify telegram commands: clearing sends an EMPTY list, setting sends the whole menu",
          _cl10 is True and _json10.loads(_q10[0].data) == {"commands": []}
          and _set10 is True
          and len(_json10.loads(_q2_10[0].data)["commands"]) == len(_n10.TG_COMMANDS)
          and _n10.telegram_set_commands("x") is False,
          "")

    # ── the Discord command bot's reply path ───────────────────────────────────────────────────
    _BOT10 = "b" * 50
    check("notify discord bot: a non-snowflake channel and a malformed token are refused first",
          _n10.discord_bot_send(_BOT10, "chan", "x") == (False, "the channel ID is missing or malformed")
          and _n10.discord_bot_send("short", "123456", "x")
          == (False, "the bot token is missing or malformed"), "")
    (_r10, _q10) = _sender10(200, _n10.discord_bot_send, _BOT10, " 123456 ", "hi")
    check("notify discord bot: replies go to the channel on discord.com with a Bot header",
          _r10 == (True, "") and _q10
          and _q10[0].full_url == "https://discord.com/api/v10/channels/123456/messages"
          and _hdr10(_q10[0], "Authorization") == "Bot " + _BOT10,
          repr(_r10))
    _b_unr10 = _sender10(urllib.error.URLError("x"), _n10.discord_bot_send, _BOT10, "123456", "m")[0]
    _b_rej10 = _sender10(urllib.error.HTTPError("u", 403, "no", {}, None),
                         _n10.discord_bot_send, _BOT10, "123456", "m")[0]
    check("notify discord bot: unreachable and rejected are told apart",
          "couldn't reach discord.com" in _b_unr10[1] and "bot is in the server" in _b_rej10[1],
          repr((_b_unr10, _b_rej10)))

    # ── notify(): dispatch only to the channels that are on, and CHECK each result ─────────────
    class _SyncThreads10:
        """A threading stand-in whose Thread runs its target on start().

        The send is then observable before notify() returns.
        """
        class Thread:
            def __init__(self, target=None, daemon=None, **k):
                self._t = target

            def start(self):
                self._t()

    _n10.threading = _SyncThreads10
    _sent10 = []
    _snd_saved10 = (_n10.send_telegram, _n10.send_discord, _n10.send_ntfy)
    _n10.send_telegram = lambda tok, chat, text: (_sent10.append(("tg", tok, chat, text)) or (True, ""))
    _n10.send_discord = lambda wh, text: (_sent10.append(("dc", wh, text)) or (False, "Discord rejected it"))
    _n10.send_ntfy = lambda srv, topic, tok, text: (_sent10.append(("nt", srv, topic, tok)) or (True, ""))
    _cap_h10, _cap_off10 = _cap10("notifications")
    try:
        _n10_store["notifications"] = {
            "telegram": {"enabled": True, "chat_id": " 77 ", "token": _n10.encrypt_secret(_TG10)},
            "discord": {"enabled": True, "webhook": _n10.encrypt_secret(_WH10)},
            "ntfy": {"enabled": False, "topic": "t"},
            "events": {"server_down": True, "server_up": False}}
        _n10.notify("server_down", "Server offline", "gmod went down")
        _n10.notify("server_up", "Server back", "")
    finally:
        _cap_off10()
        _n10.send_telegram, _n10.send_discord, _n10.send_ntfy = _snd_saved10
    check("notify(): an enabled event reaches exactly the enabled channels, decrypted",
          [s[0] for s in _sent10] == ["tg", "dc"]
          and _sent10[0][1] == _TG10 and _sent10[0][2] == "77" and _sent10[1][1] == _WH10,
          repr([s[:3] for s in _sent10]))
    check("notify(): the text carries the title and the body",
          _sent10 and "Server offline" in _sent10[0][3] and "gmod went down" in _sent10[0][3], "")
    check("notify(): a channel that refused the message is LOGGED (at WARNING), not swallowed",
          any("notification to discord failed (server_down)" in m for m in _cap_h10.warned),
          repr(_cap_h10.msgs))
    check("notify(): a disabled event sends nothing (server_up is off here)",
          len(_sent10) == 2, "%d sends" % len(_sent10))

    # ── test_send: every branch answers in words, before it ever sends ─────────────────────────
    _n10_store["notifications"] = {}
    _ts_calls10 = []
    _snd_saved10 = (_n10.send_telegram, _n10.send_discord, _n10.send_ntfy, _n10.discord_bot_send)
    _n10.send_telegram = lambda *a: (_ts_calls10.append("tg") or (False, "boom"))
    _n10.send_discord = lambda *a: (_ts_calls10.append("dc") or (True, ""))
    _n10.send_ntfy = lambda *a: (_ts_calls10.append("nt") or (True, ""))
    _n10.discord_bot_send = lambda *a: (_ts_calls10.append("bot") or (False, ""))
    try:
        _tsr10 = {
            "tg_notok": _n10.test_send("telegram"),
            "tg_badtok": _n10.test_send("telegram", token="1:2"),
            "tg_nochat": _n10.test_send("telegram", token=_TG10),
            "tg_fail": _n10.test_send("telegram", token=_TG10, chat_id="5"),
            "dc_none": _n10.test_send("discord"),
            "dc_bad": _n10.test_send("discord", webhook="https://example.com/x"),
            "dc_ok": _n10.test_send("discord", webhook=_WH10),
            "bot_notok": _n10.test_send("discord_bot"),
            "bot_badtok": _n10.test_send("discord_bot", token="x"),
            "bot_nochan": _n10.test_send("discord_bot", token=_BOT10, chat_id="abc"),
            "bot_fail": _n10.test_send("discord_bot", token=_BOT10, chat_id="123456"),
            "nt_notopic": _n10.test_send("ntfy"),
            "nt_badtopic": _n10.test_send("ntfy", topic="a b"),
            "nt_badsrv": _n10.test_send("ntfy", topic="ok", server="ftp://x"),
            "nt_ok": _n10.test_send("ntfy", topic="ok"),
            "unknown": _n10.test_send("pigeon"),
        }
    finally:
        _n10.send_telegram, _n10.send_discord, _n10.send_ntfy, _n10.discord_bot_send = _snd_saved10
    check("notify test_send: missing and malformed inputs are refused with a reason, never sent",
          _tsr10["tg_notok"] == (False, "Enter the bot token first.")
          and "expected format" in _tsr10["tg_badtok"][1]
          and "chat ID" in _tsr10["tg_nochat"][1]
          and _tsr10["dc_none"] == (False, "Enter the webhook URL first.")
          and "doesn't look like" in _tsr10["dc_bad"][1]
          and _tsr10["bot_notok"] == (False, "Enter the bot token first.")
          and "expected format" in _tsr10["bot_badtok"][1]
          and "channel ID" in _tsr10["bot_nochan"][1]
          and "topic first" in _tsr10["nt_notopic"][1]
          and "letters, digits" in _tsr10["nt_badtopic"][1]
          and "base URL only" in _tsr10["nt_badsrv"][1]
          and _tsr10["unknown"] == (False, "Unknown channel."),
          repr(_tsr10)[:600])
    check("notify test_send: only the four well-formed requests reached a sender",
          _ts_calls10 == ["tg", "dc", "bot", "nt"], repr(_ts_calls10))
    check("notify test_send: a sender's failure is reported as that provider's error",
          _tsr10["tg_fail"] == (False, "Telegram error: boom")
          and _tsr10["bot_fail"] == (False, "Discord error: unknown")
          and _tsr10["dc_ok"] == (True, "Test message sent — check Discord.")
          and _tsr10["nt_ok"] == (True, "Test message sent — check the ntfy app."),
          repr((_tsr10["tg_fail"], _tsr10["bot_fail"])))
    # ...and with the form left blank it tests the SAVED channel: the stored secret decrypted, the
    # stored chat/channel id, the stored ntfy server and topic. Every request above passes its
    # values in, so the saved half of each lookup was never read.
    _n10_store["notifications"] = {
        "telegram": {"token": _n10.encrypt_secret(_TG10), "chat_id": "4242"},
        "discord": {"webhook": _n10.encrypt_secret(_WH10), "bot_token": _n10.encrypt_secret(_BOT10),
                    "channel_id": "987654"},
        "ntfy": {"server": "https://ntfy.example.org", "topic": "saved_topic",
                 "token": _n10.encrypt_secret("tk_saved")}}
    _tss10 = []
    _n10.send_telegram = lambda *a: (_tss10.append(("tg",) + a[:2]) or (True, ""))
    _n10.send_discord = lambda *a: (_tss10.append(("dc",) + a[:1]) or (True, ""))
    _n10.send_ntfy = lambda *a: (_tss10.append(("nt",) + a[:3]) or (True, ""))
    _n10.discord_bot_send = lambda *a: (_tss10.append(("bot",) + a[:2]) or (True, ""))
    try:
        for _tsk10 in ("telegram", "discord", "discord_bot", "ntfy"):
            _n10.test_send(_tsk10)
    finally:
        _n10.send_telegram, _n10.send_discord, _n10.send_ntfy, _n10.discord_bot_send = _snd_saved10
    check("notify test_send: a blank form tests the SAVED channel, its secrets decrypted",
          _tss10 == [("tg", _TG10, "4242"), ("dc", _WH10), ("bot", _BOT10, "987654"),
                     ("nt", "https://ntfy.example.org", "saved_topic", "tk_saved")], repr(_tss10))

    # ── alerts_muted: any muting tag wins; an unreadable tag list fails OPEN ───────────────────
    class _BadTags10:
        short_name = "x"

        @property
        def tags(self):
            raise RuntimeError("detached")

    check("notify alerts_muted: one tag with notify off mutes the server",
          _n10.alerts_muted(NS(tags=[NS(notify=True), NS(notify=False)])) is True
          and _n10.alerts_muted(NS(tags=[NS(notify=True)])) is False
          and _n10.alerts_muted(NS(tags=None)) is False, "")
    check("notify alerts_muted: a tag list that cannot be read does NOT mute (fails open)",
          _n10.alerts_muted(_BadTags10()) is False, "")

    # ── a status code the provider made up cannot forge a log line ─────────────────────────────
    _cap_h10, _cap_off10 = _cap10("notifications")
    try:
        _n10._OPENER = _Opener10(urllib.error.HTTPError("https://discord.com/api/x",
                                                        "500\nFAKE: admin logged in", "x", {}, None))
        _forge10 = _n10._post("https://discord.com/api/webhooks/1/x", b"", {}, provider="discord")
    finally:
        _cap_off10()
    check("notify _post: a non-numeric HTTP status is logged as 0, never as the provider's text",
          _forge10 == (False, "rejected")
          and any(m == "notification rejected by discord: HTTP 0" for m in _cap_h10.msgs)
          and not any("FAKE" in m for m in _cap_h10.msgs),
          repr(_cap_h10.msgs))

    # ── notify() is never allowed to raise into the action that triggered it ──────────────────
    def _cfg_boom10():
        raise OSError("config vanished")

    _n10.load_config = _cfg_boom10
    _nb10 = _try10(_n10.notify, "server_down", "t")
    _n10.load_config = lambda: _n10_store
    _n10_store["notifications"] = {"telegram": {"enabled": True, "chat_id": "1", "token": _TG10},
                                   "ntfy": {"enabled": True, "topic": "t"},
                                   "events": {"server_down": True}}
    _raised_then10 = []

    def _tg_raises10(*a):
        raise ValueError("bug in a sender")

    _snd_saved10 = (_n10.send_telegram, _n10.send_ntfy)
    _n10.send_telegram = _tg_raises10
    _n10.send_ntfy = lambda *a: (_raised_then10.append("nt") or (True, ""))
    try:
        _nr10 = _try10(_n10.notify, "server_down", "t")
    finally:
        _n10.send_telegram, _n10.send_ntfy = _snd_saved10
    check("notify(): an unreadable config and a sender that raises are both contained",
          _nb10 is None and _nr10 is None, repr((_nb10, _nr10)))

    # ── the Discord Gateway session, driven through a fake socket ──────────────────────────────
    # REAL threads from here: the heartbeat must run beside the receive loop, not inside it.
    _n10.threading = _n10_saved["threading"]
    class _GwWS10:
        """A Gateway socket that hands out `frames`, then reads as closed.

        recv() waits for close() (or `idle` seconds) after the frames and answers "" — the shape of
        a socket the far end, or the heartbeat, closed.
        """

        def __init__(self, frames, idle=5.0, fail_heartbeat=False, fail_close=False):
            self.frames, self.idle = [_json10.dumps(f) for f in frames], idle
            self.fail_heartbeat, self.fail_close = fail_heartbeat, fail_close
            self.sent, self.closed_by, self.timeout = [], [], None
            self._gone = threading.Event()

        def recv(self):
            if self.frames:
                return self.frames.pop(0)
            self._gone.wait(self.idle)
            return ""

        def send(self, s):
            msg = _json10.loads(s)
            if self.fail_heartbeat and msg.get("op") == 1:
                raise OSError("broken pipe")
            self.sent.append(msg)

        def settimeout(self, t):
            self.timeout = t

        def close(self):
            self.closed_by.append(threading.get_ident())
            self._gone.set()
            if self.fail_close:
                raise OSError("already closed")

    _me10 = threading.get_ident()           # the thread discord_gateway_run itself runs on
    # 2 s: longer than any of these sessions lasts, so the timer never fires in them — and short
    # enough that each stopped heartbeat thread wakes, sees the stop, and exits soon after.
    _SLOW10 = {"op": 10, "d": {"heartbeat_interval": 2000}}
    _FAST10 = {"op": 10, "d": {"heartbeat_interval": 40}}         # 40 ms, so the test is quick
    _gw_seen10 = []
    _gw10 = _GwWS10([_SLOW10,
                     {"op": 0, "s": 4, "t": "MESSAGE_CREATE",
                      "d": {"channel_id": "77", "content": "beep",
                            "author": {"id": "8", "bot": True}}},
                     {"op": 0, "s": 5, "t": "MESSAGE_CREATE",
                      "d": {"channel_id": 123456, "content": "!status",
                            "author": {"id": "9", "username": "op", "bot": False}}},
                     {"op": 1}, {"op": 7}])
    _gwr10 = _try10(_n10.discord_gateway_run, _BOT10,
                    lambda *a: _gw_seen10.append(a), _connect=lambda: _gw10)
    _gw_ident10 = [m for m in _gw10.sent if m.get("op") == 2]
    _gw_beats10 = [m for m in _gw10.sent if m.get("op") == 1]
    check("notify gateway: IDENTIFY carries the bot token and the message intents",
          _gwr10 is None and _gw_ident10 and _gw_ident10[0]["d"]["token"] == _BOT10
          and _gw_ident10[0]["d"]["intents"] == _n10._DISCORD_INTENTS,
          repr(_gw10.sent)[:300])
    check("notify gateway: a MESSAGE_CREATE reaches the handler with its channel, bot flag, text "
          "and author",
          _gw_seen10 == [("77", True, "beep", {"id": "8", "bot": True}),
                         ("123456", False, "!status", {"id": "9", "username": "op", "bot": False})],
          repr(_gw_seen10))
    check("notify gateway: a heartbeat the server asks for is sent at once, with the last sequence",
          _gw_beats10 == [{"op": 1, "d": 5}], repr(_gw_beats10))
    check("notify gateway: a reconnect request ends the session and closes the socket",
          _gw10.closed_by == [_me10], repr(_gw10.closed_by))

    # A link that stops ACKing: the timer's second tick finds the first unanswered and closes the
    # socket itself — which is the only thing that unblocks a recv() waiting on a dead peer.
    _gwz10 = _GwWS10([_FAST10], fail_close=True)
    _t0_10 = time.monotonic()
    _gwrz10 = _try10(_n10.discord_gateway_run, _BOT10, lambda *a: None, _connect=lambda: _gwz10)
    check("notify gateway: an unACKed heartbeat closes the zombie link from the HEARTBEAT, not "
          "by waiting out recv()",
          _gwrz10 is None and [m for m in _gwz10.sent if m.get("op") == 1]
          and len(_gwz10.closed_by) == 2 and _gwz10.closed_by[0] != _me10
          and _gwz10.closed_by[1] == _me10 and time.monotonic() - _t0_10 < 3,
          repr((_gwz10.sent, _gwz10.closed_by, time.monotonic() - _t0_10)))

    _gw2_10 = _GwWS10([_FAST10,
                       {"op": 0, "t": "MESSAGE_CREATE", "d": {"channel_id": 1, "content": "x"}},
                       {"op": 11}, {"op": 7}], fail_close=True)

    def _handler_boom10(*a):
        raise RuntimeError("handler bug")

    _gwr2_10 = _try10(_n10.discord_gateway_run, _BOT10, _handler_boom10, _connect=lambda: _gw2_10)
    check("notify gateway: a failing handler, an ACK and a failing close all end the session "
          "quietly (the caller reconnects)",
          _gwr2_10 is None and _gw2_10.closed_by == [_me10], repr((_gwr2_10, _gw2_10.closed_by)))

    _gw3_10 = _GwWS10([_FAST10], idle=0.3, fail_heartbeat=True)
    _gwr3_10 = _try10(_n10.discord_gateway_run, _BOT10, lambda *a: None, _connect=lambda: _gw3_10)
    check("notify gateway: a heartbeat that cannot be sent stops the heartbeat, not the process",
          _gwr3_10 is None and not [m for m in _gw3_10.sent if m.get("op") == 1]
          and _gw3_10.closed_by == [_me10], repr((_gw3_10.sent, _gw3_10.closed_by)))

    # The other half of the zombie guard: a link that DOES ACK stays up. The sessions above either
    # never ACK or end before a second tick, so an op 11 that failed to re-arm `acked` passed all
    # of them — while a real Gateway would have been dropped by the heartbeat every other beat.
    import queue as _queue10  # noqa: E402

    class _GwAckWS10(_GwWS10):
        """A Gateway that ACKs each heartbeat and asks for a reconnect after the third."""

        def __init__(self, frames):
            super().__init__(frames)
            self._q = _queue10.Queue()

        def recv(self):
            if self.frames:
                return self.frames.pop(0)
            try:
                return self._q.get(timeout=self.idle)
            except _queue10.Empty:
                return ""

        def send(self, s):
            super().send(s)
            if _json10.loads(s).get("op") == 1:
                _beats = sum(m.get("op") == 1 for m in self.sent)
                self._q.put(_json10.dumps({"op": 11} if _beats < 3 else {"op": 7}))

        def close(self):
            super().close()
            self._q.put("")

    # 200 ms beats: the ACK is handled well inside one interval even on a loaded runner.
    _gwa10 = _GwAckWS10([{"op": 10, "d": {"heartbeat_interval": 200}}])
    _gwra10 = _try10(_n10.discord_gateway_run, _BOT10, lambda *a: None, _connect=lambda: _gwa10)
    check("notify gateway: an ACKed heartbeat keeps the link up — only the session closes it",
          _gwra10 is None and sum(m.get("op") == 1 for m in _gwa10.sent) == 3
          and _gwa10.closed_by == [_me10], repr((_gwa10.sent, _gwa10.closed_by)))

    # Without an injected socket it builds its own through websocket-client — stood in for here,
    # so nothing dials Discord — and when that package is missing it warns ONCE and returns.
    _ws_mod_saved10 = _sys10_mod.modules.get("websocket", "absent")
    _warned_saved10 = _n10._ws_warned[0]
    _cc_calls10 = []
    _gw4_10 = _GwWS10([_SLOW10, {"op": 9}])

    def _create_connection10(url, timeout=None, enable_multithread=None):
        _cc_calls10.append((url, timeout, enable_multithread))
        return _gw4_10

    _cap_h10, _cap_off10 = _cap10("notifications")
    try:
        _sys10_mod.modules["websocket"] = NS(create_connection=_create_connection10)
        _n10.discord_gateway_run(_BOT10, lambda *a: None)
        _sys10_mod.modules["websocket"] = None          # `import websocket` -> ImportError
        _n10._ws_warned[0] = False
        _n10.discord_gateway_run(_BOT10, lambda *a: None)
        _n10.discord_gateway_run(_BOT10, lambda *a: None)
    finally:
        _cap_off10()
        _n10._ws_warned[0] = _warned_saved10
        if _ws_mod_saved10 == "absent":
            _sys10_mod.modules.pop("websocket", None)
        else:
            _sys10_mod.modules["websocket"] = _ws_mod_saved10
    check("notify gateway: the real connector dials the fixed Gateway URL, multithreaded",
          _cc_calls10 == [(_n10.DISCORD_GATEWAY_URL, 40, True)], repr(_cc_calls10))
    check("notify gateway: without websocket-client it warns once, not on every reconnect",
          sum("websocket-client" in m for m in _cap_h10.msgs) == 1, repr(_cap_h10.msgs))
finally:
    for _k10, _v10 in _n10_saved.items():
        setattr(_n10, _k10, _v10)
    _n10.urllib.request.urlopen = _n10_urlopen_saved


# ══════════════════════════════════════════════════════════════════════════════════════════════
# B. panel/ops/terminal_session.py
# ══════════════════════════════════════════════════════════════════════════════════════════════
import pwd as _pwd10  # noqa: E402
import select as _sel10  # noqa: E402
import shutil as _shutil10  # noqa: E402
import sys as _sys10  # noqa: E402
import tempfile as _tmp10  # noqa: E402

from panel.ops import terminal_session as _ts10  # noqa: E402

_ts10_sessions_saved = dict(_ts10._sessions)
_ts10_saved = {k: getattr(_ts10, k) for k in
               ("time", "os", "subprocess", "_send_chan", "_open_local", "_open_tailscale",
                "_open_paramiko", "_login_shell")}
_ts10_core_saved = {k: getattr(_sm_core, k) for k in ("get_connection", "_resolve_ts_host")}
_ts10_getpw = _pwd10.getpwuid


class _Clock10:
    """A `time` stand-in: time() is set by the test, everything else is the real module."""

    def __init__(self, now=1000.0, sleep=None):
        self.now = now
        self._sleep = sleep

    def time(self):
        return self.now

    def monotonic(self):
        return time.monotonic()

    def sleep(self, s):
        return (self._sleep or time.sleep)(s)


class _OsProxy10:
    """`os` with the named functions replaced — every other name is the real module's."""

    def __init__(self, **over):
        self.__dict__.update(over)

    def __getattr__(self, name):
        return getattr(os, name)


def _sess10(sid="t10", out=None, exits=None, user_key=None):
    s = _ts10.Session(sid, "lbl-%s" % sid,
                      (lambda _sid, d: out.append(d)) if out is not None else (lambda _sid, d: None),
                      (lambda _sid, r: exits.append(r)) if exits is not None else (lambda _sid, r: None))
    s.user_key = user_key
    return s


def _open_fds10():
    return set(os.listdir("/proc/self/fd"))


class _Closable10:
    def __init__(self, fail=False):
        self.closed, self.fail = 0, fail

    def close(self):
        self.closed += 1
        if self.fail:
            raise OSError("already gone")


class _PumpChan10:
    def __init__(self, chunks, raise_after=False):
        self.chunks, self.raise_after = list(chunks), raise_after

    def recv_ready(self):
        if not self.chunks and self.raise_after:
            raise OSError("transport died")
        return bool(self.chunks)

    def recv(self, n):
        return self.chunks.pop(0)

    def exit_status_ready(self):
        return not self.chunks

    def close(self):
        pass


try:
    # ── who the local shell runs as, and what it is told about sudo ────────────────────────────
    _pwd10.getpwuid = lambda uid: NS(pw_name="svcpanel", pw_shell="/bin/bash")
    _acct10 = _ts10.panel_account()
    _pwd10.getpwuid = lambda uid: NS(pw_name="root", pw_shell="/bin/bash")
    _hint_root10 = _ts10.sudo_hint(None, True)

    def _nopw10(uid):
        raise KeyError(uid)

    _pwd10.getpwuid = _nopw10
    _acct_fail10 = _ts10.panel_account()
    _hint_fail10 = _ts10.sudo_hint(None, True)
    _pwd10.getpwuid = _ts10_getpw
    check("terminal: the local account is named from the passwd entry, '' when unreadable",
          _acct10 == "svcpanel" and _acct_fail10 == "", repr((_acct10, _acct_fail10)))
    check("terminal: no sudo hint for a remote, for root, or when the account cannot be read",
          _ts10.sudo_hint(NS(name="r"), False) == "" and _hint_root10 == "" and _hint_fail10 == "",
          repr((_hint_root10, _hint_fail10)))

    # ── _drain_input: the pump writes what write() queued, keeps a partial, surfaces a dead fd ─
    _dsess10 = _sess10("drain")
    _writes10 = []

    def _w_partial(fd, chunk):
        _writes10.append(bytes(chunk))
        return 4 if len(_writes10) == 2 else len(chunk)

    _ts10.os = _OsProxy10(write=_w_partial)
    _dsess10._inq.extend([b"first", b"second-chunk", b"third"])
    _ts10._drain_input(_dsess10, 99)
    check("terminal drain: whole chunks are popped, a partial write keeps its UNWRITTEN tail",
          _writes10 == [b"first", b"second-chunk"]
          and list(_dsess10._inq) == [b"nd-chunk", b"third"],
          repr((_writes10, list(_dsess10._inq))))

    def _w_block(fd, chunk):
        raise BlockingIOError(11, "EAGAIN")

    _ts10.os = _OsProxy10(write=_w_block)
    _ts10._drain_input(_dsess10, 99)
    check("terminal drain: a full pty leaves the queue exactly as it was, for the next pass",
          list(_dsess10._inq) == [b"nd-chunk", b"third"], repr(list(_dsess10._inq)))

    def _w_dead(fd, chunk):
        raise OSError(5, "EIO")

    _ts10.os = _OsProxy10(write=_w_dead)
    _dead10 = _try10(_ts10._drain_input, _dsess10, 99)
    check("terminal drain: a dead descriptor RAISES (the pump ends) and drops the queue",
          isinstance(_dead10, tuple) and "OSError" in _dead10[1] and not _dsess10._inq,
          repr((_dead10, list(_dsess10._inq))))
    _ts10.os = os

    # ── Aikido 745379045: queueing a keystroke costs the same however much is already queued ───
    # write() summed every queued chunk on each call, and the cap is in BYTES, so one-byte events
    # could queue 262144 chunks and make every later write walk them all — ~4.5 ms an event on the
    # single hub, measured, against ~0.4 ms for any socket event. A running byte count now.
    class _NoWalk10(_collections10.deque):
        """A queue that fails the test if anything iterates it."""

        def __iter__(self):
            raise AssertionError("the input queue was walked")

    _qs10 = _sess10("qcount")
    _qs10._fd = 99                  # a pty attached (no pump: nothing drains)
    _qs10._inq = _NoWalk10([b"k"] * 200000)
    _qs10._inq_bytes = 200000
    _walked10 = _try10(_qs10.write, "a")
    check("terminal write: queueing input does not walk the queue already there (745379045)",
          _walked10 is None and len(_qs10._inq) == 200001 and _qs10._inq_bytes == 200001,
          repr((_walked10, len(_qs10._inq), getattr(_qs10, "_inq_bytes", None))))
    _qo10 = []
    _qc10 = _sess10("qcap", out=_qo10)
    _qc10._fd = 99
    _qc10._inq.append(b"z" * (_ts10._MAX_PENDING_INPUT - 1))
    _qc10._inq_bytes = _ts10._MAX_PENDING_INPUT - 1
    _qc10.write("ab")
    check("terminal write: ...and input past the byte bound is still dropped, with a message",
          len(_qc10._inq) == 1 and _qc10._inq_bytes == _ts10._MAX_PENDING_INPUT - 1
          and any("2 bytes of input were dropped" in o for o in _qo10), repr((_qo10, _qc10._inq_bytes)))
    # The count follows the drain exactly: a partial write takes off what was written, a popped
    # chunk its length, and an emptied queue reads zero.
    _qd10 = _sess10("qdrain")
    _qd10._fd = 99
    for _ch in ("first", "second-chunk", "third"):
        _qd10.write(_ch)
    _qwr10 = []

    def _qw_partial(fd, chunk):
        _qwr10.append(bytes(chunk))
        return 4 if len(_qwr10) == 2 else len(chunk)

    _ts10.os = _OsProxy10(write=_qw_partial)
    _ts10._drain_input(_qd10, 99)
    _q_mid10 = _qd10._inq_bytes
    _ts10.os = _OsProxy10(write=lambda fd, chunk: len(chunk))
    _ts10._drain_input(_qd10, 99)
    _ts10.os = os
    check("terminal drain: the byte count drops by exactly what was written, and is 0 when empty",
          _q_mid10 == len(b"nd-chunk") + len(b"third") and not _qd10._inq and _qd10._inq_bytes == 0,
          repr((_q_mid10, list(_qd10._inq), _qd10._inq_bytes)))
    _qz10 = _sess10("qdrift")
    _qz10._fd = 99
    _qz10.write("abc")
    _qz10._inq_bytes += 5000                        # a count that drifted up
    _ts10.os = _OsProxy10(write=lambda fd, chunk: len(chunk))
    _ts10._drain_input(_qz10, 99)
    _ts10.os = os
    check("terminal drain: a queue drained empty reads zero even after the count drifted",
          not _qz10._inq and _qz10._inq_bytes == 0, repr(_qz10._inq_bytes))
    # A count that drifted up must not refuse every keystroke: an empty queue is zero, whatever the
    # counter says — and it cannot drift at all under the lock, but a stale one heals here.
    _qh10 = _sess10("qheal")
    _qh10._fd = 99
    _qh10._inq_bytes = _ts10._MAX_PENDING_INPUT
    _qh10.write("a")
    check("terminal write: an empty queue takes input whatever a drifted count says",
          list(_qh10._inq) == [b"a"] and _qh10._inq_bytes == 1,
          repr((list(_qh10._inq), _qh10._inq_bytes)))
    # A full queue refused every event with a WARNING and an on-screen line EACH: a flood of
    # keystrokes into a program that is not reading wrote a log line and a message per event.
    # Once a second per session now, with the bytes counted.
    _qclk10 = _Clock10(7000.0)
    _ts10.time = _qclk10
    _qn10 = []
    _qf10 = _sess10("qflood", out=_qn10)
    _qf10._fd = 99
    _qf10._inq.append(b"z" * _ts10._MAX_PENDING_INPUT)
    _qf10._inq_bytes = _ts10._MAX_PENDING_INPUT
    _qcap10, _qoff10 = _cap10("panel.terminal")
    try:
        for _ in range(50):
            _qf10.write("k")
        _qclk10.now = 7001.0
        _qf10.write("k")
    finally:
        _qoff10()
        _ts10.time = time
    _q_notes10 = [o for o in _qn10 if "dropped" in o]
    _q_warned10 = [m for m in _qcap10.warned if "dropped" in m]
    check("terminal write: a flood into a full queue says so once a second, not once an event",
          len(_q_notes10) == 2 and "1 bytes" in _q_notes10[0] and "50 bytes" in _q_notes10[1],
          repr(_q_notes10[:4]))
    check("terminal write: ...and logs it once a second too",
          len(_q_warned10) == 2, repr(_q_warned10[:4]))

    # ── _send_chan: a short send is continued, not discarded ───────────────────────────────────
    class _Chan10:
        def __init__(self, answers):
            self.answers, self.got = list(answers), []

        def send(self, mv):
            self.got.append(bytes(mv))
            a = self.answers.pop(0) if self.answers else 0
            if isinstance(a, BaseException):
                raise a
            return a

    _ch10 = _Chan10([3, socket.timeout(), 5])
    _sent_n10 = _ts10._send_chan(_ch10, b"abcdefgh", budget=2.0)
    check("terminal send: a short channel send continues from where it stopped",
          _sent_n10 == 8 and _ch10.got == [b"abcdefgh", b"defgh", b"defgh"],
          repr((_sent_n10, _ch10.got)))
    _t0_10 = time.monotonic()
    _stuck10 = _ts10._send_chan(_Chan10([2]), b"abcdef", budget=0.1)
    check("terminal send: a channel that stops taking bytes returns the count sent, within budget",
          _stuck10 == 2 and time.monotonic() - _t0_10 < 1.5,
          "sent=%r after %.2fs" % (_stuck10, time.monotonic() - _t0_10))

    # ── _emit: the output ceiling cuts a firehose, says so ONCE, and re-opens next second ──────
    _clk10 = _Clock10(5000.0)
    _ts10.time = _clk10
    _out10 = []
    _es10 = _sess10("emit", out=_out10)
    _big10 = "x" * (400 * 1024)
    _es10._emit(_big10)
    _es10._emit("y" * (200 * 1024))
    _es10._emit("dropped")
    _clk10.now = 5001.0
    _es10._emit("next-second")
    _ts10.time = time
    check("terminal emit: past the per-second ceiling the output is cut with ONE notice",
          len(_out10) == 3 and _out10[0] is _big10 and "output truncated" in _out10[1]
          and _out10[2] == "next-second",
          repr([o[:30] for o in _out10]))

    # ── write(): the paths that do not queue ───────────────────────────────────────────────────
    _wo10, _wx10 = [], []
    _ws10 = _sess10("write", out=_wo10, exits=_wx10)
    _ws10.write("ls\n")
    check("terminal write: with no transport attached nothing is queued",
          not _ws10._inq, repr(list(_ws10._inq)))
    _ws10._chan = _Closable10()
    _ts10._send_chan = lambda chan, payload: 3
    _ws10.write("abcdefgh")
    check("terminal write: a channel that took only part of a paste reports what was dropped",
          any("5 bytes of input were dropped" in o for o in _wo10), repr(_wo10))

    def _send_boom(chan, payload):
        raise EOFError("channel closed")

    _ts10._send_chan = _send_boom
    _ws10.write("x")
    check("terminal write: a channel that fails on send ends the session, with a reason",
          _ws10.closed and _wx10 == ["the session ended"], repr(_wx10))
    _before10 = len(_wo10)
    _ws10.write("after close")
    check("terminal write: a closed session takes no more input",
          len(_wo10) == _before10, repr(_wo10[_before10:]))
    _ts10._send_chan = _ts10_saved["_send_chan"]

    # ── resize(): clamped, ignored when junk or closed, and a real pty really changes size ─────
    class _RChan10:
        def __init__(self, fail=False):
            self.calls, self.fail = [], fail

        def resize_pty(self, width, height):
            if self.fail:
                raise OSError("gone")
            self.calls.append((width, height))

        def close(self):
            pass

    _rs10 = _sess10("resize")
    _rs10._chan = _RChan10()
    _rs10.resize("200", "50")
    _rs10.resize(99999, 1)
    _rs10.resize(1, 99999)
    _rs10.resize("wide", 10)
    check("terminal resize: sizes are clamped to 20-500 x 5-200 and junk is ignored",
          _rs10._chan.calls == [(200, 50), (500, 5), (20, 200)], repr(_rs10._chan.calls))
    _rs10._chan = _RChan10(fail=True)
    _rs10.resize(80, 24)
    check("terminal resize: a transport that refuses the resize does not end the session",
          not _rs10.closed, "")
    _rs10._chan = _RChan10()
    _rs10.close("done")
    _rs10.resize(80, 24)
    check("terminal resize: a closed session sends no resize", _rs10._chan.calls == [],
          repr(_rs10._chan.calls))
    _pm10, _psl10 = pty.openpty()
    try:
        _fs10 = _sess10("resize-fd")
        _fs10._fd = _pm10
        _fs10.resize(123, 45)
        _rows10, _cols10 = struct.unpack("HHHH", fcntl.ioctl(_psl10, termios.TIOCGWINSZ,
                                                             b"\0" * 8))[:2]
        _fs10._fd = None
    finally:
        os.close(_pm10)
        os.close(_psl10)
    check("terminal resize: a local pty is really resized (read back from the slave)",
          (_rows10, _cols10) == (45, 123), repr((_rows10, _cols10)))

    # ── close(): once, only its own registry entry, and teardown steps are independent ─────────
    _cx10 = []
    _cs10 = _sess10("close-me", exits=_cx10)
    _cs10._chan, _cs10._client = _Closable10(fail=True), _Closable10()
    _newer10 = _sess10("close-me")
    with _ts10._sessions_lock:
        _ts10._sessions["close-me"] = _newer10
    _cs10.close("bye")
    _cs10.close("again")
    check("terminal close: on_exit runs exactly once, with the first reason",
          _cx10 == ["bye"], repr(_cx10))
    check("terminal close: a failing channel close does not stop the client being closed",
          _cs10._chan.closed == 1 and _cs10._client.closed == 1, "")
    check("terminal close: it removes only ITS OWN registry entry, not a newer one under that sid",
          _ts10.get("close-me") is _newer10, repr(_ts10.get("close-me")))
    with _ts10._sessions_lock:
        _ts10._sessions.pop("close-me", None)

    def _exit_boom(sid, reason):
        raise RuntimeError("socket gone")

    _eb10 = _ts10.Session("exit-boom", "l", lambda s, d: None, _exit_boom)
    _ebr10 = _try10(_eb10.close, "x")
    check("terminal close: a failing exit callback is contained", _ebr10 is None and _eb10.closed,
          repr(_ebr10))

    # ── _close_proc: escalate by signal until poll() says it is gone, and say when it is not ───
    class _Proc10:
        def __init__(self, dies_on=None, lookup=False):
            self.pid = 999999999            # no such process: getpgid raises, send_signal is used
            self.sigs, self.dies_on, self.lookup, self._dead = [], dies_on, lookup, False
            self.tries = 0

        def poll(self):
            return 0 if self._dead else None

        def send_signal(self, sig):
            self.tries += 1
            if self.lookup:
                raise ProcessLookupError()
            self.sigs.append(sig)
            if sig == self.dies_on:
                self._dead = True

    _pp10 = _sess10("proc")
    _pp10._proc = _Proc10(dies_on=signal.SIGTERM)
    _pp10._close_proc()
    check("terminal teardown: a process that ignores SIGHUP gets SIGTERM, and no SIGKILL after "
          "it has gone", _pp10._proc.sigs == [signal.SIGHUP, signal.SIGTERM],
          repr(_pp10._proc.sigs))
    _pp10._proc = _Proc10(lookup=True)
    _pp10._close_proc()
    check("terminal teardown: a process already gone ends the escalation at once",
          _pp10._proc.tries == 1, "signals attempted: %d" % _pp10._proc.tries)
    _cap_t10, _cap_toff10 = _cap10("panel.terminal")
    try:
        _pp10._proc = _Proc10()
        _pp10._close_proc()
    finally:
        _cap_toff10()
    check("terminal teardown: a process that outlives SIGKILL is REPORTED, not assumed dead",
          _pp10._proc.sigs == [signal.SIGHUP, signal.SIGTERM, signal.SIGKILL]
          and any("survived SIGKILL" in m for m in _cap_t10.msgs),
          repr(_cap_t10.msgs))

    # ── _pump_channel: bytes decoded across reads, and the shell's exit closes the session ─────
    _po10, _px10 = [], []
    _ps10 = _sess10("pump", out=_po10, exits=_px10)
    _ps10._chan = _PumpChan10([b"caf\xc3", b"\xa9 \xe2\x94", b"\x80 ok"])
    _ts10._pump_channel(_ps10)
    check("terminal pump: a character split across two reads arrives whole, not as U+FFFD",
          "".join(_po10) == "café ─ ok", repr(_po10))
    check("terminal pump: the shell exiting closes the session with that reason",
          _ps10.closed and _px10 == ["the shell exited"], repr(_px10))
    _pe10 = []
    _ps2_10 = _sess10("pump2", exits=_pe10)
    _ps2_10._chan = _PumpChan10([b""])
    _ts10._pump_channel(_ps2_10)
    _ps3_10 = _sess10("pump3", exits=_pe10)
    _ps3_10._chan = _PumpChan10([b"x"], raise_after=True)
    _ts10._pump_channel(_ps3_10)
    check("terminal pump: EOF, and a transport error, both end the session instead of spinning",
          _ps2_10.closed and _ps3_10.closed and _pe10 == ["the shell exited", "the shell exited"],
          repr(_pe10))

    # ── _register: one live shell per socket, and both caps ────────────────────────────────────
    with _ts10._sessions_lock:
        _ts10._sessions.clear()
    _live10 = _sess10("same-sid", user_key=1)
    _ts10._register(_live10, 1)
    _dup10 = _try10(_ts10._register, _sess10("same-sid", user_key=1), 1)
    check("terminal register: a second shell on a socket with a LIVE one is refused, not swapped",
          isinstance(_dup10, tuple) and "already open" in _dup10[1]
          and _ts10.get("same-sid") is _live10,
          repr(_dup10))
    _live10._closed = True           # closing: waiting for its teardown
    _repl10 = _sess10("same-sid", user_key=1)
    _repl_r10 = _try10(_ts10._register, _repl10, 1)
    check("terminal register: a session that is already closing is replaced",
          _repl_r10 is None and _ts10.get("same-sid") is _repl10, repr(_repl_r10))
    for _i10 in range(2):
        _ts10._register(_sess10("u1-%d" % _i10, user_key=1), 1)
    _cap_u10 = _try10(_ts10._register, _sess10("u1-x", user_key=1), 1)
    check("terminal register: a fourth shell for the same user is refused",
          isinstance(_cap_u10, tuple) and "You already have 3" in _cap_u10[1]
          and _ts10.get("u1-x") is None, repr(_cap_u10))
    for _i10 in range(_ts10._MAX_SESSIONS_TOTAL - _ts10.count()):
        _ts10._register(_sess10("other-%d" % _i10, user_key=100 + _i10), 100 + _i10)
    _cap_t10b = _try10(_ts10._register, _sess10("one-too-many", user_key=999), 999)
    check("terminal register: past the panel-wide ceiling a new shell is refused",
          isinstance(_cap_t10b, tuple) and "Too many terminal sessions" in _cap_t10b[1]
          and _ts10.count() == _ts10._MAX_SESSIONS_TOTAL, repr(_cap_t10b))

    # ── the idle sweeper closes only the shells nobody has typed into ──────────────────────────
    with _ts10._sessions_lock:
        _ts10._sessions.clear()
    _stale_x10, _fresh_x10 = [], []
    _stale10 = _sess10("stale", exits=_stale_x10)
    _fresh10 = _sess10("fresh", exits=_fresh_x10)
    _stale10.last_input = 10000.0 - _ts10._IDLE_TIMEOUT - 1
    _fresh10.last_input = 10000.0 - 5

    def _stop_sleep10(s):
        raise _Stop10()

    with _ts10._sessions_lock:
        _ts10._sessions.update({"stale": _stale10, "fresh": _fresh10})
    _ts10.time = _Clock10(10000.0, sleep=_stop_sleep10)
    _swept10 = _try10(_ts10._idle_sweeper)
    _ts10.time = time
    check("terminal idle sweep: a shell with no input for the timeout is closed, saying why",
          _stale_x10 == ["closed after 15 minutes with no input"] and _ts10.get("stale") is None,
          repr((_swept10, _stale_x10)))
    check("terminal idle sweep: a shell typed into recently is left open",
          _fresh_x10 == [] and _ts10.get("fresh") is _fresh10, repr(_fresh_x10))
    _sup10 = []
    _ts10.start_idle_sweeper(lambda name, fn: _sup10.append((name, fn)))
    check("terminal idle sweep: it is started under the app's supervisor",
          _sup10 == [("terminal-idle-sweeper", _ts10._idle_sweeper)], repr(_sup10))
    _ts10.close_for_sid("fresh", "tab closed")
    _ts10.close_for_sid("never-opened")
    check("terminal: close_for_sid closes the session it names and ignores an unknown sid",
          _fresh_x10 == ["tab closed"] and _ts10.count() == 0, repr(_fresh_x10))

    # ── open_session: the transport is chosen by host kind, and every failure is contained ─────
    _picked10 = []
    _ts10._open_local = lambda sess, c, r: _picked10.append(("local", c, r))
    _ts10._open_tailscale = lambda sess, srv, c, r: _picked10.append(("tailscale", srv.name))
    _ts10._open_paramiko = lambda sess, srv, c, r: _picked10.append(("paramiko", srv.name))
    _s_l10 = _ts10.open_session("o1", None, True, 1, lambda s, d: None, lambda s, r: None,
                                cols=90, rows=30)
    _s_t10 = _ts10.open_session("o2", NS(name="ts", auth_method="tailscale"), False, 1,
                                lambda s, d: None, lambda s, r: None)
    _s_p10 = _ts10.open_session("o3", NS(name="kp", auth_method="key"), False, 2,
                                lambda s, d: None, lambda s, r: None)
    check("terminal open: local, tailscale and key hosts each get their own transport",
          _picked10 == [("local", 90, 30), ("tailscale", "ts"), ("paramiko", "kp")]
          and _s_l10.label == "local" and _s_t10.label == "ts" and _ts10.count() == 3,
          repr(_picked10))
    for _s10 in (_s_l10, _s_t10, _s_p10):
        _s10.close("")

    def _open_refuses(sess, srv, c, r):
        raise _ts10.TerminalError("That host has no SSH connection.")

    def _open_crashes(sess, srv, c, r):
        raise OSError("connection reset")

    _ts10._open_paramiko = _open_refuses
    _ref10 = _try10(_ts10.open_session, "o4", NS(name="kp"), False, 1,
                    lambda s, d: None, lambda s, r: None)
    _ts10._open_paramiko = _open_crashes
    _cap_t10, _cap_toff10 = _cap10("panel.terminal")     # keeps its traceback out of the output
    try:
        _crash10 = _try10(_ts10.open_session, "o5", NS(name="kp"), False, 1,
                          lambda s, d: None, lambda s, r: None)
    finally:
        _cap_toff10()
    check("terminal open: a refusal reaches the operator in its own words, and unregisters",
          _ref10 == ("RAISED", repr(_ts10.TerminalError("That host has no SSH connection.")))
          and _ts10.get("o4") is None, repr(_ref10))
    check("terminal open: an unexpected failure becomes a TerminalError naming only the type",
          isinstance(_crash10, tuple) and "Could not start a shell on kp (OSError)" in _crash10[1]
          and "connection reset" not in _crash10[1] and _ts10.get("o5") is None,
          repr(_crash10))

    # A close that lands WHILE the transport is opening: the opener attaches a client to a session
    # already marked closed, and open_session must release it rather than leak a live login.
    _late_client10 = _Closable10()

    def _open_then_closed(sess, srv, c, r):
        sess.close("tab closed while connecting")
        sess._client = _late_client10

    _ts10._open_paramiko = _open_then_closed
    _late10 = _try10(_ts10.open_session, "o6", NS(name="slow"), False, 1,
                     lambda s, d: None, lambda s, r: None)
    check("terminal open: a session closed mid-open has its late transport torn down",
          isinstance(_late10, tuple) and "closed while it was opening" in _late10[1]
          and _late_client10.closed == 1, repr(_late10))
    for _k10 in ("_open_local", "_open_tailscale", "_open_paramiko"):
        setattr(_ts10, _k10, _ts10_saved[_k10])

    # ── _open_paramiko: a client of its OWN, never the pooled one ──────────────────────────────
    _gc_calls10 = []
    _sm_core.get_connection = lambda srv, **kw: (_gc_calls10.append(kw) or None)
    _pnone10 = _try10(_ts10._open_paramiko, _sess10("pk0"), NS(name="h"), 80, 24)
    check("terminal paramiko: no connection is a TerminalError, asked for UNPOOLED",
          isinstance(_pnone10, tuple) and "no SSH connection" in _pnone10[1]
          and _gc_calls10 == [{"force_new": True, "pooled": False}],
          repr((_pnone10, _gc_calls10)))

    class _PkChan10(_PumpChan10):
        def __init__(self):
            _PumpChan10.__init__(self, [])
            self.timeout = "unset"

        def settimeout(self, t):
            self.timeout = t

    class _PkClient10(_Closable10):
        def __init__(self):
            _Closable10.__init__(self)
            self.shell_kw, self.chan = None, _PkChan10()

        def invoke_shell(self, **kw):
            self.shell_kw = kw
            return self.chan

    _pkc10 = _PkClient10()
    _sm_core.get_connection = lambda srv, **kw: _pkc10
    _pkx10 = []
    _pks10 = _sess10("pk1", exits=_pkx10)
    _ts10._open_paramiko(_pks10, NS(name="h"), "100", "30")
    _pks10._pump.join(timeout=5)
    check("terminal paramiko: an xterm shell at the browser's size, on a non-blocking channel",
          _pkc10.shell_kw == {"term": "xterm-256color", "width": 100, "height": 30}
          and _pkc10.chan.timeout == 0.0 and _pks10._client is _pkc10,
          repr((_pkc10.shell_kw, _pkc10.chan.timeout)))
    check("terminal paramiko: when the shell exits the session closes and releases its client",
          _pkx10 == ["the shell exited"] and _pkc10.closed == 1, repr((_pkx10, _pkc10.closed)))
    for _k10, _v10 in _ts10_core_saved.items():
        setattr(_sm_core, _k10, _v10)

    # ── _open_tailscale: the ssh argv, and no descriptor leak when ssh cannot be started ───────
    _sm_core._resolve_ts_host = lambda srv: srv.host
    _pop_calls10 = []

    class _FakeTsProc10:
        pid = 999999998

        def poll(self):
            return 0

    def _popen_ok10(argv, **kw):
        _pop_calls10.append((argv, kw))
        return _FakeTsProc10()

    def _popen_missing10(argv, **kw):
        raise FileNotFoundError("ssh")

    _tsrv10 = NS(name="tsbox", host="box.tail.ts.net", username="admin", port=2222,
                 auth_method="tailscale")
    _ts10.subprocess = NS(Popen=_popen_missing10)
    _fds_before10 = _open_fds10()
    _miss10 = _try10(_ts10._open_tailscale, _sess10("ts0"), _tsrv10, 80, 24)
    _fds_after10 = _open_fds10()
    check("terminal tailscale: no ssh client is an error, and BOTH pty ends are closed",
          isinstance(_miss10, tuple) and "FileNotFoundError" in _miss10[1]
          and _fds_after10 == _fds_before10,
          "leaked fds: %r" % sorted(_fds_after10 - _fds_before10))
    _ts10.subprocess = NS(Popen=_popen_ok10)
    _tsx10 = []
    _tss10 = _sess10("ts1", exits=_tsx10)
    _ts10._open_tailscale(_tss10, _tsrv10, 100, 40)
    _tss10._pump.join(timeout=5)
    _targv10, _tkw10 = _pop_calls10[0] if _pop_calls10 else (None, {})
    # The destination follows `--`: a stored login or host is never read as an ssh option
    # (GHSA-hh39-76g3-wxcx, F4).
    check("terminal tailscale: ssh -tt to user@host (after --) on the host's port, in its own "
          "session",
          _targv10 == ["ssh", "-tt", "-o", "StrictHostKeyChecking=accept-new",
                       "-o", "ConnectTimeout=20", "-p", "2222", "--", "admin@box.tail.ts.net"]
          and _tkw10.get("start_new_session") is True
          and (_tkw10.get("env") or {}).get("TERM") == "xterm-256color",
          repr(_targv10))
    check("terminal tailscale: the pty's far end closing ends the session (the pump retires)",
          _tsx10 == ["the shell exited"] and _tss10._fd is None, repr(_tsx10))
    _ts10.subprocess = _ts10_saved["subprocess"]
    _sm_core._resolve_ts_host = _ts10_core_saved["_resolve_ts_host"]

    # ── _pump_fd: it OWNS the descriptor — writes the queued input, survives EAGAIN, retires ───
    # A real pty pair: the test holds the slave end (standing in for the shell), the pump the
    # master. Input queued by write() must come out of the slave; the slave's echo comes back.
    _pm2_10, _psl2_10 = pty.openpty()
    _reads10 = {"n": 0}

    def _flaky_read10(fd, n):
        _reads10["n"] += 1
        if _reads10["n"] == 1:
            raise BlockingIOError(11, "EAGAIN")     # select said readable; the byte was gone
        return os.read(fd, n)

    _closes10 = []

    def _close_then_ebadf10(fd):
        os.close(fd)
        _closes10.append(fd)
        raise OSError(9, "EBADF")                   # someone else already had it: still "done"

    _fo10, _fx10 = [], []
    _fps10 = _sess10("pumpfd", out=_fo10, exits=_fx10)
    _fps10._fd = _pm2_10
    _fps10._inq.append(b"typed-line\n")
    _ts10.os = _OsProxy10(read=_flaky_read10, close=_close_then_ebadf10)
    _fpt10 = threading.Thread(target=_ts10._pump_fd, args=(_fps10,), daemon=True)
    _fpt10.start()
    _got10 = b""
    _deadline10 = time.monotonic() + 5
    while b"typed-line\n" not in _got10 and time.monotonic() < _deadline10:
        if _sel10.select([_psl2_10], [], [], 0.1)[0]:
            _got10 += os.read(_psl2_10, 1024)
    _deadline10 = time.monotonic() + 5
    while "typed-line" not in "".join(_fo10) and time.monotonic() < _deadline10:
        time.sleep(0.02)
    os.close(_psl2_10)                               # the shell exits: the master reads EIO
    _fpt10.join(timeout=5)
    _ts10.os = os
    check("terminal pump: queued input is written to the shell by the pump",
          b"typed-line\n" in _got10, repr(_got10))
    check("terminal pump: an EAGAIN on read is not the end of the session",
          _reads10["n"] >= 2 and "typed-line" in "".join(_fo10), repr((_reads10, _fo10)))
    check("terminal pump: when the shell goes the pump closes its own fd once, even if that "
          "close reports EBADF, and the session ends",
          _closes10 == [_pm2_10] and _fps10._fd is None and _fx10 == ["the shell exited"],
          repr((_closes10, _fx10)))

    # A read that returns b"" (a clean EOF rather than the pty's EIO) ends the session too.
    _pm5_10, _psl5_10 = pty.openpty()
    _ex5_10 = []
    _eof10 = _sess10("pump-eof", exits=_ex5_10)
    _eof10._fd = _pm5_10
    _ts10.os = _OsProxy10(read=lambda fd, n: b"")
    os.write(_psl5_10, b"x\n")                        # makes the master readable
    _et10 = threading.Thread(target=_ts10._pump_fd, args=(_eof10,), daemon=True)
    _et10.start()
    _et10.join(timeout=5)
    _ts10.os = os
    os.close(_psl5_10)
    check("terminal pump: a clean EOF on the pty ends the session and releases the fd",
          _ex5_10 == ["the shell exited"] and _eof10._fd is None, repr(_ex5_10))

    _pm3_10, _psl3_10 = pty.openpty()
    _bx10 = []

    def _out_boom10(sid, data):
        raise RuntimeError("socket write failed")

    _bs10 = _ts10.Session("pump-boom", "l", _out_boom10, lambda s, r: _bx10.append(r))
    _bs10._fd = _pm3_10
    os.write(_psl3_10, b"output\n")
    _bt10 = threading.Thread(target=_ts10._pump_fd, args=(_bs10,), daemon=True)
    _bt10.start()
    _bt10.join(timeout=5)
    os.close(_psl3_10)
    check("terminal pump: an error delivering output ends the session instead of killing the "
          "thread silently", _bx10 == ["the shell exited"] and _bs10._fd is None, repr(_bx10))

    # ── _close_fd: a wedged pump's descriptor is taken back by the caller ──────────────────────
    _pm4_10, _psl4_10 = pty.openpty()
    _wd10 = _sess10("wedged")
    _wd10._fd, _wd10._pump = _pm4_10, None
    _cap_t10, _cap_toff10 = _cap10("panel.terminal")
    try:
        _wd10._close_fd()
        _wd2_10 = _sess10("wedged2")
        _wd2_10._fd = 999999                         # no such descriptor: EBADF must be tolerated
        _wdr10 = _try10(_wd2_10._close_fd)
    finally:
        _cap_toff10()
    try:
        fcntl.fcntl(_pm4_10, fcntl.F_GETFD)
        _still_open10 = True
    except OSError:
        _still_open10 = False
    os.close(_psl4_10)
    check("terminal teardown: with no pump to retire it, the caller closes the pty master and "
          "says so (at WARNING)", not _still_open10 and _wd10._fd is None
          and any("pump did not retire" in m for m in _cap_t10.warned), repr(_cap_t10.msgs))
    check("terminal teardown: a descriptor already gone (EBADF) is not an error",
          _wdr10 is None and _wd2_10._fd is None, repr(_wdr10))

    # ── the idle sweeper survives a bad entry, and the login shell survives a bad passwd ───────
    _bad10 = _sess10("bad-entry")
    _bad10.last_input = None                         # makes the staleness arithmetic raise
    with _ts10._sessions_lock:
        _ts10._sessions["bad-entry"] = _bad10
    _ts10.time = _Clock10(10000.0, sleep=_stop_sleep10)
    _cap_t10, _cap_toff10 = _cap10("panel.terminal")
    try:
        _sw2_10 = _try10(_ts10._idle_sweeper)
    finally:
        _cap_toff10()
        _ts10.time = time
    with _ts10._sessions_lock:
        _ts10._sessions.pop("bad-entry", None)
    check("terminal idle sweep: a failing pass is logged and the sweeper goes on to sleep",
          _sw2_10 == ("RAISED", repr(_Stop10()))
          and any("idle sweep failed" in m for m in _cap_t10.msgs), repr((_sw2_10, _cap_t10.msgs)))
    _pwd10.getpwuid = _nopw10
    _shell_nopw10 = _ts10._login_shell()
    _pwd10.getpwuid = _ts10_getpw
    check("terminal: an account whose passwd entry cannot be read still gets a real shell",
          _shell_nopw10 == "/bin/bash", repr(_shell_nopw10))

    # ── _open_local, for real: the child gets a controlling tty and a default SIGINT ───────────
    # The Ctrl-C bug the preexec hook fixes is only visible IN the child, so run one: a tiny
    # program standing in for the login shell reports whether its stdin is its controlling
    # terminal (tcgetpgrp succeeds and names its own group) and whether SIGINT is still ignored.
    # SIGINT is IGNORED in this process while it spawns, because an ignored disposition is exactly
    # what survives fork+exec and what the hook must undo.
    _probe_dir10 = _tmp10.mkdtemp(prefix="panel-term10-")
    _probe10 = os.path.join(_probe_dir10, "probe-shell")
    with open(_probe10, "w") as _f10:
        _f10.write("#!%s\n"
                   "import os, signal, sys\n"
                   "try:\n"
                   "    ctty = os.tcgetpgrp(0) == os.getpgrp()\n"
                   "except OSError:\n"
                   "    ctty = False\n"
                   "print('PROBE ctty=%%s sigint_ignored=%%s term=%%s' %% (ctty, "
                   "signal.getsignal(signal.SIGINT) is signal.SIG_IGN, "
                   "os.environ.get('TERM')), flush=True)\n" % _sys10.executable)
    os.chmod(_probe10, 0o700)
    _lo10, _lx10, _ldone10 = [], [], threading.Event()
    _ls10 = _ts10.Session("local10", "local", lambda s, d: _lo10.append(d),
                          lambda s, r: (_lx10.append(r), _ldone10.set()))
    _ts10._login_shell = lambda: _probe10
    _sigint_prev10 = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        _lopen10 = _try10(_ts10._open_local, _ls10, 80, 24)
    finally:
        signal.signal(signal.SIGINT, _sigint_prev10)
        _ts10._login_shell = _ts10_saved["_login_shell"]
    _ldone10.wait(timeout=15)
    _ltext10 = "".join(_lo10)
    check("terminal local: the shell is started and its output reaches the browser",
          _lopen10 is None and "PROBE" in _ltext10, repr((_lopen10, _ltext10[:200])))
    check("terminal local: the shell has a CONTROLLING terminal (so Ctrl-C has somewhere to go)",
          "ctty=True" in _ltext10, repr(_ltext10[:200]))
    check("terminal local: an ignored SIGINT is reset to default in the shell",
          "sigint_ignored=False" in _ltext10, repr(_ltext10[:200]))
    check("terminal local: TERM is xterm-256color, and the shell exiting closes the session",
          "term=xterm-256color" in _ltext10 and _lx10 == ["the shell exited"],
          repr((_ltext10[:200], _lx10)))
    _ls10.close("")
    _shutil10.rmtree(_probe_dir10, ignore_errors=True)
finally:
    _pwd10.getpwuid = _ts10_getpw
    for _k10, _v10 in _ts10_saved.items():
        setattr(_ts10, _k10, _v10)
    for _k10, _v10 in _ts10_core_saved.items():
        setattr(_sm_core, _k10, _v10)
    with _ts10._sessions_lock:
        _ts10._sessions.clear()
        _ts10._sessions.update(_ts10_sessions_saved)


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Shared fixture for C and E: an in-memory database on a throwaway Flask app
# ══════════════════════════════════════════════════════════════════════════════════════════════
from flask import Flask as _Flask10  # noqa: E402

from panel.core import panel_state as _pstate10  # noqa: E402
from panel.db.models import (AuditLog as _Audit10, GameServer as _GS10, HostSample as _HS10,  # noqa: E402
                             MetricSample as _MS10, RemoteServer as _RS10, ServerTag as _Tag10,
                             db as _db10)

_dbapp10 = _Flask10("unit_part13_db")
_dbapp10.config.update(SQLALCHEMY_DATABASE_URI="sqlite://", SQLALCHEMY_TRACK_MODIFICATIONS=False,
                       SECRET_KEY="unit-part13", TESTING=True)
_db10.init_app(_dbapp10)


def _reset_db10():
    """A fresh, empty schema, and no row-keyed state. Call inside _dbapp10's app context.

    A fresh database hands out ids 1, 2, 3 again, and the panel-state maps keyed by row id still
    hold what earlier parts wrote for THEIR rows 1, 2, 3 (part12's stops leave _expected_offline
    entries): the monitor then read gmod1 as a stop the panel had issued and alerted nothing. The
    maps are emptied here, as the pruner would for rows that no longer exist; _restore_pstate10
    puts back what they held.
    """
    _db10.session.rollback()
    _db10.drop_all()
    _db10.create_all()
    for _m, _snap in _pstate_snap10:
        _m.clear()


def _mk_remote10(name, **kw):
    kw.setdefault("host", "192.0.2.10")
    kw.setdefault("username", "root")
    kw.setdefault("auth_method", "tailscale")
    r = _RS10(name=name, **kw)
    _db10.session.add(r)
    _db10.session.commit()
    return r


def _mk_gs10(remote, short, game_type="gmod", port=27015, **kw):
    kw.setdefault("installed", True)
    kw.setdefault("status", "online")
    g = _GS10(remote_id=remote.id, name=kw.pop("name", short), short_name=short,
              game_type=game_type, port=port, **kw)
    _db10.session.add(g)
    _db10.session.commit()
    return g


# Every row-keyed panel-state map, so what the monitor writes (and prunes) here is put back.
_pstate_snap10 = [(m, dict(m)) for entries in _pstate10.keyed_state_with_locks()
                  for m, _lock in entries]
_pstate_prune10 = list(_pstate10._last_sample_prune)


def _restore_pstate10():
    for m, snap in _pstate_snap10:
        m.clear()
        m.update(snap)
    _pstate10._last_sample_prune[:] = _pstate_prune10


# A tripwire under every transport for sections C and E. Their hosts are fixture rows at
# documentation addresses, so a stub that misses would otherwise go on to spawn a real `ssh` (the
# tailscale transport) or run a real local command — and most callers here swallow the error, so
# the check it belonged to could still pass. Whatever reaches one of these is recorded, and each
# section ends by asserting nothing did. (Found the hard way: a package-level stub restored in
# part02 shadowed ssh_manager's __getattr__, and app._live_run_state went past a _core stub.)
_trip10 = []
_TRIP_NAMES10 = ("_run_via_ssh_cli", "get_connection", "_exec_local_shell", "_exec_local_argv")


def _arm10():
    saved = {n: getattr(_sm_core, n) for n in _TRIP_NAMES10}

    def _wire(name):
        def _t(*a, **k):
            _trip10.append(name)
            raise ConnectionError("part13 tripwire: a test reached the real %s" % name)
        return _t

    for n in _TRIP_NAMES10:
        setattr(_sm_core, n, _wire(n))
    return saved


def _disarm10(saved):
    for n, v in saved.items():
        setattr(_sm_core, n, v)
    del _trip10[:]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# C. panel/services/monitoring.py
# ══════════════════════════════════════════════════════════════════════════════════════════════
from panel.services import monitoring as _mon10  # noqa: E402

_MON_STUBBED10 = ("run_command", "run_privileged", "_remote_listening_ports", "host_live_metrics",
                  "game_map", "server_live_metrics", "lgsm_get_values", "sm_player_slots",
                  "sm_game_engine", "sm_console_status", "sm_player_count_via_lgsm_query",
                  "sm_get_server_status", "remote_reboot", "remote_fail2ban_attempt_counts",
                  "remote_ufw_blocked_ips", "remote_ufw_deny_ip", "remote_ufw_undeny_ip",
                  "tailnet_exempt_ips", "load_config", "notifications", "time", "db",
                  "_probe_host", "_query_server_slots", "_query_host_metrics",
                  "_lgsm_maintenance_running", "_host_reachable", "_host_idle_state",
                  "_fire_reboot_when_empty", "_host_disk_pct", "_host_load_mem",
                  "_host_restart_flags", "_server_max_config")
_mon_saved10 = {k: getattr(_mon10, k) for k in _MON_STUBBED10}
_alerts10 = []


def _mon_restore10(*names):
    for k in names or _MON_STUBBED10:
        setattr(_mon10, k, _mon_saved10[k])


def _raiser10(exc):
    def _f(*a, **k):
        raise exc
    return _f


_mon10.notifications = NS(
    notify=lambda key, title, body="": _alerts10.append((key, title, body)),
    alerts_muted=_n10.alerts_muted,
    get_thresholds=lambda: {"disk_pct": 90, "load_pct": 200, "mem_pct": 90, "load_mins": 1})
_mon_trip_saved10 = _arm10()

try:
    # ── _host_reachable: an unanswered probe is "no", whichever transport failed ───────────────
    _mon10.run_command = lambda r, cmd, timeout=None: ("ok\n", "", 0)
    _reach_ok10 = _mon10._host_reachable(NS())
    _mon10.run_command = lambda r, cmd, timeout=None: ("", "SSH command timed out", -1)
    _reach_ts10 = _mon10._host_reachable(NS())
    _mon10.run_command = _raiser10(ConnectionError("down"))
    _reach_raise10 = _mon10._host_reachable(NS())
    check("monitor reachability: an answer is reachable; a timed-out read and a raise are not",
          _reach_ok10 is True and _reach_ts10 is False and _reach_raise10 is False,
          repr((_reach_ok10, _reach_ts10, _reach_raise10)))

    # ── disk / load probes: parsed when answered, None when not ────────────────────────────────
    _mon10.run_command = lambda r, cmd, timeout=None: ("87%\n", "", 0)
    _disk10 = _mon10._host_disk_pct(NS())
    _mon10.run_command = lambda r, cmd, timeout=None: ("", "timed out", -1)
    _disk_none10 = _mon10._host_disk_pct(NS())
    _load_none10 = _mon10._host_load_mem(NS())
    _mon10.run_command = lambda r, cmd, timeout=None: ("2.00 4 55\n", "", 0)
    _load10 = _mon10._host_load_mem(NS())
    _mon10.run_command = _raiser10(ConnectionError("down"))
    _disk_raise10 = _mon10._host_disk_pct(NS())
    check("monitor probes: disk % and (load-per-core %, mem %) are read from the host's answer",
          _disk10 == 87 and _load10 == (50, 55), repr((_disk10, _load10)))
    check("monitor probes: an empty or failed read is None — never 0% disk or 0% load",
          _disk_none10 is None and _load_none10 == (None, None) and _disk_raise10 is None,
          repr((_disk_none10, _load_none10, _disk_raise10)))
    _mon_restore10("run_command")

    # ── _probe_host: a port scan that raises is 'could not look', not 'nothing listening' ──────
    _mon10._host_reachable = lambda r: True
    _mon10._remote_listening_ports = _raiser10(ConnectionError("scan died"))
    _mon10._host_disk_pct = lambda r: 40
    _mon10._host_load_mem = lambda r: (10, 20)
    _mon10._host_restart_flags = lambda r: {"gmod1"}
    _probe10 = _mon10._probe_host(NS(id=7, name="h"))
    _mon10._host_reachable = _raiser10(RuntimeError("bug"))
    _probe_bug10 = _mon10._probe_host(NS(id=8, name="h"))
    _mon_restore10("_host_reachable", "_remote_listening_ports", "_host_disk_pct",
                   "_host_load_mem", "_host_restart_flags")
    check("monitor probe: a failed port scan is None (skip the servers), the rest still reported",
          _probe10 == (7, {"reachable": True, "disk": 40, "load_mem": (10, 20), "ports": None,
                           "restart_flagged": {"gmod1"}}), repr(_probe10))
    check("monitor probe: a probe that raises reads as unreachable, never as healthy",
          _probe_bug10 == (8, {"reachable": False}), repr(_probe_bug10))

    # ── the dashboard metrics workers ──────────────────────────────────────────────────────────
    _R10 = NS(id=3, name="h")
    check("monitor metrics work: only INSTALLED servers are frozen into work items",
          _mon10._metrics_work([NS(installed=True, remote=_R10, id=1, short_name="a", port=1,
                                   game_type="gmod", query_type=None, remote_id=3),
                                NS(installed=False, remote=_R10, id=2, short_name="b", port=2,
                                   game_type="gmod", query_type=None, remote_id=3)])
          == [(_R10, 1, "a", 1, "gmod", None, 3)], "")
    _maps10 = []
    _mon10.game_map = lambda r, sn, gt, port, qt: (_maps10.append(sn) or "de_dust2")
    _mon10.server_live_metrics = lambda r, sn, port: {"game_procs": 2 if sn == "run" else 0,
                                                      "ram_total": 8}
    _qm_run10 = _mon10._query_server_metrics((_R10, 1, "run", 27015, "css", None, 3))
    _qm_idle10 = _mon10._query_server_metrics((_R10, 2, "idle", 27016, "css", None, 3))
    _mon10.game_map = _raiser10(OSError("gamedig missing"))
    _qm_nomap10 = _mon10._query_server_metrics((_R10, 1, "run", 27015, "css", None, 3))
    _mon10.server_live_metrics = _raiser10(ConnectionError("down"))
    _qm_down10 = _mon10._query_server_metrics((_R10, 4, "run", 27015, "css", None, 3))
    check("monitor server metrics: the map is queried only for a RUNNING game",
          _qm_run10[3] == "de_dust2" and _qm_idle10[3] == "" and _maps10 == ["run"],
          repr((_qm_run10, _qm_idle10, _maps10)))
    check("monitor server metrics: a failed map read is '' and a failed sample is None",
          _qm_nomap10[1] is not None and _qm_nomap10[3] == ""
          and _qm_down10 == (4, None, 3, ""), repr((_qm_nomap10, _qm_down10)))

    _mon10.host_live_metrics = lambda r: {
        "host": {"ram_total": 8 << 30, "cpu_percent": 12.0},
        "users": {"run": {"game_cpu_percent": 30.0, "game_ram_mb": 900, "game_procs": 3,
                          "game_uptime_secs": 60, "game_ram_percent": 11.0}},
        "ports": {27015}}
    _mon10.game_map = _raiser10(OSError("gamedig missing"))
    _hm10 = _mon10._query_host_metrics((_R10, [(1, "run", 27015, "css", None),
                                                (2, "idle", 27016, "css", None)]))
    check("monitor host metrics: one sample, sliced per game (a stopped game reads 0, port shut)",
          len(_hm10) == 2 and _hm10[0][1]["game_cpu_percent"] == 30.0
          and _hm10[0][1]["port_open"] is True and _hm10[0][3] == ""
          and _hm10[1][1]["game_procs"] == 0 and _hm10[1][1]["port_open"] is False,
          repr(_hm10)[:300])
    _hmaps10 = []
    _mon10.game_map = lambda r, sn, gt, port, qt: (_hmaps10.append(sn) or "cs_office")
    _hm2_10 = _mon10._query_host_metrics((_R10, [(1, "run", 27015, "css", None),
                                                 (2, "idle", 27016, "css", None)]))
    check("monitor host metrics: the map is asked for only for the RUNNING game",
          _hmaps10 == ["run"] and [x[3] for x in _hm2_10] == ["cs_office", ""],
          repr((_hmaps10, [x[3] for x in _hm2_10])))
    _mon_restore10("game_map", "server_live_metrics", "host_live_metrics")

    # ── /api/dashboard/metrics: what a sample becomes in the payload ─────────────────────────────
    # "up" is a live game process, not a listening port: the port can belong to something else, and
    # a stopped game can leave it held. Reporting every sampled server as up (in _server_metrics,
    # since api_dashboard_metrics was split) left every suite green — the samplers above are tested,
    # the step that turns a sample into the payload was not. Driven through _sample_metrics, the
    # loop the route calls, with the host sampler stubbed.
    from panel.routes import api as _api10
    _api10_qhm = _api10._query_host_metrics
    try:
        _api10._query_host_metrics = lambda item: [
            (1, {"game_procs": 3, "game_cpu_percent": 30.0, "game_ram_mb": 900, "port_open": True,
                 "ram_total": 8 << 30}, 3, "de_dust2"),
            (2, {"game_procs": 0, "port_open": True, "ram_total": 8 << 30}, 3, ""),
            (4, None, 3, "")]
        _smx10 = _api10._sample_metrics([("h",)], {3: NS(display_name="h", is_local=False)}, {})
    finally:
        _api10._query_host_metrics = _api10_qhm
    check("dashboard metrics: 'up' is a live game process, not a port something else may hold",
          _smx10.get("1", {}).get("up") is True and _smx10.get("2", {}).get("up") is False,
          repr(_smx10))
    check("dashboard metrics: ...a running game carries its CPU, RAM and map",
          _smx10.get("1", {}).get("cpu") == 30.0 and _smx10.get("1", {}).get("ram_mb") == 900
          and _smx10.get("1", {}).get("map") == "de_dust2", repr(_smx10.get("1")))
    check("dashboard metrics: ...and a server whose sample failed is left out, not reported idle",
          "4" not in _smx10, repr(sorted(_smx10)))

    # ── _server_slots: which reading wins, and what an unreadable server reports ───────────────
    _mon10.lgsm_get_values = lambda r, sn, ln, keys: {"maxplayers": "24"}
    _gsl10 = NS(id=910001, remote=_R10, short_name="gm", game_type="gmod", port=27015,
                query_type=None, lgsm_name="gmodserver")

    def _slots10(**over):
        _mon10.sm_player_slots = over.get("gamedig", lambda *a: (None, None, None))
        _mon10.sm_game_engine = over.get("engine", lambda gt: "")
        _mon10.sm_console_status = over.get("console", _raiser10(AssertionError("console used")))
        _mon10.sm_player_count_via_lgsm_query = over.get("lgsmq", lambda *a, **k: None)
        _mon10.sm_get_server_status = over.get("status", lambda r, gs: "online")
        _pstate10._max_players_cache.pop(_gsl10.id, None)
        return _try10(_mon10._server_slots, _gsl10, allow_console=over.get("allow_console", False))

    _sl_gd10 = _slots10(gamedig=lambda *a: (3, None, "My Server"))
    _sl_gdmax10 = _slots10(gamedig=lambda *a: (3, 16, "My Server"))
    _sl_con10 = _slots10(engine=lambda gt: "valve", allow_console=True,
                         console=lambda r, sn, gt, selfname=None: (["a", "b"], "Console Name"))
    _sl_nocon10 = _slots10(engine=lambda gt: "valve", allow_console=False,
                           lgsmq=lambda *a, **k: 5)
    _sl_conraise10 = _slots10(engine=lambda gt: "valve", allow_console=True,
                              console=_raiser10(ConnectionError("tmux gone")))
    _sl_lgsm10 = _slots10(gamedig=_raiser10(OSError("gamedig crashed")), lgsmq=lambda *a, **k: 7)
    _sl_off10 = _slots10(status=lambda r, gs: "offline",
                         lgsmq=_raiser10(ConnectionError("query port shut")))
    _sl_on10 = _slots10(status=lambda r, gs: "online")
    _sl_st_raise10 = _slots10(status=_raiser10(ConnectionError("down")))
    check("monitor slots: gamedig's count and name win; max falls back to the LinuxGSM config",
          _sl_gd10 == (3, 24, "My Server") and _sl_gdmax10 == (3, 16, "My Server"),
          repr((_sl_gd10, _sl_gdmax10)))
    check("monitor slots: the console is read ONLY when explicitly allowed (never by a poller)",
          _sl_con10 == (2, 24, "Console Name") and _sl_nocon10 == (5, 24, None),
          repr((_sl_con10, _sl_nocon10)))
    check("monitor slots: a console read that fails is UNKNOWN, not zero players",
          _sl_conraise10 == (None, 24, None), repr(_sl_conraise10))
    check("monitor slots: LinuxGSM's own query is the next source when gamedig fails",
          _sl_lgsm10 == (7, 24, None), repr(_sl_lgsm10))
    check("monitor slots: with no query at all, a STOPPED server is 0 and a running one unknown",
          _sl_off10 == (0, 24, None) and _sl_on10 == (None, 24, None)
          and _sl_st_raise10 == (None, 24, None),
          repr((_sl_off10, _sl_on10, _sl_st_raise10)))
    _mon10.sm_player_slots = lambda *a: (0, 10, None)
    check("monitor slots: the confident-count wrapper returns the count alone",
          _mon10._server_players_confident(_gsl10) == 0, "")

    # A capacity that WAS read is kept when a re-read fails, rather than blanked.
    _pstate10._max_players_cache[_gsl10.id] = (32, 0.0)          # stale: forces a re-read
    _mon10.lgsm_get_values = _raiser10(ConnectionError("config unreadable"))
    _mx_kept10 = _mon10._server_max_config(_gsl10)
    _pstate10._max_players_cache.pop(_gsl10.id, None)
    _mx_none10 = _mon10._server_max_config(_gsl10)
    check("monitor max players: a failed re-read keeps the last capacity read; none read is None",
          _mx_kept10 == 32 and _mx_none10 is None and _gsl10.id not in _pstate10._max_players_cache,
          repr((_mx_kept10, _mx_none10)))
    _mon_restore10("lgsm_get_values", "sm_player_slots", "sm_game_engine", "sm_console_status",
                   "sm_player_count_via_lgsm_query", "sm_get_server_status")

    # ── autoblock: threshold parsing, the whitelist, and the REMOTE reconcile ──────────────────
    _ab_cfg10 = {}
    _mon10.load_config = lambda: _ab_cfg10
    _ab_cfg10["autoblock_threshold"] = "lots"
    _thr_junk10 = _mon10._autoblock_threshold()
    _ab_cfg10["autoblock_threshold"] = 0
    _thr_lo10 = _mon10._autoblock_threshold()
    _ab_cfg10["autoblock_threshold"] = 10 ** 9
    _thr_hi10 = _mon10._autoblock_threshold()
    check("monitor autoblock: the threshold is clamped to 1..100000 and junk means the default",
          (_thr_junk10, _thr_lo10, _thr_hi10) == (_mon10._AUTOBLOCK_DEFAULT_THRESHOLD, 1, 100000),
          repr((_thr_junk10, _thr_lo10, _thr_hi10)))
    _ab_cfg10.update({"autoblock_threshold": 5,
                      "security_whitelist": ["198.51.100.0/24", "not-an-ip", "203.0.113.77"]})
    _nets10 = _mon10._whitelist_networks()
    check("monitor whitelist: an entry that no longer parses is skipped, the rest still apply",
          len(_nets10) == 2 and _mon10._whitelisted("198.51.100.9", _nets10)
          and not _mon10._whitelisted("192.0.2.1", _nets10), repr(_nets10))

    _ab_calls10 = []
    _mon10.remote_fail2ban_attempt_counts = lambda r, days: {
        "192.0.2.50": 9,           # over threshold, not blocked yet  -> block
        "198.51.100.9": 50,        # over, but whitelisted            -> never
        "100.64.0.7": 50,          # over, but on the tailnet         -> never
        "192.0.2.60": 9,           # over, block will FAIL            -> reported
        "192.0.2.70": 1,           # auto-blocked, now under          -> release (fails)
        "192.0.2.80": 40}          # over, but MANUALLY blocked       -> left exactly as it is
    _mon10.remote_ufw_blocked_ips = lambda r: {"192.0.2.70": _mon10._AUTOBLOCK_TAG,
                                                "192.0.2.80": ""}    # a MANUAL block: untouched
    _mon10.tailnet_exempt_ips = lambda r, ips: {"100.64.0.7"}
    _mon10.remote_ufw_deny_ip = lambda r, ip, tag=None: (
        _ab_calls10.append(("deny", ip, tag)) or (ip != "192.0.2.60", "x"))
    _mon10.remote_ufw_undeny_ip = lambda r, ip: (_ab_calls10.append(("undeny", ip)) or (False, "x"))
    _cap_m10, _cap_moff10 = _cap10("panel.monitoring")
    try:
        _abr10 = _mon10._autoblock_reconcile(NS(is_local=False, name="edge"))
    finally:
        _cap_moff10()
    check("monitor autoblock (remote): only a non-exempt offender is blocked, with the panel tag",
          sorted(c for c in _ab_calls10 if c[0] == "deny")
          == [("deny", "192.0.2.50", "panel-autoblock"), ("deny", "192.0.2.60", "panel-autoblock")],
          repr(_ab_calls10))
    check("monitor autoblock (remote): the tally counts what APPLIED, and a manual block is kept",
          _abr10 == (1, 0) and ("undeny", "192.0.2.80") not in _ab_calls10
          and not any(c[:2] == ("deny", "192.0.2.80") for c in _ab_calls10)
          and ("undeny", "192.0.2.70") in _ab_calls10, repr((_abr10, _ab_calls10)))
    check("monitor autoblock (remote): changes that did not apply are logged (at WARNING), by IP",
          any("did not apply" in m and "block 192.0.2.60" in m and "release 192.0.2.70" in m
              for m in _cap_m10.warned), repr(_cap_m10.msgs))
    _ab_calls10[:] = []
    _mon10.remote_fail2ban_attempt_counts = lambda r, days: None
    _abn10 = _mon10._autoblock_reconcile(NS(is_local=False, name="edge"))
    check("monitor autoblock (remote): an unreadable fail2ban tally changes NOTHING",
          _abn10 == (0, 0) and _ab_calls10 == [], repr((_abn10, _ab_calls10)))
    _mon_restore10("load_config", "remote_fail2ban_attempt_counts", "remote_ufw_blocked_ips",
                   "tailnet_exempt_ips", "remote_ufw_deny_ip", "remote_ufw_undeny_ip")

    # ── the database-backed passes ─────────────────────────────────────────────────────────────
    with _dbapp10.app_context():
        _reset_db10()
        _ra10 = _mk_remote10("alpha")
        _rb10 = _mk_remote10("beta")
        _g1_10 = _mk_gs10(_rb10, "gmod1", port=27015)
        _g2_10 = _mk_gs10(_rb10, "gmod2", port=27016, status="installing")
        _muted_tag10 = _Tag10(name="staging", notify=False)
        _g3_10 = _mk_gs10(_rb10, "gmod3", port=27017)
        _g3_10.tags.append(_muted_tag10)
        _db10.session.commit()
        _ids10 = {"ra": _ra10.id, "rb": _rb10.id, "g1": _g1_10.id, "g2": _g2_10.id,
                  "g3": _g3_10.id}

        # _monitor_pass, one sweep at a time, with the probes scripted per host.
        _probes10 = {}
        _mon10._probe_host = lambda r: (r.id, _probes10[r.id])
        _mon10._lgsm_maintenance_running = lambda r, gs: False

        def _sweep10(pa, pb):
            _probes10[_ids10["ra"]], _probes10[_ids10["rb"]] = pa, pb
            del _alerts10[:]
            _mon10._monitor_pass()
            return [a[0] for a in _alerts10]

        _UP10 = {"reachable": True, "disk": 50, "load_mem": (10, 20), "ports": {27015, 27017},
                 "restart_flagged": set()}
        _first10 = _sweep10(dict(_UP10), {"reachable": False})
        check("monitor pass: the first sweep only records a baseline — nothing alerts",
              _first10 == [], repr(_first10))
        check("monitor pass: host reachability is written to the COLUMN, not just to memory",
              _db10.session.get(_RS10, _ids10["ra"]).is_online is True
              and _db10.session.get(_RS10, _ids10["rb"]).is_online is False, "")
        _second10 = _sweep10({"reachable": False},
                             dict(_UP10, disk=95, load_mem=(250, None)))
        check("monitor pass: a host going down and one coming back each alert once",
              "remote_unreachable" in _second10 and "remote_recovered" in _second10,
              repr(_second10))
        check("monitor pass: a full disk and a sustained CPU load alert; an unread memory figure "
              "does not", "disk_low" in _second10 and _second10.count("high_load") == 1,
              repr(_alerts10))
        _third10 = _sweep10({"reachable": False}, dict(_UP10, disk=96, load_mem=(260, None)))
        check("monitor pass: an alert already raised is not repeated while the condition holds",
              "disk_low" not in _third10 and "high_load" not in _third10, repr(_third10))
        _sweep10({"reachable": False}, dict(_UP10, disk=80, load_mem=(100, None)))
        _rearm10 = _sweep10({"reachable": False}, dict(_UP10, disk=95, load_mem=(250, None)))
        check("monitor pass: once well below the line, disk and load RE-ARM and alert again",
              "disk_low" in _rearm10 and "high_load" in _rearm10, repr(_rearm10))

        # Servers on beta: gmod1 goes down unexpectedly, then comes back; gmod3 is muted.
        _down10 = _sweep10({"reachable": False}, dict(_UP10, ports=set()))
        check("monitor pass: a server that stops listening alerts 'offline' — unless muted",
              [a for a in _alerts10 if a[0] == "server_down"]
              == [("server_down", "Server offline", "gmod1 on beta went offline unexpectedly.")],
              repr(_alerts10))
        check("monitor pass: the status COLUMN follows what the sweep measured",
              _db10.session.get(_GS10, _ids10["g1"]).status == "offline"
              and _db10.session.get(_GS10, _ids10["g2"]).status == "installing", "")
        _up10 = _sweep10({"reachable": False}, dict(_UP10))
        check("monitor pass: it coming back alerts 'back online' (the muted one stays quiet)",
              [a[2] for a in _alerts10 if a[0] == "server_up"] == ["gmod1 on beta is back online."],
              repr(_alerts10))
        # A stop the PANEL issued: no alert either way.
        _mon10._expected_offline[_ids10["g1"]] = time.time()
        _exp10 = _sweep10({"reachable": False}, dict(_UP10, ports={27017}))
        _exp_back10 = _sweep10({"reachable": False}, dict(_UP10))
        _mon10._expected_offline.pop(_ids10["g1"], None)
        check("monitor pass: a panel-issued stop and its restart produce NO alert at all",
              "server_down" not in _exp10 and "server_up" not in _exp_back10,
              repr((_exp10, _exp_back10)))
        # LinuxGSM's own maintenance: the down is suppressed and so is the recovery.
        _mon10._lgsm_maintenance_running = lambda r, gs: True
        _mt10 = _sweep10({"reachable": False}, dict(_UP10, ports={27017}))
        _mon10._lgsm_maintenance_running = lambda r, gs: False
        _mt_back10 = _sweep10({"reachable": False}, dict(_UP10))
        check("monitor pass: a scheduled LinuxGSM update is neither 'offline' nor 'back online'",
              "server_down" not in _mt10 and "server_up" not in _mt_back10,
              repr((_mt10, _mt_back10)))
        # A status write that cannot be committed is rolled back, not left half-applied.
        _cap_m10, _cap_moff10 = _cap10("panel.monitoring")
        _mon10.db = NS(session=NS(query=_db10.session.query,
                                  commit=_raiser10(RuntimeError("database is locked")),
                                  rollback=_db10.session.rollback))
        try:
            _commit_r10 = _try10(_sweep10, {"reachable": False}, dict(_UP10, ports={27017}))
        finally:
            _cap_moff10()
            _mon_restore10("db")
        check("monitor pass: a commit that fails is rolled back and logged, and the sweep survives",
              not (isinstance(_commit_r10, tuple) and _commit_r10[:1] == ("RAISED",))
              and _db10.session.get(_GS10, _ids10["g1"]).status == "online"
              and any("persisting server status failed" in m for m in _cap_m10.msgs),
              repr((_commit_r10, _cap_m10.msgs)))
        _mon_restore10("_probe_host", "_lgsm_maintenance_running")

        # ── _refresh_player_counts: one-shot empty, full on the transition, peak record ────────
        _counts10 = {}
        _mon10._query_server_slots = lambda gs: (gs.id, _counts10.get(gs.id, (None, None, None)))
        _g1db10 = _db10.session.get(_GS10, _ids10["g1"])
        _g1db10.notify_when_empty = True
        _g1db10.peak_players = 3
        _db10.session.commit()
        _pstate10._server_peak_notified.pop(_ids10["g1"], None)
        _pstate10._server_full_alerted.pop(_ids10["g1"], None)
        _pstate10._server_full_alerted.pop(_ids10["g3"], None)

        def _poll10(counts):
            _counts10.clear()
            _counts10.update(counts)
            del _alerts10[:]
            _mon10._refresh_player_counts(_dbapp10)
            _db10.session.expire_all()
            return [a[0] for a in _alerts10]

        _p1_10 = _poll10({_ids10["g1"]: (0, 10, "Game Name"), _ids10["g3"]: (10, 10, None)})
        check("monitor players: notify-when-empty fires ONCE on a confirmed 0, and is disarmed",
              _p1_10.count("server_empty") == 1
              and _db10.session.get(_GS10, _ids10["g1"]).notify_when_empty is False,
              repr(_p1_10))
        check("monitor players: a muted server at its cap is marked full but sends nothing",
              "server_full" not in _p1_10 and _pstate10._server_full_alerted.get(_ids10["g3"]) is True,
              repr(_p1_10))
        check("monitor players: the cache holds the count, the max and the advertised name",
              _pstate10._player_counts.get(_ids10["g1"], {}).get("count") == 0
              and _pstate10._player_counts[_ids10["g1"]]["name"] == "Game Name", "")
        _p2_10 = _poll10({_ids10["g1"]: (10, 10, None)})
        _p3_10 = _poll10({_ids10["g1"]: (10, 10, None)})
        check("monitor players: 'server full' fires on the transition INTO full, not every poll",
              _p2_10.count("server_full") == 1 and "server_full" not in _p3_10,
              repr((_p2_10, _p3_10)))
        check("monitor players: a poll with no name keeps the last one read, not a blank",
              _pstate10._player_counts[_ids10["g1"]]["name"] == "Game Name", "")
        check("monitor players: 10 players on a server whose record was 3 is a new record",
              "server_peak" in _p2_10 and _db10.session.get(_GS10, _ids10["g1"]).peak_players == 10,
              repr(_p2_10))
        _p4_10 = _poll10({_ids10["g1"]: (4, 10, None)})
        _p5_10 = _poll10({_ids10["g1"]: (10, 10, None)})
        check("monitor players: dropping below the cap RE-ARMS the full alert",
              _pstate10._server_full_alerted.get(_ids10["g1"]) is True and "server_full" in _p5_10,
              repr((_p4_10, _p5_10)))
        # The stub commit fails without poisoning the session the way a real one does, so what is
        # asserted is the contract with the session: the failed write is ROLLED BACK — otherwise
        # every later statement in the same pass raises PendingRollbackError — and not stored.
        _rolled10 = []
        _mon10.db = NS(session=NS(commit=_raiser10(RuntimeError("database is locked")),
                                  rollback=lambda: (_rolled10.append(1), _db10.session.rollback())))
        try:
            _p6_10 = _poll10({_ids10["g1"]: (99, 100, None)})
        finally:
            _mon_restore10("db")
        check("monitor players: a peak that could not be SAVED is rolled back, not half-applied",
              _rolled10 == [1] and _db10.session.get(_GS10, _ids10["g1"]).peak_players == 10,
              repr((_p6_10, _rolled10)))
        _mon_restore10("_query_server_slots")

        # ── _record_metric_samples: a failed read is skipped, never written as zeros ───────────
        _mon10._query_host_metrics = lambda work: [
            (_ids10["g1"], {"ram_total": 8000, "ram_used": 2000, "disk_total": 100,
                            "disk_used": 25, "cpu_percent": 12.34, "game_cpu_percent": 5.44,
                            "game_ram_mb": 700}, _ids10["rb"], ""),
            (_ids10["g3"], {"ram_total": 0, "cpu_percent": 0.0}, _ids10["rb"], ""),
            (_ids10["g2"], None, _ids10["rb"], "")]
        _mon10._record_metric_samples(_dbapp10)
        _ms10 = _MS10.query.all()
        _hs10 = _HS10.query.all()
        check("monitor history: one game sample and one host sample from the good read only",
              [(m.server_id, m.cpu, m.ram_mb) for m in _ms10] == [(_ids10["g1"], 5.4, 700)]
              and [(h.remote_id, h.cpu, h.ram_pct, h.disk_pct) for h in _hs10]
              == [(_ids10["rb"], 12.3, 25.0, 25.0)],
              repr(([(m.server_id, m.cpu) for m in _ms10], [(h.remote_id, h.cpu) for h in _hs10])))
        _mon_restore10("_query_host_metrics")

        # ── reboot-when-empty: the marks, the fire, and the watcher's commit point ─────────────
        _pstate10._expected_offline.pop(_ids10["g1"], None)
        _pstate10._expected_offline[_ids10["g3"]] = 12345.0
        _rbok10, _ = _mon10._reboot_expecting_offline(_rb10, lambda r: (False, "refused"))
        check("monitor reboot: a refused reboot puts back exactly the marks that were there",
              _rbok10 is False and _ids10["g1"] not in _pstate10._expected_offline
              and _pstate10._expected_offline.get(_ids10["g3"]) == 12345.0,
              repr({k: _pstate10._expected_offline.get(k) for k in (_ids10["g1"], _ids10["g3"])}))
        _mon10._reboot_expecting_offline(_rb10, lambda r: (True, "rebooting"))
        check("monitor reboot: a reboot that ran marks every server on the host expected-offline",
              all(_pstate10._expected_offline.get(_ids10[k], 0) > time.time()
                  for k in ("g1", "g2", "g3")), "")

        _mon10.remote_reboot = lambda r: (True, "rebooting now")
        del _alerts10[:]
        with _dbapp10.test_request_context():
            _fire_ok10 = _mon10._fire_reboot_when_empty(_rb10, {"by": "alice"})
            _mon10.remote_reboot = lambda r: (False, "no sudo")
            _fire_bad10 = _mon10._fire_reboot_when_empty(_rb10, {})
        _audit10 = [(a.action, a.username, a.success) for a in
                    _Audit10.query.filter_by(action="reboot_when_empty_fire").order_by(_Audit10.id)]
        check("monitor reboot: a fired reboot is audited under the operator who queued it",
              _fire_ok10 == (True, "rebooting now")
              and _audit10 == [("reboot_when_empty_fire", "alice", True),
                               ("reboot_when_empty_fire", "system", False)],
              repr(_audit10))
        check("monitor reboot: a refused reboot is announced as FAILED, not as having run",
              [a[1] for a in _alerts10] == ["Host auto-rebooted", "Auto-reboot failed"]
              and _fire_bad10 == (False, "no sudo"), repr(_alerts10))
        _mon_restore10("remote_reboot")

        _fired10, _sleeps10 = [], {"n": 0}
        _rc10 = _mk_remote10("gamma")
        _rd10 = _mk_remote10("delta")
        _re10 = _mk_remote10("epsilon")
        _gone_id10 = 424242

        def _watch_sleep10(s):
            _sleeps10["n"] += 1
            if _sleeps10["n"] == 2:
                with _pstate10._rwe_lock:
                    _pstate10._reboot_when_empty.update({
                        _gone_id10: {"by": "x"}, _ra10.id: {"by": "x"}, _rb10.id: {"by": "x"},
                        _rc10.id: {"by": "alice"}, _rd10.id: {"by": "x"}, _re10.id: {"by": "x"}})
            elif _sleeps10["n"] >= 3:
                raise _Stop10()

        def _idle_state10(r):
            if r.id == _rb10.id:
                return "busy"
            if r.id == _rd10.id:                        # cancelled while the probes ran
                with _pstate10._rwe_lock:
                    _pstate10._reboot_when_empty.pop(r.id, None)
            if r.id == _re10.id:
                raise RuntimeError("probe bug")
            return "idle"

        with _pstate10._rwe_lock:
            _rwe_saved10 = dict(_pstate10._reboot_when_empty)
            _pstate10._reboot_when_empty.clear()
        _mon10.time = _Clock10(time.time(), sleep=_watch_sleep10)
        _mon10._host_reachable = lambda r: r.id != _ra10.id
        _mon10._host_idle_state = _idle_state10
        _mon10._fire_reboot_when_empty = lambda r, info: _fired10.append((r.name, dict(info)))
        try:
            _wr10 = _try10(_mon10._reboot_when_empty_watch, _dbapp10)
            with _pstate10._rwe_lock:
                _left10 = sorted(_pstate10._reboot_when_empty)
                _pstate10._reboot_when_empty.clear()
                _pstate10._reboot_when_empty.update(_rwe_saved10)
        finally:
            _mon_restore10("time", "_host_reachable", "_host_idle_state", "_fire_reboot_when_empty")
        check("monitor reboot watch: only the reachable, IDLE, still-queued host is rebooted",
              _fired10 == [("gamma", {"by": "alice"})], repr(_fired10))
        check("monitor reboot watch: a deleted host is dequeued; unreachable, busy and failing "
              "hosts stay queued; a cancelled one is not rebooted",
              _left10 == sorted([_ra10.id, _rb10.id, _re10.id]) and _sleeps10["n"] == 3
              and _wr10 == ("RAISED", repr(_Stop10())),
              repr((_left10, _sleeps10, _wr10)))

        # With no installed servers at all, the poll and the sampler do nothing.
        _GS10.query.delete()
        _db10.session.commit()
        _mon10._query_server_slots = _raiser10(AssertionError("polled with no servers"))
        _mon10._query_host_metrics = _raiser10(AssertionError("sampled with no servers"))
        try:
            _empty_poll10 = _try10(_mon10._refresh_player_counts, _dbapp10)
            _empty_rec10 = _try10(_mon10._record_metric_samples, _dbapp10)
        finally:
            _mon_restore10("_query_server_slots", "_query_host_metrics")
        check("monitor: with no installed servers the poller and sampler return without work",
              _empty_poll10 is None and _empty_rec10 is None, repr((_empty_poll10, _empty_rec10)))
        _db10.session.remove()
    check("monitor: nothing in this section reached a real SSH or local transport",
          _trip10 == [], repr(_trip10))
finally:
    _disarm10(_mon_trip_saved10)
    _mon_restore10()
    _restore_pstate10()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# D. panel/ops/ssh_manager/_core.py — the transports (NOT the `sudo -u` builders; see the top)
# ══════════════════════════════════════════════════════════════════════════════════════════════
import paramiko as _paramiko10  # noqa: E402
import shlex as _shlex10  # noqa: E402

from panel.core import config as _cfgmod10  # noqa: E402
from panel.db.models import UnreadableSecret as _Unreadable10  # noqa: E402
from panel.ops import system_ops as _so10  # noqa: E402
from panel.ops import tailscale_integration as _tsi10  # noqa: E402
from panel.security import privileged as _priv10  # noqa: E402

_CORE_STUBBED10 = ("_exec_local_shell", "_exec_local_argv", "_run_local", "run_command",
                   "run_privileged", "helper_present", "_real_subprocess", "subprocess",
                   "_finish", "_kill_process_tree", "_tpool", "time", "paramiko",
                   "_ssh_connect_timeout", "_persist_host_key", "_close_key", "get_connection",
                   "_drain_exec", "_collect_capped", "_ssh_mux_opts", "_resolve_ts_host",
                   "_SSH_CM_DIR", "forget_remote_caches")
_core_saved10 = {k: getattr(_sm_core, k) for k in _CORE_STUBBED10}
_core_conns_saved10 = dict(_sm_core._connections)
_core_keys_saved10 = dict(_sm_core._remote_conn_keys)
_core_helper_saved10 = dict(_sm_core._HELPER_STATE)
_core_helper_path10 = _priv10.HELPER_PATH
_core_tsinfo10 = _tsi10.get_tailscale_info
_core_cfgload10 = _cfgmod10.load_config
_core_live10 = _so10.live_metrics


def _core_restore10(*names):
    for k in names or _CORE_STUBBED10:
        setattr(_sm_core, k, _core_saved10[k])


def _unshim10(fn):
    """Return the real _core._run_local under any number of tools/nosudo_runner wrappers.

    Each wrapper refuses a sudo command before the real body runs; `fn` itself comes back when
    nothing wraps it, as when CI runs the suite bare. The runner can be installed more than once:
    part05 loads it again as `nsr_probe`, and that copy wraps the first copy's wrapper.
    """
    for _ in range(8):
        if getattr(fn, "__name__", "") == "_run_local" and fn.__module__ == _sm_core.__name__:
            return fn
        inner = [c.cell_contents for c in (getattr(fn, "__closure__", None) or ())
                 if getattr(c.cell_contents, "__name__", "") in ("_run_local", "_sm_local")]
        if not inner:
            break
        fn = inner[0]
    return fn


def _proc_state13(pid):
    """Return the state letter /proc shows for `pid`, or "" once the pid is gone."""
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return fh.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return ""


def _await_group_dead13(proc, grand, deadline=10.0):
    """Poll until `proc` is reaped and `grand` has stopped running, or `deadline` seconds pass.

    Returns {"child": its rc or None, "grand": the state it was seen dead in or None, "last": the
    last state read}. Each is LATCHED at the first read that finds it dead and never read again,
    because a dying pid is a different fact on every read. The orphaned grandchild's reaper
    (systemd --user here) takes it Z -> X -> gone, and the check this replaces counted only Z as
    dead: it looped out on Z, re-read the pid mid-reap as X ("running") and failed, then its
    message re-read it gone and printed dead=True. Once gone, the pid can also be reused.
    """
    seen = {"child": None, "grand": None, "last": None}
    end = time.monotonic() + deadline
    while True:
        if seen["child"] is None:
            seen["child"] = proc.poll()
        if seen["grand"] is None:
            seen["last"] = _proc_state13(grand)
            if seen["last"] in ("", "Z", "X"):      # gone, a zombie, or being reaped
                seen["grand"] = seen["last"] or "gone"
        if (seen["child"] is not None and seen["grand"] is not None) or time.monotonic() >= end:
            return seen
        time.sleep(0.05)


_LOCAL10 = NS(id=701, name="panel", is_local=True, auth_method="local", sudo_enabled=True)
_REMOTE10 = NS(id=702, name="edge", is_local=False, auth_method="key", host="192.0.2.20",
               port=22, username="root", sudo_enabled=True)

try:
    # ── _run_local: sudo=True wraps the WHOLE command in `sudo bash -c`, once ───────────────────
    _rl_calls10 = []
    _sm_core._exec_local_shell = lambda cmd, timeout=30, stdin_text=None: (
        _rl_calls10.append((cmd, stdin_text)) or ("o", "", 0))
    _real_rl10 = _unshim10(_sm_core._run_local)
    _real_rl10("ls /root | wc -l", sudo=True)
    _real_rl10("sudo -n /usr/bin/true", sudo=True)
    _real_rl10("uptime", stdin_text="in")
    check("core local: sudo=True runs the whole pipeline under one `sudo bash -c`",
          _rl_calls10[0] == ("sudo bash -c " + _shlex10.quote("ls /root | wc -l"), None),
          repr(_rl_calls10[:1]))
    check("core local: a command that escalates itself is not wrapped again; sudo=False is as-is",
          _rl_calls10[1][0] == "sudo -n /usr/bin/true" and _rl_calls10[2] == ("uptime", "in"),
          repr(_rl_calls10[1:]))
    _core_restore10("_exec_local_shell")

    # ── _kill_process_tree: the whole group dies, grandchildren included ───────────────────────
    import subprocess as _sp10  # noqa: E402
    _kp10 = _sp10.Popen(["/bin/sh", "-c", "sleep 30 & echo $!; wait"], stdout=_sp10.PIPE,
                        stdin=_sp10.DEVNULL, start_new_session=True)
    _grand10 = int(_kp10.stdout.readline().strip() or 0)
    _sm_core._kill_process_tree(_kp10)
    _seen10 = _await_group_dead13(_kp10, _grand10)
    check("core kill: a timed-out command's whole process group is killed, grandchild included",
          _grand10 > 0 and _seen10["child"] is not None and _seen10["grand"] is not None,
          "grandchild %s, seen %r" % (_grand10, _seen10))

    class _GhostProc10:
        pid = 999999999                     # no such process: getpgid raises

        def __init__(self):
            self.calls = []

        def kill(self):
            self.calls.append("kill")
            raise ProcessLookupError()

        def communicate(self, timeout=None):
            self.calls.append("communicate")
            raise OSError("no pipes")

        def wait(self, timeout=None):
            self.calls.append("wait")
            raise OSError("no such child")

    # Reaped with wait(), never communicate(): communicate() READS the pipes, and a capped reader
    # may still be reading them (under eventlet a second reader on one descriptor raises).
    _gp10 = _GhostProc10()
    _gpr10 = _try10(_sm_core._kill_process_tree, _gp10)
    check("core kill: a process already gone falls back to kill(), and every failure is contained",
          _gpr10 is None and _gp10.calls == ["kill", "wait"], repr((_gpr10, _gp10.calls)))

    # ── _collect_capped: the ceiling on KEPT output, and pipes that break under it ─────────────
    class _Stream10:
        def __init__(self, chunks, fail=False):
            self.chunks, self.fail = list(chunks), fail

        def read1(self, n):
            if self.chunks:
                return self.chunks.pop(0)
            if self.fail:
                raise OSError("pipe closed by a kill")
            return b""

    class _Stdin10:
        def __init__(self):
            self.wrote, self.closes = [], 0

        def write(self, b):
            self.wrote.append(b)
            raise BrokenPipeError()

        def close(self):
            self.closes += 1
            raise OSError("already closed")

    _cp10 = NS(stdout=_Stream10([b"abcdef", b"ghij"]), stderr=_Stream10([b"err"], fail=True),
               stdin=_Stdin10(), wait=lambda timeout=None: 0)
    _ccr10 = _sm_core._collect_capped(_cp10, 5, kill=lambda: None, threads=threading,
                                      stdin_bytes=b"secret", cap=4)
    check("core capture: only the first `cap` bytes are kept, and truncation is reported",
          _ccr10 == (b"abcd", b"err", 0, True), repr(_ccr10))
    check("core capture: a command that exits without reading its stdin is not an error",
          _cp10.stdin.wrote == [b"secret"] and _cp10.stdin.closes == 1, "")

    # ── the two local exec paths, when Popen or the collection fails ───────────────────────────
    _pop_kw10 = []

    def _popen_rec10(argv, **kw):
        _pop_kw10.append((argv, kw))
        return NS(pid=999999997)

    _killed10 = []
    _sm_core._real_subprocess = NS(Popen=_raiser10(OSError("fork failed")), PIPE="PIPE",
                                   DEVNULL="DEVNULL")
    _sh_fail10 = _sm_core._exec_local_shell("echo hi", timeout=5)
    _argv_fail10 = _sm_core._exec_local_argv(["true"], timeout=5)
    _sm_core._real_subprocess = NS(Popen=_popen_rec10, PIPE="PIPE", DEVNULL="DEVNULL")
    _sm_core._finish = _raiser10(RuntimeError("collector bug"))
    _sm_core._kill_process_tree = lambda p: _killed10.append(p.pid)
    _sh_fin10 = _sm_core._exec_local_shell("cat", timeout=5, stdin_text="payload")
    _argv_fin10 = _sm_core._exec_local_argv(["cat"], timeout=5, stdin_text="payload")
    _core_restore10("_real_subprocess", "_finish", "_kill_process_tree")
    check("core local exec: a command that cannot start answers rc -1 with a generic message",
          _sh_fail10 == ("", "command execution error", -1)
          and _argv_fail10 == ("", "command execution error", -1),
          repr((_sh_fail10, _argv_fail10)))
    check("core local exec: a failure AFTER the start kills what was started",
          _sh_fin10 == ("", "command execution error", -1) and _argv_fin10[2] == -1
          and _killed10 == [999999997, 999999997], repr((_sh_fin10, _killed10)))
    check("core local exec: the shell path runs /bin/bash -c; stdin is a pipe only when fed",
          _pop_kw10 and _pop_kw10[0][0] == ["/bin/bash", "-c", "cat"]
          and _pop_kw10[0][1].get("stdin") == "PIPE"
          and _pop_kw10[1][0] == ["cat"] and _pop_kw10[1][1].get("start_new_session") is True,
          repr(_pop_kw10))
    _sm_core._tpool = None
    check("core local exec: without eventlet the function simply runs inline",
          _try10(_sm_core._in_tpool, lambda: 42) == 42, "")
    _core_restore10("_tpool")

    # ── the privileged fallbacks ───────────────────────────────────────────────────────────────
    _rp_calls10 = []

    def _rp10(script):
        def _f(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
            _rp_calls10.append((verb, list(args)))
            rc = script.pop(0) if script else 0
            if isinstance(rc, BaseException):
                raise rc
            return ("out-%s" % verb, "", rc)
        return _f

    _sm_core.run_privileged = _rp10([1, 0])
    _rs_out10 = _sm_core._restart_sshd(_REMOTE10)
    _rs_calls10, _rp_calls10[:] = list(_rp_calls10), []
    check("core sshd restart: the unit is `ssh` on Debian/Ubuntu, `sshd` elsewhere — both tried",
          _rs_calls10 == [("service-restart", ["ssh"]), ("service-restart", ["sshd"])]
          and _rs_out10 == ("out-service-restart", "", 0), repr(_rs_calls10))
    _sm_core.run_privileged = _rp10([1, 1, 1])
    _f2b_out10 = _sm_core._f2b_reload(_REMOTE10)
    _f2b_calls10, _rp_calls10[:] = list(_rp_calls10), []
    _sm_core.run_privileged = _rp10([1, 0])
    _sm_core._f2b_reload(_REMOTE10)
    check("core fail2ban reload: reload, then the unit's reload, then a restart — stopping at "
          "the first that works, and reporting the last failure when none does",
          [v for v, _a in _f2b_calls10] == ["f2b-reload", "service-reload", "service-restart"]
          and _f2b_out10[2] == 1 and [v for v, _a in _rp_calls10] == ["f2b-reload", "service-reload"],
          repr((_f2b_calls10, _rp_calls10)))
    _rp_calls10[:] = []

    _dclock10 = _Clock10(1000.0)
    _dclock10._sleep = lambda s: setattr(_dclock10, "now", _dclock10.now + s)
    _sm_core.time = _dclock10
    _sm_core.run_privileged = _rp10([0, 0, 1])
    _dpkg_free10 = _sm_core._wait_for_dpkg_lock(_REMOTE10, timeout=60)
    _dpkg_n10 = len(_rp_calls10)
    _sm_core.run_privileged = _rp10([0] * 100)
    _dpkg_held10 = _sm_core._wait_for_dpkg_lock(_REMOTE10, timeout=5)
    _core_restore10("time")
    check("core dpkg lock: waits while held and returns True once free; gives up at the deadline",
          _dpkg_free10 is True and _dpkg_n10 == 3 and _dpkg_held10 is False,
          repr((_dpkg_free10, _dpkg_n10, _dpkg_held10)))
    _rp_calls10[:] = []

    _sm_core.run_privileged = _rp10([RuntimeError("helper crashed")])
    _gp_r10 = _try10(_sm_core.set_game_priority, _REMOTE10, "gmod1")
    check("core priority: a renice that fails is non-fatal, and asked for the right account",
          _gp_r10 is None and _rp_calls10 == [("renice-users", ["-1", "gmod1"])],
          repr((_gp_r10, _rp_calls10)))
    _rp_calls10[:] = []

    # enrol_game_user on the panel host, when the passwd lookup of its OWN uid fails
    _core_getpw10 = _pwd10.getpwuid
    _pwd10.getpwuid = _nopw10
    try:
        _sm_core.run_privileged = _rp10([0])
        _en_ok10 = _sm_core.enrol_game_user(_LOCAL10, "gmod1")
        _en_calls10 = list(_rp_calls10)

        def _rp_refused10(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
            return ("", "gmod1 can already reach root\n", 2)

        _sm_core.run_privileged = _rp_refused10
        _en_no10 = _sm_core.enrol_game_user(_LOCAL10, "gmod1")
        _sm_core.run_privileged = _raiser10(ConnectionError("no helper"))
        _en_raise10 = _sm_core.enrol_game_user(_LOCAL10, "gmod1")
    finally:
        _pwd10.getpwuid = _core_getpw10
    check("core enrol: with no passwd entry for our own uid, the account is still enrolled",
          _en_ok10 is None and _en_calls10 == [("gameuser-group", ["gmod1"])], repr(_en_calls10))
    check("core enrol: a refusal comes back as the helper's own words; a failure as a reason",
          _en_no10 == "gmod1 can already reach root"
          and _en_raise10 == "the enrolment could not be run", repr((_en_no10, _en_raise10)))
    _core_restore10("run_privileged")

    # ── the named root writes: never the content in a command line on the panel host ───────────
    _wr_calls10 = []
    _sm_core.run_command = lambda s, cmd, timeout=30, sudo=None, **k: (
        _wr_calls10.append(("ssh", cmd, sudo)) or ("", "", 0))
    _sm_core._exec_local_argv = lambda argv, timeout=30, stdin_text=None: (
        _wr_calls10.append(("argv", argv, stdin_text)) or ("", "", 0))
    _sm_core._run_local = lambda cmd, timeout=30, sudo=False, **k: (
        _wr_calls10.append(("local-shell", cmd, sudo)) or ("", "", 0))
    _BODY10 = 'APT::Periodic::Unattended-Upgrade "1";\n'
    _sm_core.write_root_file(_REMOTE10, "apt-auto-upgrades", _BODY10)
    _sm_core.helper_present = lambda recheck=False: True
    _sm_core.write_root_file(_LOCAL10, "apt-auto-upgrades", _BODY10)
    _sm_core.write_content_cron(_LOCAL10, "gmcontent", "0 4 * * 0 update\n")
    _sm_core.helper_present = lambda recheck=False: False
    _sm_core.write_root_file(_LOCAL10, "apt-auto-upgrades", _BODY10)
    _sm_core.write_content_cron(_LOCAL10, "gmcontent", "0 4 * * 0 update\n")
    _sm_core.write_content_cron(_REMOTE10, "gmcontent", "0 4 * * 0 update\n")
    check("core root write: a REMOTE gets the rendered command, with root",
          _wr_calls10[0] == ("ssh", _priv10.remote_write_command("apt-auto-upgrades", _BODY10), True)
          and _BODY10.strip() not in _wr_calls10[0][1], repr(_wr_calls10[:1])[:200])
    check("core root write: with the helper, the target is NAMED and the content goes on stdin",
          _wr_calls10[1] == ("argv", _priv10.helper_argv("write-file", ["apt-auto-upgrades"]), _BODY10)
          and _wr_calls10[2] == ("argv", _priv10.helper_argv("content-cron-write", ["gmcontent"]),
                                 "0 4 * * 0 update\n"),
          repr(_wr_calls10[1:3])[:300])
    check("core root write: without the helper (pre-install hosts) it is the old root shell form",
          [(c[0], c[2]) for c in _wr_calls10[3:5]] == [("local-shell", True), ("local-shell", True)]
          and _wr_calls10[5][0] == "ssh" and _wr_calls10[5][2] is True,
          repr([c[0] for c in _wr_calls10]))

    _sm_core._exec_local_argv = lambda argv, timeout=30, stdin_text=None: ("tool out", "tool err", 3)
    _sm_core.helper_present = lambda recheck=False: True
    _rp_split10 = _sm_core.run_privileged(_LOCAL10, "dpkg-lock-held", [], merge_stderr=False)
    _rp_merged10 = _sm_core.run_privileged(_LOCAL10, "dpkg-lock-held", [])
    check("core privileged: through the helper, stderr is merged into stdout unless asked not to",
          _rp_split10 == ("tool out", "tool err", 3) and _rp_merged10 == ("tool out\ntool err", "", 3),
          repr((_rp_split10, _rp_merged10)))

    _disc_argv10 = []
    _sm_core._exec_local_argv = lambda argv, timeout=30, stdin_text=None: (
        _disc_argv10.append(argv) or (
            "FOUND|gm|gmodserver|27015|2|3|4|1\nnoise\nFOUND|short\n"
            "FOUND||x|1|1|1|1|1\nFOUND|cs|csgoserver|x|y|0|0|0\n", "", 0))
    _disc10 = _sm_core.discover_linuxgsm_servers(_LOCAL10)
    _sm_core._exec_local_argv = lambda argv, timeout=30, stdin_text=None: ("FOUND|a|b|1|1|1|1|1", "", 1)
    _disc_fail10 = _sm_core.discover_linuxgsm_servers(_LOCAL10)
    check("core discover: on the panel host the helper does the scan (one verb, no shell)",
          _disc_argv10 == [_priv10.helper_argv("lgsm-discover", [])], repr(_disc_argv10))
    check("core discover: FOUND lines are parsed; malformed ones are skipped, junk counts are 0",
          _disc10 == [{"user": "gm", "lgsm_name": "gmodserver", "port": 27015, "backups": 2,
                       "mods": 3, "cron": 4, "autostart": True},
                      {"user": "cs", "lgsm_name": "csgoserver", "port": None, "backups": 0,
                       "mods": 0, "cron": 0, "autostart": False}],
          repr(_disc10))
    check("core discover: a scan that failed is [] — not whatever it half-printed",
          _disc_fail10 == [], repr(_disc_fail10))
    _core_restore10("run_command", "_exec_local_argv", "_run_local", "helper_present")

    # helper_present: an unreadable helper path is "not installed", not an exception
    _priv10.HELPER_PATH = object()
    _hp10 = _try10(_sm_core.helper_present, True)
    _priv10.HELPER_PATH = _core_helper_path10
    _sm_core._HELPER_STATE.clear()
    _sm_core._HELPER_STATE.update(_core_helper_saved10)
    check("core helper: a path that cannot even be checked reads as no helper",
          _hp10 is False, repr(_hp10))

    # ── the ssh timeout knob and the tailscale host name ───────────────────────────────────────
    _cfgmod10.load_config = lambda: {"ssh_timeout": "soon"}
    _to_junk10 = _core_saved10["_ssh_connect_timeout"]()
    _cfgmod10.load_config = lambda: {"ssh_timeout": 500}
    _to_hi10 = _core_saved10["_ssh_connect_timeout"]()
    _cfgmod10.load_config = _core_cfgload10
    check("core ssh timeout: junk means the default 10s, and it is capped at 120s",
          (_to_junk10, _to_hi10) == (10, 120), repr((_to_junk10, _to_hi10)))

    _tsi_calls10 = []

    def _tsinfo10(dns):
        def _f():
            _tsi_calls10.append(dns)
            if isinstance(dns, BaseException):
                raise dns
            return NS(dns_name=dns)
        return _f

    def _rts10(host, dns):
        _tsi10.get_tailscale_info = _tsinfo10(dns)
        return _core_saved10["_resolve_ts_host"](NS(host=host))

    _ts_hosts10 = (_rts10("box", "me.tail1234.ts.net"), _rts10("box", "me"), _rts10("box", ""),
                   _rts10("box", RuntimeError("tailscaled down")))
    _tsi_calls10[:] = []
    _ts_fq10 = (_rts10("100.64.0.9", "me.x.ts.net"), _rts10("box.example.com", "me.x.ts.net"))
    _tsi10.get_tailscale_info = _core_tsinfo10
    check("core tailscale host: a bare name takes this node's MagicDNS domain",
          _ts_hosts10[:2] == ("box.tail1234.ts.net", "box.ts.net"), repr(_ts_hosts10))
    check("core tailscale host: no domain, or tailscaled not answering, leaves the name as typed",
          _ts_hosts10[2:] == ("box", "box"), repr(_ts_hosts10))
    check("core tailscale host: a tailnet IP or a dotted name is used as-is, without asking",
          _ts_fq10 == ("100.64.0.9", "box.example.com") and _tsi_calls10 == [],
          repr((_ts_fq10, _tsi_calls10)))

    # ── the control-socket directory: a missing or uncreatable one means no multiplexing ───────
    _cm_tmp10 = _tmp10.mkdtemp(prefix="panel-cm10-")
    _cm_file10 = os.path.join(_cm_tmp10, "a-file")
    open(_cm_file10, "w").close()
    _sm_core._SSH_CM_DIR = os.path.join(_cm_file10, "sub")
    _mux10 = _sm_core._ssh_mux_opts()
    # One that exists but others can write: a socket planted in it would get every command.
    _cm_loose10 = os.path.join(_cm_tmp10, "loose")
    os.mkdir(_cm_loose10)
    os.chmod(_cm_loose10, 0o777)
    _sm_core._SSH_CM_DIR = _cm_loose10
    _cap_cm10, _cap_cmoff10 = _cap10("panel.ssh")
    try:
        _mux_loose10 = _sm_core._ssh_mux_opts()
    finally:
        _cap_cmoff10()
    _core_restore10("_SSH_CM_DIR")
    _cm_missing10 = _sm_core._cm_dir_is_ours(os.path.join(_cm_tmp10, "never-made"))
    _shutil10.rmtree(_cm_tmp10, ignore_errors=True)
    check("core ssh mux: a socket dir that cannot be created, or does not exist, disables it",
          _mux10 == [] and _cm_missing10 is False, repr((_mux10, _cm_missing10)))
    check("core ssh mux: a socket dir others can write disables it, and says so",
          _mux_loose10 == [] and any("multiplexing disabled" in m for m in _cap_cm10.warned),
          repr((_mux_loose10, _cap_cm10.msgs)))

    # ── the tailscale transport: timeouts and failures are rc -1, never a raise ────────────────
    _sm_core._ssh_mux_opts = lambda: []
    _sm_core._resolve_ts_host = lambda s: s.host
    _sm_core._ssh_connect_timeout = lambda: 7
    _TSREM10 = NS(id=703, name="ts", is_local=False, auth_method="tailscale", host="box.ts.net",
                  port=None, username="admin", sudo_enabled=True)
    _cli_pop10 = []

    def _cli_popen10(argv, **kw):
        _cli_pop10.append((argv, kw))
        return NS(kill=lambda: None)

    _sm_core.subprocess = NS(Popen=_cli_popen10, PIPE="PIPE", DEVNULL="DEVNULL")
    _cli_feed10 = []
    _sm_core._collect_capped = lambda p, t, kill, threads, stdin_bytes=None: (
        _cli_feed10.append(stdin_bytes) or (b"line\r\nout \xff\n", b" warn \n", 0, True))
    _cap_s10, _cap_soff10 = _cap10("panel.ssh")
    try:
        _cli_ok10 = _sm_core._run_via_ssh_cli(_TSREM10, "cat /etc/hostname", timeout=9,
                                               stdin_text="s3cret")
    finally:
        _cap_soff10()
    _sm_core._collect_capped = lambda *a, **k: None
    _cli_to10 = _sm_core._run_via_ssh_cli(_TSREM10, "sleep 99", sudo=False)
    _sm_core.subprocess = NS(Popen=_raiser10(FileNotFoundError("ssh")), PIPE="PIPE",
                             DEVNULL="DEVNULL")
    _cli_err10 = _sm_core._run_via_ssh_cli(_TSREM10, "true")
    _core_restore10("subprocess", "_collect_capped", "_ssh_mux_opts", "_resolve_ts_host",
                    "_ssh_connect_timeout")
    check("core ssh cli: the argv is ssh -T, batch mode, the configured timeout, the destination "
          "after --, and root via `sudo bash -c` when asked",
          _cli_pop10 and _cli_pop10[0][0] == [
              "ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
              "-o", "ConnectTimeout=7", "-p", "22", "--", "admin@box.ts.net",
              "sudo bash -c " + _shlex10.quote("cat /etc/hostname")],
          repr(_cli_pop10[:1]))
    check("core ssh cli: a secret goes down stdin (a pipe), never on the command line",
          _cli_pop10[0][1].get("stdin") == "PIPE" and _cli_feed10 == [b"s3cret"]
          and _cli_pop10[1][1].get("stdin") == "DEVNULL"
          and not any("s3cret" in a for a in _cli_pop10[0][0]), repr(_cli_pop10))
    check("core ssh cli: output is decoded leniently and stripped; truncation is logged",
          _cli_ok10 == ("line\nout �", "warn", 0)
          and any("truncated" in m for m in _cap_s10.msgs), repr((_cli_ok10, _cap_s10.msgs)))
    check("core ssh cli: a timeout and a missing ssh binary are rc -1 answers, not exceptions",
          _cli_to10 == ("", "SSH command timed out", -1)
          and _cli_err10 == ("", "ssh command error", -1), repr((_cli_to10, _cli_err10)))

    # ── _drain_exec: both streams drained to a cap, and a silent remote is given up on ─────────
    class _ExecChan10:
        def __init__(self, out=(), err=(), rc=0, exit_ready=True, close_fails=False):
            self.out, self.err, self.rc = list(out), list(err), rc
            self.exit_ready, self.close_fails, self.closed = exit_ready, close_fails, 0

        def settimeout(self, t):
            self.timeout = t

        def _pop(self, q):
            v = q.pop(0)
            if isinstance(v, BaseException):
                raise v
            return v

        def recv_ready(self):
            return bool(self.out)

        def recv(self, n):
            return self._pop(self.out)

        def recv_stderr_ready(self):
            return bool(self.err)

        def recv_stderr(self, n):
            return self._pop(self.err)

        def exit_status_ready(self):
            return self.exit_ready

        def recv_exit_status(self):
            return self.rc

        def close(self):
            self.closed += 1
            if self.close_fails:
                raise OSError("channel already gone")

    _dx10 = _sm_core._drain_exec(_ExecChan10(out=[b"aaaa", socket.timeout(), b"bbbb", b"cccc"],
                                             err=[b"eeee", b"ffff", b"gggg"], rc=3),
                                 max_bytes=6)
    check("core drain: stdout and stderr each keep their first max_bytes and report truncation",
          _dx10 == (b"aaaabb", b"eeeeff", 3, True), repr(_dx10))
    _dx_eof10 = _sm_core._drain_exec(_ExecChan10(out=[b"x", b""], err=[b""], rc=0))
    check("core drain: an empty read ends that stream's pass without losing what came before",
          _dx_eof10 == (b"x", b"", 0, False), repr(_dx_eof10))
    _silent10 = _ExecChan10(exit_ready=False, close_fails=True)
    _t0_10 = time.monotonic()
    _dx_idle10 = _sm_core._drain_exec(_silent10, idle_limit=0.05)
    check("core drain: a remote that sends nothing and never exits is given up on as rc -1",
          _dx_idle10[2] == -1 and b"no output and no exit status" in _dx_idle10[1]
          and _silent10.closed == 1 and time.monotonic() - _t0_10 < 3, repr(_dx_idle10))

    # ── run_command's paramiko path ────────────────────────────────────────────────────────────
    class _ExecStdin10:
        def __init__(self, fail_shutdown=True):
            self.wrote, self.flushed, self.shutdowns = [], 0, 0
            self.fail_shutdown = fail_shutdown
            self.channel = NS(shutdown_write=self._shutdown)

        def _shutdown(self):
            self.shutdowns += 1
            if self.fail_shutdown:
                raise OSError("half-closed")

        def write(self, s):
            self.wrote.append(s)

        def flush(self):
            self.flushed += 1

    _exec_seen10 = []

    class _ExecClient10:
        def __init__(self, fail=False):
            self.fail, self.stdin = fail, _ExecStdin10()

        def exec_command(self, cmd, timeout=None):
            _exec_seen10.append((cmd, timeout))
            if self.fail:
                raise _paramiko10.SSHException("channel closed")
            return self.stdin, NS(channel="CHAN"), NS()

    _drain_args10 = []
    _sm_core._drain_exec = lambda chan, idle_limit=None: (
        _drain_args10.append((chan, idle_limit)) or (b" out \n", b"err\n", 0, True))
    _xc10 = _ExecClient10()
    _sm_core.get_connection = lambda server, **kw: _xc10
    _cap_s10, _cap_soff10 = _cap10("panel.ssh")
    try:
        _rc_out10 = _sm_core.run_command(_REMOTE10, "id -u", timeout=12, stdin_text="pw\n")
    finally:
        _cap_soff10()
    _sm_core.get_connection = lambda server, **kw: _ExecClient10(fail=True)
    _rc_fail10 = _try10(_sm_core.run_command, _REMOTE10, "id -u", sudo=False)
    _core_restore10("_drain_exec", "get_connection")
    check("core run_command: sudo=True on a remote is `sudo bash -c` around the whole command",
          _exec_seen10[0] == ("sudo bash -c " + _shlex10.quote("id -u"), 12)
          and _exec_seen10[1] == ("id -u", 30), repr(_exec_seen10))
    check("core run_command: stdin gets the secret, then EOF — even if the half-close fails",
          _xc10.stdin.wrote == ["pw\n"] and _xc10.stdin.flushed == 1
          and _xc10.stdin.shutdowns == 1, repr((_xc10.stdin.wrote, _xc10.stdin.shutdowns)))
    check("core run_command: the drain is bounded by silence (>= 300s), decoded and stripped",
          _drain_args10 == [("CHAN", 300)] and _rc_out10 == ("out", "err", 0)
          and any("truncated" in m for m in _cap_s10.msgs), repr((_drain_args10, _rc_out10)))
    check("core run_command: an exec failure on a live connection is a ConnectionError",
          isinstance(_rc_fail10, tuple) and _rc_fail10[1].startswith("ConnectionError(")
          and "Command failed" in _rc_fail10[1], repr(_rc_fail10))

    # ── remote_public_ip: the next source is tried when one fails ──────────────────────────────
    _pip_n10 = {"n": 0}

    def _pip_rc10(server, cmd, timeout=None):
        _pip_n10["n"] += 1
        if _pip_n10["n"] == 1:
            raise ConnectionError("blip")
        return ("203.0.113.5\nextra", "", 0) if _pip_n10["n"] == 2 else ("", "", 1)

    _sm_core.run_command = _pip_rc10
    _pip10 = _sm_core.remote_public_ip(_REMOTE10)
    _sm_core.run_command = lambda server, cmd, timeout=None: ("<html>blocked</html>", "", 0)
    _pip_none10 = _sm_core.remote_public_ip(_REMOTE10)
    check("core public ip: a failing lookup falls through to the next; non-IP answers are ''",
          _pip10 == "203.0.113.5" and _pip_none10 == "", repr((_pip10, _pip_none10)))

    # ── the live-metrics parsers ───────────────────────────────────────────────────────────────
    _HOST_OUT10 = ("cpu  100 0 100 800 0 0 0 0 0 0\n"
                   "GJA gm 1000\nGJA other 50\nGJA broken x\n"
                   "cpu  150 0 150 900 0 0 0 0 0 0\n"
                   "GJB gm 1100\nGJB other 50\n"
                   "MEM 8000000000 2000000000\nLOAD 0.50 0.40 0.30\nDISK 100000 25000\n"
                   "CORES 4\nUPTIME 3600\nGAMERAM gm 2048000 3\nGUP gm 120\n"
                   "PORT 27015\nPORT 22\nPORT notaport\n\ngarbage\n")
    _hm_calls10 = {"n": 0}

    def _hm_rc10(server, cmd, timeout=None, sudo=None):
        _hm_calls10["n"] += 1
        return (_HOST_OUT10 if server.id == 801 else "", "", 0 if server.id == 801 else -1)

    _sm_core.run_command = _hm_rc10
    _sm_core._host_metrics_cache.pop(801, None)
    _sm_core._host_metrics_cache.pop(802, None)
    _hlm10 = _sm_core.host_live_metrics(NS(id=801))
    _hlm_again10 = _sm_core.host_live_metrics(NS(id=801))
    _hlm_fail10 = _sm_core.host_live_metrics(NS(id=802))
    _hlm_calls10 = _hm_calls10["n"]
    _sm_core._host_metrics_cache.pop(801, None)
    check("core host metrics: the host's CPU, RAM, disk, load, cores, uptime and ports are parsed",
          _hlm10["host"] == {"cpu_percent": 50.0, "ram_used": 2000000000, "ram_total": 8000000000,
                             "ram_percent": 25.0, "disk_used": 25000, "disk_total": 100000,
                             "disk_percent": 25.0, "load": [0.5, 0.4, 0.3], "cores": 4,
                             "uptime_secs": 3600}
          and _hlm10["ports"] == {27015, 22},
          repr(_hlm10["host"]))
    check("core host metrics: every user's share comes from the same sample window",
          _hlm10["users"]["gm"] == {"game_cpu_percent": 50.0, "game_ram_mb": 2000, "game_procs": 3,
                                    "game_uptime_secs": 120, "game_ram_percent": 26.2}
          and _hlm10["users"]["other"]["game_cpu_percent"] == 0.0,
          repr(_hlm10["users"]))
    check("core host metrics: a second viewer within the TTL reuses the sample; a failed read is "
          "never cached (so the next poll retries)",
          _hlm_again10 is _hlm10 and _hlm_calls10 == 2 and 802 not in _sm_core._host_metrics_cache
          and _hlm_fail10["host"]["ram_total"] == 0, repr(_hlm_calls10))

    _slm_calls10 = {"n": 0}

    def _slm_rc10(server, cmd, timeout=None, sudo=None):
        _slm_calls10["n"] += 1
        return ("cpu  1 0 1 8 0 0 0\n\ncpu  2 0 2 9 0 0 0\nMEM 100 50\n", "", 0)

    _sm_core.run_command = _slm_rc10
    _sm_core._live_metrics_cache.pop((803, None, None), None)
    _slm10 = _sm_core.server_live_metrics(NS(id=803))
    _slm_again10 = _sm_core.server_live_metrics(NS(id=803))
    _sm_core._live_metrics_cache.pop((803, None, None), None)
    check("core server metrics: a blank line is skipped, and a repeat inside the TTL is served "
          "from the cache", _slm10["ram_percent"] == 50.0 and _slm_again10 is _slm10
          and _slm_calls10["n"] == 1, repr((_slm10.get("ram_percent"), _slm_calls10)))

    _RLM_OUT10 = ("===A\ncpu  100 0 100 800 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\n"
                  "===B\ncpu  150 0 150 900 0 0 0 0\ncpu0 75 0 75 450 0 0 0 0\n\n"
                  "===MEM\nMemTotal: 8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: junk kB\n"
                  "===DISK\nFilesystem 1B-blocks Used Available Use% Mounted\n"
                  "/dev/sda1 100000 25000 75000 25% /\n")
    _sm_core.run_command = lambda server, cmd, timeout=None: (_RLM_OUT10, "", 0)
    _so10.live_metrics = _raiser10(OSError("no /proc"))
    try:
        _rlm10 = _sm_core.remote_live_metrics(_LOCAL10)
    finally:
        _so10.live_metrics = _core_live10
    check("core remote metrics: the panel host falls back to the command when its own reader fails",
          _rlm10.get("read_ok") is True and _rlm10.get("cpu_overall") == 50.0
          and _rlm10.get("cpu_cores") == [50.0]
          and _rlm10.get("ram_total") == 8000000 * 1024 and _rlm10.get("ram_percent") == 25.0
          and _rlm10.get("disk_percent") == 25.0,
          repr(_rlm10))
    check("core remote metrics: an unparseable meminfo line is skipped, not fatal",
          _rlm10.get("swap_total") == 0 and _rlm10.get("swap_percent") == 0, repr(_rlm10))
    _core_restore10("run_command")

    # ── get_connection: auth methods, host-key pinning, pooling ────────────────────────────────
    class _Key10:
        def __init__(self, name, b64):
            self.name, self.b64 = name, b64

        def get_name(self):
            return self.name

        def get_base64(self):
            return self.b64

    class _Tr10:
        def __init__(self):
            self.active, self.ignores, self.keepalive = True, 0, None

        def is_active(self):
            return self.active

        def send_ignore(self):
            self.ignores += 1

        def set_keepalive(self, n):
            self.keepalive = n

    class _FakeSSH10:
        script = {}
        made = []

        def __init__(self):
            self.policy, self.host, self.kw, self.closed = None, None, None, 0
            self.transport = _Tr10()
            _FakeSSH10.made.append(self)

        def set_missing_host_key_policy(self, p):
            self.policy = p

        def connect(self, host, **kw):
            self.host, self.kw = host, kw
            s = _FakeSSH10.script
            if s.get("hook"):
                s["hook"](self)
            if s.get("raise"):
                raise s["raise"]
            if s.get("key"):
                self.policy.missing_host_key(self, host, _Key10(*s["key"]))

        def get_transport(self):
            return self.transport

        def close(self):
            self.closed += 1
            if getattr(self, "fail_close", False):
                raise OSError("close on a dead transport")

    _persisted10 = []
    _sm_core.paramiko = NS(SSHClient=_FakeSSH10,
                           AuthenticationException=_paramiko10.AuthenticationException)
    _sm_core._ssh_connect_timeout = lambda: 7
    _sm_core._persist_host_key = lambda server, key: _persisted10.append((server.id, key))
    _sm_core._connections.clear()
    _sm_core._remote_conn_keys.clear()

    def _srv10(**kw):
        base = dict(id=901, name="pw-host", host="192.0.2.30", port=2200, username="admin",
                    auth_method="password", auth_credential="hunter2", host_key="",
                    is_local=False, sudo_enabled=False)
        base.update(kw)
        return NS(**base)

    def _gc10(server, script=None, **kw):
        _FakeSSH10.script = script or {}
        return _try10(_sm_core.get_connection, server, **kw)

    check("core connect: the panel host needs no SSH connection",
          _sm_core.get_connection(_LOCAL10) is None, "")
    _pw_srv10 = _srv10()
    _c1_10 = _gc10(_pw_srv10, {"key": ("ssh-ed25519", "AAAAfirst")})
    _c1_closed10 = getattr(_c1_10, "closed", None)    # read now: a later check closes it on purpose
    _key1_10 = _sm_core._conn_key("admin", "192.0.2.30", 2200)
    check("core connect: a password host connects with the password only (no agent, no keys) "
          "and the configured timeout",
          isinstance(_c1_10, _FakeSSH10) and _c1_10.host == "192.0.2.30"
          and _c1_10.kw == {"port": 2200, "username": "admin", "password": "hunter2", "timeout": 7,
                            "allow_agent": False, "look_for_keys": False},
          repr(getattr(_c1_10, "kw", _c1_10)))
    check("core connect: first contact pins the presented host key",
          _persisted10 == [(901, "ssh-ed25519 AAAAfirst")], repr(_persisted10))
    check("core connect: the client is pooled under user@host:port, remembered for its row, and "
          "kept warm", _sm_core._connections.get(_key1_10) is _c1_10
          and _sm_core._remote_conn_keys.get(901) == _key1_10 and _c1_10.transport.keepalive == 30,
          repr(sorted(_sm_core._connections)))
    check("core connect: a connection that succeeds is handed out open — the close on failure "
          "does not reach it (positive control)", _c1_closed10 == 0, repr(_c1_closed10))
    _c1b_10 = _gc10(_pw_srv10)
    check("core connect: a live pooled client is reused (and poked), not reopened",
          _c1b_10 is _c1_10 and _c1_10.transport.ignores == 1 and len(_FakeSSH10.made) == 1,
          "made %d" % len(_FakeSSH10.made))
    _c1_10.transport.active = False
    _c1c_10 = _gc10(_pw_srv10)
    check("core connect: a dead pooled client is closed and replaced",
          _c1c_10 is not _c1_10 and _c1_10.closed == 1
          and _sm_core._connections.get(_key1_10) is _c1c_10, "")
    # force_new means a NEW connection even while the pooled one is alive (the caller has reason
    # to distrust it), and the new one takes the pool slot. Restored after, for the checks below.
    _made_fn10 = len(_FakeSSH10.made)
    _c1f_10 = _gc10(_pw_srv10, force_new=True)
    check("core connect: force_new opens a fresh client even while the pooled one is alive",
          isinstance(_c1f_10, _FakeSSH10) and _c1f_10 is not _c1c_10
          and len(_FakeSSH10.made) == _made_fn10 + 1
          and _sm_core._connections.get(_key1_10) is _c1f_10, repr(_c1f_10))
    _sm_core._connections[_key1_10] = _c1c_10
    _c1c_10.get_transport = _raiser10(EOFError("transport torn down"))
    _c1c_10.fail_close = True

    def _no_keepalive10(client):
        client.transport.set_keepalive = _raiser10(OSError("no transport yet"))

    _c1d_10 = _gc10(_pw_srv10, {"hook": _no_keepalive10})
    check("core connect: a pooled client that cannot even be probed or closed is replaced, and a "
          "keepalive that cannot be set does not fail the connection",
          isinstance(_c1d_10, _FakeSSH10) and _c1d_10 is not _c1c_10 and _c1c_10.closed == 1
          and _sm_core._connections.get(_key1_10) is _c1d_10, repr(_c1d_10))

    _tsi10.get_tailscale_info = lambda: NS(dns_name="me.tailabc.ts.net")
    _persisted10[:] = []
    _c2_10 = _gc10(_srv10(id=902, host="box", port=22, auth_method="tailscale",
                          auth_credential="", host_key="ssh-ed25519 OLD"),
                   {"key": ("ssh-ed25519", "NEW")})
    # ...and one with no key stored at all: first contact over the tailnet captures a key, which
    # must not be pinned — WireGuard, not the SSH host key, is the trust anchor there.
    _c2b_10 = _gc10(_srv10(id=912, host="box2.example.ts.net", port=22, auth_method="tailscale",
                           auth_credential="", host_key=""), {"key": ("ssh-ed25519", "FIRST")})
    _tsi10.get_tailscale_info = _core_tsinfo10
    check("core connect: a tailscale host resolves a bare name via MagicDNS and uses the agent",
          isinstance(_c2_10, _FakeSSH10) and _c2_10.host == "box.tailabc.ts.net"
          and _c2_10.kw.get("allow_agent") is True and _c2_10.kw.get("look_for_keys") is True,
          repr(getattr(_c2_10, "kw", _c2_10)))
    check("core connect: over tailscale a changed host key is accepted, and never re-pinned",
          isinstance(_c2_10, _FakeSSH10) and isinstance(_c2b_10, _FakeSSH10)
          and _persisted10 == [], repr((_c2_10, _c2b_10, _persisted10)))

    _c3_10 = _gc10(_srv10(id=903, host="192.0.2.33", auth_method="key", auth_credential=""), pooled=False)
    check("core connect: a key host with no stored path uses ~/.ssh/id_rsa",
          isinstance(_c3_10, _FakeSSH10)
          and _c3_10.kw.get("key_filename") == os.path.expanduser("~/.ssh/id_rsa"),
          repr(getattr(_c3_10, "kw", _c3_10)))
    check("core connect: pooled=False hands back a client the pool never sees",
          _c3_10 not in _sm_core._connections.values() and 903 not in _sm_core._remote_conn_keys, "")

    _made_before10 = len(_FakeSSH10.made)
    _unr10 = _gc10(_srv10(id=904, host="192.0.2.34", auth_method="key", host_key=_Unreadable10()))
    check("core connect: a pinned key that cannot be DECRYPTED refuses to connect at all",
          isinstance(_unr10, tuple) and _unr10[1].startswith("HostKeyMismatch(")
          and "cannot be decrypted" in _unr10[1]
          and all(m.host is None for m in _FakeSSH10.made[_made_before10:]),
          repr(_unr10)[:200])
    _made_mitm10 = len(_FakeSSH10.made)
    _mitm10 = _gc10(_srv10(id=905, host="192.0.2.35", auth_method="key", host_key="ssh-ed25519 PINNED"),
                    {"key": ("ssh-ed25519", "SOMEONE-ELSE")})
    _mitm_clients10 = _FakeSSH10.made[_made_mitm10:]
    check("core connect: a CHANGED host key on a direct host is refused, unwrapped",
          isinstance(_mitm10, tuple) and _mitm10[1].startswith("HostKeyMismatch(")
          and "CHANGED" in _mitm10[1], repr(_mitm10)[:200])
    # paramiko's connect() has started a Transport thread and opened the socket by the time the
    # host-key policy raises, and closes neither. On a test host three refused connects left three
    # threads and three ESTABLISHED sockets 30 s later; a man-in-the-middle can hold them for good.
    check("core connect: ...and the client it refused is CLOSED, not left holding a thread and a "
          "socket", [c.closed for c in _mitm_clients10] == [1]
          and _mitm_clients10[0] not in _sm_core._connections.values(),
          repr([c.closed for c in _mitm_clients10]))
    _same10 = _gc10(_srv10(id=906, host="192.0.2.36", auth_method="key", host_key="ssh-ed25519 PINNED"),
                    {"key": ("ssh-ed25519", "PINNED")}, pooled=False)
    check("core connect: the pinned key presented again is accepted",
          isinstance(_same10, _FakeSSH10), repr(_same10))

    _errs10, _err_closed10 = {}, {}
    for _label10, _exc10 in (("auth", _paramiko10.AuthenticationException("no")),
                             ("timeout", socket.timeout()),
                             ("dns", socket.gaierror(-2, "Name or service not known")),
                             ("other", RuntimeError("banner garbled"))):
        _made_err10 = len(_FakeSSH10.made)
        _errs10[_label10] = _gc10(_srv10(id=907, host="192.0.2.37"), {"raise": _exc10}, force_new=True)
        _err_closed10[_label10] = [c.closed for c in _FakeSSH10.made[_made_err10:]]
    check("core connect: a failed login, a timeout, an unresolvable name and any other connect "
          "error each CLOSE the client they failed on",
          _err_closed10 == {"auth": [1], "timeout": [1], "dns": [1], "other": [1]},
          repr(_err_closed10))

    # Not only Exception: an eventlet Timeout or a killed green thread is a BaseException, reaches
    # the caller unwrapped, and leaves the same thread and socket behind if nothing closes them.
    class _Killed10(BaseException):
        pass

    _made_kill10 = len(_FakeSSH10.made)
    _FakeSSH10.script = {"raise": _Killed10("green thread killed mid-connect")}
    try:
        _sm_core.get_connection(_srv10(id=909, host="192.0.2.39"), force_new=True)
        _kill10 = "returned"
    except _Killed10 as _e10:
        _kill10 = "raised " + str(_e10)
    _FakeSSH10.script = {}
    check("core connect: a connect killed by a BaseException closes the client and re-raises it "
          "as it came", _kill10 == "raised green thread killed mid-connect"
          and [c.closed for c in _FakeSSH10.made[_made_kill10:]] == [1],
          repr((_kill10, [c.closed for c in _FakeSSH10.made[_made_kill10:]])))
    check("core connect: each failure becomes a ConnectionError that says which it was",
          all(isinstance(v, tuple) and v[1].startswith("ConnectionError(") for v in _errs10.values())
          and "authentication failed" in _errs10["auth"][1]
          and "timed out" in _errs10["timeout"][1]
          and "Cannot resolve hostname" in _errs10["dns"][1]
          and "banner garbled" in _errs10["other"][1],
          repr(_errs10)[:400])

    # Two green threads connecting to one host at once: the loser closes its own client and
    # hands back the winner's, rather than leaking a second socket into the pool.
    _winner10 = _FakeSSH10()
    _race_srv10 = _srv10(id=908, host="192.0.2.31")
    _race_key10 = _sm_core._conn_key("admin", "192.0.2.31", 2200)

    def _someone_else_won10(client):
        _sm_core._connections[_race_key10] = _winner10
        client.fail_close = True             # and closing our spare fails too: still handled

    _race10 = _gc10(_race_srv10, {"hook": _someone_else_won10})
    _loser10 = _FakeSSH10.made[-1]
    check("core connect: losing a connect race returns the winner's client and closes ours",
          _race10 is _winner10 and _loser10.closed == 1
          and _sm_core._remote_conn_keys.get(908) == _race_key10, "")

    # _close_key / close_connection
    class _BadClose10:
        def close(self):
            raise OSError("socket already dead")

    _sm_core._connections["k@h:1"] = _BadClose10()
    _sm_core._remote_conn_keys[950] = "k@h:1"
    _ck10 = _try10(_sm_core._close_key, "k@h:1")
    check("core pool: closing a client whose socket is already dead still drops it from the pool",
          _ck10 is True and "k@h:1" not in _sm_core._connections
          and 950 not in _sm_core._remote_conn_keys, repr(_ck10))
    _sm_core._close_key = lambda key: _persisted10.append(("closed", key))
    _persisted10[:] = []
    _sm_core.close_connection(_LOCAL10)
    check("core pool: close_connection on the panel host closes nothing",
          _persisted10 == [], repr(_persisted10))
    _core_restore10("_close_key")

    # _PinPolicy on its own: first contact captures, a match passes, a change is rejected unless
    # the caller said the key is not the trust anchor.
    _pp_first10 = _sm_core._PinPolicy("")
    _pp_first10.missing_host_key(None, "h", _Key10("ssh-rsa", "AAA"))
    _pp_loose10 = _sm_core._PinPolicy("ssh-rsa OLD", reject_on_change=False)
    _pp_loose_r10 = _try10(_pp_loose10.missing_host_key, None, "h", _Key10("ssh-rsa", "NEW"))
    check("core host key policy: first contact captures; a change is let through only when told",
          _pp_first10.captured == "ssh-rsa AAA" and _pp_loose_r10 is None
          and _pp_loose10.captured is None, repr((_pp_first10.captured, _pp_loose_r10)))

    # _persist_host_key: never lets a pin failure become a failed connection
    class _PinRefuses10:
        id = 960

        @property
        def host_key(self):
            return ""

        @host_key.setter
        def host_key(self, v):
            raise RuntimeError("detached instance")

    # ...and answers False rather than None when it did not store the pin: get_connection refuses
    # the connection on False, because an unstored pin makes the NEXT fresh connection first
    # contact again. Both ways a store can fail: no app to reach the database with, and a database
    # that will not answer.
    from flask import has_app_context as _hac10  # noqa: E402
    _pin_app_saved10 = _sm_core._pin_app
    _nodb_dir10 = _tmp10.mkdtemp(prefix="unit-nodb-")
    try:
        _sm_core._pin_app = None
        _phk10 = _try10(_core_saved10["_persist_host_key"], _PinRefuses10(), "ssh-rsa X")
        _nodb_app10 = _Flask10("unit_part13_nodb")
        _nodb_app10.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_nodb_dir10, "gone", "x.db"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False, SECRET_KEY="unit-part13", TESTING=True)
        _db10.init_app(_nodb_app10)
        _sm_core._pin_app = _nodb_app10
        _phk_db10 = _try10(_core_saved10["_persist_host_key"], _PinRefuses10(), "ssh-rsa X")
    finally:
        _sm_core._pin_app = _pin_app_saved10
        _shutil10.rmtree(_nodb_dir10, ignore_errors=True)
    check("core host key: a pin that cannot be stored answers False, and never raises",
          _phk10 is False and _phk_db10 is False and not _hac10(),
          repr((_phk10, _phk_db10, _hac10())))

    # The pool is invalidated when the ROW changes, and per-host caches when the row goes away.
    with _dbapp10.app_context():
        _reset_db10()
        _row10 = _mk_remote10("pin-row", host="192.0.2.40", auth_method="key")
        _core_saved10["_persist_host_key"](_row10, "ssh-ed25519 ROWKEY")
        _db10.session.expire_all()
        _pinned10 = _db10.session.get(_RS10, _row10.id).host_key
        _closed_keys10 = []
        _sm_core._remote_conn_keys[_row10.id] = "root@192.0.2.40:22"
        _sm_core._close_key = lambda key: _closed_keys10.append(key)
        _row10 = _db10.session.get(_RS10, _row10.id)
        _row10.host = "192.0.2.41"
        _db10.session.commit()
        _sm_core._close_key = _raiser10(RuntimeError("pool bug"))
        _row10.port = 2222
        _upd_r10 = _try10(_db10.session.commit)
        _db10.session.rollback()         # a no-op after a commit; after a failed one, it is not
        _core_restore10("_close_key")
        _sm_core.forget_remote_caches = _raiser10(RuntimeError("cache bug"))
        _db10.session.delete(_row10)
        _del_r10 = _try10(_db10.session.commit)
        _db10.session.rollback()
        _core_restore10("forget_remote_caches")
        _gone10 = _RS10.query.filter_by(name="pin-row").first() is None
        _db10.session.remove()
    check("core host key: a first-contact pin is stored on the host's row",
          _pinned10 == "ssh-ed25519 ROWKEY", repr(_pinned10))

    # ...and only on the row for the endpoint that connection met (_pin_row_matches). The row is
    # loaded by id, and SQLite hands a deleted host's id to the next host created, so a handshake
    # held across a delete — the far side holds it, so the far side chooses — pinned the OLD box's
    # key on the host that took the id, and the panel then trusted that box at the new address.
    # Each "caller" below is the copy the connection was made with: loaded, then detached.
    import datetime as _dtp10  # noqa: E402
    from panel.db.models import UnreadableSecret as _US10  # noqa: E402

    def _caller10(row):
        _db10.session.refresh(row)
        _db10.session.expunge(row)
        return row

    with _dbapp10.app_context():
        _reset_db10()
        _met10 = _caller10(_mk_remote10("pin-met", host="192.0.2.60", auth_method="key"))
        _db10.session.execute(_db10.text("UPDATE remote_server SET created_at = :c WHERE id = :i"),
                              {"c": _dtp10.datetime(2001, 1, 1), "i": _met10.id})
        _db10.session.commit()
        _reborn_r10 = _core_saved10["_persist_host_key"](_met10, "ssh-ed25519 OLDBOX")
        _reborn_k10 = _db10.session.get(_RS10, _met10.id).host_key
        _db10.session.remove()
    with _dbapp10.app_context():
        _reset_db10()
        _met10 = _caller10(_mk_remote10("pin-moved", host="192.0.2.61", auth_method="key"))
        _db10.session.execute(_db10.text("UPDATE remote_server SET host = '192.0.2.62' WHERE id = :i"),
                              {"i": _met10.id})
        _db10.session.commit()
        _moved_r10 = _core_saved10["_persist_host_key"](_met10, "ssh-ed25519 OTHERADDR")
        _moved_k10 = _db10.session.get(_RS10, _met10.id).host_key
        _db10.session.remove()
    with _dbapp10.app_context():
        _reset_db10()
        _met10 = _caller10(_mk_remote10("pin-race", host="192.0.2.63", auth_method="key"))
        _db10.session.execute(_db10.text("UPDATE remote_server SET host_key = NULL WHERE id = :i"),
                              {"i": _met10.id})
        _row10 = _db10.session.get(_RS10, _met10.id)
        _row10.host_key = "ssh-ed25519 FIRSTSEEN"
        _db10.session.commit()
        _race_r10 = _core_saved10["_persist_host_key"](_met10, "ssh-ed25519 SECONDSEEN")
        _same_r10 = _core_saved10["_persist_host_key"](_met10, "ssh-ed25519 FIRSTSEEN")
        _db10.session.expire_all()
        _race_k10 = _db10.session.get(_RS10, _met10.id).host_key
        _db10.session.remove()
    check("core host key: a connection whose host was replaced by one that took its id pins "
          "nothing on the new host", _reborn_r10 is False and not _reborn_k10,
          repr((_reborn_r10, _reborn_k10)))
    check("core host key: ...nor on a row that now names another address",
          _moved_r10 is False and not _moved_k10, repr((_moved_r10, _moved_k10)))
    check("core host key: a pin another first contact already stored is never replaced by a "
          "different key", _race_r10 is False and _race_k10 == "ssh-ed25519 FIRSTSEEN",
          repr((_race_r10, _race_k10)))
    check("core host key: ...and the same key again is simply accepted (control)",
          _same_r10 is True, repr(_same_r10))
    _unreadable_row10 = NS(created_at=None, host="192.0.2.64", port=22, host_key=_US10())
    check("core host key: a pin this host cannot decrypt is never replaced (it reads as '')",
          _sm_core._pin_row_matches(_unreadable_row10, NS(host="192.0.2.64", port=22),
                                    "ssh-ed25519 NEW") is False
          and _sm_core._pin_row_matches(NS(created_at=None, host="192.0.2.64", port=22,
                                           host_key=""),
                                        NS(host="192.0.2.64", port=22), "ssh-ed25519 NEW") is True,
          "")
    check("core pool: repointing a host closes BOTH the key its client was opened under and the "
          "key it spells now", _closed_keys10 == ["root@192.0.2.40:22", "root@192.0.2.41:22"],
          repr(_closed_keys10))
    check("core pool: a pool or cache failure never turns into a failed commit",
          _upd_r10 is None and _del_r10 is None and _gone10, repr((_upd_r10, _del_r10)))

    # ── a first-contact pin taken on a WORKER thread is stored ─────────────────────────────────
    # Most first contacts happen on ThreadPoolExecutor workers with no app context: the monitor's
    # host probes, the player poll, /api/servers' port scan. The pin used to be stored with
    # `server.host_key = keystr; db.session.commit()`, which raised there and was swallowed, so the
    # host stayed unpinned while its pooled client lived — and every fresh connection after that
    # (a TCP reset forces one) was first contact again and trusted whatever key it was shown.
    # Driven through the monitor's REAL pool (_probe_hosts), with its reachability read wired to
    # the real get_connection and the fake client presenting a chosen key. A FILE database, not
    # _dbapp10's in-memory one: that shares one connection between every session, which is not
    # what a worker's commit meets in production.
    _core_restore10("_persist_host_key", "get_connection")
    _pin_dir10 = _tmp10.mkdtemp(prefix="unit-pin-")
    _pinapp10 = _Flask10("unit_part13_pin")
    _pinapp10.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_pin_dir10, "pin.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False, SECRET_KEY="unit-part13", TESTING=True)
    _db10.init_app(_pinapp10)
    _MON_PROBES10 = ("run_command", "_remote_listening_ports", "_host_disk_pct", "_host_load_mem",
                     "_host_restart_flags")
    _mon_saved10 = {k: getattr(_mon10, k) for k in _MON_PROBES10}
    _pin_app_saved10 = _sm_core._pin_app
    _wctx10 = []
    try:
        _sm_core.register_pin_app(_pinapp10)

        def _mon_reach10(remote, cmd, timeout=30, **k):
            _wctx10.append(_hac10())
            _sm_core.get_connection(remote)
            return ("ok", "", 0)

        _mon10.run_command = _mon_reach10
        for _k10 in _MON_PROBES10[1:]:
            setattr(_mon10, _k10, lambda *a, **k: None)
        _sm_core._connections.clear()
        with _pinapp10.app_context():
            _db10.create_all()
            _wrow10 = _RS10(name="pin-worker", host="192.0.2.50", port=22, username="root",
                            auth_method="key", auth_credential="")
            _db10.session.add(_wrow10)
            _db10.session.commit()
            _wid10 = _wrow10.id
            _FakeSSH10.script = {"key": ("ssh-ed25519", "K1")}
            _wprobe10 = _mon10._probe_hosts([_wrow10]).get(_wid10) or {}
            _wparent10 = (_wrow10.host_key, _wrow10 in _db10.session.dirty)
        with _pinapp10.app_context():
            _wstored10 = _db10.session.get(_RS10, _wid10).host_key
        # The pooled client dies (a reset), and the next connection meets a different key.
        _sm_core._connections.clear()
        with _pinapp10.app_context():
            _FakeSSH10.script = {"key": ("ssh-ed25519", "KMITM")}
            _wmitm10 = _try10(_sm_core.get_connection, _db10.session.get(_RS10, _wid10))
            _wafter10 = _db10.session.get(_RS10, _wid10).host_key
        # ...and when the pin cannot be stored at all, the connection is refused, not used.
        _sm_core._connections.clear()
        _sm_core._pin_app = None
        _FakeSSH10.script = {"key": ("ssh-ed25519", "K1")}
        _made_before_nopin10 = len(_FakeSSH10.made)
        _nopin10 = _try10(_sm_core.get_connection,
                          _srv10(id=_wid10, host="192.0.2.51", auth_method="key", host_key=""))
        _nopin_clients10 = _FakeSSH10.made[_made_before_nopin10:]
    finally:
        _sm_core._pin_app = _pin_app_saved10
        for _k10, _v10 in _mon_saved10.items():
            setattr(_mon10, _k10, _v10)
        _sm_core._connections.clear()
        _shutil10.rmtree(_pin_dir10, ignore_errors=True)
    check("core host key: the monitor probe really ran on a worker with no app context",
          _wctx10 == [False], repr(_wctx10))
    check("core host key: a first-contact pin taken on a monitor WORKER is stored in the database",
          _wprobe10.get("reachable") is True and _wstored10 == "ssh-ed25519 K1",
          "probe=%r stored=%r" % (_wprobe10, _wstored10))
    check("core host key: ...and the caller's own row carries it without being left dirty",
          _wparent10 == ("ssh-ed25519 K1", False), repr(_wparent10))
    check("core host key: ...so once the pooled client is gone, a DIFFERENT key is refused",
          isinstance(_wmitm10, tuple) and _wmitm10[1].startswith("HostKeyMismatch(")
          and _wafter10 == "ssh-ed25519 K1", "%r pin=%r" % (_wmitm10, _wafter10))
    check("core host key: a pin that could not be stored refuses the connection and closes it",
          isinstance(_nopin10, tuple) and _nopin10[1].startswith("ConnectionError(")
          and "could not store its SSH host key" in _nopin10[1]
          and [c.closed for c in _nopin_clients10] == [1] and not _sm_core._connections,
          "%r closed=%r" % (_nopin10, [c.closed for c in _nopin_clients10]))
finally:
    _core_restore10()
    _sm_core._connections.clear()
    _sm_core._connections.update(_core_conns_saved10)
    _sm_core._remote_conn_keys.clear()
    _sm_core._remote_conn_keys.update(_core_keys_saved10)
    _sm_core._HELPER_STATE.clear()
    _sm_core._HELPER_STATE.update(_core_helper_saved10)
    _priv10.HELPER_PATH = _core_helper_path10
    _tsi10.get_tailscale_info = _core_tsinfo10
    _cfgmod10.load_config = _core_cfgload10
    _so10.live_metrics = _core_live10


# ══════════════════════════════════════════════════════════════════════════════════════════════
# E. app.py — the helpers and background passes it defines
# ══════════════════════════════════════════════════════════════════════════════════════════════
# What this cannot reach, and why: the `if __name__ == "__main__":` block (the process's own
# startup — binds, starts threads, serves) and create_app()/register_routes() internals, which
# need the real data/ directory and start the tickers. The functions below are module level and
# are driven directly.
import datetime as _dt10  # noqa: E402

import app as _app10mod  # noqa: E402
from panel.core.clock import utcnow as _utcnow10  # noqa: E402
from panel.db.models import (GlobalBan as _GBan10, Group as _Group10, SetupState as _Setup10,  # noqa: E402
                             User as _User10, UserSession as _USess10)
from panel.ops.ssh_manager import cron as _smcron10  # noqa: E402
from panel.ops.ssh_manager import hosts as _smhosts10  # noqa: E402
from panel.security import auth as _ca13_auth  # noqa: E402

_APP_STUBBED10 = ("time", "db", "open", "load_config", "update_config", "log_action",
                  "notifications", "current_user", "get_user_permissions",
                  "accessible_remote_ids", "lgsm_get_values", "_remote_listening_ports",
                  "ensure_persistent_bans", "console_steamid_ban", "ensure_node_tools_cron",
                  "remote_set_fail2ban_ignoreip", "get_server_status", "pro_status",
                  "_refresh_player_counts", "_record_metric_samples", "_prune_metric_samples",
                  "_node_tools_cron_pass", "_monitor_pass", "_autoblock_hosts",
                  "_autoblock_reconcile", "_apply_whitelist_to_fail2ban",
                  "_apply_whitelist_to_remotes", "_host_reachable", "_autoblock_threshold",
                  "AUTH_LOG_PATH")
_app_saved10 = {k: getattr(_app10mod, k, "<absent>") for k in _APP_STUBBED10}
_app_so_saved10 = {k: getattr(_so10, k) for k in ("ensure_panel_host_whitelist",
                                                   "ensure_panel_fail2ban",
                                                   "fail2ban_unban_ip_everywhere",
                                                   "os_update_available")}
_app_dicts10 = {k: dict(getattr(_app10mod, k)) for k in
                ("_LOGIN_FAILS", "_LOGIN_BLOCK_LOGGED", "_ADMIN_BF_NOTIFIED", "_ASSET_HASHES",
                 "_RESOLVED_BIND")}
_app_cron_up10 = _smcron10.upgrade_managed_cron_tracking
_app_osck10 = _smhosts10.remote_os_check_updates
_app_slm10 = _sm_core.server_live_metrics
_app_suggest10 = _tsi10.suggest_best_bind
_app_authlog_state10 = (list(_app10mod._authlog.handlers), _app10mod._authlog.level,
                        _app10mod._authlog.propagate)


def _app_restore10(*names):
    for k in names or _APP_STUBBED10:
        v = _app_saved10[k]
        if v == "<absent>":
            if k in vars(_app10mod):
                delattr(_app10mod, k)
        else:
            setattr(_app10mod, k, v)


def _sleeper10(limit, seen):
    """A sleep that records its argument and stops the loop on call number `limit`."""
    def _s(sec):
        seen.append(sec)
        if len(seen) >= limit:
            raise _Stop10()
    return _s


class _RaisingUser10:
    @property
    def is_authenticated(self):
        raise RuntimeError("no login manager on this thread")


_app_trip_saved10 = _arm10()
try:
    # ── small pure helpers ─────────────────────────────────────────────────────────────────────
    check("app _log_ip: only a real IP is written to auth.log; CR/LF can never forge a line",
          _app10mod._log_ip(" 10.0.0.1 ") == "10.0.0.1"
          and _app10mod._log_ip("2001:db8::1") == "2001:db8::1"
          and _app10mod._log_ip("1.2.3.4\r\nFAKE") == "unknown"
          and _app10mod._log_ip(None) == "unknown", "")
    check("app _session_label: a UA with nothing recognisable is 'Unknown device'",
          _app10mod._session_label("") == "Unknown device"
          and _app10mod._session_label("Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0")
          == "Firefox on Linux", "")
    check("app ports: an aux port with nothing free above it is left alone, not moved to junk",
          _app10mod._dedupe_aux_ports({"clientport": 65535}, {65535}) == {}, "")
    check("app bind: only a concrete loopback address counts as loopback",
          _app10mod._bind_is_loopback("127.0.0.2") and _app10mod._bind_is_loopback("::1")
          and not _app10mod._bind_is_loopback("") and not _app10mod._bind_is_loopback("localhost"),
          "")
    check("app https: behind a trusted proxy the panel stands its own TLS down",
          _app10mod._effective_https({"use_https": True, "trust_proxy": True}) is False
          and _app10mod._effective_https({"use_https": True}) is True, "")
    # Aikido 745379296: trust_proxy with a bind beyond loopback is a direct path around the proxy.
    # Said at startup — the function, and that the entry point really calls it with the bind.
    _tpw10 = getattr(_app10mod, "_trust_proxy_bind_warning", lambda c, b: "")
    check("app startup: trust_proxy with a public bind is warned about, naming the fix",
          "bind_host" in _tpw10({"trust_proxy": True}, "0.0.0.0")  # nosec B104 - the input under test
          and "trusted_proxies" in _tpw10({"trust_proxy": True}, "0.0.0.0"),  # nosec B104
          repr(_tpw10({"trust_proxy": True}, "0.0.0.0")))  # nosec B104
    check("app startup: ...but not with a loopback bind, nor without trust_proxy (control)",
          _tpw10({"trust_proxy": True}, "127.0.0.1") == ""
          and _tpw10({"trust_proxy": False}, "0.0.0.0") == "", "")  # nosec B104
    import ast as _ast10
    _main10 = [n for n in _ast10.parse(open(_app10mod.__file__, encoding="utf-8").read()).body
               if isinstance(n, _ast10.If) and "__main__" in _ast10.dump(n.test)]
    _calls10 = [c for n in _main10 for c in _ast10.walk(n) if isinstance(c, _ast10.Call)
                and getattr(c.func, "id", "") == "_trust_proxy_bind_warning"
                and [getattr(a, "id", None) for a in c.args] == ["cfg", "host"]]
    check("app startup: the entry point asks it, with the bind it resolved",
          len(_calls10) == 1, "%d calls in the __main__ block" % len(_calls10))
    check("app origins: a malformed host or origin is None, not an exception",
          _app10mod._host_port("[::1") is None and _app10mod._origin_key("http://[::1") is None
          and _app10mod._host_port("panel.example.com:8443") == ("panel.example.com", 8443), "")
    _app10mod._RESOLVED_BIND.pop(59999, None)
    _tsi10.suggest_best_bind = _raiser10(RuntimeError("tailscale not installed"))
    _rb_fail10 = _app10mod._resolved_bind({"port": 59999})
    _tsi10.suggest_best_bind = _raiser10(AssertionError("asked twice"))
    _rb_cached10 = _app10mod._resolved_bind({"port": 59999})
    _tsi10.suggest_best_bind = _app_suggest10
    check("app bind: an unresolvable automatic bind falls back to 0.0.0.0, decided ONCE",
          _rb_fail10 == "0.0.0.0" and _rb_cached10 == "0.0.0.0"
          and _app10mod._resolved_bind({"bind_host": "127.0.0.1", "port": 59999}) == "127.0.0.1",
          repr((_rb_fail10, _rb_cached10)))
    # The version is worked out in ONE place, system_ops.panel_version (the commit's date); app.py
    # only asks it, once, at import. So: it is that answer, and a failure there is "unknown".
    _so_pv10 = _app10mod.so.panel_version
    try:
        _app10mod.so.panel_version = lambda: "2026.9.26"
        _ver10_ok = _app10mod._read_version()
        _app10mod.so.panel_version = _raiser10(OSError("git missing"))
        _ver10 = _app10mod._read_version()
    finally:
        _app10mod.so.panel_version = _so_pv10
    check("app version: it is system_ops.panel_version's answer, not a second reading of VERSION",
          _ver10_ok == "2026.9.26", repr(_ver10_ok))
    check("app version: a version that cannot be worked out reads as 'unknown', never an exception",
          _ver10 == "unknown", repr(_ver10))

    _now10 = time.time()
    _jobs10 = {"old": {"updated": _now10 - 8000}, "fresh": {"started": _now10 - 10},
               "undated": {}}
    _app10mod._prune_jobs(_jobs10, threading.Lock())
    check("app jobs: entries idle past two hours (or never dated) are pruned, live ones kept",
          sorted(_jobs10) == ["fresh"], repr(sorted(_jobs10)))
    _app10mod._LOGIN_FAILS.update({"198.51.100.1": [_now10 - 1000], "198.51.100.2": [_now10]})
    _app10mod._LOGIN_BLOCK_LOGGED.update({"198.51.100.1": _now10 - 1000})
    _app10mod._ADMIN_BF_NOTIFIED.update({"old-admin": _now10 - 1000, "new-admin": _now10})
    _app10mod._prune_login_fails(_now10)
    check("app login throttle: aged-out IPs and admin alert marks are forgotten, recent ones kept",
          "198.51.100.1" not in _app10mod._LOGIN_FAILS and "198.51.100.2" in _app10mod._LOGIN_FAILS
          and "198.51.100.1" not in _app10mod._LOGIN_BLOCK_LOGGED
          and "old-admin" not in _app10mod._ADMIN_BF_NOTIFIED
          and "new-admin" in _app10mod._ADMIN_BF_NOTIFIED, "")

    # ── config read-modify-writes, against an in-memory config ─────────────────────────────────
    _acfg10 = {}
    _app10mod.load_config = lambda: _acfg10
    _app10mod.update_config = lambda fn: fn(_acfg10)
    _app10mod._set_autoblock_host(5, True)
    _app10mod._set_autoblock_host(3, True)
    _app10mod._set_autoblock_host(5, False)
    check("app autoblock hosts: toggling writes a sorted list of the hosts that have it on",
          _acfg10.get("autoblock_hosts") == [3] and _app10mod._autoblock_hosts() == {3},
          repr(_acfg10.get("autoblock_hosts")))
    _wl_ok10 = _app10mod._security_whitelist_add(" 203.0.113.7 ")
    _wl_zone10 = _app10mod._security_whitelist_add("fe80::1%eth0\n[sshd]")
    _wl_zone_only10 = _app10mod._security_whitelist_add("fe80::1%eth0")
    _wl_net10 = _app10mod._security_whitelist_add("198.51.100.0/24")
    check("app whitelist: an address is stored canonical; a zone id (a line break in a jail file) "
          "is refused", _wl_ok10 == "203.0.113.7" and _wl_zone10 is None
          and _wl_zone_only10 is None
          and _acfg10["security_whitelist"] == ["198.51.100.0/24", "203.0.113.7"],
          repr(_acfg10.get("security_whitelist")))
    _wl_rm10 = _app10mod._security_whitelist_remove("203.0.113.7")
    _wl_rm_raw10 = _app10mod._security_whitelist_remove("  not-an-ip  ")
    _app10mod._security_whitelist_add("2001:db8::1")
    _wl_rm_v6_10 = _app10mod._security_whitelist_remove("2001:DB8:0::1")   # typed differently
    check("app whitelist: removal takes the canonical form, or the raw text for a stale entry",
          _wl_rm10 == "203.0.113.7" and _wl_rm_raw10 == "not-an-ip" and _wl_rm_v6_10 == "2001:db8::1"
          and _app10mod._security_whitelist() == ["198.51.100.0/24"],
          repr(_acfg10.get("security_whitelist")))

    _acfg10.update({"security_whitelist": ["198.51.100.0/24"], "port": 8443})
    _f2b_seen10 = []
    _so10.ensure_panel_host_whitelist = lambda wl: (_f2b_seen10.append(("host", list(wl)))
                                                    or (False, "no sshd jail"))
    _so10.ensure_panel_fail2ban = lambda path, port, wl: (_f2b_seen10.append(("panel", port, list(wl)))
                                                          or (True, "jail ok"))
    _awf10 = _app10mod._apply_whitelist_to_fail2ban()
    _so10.ensure_panel_host_whitelist = _raiser10(OSError("fail2ban missing"))
    _so10.ensure_panel_fail2ban = _raiser10(OSError("fail2ban missing"))
    _awf_bad10 = _app10mod._apply_whitelist_to_fail2ban()
    for _k10, _v10 in _app_so_saved10.items():
        setattr(_so10, _k10, _v10)
    check("app fail2ban whitelist: every jail gets the list, and the panel jail its port — a "
          "failure on the host's other jails does not stop the panel's",
          _awf10 == (True, "jail ok") and _f2b_seen10 == [("host", ["198.51.100.0/24"]),
                                                          ("panel", 8443, ["198.51.100.0/24"])],
          repr((_awf10, _f2b_seen10)))
    check("app fail2ban whitelist: when fail2ban cannot be updated, it says so",
          _awf_bad10 == (False, "could not update fail2ban"), repr(_awf_bad10))

    _ae_calls10 = []
    _app10mod._apply_whitelist_to_fail2ban = lambda: _ae_calls10.append("panel-jail")
    _app10mod._apply_whitelist_to_remotes = lambda app, unban_ip=None: _ae_calls10.append(
        ("remotes", unban_ip))
    _so10.fail2ban_unban_ip_everywhere = lambda ip: (_ae_calls10.append(("unban", ip)),
                                                     (_ for _ in ()).throw(OSError("jail gone")))
    _ae_r10 = _try10(_app10mod._apply_whitelist_everywhere, _dbapp10, unban_ip="203.0.113.9")
    _so10.fail2ban_unban_ip_everywhere = _app_so_saved10["fail2ban_unban_ip_everywhere"]
    _app_restore10("_apply_whitelist_to_fail2ban", "_apply_whitelist_to_remotes")
    check("app whitelist everywhere: the panel jail, then the local unban, then every remote — a "
          "failed unban does not stop the remotes",
          _ae_r10 is None and _ae_calls10 == ["panel-jail", ("unban", "203.0.113.9"),
                                              ("remotes", "203.0.113.9")], repr(_ae_calls10))

    _app10mod._autoblock_threshold = lambda: int(_acfg10.get("autoblock_threshold", 20))
    _thr_log10 = []
    _app10mod.log_action = lambda user, action, **kw: _thr_log10.append((action, kw.get("detail")))
    _app10mod.current_user = NS(id=1, username="admin")
    _thr_set10 = _app10mod._maybe_set_threshold({"threshold": "250"})
    _thr_lo10 = _app10mod._maybe_set_threshold({"threshold": 0})
    _thr_bad10 = _app10mod._maybe_set_threshold({"threshold": "many"})
    _thr_none10 = _app10mod._maybe_set_threshold({})
    _app_restore10("_autoblock_threshold", "log_action", "current_user")
    check("app autoblock threshold: a submitted value is clamped, saved and audited; junk or "
          "nothing changes nothing", (_thr_set10, _thr_lo10, _thr_bad10, _thr_none10) == (250, 1, 1, 1)
          and _thr_log10 == [("autoblock_threshold", "250 attempts / 7d"),
                             ("autoblock_threshold", "1 attempts / 7d")],
          repr((_thr_set10, _thr_lo10, _thr_bad10, _thr_none10, _thr_log10)))
    _app_restore10("load_config", "update_config")

    # ── the background loops: one pass each, a failing pass contained, then the right sleep ────
    _loop_calls10, _slept10 = [], []
    _app10mod.time = _Clock10(time.time(), sleep=_sleeper10(1, _slept10))
    _app10mod._refresh_player_counts = lambda app: (_loop_calls10.append(("players", app)),
                                                    (_ for _ in ()).throw(RuntimeError("x")))
    _pw10 = _try10(_app10mod._player_count_watch, _dbapp10)
    _app10mod._record_metric_samples = lambda app: (_loop_calls10.append("record"),
                                                    (_ for _ in ()).throw(RuntimeError("x")))
    _app10mod._prune_metric_samples = lambda app: (_loop_calls10.append("prune"),
                                                   (_ for _ in ()).throw(RuntimeError("x")))
    _app10mod.time = _Clock10(time.time(), sleep=_sleeper10(1, _slept10))
    _mw10 = _try10(_app10mod._metrics_history_watch, _dbapp10)
    _app10mod._node_tools_cron_pass = lambda app: (_loop_calls10.append("node-tools"),
                                                   (_ for _ in ()).throw(RuntimeError("x")))
    _app10mod.time = _Clock10(time.time(), sleep=_sleeper10(1, _slept10))
    _nw10 = _try10(_app10mod._node_tools_cron_watch, _dbapp10)
    _in_ctx10 = []
    _app10mod._monitor_pass = lambda: (_in_ctx10.append(__import__("flask").has_app_context()),
                                       (_ for _ in ()).throw(RuntimeError("x")))
    _mon_slept10 = []
    _app10mod.time = _Clock10(time.time(), sleep=_sleeper10(2, _mon_slept10))
    _monw10 = _try10(_app10mod._monitor_watch, _dbapp10)
    _app_restore10("time", "_refresh_player_counts", "_record_metric_samples",
                   "_prune_metric_samples", "_node_tools_cron_pass", "_monitor_pass")
    check("app loops: each background pass runs, survives its own failure, and sleeps its "
          "interval", all(r == ("RAISED", repr(_Stop10())) for r in (_pw10, _mw10, _nw10, _monw10))
          and _loop_calls10 == [("players", _dbapp10), "record", "prune", "node-tools"]
          and _slept10 == [_app10mod._PLAYER_POLL_SECONDS, _app10mod._METRIC_SAMPLE_SECONDS, 86400],
          repr((_loop_calls10, _slept10)))
    check("app loops: the monitor sleeps FIRST, then sweeps inside an app context",
          _mon_slept10 == [_app10mod._MONITOR_SECONDS] * 2 and _in_ctx10 == [True],
          repr((_mon_slept10, _in_ctx10)))

    # ── database-backed helpers ────────────────────────────────────────────────────────────────
    with _dbapp10.app_context():
        _reset_db10()
        _ea10 = _mk_remote10("east", host="192.0.2.50")
        _we10 = _mk_remote10("west", host="192.0.2.51")
        _lo_row10 = _mk_remote10("panel", host="127.0.0.1", is_local=True, auth_method="local")
        _css1_10 = _mk_gs10(_ea10, "css1", game_type="css", port=27015)
        _css2_10 = _mk_gs10(_ea10, "css2", game_type="css", port=27016)
        _css3_10 = _mk_gs10(_we10, "css3", game_type="css", port=27015)
        _gm10 = _mk_gs10(_we10, "gmodx", game_type="rust", port=28015)
        _css_off10 = _mk_gs10(_we10, "css4", game_type="css", port=27030, installed=False,
                              status="failed")
        _E10 = {"ea": _ea10.id, "we": _we10.id, "lo": _lo_row10.id, "css1": _css1_10.id,
                "css2": _css2_10.id, "css3": _css3_10.id, "gm": _gm10.id}

        # Source aux ports: move THIS instance's SourceTV/client off anything taken on the host.
        def _lgv10(remote, short, lgsm, keys):
            return {"css1": {"clientport": "27006", "sourcetvport": "27020"},
                    "css2": {"clientport": "27005", "sourcetvport": "27020"}}.get(short, {})

        _app10mod.lgsm_get_values = _lgv10
        _app10mod._remote_listening_ports = lambda r: {27005}
        _aux10 = _app10mod._resolve_source_aux_ports(_ea10, _E10["ea"], "css2", "cssserver", 27016)
        _app10mod.lgsm_get_values = lambda *a: {"maxplayers": "16"}
        _aux_none10 = _app10mod._resolve_source_aux_ports(_ea10, _E10["ea"], "css2", "cssserver",
                                                          27016)
        _app10mod.lgsm_get_values = lambda *a: None
        _aux_unread10 = _app10mod._resolve_source_aux_ports(_ea10, _E10["ea"], "css2",
                                                            "cssserver", 27016)
        _app10mod.lgsm_get_values = _raiser10(ConnectionError("down"))
        _aux_raise10 = _app10mod._resolve_source_aux_ports(_ea10, _E10["ea"], "css2",
                                                           "cssserver", 27016)
        check("app source ports: taken client/SourceTV ports move to the next free ones, avoiding "
              "a sibling's CONFIGURED ports even while it is stopped",
              _aux10 == {"clientport": "27007", "sourcetvport": "27021"}, repr(_aux10))
        check("app source ports: a non-Source game, an unreadable config or a failed read "
              "changes nothing", _aux_none10 == {} and _aux_unread10 == {} and _aux_raise10 == {},
              repr((_aux_none10, _aux_unread10, _aux_raise10)))
        _app10mod._remote_listening_ports = lambda r: set(range(27000, 28000))
        _app10mod.lgsm_get_values = lambda *a: {}
        _rfp10 = _app10mod.resolve_free_port(_ea10, _E10["ea"], 27015, "css")
        _app_restore10("lgsm_get_values", "_remote_listening_ports")
        check("app free port: with nothing free nearby the answer is None, never a taken port",
              _rfp10 == (None, False), repr(_rfp10))

        check("app selection: submitted ids resolve to rows, skipping junk, unknown and repeats",
              [r.name for r in _app10mod._selected_remotes(
                  [str(_E10["ea"]), "x", str(_E10["ea"]), "99999", None])] == ["east"]
              and [g.short_name for g in _app10mod._selected_game_servers(
                  [_E10["css3"], "junk", _E10["css3"], 424242])] == ["css3"], "")

        # Global SteamID bans: every INSTALLED valve server, and an audit row of what happened.
        _bans_sent10 = []

        def _ban10(remote, short, lgsm, steamid, unban=False):
            _bans_sent10.append((short, steamid, unban))
            if short == "css3":
                raise ConnectionError("host down")
            return (True, "banned") if short == "css1" else (False, "offline")

        _app10mod.ensure_persistent_bans = lambda remote, short, lgsm: None
        _app10mod.console_steamid_ban = _ban10
        _app10mod._fan_out_global_ban(_dbapp10, "STEAM_0:1:42")
        _app10mod._fan_out_global_ban(_dbapp10, "STEAM_0:1:42", unban=True)
        _db10.session.add_all([_GBan10(steamid="STEAM_0:0:1"), _GBan10(steamid="[U:1:2]")])
        _db10.session.commit()
        _bans_sent10[:] = []
        _app10mod.ensure_persistent_bans = _raiser10(ConnectionError("cfg unreadable"))
        _app10mod._sync_global_bans(_dbapp10)
        _sync_sent10 = sorted(_bans_sent10)
        _GBan10.query.delete()
        _db10.session.commit()
        _app10mod._sync_global_bans(_dbapp10)
        _app10mod.log_action = _raiser10(RuntimeError("audit table locked"))
        _lbf10 = _try10(_app10mod._log_ban_fanout, "global_ban_apply", "S", ["a"], [], [])
        _app_restore10("ensure_persistent_bans", "console_steamid_ban", "log_action")
        _db10.session.expire_all()
        _ban_rows10 = [(a.action, a.target, a.detail, a.success) for a in
                       _Audit10.query.filter(_Audit10.action.like("global_ban%")).order_by(_Audit10.id)]
        check("app global ban: every installed valve server is asked — not other engines, not a "
              "failed install", sorted({s for s, _i, _u in _sync_sent10}) == ["css1", "css2", "css3"]
              and len(_sync_sent10) == 6, repr(_sync_sent10))
        check("app global ban: the audit row says what ACTUALLY happened, per outcome",
              _ban_rows10[:2] == [
                  ("global_ban_apply", "STEAM_0:1:42",
                   "1 applied; 1 not running (css2); 1 failed (css3)", False),
                  ("global_ban_lift", "STEAM_0:1:42",
                   "1 applied; 1 not running (css2); 1 failed (css3)", False)],
              repr(_ban_rows10))
        check("app global ban: a sync covers every ban on every server, even when the persistent "
              "setup fails; an empty list writes no row",
              _ban_rows10[2:] == [("global_ban_sync", "2 ban(s)",
                                   "2 applied; 2 not running (css2/STEAM_0:0:1, css2/[U:1:2]); "
                                   "2 failed (css3/STEAM_0:0:1, css3/[U:1:2])", False)],
              repr(_ban_rows10[2:]))
        check("app global ban: an audit write that fails is contained", _lbf10 is None, repr(_lbf10))

        # Whitelist to every REMOTE (never the panel host itself); one failing host is skipped.
        _ign10 = []

        def _ignore10(remote, wl, unban_ip=None):
            _ign10.append((remote.name, list(wl), unban_ip))
            if remote.name == "east":
                raise ConnectionError("down")

        _app10mod.load_config = lambda: {"security_whitelist": ["203.0.113.0/24"]}
        _app10mod.remote_set_fail2ban_ignoreip = _ignore10
        _awr10 = _try10(_app10mod._apply_whitelist_to_remotes, _dbapp10, unban_ip="203.0.113.4")
        _app_restore10("load_config", "remote_set_fail2ban_ignoreip")
        check("app whitelist remotes: every remote is updated (not the panel host), past a failure",
              _awr10 is None and sorted(n for n, _w, _u in _ign10) == ["east", "west"]
              and all(w == ["203.0.113.0/24"] and u == "203.0.113.4" for _n, w, u in _ign10),
              repr(_ign10))

        # node-tools cron pass: every host, then every server's cron — one failure stops nothing.
        _nt10 = []
        _app10mod.ensure_node_tools_cron = lambda r: (
            _nt10.append(("host", r.name)),
            (_ for _ in ()).throw(ConnectionError("down")) if r.name == "east" else None)
        _smcron10.upgrade_managed_cron_tracking = lambda remote, short, lgsm, game_type=None, port=None: (
            _nt10.append(("cron", short, game_type, port)),
            (_ for _ in ()).throw(RuntimeError("x")) if short == "css1" else None)
        try:
            _ntr10 = _try10(_app10mod._node_tools_cron_pass, _dbapp10)
        finally:
            _smcron10.upgrade_managed_cron_tracking = _app_cron_up10
            _app_restore10("ensure_node_tools_cron")
        check("app node-tools pass: every host gets the cron and every server its upgrade, past "
              "failures", _ntr10 is None
              and sorted(x[1] for x in _nt10 if x[0] == "host") == ["east", "panel", "west"]
              and ("cron", "css3", "css", 27015) in _nt10
              and len([x for x in _nt10 if x[0] == "cron"]) == 5, repr(_nt10))

        # Autoblock: the immediate run (a thread) and the hourly watcher.
        _abn_done10, _abn10 = threading.Event(), []

        def _abr_now10(remote):
            _abn10.append(remote.name)
            _abn_done10.set()
            raise RuntimeError("ufw exploded")

        _app10mod._autoblock_reconcile = _abr_now10
        _app10mod._run_autoblock_now(_dbapp10, 424242)          # a host that does not exist
        _app10mod._run_autoblock_now(_dbapp10, _E10["we"])
        _abn_done10.wait(5)
        time.sleep(0.05)
        check("app autoblock now: the named host is reconciled in the background (and a failure "
              "there is contained); an unknown id does nothing", _abn10 == ["west"], repr(_abn10))

        _abw_hosts10 = [set(), {_E10["ea"], 424242, _E10["we"], _E10["lo"]}]
        _app10mod._autoblock_hosts = lambda: _abw_hosts10.pop(0) if _abw_hosts10 else set()
        _app10mod._autoblock_reconcile = lambda r: (
            (2, 1) if r.name == "east" else (0, 0) if r.name == "panel"      # nothing to change
            else (_ for _ in ()).throw(RuntimeError("x")))
        _abw_slept10 = []
        _app10mod.time = _Clock10(time.time(), sleep=_sleeper10(3, _abw_slept10))
        _abw10 = _try10(_app10mod._autoblock_watch, _dbapp10)
        _app_restore10("time", "_autoblock_hosts", "_autoblock_reconcile")
        _abw_rows10 = [(a.target, a.detail, a.username) for a in
                       _Audit10.query.filter_by(action="autoblock_reconcile")]
        check("app autoblock watch: hourly, every enabled host that exists, with an audit row of "
              "what changed", _abw10 == ("RAISED", repr(_Stop10()))
              and _abw_slept10 == [3600, 3600, 3600]
              and _abw_rows10 == [("east", "+2 blocked, -1 released", "system")], repr(_abw_rows10))

        # Metric retention: old rows pruned, at most every 30 minutes.
        _old_ts10 = _utcnow10() - _dt10.timedelta(days=_app10mod._METRIC_RETENTION_DAYS + 1)
        _db10.session.add_all([_MS10(server_id=1, ts=_old_ts10), _MS10(server_id=1),
                               _HS10(remote_id=1, ts=_old_ts10), _HS10(remote_id=1)])
        _db10.session.commit()
        _pstate10._last_sample_prune[0] = 0.0
        _app10mod._prune_metric_samples(_dbapp10)
        _after10 = (_MS10.query.count(), _HS10.query.count())
        _db10.session.add(_MS10(server_id=2, ts=_old_ts10))
        _db10.session.commit()
        _app10mod._prune_metric_samples(_dbapp10)
        check("app history prune: samples past the retention window go, recent ones stay — and "
              "not again within 30 minutes", _after10 == (1, 1) and _MS10.query.count() == 2,
              repr((_after10, _MS10.query.count())))

        # Admin brute-force: only a SUPER ADMIN's name, only past the threshold, once per window.
        _db10.session.add_all([_User10(username="boss", password_hash="x", is_superadmin=True),
                               _User10(username="pleb", password_hash="x"),
                               _User10(username="boss2", password_hash="x", is_superadmin=True)])
        for _i10 in range(5):
            _db10.session.add(_Audit10(username="boss", action="login_failed"))
            _db10.session.add(_Audit10(username="pleb", action="login_failed"))
        for _i10 in range(4):
            _db10.session.add(_Audit10(username="boss2", action="login_failed"))
        _db10.session.commit()
        _bf10 = []
        _app10mod.notifications = NS(notify=lambda k, t, b="": _bf10.append((k, b)))
        _app10mod._ADMIN_BF_NOTIFIED.pop("boss", None)
        for _who10 in ("boss", "boss", "pleb", "boss2", "(blank)", "nobody"):
            _app10mod._maybe_alert_admin_bruteforce(_who10, "203.0.113.66", time.time())
        _app_restore10("notifications")
        check("app brute-force: 5 failed logins on a super admin alert ONCE; a normal user, a "
              "super admin under the threshold and an unknown name never do",
              _bf10 == [("admin_bruteforce",
                         "5 failed logins for super admin 'boss' from 203.0.113.66 in the last 5 min.")],
              repr(_bf10))

        # Session bookkeeping: a row per login, and a failed write is not a failed login.
        _su10 = _User10.query.filter_by(username="boss").first()
        with _dbapp10.test_request_context("/login", headers={"User-Agent": "UA/1.0",
                                                              "Cookie": "remember_token=abc"},
                                           environ_base={"REMOTE_ADDR": "203.0.113.9"}):
            _sid10 = _app10mod._register_session(_su10)
            _app10mod.db = NS(session=NS(add=lambda row: None,
                                         commit=_raiser10(RuntimeError("database is locked")),
                                         rollback=_db10.session.rollback))
            _su2_10 = NS(id=_su10.id)
            _sid_fail10 = _app10mod._register_session(_su2_10, remember=False)
            _app_restore10("db")
        _srow10 = _USess10.query.filter_by(sid=_sid10 or "-").first()
        check("app sessions: a login records its sid, device and IP, and a remember-me cookie makes "
              "it a long-lived row", bool(_sid10) and getattr(_su10, "_sid", None) == _sid10
              and _srow10 is not None and _srow10.remember is True
              and _srow10.user_agent == "UA/1.0" and _srow10.ip == "203.0.113.9",
              repr((_sid10, _srow10 and (_srow10.remember, _srow10.ip))))
        check("app sessions: a session row that cannot be written returns None and the login goes on",
              _sid_fail10 is None and not hasattr(_su2_10, "_sid"), repr(_sid_fail10))

        # Setup-wizard ownership.
        _app10mod.current_user = _RaisingUser10()
        with _dbapp10.test_request_context("/setup"):
            __import__("flask").session["_setup_owner"] = "tok-123"
            _db10.session.add(_Setup10(data="not json at all"))
            _db10.session.commit()
            _own_bad10 = _app10mod._setup_owner_ok()
            _st10 = _Setup10.query.first()
            _st10.data = _json10.dumps({"owner": _app10mod._setup_owner_hash("tok-123")})
            _db10.session.commit()
            _own_ok10 = _app10mod._setup_owner_ok()
            __import__("flask").session["_setup_owner"] = "someone-else"
            _own_other10 = _app10mod._setup_owner_ok()
        _app_restore10("current_user")
        check("app setup owner: with an admin created, only the browser that created it may go on "
              "— an unreadable wizard state denies rather than opens",
              (_own_bad10, _own_ok10, _own_other10) == (False, True, False),
              repr((_own_bad10, _own_ok10, _own_other10)))

        # Mod restart advice, and the stale flag it clears.
        _css1db10 = _db10.session.get(_GS10, _E10["css1"])
        _css1db10.restart_pending = True
        _db10.session.commit()
        _app10mod.get_server_status = lambda r, gs: "offline"
        _mr_off10 = _app10mod._apply_mod_restart(_css1db10, _ea10)
        _app10mod.get_server_status = lambda r, gs: "online"
        _mr_on10 = _app10mod._apply_mod_restart(_css1db10, _ea10)
        _app10mod.get_server_status = _raiser10(ConnectionError("down"))
        _mr_unk10 = _app10mod._apply_mod_restart(_css1db10, _ea10)
        _app_restore10("get_server_status")
        _db10.session.expire_all()
        check("app mod restart: a stopped server needs nothing (and a stale restart flag is "
              "cleared); a running or unreadable one is told to restart — never restarted for it",
              _mr_off10[0] == "idle" and _mr_on10[0] == "needed" and _mr_unk10[0] == "needed"
              and _db10.session.get(_GS10, _E10["css1"]).restart_pending is False,
              repr((_mr_off10[0], _mr_on10[0], _mr_unk10[0])))

        # Custom command form + group assignment.
        with _dbapp10.test_request_context("/c", method="POST", data={
                "name": "Map", "command_template": "changelevel {}", "scope": "engine|bogus"}):
            _cf_bad10 = _app10mod._custom_cmd_form()
        with _dbapp10.test_request_context("/c", method="POST", data={
                "name": "Say", "command_template": "say " + "x" * 600, "scope": "all|"}):
            _cf_long10 = _app10mod._custom_cmd_form()
        with _dbapp10.test_request_context("/c", method="POST", data={
                "name": "Map", "command_template": "changelevel {}", "scope": "engine|valve",
                "enabled": "on"}):
            _cf_ok10 = _app10mod._custom_cmd_form()
        with _dbapp10.test_request_context("/c", method="POST", data={
                "name": "Say", "command_template": "say hi", "scope": "planet|mars"}):
            _cf_scope10 = _app10mod._custom_cmd_form()
        check("app custom command: an unknown engine and an over-long template are refused with a "
              "reason; a valid form comes back as fields",
              _cf_bad10[0] is None and "valid engine" in _cf_bad10[1]
              and _cf_long10[0] is None and "too long" in _cf_long10[1]
              and _cf_ok10 == ({"name": "Map", "command_template": "changelevel {}",
                                "argument_label": "", "argument_pattern": "",
                                "scope_type": "engine", "scope_value": "valve", "enabled": True},
                               None), repr((_cf_bad10, _cf_long10[1], _cf_ok10)))
        check("app custom command: an unknown scope TYPE falls back to every server, value dropped",
              _cf_scope10[1] is None and _cf_scope10[0]["scope_type"] == "all"
              and _cf_scope10[0]["scope_value"] == "" and _cf_scope10[0]["enabled"] is False,
              repr(_cf_scope10))
        _grp_a10, _grp_b10 = _Group10(name="mods"), _Group10(name="admins")
        _db10.session.add_all([_grp_a10, _grp_b10])
        _db10.session.commit()
        _cmd10 = NS(groups=None)
        with _dbapp10.test_request_context("/c", method="POST",
                                           data={"groups": [str(_grp_a10.id), "junk"]}):
            _app10mod._assign_command_groups(_cmd10)
        _cmd_none10 = NS(groups="unset")
        with _dbapp10.test_request_context("/c", method="POST", data={}):
            _app10mod._assign_command_groups(_cmd_none10)
        check("app custom command: exactly the ticked groups (junk ignored); none ticked is none",
              [g.name for g in _cmd10.groups] == ["mods"] and _cmd_none10.groups == [],
              repr((_cmd10.groups, _cmd_none10.groups)))

        # Ubuntu Pro status cache: fresh serves the stored value; a failed read never replaces it.
        _pro_calls10 = []
        _app10mod.pro_status = lambda r, force=False: (_pro_calls10.append(force)
                                                       or dict(_pro_next10))
        _pro_saved10 = []
        _pro_fresh10 = NS(cached_pro={"data": {"attached": True}, "ts": time.time()},
                          update_pro_cache=lambda d: _pro_saved10.append(d))
        _pro_next10 = {"attached": False}
        _p_fresh10 = _app10mod._pro_status_cached(_pro_fresh10)
        _pro_n_fresh10 = (len(_pro_calls10), len(_pro_saved10))
        _pro_stale10 = NS(cached_pro={"data": {"attached": True}, "ts": 0},
                          update_pro_cache=_raiser10(RuntimeError("db locked")))
        _p_new10 = _app10mod._pro_status_cached(_pro_stale10)
        _pro_next10 = {"unreadable": True}
        _p_unread10 = _app10mod._pro_status_cached(_pro_stale10)
        _pro_next10 = {"attached": True, "services": ["esm-infra"]}
        _pro_ok10 = NS(cached_pro=None, update_pro_cache=lambda d: _pro_saved10.append(d))
        _p_saved10 = _app10mod._pro_status_cached(_pro_ok10, force=True)
        _app_restore10("pro_status")
        check("app pro cache: a good read is stored for next time and returned",
              _p_saved10 == {"attached": True, "services": ["esm-infra"]}
              and _pro_saved10 == [_p_saved10] and _pro_calls10[-1] is True,
              repr((_p_saved10, _pro_saved10)))
        check("app pro cache: a fresh stored status is served without running the slow client",
              _p_fresh10 == {"attached": True} and _pro_n_fresh10 == (0, 0),
              repr((_p_fresh10, _pro_calls10)))
        check("app pro cache: a stale one is re-read (a failed save does not lose the answer); an "
              "UNREADABLE re-read hands back the last known value, marked stale",
              _p_new10 == {"attached": False}
              and _p_unread10 == {"attached": True, "unreadable": True, "stale": True},
              repr((_p_new10, _p_unread10)))

        # OS update checks: unreachable and failed checks are None, never "up to date".
        _app10mod._host_reachable = lambda r: False
        _osu_unr10 = _app10mod._os_updates_for(_ea10)
        _app10mod._host_reachable = lambda r: True
        _smhosts10.remote_os_check_updates = _raiser10(ConnectionError("apt locked"))
        _osu_err10 = _app10mod._os_updates_for(_ea10)
        _smhosts10.remote_os_check_updates = lambda r: {"ok": False, "packages": []}
        _osu_fail10 = _app10mod._os_updates_for(_ea10)
        _smhosts10.remote_os_check_updates = lambda r: {"ok": True, "packages": [{"name": "curl"}]}
        _osu_ok10 = _app10mod._os_updates_for(_ea10)
        _smhosts10.remote_os_check_updates = _raiser10(AssertionError("asked the panel host over SSH"))
        _so10.os_update_available = lambda refresh=False: {"ok": True, "packages": [], "refresh": refresh}
        _osu_local10 = _app10mod._os_updates_for(_db10.session.get(_RS10, _E10["lo"]))
        _so10.os_update_available = _app_so_saved10["os_update_available"]
        _smhosts10.remote_os_check_updates = _app_osck10
        _app_restore10("_host_reachable")
        check("app os updates: the panel host is checked locally, with a fresh apt read",
              _osu_local10 == {"ok": True, "packages": [], "refresh": True}, repr(_osu_local10))
        check("app os updates: an unreachable host, a raise and a failed check are all None",
              _osu_unr10 is None and _osu_err10 is None and _osu_fail10 is None
              and _osu_ok10 == {"ok": True, "packages": [{"name": "curl"}]},
              repr((_osu_unr10, _osu_err10, _osu_fail10)))

        # Is the game running at all? A failed read is None, not "stopped".
        _lrs_hits10 = []

        def _slm_down10(remote, short, port, force=False):
            _lrs_hits10.append(short)
            raise ConnectionError("down")

        _sm_core.server_live_metrics = _slm_down10
        _lrs10 = _app10mod._live_run_state(_css1db10, _ea10)
        _sm_core.server_live_metrics = _app_slm10
        check("app run state: a metrics read that raises is None (unknown), never False — and it "
              "was THIS read that raised", _lrs10 is None and _lrs_hits10 == ["css1"],
              repr((_lrs10, _lrs_hits10)))
        # The other failed read: an SSH blip answers the all-zero default sample, not a raise.
        _sm_core.server_live_metrics = lambda *a, **k: {"ram_total": 0, "port_open": False,
                                                        "game_procs": 0}
        _lrs_zero10 = _app10mod._live_run_state(_css1db10, _ea10)
        _sm_core.server_live_metrics = _app_slm10
        check("app run state: an all-zero sample (a read that failed quietly) is None, not stopped",
              _lrs_zero10 is None, repr(_lrs_zero10))

        # Template filters, the language picker and the static asset URL.
        _app10mod.register_template_filters(_dbapp10)
        _fdt10 = _dbapp10.jinja_env.filters["datetime"]
        _fdt_out10 = str(_fdt10(_dt10.datetime(2026, 9, 26, 7, 5, 9, 123)))
        check("app datetime filter: nothing is 'Never'; a time is UTC-tagged for the browser",
              _fdt10(None) == "Never"
              and 'data-utc="2026-09-26T07:05:09Z"' in _fdt_out10 and "2026-09-26 07:05:09 UTC" in _fdt_out10,
              _fdt_out10)
        _app10mod.current_user = _RaisingUser10()
        with _dbapp10.test_request_context("/"):
            __import__("flask").session["lang"] = "fr"
            _lang_sess10 = _app10mod._current_lang()
        _lang_none10 = _app10mod._current_lang()
        _app_restore10("current_user")
        check("app language: an unreadable user falls back to the session's choice, and no request "
              "at all to English", _lang_sess10 == "fr" and _lang_none10 == "en",
              repr((_lang_sess10, _lang_none10)))
        with _dbapp10.test_request_context("/"):
            _au10 = _app10mod._asset_url(_dbapp10, "no-such-asset-part13.css")
        check("app asset url: a missing file still gets a plain URL (and its 404), no ?v=",
              _au10.endswith("/static/no-such-asset-part13.css") and "?v=" not in _au10, _au10)

        # The context processor: a failing permission lookup hides the host nav rather than
        # breaking every page; with permission it lists only the hosts this admin's groups grant.
        _app10mod.register_context_processors(_dbapp10)
        _ctx_fn10 = [f for f in _dbapp10.template_context_processors[None]
                     if getattr(f, "__name__", "") == "inject_globals"][-1]
        _tsi10.get_tailscale_info = _raiser10(RuntimeError("tailscaled down"))
        _app10mod.load_config = lambda: {}
        _app10mod.current_user = NS(is_authenticated=True, is_superadmin=False,
                                    must_change_password=False, language="en")
        _app10mod.get_user_permissions = _raiser10(RuntimeError("group table locked"))
        with _dbapp10.test_request_context("/"):
            _ctx_bad10 = _ctx_fn10()
        _app10mod.get_user_permissions = lambda u: {"manage_remotes"}
        _app10mod.accessible_remote_ids = lambda u: {_E10["we"]}
        with _dbapp10.test_request_context("/"):
            _ctx_ok10 = _ctx_fn10()
        _tsi10.get_tailscale_info = _core_tsinfo10
        _app_restore10("load_config", "current_user", "get_user_permissions",
                       "accessible_remote_ids")
        check("app page context: a failed permission read shows no host nav and no banner, and "
              "Tailscale being down is just no Tailscale link",
              _ctx_bad10["nav_remotes"] == [] and _ctx_bad10["local_remote_id"] is None
              and _ctx_bad10["tailscale_url"] is None and _ctx_bad10["show_app_chrome"] is True,
              repr({k: _ctx_bad10[k] for k in ("nav_remotes", "local_remote_id", "tailscale_url")}))
        check("app page context: a delegated host admin sees only the hosts their groups grant",
              [r.name for r in _ctx_ok10["nav_remotes"]] == ["west"]
              and _ctx_ok10["local_remote_id"] is None,
              repr([r.name for r in _ctx_ok10["nav_remotes"]]))
        _db10.session.remove()

    # The brute-force check runs on the login path: with no database to ask it must stay quiet
    # rather than fail the login response.
    _bf_off10 = []
    _app10mod.notifications = NS(notify=lambda *a: _bf_off10.append(a))
    _bf_noctx10 = _try10(_app10mod._maybe_alert_admin_bruteforce, "boss", "203.0.113.66", time.time())
    _app_restore10("notifications")
    check("app brute-force: a check that cannot reach the database is contained and alerts nothing",
          _bf_noctx10 is None and _bf_off10 == [], repr((_bf_noctx10, _bf_off10)))

    # ── auth.log: attached once, to the file fail2ban reads, and never fatal ───────────────────
    _alog_dir10 = _tmp10.mkdtemp(prefix="panel-authlog10-")
    for _h10 in [h for h in _app10mod._authlog.handlers if getattr(h, "_panel_auth", False)]:
        _app10mod._authlog.removeHandler(_h10)
    _app10mod.AUTH_LOG_PATH = os.path.join(_alog_dir10, "auth.log")
    _app10mod._setup_auth_log()
    _app10mod._setup_auth_log()
    _mine10 = [h for h in _app10mod._authlog.handlers if getattr(h, "_panel_auth", False)]
    _app10mod._authlog.info("login failed for x from 203.0.113.5")
    for _h10 in _mine10:
        _h10.flush()
        _h10.close()
        _app10mod._authlog.removeHandler(_h10)
    _alog_text10 = open(os.path.join(_alog_dir10, "auth.log")).read()
    _app10mod.AUTH_LOG_PATH = os.path.join(_alog_dir10, "no", "such", "dir", "auth.log")
    _alog_bad10 = _try10(_app10mod._setup_auth_log)
    _bad_handlers10 = [h for h in _app10mod._authlog.handlers if getattr(h, "_panel_auth", False)]
    _shutil10.rmtree(_alog_dir10, ignore_errors=True)
    check("app auth log: ONE handler however often it is set up, writing the line fail2ban reads",
          len(_mine10) == 1 and "login failed for x from 203.0.113.5" in _alog_text10
          and _app10mod._authlog.propagate is False, repr(_alog_text10[-120:]))
    check("app auth log: a log that cannot be opened is skipped, never a failed login",
          _alog_bad10 is None and _bad_handlers10 == [], repr(_alog_bad10))
    check("app: nothing in this section reached a real SSH or local transport",
          _trip10 == [], repr(_trip10))
finally:
    _disarm10(_app_trip_saved10)
    _app_restore10()
    for _k10, _v10 in _app_so_saved10.items():
        setattr(_so10, _k10, _v10)
    for _k10, _v10 in _app_dicts10.items():
        _d10 = getattr(_app10mod, _k10)
        _d10.clear()
        _d10.update(_v10)
    _smcron10.upgrade_managed_cron_tracking = _app_cron_up10
    _smhosts10.remote_os_check_updates = _app_osck10
    _sm_core.server_live_metrics = _app_slm10
    _tsi10.suggest_best_bind = _app_suggest10
    _tsi10.get_tailscale_info = _core_tsinfo10
    for _h10 in list(_app10mod._authlog.handlers):
        if _h10 not in _app_authlog_state10[0]:
            _app10mod._authlog.removeHandler(_h10)
    for _h10 in _app_authlog_state10[0]:
        if _h10 not in _app10mod._authlog.handlers:
            _app10mod._authlog.addHandler(_h10)
    _app10mod._authlog.setLevel(_app_authlog_state10[1])
    _app10mod._authlog.propagate = _app_authlog_state10[2]
    _restore_pstate10()


# ══════════════════════════════════════════════════════════════════════════════════════════════
# F. app.py — create_app's one-time boot steps and response hooks, and the loops register_routes
#    hands to its supervisor
# ══════════════════════════════════════════════════════════════════════════════════════════════
# create_app runs here for REAL, twice, against a throwaway data dir. config.json, secret_key and
# cred_key are already the runner's (tests/unit_test.py); DB_PATH, DATA_DIR and the auth log are
# pointed into a temp dir below — both where app.py holds them and where panel.core.config does,
# because _ensure_db_healthy and harden_data_permissions read config's. No thread starts:
# app.threading's Thread only records its target, so each loop the supervisor would run can be
# taken out and run for a single pass. The checkout's own data/panel.db must not appear.
import gzip as _gzip13  # noqa: E402
import logging as _logging13  # noqa: E402
import inspect as _inspect13  # noqa: E402
import sqlite3 as _sqlite13  # noqa: E402
from datetime import timedelta as _td13  # noqa: E402
from pathlib import Path as _Path13  # noqa: E402

from flask import Response as _Resp13, abort as _abort13, request as _req13  # noqa: E402

from panel.db import models as _models13  # noqa: E402
from panel.ops import socket_hooks as _hooks13  # noqa: E402
from panel.routes import _shared as _shared13  # noqa: E402
from panel.security import banlist as _banlist13  # noqa: E402

_CA13_LIVE_DB = str(_cfgmod10.DB_PATH)
_CA13_LIVE_DB_EXISTED = os.path.exists(_CA13_LIVE_DB)
_CA13_DIR = _Path13(_tmp10.mkdtemp(prefix="lgsm-unit-p13-app-")) / "data"
_CA13_DIR.mkdir()
_CA13_DB = _CA13_DIR / "panel.db"
_CA13_CFG_SNAP = (_cfgmod10.CONFIG_FILE.read_bytes() if _cfgmod10.CONFIG_FILE.exists() else None)
# (owner, attribute) -> the value before this section touched it; put back in the finally.
_CA13_SAVED = {}
_CA13_SHARED = ("_looks_installed", "_notify_servers_changed", "_run_due_game_backups",
                "_run_due_restarts", "_run_pending_backups")
# What the loops' collaborators do in the pass under test: each entry is set by that check.
_TK13 = {"looks": {}, "calls": [], "fail_from": {}}


def _ca13_set(owner, name, value):
    """Replace owner.name for this section, remembering the original the first time."""
    _CA13_SAVED.setdefault((owner, name), getattr(owner, name))
    setattr(owner, name, value)


def _ca13_restore():
    """Put back every attribute _ca13_set replaced."""
    for (owner, name), value in _CA13_SAVED.items():
        setattr(owner, name, value)
    _CA13_SAVED.clear()


def _tk13_rec(label, *args):
    """Record a collaborator call, and raise from the call the check scripted `label` to fail on."""
    _TK13["calls"].append((label,) + args)
    if sum(1 for c in _TK13["calls"] if c[0] == label) >= _TK13["fail_from"].get(label, 1 << 30):
        raise RuntimeError("%s failed" % label)


def _tk13_looks(app, remote, short, lgsm):
    """Stand-in for _shared._looks_installed: the verdict the check scripted for `short`."""
    _TK13["calls"].append(("looks", short, lgsm))
    verdict = _TK13["looks"].get(short)
    if isinstance(verdict, Exception):
        raise verdict
    return verdict


_TK13_STUBS = {
    "_looks_installed": _tk13_looks,
    "_notify_servers_changed": lambda app: _tk13_rec("notify", app),
    "_run_due_game_backups": lambda app: _tk13_rec("due-backups", app),
    "_run_due_restarts": lambda app: _tk13_rec("due-restarts", app),
    "_run_pending_backups": lambda app: _tk13_rec("pending-backups", app),
}


class _TkRecThread13:
    """A Thread for create_app that records its target and never starts it."""

    started = []

    def __init__(self, target=None, daemon=None, args=(), kwargs=None, name=None):
        self.target, self.daemon = target, daemon

    def start(self):
        """Remember the target instead of running it."""
        _TkRecThread13.started.append(self.target)

    def join(self, timeout=None):
        """Nothing was started, so there is nothing to wait for."""
        return None


class _TkInlineThread13(_TkRecThread13):
    """A Thread whose start() runs the target inline; the target ending on _Stop10 is its exit."""

    def start(self):
        """Run the target now, as the supervised worker would, until it stops."""
        _TK13["calls"].append(("thread", self.daemon))
        try:
            self.target()
        except _Stop10:
            _TK13["calls"].append(("thread-exited",))


def _tk13_threading(thread_cls):
    """The real threading module, with Thread replaced by `thread_cls`."""
    return NS(Thread=thread_cls, Lock=threading.Lock, RLock=threading.RLock,
              local=threading.local, Event=threading.Event,
              current_thread=threading.current_thread)


def _tk13_loops(runners):
    """Map each recorded supervisor runner to {name: (runner, loop)} via its closure."""
    out = {}
    for runner in runners:
        nonlocals = _inspect13.getclosurevars(runner).nonlocals
        if "name" in nonlocals and "target" in nonlocals:
            out[nonlocals["name"]] = (runner, nonlocals["target"])
    return out


def _ca13_config(**over):
    """Write config.json for the next boot: setup done, plus `over`."""
    cfg = dict(_cfgmod10.DEFAULT_CONFIG, setup_complete=True)
    cfg.update(over)
    _cfgmod10.CONFIG_FILE.write_text(_json10.dumps(cfg))


def _ca13_seed_rows(now):
    """Rows for the boot's one-time steps: legacy plaintext, a stale grant, aged audit rows."""
    db = _models13.db
    db.session.add(_models13.SetupState(step="complete", complete=True))
    for name, method, cred in (("pw-host", "password", "hunter2"),
                               ("key-host", "key", _CA13_KEY_CT),
                               ("ts-host", "tailscale", "tskey-left-alone")):
        db.session.add(_models13.RemoteServer(name=name, host="192.0.2.30", username="root",
                                              auth_method=method, auth_credential=cred))
    db.session.add(_models13.User(username="legacy", password_hash="x", email="ops@example.com"))
    db.session.add(_models13.Group(name="legacy-grant",
                                   permissions='["view_servers", "super_admin"]'))
    old = now - _td13(days=60)
    db.session.add_all([_models13.AuditLog(action="old", ip_address="203.0.113.1", timestamp=old)
                        for _ in range(120)])
    db.session.add(_models13.AuditLog(action="aged", ip_address="203.0.113.77",
                                      timestamp=now - _td13(days=10)))
    db.session.add(_models13.AuditLog(action="recent", ip_address="203.0.113.78",
                                      timestamp=now - _td13(hours=1)))
    db.session.commit()


def _ca13_seed():
    """Create the throwaway panel.db with the models' schema and the rows boot will migrate."""
    seed = _Flask10("unit_part13_seed")
    seed.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///%s" % _CA13_DB,
                       SQLALCHEMY_TRACK_MODIFICATIONS=False)
    _models13.db.init_app(seed)
    with seed.app_context():
        _models13.db.create_all()
        _ca13_seed_rows(_utcnow10())
        _models13.db.session.remove()
        _models13.db.engine.dispose()
    # One host name written back as PLAINTEXT, past the column type, as a pre-encryption install
    # left it — the at-rest migration's job.
    con = _sqlite13.connect(str(_CA13_DB))
    try:
        con.execute("UPDATE remote_server SET host='10.9.8.7' WHERE name='pw-host'")
        con.commit()
    finally:
        con.close()


def _ca13_raw(sql, *args):
    """Rows from the throwaway panel.db, read past the ORM (so ciphertext stays ciphertext)."""
    con = _sqlite13.connect(str(_CA13_DB))
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def _ca13_boot():
    """Run create_app with threads recorded, not started; return (app, supervisor runners)."""
    _TkRecThread13.started = []
    _ca13_set(_app10mod, "threading", _tk13_threading(_TkRecThread13))
    try:
        app = _app10mod.create_app()
    finally:
        _app10mod.threading = _CA13_SAVED.pop((_app10mod, "threading"))
    return app, list(_TkRecThread13.started)


def _ca13_probe_big():
    """A 200 JSON body well past the gzip floor, which already varies on Origin."""
    return _Resp13(_json10.dumps({"rows": ["x" * 40] * 60}), mimetype="application/json",
                   headers={"Vary": "Origin"})


def _ca13_probe_stream():
    """A 200 JSON response whose body raises when read: the gzip step cannot read it."""
    def _body():
        """Yield nothing, raising as soon as the body is read."""
        raise RuntimeError("the body broke")
        yield b""  # pragma: no cover - makes this a generator
    return _Resp13(_body(), mimetype="application/json")


def _ca13_add_probes(app):
    """Routes for the response hooks and error handler; added before the app's first request."""
    app.add_url_rule("/_p13/big", "p13_big", _ca13_probe_big)
    app.add_url_rule("/_p13/small", "p13_small", lambda: {"ok": True})
    app.add_url_rule("/_p13/ip", "p13_ip", lambda: _req13.remote_addr or "")
    app.add_url_rule("/_p13/boom", "p13_boom", _raiser10(RuntimeError("page view bug")))
    app.add_url_rule("/api/_p13/boom", "p13_api_boom", _raiser10(RuntimeError("api view bug")))
    app.add_url_rule("/api/_p13/unauth", "p13_unauth", lambda: _abort13(401))
    app.add_url_rule("/api/_p13/gone", "p13_gone", lambda: _abort13(404))
    app.add_url_rule("/_p13/stream", "p13_stream", _ca13_probe_stream)


def _ca13_wsgi_chain(app):
    """The middleware classes around the Flask app, outermost first."""
    chain, w = [], app.wsgi_app
    while w is not None and len(chain) < 8:
        chain.append(w)
        w = getattr(w, "app", None)
    return chain


def _ca13_body(resp, gz=False):
    """A test-client response's JSON (gunzipped first when `gz`), or None — never a raise.

    A check reading a body the code under test got wrong must fail by name, not end section F.
    """
    try:
        data = _gzip13.decompress(resp.data) if gz else resp.data
        return _json10.loads(data)
    except (OSError, EOFError, ValueError):
        return None


def _ca13_gunzip(data):
    """`data` gunzipped, or None when it is not gzip."""
    try:
        return _gzip13.decompress(data)
    except (OSError, EOFError):
        return None


def _ca13_logs(cap):
    """The messages a _cap10 handler collected, as one string."""
    return "\n".join(cap.msgs)


def _tk13_run(loop, sleeps_until_stop):
    """Run one supervised loop until its sleep has been called `sleeps_until_stop` times."""
    slept = []
    _ca13_set(_app10mod, "time", _Clock10(time.time(), sleep=_sleeper10(sleeps_until_stop, slept)))
    try:
        result = _try10(loop)
    finally:
        _app10mod.time = _CA13_SAVED.pop((_app10mod, "time"))
    return result, slept


def _ca13_check_sessions_and_secrets(app):
    """The session-default nudge, and the legacy plaintext credential and e-mail encryption."""
    cfg = _cfgmod10.load_config()
    check("create_app: the old 12h / 14d session defaults are moved to 8h / 3d, and saved",
          all((cfg.get("session_lifetime_hours") == 8, cfg.get("remember_days") == 3,
               app.config["PERMANENT_SESSION_LIFETIME"] == 8 * 3600)),
          repr((cfg.get("session_lifetime_hours"), cfg.get("remember_days"))))
    creds = dict(_ca13_raw("SELECT name, auth_credential FROM remote_server"))
    pw, key, tsk = creds.get("pw-host", ""), creds.get("key-host", ""), creds.get("ts-host", "")
    check("create_app: a legacy plaintext SSH password is encrypted at boot, and decrypts back",
          all((_cfgmod10.is_encrypted(pw), _cfgmod10.decrypt_secret(pw) == "hunter2")), pw[:12])
    check("create_app: an already-encrypted key path is left as it was, and a Tailscale host's "
          "credential (not a secret the panel holds) is not touched",
          all((key == _CA13_KEY_CT, tsk == "tskey-left-alone")), repr((key[:12], tsk)))
    email = (_ca13_raw("SELECT email FROM user WHERE username='legacy'") or [("",)])[0][0] or ""
    check("create_app: a legacy plaintext e-mail address is encrypted at boot, and decrypts back",
          all((_cfgmod10.is_encrypted(email),
               _cfgmod10.decrypt_secret(email) == "ops@example.com")), email[:12])


def _ca13_check_migrations(app, logs):
    """The at-rest column encryption, the stale super_admin grant, retention and IP ageing."""
    host = (_ca13_raw("SELECT host FROM remote_server WHERE name='pw-host'") or [("",)])[0][0]
    with app.app_context():
        orm_host = _models13.RemoteServer.query.filter_by(name="pw-host").first().host
        perms = _models13.Group.query.filter_by(name="legacy-grant").first().get_permissions()
    check("create_app: a host name left in plaintext is encrypted at rest, and still reads back",
          all((_cfgmod10.is_encrypted(host), orm_host == "10.9.8.7",
               "encrypted at-rest columns on 1 row(s)" in logs)),
          repr((host[:12], orm_host, [m for m in logs.split("\n") if "at-rest" in m])))
    check("create_app: a stored super_admin group grant is stripped, the rest of it kept",
          all((sorted(perms) == ["view_servers"],
               "removed the legacy super_admin permission from 1 group(s)" in logs)),
          repr(perms))
    kinds = sorted(r[0] for r in _ca13_raw("SELECT DISTINCT action FROM audit_log WHERE action IN "
                                           "('old', 'aged', 'recent')"))
    aged = dict(_ca13_raw("SELECT action, ip_address FROM audit_log"))
    check("create_app: audit rows past the retention window are deleted, newer ones kept, and a "
          "big prune reclaims the space", all((kinds == ["aged", "recent"],
                                               _CA13_OPTIMIZED == [True])),
          repr((kinds, _CA13_OPTIMIZED)))
    check("create_app: an audit IP past its own retention is reduced to a prefix, a recent one "
          "kept",
          all(("/" in (aged.get("aged") or ""), aged.get("recent") == "203.0.113.78",
               "reduced the IP on 1 audit entries to a network prefix" in logs)),
          repr((aged, [m for m in logs.split("\n") if "reduced the IP" in m])))


def _ca13_check_proxy(app, client):
    """trust_proxy puts ProxyFix in front, inside the ban gate, and the client IP is the hop's."""
    names = [type(w).__name__ for w in _ca13_wsgi_chain(app)]
    fix = [w for w in _ca13_wsgi_chain(app) if type(w).__name__ == "ProxyFix"]
    got = client.get("/_p13/ip", environ_base={"REMOTE_ADDR": "127.0.0.1"},
                     headers={"X-Forwarded-For": "198.51.100.7"}).get_data(as_text=True)
    check("create_app: trust_proxy wraps the app in ProxyFix (one hop), inside the ban gate",
          all((app.config.get("_TRUST_PROXY") is True, names[:2] == ["ProxiedBanGate", "ProxyFix"],
               bool(fix) and fix[0].x_for == 1, got == "198.51.100.7")), repr((names, got)))


def _ca13_login_fails(client, n, remote, xff_for):
    """POST n failed logins from `remote`, each with X-Forwarded-For xff_for(i); returns the 1-based
    attempt the throttle first refused, or None.

    A failure that carries X-Forwarded-For schedules banlist.refresh_soon() (a read of fail2ban and
    the firewall, 3 s later, on a thread). Left real, that thread fired inside the NEXT part and
    ran part16's tripwired _run_verb — a leak that only showed once part16 followed this part. The
    refresh is not what these checks are about, so it is held off for them.
    """
    from panel.security import banlist as _bl13
    saved = _bl13.refresh_soon
    _bl13.refresh_soon = lambda delay=3.0: None
    try:
        for i in range(n):
            r = client.post("/login", data={"username": "p13_nobody", "password": "wrong"},
                            environ_base={"REMOTE_ADDR": remote},
                            headers={"X-Forwarded-For": xff_for(i)})
            if b"Too many failed attempts" in r.data:
                return i + 1
        return None
    finally:
        _bl13.refresh_soon = saved


def _ca13_check_login_behind_proxy(app, client):
    """Aikido 745379296 end to end: this app came up with trust_proxy, so ProxyFix is REALLY in front
    (a test that only flips _TRUST_PROXY never installs it, and passed against a fix that returned
    ProxyFix's rewritten remote_addr). A direct client rotating X-Forwarded-For is still ONE throttle
    bucket, and auth.log names the address that really connected."""
    auth_log = _CA13_DIR / "auth.log"
    fails = _app10mod._LOGIN_FAILS
    saved_csrf = app.config.get("WTF_CSRF_ENABLED", True)
    saved_uid = _ca13_auth._loopback_peer_uid
    app.config["WTF_CSRF_ENABLED"] = False
    try:
        fails.clear()
        before = auth_log.read_text() if auth_log.exists() else ""
        at = _ca13_login_fails(client, 20, "203.0.113.9", lambda i: "192.0.2.%d" % (i + 1))
        logged = (auth_log.read_text() if auth_log.exists() else "")[len(before):]
        keys = sorted(fails)
        check("login behind ProxyFix: a direct client rotating X-Forwarded-For is throttled "
              "(745379296)",
              at is not None and at <= _app10mod.LOGIN_MAX_FAILS + 1,
              "first refused at attempt %r; keys %r" % (at, keys[:4]))
        check("login behind ProxyFix: ...as ONE bucket, the address that connected",
              len(keys) == 1 and "203.0.113.9" in str(keys[0]), repr(keys[:4]))
        check("login behind ProxyFix: ...and auth.log names it, never an address it made up",
              "from 203.0.113.9" in logged and "192.0.2." not in logged, logged[-300:])
        # The control: the README's layout, a proxy on loopback. Its X-Forwarded-For IS the client —
        # each forwarded client its own bucket — so a fix that ignored the header everywhere fails.
        fails.clear()
        _ca13_auth._loopback_peer_uid = lambda _env: 0
        _ca13_login_fails(client, 1, "127.0.0.1", lambda i: "198.51.100.4")
        check("login behind ProxyFix: a proxy on loopback still names the client (control)",
              sorted(fails) == ["198.51.100.4"], repr(sorted(fails)))
        # ...but not when the loopback socket is a local account that is no proxy.
        fails.clear()
        _ca13_auth._loopback_peer_uid = lambda _env: 54321
        _ca13_login_fails(client, 1, "127.0.0.1", lambda i: "198.51.100.5")
        check("login behind ProxyFix: a local game account on loopback is keyed as loopback",
              sorted(fails) == ["127.0.0.1"], repr(sorted(fails)))
        # config.json's trusted_proxies reached this app at boot: a proxy on another machine it
        # lists is believed.
        fails.clear()
        _ca13_login_fails(client, 1, "198.51.100.9", lambda i: "192.0.2.50")
        check("login behind ProxyFix: a proxy config.json lists in trusted_proxies names the client",
              sorted(fails) == ["192.0.2.50"], repr(sorted(fails)))
    finally:
        _ca13_auth._loopback_peer_uid = saved_uid
        app.config["WTF_CSRF_ENABLED"] = saved_csrf
        fails.clear()


def _ca13_check_compression(app, client):
    """gzip for big text answers the client accepts, the Vary merge, and the cache headers."""
    gz = {"Accept-Encoding": "gzip"}
    css_dir = os.path.join(app.static_folder, "css")
    css = sorted(p for p in os.listdir(css_dir) if p.endswith(".css"))[0]
    with open(os.path.join(css_dir, css), "rb") as fh:
        raw = fh.read()
    st = client.get("/static/css/" + css, headers=gz)
    check("app responses: a static asset is gzipped, decodes to the file, and is cached a week",
          all((st.headers.get("Content-Encoding") == "gzip", _ca13_gunzip(st.data) == raw,
               st.headers.get("Cache-Control") == "public, max-age=604800",
               "Accept-Encoding" in (st.headers.get("Vary") or ""))), repr(dict(st.headers)))
    big = client.get("/_p13/big", headers=gz)
    check("app responses: a big page is gzipped, its own Vary kept with Accept-Encoding added, "
          "and it must be revalidated", all((
              big.headers.get("Content-Encoding") == "gzip",
              (_ca13_body(big, gz=True) or {}).get("rows", [""])[0] == "x" * 40,
              [v.strip() for v in big.headers.get("Vary", "").split(",")][:2]
              == ["Origin", "Accept-Encoding"],
              big.headers.get("Cache-Control") == "no-cache, private")), repr(dict(big.headers)))
    plain, small = client.get("/_p13/big"), client.get("/_p13/small", headers=gz)
    check("app responses: no gzip without Accept-Encoding, nor below the size floor",
          all(("Content-Encoding" not in plain.headers, "Content-Encoding" not in small.headers,
               (_ca13_body(plain) or {}).get("rows", [""])[0] == "x" * 40,
               _ca13_body(small) == {"ok": True})),
          repr((dict(plain.headers), dict(small.headers))))
    cap, off = _cap10(app.logger.name)
    try:
        broken = client.get("/_p13/stream", headers=gz)
    finally:
        off()
    check("app responses: a body the gzip step cannot read goes out uncompressed, and it is logged",
          all((broken.status_code == 200, "Content-Encoding" not in broken.headers,
               "response gzip skipped" in _ca13_logs(cap))), repr((broken.status_code, cap.msgs)))
    hsts = client.get("/_p13/small", headers={"X-Forwarded-Proto": "https"})
    check("app responses: HSTS is sent over proxied HTTPS, and not over plain HTTP",
          all(("max-age=31536000" in (hsts.headers.get("Strict-Transport-Security") or ""),
               "Strict-Transport-Security" not in small.headers)), repr(dict(hsts.headers)))


def _ca13_check_errors(app, client):
    """The error handler: HTML stays HTML, the API gets JSON, and a 401 keeps its own shape."""
    xhr = {"X-Requested-With": "XMLHttpRequest"}
    quiet = (app.logger, _logging13.getLogger("panel.app"))   # both 500s log a traceback by design
    for lg in quiet:
        lg.disabled = True
    try:
        page, api = client.get("/_p13/boom"), client.get("/api/_p13/boom")
    finally:
        for lg in quiet:
            lg.disabled = False
    gone = client.get("/api/_p13/gone")
    unauth = client.get("/api/_p13/unauth", headers=xhr)
    check("app errors: a page view that raises is an ordinary 500 page, not JSON",
          all((page.status_code == 500, page.get_json(silent=True) is None)), page.status_code)
    check("app errors: an API view that raises, and an API 404, answer JSON with success False",
          all((api.status_code == 500, (api.get_json(silent=True) or {}).get("success") is False,
               gone.status_code == 404,
               (gone.get_json(silent=True) or {}).get("success") is False)),
          repr((api.status_code, api.data[:80], gone.status_code, gone.data[:80])))
    check("app errors: a 401 keeps its own response (the page's session-expired handling reads it)",
          all((unauth.status_code == 401, unauth.get_json(silent=True) is None)),
          repr((unauth.status_code, unauth.data[:80])))


def _tk13_check_supervisor(loops, app):
    """A supervised worker that exits is logged and respawned after five seconds, as a daemon."""
    runner = loops["due-actions"][0]
    _TK13["calls"][:] = []
    _ca13_set(_app10mod, "threading", _tk13_threading(_TkInlineThread13))
    cap, off = _cap10(app.logger.name)
    try:
        res, slept = _tk13_run(runner, 2)
    finally:
        off()
        _app10mod.threading = _CA13_SAVED.pop((_app10mod, "threading"))
    check("app supervisor: a worker that exits is logged by name and respawned after 5s, as a "
          "daemon thread", all((res == ("RAISED", repr(_Stop10())), slept == [45, 90, 5],
                                _TK13["calls"] == [("thread", True), ("due-restarts", app),
                                                   ("thread-exited",)],
                                "due-actions thread exited — respawning in 5s" in _ca13_logs(cap))),
          repr((slept, _TK13["calls"], cap.msgs)))


def _tk13_check_backup_loops(loops, app):
    """The backup and due-action loops: first sleep, a pass, a failing pass contained, interval."""
    _TK13["calls"][:] = []
    _TK13["fail_from"] = {"daily": 2}
    _ca13_set(_app10mod, "bk", NS(daily_backup_tick=lambda: _tk13_rec("daily")))
    try:
        _run1, slept1 = _tk13_run(loops["backup-ticker"][1], 3)
    finally:
        _app10mod.bk = _CA13_SAVED.pop((_app10mod, "bk"))
    check("app backup loop: waits 2 min first, then the daily tick, the per-server schedules and "
          "the queue, hourly — and a failing tick skips the rest of that pass only",
          all((slept1 == [120, 3600, 3600],
               _TK13["calls"] == [("daily",), ("due-backups", app), ("pending-backups", app),
                                  ("daily",)])), repr((slept1, _TK13["calls"])))
    _TK13["calls"][:] = []
    _TK13["fail_from"] = {"due-restarts": 2}
    _run2, slept2 = _tk13_run(loops["due-actions"][1], 3)
    check("app due-actions loop: waits 45s first, then applies queued restarts every 90s, past a "
          "failing pass", all((slept2 == [45, 90, 90],
                               _TK13["calls"] == [("due-restarts", app)] * 2)),
          repr((slept2, _TK13["calls"])))
    _TK13["fail_from"] = {}


def _tk13_seed_reconcile(app):
    """Game servers in every state the reconcile loop meets; returns {short_name: row id}."""
    rows = (("tkA", "installing", False), ("tkB", "configuring", False), ("tkC", "failed", False),
            ("tkD", "installing", False), ("tkE", "failed", False), ("tkF", "installing", False),
            ("tkG", "online", True), ("tkH", "installing", False))
    db, ids = _models13.db, {}
    with app.app_context():
        host = _models13.RemoteServer(name="rc-host", host="192.0.2.40", username="root",
                                      auth_method="tailscale")
        db.session.add(host)
        db.session.commit()
        for i, (short, status, installed) in enumerate(rows):
            gs = _models13.GameServer(remote_id=host.id, name=short, short_name=short,
                                      game_type="gmod", port=27100 + i, status=status,
                                      installed=installed)
            db.session.add(gs)
            db.session.commit()
            ids[short] = gs.id
    return ids


def _tk13_states(app):
    """{short_name: (installed, status)} for every game server row."""
    with app.app_context():
        return {g.short_name: (g.installed, g.status) for g in _models13.GameServer.query.all()}


def _tk13_check_reconcile(loops, app):
    """Stranded installs are judged by what the host says; only a real change is announced."""
    ids = _tk13_seed_reconcile(app)
    _pstate10._install_jobs[ids["tkA"]] = {"status": "running"}
    _pstate10._install_jobs[ids["tkH"]] = {"status": "failed"}
    _TK13["looks"] = {"tkB": True, "tkC": False, "tkD": False, "tkE": None,
                      "tkF": RuntimeError("ssh dropped"), "tkH": None}
    _TK13["calls"][:] = []
    cap, off = _cap10(app.logger.name)
    try:
        _res, slept = _tk13_run(loops["install-reconcile"][1], 2)
    finally:
        off()
        for short in ("tkA", "tkH"):
            _pstate10._install_jobs.pop(ids[short], None)
    asked = [c[1:] for c in _TK13["calls"] if c[0] == "looks"]
    logs = _ca13_logs(cap)
    check("app install reconcile: every stranded or failed row is asked about (with its script "
          "name) — never a live install, never a running server",
          all((sorted(asked) == [(s, "gmodserver")
                                 for s in ("tkB", "tkC", "tkD", "tkE", "tkF", "tkH")],
               slept == [20, 600])), repr((asked, slept)))
    eq("app install reconcile: installed -> offline, clearly not -> failed, can't tell -> left",
       _tk13_states(app),
       {"tkA": (False, "installing"), "tkB": (True, "offline"), "tkC": (False, "failed"),
        "tkD": (False, "failed"), "tkE": (False, "failed"), "tkF": (False, "installing"),
        "tkG": (True, "online"), "tkH": (False, "installing")})
    check("app install reconcile: only a row that CHANGED is announced and logged",
          all(([c for c in _TK13["calls"] if c[0] == "notify"] == [("notify", app)] * 2,
               "'tkB' -> installed" in logs, "'tkD' -> failed" in logs, "'tkC'" not in logs)),
          repr((_TK13["calls"], cap.msgs)))


def _tk13_check_priority(loops, app):
    """One batched renice per host for its installed servers, past a host that fails."""
    db, calls = _models13.db, []
    with app.app_context():
        _models13.GameServer.query.delete()
        one = _models13.RemoteServer(name="pk-one", host="192.0.2.41", username="root",
                                     auth_method="tailscale")
        two = _models13.RemoteServer(name="pk-two", host="192.0.2.42", username="root",
                                     auth_method="tailscale")
        db.session.add_all([one, two])
        db.session.commit()
        for i, (host, short, installed) in enumerate(((one, "pkb", True), (one, "pka", True),
                                                      (one, "pkz", False), (two, "pkq", True))):
            db.session.add(_models13.GameServer(remote_id=host.id, name=short, short_name=short,
                                                game_type="gmod", port=27200 + i,
                                                installed=installed, status="online"))
        db.session.commit()

    def _bulk(remote, users):
        """Record the batch, and fail for the first host."""
        calls.append((remote.name, list(users)))
        if remote.name == "pk-one":
            raise RuntimeError("renice refused")

    _ca13_set(_app10mod, "set_game_priority_bulk", _bulk)
    try:
        _res, slept = _tk13_run(loops["priority-keeper"][1], 2)
    finally:
        _app10mod.set_game_priority_bulk = _CA13_SAVED.pop((_app10mod, "set_game_priority_bulk"))
    check("app priority keeper: one sorted batch per host of its INSTALLED servers, every 2 min, "
          "and a host whose renice fails does not stop the next",
          all((calls == [("pk-one", ["pka", "pkb"]), ("pk-two", ["pkq"])], slept == [60, 120])),
          repr((calls, slept)))


def _tk13_hush(logger, keep):
    """Detach every handler on `logger` but `keep`, and stop it propagating; return the undo.

    For a check that provokes an error on purpose and asserts on the captured record: the record
    still reaches `keep`, but its traceback stays out of the run's output. Flask's own handler put
    the two below in the unit log, pointing only at app.py lines, and they were read there as
    real tickers left running by an earlier check.
    """
    others, propagate = [h for h in logger.handlers if h is not keep], logger.propagate
    for h in others:
        logger.removeHandler(h)
    logger.propagate = False

    def _undo():
        for h in others:
            logger.addHandler(h)
        logger.propagate = propagate
    return _undo


def _tk13_check_tick_failures(loops, app):
    """A tick that cannot even read the database is logged, and the loop keeps its interval."""
    cap, off = _cap10(app.logger.name)
    unhush = _tk13_hush(app.logger, cap)
    _ca13_set(_app10mod, "GameServer", NS())       # every query in the tick raises
    try:
        _r1, rec_slept = _tk13_run(loops["install-reconcile"][1], 2)
        _r2, pk_slept = _tk13_run(loops["priority-keeper"][1], 2)
    finally:
        unhush()
        off()
        _app10mod.GameServer = _CA13_SAVED.pop((_app10mod, "GameServer"))
    logs = _ca13_logs(cap)
    check("app loops: a reconcile or priority tick that cannot read the database is logged, and "
          "the loop sleeps its interval and goes on",
          all((rec_slept == [20, 600], pk_slept == [60, 120],
               "install-reconcile tick failed" in logs, "priority keeper tick failed" in logs)),
          repr((rec_slept, pk_slept, cap.msgs)))


def _ca13_check_failing_boot():
    """Every one-time boot step failing: the panel still boots, and each failure is logged."""
    _ca13_config(session_lifetime_hours=10, audit_log_retention_days="a month")
    before = _ca13_raw("SELECT COUNT(*) FROM audit_log")
    for owner, name, exc in ((_n10, "migrate_master_switch", "config locked"),
                             (_app10mod, "strip_legacy_superadmin_grants", "database locked"),
                             (_app10mod, "is_encrypted", "cred_key unreadable"),
                             (_models13, "encrypt_at_rest_columns", "disk full"),
                             (_models13, "anonymise_audit_ips", "disk full")):
        _ca13_set(owner, name, _raiser10(RuntimeError(exc)))
    cap_a, off_a = _cap10("app")
    cap_p, off_p = _cap10("panel.app")
    try:
        app, _runners = _ca13_boot()
    finally:
        off_a()
        off_p()
        _ca13_restore_some(("migrate_master_switch", "strip_legacy_superadmin_grants",
                            "is_encrypted", "encrypt_at_rest_columns", "anonymise_audit_ips"))
    logs = _ca13_logs(cap_a) + "\n" + _ca13_logs(cap_p)
    names = [type(w).__name__ for w in _ca13_wsgi_chain(app)]
    check("create_app: with every one-time step failing, the panel still boots, routes and all",
          all(("login" in app.view_functions, "ProxyFix" not in names,
               _cfgmod10.load_config().get("session_lifetime_hours") == 10)), repr(names))
    check("create_app: each failed boot step is logged, not swallowed",
          all((m in logs for m in ("notifications master-switch migration skipped",
                                   "legacy super_admin cleanup skipped",
                                   "at-rest column encryption migration failed",
                                   "audit IP anonymisation failed"))), logs[-400:])
    check("create_app: an unparseable audit retention deletes nothing",
          _ca13_raw("SELECT COUNT(*) FROM audit_log") == before, repr(before))
    _ca13_add_probes(app)
    client = app.test_client()
    hsts = client.get("/_p13/small", headers={"X-Forwarded-Proto": "https"})
    plain = client.get("/_p13/small")
    check("app responses: with no proxy trusted, X-Forwarded-Proto: https alone still earns HSTS "
          "(Tailscale Serve sets it), and plain HTTP does not",
          all(("max-age=31536000" in (hsts.headers.get("Strict-Transport-Security") or ""),
               "Strict-Transport-Security" not in plain.headers)),
          repr((dict(hsts.headers), dict(plain.headers))))
    return app


def _ca13_restore_some(names):
    """Put back the replaced attributes with these names, leaving the rest in place."""
    for key in [k for k in _CA13_SAVED if k[1] in names]:
        setattr(key[0], key[1], _CA13_SAVED.pop(key))


_CA13_KEY_CT = _cfgmod10.encrypt_secret("/root/.ssh/k")
_CA13_OPTIMIZED = []
_ca13_real_optimize = _models13.optimize_database


def _ca13_optimize():
    """Record that boot asked for a reclaim, then run the real one on the throwaway file."""
    res = _ca13_real_optimize()
    _CA13_OPTIMIZED.append(bool(res and res[0]))
    return res


def _ca13_first_boot():
    """Seed the throwaway install, boot it, and return (app, runners, boot logs)."""
    _ca13_seed()
    _ca13_config(session_lifetime_hours=12, remember_days=14, trust_proxy=True,
                 trusted_proxies=["127.0.0.1", "::1", "198.51.100.0/24"],
                 audit_log_retention_days=30, audit_ip_retention_days=7)
    cap_a, off_a = _cap10("app")
    cap_p, off_p = _cap10("panel.app")
    try:
        app, runners = _ca13_boot()
    finally:
        off_a()
        off_p()
    return app, runners, _ca13_logs(cap_a) + "\n" + _ca13_logs(cap_p)


def _ca13_teardown(apps, saved):
    """Close every boot's database and put back the process-wide state boot registered."""
    for app in apps:
        with app.app_context():
            _models13.db.session.remove()
            _models13.db.engine.dispose()
    _banlist13._listeners.clear()
    _banlist13._listeners.update(saved["listeners"])
    _hooks13._hooks.clear()
    _hooks13._hooks.update(saved["hooks"])
    handlers, level, propagate = saved["authlog"]
    for h in [h for h in _app10mod._authlog.handlers if h not in handlers]:
        _app10mod._authlog.removeHandler(h)
        h.close()
    _app10mod._authlog.setLevel(level)
    _app10mod._authlog.propagate = propagate
    if _CA13_CFG_SNAP is None:
        _cfgmod10.CONFIG_FILE.unlink(missing_ok=True)
    else:
        _cfgmod10.CONFIG_FILE.write_bytes(_CA13_CFG_SNAP)
    _shutil10.rmtree(str(_CA13_DIR.parent), ignore_errors=True)


_ca13_saved_state = {"listeners": dict(_banlist13._listeners), "hooks": dict(_hooks13._hooks),
                     "authlog": (list(_app10mod._authlog.handlers), _app10mod._authlog.level,
                                 _app10mod._authlog.propagate)}
_ca13_apps = []
_ca13_trip = _arm10()
try:
    for _n13 in _CA13_SHARED:
        _ca13_set(_shared13, _n13, _TK13_STUBS[_n13])
    for _owner13, _name13, _val13 in ((_cfgmod10, "DATA_DIR", _CA13_DIR),
                                      (_cfgmod10, "DB_PATH", _CA13_DB),
                                      (_app10mod, "DB_PATH", _CA13_DB),
                                      (_app10mod, "AUTH_LOG_PATH", str(_CA13_DIR / "auth.log")),
                                      (_models13, "optimize_database", _ca13_optimize)):
        _ca13_set(_owner13, _name13, _val13)
    _ca13_app, _ca13_runners, _ca13_bootlog = _ca13_first_boot()
    _ca13_apps.append(_ca13_app)
    check("create_app: the database it opened is the throwaway one, never the checkout's",
          _ca13_app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///%s" % _CA13_DB,
          _ca13_app.config["SQLALCHEMY_DATABASE_URI"])
    _ca13_add_probes(_ca13_app)
    _ca13_client = _ca13_app.test_client()
    _ca13_check_sessions_and_secrets(_ca13_app)
    _ca13_check_migrations(_ca13_app, _ca13_bootlog)
    _ca13_check_proxy(_ca13_app, _ca13_client)
    _ca13_check_login_behind_proxy(_ca13_app, _ca13_client)
    _ca13_check_compression(_ca13_app, _ca13_client)
    _ca13_check_errors(_ca13_app, _ca13_client)
    _ca13_loops = _tk13_loops(_ca13_runners)
    check("create_app: register_routes hands its loops to the supervisor, and starts none itself",
          {"backup-ticker", "due-actions", "install-reconcile", "priority-keeper"}
          <= set(_ca13_loops), sorted(_ca13_loops))
    _tk13_check_supervisor(_ca13_loops, _ca13_app)
    _tk13_check_backup_loops(_ca13_loops, _ca13_app)
    _tk13_check_reconcile(_ca13_loops, _ca13_app)
    _tk13_check_priority(_ca13_loops, _ca13_app)
    _tk13_check_tick_failures(_ca13_loops, _ca13_app)
    _ca13_apps.append(_ca13_check_failing_boot())
    check("app boot: nothing in this section reached a real SSH or local transport",
          _trip10 == [], repr(_trip10))
except Exception as _e13:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    check("app boot: the create_app harness ran to the end", False,
          "raised %s: %s" % (type(_e13).__name__, _e13))
finally:
    _disarm10(_ca13_trip)
    _ca13_restore()
    _ca13_teardown(_ca13_apps, _ca13_saved_state)
check("app boot: the checkout's own data/panel.db was not created",
      _CA13_LIVE_DB_EXISTED or not os.path.exists(_CA13_LIVE_DB), _CA13_LIVE_DB)


# ══════════════════════════════════════════════════════════════════════════════════════════════
# G. panel/ops/ssh_manager/_core.py — the LinuxGSM maintenance cron, per supported command
# ══════════════════════════════════════════════════════════════════════════════════════════════
def _core_cron13(supported):
    """install_game_cron for `supported`, with the crontab rewrite recorded; (result, rewrites)."""
    seen = []
    saved = _sm_core._rewrite_crontab
    _sm_core._rewrite_crontab = lambda server, user, grep_args, add_lines, **k: (
        seen.append((user, grep_args, list(add_lines))), (True, ""))[1]
    try:
        return _sm_core.install_game_cron(NS(is_local=False), "gm4", "gmodserver", supported), seen
    finally:
        _sm_core._rewrite_crontab = saved


_cron_all13, _cron_all_seen13 = _core_cron13({"monitor", "mods-update", "update", "update-lgsm"})
_cron_lines13 = _cron_all_seen13[0][2] if _cron_all_seen13 else []
check("core cron: each supported command gets its own schedule, recorder-wrapped, in one rewrite",
      all((_cron_all13 == (True, ""), len(_cron_all_seen13) == 1,
           [ln.split(" /home/")[0].split(" ", 5)[:5] for ln in _cron_lines13] ==
           [["*/5", "*", "*", "*", "*"], ["0", "5", "*", "*", "*"], ["15", "5", "*", "*", "*"],
            ["30", "5", "*", "*", "0"]],
           [c for c in ("monitor", "mods-update", "update", "update-lgsm")
            if not any("/home/gm4/gmodserver %s" % c in ln for ln in _cron_lines13)] == [],
           all("/home/gm4/.lgsm-cron/" in ln for ln in _cron_lines13))),
      repr(_cron_lines13))
_cron_none13, _cron_none_seen13 = _core_cron13(set())
check("core cron: a game supporting none of them rewrites nothing, and says so",
      all((_cron_none13 == (True, "no maintenance commands to schedule"), _cron_none_seen13 == [])),
      repr((_cron_none13, _cron_none_seen13)))


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Suite hygiene, checked last: nothing the unit parts did is left bound on the ssh_manager PACKAGE
# ══════════════════════════════════════════════════════════════════════════════════════════════
# The package resolves names through __getattr__ so that ONE stub, on the defining submodule,
# reaches every caller. A name set on the package itself — a stub, or the "restore" that follows
# it — is a real attribute from then on and shadows __getattr__ for the rest of the process:
# later stubs on the submodule silently miss every `_sm.<name>` caller. part02 did exactly that
# with server_live_metrics, and a check here passed while app ran the real read.
import types as _types10  # noqa: E402

import panel.ops.ssh_manager as _smpkg10  # noqa: E402

_pkg_leaks10 = sorted(k for k, v in vars(_smpkg10).items()
                      if not k.startswith("__") and k != "_MODULES"
                      and not isinstance(v, _types10.ModuleType))
check("ssh_manager: no unit part left a name bound on the package (it shadows __getattr__)",
      not _pkg_leaks10, "bound on the package: %r" % (_pkg_leaks10,))
