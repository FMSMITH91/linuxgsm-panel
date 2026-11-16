"""Part 229 of the unit suite: an account links its own Telegram chat and gets its alerts there.

* Link codes: random, single-use, good for CODE_TTL, claimed only from a private chat, and at most
  CODES_MAX asked per account per CODE_TTL. "/start <code>" (also "/start@bot <code>") carries one.
* The routes: no link while the panel has no bot; a recent password confirmation first (step-up); a
  t.me link with the code; the check reads the bot's waiting messages once (the command poll off),
  links the chat, stores it encrypted, audits it, and tells the chat; unlink forgets it.
* The command bot's poll links a "/start <code>" from any private chat and runs no command for it.
* push_alerts sends a linked chat the same short alert text a browser gets.

HOW IT RUNS. Through the real routes and the bot's real update router on part12's Flask app, with
Telegram's API stubbed at notifications (getMe, getUpdates, sendMessage): nothing leaves the process.
"""
import time as _time229

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_client, _p9_drain, _p9_json, _p9_patch, _p9_restore_all
from panel.db.models import AuditLog as _AL229, User as _U229, db as _db229
from panel.security import auth as _auth229
from panel.services import notifications as _nt229, push_alerts as _pa229, telegram_link as _tl229
from panel.services.bots import telegram as _tgb229

_trips229 = len(_P9_TRIPPED)
_IDS229 = []
_K229 = "lantern orchard pebble"          # the fixture's password (no real credential)
_TOKEN229 = "123456:TESTONLYTOKEN"         # a bot token of Telegram's shape (no real bot)
_XHR229 = {"X-Requested-With": "XMLHttpRequest"}


def _user229(name):
    with _p9.app_context():
        u = _U229(username=name, password_hash=_auth229.hash_password(_K229), display_name=name, is_active=True)
        _db229.session.add(u)
        _db229.session.commit()
        _IDS229.append(u.id)
        return u.id


def _codes229():
    _tl229.reset()
    c = _tl229.new_code(9001, now=1000)
    first = _tl229.claim(c, 555, "private", now=1001)
    again = _tl229.claim(c, 555, "private", now=1002)
    c2 = _tl229.new_code(9001, now=1003)
    group = _tl229.claim(c2, -100555, "group", now=1004)
    late = _tl229.claim(c2, 555, "private", now=1003 + _tl229.CODE_TTL + 1)
    _tl229.reset()
    many = [_tl229.new_code(9002, now=2000 + i) is not None for i in range(_tl229.CODES_MAX + 1)]
    _tl229.reset()
    eq("telegram link: a code is claimed once, from a private chat, before it expires; an account gets "
       "CODES_MAX codes per CODE_TTL", (first, again, group, late, many),
       (9001, None, None, None, [True] * _tl229.CODES_MAX + [False]))
    eq("telegram link: '/start <code>' and '/start@bot <code>' carry the code; nothing else does",
       [_tl229.start_payload(t) for t in ("/start abc", "/start@PanelBot abc", "/start", "/status abc", "/start a b")],
       ["abc", "abc", "", "", ""])


def _stub_api229(sent, updates):
    _p9_patch(_tl229, "bot_token", lambda: _TOKEN229)
    _p9_patch(_nt229, "telegram_get_me", lambda token: "PanelBot")
    _p9_patch(_nt229, "send_telegram", lambda token, chat, text: sent.append((str(chat), text)) or (True, ""))
    _p9_patch(_tgb229, "_tg_settings", lambda: (_TOKEN229, "", "off"))
    _p9_patch(_nt229, "telegram_get_updates", lambda token, offset=None, timeout=25: list(updates))


def _routes229():
    uid = _user229("p229_tg")
    _tl229.reset()
    c = _p9_client(uid)
    _p9_patch(_tl229, "bot_token", lambda: "")
    off = c.post("/account/telegram/link")
    sent, updates = [], []
    _stub_api229(sent, updates)
    r = c.post("/account/telegram/link")
    url = _p9_json(r).get("url") or ""
    updates.append({"update_id": 1, "message": {"text": "/start " + url.split("start=", 1)[-1],
                                                "chat": {"id": 424242, "type": "private"}}})
    chk = c.post("/account/telegram/check")
    with _p9.app_context():
        from sqlalchemy import Text, select, type_coerce
        t = _U229.__table__
        raw = _db229.session.execute(select(type_coerce(t.c.telegram_chat, Text)).where(t.c.id == uid)).scalar()
        chat = _db229.session.get(_U229, uid).telegram_chat
        audited = _AL229.query.filter_by(action="telegram_link", target="p229_tg").count()
    eq("telegram link: none without the panel's bot; with it a t.me link carrying the code, and the check "
       "links the chat that pressed Start, stored encrypted, audited, and told",
       (off.status_code, r.status_code, url.startswith("https://t.me/PanelBot?start="),
        _p9_json(chk).get("linked"), chat, str(raw)[:4], audited, [s[0] for s in sent]),
       (400, 200, True, True, "424242", "enc:", 1, ["424242"]))
    stale = _p9_client(uid)
    with stale.session_transaction() as s:
        s["_auth_at"] = _time229.time() - 3600
        s.permanent = True
    sr = stale.post("/account/telegram/link", headers=_XHR229)
    eq("telegram link: asking for a link needs a recent password confirmation (step-up)",
       (sr.status_code, _p9_json(sr).get("error")), (403, "reauth_required"))
    _p9_drain()
    sent.clear()
    with _p9.app_context():
        _pa229.deliver([("account", "password_changed", "p229_tg")])
    eq("telegram link: a linked chat gets the account's alert, the same short text a browser gets",
       sent, [("424242", "Your account changed\nPassword changed")])
    un = c.post("/account/telegram/unlink")
    with _p9.app_context():
        left = _db229.session.get(_U229, uid).telegram_chat
    eq("telegram link: unlink forgets the chat", (un.status_code, left), (302, ""))


def _bot229():
    uid = _user229("p229_bot")
    _tl229.reset()
    sent = []
    _stub_api229(sent, [])
    code = _tl229.new_code(uid)
    grp = {"update_id": 5, "message": {"text": "/start " + code, "chat": {"id": -100777, "type": "group"},
                                       "from": {"id": 777}}}
    _tgb229._tg_handle(_p9, _TOKEN229, "999", "PanelBot", grp)
    mine = {"update_id": 6, "message": {"text": "/start " + code, "chat": {"id": 777, "type": "private"},
                                        "from": {"id": 777}}}
    _tgb229._tg_handle(_p9, _TOKEN229, "999", "PanelBot", mine)
    with _p9.app_context():
        chat = _db229.session.get(_U229, uid).telegram_chat
    eq("telegram link: the command bot's poll links '/start <code>' from a private chat, not from a group, "
       "and answers only the chat it linked", (chat, [s[0] for s in sent]), ("777", ["777"]))


try:
    for _sec229 in (_codes229, _routes229, _bot229):
        try:
            _sec229()
        finally:
            _p9_drain()
            _p9_restore_all()
finally:
    _tl229.reset()
    with _p9.app_context():
        for _uid229 in _IDS229:
            _u229 = _db229.session.get(_U229, _uid229)
            if _u229 is not None:
                _db229.session.delete(_u229)
        _db229.session.commit()
check("telegram link: nothing in this part reached a real transport (part12's tripwire)",
      len(_P9_TRIPPED) == _trips229)
