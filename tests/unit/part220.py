"""Part 220 of the unit suite: what the Active Sessions list and Settings say about how long a sign-in lasts.

* Active Sessions (/api/account/sessions): each row says whether it is a "remember me" sign-in and when
  it ends, from UserSession.signs_out_at / idle_signout_minutes, the rule is_expired and the sweep apply:
  a row listed one minute before its end is pruned one minute after it, and the list costs the same
  number of queries for one row as for four. account_sessions.js turns those into the row's sentence
  (run in node).
* Settings > Sessions & Security: the step-up window (session_policy.step_up_minutes) is a field with
  NIST's 15 minutes beside it (OWASP gives no number) and notes past it and at 0; a save stores it,
  puts it in force at once (the next high-risk route reads it) and names the change in the audit row;
  a save without the field keeps it. The card's sentences explain both kinds of sign-in, and the login
  page's "Remember me" says how long it lasts, both from the limit the server ends such a login at.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import json as _json220
import os as _os220
import shutil as _shutil220
import subprocess as _sp220  # nosec B404 - runs node on the panel's own JS, nothing else
import time as _time220
from datetime import datetime as _dt220, timedelta as _td220

from sqlalchemy import event as _sa_event220

from unit import REPO_ROOT as _ROOT
from unit.part01 import check, eq, skip
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import i18n as _i18n220, session_policy as _sp_pol220
from panel.core.clock import utcnow as _now220
from panel.db.models import AuditLog as _AL220, Group as _G220, User as _U220, UserSession as _US220, db as _db220
from panel.security import auth as _auth220

_trips220 = len(_P9_TRIPPED)
_IDS220 = []
_K220 = "harbour lantern quietly"       # the fixtures' password (no real credential)
_XHR220 = {"X-Requested-With": "XMLHttpRequest"}
_LIFE_KEYS220 = ("PERMANENT_SESSION_LIFETIME", "SESSION_ABSOLUTE_SECONDS", "REMEMBER_COOKIE_DURATION",
                 "STEP_UP_MINUTES", "SESSION_PROTECTION", "REQUIRE_2FA")


def _user220(name, superadmin=False):
    """A fresh account with _K220 as its password; its id."""
    with _p9.app_context():
        u = _U220(username=name, password_hash=_auth220.hash_password(_K220), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        _db220.session.add(u)
        _db220.session.commit()
        _IDS220.append(u.id)
        return u.id


def _login220(name, remember=False):
    """POST the login form; the signed-in client."""
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = "198.51.100.220"
    data = {"username": name, "password": _K220}
    if remember:
        data["remember"] = "on"
    c.post("/login", data=data)
    return c


def _lifetimes220(idle_min=20, absolute_h=4, remember_d=3):
    _p9.config.update(PERMANENT_SESSION_LIFETIME=idle_min * 60, SESSION_ABSOLUTE_SECONDS=absolute_h * 3600,
                      REMEMBER_COOKIE_DURATION=_td220(days=remember_d))


def _iso220(value):
    return _dt220.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ") if "." in value else _dt220.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _rows220(uid):
    with _p9.app_context():
        return {r.remember: r.created_at for r in _US220.query.filter_by(user_id=uid).all()}


def _set_created220(uid, ago):
    with _p9.app_context():
        for row in _US220.query.filter_by(user_id=uid).all():
            row.created_at = row.last_seen = _now220() - _td220(seconds=ago)
        _db220.session.commit()


# ── 1. Active Sessions: what kind of sign-in, and when it ends ──────────────────────────────────
def _s220_rows():
    live = {k: _p9.config.get(k) for k in _LIFE_KEYS220}
    try:
        _lifetimes220()
        uid = _user220("p220_rows")
        plain = _login220("p220_rows")
        _login220("p220_rows", remember=True)
        listed = {s["remember"]: s for s in _p9_json(plain.get("/api/account/sessions", headers=_XHR220))["sessions"]}
        created = _rows220(uid)
    finally:
        _p9.config.update(live)
    p, r = listed.get(False, {}), listed.get(True, {})
    eq("sessions list: a normal sign-in says it ends after the idle timeout or at sign-in + the absolute limit",
       (p.get("idle_minutes"), p.get("ends") and _iso220(p["ends"]) - created.get(False)), (20, _td220(hours=4)))
    eq("sessions list: a remembered sign-in is marked so and ends at sign-in + the remember days, with no idle part",
       (r.get("remember"), r.get("idle_minutes"), r.get("ends") and _iso220(r["ends"]) - created.get(True)),
       (True, None, _td220(days=3)))


def _s220_end_is_the_rule():
    """A row listed one minute before its end is gone one minute after: `ends` is the expiry itself."""
    live = {k: _p9.config.get(k) for k in _LIFE_KEYS220}
    try:
        _lifetimes220(idle_min=600, absolute_h=10)
        uid = _user220("p220_edge")
        c = _login220("p220_edge")
        _set_created220(uid, 10 * 3600 - 60)
        before = _p9_json(c.get("/api/account/sessions", headers=_XHR220)).get("sessions", [])
        _set_created220(uid, 10 * 3600 + 60)
        after = c.get("/api/account/sessions", headers=_XHR220)
        left = _rows220(uid)
    finally:
        _p9.config.update(live)
    ends = before[0]["ends"] if before else None
    _all220("sessions list: a row one minute before its listed end is listed (its end a minute ahead, its idle "
            "part dropped when idle and absolute coincide); one minute past it the server has ended it",
            [len(before) == 1,
             ends is not None and 0 < (_iso220(ends) - _now220()).total_seconds() <= 61,
             before and before[0]["idle_minutes"] is None,
             after.status_code == 401,
             left == {}], repr((before, after.status_code, left)))


def _all220(name, conds, detail=""):
    """check() over a list of conditions, so a check of several facts stays one branch."""
    check(name, all(conds), detail)


def _queries220(client):
    """Statements one GET of the sessions list runs."""
    n = [0]

    def _count(*_a):
        n[0] += 1
    with _p9.app_context():
        engine = _db220.engine
    _sa_event220.listen(engine, "after_cursor_execute", _count)
    try:
        client.get("/api/account/sessions", headers=_XHR220)
    finally:
        _sa_event220.remove(engine, "after_cursor_execute", _count)
    return n[0]


def _s220_queries():
    _user220("p220_many")
    c = _login220("p220_many")
    c.get("/api/account/sessions", headers=_XHR220)          # the first call adopts/settles; count the next
    one = _queries220(c)
    for remember in (False, True, True):
        _login220("p220_many", remember=remember)
    four = _queries220(c)
    eq("sessions list: four rows cost the same queries as one (the end times are worked out, not looked up)",
       four, one)


_ENDING_JS220 = r"""
const tf = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => String(v[k]));
%s
const later = new Date(Date.now() + 5 * 86400000);
const now = new Date().toISOString();
console.log(JSON.stringify({
  remembered: ending({remember: true, idle_minutes: null, ends: later.toISOString()}),
  remembered_idle: ending({remember: true, idle_minutes: 1440, ends: later.toISOString()}),
  plain: ending({remember: false, idle_minutes: 30, ends: now}),
  plain_hours: ending({remember: false, idle_minutes: 120, ends: now}),
  plain_days: ending({remember: false, idle_minutes: 4320, ends: now}),
  plain_only: ending({remember: false, idle_minutes: null, ends: now}),
  none: ending({remember: false, idle_minutes: 30, ends: null}),
  today: at(now), other: at(later.toISOString()),
  later_text: later.toLocaleString(undefined, {hour: 'numeric', minute: '2-digit', month: 'short', day: 'numeric'}),
  now_text: new Date(now).toLocaleString(undefined, {hour: 'numeric', minute: '2-digit'})}));
"""


def _s220_js_sentence():
    name = "sessions list: the row's sentence names the kind of sign-in and its end (time alone today, date too later)"
    if not _shutil220.which("node"):
        skip(name, "no node on this machine")
        return
    with open(_os220.path.join(str(_ROOT), "panel", "static", "js", "account_sessions.js"), encoding="utf-8") as fh:
        src = fh.read()
    a, b = src.find("  function at(iso){"), src.find("  function row(s){")
    if min(a, b) < 0:
        check(name, False, "source not found")
        return
    r = _sp220.run(["node", "-"], input=_ENDING_JS220 % src[a:b], capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, check=False)
    try:
        got = _json220.loads(r.stdout.strip())
    except ValueError:
        got = {"error": (r.stdout + r.stderr)[-300:]}
    later, now = got.get("later_text"), got.get("now_text")
    eq(name, got, dict(got, **{
        "remembered": "Remembered · signs out %s" % later,
        "remembered_idle": "Remembered · signs out after 24 h idle or at %s" % later,
        "plain": "Signs out after 30 min idle or at %s" % now,
        "plain_hours": "Signs out after 2 h idle or at %s" % now,
        "plain_days": "Signs out after 3 d idle or at %s" % now,
        "plain_only": "Signs out %s" % now,
        "none": "", "today": now, "other": later}) if later and now else {"node": "ran"})


# ── 2. Settings: the step-up window ──────────────────────────────────────────────────────────────
def _note220(page, note_id):
    """Whether the note with `note_id` is shown (it carries d-none while hidden), None if absent."""
    import re
    m = re.search(r'<div class="([^"]*)" id="%s">' % note_id, page)
    return None if m is None else "d-none" not in m.group(1)


def _s220_step_up_values():
    eq("step-up setting: unset or unreadable is 10 minutes; held to 0 (off) .. 1440",
       [_sp_pol220.step_up_minutes(c) for c in ({}, {"step_up_minutes": None}, {"step_up_minutes": "abc"},
                                                 {"step_up_minutes": "Infinity"}, {"step_up_minutes": 25},
                                                 {"step_up_minutes": 10 ** 9}, {"step_up_minutes": -3},
                                                 {"step_up_minutes": 0})],
       [10, 10, 10, 10, 25, 1440, 0, 0])


def _settings_pages220(saved):
    pages = {}
    for value in (10, 40, 0):
        saved["step_up_minutes"] = value
        pages[value] = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    return pages


def _last_audit220():
    with _p9.app_context():
        r = _AL220.query.filter_by(action="settings_update").order_by(_AL220.id.desc()).first()
        return r.detail if r else None


def _s220_settings():
    saved, live = {}, {k: _p9.config.get(k) for k in _LIFE_KEYS220}
    form = {"session_idle_minutes": "30", "session_absolute_hours": "8", "remember_days": "3"}
    try:
        import panel.routes.admin_notifications as _an220
        _p9_patch(_an220, "update_config", lambda mutate: mutate(saved))
        _p9_patch(_an220, "load_config", lambda: dict(saved))
        pages = _settings_pages220(saved)
        saved["step_up_minutes"] = 10
        r = _p9_client(P9_ADMIN).post("/settings/save", data=dict(form, step_up_minutes="25"))
        stored, applied, audit = saved.get("step_up_minutes"), _p9.config.get("STEP_UP_MINUTES"), _last_audit220()
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
        kept = _p9_client(P9_ADMIN).post("/settings/save", data=form)
        kept_values = (saved.get("step_up_minutes"), _p9.config.get("STEP_UP_MINUTES"))
    finally:
        _p9.config.update(live)
        _p9_restore_all()
    _all220("step-up setting: the field shows the value in force, with NIST's 15 minutes and OWASP's lack of a "
            "number beside it",
            ['id="s-stepup" name="step_up_minutes" min="0" max="1440"' in pages[10],
             'value="10"\n                     data-owasp-max="15"' in pages[10],
             "OWASP gives no number; NIST: 15 min at most. 0 = off." in pages[10]], "")
    eq("step-up setting: 'Longer than NIST recommends' shows past 15 and the 'Off' note at 0, never inside the range",
       [(_note220(pages[v], "s-stepup-note"), _note220(pages[v], "s-stepup-off")) for v in (10, 40, 0)],
       [(False, False), (True, False), (False, True)])
    eq("step-up setting: a save stores it, puts it in force at once and names the change in the audit row",
       (r.status_code, stored, applied, audit and "step-up 10 -> 25 min" in audit), (302, 25, 25, True))
    eq("step-up setting: a save without the field (an older form) keeps the stored window and the one in force",
       (kept.status_code, kept_values), (302, (25, 25)))


def _age220(client, seconds):
    with client.session_transaction() as s:
        s["_auth_at"] = _time220.time() - seconds


def _s220_step_up_in_force():
    """The window Settings saves is the one the high-risk routes apply (here: adding a group)."""
    saved, live = {}, {k: _p9.config.get(k) for k in _LIFE_KEYS220}
    form = {"session_idle_minutes": "30", "session_absolute_hours": "8", "remember_days": "3"}
    _user220("p220_step", superadmin=True)
    try:
        import panel.routes.admin_notifications as _an220
        _p9_patch(_an220, "update_config", lambda mutate: mutate(saved))
        _p9_patch(_an220, "load_config", lambda: dict(saved))
        c = _login220("p220_step")
        _p9_client(P9_ADMIN).post("/settings/save", data=dict(form, step_up_minutes="30"))
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
        _age220(c, 20 * 60)
        long_window = c.post("/groups/add", data={"name": "p220-long"}, headers=_XHR220)
        _p9_client(P9_ADMIN).post("/settings/save", data=dict(form, step_up_minutes="5"))
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
        _age220(c, 6 * 60)
        short_window = c.post("/groups/add", data={"name": "p220-short"}, headers=_XHR220)
    finally:
        _p9.config.update(live)
        _p9_restore_all()
    eq("step-up setting: a 30-minute window saved in Settings lets a 20-minute-old proof add a group; a 5-minute "
       "one refuses a 6-minute-old proof with reauth_required",
       (long_window.status_code, _p9_json(short_window).get("error")), (200, "reauth_required"))


# ── 3. The card's sentences and the login page's "Remember me" ───────────────────────────────────
def _s220_remember_text():
    live = {k: _p9.config.get(k) for k in _LIFE_KEYS220}
    try:
        _lifetimes220(remember_d=7)
        seven = _p9.test_client().get("/login").get_data(as_text=True)
        _lifetimes220(absolute_h=30, remember_d=1)
        thirty = _p9.test_client().get("/login").get_data(as_text=True)
        _lifetimes220(remember_d=1)
        one = _p9.test_client().get("/login").get_data(as_text=True)
        _lifetimes220(remember_d=3)
        settings = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    finally:
        _p9.config.update(live)
    eq("login page: 'Remember me' says how long it lasts, from the limit the server ends it at (the absolute "
       "limit when that is longer)",
       ['<span class="small text-secondary" id="remember-for">for %s</span>' % w in p
        for p, w in ((seven, "7 days"), (thirty, "30 hours"), (one, "1 day"))], [True, True, True])
    _all220("settings: the card explains a normal sign-in and a remembered one, and which actions ask again",
            ["A normal sign-in ends after the idle timeout without use, or at the absolute limit." in settings,
             "With “Remember me”, a sign-in lasts 3 days, then asks for the password." in settings,
             "The password is asked again before a terminal" in settings,
             "A login ends after the idle timeout without use" not in settings], "")
    eq("i18n: the new sentences with values are in both catalogs",
       [k in _i18n220.catalog(lang) for lang in ("es", "fr") for k in
        ("for {lasts}", "Signs out after {idle} idle or at {when}", "Remembered · signs out {when}")],
       [True] * 6)


try:
    _p9_arm(who="part220")
    for _fn220 in (_s220_rows, _s220_end_is_the_rule, _s220_queries, _s220_js_sentence, _s220_step_up_values,
                   _s220_settings, _s220_step_up_in_force, _s220_remember_text):
        _p9_arm(who="part220")
        try:
            _fn220()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _uid220 in _IDS220:
            _US220.query.filter_by(user_id=_uid220).delete()
            _u220 = _db220.session.get(_U220, _uid220)
            if _u220 is not None:
                _db220.session.delete(_u220)
        for _g220 in _G220.query.filter(_G220.name.like("p220-%")).all():
            _db220.session.delete(_g220)
        _db220.session.commit()

check("part220: nothing reached a real transport", len(_P9_TRIPPED) == _trips220, repr(_P9_TRIPPED[_trips220:]))
