"""Part 222 of the unit suite: Origin verification, the split style policy and the invite's second code.

* Origin (OWASP CSRF Prevention, "Fetch Metadata headers" and "Using Standard Headers to Verify
  Origin"): a state-changing request without Sec-Fetch-Site, or with same-site, is refused when its
  Origin (or, without one, its Referer) is not the panel's own, "null" included; same-origin, a
  cookie-less API token and a request with neither header pass; the step-up round trip still works.
* Styles (OWASP CSP Cheat Sheet; CSP Level 3 style-src-elem / style-src-attr): <style> blocks need
  the nonce, every template's <style> carries it, and the terminal gives xterm's blocks the nonce.
* Invite code (OWASP Authentication "Account Lockout", Forgot Password "PINs"; NIST SP 800-63B
  out-of-band): shown once at creation, stored as Argon2id, asked before the account form, bound to
  its invite, and the fifth wrong code revokes the invite with an audit row and an alert.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import os as _os222
import re as _re222

from unit import REPO_ROOT
from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.db.models import (AuditLog as _AL222, Group as _G222, Invite as _Inv222, User as _U222,
                             UserSession as _US222, db as _db222, _LIGHT_MIGRATIONS as _LM222)
from panel.routes import account_security as _as222, admin_notifications as _an222
from panel.security import account_guard as _ag222, auth as _auth222

_trips222 = len(_P9_TRIPPED)
_IDS222 = []
_K222 = "orchard lantern quietly"          # the fixtures' password (no real credential)
_K222_NEW = "copper meadow whistle harbour"   # the password an invitee picks (no real credential)
_XHR222 = {"X-Requested-With": "XMLHttpRequest"}
_POST222 = "/api/account/ui-order/reset"   # a state-changing route any signed-in account may call
_NOTES222 = []


def _all222(name, conds, detail=""):
    """check() over a list of conditions, so a check of several facts stays one branch."""
    check(name, all(conds), detail)


def _user222(name, superadmin=False):
    """A fresh account with _K222 as its password; its id."""
    with _p9.app_context():
        u = _U222(username=name, password_hash=_auth222.hash_password(_K222), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        _db222.session.add(u)
        _db222.session.commit()
        _IDS222.append(u.id)
        return u.id


def _last_id222():
    with _p9.app_context():
        r = _AL222.query.order_by(_AL222.id.desc()).first()
        return r.id if r else 0


def _audits222(action, since_id=0):
    with _p9.app_context():
        return [(_r.username, _r.detail, _r.success) for _r in
                _AL222.query.filter(_AL222.action == action, _AL222.id > since_id).order_by(_AL222.id).all()]


def _post222(client, **headers):
    """POST the probe route with these headers; its status.

    The denial log's rate limit is reset first, so every refusal writes its own row.
    """
    _ag222.reset_denials()
    return client.post(_POST222, headers=dict(_XHR222, **headers)).status_code


# ── 1. Origin verification ───────────────────────────────────────────────────────────────────────
def _s222_origin_header():
    _ag222.reset_denials()
    first = _last_id222()
    a = _p9_client(P9_ADMIN)
    got = [_post222(a, Origin="https://evil.test"), _post222(a, Origin="null"),
           _post222(a, Origin="http://localhost"), _post222(a, Origin="http://localhost:8123"),
           _post222(a, **{"Origin": "https://evil.test", "Sec-Fetch-Site": "same-site"}),
           _post222(a, **{"Origin": "https://evil.test", "Sec-Fetch-Site": "same-origin"}),
           _post222(a, **{"Origin": "https://evil.test", "Sec-Fetch-Site": "unheard-of"})]
    eq("origin: without Fetch Metadata a foreign Origin, null and another port are refused and the panel's own "
       "passes; same-site and an unknown value are verified, same-origin is the browser's word",
       got, [403, 403, 200, 403, 403, 200, 403])
    rows = _audits222("csrf_rejected", first)
    _all222("origin: each refusal is audited once as csrf_rejected, naming the header and the origin",
            [len(rows) == 5, "foreign Origin 'https://evil.test' on POST" in (rows[0][1] if rows else ""),
             _audits222("access_denied", first) == []], repr(rows))
    r = a.post(_POST222, headers=dict(_XHR222, Origin="https://evil.test"))
    check("origin: the refusal answers JSON in plain words",
          _p9_json(r).get("message") == "That request did not come from this panel's own page and was refused.",
          repr(_p9_json(r)))


def _s222_referer_and_none():
    a = _p9_client(P9_ADMIN)
    got = [_post222(a, Referer="https://evil.test/page"), _post222(a, Referer="http://localhost/settings"),
           _post222(a, Referer="file:///home/x.html"), _post222(a),
           a.get("/api/auth/ping", headers={"Origin": "https://evil.test"}).status_code]
    eq("origin: without Origin a foreign or non-http Referer is refused, the panel's own passes, neither header "
       "leaves it to the token, and a GET is never checked", got, [403, 200, 403, 200, 200])


def _s222_proxy_and_bearer():
    a = _p9_client(P9_ADMIN)
    fwd = _post222(a, **{"Origin": "https://panel.example.test", "X-Forwarded-Host": "panel.example.test"})
    other = _post222(a, **{"Origin": "https://panel.example.test", "X-Forwarded-Host": "else.example.test"})
    bare = _p9.test_client()
    bearer = bare.post(_POST222, headers=dict(_XHR222, Origin="https://evil.test",
                                              Authorization="Bearer not-a-real-token"))
    _all222("origin: the host a proxy forwarded is the panel's own, another is not; a cookie-less API token "
            "is not checked (nothing for another site to ride) and meets the token check instead",
            [fwd == 200, other == 403, bearer.status_code in (401, 302)], repr((fwd, other, bearer.status_code)))
    eq("origin: the Referer's origin keeps its port and brackets an IPv6 host; junk reads as no origin",
       [_as222._referer_origin(v) for v in ("https://p.example.test:8443/x?y", "http://[2001:db8::1]:5000/",
                                            "javascript:alert(1)", "http://[bad", None, "")],
       ["https://p.example.test:8443", "http://[2001:db8::1]:5000", "", "", None, None])


def _s222_step_up_round_trip():
    _ag222.reset_denials()
    _user222("p222_step", superadmin=True)
    c = _p9.test_client()
    c.post("/login", data={"username": "p222_step", "password": _K222})
    with c.session_transaction() as s:
        s["_auth_at"] = 0
    own = {"Origin": "http://localhost"}
    nav = c.post("/groups/add", data={"name": "p222-a"}, headers=dict(own, Referer="http://localhost/groups"))
    evil = c.post("/account/reauth", data={"password": _K222, "next": "/groups"},
                  headers={"Origin": "https://evil.test"})
    right = c.post("/account/reauth", data={"password": _K222, "next": "/groups"}, headers=own)
    again = c.post("/groups/add", data={"name": "p222-a"}, headers=dict(_XHR222, **own))
    with _p9.app_context():
        made = [g.name for g in _G222.query.filter(_G222.name == "p222-a").all()]
    _all222("origin: a step-up still goes to the confirm page and back with the panel's own Origin, and a "
            "confirm posted from another site is refused",
            [nav.status_code == 302, "/account/reauth?next=%2Fgroups" in nav.headers.get("Location", ""),
             evil.status_code == 403, right.status_code == 302,
             right.headers.get("Location", "").endswith("/groups"), again.status_code == 200, made == ["p222-a"]],
            repr((nav.status_code, evil.status_code, right.status_code, again.status_code, made)))


# ── 2. Styles ────────────────────────────────────────────────────────────────────────────────────
def _read222(*rel):
    with open(_os222.path.join(REPO_ROOT, *rel), encoding="utf-8") as fh:
        return fh.read()


def _s222_style_policy():
    src = _read222("panel", "install", "app.py")
    csp = src[src.index("    def _csp():"):src.index("    @app.after_request")]
    _all222("csp: <style> blocks need 'self' or the nonce (style-src-elem), attributes are allowed on their own "
            "directive, and style-src keeps 'unsafe-inline' only as the fallback for older browsers",
            [csp.count("style-src-elem 'self' 'nonce-%s'; ") == 1, csp.count("style-src-attr 'unsafe-inline'; ") == 1,
             "style-src 'self' 'unsafe-inline'; " in csp, csp.count("'nonce-%s'") == 2], csp[-500:])
    tdir = _os222.path.join(REPO_ROOT, "panel", "templates")
    bare, seen = [], 0
    for name in sorted(_os222.listdir(tdir)):
        if name.endswith(".html"):
            for tag in _re222.findall(r"<style\b[^>]*>", _read222("panel", "templates", name)):
                seen += 1
                if 'nonce="{{ csp_nonce }}"' not in tag:
                    bare.append(name)
    check("csp: every <style> block in the templates carries the request's nonce", seen >= 5 and bare == [],
          "%d blocks, without the nonce: %r" % (seen, bare))


def _s222_terminal_nonce():
    js = _read222("panel", "static", "js", "host_terminal.js")
    _all222("csp: the terminal gives the <style> blocks xterm makes in open() this script's nonce, and puts "
            "createElement back afterwards",
            ["var STYLE_NONCE = (document.currentScript && document.currentScript.nonce) || '';" in js,
             "withStyleNonce(function () { term.open(host); });" in js, "term.open(host);\n" not in js,
             "try { return fn(); } finally { document.createElement = make; }" in js,
             "el.setAttribute('nonce', STYLE_NONCE)" in js], "")


# ── 3. The invite's second code ──────────────────────────────────────────────────────────────────
def _mint222(client, **form):
    r = client.post("/users/invite", data=dict({"hours": "2", "note": "p222"}, **form), headers=_XHR222)
    cred = _p9_json(r).get("credential") or {}
    token = cred.get("password", "").rsplit("/invite/", 1)[-1]
    with _p9.app_context():
        inv = _Inv222.by_token(token)
        return token, cred.get("code"), (inv.id, inv.code_hash) if inv else (None, None)


def _admin222():
    with _p9.app_context():
        _ag222.reset_throttle()
    return _p9_client(_user222("p222_admin%d" % len(_IDS222), superadmin=True))


def _s222_mint():
    a = _admin222()
    sup = _mint222(a, is_superadmin="on")
    on = _mint222(a, require_code="on")
    off = _mint222(a)
    _all222("invite code: a superadmin invite always gets a code even with the switch off, another gets one "
            "when asked, and none when not",
            [bool(sup[1]) and bool(sup[2][1]), bool(on[1]) and bool(on[2][1]), off[1] is None, off[2][1] is None],
            repr((sup[1], on[1], off[1])))
    check("invite code: eight digits shown once as two groups of four, stored only as Argon2id",
          bool(_re222.fullmatch(r"\d{4} \d{4}", sup[1] or "")) and sup[2][1].startswith("$argon2id$")
          and sup[1].replace(" ", "") not in sup[2][1], repr((sup[1], (sup[2][1] or "")[:20])))
    page = a.get("/users").get_data(as_text=True)
    _all222("invite code: the create form's switch starts on, and the credential modal has the code's field",
            ['name="require_code" class="form-check-input" role="switch"\n                   id="inv-code" checked>'
             in page, 'id="cred-code-block" hidden' in page, 'data-action="copyInviteCode"' in page,
             'data-action="syncInviteCode" data-on="change"' in page], "")


def _redeem222(client, token, **form):
    r = client.post("/invite/" + token, data=form) if form else client.get("/invite/" + token)
    return r.status_code, r.get_data(as_text=True)


def _account222(name):
    return {"username": name, "password": _K222_NEW, "confirm_password": _K222_NEW}


def _made222(name):
    with _p9.app_context():
        return _U222.query.filter_by(username=name).first() is not None


def _s222_redeem():
    a = _admin222()
    token, code, (iid, _h) = _mint222(a, require_code="on")
    v = _p9.test_client()
    ask = _redeem222(v, token)
    skip = _redeem222(v, token, **_account222("p222_skip"))
    right = _redeem222(v, token, invite_code=code.replace(" ", "-"))
    made = _redeem222(v, token, **_account222("p222_new"))
    _IDS222.extend(u for u in [_uid222("p222_new")] if u)
    _all222("invite code: the link asks for the code first; the account form posted without it makes nothing",
            [ask[0] == 200, 'name="invite_code"' in ask[1], 'name="username"' not in ask[1],
             skip[0] == 200, 'name="invite_code"' in skip[1], not _made222("p222_skip")], repr((ask[0], skip[0])))
    _all222("invite code: the right code (dashes and spaces ignored) opens the account form, which then makes "
            "the account",
            [right[0] == 200, 'name="username"' in right[1], made[0] == 302, _made222("p222_new")],
            repr((right[0], made[0])))
    with v.session_transaction() as s:
        check("invite code: the browser's 'code entered' mark is dropped once the account exists",
              _an222._CODE_OK not in s, repr(dict(s)))
    check("invite code: the invite is then used", _state222(iid) == "used", _state222(iid))


def _uid222(name):
    with _p9.app_context():
        u = _U222.query.filter_by(username=name).first()
        return u.id if u else None


def _state222(iid):
    with _p9.app_context():
        inv = _db222.session.get(_Inv222, iid)
        return inv.state if inv else None


def _s222_bound_and_legacy():
    a = _admin222()
    t1, c1, _i1 = _mint222(a, require_code="on")
    t2, _c2, _i2 = _mint222(a, require_code="on")
    t3, c3, _i3 = _mint222(a)
    v = _p9.test_client()
    _redeem222(v, t1, invite_code=c1)
    other = _redeem222(v, t2)
    legacy = _redeem222(v, t3)
    _all222("invite code: a code entered for one invite does not open another, and an invite made without "
            "one goes straight to the account form",
            ['name="invite_code"' in other[1], 'name="username"' not in other[1], c3 is None,
             'name="username"' in legacy[1], 'name="invite_code"' not in legacy[1]], "")


def _s222_burn():
    a = _admin222()
    token, code, (iid, _h) = _mint222(a, require_code="on", note="p222 burn")
    first = _last_id222()
    _NOTES222.clear()
    _p9_patch(_an222.notifications, "notify", lambda *args, **_kw: _NOTES222.append(args))
    v = _p9.test_client()
    wrong = "0000 0000" if code != "0000 0000" else "1111 1111"
    tries = [_redeem222(v, token, invite_code=wrong) for _ in range(_Inv222.CODE_MAX_TRIES)]
    after = _redeem222(v, token, invite_code=code)
    _all222("invite code: each wrong code says how many tries are left; the fifth revokes the invite",
            [[t[0] for t in tries] == [400, 400, 400, 400, 404], "Tries left: 4." in tries[0][1],
             "Tries left: 1." in tries[3][1], "Too many wrong codes" in tries[4][1],
             after[0] == 404, _state222(iid) == "burned"], repr([t[0] for t in tries] + [after[0], _state222(iid)]))
    wrongs, burned = _audits222("invite_code_wrong", first), _audits222("invite_burned", first)
    _all222("invite code: every wrong code is audited, the revocation once, and the administrators are alerted",
            [len(wrongs) == 5, all(w[2] is False for w in wrongs), len(burned) == 1,
             "revoked after 5 wrong codes" in (burned[0][1] if burned else ""),
             [n[1] for n in _NOTES222] == ["Invite revoked after wrong codes"]], repr((wrongs, burned, _NOTES222)))


def _s222_counter_and_migration():
    a = _admin222()
    iid = _mint222(a, require_code="on")[2][0]
    with _p9.test_request_context("/invite/x", method="POST"):
        inv = _db222.session.get(_Inv222, iid)
        _inv_plain = _Inv222(code_hash=None)
        lefts = [_an222._count_wrong_code(inv) for _ in range(3)]
        matches = [inv.code_matches(x) for x in ("", "12345678x", "1234567")] + [_inv_plain.code_matches("12345678")]
    eq("invite code: the counter counts down from the stored count, and junk, short input or an invite with no "
       "code never matches", (lefts, matches), ([4, 3, 2], [False, False, False, False]))
    _all222("invite code: both columns have a light-migration entry, so an existing panel gains them",
            [_LM222.get(("invite", "code_hash")) == "ALTER TABLE invite ADD COLUMN code_hash VARCHAR(255)",
             _LM222.get(("invite", "code_failures"))
             == "ALTER TABLE invite ADD COLUMN code_failures INTEGER DEFAULT 0"], "")


def _s222_cred_code_js():
    from unit.part47 import _cut47, _node47
    src = _read222("panel", "static", "js", "manage_users.js")
    prog = ("const mk = k => ({kind: k, hidden: false, getAttribute: () => k});\n"
            "const modal = {querySelectorAll: () => [mk('password'), mk('invite')]};\n"
            "const box = {value: 'stale'}, block = {hidden: true}, note = {hidden: true};\n"
            "const pw = {value: '', setAttribute(){}};\n"
            "const els = {'cred-user': {textContent: ''}, 'cred-pw': pw, credentialModal: modal,\n"
            "  'cred-code': box, 'cred-code-block': block, 'cred-code-note': note};\n"
            "global.window = global; global.document = {getElementById: id => els[id] || null};\n"
            "global.bootstrap = {Modal: function(){ this.show = () => 0; }};\n"
            + _cut47(src, "function _credShowCode(") + "\n"
            + _cut47(src, "window.showCredential = function") + "\n"
            "const snap = () => [box.value, block.hidden, note.hidden];\n"
            "showCredential({username: 'Invite link', password: 'https://x/invite/a', kind: 'invite', code: '1234 5678'});\n"
            "const withCode = snap();\n"
            "showCredential({username: 'Invite link', password: 'https://x/invite/b', kind: 'invite'});\n"
            "const without = snap();\n"
            "showCredential({username: 'alice', password: 'pw-1', code: '9999 9999'});\n"
            "console.log(JSON.stringify({withCode, without, password: snap()}));\n")
    out = _node47(prog)
    if out is None:
        skip("invite code: the credential dialog shows an invite's code", "node is not installed here")
        return
    eq("invite code: the credential dialog shows an invite's code with its note, and clears and hides both for an "
       "invite without one and for a password", out,
       {"withCode": ["1234 5678", False, False], "without": ["", True, True], "password": ["", True, True]})


try:
    for _fn222 in (_s222_origin_header, _s222_referer_and_none, _s222_proxy_and_bearer, _s222_step_up_round_trip,
                   _s222_style_policy, _s222_terminal_nonce, _s222_mint, _s222_redeem, _s222_bound_and_legacy,
                   _s222_burn, _s222_counter_and_migration, _s222_cred_code_js):
        _p9_arm(who="part222")
        try:
            _fn222()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _ag222.reset_denials()
    _ag222.reset_throttle()
    with _p9.app_context():
        _Inv222.query.filter(_Inv222.note.like("p222%")).delete(synchronize_session=False)
        _G222.query.filter(_G222.name.like("p222-%")).delete(synchronize_session=False)
        for _id222 in _IDS222:
            _US222.query.filter_by(user_id=_id222).delete()
            _u222 = _db222.session.get(_U222, _id222)
            if _u222 is not None:
                _db222.session.delete(_u222)
        _db222.session.commit()

check("part222: nothing reached a real transport", len(_P9_TRIPPED) == _trips222, repr(_P9_TRIPPED[_trips222:]))
