"""Part 216 of the unit suite: the panel owner account (panel/security/owner.py).

* The flag: at most one row holds it (a partial unique index), an upgrade gives it to the active
  superadmin with the lowest id, a start with an owner moves nothing, and the index is built.
* Untouchable: through /users, no other superadmin may edit, deactivate, demote, rename, reset or
  delete the panel owner; each refusal is a 403 and an access_denied audit row. The panel owner may
  still edit their own display name, and may not deactivate, demote or rename themselves. No
  account may deactivate itself.
* The Users page: the Owner badge, no Edit/Delete for anyone else on that row, and the edit data
  island leaves the row out for them.
* Transfer: owner only, to an active superadmin with 2FA on, with the password AND a live
  authenticator code (no backup code), under the shared re-authentication throttle; audited under
  both names, a notice for each account, and one owner after a race.
* The panel host's terminal and the panel backup restore are the panel owner's only.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import os as _os216
import sqlite3 as _sq216
import tempfile as _tf216

import pyotp as _pyotp216
import sqlalchemy as _sa216
from flask import Flask as _Flask216
from sqlalchemy.exc import IntegrityError as _IntegrityError216

from unit.part01 import check, eq
from unit.part12 import (P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes,
                         _p9_json, _p9_patch, _p9_restore_all)
from panel.db import models as _m216
from panel.db.models import AuditLog as _AL216, User as _U216, UserSession as _US216, db as _db216
from panel.routes import _shared as _sh216, host_terminal as _ht216, owner_transfer as _ot216
from panel.routes import panel_backup as _pb216
from panel.security import account_guard as _ag216, account_notices as _an216, auth as _auth216
from panel.security import owner as _ow216
from panel.services import notifications as _nt216

_trips216 = len(_P9_TRIPPED)
with _p9.app_context():
    _OWNER_BEFORE216 = [u.id for u in _U216.query.filter_by(is_owner=True).all()]
_IDS216 = []
_K216 = "harbour lantern quietly"          # the fixtures' password (no real credential)
_K216_WRONG = "not the password at all"
_XHR216 = {"X-Requested-With": "XMLHttpRequest"}
_NOTIFIED216 = []


def _user216(name, superadmin=True, owner=False, totp=None, active=True):
    """A fresh account with _K216 as its password; its id."""
    with _p9.app_context():
        u = _U216(username=name, password_hash=_auth216.hash_password(_K216), display_name=name,
                  is_superadmin=superadmin, is_owner=owner, is_active=active)
        if totp:
            from panel.core.config import encrypt_secret
            u.totp_secret, u.totp_enabled = encrypt_secret(totp), True
        _db216.session.add(u)
        _db216.session.commit()
        _IDS216.append(u.id)
        return u.id


def _row216(uid):
    with _p9.app_context():
        u = _db216.session.get(_U216, uid)
        return None if u is None else (u.username, u.display_name, u.is_active, u.is_superadmin,
                                       u.is_owner, u.totp_enabled, u.password_hash)


def _owners216():
    with _p9.app_context():
        return sorted(u.id for u in _U216.query.filter_by(is_owner=True).all())


def _audits216(action, since_id=0):
    with _p9.app_context():
        return [(_r.username, _r.target, _r.detail, _r.success) for _r in
                _AL216.query.filter(_AL216.action == action, _AL216.id > since_id).order_by(_AL216.id).all()]


def _last_id216():
    with _p9.app_context():
        r = _AL216.query.order_by(_AL216.id.desc()).first()
        return r.id if r else 0


def _set216(uid, **values):
    with _p9.app_context():
        u = _db216.session.get(_U216, uid)
        for k, v in values.items():
            setattr(u, k, v)
        _db216.session.commit()


def _reset216():
    _ag216.reset_throttle()
    _ag216.reset_denials()
    _sh216._REAUTH_FAILS.clear()


def _retire216():
    """Deactivate every account an earlier check made, so none is a transfer candidate any more."""
    with _p9.app_context():
        if _IDS216:
            _db216.session.execute(_sa216.update(_U216).where(_U216.id.in_(_IDS216)).values(is_active=False))
            _db216.session.commit()


def _no_owner216():
    """Clear the flag everywhere (part12's own accounts have none; a check may have set one)."""
    with _p9.app_context():
        _db216.session.execute(_sa216.update(_U216).values(is_owner=False))
        _db216.session.commit()


# ── 1. the flag ──────────────────────────────────────────────────────────────────────────────────
def _s216_unique_index():
    _no_owner216()
    a, b = _user216("p216-ix-a", owner=True), _user216("p216-ix-b")
    with _p9.app_context():
        _db216.session.get(_U216, b).is_owner = True
        try:
            _db216.session.commit()
            second = True
        except _IntegrityError216:
            _db216.session.rollback()
            second = False
    eq("owner flag: the database refuses a second panel owner", (second, _owners216()), (False, [a]))
    _no_owner216()


def _old_db216(path):
    """A database as the version before is_owner made it: no column, no index."""
    eng = _sa216.create_engine("sqlite:///" + path)
    _db216.metadata.create_all(eng)
    with eng.begin() as c:
        c.exec_driver_sql("DROP INDEX ix_user_one_owner")
        c.exec_driver_sql("ALTER TABLE user DROP COLUMN is_owner")
        for i, sup, act in ((1, 1, 0), (2, 0, 1), (3, 1, 1), (4, 1, 1)):
            c.exec_driver_sql("INSERT INTO user (id, username, password_hash, is_superadmin, is_active, "
                              "auth_epoch, last_totp_step, otp_nag_dismissed, must_change_password) "
                              "VALUES (?, ?, 'x', ?, ?, 0, 0, 0, 0)", (i, "p216-old%d" % i, sup, act))
    eng.dispose()


def _one216(path, sql):
    con = _sq216.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _s216_upgrade():
    tmp = _tf216.mkdtemp(prefix="lgsm-unit-p216-")
    path = _os216.path.join(tmp, "old.db")
    app = _Flask216("p216_upgrade")
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + path, SQLALCHEMY_TRACK_MODIFICATIONS=False)
    _db216.init_app(app)
    try:
        _old_db216(path)
        with app.app_context():
            _m216._run_light_migrations()
        first = _one216(path, "SELECT id FROM user WHERE is_owner = 1")
        idx = _one216(path, "SELECT sql FROM sqlite_master WHERE name = 'ix_user_one_owner'")
        with app.app_context():
            _m216._run_light_migrations()
            moved = _m216._ensure_one_owner()
            _db216.session.commit()
        again = _one216(path, "SELECT id FROM user WHERE is_owner = 1")
        con = _sq216.connect(path)
        con.execute("UPDATE user SET is_owner = 0")
        con.execute("UPDATE user SET is_active = 0 WHERE id = 3")
        con.commit()
        con.close()
        with app.app_context():
            gave = _m216._ensure_one_owner()
            _db216.session.commit()
        after = _one216(path, "SELECT id FROM user WHERE is_owner = 1")
    finally:
        with app.app_context():
            _db216.session.remove()
            _db216.engine.dispose()
        import shutil as _shutil216
        _shutil216.rmtree(tmp, ignore_errors=True)
    eq("owner flag: an upgrade adds the column and makes the active superadmin with the lowest id the panel "
       "owner (an inactive one and a plain account with lower ids are passed over)", first, [(3,)])
    check("owner flag: ...and builds the unique partial index on an upgraded database",
          bool(idx) and "UNIQUE" in idx[0][0].upper() and "is_owner = 1" in idx[0][0], repr(idx))
    eq("owner flag: a later start, with a panel owner, moves nothing", (again, moved), ([(3,)], False))
    eq("owner flag: a database left with no panel owner gets one at the next start, the next active "
       "superadmin", (after, gave), ([(4,)], True))


# ── 2. untouchable through /users ───────────────────────────────────────────────────────────────
def _edit216(actor, target, **form):
    data = {"username": form.pop("username", None) or _row216(target)[0], "is_active": "on",
            "is_superadmin": "on", "display_name": "p216 edited"}
    data.update(form)
    data = {k: v for k, v in data.items() if v is not None}
    return _p9_client(actor).post("/users/%d/edit" % target, data=data, headers=_XHR216)


def _s216_others_refused():
    _no_owner216()
    own = _user216("p216-own", owner=True, totp=_pyotp216.random_base32())
    other = _user216("p216-other")
    before = _row216(own)
    since = _last_id216()
    out = {}
    for label, form in (("display name", {}), ("deactivate", {"is_active": None}),
                        ("demote", {"is_superadmin": None}), ("rename", {"username": "p216-taken"}),
                        ("reset password", {"reset_password": "on"}), ("reset 2fa", {"reset_2fa": "on"})):
        r = _edit216(other, own, **form)
        out[label] = (r.status_code, _p9_json(r).get("message"))
    r = _p9_client(other).post("/users/%d/delete" % own, headers=_XHR216)
    out["delete"] = (r.status_code, _p9_json(r).get("message"))
    eq("untouchable: another superadmin's edit of the panel owner is refused whole, every kind of it",
       {k: v for k, v in out.items() if k != "delete"},
       {k: (403, _ow216.NOT_YOURS) for k in ("display name", "deactivate", "demote", "rename",
                                              "reset password", "reset 2fa")})
    eq("untouchable: ...and so is deleting the panel owner", out["delete"], (403, _ow216.NO_DELETE))
    eq("untouchable: ...and the account is exactly as it was (name, active, superadmin, owner, 2FA, password)",
       _row216(own), before)
    rows = _audits216("access_denied", since)
    check("untouchable: each refusal is an access_denied audit row naming who asked and whose account",
          len(rows) == 7 and all(r[0] == "p216-other" and r[1] == "p216-own" and r[3] is False for r in rows)
          and "deletion of the panel owner's account" in rows[-1][2], repr(rows))
    _edit216(other, other)                       # positive control: a non-owner peer is still editable
    r = _edit216(own, other, is_active=None)
    check("untouchable: the panel owner can still deactivate another superadmin (control)",
          r.status_code == 200 and _row216(other)[2] is False, repr((r.status_code, _p9_json(r))))


def _s216_self_edits():
    _no_owner216()
    own = _user216("p216-self", owner=True)
    peer = _user216("p216-peer")
    r = _edit216(own, own, display_name="p216 my name")
    check("own row: the panel owner may change their own display name",
          r.status_code == 200 and _row216(own)[1] == "p216 my name", repr((r.status_code, _p9_json(r))))
    out = {}
    for label, form in (("deactivate", {"is_active": None}), ("demote", {"is_superadmin": None}),
                        ("rename", {"username": "p216-self2"})):
        r = _edit216(own, own, **form)
        out[label] = (r.status_code, _p9_json(r).get("message"))
    eq("own row: the panel owner may not deactivate, demote or rename themselves",
       out, {"deactivate": (403, _ow216.NO_DEACTIVATE), "demote": (403, _ow216.NO_DEMOTE),
             "rename": (403, _ow216.NO_RENAME)})
    eq("own row: ...and is still active, a superadmin, the panel owner, and named as before",
       _row216(own)[0:1] + _row216(own)[2:5], ("p216-self", True, True, True))
    r = _edit216(peer, peer, is_active=None)
    eq("own row: no account may deactivate itself (a non-owner superadmin here)",
       (r.status_code, _p9_json(r).get("message"), _row216(peer)[2]), (403, _ow216.NO_SELF_DEACTIVATE, True))


# ── 3. the Users page ────────────────────────────────────────────────────────────────────────────
def _s216_users_page():
    _no_owner216()
    own = _user216("p216-page-own", owner=True)
    other = _user216("p216-page-other")
    as_other = _p9_client(other).get("/users").get_data(as_text=True)
    as_own = _p9_client(own).get("/users").get_data(as_text=True)
    island = as_other.split('id="users-data"', 1)[-1].split("</script>", 1)[0]
    own_island = as_own.split('id="users-data"', 1)[-1].split("</script>", 1)[0]
    check("users page: the panel owner's row carries the Owner badge",
          ">Owner</span>" in as_other and ">Owner</span>" in as_own, "")
    check("users page: another superadmin is offered neither Edit nor Delete on that row, and the edit data "
          "leaves it out", "/users/%d/delete" % own not in as_other
          and 'data-args=\'[%d]\'' % own not in as_other and '"id": %d,' % own not in island
          and "Only the panel owner can change the owner's account." in as_other, island[:300])
    check("users page: ...while another superadmin's row keeps both (control)",
          "/users/%d/delete" % other in as_own and 'data-args=\'[%d]\'' % other in as_own, "")
    check("users page: the panel owner edits their own row, marked as their own and as the owner's, and is "
          "offered no Delete on it", 'data-args=\'[%d]\'' % own in as_own and "/users/%d/delete" % own not in as_own
          and '"id": %d,' % own in own_island and '"is_owner": true,\n  "is_self": true' in own_island,
          own_island[:400])


# ── 4. transfer ──────────────────────────────────────────────────────────────────────────────────
def _transfer216(actor, target, secret, password=_K216, code=None):
    c = _p9_client(actor)
    data = {"new_owner": str(target), "password": password,
            "totp_code": code if code is not None else (_pyotp216.TOTP(secret).now() if secret else "")}
    r = c.post("/account/owner/transfer", data=data)
    return r, _p9_flashes(c)


def _transfer_rig216(tag):
    """A panel owner and a successor, both with 2FA; plus accounts ownership may not go to.

    Named p216-<tag>-own, p216-<tag>-new and so on.
    """
    _no_owner216()
    _reset216()
    _retire216()
    s_own, s_new = _pyotp216.random_base32(), _pyotp216.random_base32()
    ids = {"own": _user216("p216-%s-own" % tag, owner=True, totp=s_own),
           "new": _user216("p216-%s-new" % tag, totp=s_new),
           "no2fa": _user216("p216-%s-no2fa" % tag),
           "inactive": _user216("p216-%s-off" % tag, totp=_pyotp216.random_base32(), active=False),
           "plain": _user216("p216-%s-plain" % tag, superadmin=False, totp=_pyotp216.random_base32())}
    return ids, s_own, s_new


def _s216_transfer_refusals():
    ids, s_own, _s_new = _transfer_rig216("tr")
    since = _last_id216()
    out = {}
    for label in ("no2fa", "inactive", "plain"):
        out[label] = _transfer216(ids["own"], ids[label], s_own)[1]
    out["self"] = _transfer216(ids["own"], ids["own"], s_own)[1]
    out["garbage"] = _transfer216(ids["own"], "1" * 30, s_own)[1]
    eq("transfer: ownership goes only to another active superadmin with 2FA on",
       out, {k: [_ot216.NOT_ELIGIBLE] for k in ("no2fa", "inactive", "plain", "self", "garbage")})
    out = {"password": _transfer216(ids["own"], ids["new"], s_own, password=_K216_WRONG)[1],
           "code": _transfer216(ids["own"], ids["new"], s_own, code="000000")[1]}
    with _p9.app_context():
        backup = "p216backupcode"
        u = _db216.session.get(_U216, ids["own"])
        u.set_backup_codes([backup])
        _db216.session.commit()
    out["backup code"] = _transfer216(ids["own"], ids["new"], s_own, code=backup)[1]
    eq("transfer: a wrong password, a wrong code and a backup code are each refused",
       out, {"password": [_ot216.WRONG_PASSWORD], "code": [_ot216.WRONG_CODE],
             "backup code": [_ot216.WRONG_CODE]})
    _set216(ids["own"], last_totp_step=10 ** 12)
    eq("transfer: an authenticator code already spent is refused (one use per code)",
       _transfer216(ids["own"], ids["new"], s_own)[1], [_ot216.REPLAYED_CODE])
    _set216(ids["own"], totp_enabled=False)
    eq("transfer: a panel owner without 2FA is told to turn it on first",
       _transfer216(ids["own"], ids["new"], None, code="")[1], [_ot216.NEEDS_2FA])
    rows = _audits216("owner_transferred", since)
    check("transfer: every refused attempt is a failed owner_transferred audit row",
          len(rows) == 10 and all(r[3] is False and r[2].startswith("refused: ") for r in rows), repr(rows))
    eq("transfer: ...and the panel owner never moved", _owners216(), [ids["own"]])


def _s216_transfer_not_owner():
    ids, _s_own, s_new = _transfer_rig216("tn")
    since = _last_id216()
    r = _p9_client(ids["new"]).post("/account/owner/transfer", headers=_XHR216, data={
        "new_owner": str(ids["new"]), "password": _K216, "totp_code": _pyotp216.TOTP(s_new).now()})
    eq("transfer: an account that is not the panel owner is refused with a 403 and an access_denied row",
       (r.status_code, _p9_json(r).get("message"), [(a[0], a[3]) for a in _audits216("access_denied", since)],
        _owners216()), (403, _ot216.NOT_OWNER, [("p216-tn-new", False)], [ids["own"]]))


def _s216_transfer_throttle():
    ids, s_own, _s_new = _transfer_rig216("tt")
    from app import LOGIN_MAX_FAILS
    c = _p9_client(ids["own"])
    for _i in range(LOGIN_MAX_FAILS):
        c.post("/account/2fa/disable", data={"password": _K216_WRONG, "totp_code": "000000"})
    _p9_flashes(c)
    eq("transfer: under the shared re-authentication budget — wrong passwords on the 2FA switch-off use it "
       "up, and then even the right password and code are refused",
       (_transfer216(ids["own"], ids["new"], s_own)[1], _owners216()),
       ([_sh216.REAUTH_BLOCKED_MSG], [ids["own"]]))
    _reset216()


def _s216_transfer_done():
    ids, s_own, _s_new = _transfer_rig216("td")
    _NOTIFIED216.clear()
    _p9_patch(_nt216, "notify", lambda *a, **k: _NOTIFIED216.append(a))
    since = _last_id216()
    r, flashes = _transfer216(ids["own"], ids["new"], s_own)
    eq("transfer: the panel owner's password and a live code move ownership to the chosen account",
       (r.status_code, flashes, _owners216()),
       (302, ["Ownership transferred to p216-td-new. You are still a superadmin."], [ids["new"]]))
    eq("transfer: ...and the old panel owner is still an active superadmin", _row216(ids["own"])[2:5],
       (True, True, False))
    rows = _audits216("owner_transferred", since)
    eq("transfer: audited as owner_transferred under each account, both naming the two",
       [(r[1], r[2], r[3]) for r in rows],
       [(n, "ownership moved from 'p216-td-own' to 'p216-td-new'", True) for n in ("p216-td-own", "p216-td-new")])
    with _p9.app_context():
        notes = [[lbl for lbl, _w, _ip in _an216.recent_changes(_db216.session.get(_U216, i))]
                 for i in (ids["own"], ids["new"])]
    eq("transfer: each account's Account page lists it among its recent security changes",
       notes, [["Panel ownership transferred"], ["Panel ownership transferred"]])
    check("transfer: ...and the panel-wide channels are told", any(a[0] == "account_change" and
          "p216-td-new" in a[2] for a in _NOTIFIED216), repr(_NOTIFIED216))
    page = _p9_client(ids["new"]).get("/account").get_data(as_text=True)
    check("transfer: the new panel owner's Account page offers the transfer to the old one",
          'id="sec-owner"' in page and '<option value="%d" data-no-i18n>p216-td-own</option>' % ids["own"] in page, "")
    old_page = _p9_client(ids["own"]).get("/account").get_data(as_text=True)
    check("transfer: ...and the old panel owner's no longer shows it", 'id="sec-owner"' not in old_page, "")


def _s216_transfer_race():
    ids, s_own, _s_new = _transfer_rig216("rc")
    racer = _user216("p216-rc-racer", totp=_pyotp216.random_base32())
    real_release = _ot216.reauth_release

    def _meanwhile(u, stamp):
        """Another request moves ownership while this one is between its checks and its move."""
        real_release(u, stamp)
        with _p9.app_context():
            ok = _ow216.transfer(_db216.session.get(_U216, ids["own"]), _db216.session.get(_U216, racer))
            _NOTIFIED216.append(("race", ok))
    _NOTIFIED216.clear()
    _p9_patch(_ot216, "reauth_release", _meanwhile)
    r, flashes = _transfer216(ids["own"], ids["new"], s_own)
    eq("transfer: two transfers racing from the same panel owner leave exactly one owner, the first to land, "
       "and the second says nothing moved", (flashes, _owners216(), _NOTIFIED216[:1]),
       ([_ot216.CHANGED_MEANWHILE], [racer], [("race", True)]))


def _s216_account_page():
    ids, _s_own, _s_new = _transfer_rig216("ap")
    _set216(ids["new"], is_active=False)
    page = _p9_client(ids["own"]).get("/account").get_data(as_text=True)
    check("account page: with nobody eligible, the panel owner is told who ownership can go to, and offered no "
          "form", 'id="sec-owner"' in page and "and there is none yet" in page
          and "account_owner_transfer" not in page and "/account/owner/transfer" not in page, "")
    _set216(ids["own"], totp_enabled=False)
    page = _p9_client(ids["own"]).get("/account").get_data(as_text=True)
    check("account page: without 2FA, the panel owner is told to turn it on first",
          "Turn on two-factor authentication first" in page and "/account/owner/transfer" not in page, "")


# ── 5. the panel host's shell and the panel backup restore ──────────────────────────────────────
def _s216_terminal():
    _no_owner216()
    own = _user216("p216-term-own", owner=True)
    other = _user216("p216-term-other")
    with _p9.app_context():
        local = _db216.session.get(_m216.RemoteServer, P9_LOCAL)
        remote = _db216.session.get(_m216.RemoteServer, P9_HOST)
        verdicts = [_ht216.may_shell_on(_db216.session.get(_U216, u), h) for u in (own, other)
                    for h in (local, remote)]
    eq("terminal: a shell on the panel host is the panel owner's only; any superadmin keeps remote hosts",
       verdicts, [True, True, False, True])
    r = _p9_client(other).get("/terminal/%d" % P9_LOCAL, headers=_XHR216)
    check("terminal: ...and the page route refuses another superadmin with a 403",
          r.status_code == 403 and "panel owner only" in r.get_data(as_text=True),
          repr((r.status_code, r.headers.get("Location"), r.get_data(as_text=True)[:200])))


def _s216_restore():
    _no_owner216()
    own = _user216("p216-rs-own", owner=True)
    other = _user216("p216-rs-other")
    called = []
    _p9_patch(_pb216.bk, "restore_backup", lambda *a, **k: called.append(a) or (False, "Backup not found."))
    since = _last_id216()
    r = _p9_client(other).post("/api/panel/backup/restore", json={"name": "x.tar.gz"})
    eq("restore: another superadmin's panel backup restore is refused with a 403 and never runs",
       (r.status_code, _p9_json(r).get("message"), called), (403, _ow216.RESTORE_OWNER_ONLY, []))
    check("restore: ...and is an access_denied audit row", [(a[0], a[3]) for a in
          _audits216("access_denied", since)] == [("p216-rs-other", False)], repr(_audits216("access_denied", since)))
    _p9_client(own).post("/api/panel/backup/restore", json={"name": "x.tar.gz"})
    eq("restore: the panel owner's restore reaches the restore (control)", len(called), 1)
    _p9_patch(_pb216, "_fetch_backup_listings", lambda *a, **k: ({}, {}))
    _p9_patch(_pb216.bk, "list_backups", lambda: [])
    flags = [_p9_json(_p9_client(u).get("/api/panel/backups")).get("can_restore") for u in (own, other)]
    eq("restore: the backups list offers Restore to the panel owner only", flags, [True, False])


try:
    _p9_arm(who="part216")
    for _fn216 in (_s216_unique_index, _s216_upgrade, _s216_others_refused, _s216_self_edits,
                   _s216_users_page, _s216_transfer_refusals, _s216_transfer_not_owner,
                   _s216_transfer_throttle, _s216_transfer_done, _s216_transfer_race,
                   _s216_account_page, _s216_terminal, _s216_restore):
        _p9_arm(who="part216")
        try:
            _fn216()
        finally:
            _p9_restore_all()
            _reset216()
finally:
    _p9_restore_all()
    _reset216()
    _no_owner216()
    with _p9.app_context():
        for _uid216 in _OWNER_BEFORE216:          # part12's own panel owner, as it was
            _db216.session.get(_U216, _uid216).is_owner = True
        for _uid216 in _IDS216:
            _US216.query.filter_by(user_id=_uid216).delete()
            _u216 = _db216.session.get(_U216, _uid216)
            if _u216 is not None:
                _db216.session.delete(_u216)
        _db216.session.commit()

check("part216: nothing reached a real transport", len(_P9_TRIPPED) == _trips216, repr(_P9_TRIPPED[_trips216:]))
