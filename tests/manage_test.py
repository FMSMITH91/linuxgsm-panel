#!/usr/bin/env python3
"""Tests for manage.py — the offline recovery CLI.

This is the tool you reach for when the web UI can't help: a forgotten password, a deactivated
sole admin, a 2FA device that's gone. It had no tests at all (0% coverage), which is a bad place
for a gap — its whole job is to work on the day everything else doesn't.

The properties that matter, in order:

  1. deactivating or demoting the LAST active superadmin is refused, and rolled back. A recovery
     tool that can brick the panel is worse than no recovery tool.
  2. a password reset revokes existing sessions (auth_epoch), or a stolen cookie survives the reset
     that was meant to lock the thief out.
  3. disable-2fa clears the SECRET, not just the flag — leaving the secret behind means re-enabling
     silently restores the old device.
  4. with no terminal, the CLI never guesses which user you meant unless there is exactly one
     superadmin to default to.

No network, no SSH; it runs against a throwaway database like the other suites.

    python tests/manage_test.py     # exits 0 if all checks pass, 1 otherwise
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("SKIP: %s already exists — this only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}
_CFG_BACKUP = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

from config import load_config, save_config  # noqa: E402
_cfg = load_config()
_cfg["setup_complete"] = True
save_config(_cfg)

import system_ops as _so  # noqa: E402
_so._check_sudo = lambda force=False: False   # never probe real sudo (pam_faillock)

import manage  # noqa: E402   (creates its own app at import, exactly as the CLI does)
from models import db, User  # noqa: E402
import auth  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def raises_exit(fn, *a, **kw):
    """(did_it_exit, message) — the CLI signals refusal with sys.exit('reason')."""
    try:
        fn(*a, **kw)
        return False, ""
    except SystemExit as e:
        return True, str(e.code)


class Args(object):
    def __init__(self, **kw):
        self.username = kw.pop("username", None)
        self.password = kw.pop("password", None)
        for k, v in kw.items():
            setattr(self, k, v)


def seed(**kw):
    with manage.app.app_context():
        u = User(username=kw["username"], password_hash=auth.hash_password("Str0ng!passw0rd"),
                 display_name=kw["username"], is_superadmin=kw.get("admin", False),
                 is_active=kw.get("active", True))
        u.totp_enabled = kw.get("totp", False)
        if kw.get("totp"):
            u.totp_secret = "SEEDSECRET"
        db.session.add(u)
        db.session.commit()
        return u.id


def cleanup():
    try:
        with manage.app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass
    if _CFG_BACKUP is not None:
        CONFIG_FILE.write_bytes(_CFG_BACKUP)
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE,
              DB_PATH.with_name("panel.db-wal"), DB_PATH.with_name("panel.db-shm"),
              DB_PATH.with_name("panel.db.backup")):
        if p not in _PREEXISTING and p.exists():
            try:
                p.unlink()
            except OSError:
                pass


try:
    admin_id = seed(username="cli_admin", admin=True)
    seed(username="cli_user", admin=False)

    # ── 1. The lock-out guard ─────────────────────────────────────────────────────────────────
    # cli_admin is the only active superadmin. Every way of removing that must be refused, and the
    # refusal must leave the row untouched — a half-applied change is the same brick.
    for field, value, label in (("is_active", False, "deactivate"), ("is_superadmin", False, "demote")):
        exited, msg = raises_exit(manage._set_flag, "cli_admin", field, value, label)
        with manage.app.app_context():
            still = db.session.get(User, admin_id)
            intact = still.is_active and still.is_superadmin
        check("lockout: %s of the last active superadmin is refused" % label,
              exited and "no active superadmin" in msg, msg[:70])
        check("lockout: ...and the account is left untouched, not half-changed" , intact)

    # With a second admin present the same operation is allowed.
    second_id = seed(username="cli_admin2", admin=True)
    exited, msg = raises_exit(manage._set_flag, "cli_admin2", "is_superadmin", False, "demoted")
    with manage.app.app_context():
        demoted = not db.session.get(User, second_id).is_superadmin
    check("lockout: demoting a SECOND admin is allowed", not exited and demoted, msg[:70])

    # An inactive superadmin does not count as cover — the guard checks active ones.
    with manage.app.app_context():
        u2 = db.session.get(User, second_id)
        u2.is_superadmin, u2.is_active = True, False
        db.session.commit()
    exited, msg = raises_exit(manage._set_flag, "cli_admin", "is_active", False, "deactivate")
    check("lockout: an INACTIVE superadmin does not count as cover", exited, msg[:70])

    # ── 2. A password reset must revoke existing sessions ─────────────────────────────────────
    with manage.app.app_context():
        before = db.session.get(User, admin_id)
        old_hash, old_epoch = before.password_hash, (before.auth_epoch or 0)
    manage.cmd_reset_password(Args(username="cli_admin", password="An0ther!Str0ng1"))
    with manage.app.app_context():
        after = db.session.get(User, admin_id)
        check("reset: the password actually changes", after.password_hash != old_hash)
        check("reset: the new password verifies",
              auth.check_password("An0ther!Str0ng1", after.password_hash))
        check("reset: auth_epoch is bumped, so existing sessions die",
              (after.auth_epoch or 0) > old_epoch,
              "%s -> %s" % (old_epoch, after.auth_epoch))

    exited, msg = raises_exit(manage.cmd_reset_password, Args(username="cli_admin", password="weak"))
    check("reset: a weak --password is refused before anything is written",
          exited and "Weak password" in msg, msg[:60])
    exited, msg = raises_exit(manage.cmd_reset_password, Args(username="nobody_here", password="An0ther!Str0ng1"))
    check("reset: an unknown username is refused", exited and "No such user" in msg, msg[:60])

    # ── 3. disable-2fa must clear the SECRET, not just the flag ───────────────────────────────
    tot_id = seed(username="cli_2fa", totp=True)
    manage.cmd_disable_2fa(Args(username="cli_2fa"))
    with manage.app.app_context():
        t = db.session.get(User, tot_id)
        check("2fa: the flag is cleared", t.totp_enabled is False)
        check("2fa: and the SECRET is wiped, so re-enabling cannot restore the old device",
              not t.totp_secret, repr(t.totp_secret))

    # ── 4. Without a terminal the CLI must not guess ──────────────────────────────────────────
    # sys.stdin.isatty is read-only on a real file object, so swap the whole stream for a stub.
    _real_stdin = sys.stdin
    try:
        sys.stdin = type("_NoTTY", (), {"isatty": staticmethod(lambda: False)})()
        with manage.app.app_context():
            # Two active superadmins → ambiguous → refuse rather than pick.
            for uid in (admin_id, second_id):
                u = db.session.get(User, uid)
                u.is_superadmin, u.is_active = True, True
            db.session.commit()
        with manage.app.app_context():
            exited, msg = raises_exit(manage._resolve_username, None, True)
        check("no tty: with two superadmins it refuses to guess",
              exited and "pass a username" in msg, msg[:70])
        with manage.app.app_context():
            db.session.get(User, second_id).is_superadmin = False
            db.session.commit()
        with manage.app.app_context():
            picked = manage._resolve_username(None, True)
        check("no tty: with exactly one superadmin it defaults to them", picked == "cli_admin", picked)
        # disable-2fa passes default_sole_admin=False — it must never pick for you.
        with manage.app.app_context():
            exited, msg = raises_exit(manage._resolve_username, None, False)
        check("no tty: disable-2fa still refuses, even with one admin", exited, msg[:70])
    finally:
        sys.stdin = _real_stdin

    # ── 5. create-admin ───────────────────────────────────────────────────────────────────────
    manage.cmd_create_admin(Args(username="cli_new", password="Br@ndNew1pass"))
    with manage.app.app_context():
        n = User.query.filter_by(username="cli_new").first()
        check("create-admin: the account exists, superadmin and active",
              n is not None and n.is_superadmin and n.is_active)
    exited, msg = raises_exit(manage.cmd_create_admin, Args(username="cli_new", password="Br@ndNew1pass"))
    check("create-admin: refuses to clobber an existing user",
          exited and "already exists" in msg, msg[:60])

    # ── 6. The interactive menu accepts a number or a name ────────────────────────────────────
    _real_input = manage.input if hasattr(manage, "input") else None
    import builtins
    _saved_input = builtins.input
    try:
        with manage.app.app_context():
            names = [u.username for u in User.query.order_by(User.username).all()]
            builtins.input = lambda *a: "2"
            check("menu: a number selects the matching row", manage._pick_user_interactive() == names[1])
            builtins.input = lambda *a: names[0]
            check("menu: a typed username is accepted", manage._pick_user_interactive() == names[0])
            _tries = iter(["nope", "1"])
            builtins.input = lambda *a: next(_tries)
            check("menu: a bad choice re-prompts rather than exiting",
                  manage._pick_user_interactive() == names[0])
    finally:
        builtins.input = _saved_input

except Exception:
    # Without this the suite just reports fewer checks than it has and looks green-ish. A crash
    # part-way through is a FAILURE, and the traceback is the whole point of running it.
    import traceback
    traceback.print_exc()
    results.append((False, "suite crashed before finishing — see the traceback above", ""))
finally:
    passed = sum(1 for ok, _, _ in results if ok)
    for ok, name, detail in results:
        line = ("PASS" if ok else "FAIL") + "  " + name
        if detail and not ok:
            line += "   [%s]" % detail
        print(line)
    print("\n%d / %d checks passed" % (passed, len(results)))
    cleanup()
    sys.exit(0 if results and passed == len(results) else 1)
