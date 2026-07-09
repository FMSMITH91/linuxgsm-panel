#!/usr/bin/env python3
"""Offline admin / recovery CLI for the LinuxGSM Panel.

Use this when you're locked out of the web UI — a forgotten password, or you
deactivated / deleted your only superadmin. It operates directly on the panel
database, so it needs no login.

Run from the panel directory with its venv (or `sudo linuxgsm-panel-recover`):

    ./venv/bin/python manage.py list-users
    ./venv/bin/python manage.py reset-password            # pick from a menu (or the sole admin)
    ./venv/bin/python manage.py reset-password <username> # a specific user
    ./venv/bin/python manage.py disable-2fa               # pick from a menu
    ./venv/bin/python manage.py create-admin <username>
    ./venv/bin/python manage.py promote <username>
    ./venv/bin/python manage.py activate <username>

Run interactively with no username and you get a numbered menu of users to choose
from. Passwords are read interactively (never echoed, never in shell history)
unless you pass --password, and you're re-prompted until one meets the policy.
"""
import argparse
import getpass
import os
import sys
import warnings

# This offline CLI doesn't run the web server, but importing the app pulls in eventlet, which emits a
# deprecation warning and — at interpreter shutdown — a harmless but alarming "greenlet is being
# finalized" traceback. Silence the warning here, and hard-exit at the end (below) to skip the noisy
# teardown, so a locked-out admin sees a clean tool.
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app import create_app, password_problem   # noqa: E402  (must follow the warnings filter)
from models import db, User                     # noqa: E402
import auth                                      # noqa: E402

app = create_app()


def _read_password(args):
    """A policy-passing password: from --password (validated once), else prompted and RE-PROMPTED
    until it matches its confirmation and meets the strength policy (so a weak entry doesn't abort
    the whole command)."""
    pw = getattr(args, "password", None)
    if pw:
        err = password_problem(pw)
        if err:
            sys.exit("Weak password: " + err)
        return pw
    while True:
        try:
            pw = getpass.getpass("New password: ")
            if pw != getpass.getpass("Confirm password: "):
                print("  Passwords do not match — try again.\n")
                continue
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nCancelled.")
        err = password_problem(pw)
        if err:
            print("  %s — try again.\n" % err)
            continue
        return pw


def _require_user(username):
    u = User.query.filter_by(username=username).first()
    if not u:
        sys.exit("No such user: %s" % username)
    return u


def cmd_list_users(args):
    with app.app_context():
        users = User.query.order_by(User.username).all()
        if not users:
            print("(no users yet — run: manage.py create-admin <name>)")
            return
        for u in users:
            flags = (["superadmin"] if u.is_superadmin else []) + \
                    (["active"] if u.is_active else ["INACTIVE"])
            groups = ", ".join(g.name for g in u.groups) or "-"
            print("  %-20s [%s]  groups: %s" % (u.username, ", ".join(flags), groups))


def _pick_user_interactive(prompt="Which user?"):
    """Show a numbered menu of every user and return the chosen username (accepts the number or a
    typed username). Loops until a valid choice is made."""
    users = User.query.order_by(User.username).all()
    if not users:
        sys.exit("No users exist yet. Create one:  manage.py create-admin <name>")
    print(prompt)
    for i, u in enumerate(users, 1):
        flags = (["superadmin"] if u.is_superadmin else []) + ([] if u.is_active else ["inactive"])
        tag = ("  [" + ", ".join(flags) + "]") if flags else ""
        print("  %2d) %s%s" % (i, u.username, tag))
    while True:
        try:
            sel = input("Enter a number (or username): ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nCancelled.")
        if sel.isdigit() and 1 <= int(sel) <= len(users):
            return users[int(sel) - 1].username
        if any(u.username == sel for u in users):
            return sel
        print("  Not a valid choice — try again.")


def _resolve_username(username, default_sole_admin=True):
    """The user to act on. Given a name → use it. Omitted + a terminal → numbered menu. Omitted +
    non-interactive (a script) → the sole superadmin when default_sole_admin, else refuse to guess."""
    if username:
        return username
    if sys.stdin.isatty():
        return _pick_user_interactive()
    if default_sole_admin:
        admins = User.query.filter_by(is_superadmin=True).order_by(User.username).all()
        if not admins:
            sys.exit("No superadmin exists yet. Create one:  manage.py create-admin <name>")
        if len(admins) == 1:
            print("Resetting the only superadmin: %s" % admins[0].username)
            return admins[0].username
        sys.exit("Several superadmins — pass a username (no terminal here for the menu):\n  " +
                 "\n  ".join(a.username for a in admins))
    sys.exit("Pass a username (no terminal here for the menu).")


def cmd_reset_password(args):
    with app.app_context():
        username = _resolve_username(args.username, default_sole_admin=True)
        u = _require_user(username)
        u.password_hash = auth.hash_password(_read_password(args))
        u.auth_epoch = (u.auth_epoch or 0) + 1   # revoke existing sessions
        db.session.commit()
        print("Password reset for '%s' (existing sessions revoked)." % username)


def cmd_create_admin(args):
    with app.app_context():
        if User.query.filter_by(username=args.username).first():
            sys.exit("User '%s' already exists — use reset-password / promote instead." % args.username)
        u = User(username=args.username, password_hash=auth.hash_password(_read_password(args)),
                 display_name=args.username, is_superadmin=True, is_active=True)
        db.session.add(u)
        db.session.commit()
        print("Superadmin '%s' created." % args.username)


def cmd_disable_2fa(args):
    with app.app_context():
        username = _resolve_username(args.username, default_sole_admin=False)
        u = _require_user(username)
        u.totp_enabled = False
        u.totp_secret = None
        db.session.commit()
        print("Two-factor auth disabled for '%s'." % username)


def _set_flag(username, field, value, label):
    with app.app_context():
        u = _require_user(username)
        setattr(u, field, value)
        db.session.flush()
        # Never let the panel end up with no way to administer it.
        if User.query.filter_by(is_superadmin=True, is_active=True).count() == 0:
            db.session.rollback()
            sys.exit("Refusing — that would leave no active superadmin. "
                     "Create or promote another admin first.")
        db.session.commit()
        print("'%s' %s." % (username, label))


def main():
    p = argparse.ArgumentParser(description="LinuxGSM Panel admin / recovery CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-users", help="List all users").set_defaults(func=cmd_list_users)

    sp = sub.add_parser("reset-password", help="Reset a user's password (menu if no username given)")
    sp.add_argument("username", nargs="?", help="Omit for a numbered menu (or the sole superadmin)")
    sp.add_argument("--password", help="Set non-interactively (avoid — ends up in shell history)")
    sp.set_defaults(func=cmd_reset_password)

    cp = sub.add_parser("create-admin", help="Create a new superadmin user")
    cp.add_argument("username")
    cp.add_argument("--password")
    cp.set_defaults(func=cmd_create_admin)

    dp2 = sub.add_parser("disable-2fa", help="Turn off a user's two-factor auth (menu if no username)")
    dp2.add_argument("username", nargs="?", help="Omit for a numbered menu")
    dp2.set_defaults(func=cmd_disable_2fa)

    for name, field, val, lbl in [
        ("promote", "is_superadmin", True, "promoted to superadmin"),
        ("demote", "is_superadmin", False, "demoted from superadmin"),
        ("activate", "is_active", True, "activated"),
        ("deactivate", "is_active", False, "deactivated"),
    ]:
        pp = sub.add_parser(name, help=lbl.capitalize())
        pp.add_argument("username")
        pp.set_defaults(func=(lambda a, f=field, v=val, l=lbl: _set_flag(a.username, f, v, l)))

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    _code = 0
    try:
        main()
    except SystemExit as _e:               # sys.exit(): a string message prints to stderr (rc 1)
        if isinstance(_e.code, str):
            print(_e.code, file=sys.stderr)
            _code = 1
        elif isinstance(_e.code, int):
            _code = _e.code
    except KeyboardInterrupt:
        _code = 130
    sys.stdout.flush()
    sys.stderr.flush()
    # Hard-exit so eventlet's greenlet-finalization teardown (a harmless but scary traceback) never
    # prints. The DB change is already committed above, so nothing is lost by skipping normal cleanup.
    os._exit(_code)
