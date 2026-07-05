#!/usr/bin/env python3
"""Offline admin / recovery CLI for the LinuxGSM Panel.

Use this when you're locked out of the web UI — a forgotten password, or you
deactivated / deleted your only superadmin. It operates directly on the panel
database, so it needs no login.

Run from the panel directory with its venv:

    ./venv/bin/python manage.py list-users
    ./venv/bin/python manage.py reset-password <username>
    ./venv/bin/python manage.py create-admin <username>
    ./venv/bin/python manage.py promote <username>
    ./venv/bin/python manage.py activate <username>

Passwords are read interactively (never echoed, never in shell history) unless
you pass --password. They must meet the same strength policy as the web UI.
"""
import argparse
import getpass
import sys

from app import create_app, password_problem
from models import db, User
import auth

app = create_app()


def _read_password(args):
    pw = getattr(args, "password", None)
    if not pw:
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
    err = password_problem(pw)
    if err:
        sys.exit("Weak password: " + err)
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


def cmd_reset_password(args):
    with app.app_context():
        u = _require_user(args.username)
        u.password_hash = auth.hash_password(_read_password(args))
        db.session.commit()
        print("Password reset for '%s'." % args.username)


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
        u = _require_user(args.username)
        u.totp_enabled = False
        u.totp_secret = None
        db.session.commit()
        print("Two-factor auth disabled for '%s'." % args.username)


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

    sp = sub.add_parser("reset-password", help="Reset a user's password")
    sp.add_argument("username")
    sp.add_argument("--password", help="Set non-interactively (avoid — ends up in shell history)")
    sp.set_defaults(func=cmd_reset_password)

    cp = sub.add_parser("create-admin", help="Create a new superadmin user")
    cp.add_argument("username")
    cp.add_argument("--password")
    cp.set_defaults(func=cmd_create_admin)

    dp2 = sub.add_parser("disable-2fa", help="Turn off a user's two-factor auth (lost authenticator)")
    dp2.add_argument("username")
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
    main()
