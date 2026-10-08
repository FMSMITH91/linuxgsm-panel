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

from panel.core.config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("SKIP: %s already exists — this only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

_TOKEN_FILE = DATA_DIR / "setup_token"   # what `manage.py setup-token` writes

# panel.db.backup is in here, and it is the one that matters. It is not scratch: models.
# _ensure_db_healthy keeps it as the rolling KNOWN-GOOD copy and restores from it when the live
# database is corrupt. The cleanup below unlinks it, and "not in _PREEXISTING" was the only thing
# standing between a developer's data and that unlink — so it was deleted every run.
#
# The window is narrow and it is exactly the wrong one: these harnesses refuse to run at all while
# panel.db EXISTS, so the only state in which they run and the backup is present is "the live
# database is missing and this copy is the last one left". The WAL/SHM pair is here for the same
# reason — they hold committed pages the main file may not have yet.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE, _TOKEN_FILE,
                            DB_PATH.with_name("panel.db.backup"),
                            DB_PATH.with_name("panel.db-wal"),
                            DB_PATH.with_name("panel.db-shm")) if p.exists()}

# A config that was already on disk is RESTORED BYTE-FOR-BYTE at the end. Every DB-owning suite
# has to edit config.json to boot the app, and deleting it only when the suite CREATED it is not
# enough: on a developer's tree the file is theirs and the edits stay behind. That is not
# hypothetical — a leftover ssh_timeout=1 makes the UNIT suite's "no override -> the documented
# default" check fail, in a different suite, pointing at config rather than at whoever wrote it.
# tools/smoke-local.sh sidesteps this by copying to a throwaway tree; running a suite in-tree
# (which CI does, where no config pre-exists) should not behave differently.
_CONFIG_SNAPSHOT = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None
_CFG_BACKUP = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

from panel.core.config import load_config, save_config  # noqa: E402
_cfg = load_config()
_cfg["setup_complete"] = True
save_config(_cfg)

from panel.ops import system_ops as _so  # noqa: E402
_so._check_sudo = lambda force=False: False   # never probe real sudo (pam_faillock)

import manage  # noqa: E402   (creates its own app at import, exactly as the CLI does)
from panel.db.models import db, User  # noqa: E402
from panel.security import auth  # noqa: E402

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
        """Build an argparse-like namespace: username and password default to None."""
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
            u.totp_secret = "SEEDSECRET"  # nosec B105 - a planted fixture value the 2fa check proves is wiped
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
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE, _TOKEN_FILE,
              DB_PATH.with_name("panel.db-wal"), DB_PATH.with_name("panel.db-shm"),
              DB_PATH.with_name("panel.db.backup")):
        if p not in _PREEXISTING and p.exists():
            try:
                p.unlink()
            except OSError as e:
                # Said, not swallowed: a panel.db left behind makes the NEXT run of every
                # DB-owning suite print SKIP and exit 0, with nothing to say why.
                print("cleanup: could not remove %s (%s)" % (p, e), file=sys.stderr)
    if _CONFIG_SNAPSHOT is not None:
        try:
            CONFIG_FILE.write_bytes(_CONFIG_SNAPSHOT)   # undo our edits to someone else's config
        except OSError:
            pass  # cleanup only: a config it cannot restore must not hide the result


def _run_setup_token(raw=True):
    """(exited, message, stdout) of `manage.py setup-token [--raw]`."""
    import contextlib
    import io
    _out = io.StringIO()
    with contextlib.redirect_stdout(_out):
        exited, msg = raises_exit(manage.cmd_setup_token, Args(raw=raw))
    return exited, msg, _out.getvalue()


# ── Aikido 745379084: a stored name cannot drive the operator's terminal ─────────────────
# This CLI is what the operator runs as root in a recovery ("which account is compromised?").
# A username or group name stored with ESC sequences — cursor up, erase line, an OSC 52
# clipboard write — was printed raw, so a delegate could hide or forge rows in exactly that
# listing. Rows stored before validation existed are why the OUTPUT is escaped too.
def _check_tty_safe():
    """The recovery CLI shows stored names escaped, and still acts on the real rows."""
    from panel.db.models import Group

    def _tty_dirty(text):
        """The characters in `text` a terminal would act on rather than show (newlines aside)."""
        return [c for c in text if c != "\n" and not c.isprintable()]

    def _captured(fn, *a):
        _o = io.StringIO()
        try:
            with contextlib.redirect_stdout(_o):
                fn(*a)
        except SystemExit:
            pass  # the command exits; its output is what is checked
        return _o.getvalue()

    _esc_name = "\x1b[1A\x1b[2K\x1b]52;c;ZWNobyBoaQ==\x07zz"
    _esc_id = seed(username=_esc_name)
    with manage.app.app_context():
        _esc_group = Group(name="ops\x1b[2Kteam\n  forged_admin [active]  groups: -", description="")
        db.session.add(_esc_group)
        _esc_row = db.session.get(User, _esc_id)
        _esc_row.groups.append(_esc_group)
        db.session.commit()
        _n_users = User.query.count()
    _listed = _captured(manage.cmd_list_users, Args())
    check("list-users: a stored username or group name puts no control character on the terminal",
          not _tty_dirty(_listed), repr(sorted(set(_tty_dirty(_listed)))))
    check("list-users: ...nor a forged row — one line per user",
          len(_listed.splitlines()) == _n_users, "%d lines for %d users" % (
              len(_listed.splitlines()), _n_users))
    check("list-users: ...and the name is still shown, escaped visibly (control)",
          "\\x1b[1A" in _listed and "zz [active]" in _listed, repr(_listed[:200]))
    builtins.input = lambda *_a: "1"          # the injected row sorts first (ESC < 'A')
    try:
        with manage.app.app_context():
            _pick_out = io.StringIO()
            with contextlib.redirect_stdout(_pick_out):
                _picked = manage._pick_user_interactive()
    finally:
        builtins.input = _saved_input
    check("menu: the picker shows a stored name without its control characters",
          not _tty_dirty(_pick_out.getvalue()), repr(_pick_out.getvalue()[:160]))
    check("menu: ...while the choice is still the REAL stored name, so the command acts on it",
          _picked == _esc_name, repr(_picked))
    for _what, _fn, _args in (
            ("disable-2fa", manage.cmd_disable_2fa, Args(username=_esc_name)),
            ("reset-password", manage.cmd_reset_password,
             Args(username=_esc_name, password="An0ther!passw0rd")),  # nosec B106 - test fixture
            ("disable", manage._set_flag, None)):
        if _args is None:
            _said = _captured(_fn, _esc_name, "is_active", False, "deactivated")
        else:
            _said = _captured(_fn, _args)
        check("%s: the confirmation echoes the name without its control characters" % _what,
              _said and not _tty_dirty(_said), repr(_said[:160]))
    with manage.app.app_context():
        _gone = raises_exit(manage._require_user, "nobody\x1b]52;c;eA==\x07")
    check("a missing user: the refusal echoes the typed name without its control characters",
          _gone[0] and not _tty_dirty(_gone[1]), repr(_gone))


try:
    # ── 0. The first-run wizard's setup token ─────────────────────────────────────────────────
    # Before the first admin exists the wizard answers only to a browser that shows this token;
    # the installer runs this command (as the panel's account) and prints the link it makes.
    # Nothing is seeded yet, so this is a fresh install.
    if _TOKEN_FILE.exists() and _TOKEN_FILE not in _PREEXISTING:
        _TOKEN_FILE.unlink()
    _ex, _msg, _tok1 = _run_setup_token()
    _tok1 = _tok1.strip()
    import re as _re
    check("setup-token: on a fresh install it prints a token", not _ex and
          bool(_re.fullmatch(r"[A-Za-z0-9_-]{32,}", _tok1)), "%r %r" % (_msg, _tok1))
    check("setup-token: ...and writes it to data/setup_token, owner-only (0600)",
          _TOKEN_FILE.exists() and _TOKEN_FILE.read_text().strip() == _tok1
          and (_TOKEN_FILE.stat().st_mode & 0o777) == 0o600,
          oct(_TOKEN_FILE.stat().st_mode & 0o777) if _TOKEN_FILE.exists() else "no file")
    _ex, _msg, _tok2 = _run_setup_token()
    check("setup-token: run again it prints the SAME token (the link already printed still works)",
          not _ex and _tok2.strip() == _tok1, "%r vs %r" % (_tok2.strip(), _tok1))
    _ex, _msg, _human = _run_setup_token(raw=False)
    check("setup-token: without --raw it prints the /setup?token= link",
          not _ex and ("/setup?token=" + _tok1) in _human, _human[:200])
    # An empty file (a truncated write, a full disk) is not a token: it is replaced, not printed.
    _TOKEN_FILE.write_text("", encoding="ascii")
    _ex, _msg, _tok3 = _run_setup_token()
    check("setup-token: an empty token file is replaced with a real token",
          not _ex and bool(_re.fullmatch(r"[A-Za-z0-9_-]{32,}", _tok3.strip()))
          and _TOKEN_FILE.read_text().strip() == _tok3.strip(), "%r" % _tok3)

    admin_id = seed(username="cli_admin", admin=True)

    # Once an admin exists the token opens nothing — refused, and the file is deleted.
    _ex, _msg, _out = _run_setup_token()
    check("setup-token: refused once setup has an administrator", _ex and not _out.strip()
          and "administrator" in _msg, "%r %r" % (_msg, _out))
    check("setup-token: ...and the leftover token file is deleted", not _TOKEN_FILE.exists())
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
    manage.cmd_reset_password(Args(username="cli_admin", password="An0ther!Str0ng1"))  # nosec B106 - test fixture
    with manage.app.app_context():
        after = db.session.get(User, admin_id)
        check("reset: the password actually changes", after.password_hash != old_hash)
        check("reset: the new password verifies",
              auth.check_password("An0ther!Str0ng1", after.password_hash))
        check("reset: auth_epoch is bumped, so existing sessions die",
              (after.auth_epoch or 0) > old_epoch,
              "%s -> %s" % (old_epoch, after.auth_epoch))

    exited, msg = raises_exit(manage.cmd_reset_password,
                              Args(username="cli_admin", password="weak"))  # nosec B106 - test fixture
    check("reset: a weak --password is refused before anything is written",
          exited and "Weak password" in msg, msg[:60])
    exited, msg = raises_exit(manage.cmd_reset_password,
                              Args(username="nobody_here", password="An0ther!Str0ng1"))  # nosec B106 - test fixture
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
    manage.cmd_create_admin(Args(username="cli_new", password="Br@ndNew1pass"))  # nosec B106 - test fixture
    with manage.app.app_context():
        n = User.query.filter_by(username="cli_new").first()
        check("create-admin: the account exists, superadmin and active",
              n is not None and n.is_superadmin and n.is_active)
    exited, msg = raises_exit(manage.cmd_create_admin,
                              Args(username="cli_new", password="Br@ndNew1pass"))  # nosec B106 - test fixture
    check("create-admin: refuses to clobber an existing user",
          exited and "already exists" in msg, msg[:60])

    # ── 6. The interactive menu accepts a number or a name ────────────────────────────────────
    import builtins
    import contextlib
    import io
    _saved_input = builtins.input
    seed(username="cli_gone", active=False)
    seed(username="cli_gone_admin", admin=True, active=False)

    def _menu(*answers):
        """Return (chosen, printed) for the menu run on these scripted answers.

        Past the last answer, input() raises EOFError and the menu takes its own "Cancelled." exit,
        so a menu that wrongly re-prompts comes back None and fails its check by name. A stub that
        repeats one answer forever turned exactly that bug into a hang the memory cap killed.
        """
        _left = iter(answers)

        def _answer(*_a):
            try:
                return next(_left)
            except StopIteration:
                raise EOFError from None
        builtins.input = _answer
        _out = io.StringIO()
        try:
            with contextlib.redirect_stdout(_out):
                chosen = manage._pick_user_interactive()
        except SystemExit:
            chosen = None
        return chosen, _out.getvalue()

    try:
        with manage.app.app_context():
            names = [u.username for u in User.query.order_by(User.username).all()]
            check("menu: a number selects the matching row", _menu("2")[0] == names[1])
            check("menu: a typed username is accepted", _menu(names[0])[0] == names[0])
            check("menu: a bad choice re-prompts rather than exiting",
                  _menu("nope", "1")[0] == names[0])
            _shown = _menu("1")[1].splitlines()
            _row = {n: "  %2d) %s" % (i, n) for i, n in enumerate(names, 1)}
            check("menu: the prompt, then one numbered line per user in name order",
                  _shown[:1] == ["Which user?"] and len(_shown) == 1 + len(names)
                  and all(line.startswith(_row[n]) for line, n in zip(_shown[1:], names)),
                  repr(_shown[:4]))
            check("menu: a superadmin is tagged, a plain user is not",
                  _row["cli_new"] + "  [superadmin]" in _shown and _row["cli_user"] in _shown,
                  repr(_shown))
            check("menu: an inactive user is tagged, and an inactive superadmin carries both",
                  _row["cli_gone"] + "  [inactive]" in _shown
                  and _row["cli_gone_admin"] + "  [superadmin, inactive]" in _shown,
                  repr(_shown))
    finally:
        builtins.input = _saved_input

    _check_tty_safe()

except BaseException:
    # BaseException, not Exception: the finally below ends in sys.exit(), which REPLACES an
    # exception still in flight. An eventlet Timeout (a BaseException) raised mid-suite
    # therefore ended the run early with "N / N checks passed" and exit 0. Recorded here,
    # it is a failure with its traceback, like any other crash.
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
            line += "   [%s]" % (detail,)   # (detail,) not detail: a multi-element TUPLE detail made
            #     THIS line raise ('not all arguments converted'), so a
            #     FAILING check printed a traceback instead of its name
        #     and killed the tally and cleanup. Lists and ints are fine
        #     here; the concat-style printer elsewhere breaks on those.
        print(line)
    print("\n%d / %d checks passed" % (passed, len(results)))
    cleanup()
    sys.exit(0 if results and passed == len(results) else 1)
