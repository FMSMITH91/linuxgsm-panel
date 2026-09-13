#!/usr/bin/env python3
"""Tests for the first-run setup wizard — the one flow that runs UNAUTHENTICATED.

panel/routes/route_helpers.py sat at 21% coverage, the worst of any application module, and the
reason is structural rather than an oversight: every other suite marks `setup_complete` before it
creates the app, because they need a panel that is past setup. So the wizard's whole POST path —
the code that writes the panel's bind address and creates the FIRST superadmin, with no login in
front of it — was never executed by a test.

That is a bad gap to have here specifically. The wizard cannot require auth (there are no users
yet), so the ONLY thing standing between the public internet and "create a superadmin" is the lock
that closes it once setup is done. That lock has already been wrong twice, and both regressions are
described at length in route_helpers.py:

  1. only GET was blocked, so an unauthenticated POST /setup with step=admin_user still created a
     brand-new superadmin on a fully configured install.
  2. the lock was gated on is_setup_complete(), which is (DB row AND config flag) — and the config
     half FAILS OPEN, because load_config() swallows JSONDecodeError/OSError and returns
     DEFAULT_CONFIG, where setup_complete is False. So deleting data/config.json, or truncating it
     on a full disk, or hand-editing it into invalid JSON, reopened the wizard on a live install.

Both are now defended by reading the SetupState row alone. Neither had a test. They do now: the
config-corruption cases below are the ones that matter most, because nothing about them looks like
an attack — a full disk produces the same file.

Runs against a throwaway database like the other suites, and deliberately does NOT pre-complete
setup — that is the entire point.

    python tests/setup_wizard_test.py     # exits 0 if all checks pass, 1 otherwise
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panel.core.config import DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("SKIP: %s already exists — this only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}
_CFG_BACKUP = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

# NOTE: no `setup_complete = True` here, unlike every other suite. The wizard must be OPEN when the
# app is created, or there is nothing to test.
from panel.core.config import load_config, save_config  # noqa: E402

from panel.ops import system_ops as _so  # noqa: E402
_so._check_sudo = lambda force=False: False   # never probe real sudo (pam_faillock)

from app import create_app  # noqa: E402
from panel.db.models import db, User, SetupState  # noqa: E402

app = create_app()
app.config["WTF_CSRF_ENABLED"] = False
app.config["SESSION_PROTECTION"] = None
app.config["SESSION_COOKIE_SECURE"] = False

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def cleanup():
    try:
        with app.app_context():
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


def superadmins():
    with app.app_context():
        return [u.username for u in User.query.filter_by(is_superadmin=True).all()]


def mark_setup_complete():
    """Finish setup the way the wizard's last step does: the DB row AND the config flag."""
    with app.app_context():
        st = SetupState.query.first() or SetupState(step="done", data="{}")
        st.complete = True
        st.step = "done"
        db.session.add(st)
        db.session.commit()
    cfg = load_config()
    cfg["setup_complete"] = True
    save_config(cfg)


try:
    # ── While setup is OPEN ───────────────────────────────────────────────────────────────────
    c = app.test_client()
    r = c.get("/setup")
    check("open: GET /setup renders the wizard (200, not a redirect)",
          r.status_code == 200, "got %d" % r.status_code)

    # Any other path funnels into the wizard — until setup is done there are no users, so even
    # /login must not be reachable (it would be a login form with nothing to log into).
    r = c.get("/login", follow_redirects=False)
    check("open: every other page redirects into the wizard",
          r.status_code in (301, 302, 303) and "/setup" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))

    # Step 1 writes the panel's own binding. This is the step the second regression let an
    # unauthenticated caller re-run on a live install.
    r = c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                               "port": "5051", "bind_host": "127.0.0.1"})
    _cfg_after = load_config()
    check("open: step=welcome saves the site settings",
          _cfg_after.get("site_title") == "Test Panel" and _cfg_after.get("port") == 5051
          and _cfg_after.get("bind_host") == "127.0.0.1", str(_cfg_after.get("port")))

    # ── Step 2 validation: none of these may create an account ────────────────────────────────
    for _name, _form, _why in (
            ("a short username", {"username": "ab", "password": "Sufficient1!pass",
                                  "confirm_password": "Sufficient1!pass"}, "under 3 chars"),
            ("a weak password", {"username": "admin1", "password": "short",
                                 "confirm_password": "short"}, "password_problem"),
            ("a mismatched confirmation", {"username": "admin1", "password": "Sufficient1!pass",
                                           "confirm_password": "Different1!pass"}, "mismatch")):
        c.post("/setup", data=dict(step="admin_user", **_form))
        check("open: %s creates no account (%s)" % (_name, _why), superadmins() == [],
              str(superadmins()))

    # The happy path.
    r = c.post("/setup", data={"step": "admin_user", "username": "firstadmin",
                               "password": "Sufficient1!pass", "confirm_password": "Sufficient1!pass",
                               "email": "admin@example.com"})
    check("open: a valid step=admin_user creates the first superadmin",
          superadmins() == ["firstadmin"], str(superadmins()))
    with app.app_context():
        _u = User.query.filter_by(username="firstadmin").first()
        check("open: the first admin is active and a superadmin",
              _u is not None and _u.is_superadmin and _u.is_active)
        check("open: their password is HASHED, never stored in the clear",
              _u is not None and "Sufficient1!pass" not in (_u.password_hash or ""))
        check("open: their email is encrypted at rest, not stored in the clear",
              _u is not None and "admin@example.com" not in (_u.email or ""))

    # A second admin_user POST must be refused even while the wizard is still open — the wizard
    # creates the FIRST admin only (defence in depth behind the completion lock).
    c.post("/setup", data={"step": "admin_user", "username": "sneak",
                           "password": "Sufficient1!pass", "confirm_password": "Sufficient1!pass"})
    check("open: step=admin_user refuses once a superadmin exists",
          superadmins() == ["firstadmin"], str(superadmins()))

    # ── Once setup is COMPLETE, the wizard is permanently locked ──────────────────────────────
    mark_setup_complete()
    c = app.test_client()

    r = c.get("/setup", follow_redirects=False)
    check("locked: GET /setup redirects to login",
          r.status_code in (301, 302, 303) and "login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))

    # REGRESSION 1: POST used to be unguarded while GET was blocked.
    r = c.post("/setup", data={"step": "admin_user", "username": "backdoor",
                               "password": "Sufficient1!pass", "confirm_password": "Sufficient1!pass"},
               follow_redirects=False)
    check("locked: POST step=admin_user cannot create a superadmin",
          "backdoor" not in superadmins(), str(superadmins()))

    _before = load_config()
    c.post("/setup", data={"step": "welcome", "site_title": "Hijacked",
                           "port": "1234", "bind_host": "0.0.0.0"}, follow_redirects=False)
    _after = load_config()
    check("locked: POST step=welcome cannot rewrite the panel's binding",
          _after.get("bind_host") == _before.get("bind_host")
          and _after.get("port") == _before.get("port")
          and _after.get("site_title") == _before.get("site_title"),
          "%s:%s -> %s:%s" % (_before.get("bind_host"), _before.get("port"),
                              _after.get("bind_host"), _after.get("port")))

    # REGRESSION 2, the important one: the lock must read the DB ROW ALONE. load_config() fails
    # OPEN — it swallows a JSONDecodeError/OSError and hands back DEFAULT_CONFIG, where
    # setup_complete is False — so anything gated on is_setup_complete() reopens the moment
    # config.json is unreadable. A full disk truncates a file the same way an attacker would.
    for _label, _writer in (
            ("deleted", lambda: CONFIG_FILE.unlink()),
            ("truncated to empty", lambda: CONFIG_FILE.write_text("", encoding="utf-8")),
            ("invalid JSON", lambda: CONFIG_FILE.write_text("{not json", encoding="utf-8"))):
        _writer()
        c2 = app.test_client()
        r = c2.get("/setup", follow_redirects=False)
        check("locked: with config.json %s, GET /setup STAYS locked" % _label,
              r.status_code in (301, 302, 303) and "login" in (r.headers.get("Location") or ""),
              "%d -> %s" % (r.status_code, r.headers.get("Location")))
        c2.post("/setup", data={"step": "admin_user", "username": "cfgbreak-%s" % _label[:4],
                                "password": "Sufficient1!pass",
                                "confirm_password": "Sufficient1!pass"}, follow_redirects=False)
        check("locked: with config.json %s, POST still creates NO superadmin" % _label,
              not any(u.startswith("cfgbreak") for u in superadmins()), str(superadmins()))

        # THE ACTUAL EXPLOIT from regression #2, and the reason the two above are not enough:
        # step=admin_user is additionally guarded by "a superadmin already exists", so it stays
        # shut even when the outer lock is broken. step=welcome has no such inner guard — it just
        # writes. On a live install that turns a loopback-only panel into 0.0.0.0 at the next
        # restart, from an unauthenticated request, with no credential involved.
        c2.post("/setup", data={"step": "welcome", "site_title": "Hijacked-%s" % _label[:4],
                                "port": "1234", "bind_host": "0.0.0.0"}, follow_redirects=False)
        _cfg_now = load_config()
        check("locked: with config.json %s, POST step=welcome cannot rewrite the binding" % _label,
              not str(_cfg_now.get("site_title", "")).startswith("Hijacked")
              and _cfg_now.get("port") != 1234,
              "config now says %s / %s" % (_cfg_now.get("site_title"), _cfg_now.get("port")))

        # The setup-only Tailscale endpoints share that lock for the same reason — they are
        # unauthenticated too, and one of them makes the panel reach out to a supplied host.
        for _ep in ("/api/setup/tailscale/status",):
            rr = c2.get(_ep)
            check("locked: with config.json %s, %s is refused" % (_label, _ep),
                  rr.status_code in (401, 403, 301, 302, 303),
                  "got %d" % rr.status_code)
        rr = c2.post("/api/setup/tailscale/up", json={})
        check("locked: with config.json %s, tailscale/up is refused" % _label,
              rr.status_code in (401, 403, 301, 302, 303), "got %d" % rr.status_code)

    # Put a valid config back so the final state is sane for cleanup.
    save_config({"setup_complete": True})

except Exception:
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
