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

# panel.db.backup is in here, and it is the one that matters. It is not scratch: models.
# _ensure_db_healthy keeps it as the rolling KNOWN-GOOD copy and restores from it when the live
# database is corrupt. The cleanup below unlinks it, and "not in _PREEXISTING" was the only thing
# standing between a developer's data and that unlink — so it was deleted every run.
#
# The window is narrow and it is exactly the wrong one: these harnesses refuse to run at all while
# panel.db EXISTS, so the only state in which they run and the backup is present is "the live
# database is missing and this copy is the last one left". The WAL/SHM pair is here for the same
# reason — they hold committed pages the main file may not have yet.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE,
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
    if _CONFIG_SNAPSHOT is not None:
        try:
            CONFIG_FILE.write_bytes(_CONFIG_SNAPSHOT)   # undo our edits to someone else's config
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

    # The port this step writes is the address the panel BINDS TO on its next boot, and nothing
    # downstream re-checks it — app.py reads cfg["port"] and hands it straight to socketio.run().
    # It was parsed with _int_or, which carries no range, so a typo of 0 or 99999 was saved and the
    # panel would not come back up: recoverable only with linuxgsm-panel-recover or by editing
    # config.json by hand. (The comment here used to say api_panel_change_port validated it. That
    # is a different route, and the wizard never calls it.) Same bounds as that route.
    _port_before = load_config().get("port")
    for _bad in ("0", "80", "1023", "65536", "99999", "-1", "abc", "", "5051.5", "\u0665\u0660\u0665\u0661"):
        r = c.post("/setup", data={"step": "welcome", "site_title": "Should Not Save",
                                   "port": _bad, "bind_host": "127.0.0.1"})
        check("open: step=welcome refuses port=%r" % _bad,
              r.status_code < 500 and load_config().get("port") == _port_before,
              "status %d, config port is now %s" % (r.status_code, load_config().get("port")))
    check("open: a refused port leaves the rest of step 1 unsaved too",
          load_config().get("site_title") == "Test Panel", load_config().get("site_title"))
    # Positive control: a valid port still saves, so the block above cannot pass by refusing all.
    r = c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                               "port": "5052", "bind_host": "127.0.0.1"})
    check("open: step=welcome still accepts a valid port (positive control)",
          load_config().get("port") == 5052, str(load_config().get("port")))

    # ── ...and the BIND ADDRESS, which sat two lines below the port carrying the same false
    # claim. app.py reads cfg["bind_host"] and hands it to socketio.run(), so a value the host
    # cannot bind is a panel that does not come back up — the identical unrecoverable state the
    # port bound above exists to prevent. Both writers now go through bind_host_error().
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})
    _bind_before = load_config().get("bind_host")
    for _bad in ("not-an-ip", "0.0.0.0; rm -rf /", "999.1.1.1",
                 "example.com", "127.0.0.1:5000", "<script>", "localhost"):
        r = c.post("/setup", data={"step": "welcome", "site_title": "Should Not Save",
                                   "port": "5052", "bind_host": _bad})
        check("open: step=welcome refuses bind_host=%r" % _bad,
              r.status_code < 500 and load_config().get("bind_host") == _bind_before,
              "status %d, config bind_host is now %r" % (r.status_code, load_config().get("bind_host")))
    # A BLANK field is not a bad value — it means "use the default", which is what the form offers
    # when the operator leaves the box alone. Asserted rather than assumed, because the refusals
    # above would otherwise be free to swallow it.
    r = c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                               "port": "5052", "bind_host": ""})
    check("open: step=welcome treats a blank bind_host as the 0.0.0.0 default",
          load_config().get("bind_host") == "0.0.0.0", repr(load_config().get("bind_host")))
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})
    _bind_before = load_config().get("bind_host")
    check("open: a refused bind address leaves the rest of step 1 unsaved too",
          load_config().get("site_title") == "Test Panel", load_config().get("site_title"))
    for _good in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        r = c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                                   "port": "5052", "bind_host": _good})
        check("open: step=welcome accepts bind_host=%r (positive control)" % _good,
              load_config().get("bind_host") == _good, repr(load_config().get("bind_host")))
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})

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

    # ── setup must not be able to FINISH before it has produced an admin ──────────────────────
    # The handler dispatches on the `step` field from the FORM, so nothing makes a caller walk the
    # wizard in order, and the wizard is unauthenticated until it completes. On a fresh panel that
    # let anyone who could reach the port POST step=remote_server&action=skip and close setup with
    # zero accounts: SetupState.complete True, config setup_complete True, superadmins 0 — and
    # every page from then on redirecting to a login nobody could pass. Getting back in needed
    # `manage.py create-admin` from a shell. The same request also ran the Tailscale auto-setup,
    # so an unauthenticated POST reconfigured the host.
    check("open: nobody has been created yet (the precondition for the next check)",
          superadmins() == [], str(superadmins()))
    _r_jump = c.post("/setup", data={"step": "remote_server", "action": "skip"})
    with app.app_context():
        _st_jump = SetupState.query.first()
        _complete_jump = bool(getattr(_st_jump, "complete", False))
    check("open: a jump straight to the last step does NOT complete setup with no admin",
          not _complete_jump,
          "setup closed itself with %s admins — the panel is now unreachable without the CLI"
          % len(superadmins()))
    check("open: ...and the config flag is not set either",
          not load_config().get("setup_complete", False),
          "config says setup_complete with no account to log in as")
    check("open: ...and the wizard is still reachable to finish properly",
          c.get("/setup").status_code == 200, "the wizard closed behind itself")

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

    # ── From here the wizard belongs to the browser that created the admin ────────────────────
    # It stayed open to ANY caller until the last step, and the steps after the admin are the
    # dangerous ones: /api/setup/tailscale/up joined this host to the caller's tailnet with
    # Tailscale SSH on and handed them the auth URL, and step=welcome rewrote the bind.
    def _wiz_step():
        with app.app_context():
            return SetupState.query.first().step

    _att = app.test_client()
    r = _att.get("/setup", follow_redirects=False)
    check("owner: another browser's GET /setup is sent to sign in, not shown the wizard",
          r.status_code in (301, 302, 303) and "/login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    # The three that act on the host are stubbed, so a broken gate records a call instead of
    # installing Tailscale or joining a tailnet from a test run.
    from panel.ops import tailscale_integration as _ts_mod
    _ts_saved = (_ts_mod.install_tailscale_local, _ts_mod.tailscale_up_local,
                 _ts_mod.setup_tailscale_serve)
    _ts_calls = []
    _ts_mod.install_tailscale_local = lambda *a, **k: (_ts_calls.append("install") or (True, ""))
    _ts_mod.tailscale_up_local = lambda *a, **k: (_ts_calls.append("up") or (True, "https://x"))
    _ts_mod.setup_tailscale_serve = lambda *a, **k: (_ts_calls.append("serve") or (True, ""))
    try:
        for _ep, _meth in (("/api/setup/tailscale/up", "post"),
                           ("/api/setup/tailscale/install", "post"),
                           ("/api/setup/tailscale/serve", "post"),
                           ("/api/setup/tailscale/status", "get")):
            rr = getattr(_att, _meth)(_ep, json={}) if _meth == "post" else _att.get(_ep)
            check("owner: another browser is refused %s" % _ep, rr.status_code == 403,
                  "got %d" % rr.status_code)
        check("owner: ...and nothing was run on the host for it", _ts_calls == [], repr(_ts_calls))
    finally:
        (_ts_mod.install_tailscale_local, _ts_mod.tailscale_up_local,
         _ts_mod.setup_tailscale_serve) = _ts_saved
    _bind_owner = load_config().get("bind_host")
    _att.post("/setup", data={"step": "welcome", "site_title": "Hijacked", "port": "5099",
                              "bind_host": "0.0.0.0"})
    check("owner: another browser cannot rewrite the bind or port",
          load_config().get("bind_host") == _bind_owner and load_config().get("port") != 5099,
          "%s %s" % (load_config().get("bind_host"), load_config().get("port")))
    _att.post("/setup", data={"step": "tailscale"})
    check("owner: another browser cannot advance the wizard", _wiz_step() == "tailscale",
          _wiz_step())
    # The owner's own browser carries on (positive control for every refusal above)...
    rr = c.get("/api/setup/tailscale/status")
    check("owner: the creating browser still reaches the Tailscale step's API",
          rr.status_code == 200, "got %d" % rr.status_code)
    # ...and the way back in from any other browser is to sign in as the admin.
    r = _att.get("/login", follow_redirects=False)
    check("owner: /login is reachable once an admin exists (not bounced into the wizard)",
          r.status_code == 200, "got %d -> %s" % (r.status_code, r.headers.get("Location")))
    _rec = app.test_client()
    _rec.post("/login?next=/setup", data={"username": "firstadmin",
                                          "password": "Sufficient1!pass"})
    r = _rec.get("/setup", follow_redirects=False)
    check("owner: a browser signed in as the superadmin may finish the wizard",
          r.status_code == 200, "got %d -> %s" % (r.status_code, r.headers.get("Location")))
    c.post("/setup", data={"step": "tailscale"})
    check("owner: the creating browser advances the wizard", _wiz_step() == "remote_server",
          _wiz_step())

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
    # Written directly: save_config now REFUSES to replace a config.json it cannot read (the file
    # the loop above left as invalid JSON), which is the point of that refusal.
    CONFIG_FILE.write_text('{"setup_complete": true}', encoding="utf-8")

except Exception:
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
