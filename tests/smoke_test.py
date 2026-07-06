"""Smoke test — boots the app on a THROWAWAY database and exercises the main
pages plus the group create/edit routes, asserting nothing returns a 5xx.

This catches the class of bug a syntax/compile check can't see: a route that
500s at runtime (wrong model assigned to a relationship, unguarded int() on
form input, a template that errors, etc.). It needs no configured install and
no network, so it runs in CI on every push.

SAFETY: it refuses to run if a real database already exists, and it removes any
data files it created, so it never touches a live install's data.

    python tests/smoke_test.py     # exits 0 if all checks pass, 1 otherwise
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE

# Never clobber a real install: only run against a fresh, throwaway data dir.
if DB_PATH.exists():
    print("SKIP: %s already exists — the smoke test only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}

# Mark setup complete in config BEFORE the app loads it — is_setup_complete()
# requires both this flag and a SetupState(complete=True) row (added below).
from config import load_config, save_config
_cfg = load_config()
_cfg["setup_complete"] = True
save_config(_cfg)

from app import create_app
from models import db, User, Group, RemoteServer, GameServer, SetupState
import auth

app = create_app()
app.config["WTF_CSRF_ENABLED"] = False   # test client posts without a browser-issued token
app.config["SESSION_PROTECTION"] = None  # tests inject the session directly (no IP/UA fingerprint)
app.config["SESSION_COOKIE_SECURE"] = False  # test client talks http://; Secure cookies wouldn't round-trip
app.config["REMEMBER_COOKIE_SECURE"] = False
results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def client_as(user_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = str(user_id)
        s["_fresh"] = True
    return c


def cleanup():
    # Release the SQLite file handle first, or Windows won't let us delete it.
    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass   # best-effort cleanup in a throwaway test
    # Remove only what we created, so a local run leaves the tree clean.
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE):
        if p not in _PREEXISTING and p.exists():
            try:
                p.unlink()
            except OSError:
                pass


try:
    # ── Fixtures: a superadmin, one remote host, one game server on it ──
    with app.app_context():
        db.session.add(SetupState(step="complete", complete=True))
        admin = User(username="smoke_admin",
                     password_hash=auth.hash_password("Str0ng!passw0rd"),
                     display_name="Smoke Admin", is_superadmin=True, is_active=True)
        db.session.add(admin)
        remote = RemoteServer(name="smoke-host", host="127.0.0.1", port=22,
                              username="root", auth_method="key", auth_credential="")
        remote2 = RemoteServer(name="smoke-host-2", host="127.0.0.1", port=22,
                               username="root", auth_method="key", auth_credential="")
        db.session.add_all([remote, remote2])
        db.session.flush()
        gs = GameServer(remote_id=remote.id, name="smoke-cs", short_name="csgoserver",
                        game_type="csgo", port=27015)
        db.session.add(gs)
        # A non-superadmin with MANAGE_REMOTES but access to remote #1 ONLY, to prove
        # remote management is scoped per host (not global with the permission).
        mrg = Group(name="smoke_mr", description="", is_default=False)
        mrg.set_permissions([auth.MANAGE_REMOTES])
        mrg.servers.append(remote)
        db.session.add(mrg)
        db.session.flush()
        mru = User(username="smoke_mr", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="MR", is_superadmin=False, is_active=True)
        mru.groups.append(mrg)
        db.session.add(mru)
        # A 2FA-enabled user with known backup codes, to exercise backup-code login.
        from config import encrypt_secret
        tfa = User(username="smoke_2fa", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="2FA", is_superadmin=True, is_active=True, totp_enabled=True,
                   totp_secret=encrypt_secret(auth.generate_totp_secret()))
        bc_codes = auth.generate_backup_codes()
        tfa.set_backup_codes(bc_codes)
        db.session.add(tfa)
        # A delegated admin: MANAGE_USERS + MANAGE_GROUPS but NOT superadmin — used to prove
        # they can't escalate to superadmin via user/group management.
        dg = Group(name="smoke_deleg", description="", is_default=False)
        dg.set_permissions([auth.MANAGE_USERS, auth.MANAGE_GROUPS])
        db.session.add(dg)
        db.session.flush()
        deleg = User(username="smoke_deleg", password_hash=auth.hash_password("Str0ng!passw0rd"),
                     display_name="Deleg", is_superadmin=False, is_active=True)
        deleg.groups.append(dg)
        db.session.add(deleg)
        db.session.commit()
        admin_id, remote_id = admin.id, remote.id
        remote2_id, mru_id = remote2.id, mru.id
        gs_id = gs.id
        bc_code = bc_codes[0]
        deleg_id, admin2_id = deleg.id, tfa.id

    c = client_as(admin_id)

    # ── Every main page must RENDER (200) — not 500, and not a silent redirect
    #    to /setup or /login (which would mean the check isn't really exercising
    #    the page). We skip pages that shell out to host-only tooling
    #    (/server-management runs ufw/systemctl), so the test stays portable.
    for path in ["/", "/users", "/groups", "/logs", "/remotes", "/tailscale", "/account"]:
        code = c.get(path).status_code
        check("GET %s renders (200)" % path, code == 200, "got %d" % code)

    # ── Audit-log filters/sort must be injection-safe: a junk sort column, bad
    #    direction/status, and hostile filter values are allowlisted/parameterized,
    #    so the page still renders 200 rather than 500. ──
    r = c.get("/logs?sort=id%3BDROP+TABLE&dir=nonsense&status=xyz"
              "&q=%27%22%3B--&action=whatever&user=nobody")
    check("GET /logs with junk filter/sort params -> 200 (allowlisted)",
          r.status_code == 200, "got %d" % r.status_code)

    # The Files & Config page (config editor + file browser + cron manager) must render.
    check("GET /server/<id>/files renders (200)",
          c.get("/server/%d/files" % gs_id).status_code == 200)

    # Alerts endpoint: GET returns the provider list; POST filters to known keys and never 500s
    # (the config write to the game host fails on the test box, but returns gracefully).
    al = c.get("/api/server/%d/alerts" % gs_id)
    check("alerts: GET returns the provider list",
          al.status_code == 200 and isinstance((al.get_json() or {}).get("providers"), list))
    alp = c.post("/api/server/%d/alerts" % gs_id, json={"values": {"discordalert": "on", "notakey": "x"}})
    check("alerts: POST returns a JSON result (no 500)", "success" in (alp.get_json() or {}))

    # Liveness probe: unauthenticated, returns 200 + {"status":"ok"}, works pre-login.
    hz = app.test_client().get("/healthz")
    check("GET /healthz -> 200 ok (unauthenticated)",
          hz.status_code == 200 and (hz.get_json() or {}).get("status") == "ok",
          "got %d" % hz.status_code)

    # Panel self-update live-log endpoint renders (no update running -> exists:false).
    ul = c.get("/api/panel/update-log")
    check("GET /api/panel/update-log -> 200 (superadmin)",
          ul.status_code == 200 and "lines" in (ul.get_json() or {}), "got %d" % ul.status_code)

    # change-port validation: out-of-range ports are refused BEFORE any save/restart, so
    # these are side-effect-free. (A valid port would restart the panel — not exercised here.)
    cp1 = c.post("/api/panel/change-port", json={"port": 80})
    check("change-port refuses a privileged port (<1024)",
          cp1.status_code == 400 and not (cp1.get_json() or {}).get("success"))
    cp2 = c.post("/api/panel/change-port", json={"port": 99999})
    check("change-port refuses an out-of-range port (>65535)",
          cp2.status_code == 400 and not (cp2.get_json() or {}).get("success"))
    # Bind-address validation: a non-IP is rejected by ipaddress parsing before any save or
    # restart, so this is env-independent and side-effect-free.
    cp3 = c.post("/api/panel/change-port", json={"port": 5000, "bind_host": "not-an-ip"})
    check("change-port refuses a non-IP bind address",
          cp3.status_code == 400 and not (cp3.get_json() or {}).get("success"))

    # ── Backups: list + settings + name validation (no real backup/restart triggered) ──
    bl = c.get("/api/panel/backups")
    _blj = bl.get_json() or {}
    check("backups: list endpoint returns backups + settings",
          bl.status_code == 200 and "settings" in _blj and "backups" in _blj)
    check("backups: response includes full-backup settings + per-server games",
          "full" in _blj and "games" in _blj)
    bset = c.post("/api/panel/backup/settings", json={"enabled": True, "keep_days": 7,
                                                      "full_interval_days": 7, "full_keep": 2})
    check("backups: settings save round-trips keep_days + full settings",
          (bset.get_json() or {}).get("settings", {}).get("keep_days") == 7
          and (bset.get_json() or {}).get("full", {}).get("interval_days") == 7)
    bdel = c.post("/api/panel/backup/delete", json={"name": "../../etc/passwd"})
    check("backups: delete rejects a traversal name", not (bdel.get_json() or {}).get("success"))
    bres = c.post("/api/panel/backup/restore", json={"name": "nope.tar.gz"})
    check("backups: restore rejects an invalid name", not (bres.get_json() or {}).get("success"))
    check("backups: download 404s on a bad name", c.get("/api/panel/backup/download/..%2f..%2fetc%2fpasswd").status_code in (400, 404))

    # ── Privilege-escalation guards: a delegated admin (MANAGE_USERS + MANAGE_GROUPS,
    #    NOT superadmin) must not be able to become / create a superadmin. ──
    dc = client_as(deleg_id)
    dc.post("/users/add", data={"username": "esc_user", "password": "Str0ng!passw0rd",
                                "is_superadmin": "on"})
    with app.app_context():
        eu = User.query.filter_by(username="esc_user").first()
        check("MANAGE_USERS user can't create a superadmin", eu is None or not eu.is_superadmin)
    dc.post("/users/%d/edit" % admin2_id,
            data={"is_superadmin": "on", "is_active": "on", "password": "hijacked1!A"})
    with app.app_context():
        a2 = User.query.get(admin2_id)
        check("MANAGE_USERS user can't reset a superadmin's password",
              a2.is_superadmin and auth.check_password("Str0ng!passw0rd", a2.password_hash))
    dc.post("/groups/add", data={"name": "esc_group", "permissions": ["super_admin", "manage_users"]})
    with app.app_context():
        eg = Group.query.filter_by(name="esc_group").first()
        check("MANAGE_GROUPS user can't grant super_admin to a group",
              eg is not None and "super_admin" not in eg.get_permissions())

    # ── Group create via the real route WITH a host selected. This is the exact
    #    regression that 500'd: the route assigned GameServer objects to
    #    Group.servers, which is a RemoteServer collection. ──
    import secrets as _secrets
    gtag = "smokegrp_" + _secrets.token_hex(3)
    r = c.post("/groups/add", data={"name": gtag,
                                    "permissions": auth.VIEW_SERVERS,
                                    "servers": str(remote_id)})
    check("POST /groups/add with a host selected -> not 5xx", r.status_code < 500,
          "got %d" % r.status_code)
    with app.app_context():
        g = Group.query.filter_by(name=gtag).first()
        gid = g.id if g else None
        check("add_group persisted host access",
              g is not None and any(rs.id == remote_id for rs in g.servers))

    # ── Group edit, including deliberately malformed/unknown server ids: must
    #    not 5xx and must keep only the valid host. ──
    if gid:
        r = c.post("/groups/%d/edit" % gid,
                   data={"name": gtag, "permissions": auth.VIEW_SERVERS,
                         "servers": ["not-a-number", "999999", str(remote_id)]})
        check("POST /groups/<id>/edit tolerates bad ids -> not 5xx",
              r.status_code < 500, "got %d" % r.status_code)
        with app.app_context():
            g = Group.query.get(gid)
            check("edit_group kept only the valid host",
                  g is not None and [rs.id for rs in g.servers] == [remote_id])

    # ── A non-numeric port must not 5xx the settings/remote forms ──
    r = c.post("/remotes/%d/edit" % remote_id,
               data={"name": "smoke-host", "host": "127.0.0.1", "ssh_port": "abc",
                     "ssh_user": "root", "auth_method": "key"})
    check("POST /remotes/<id>/edit with non-numeric port -> not 5xx",
          r.status_code < 500, "got %d" % r.status_code)

    # ── Remote management is scoped per host: a MANAGE_REMOTES user can reach the
    #    remote their group grants, but a NON-granted remote id returns 403 (no
    #    remote-level IDOR). The 403 is enforced in get_remote before any SSH. ──
    mrc = client_as(mru_id)
    check("MANAGE_REMOTES user: /remotes renders (200)",
          mrc.get("/remotes").status_code == 200)
    check("MANAGE_REMOTES user: non-granted remote -> 403",
          mrc.get("/api/remote/%d/firewall" % remote2_id).status_code == 403)
    check("MANAGE_REMOTES user: non-granted remote reboot -> 403",
          mrc.post("/api/remote/%d/reboot" % remote2_id).status_code == 403)

    # ── Scheduled-tasks (cron) endpoints need MANAGE_SERVERS (same gate as the file
    #    editor). The MANAGE_REMOTES user CAN reach this server (its group grants the
    #    host) but lacks MANAGE_SERVERS, so every cron verb is refused with 403 — and
    #    the refusal happens before any SSH, so the check stays offline/portable. ──
    check("cron list without MANAGE_SERVERS -> 403",
          mrc.get("/api/server/%d/cron" % gs_id).status_code == 403)
    check("cron add without MANAGE_SERVERS -> 403",
          mrc.post("/api/server/%d/cron" % gs_id,
                   json={"schedule": "@daily", "command": "/bin/true"}).status_code == 403)
    check("cron delete without MANAGE_SERVERS -> 403",
          mrc.post("/api/server/%d/cron/delete" % gs_id, json={"raw": "x"}).status_code == 403)

    # ── Cookie-reuse defense: a session/remember cookie captured before logout must
    #    NOT work after logout. We log in for real (so we get genuine signed session +
    #    remember_token cookies), clone the cookie jar the way a thief would, log out,
    #    then replay the pre-logout cookies. They must work BEFORE and be rejected AFTER.
    #    This proves logout invalidates cookies server-side (epoch bump), not just in the
    #    browser (where clearing the client's copy wouldn't stop a captured one). ──
    def _cookie_names(client):
        return {k[2] for k in getattr(client, "_cookies", {})}

    def _clone_cookies(src, keep=None):
        """A fresh client holding a snapshot of src's cookies (optionally only those
        whose name is in `keep`) — a stand-in for cookies captured off the wire/disk."""
        t = app.test_client()
        jar = dict(getattr(src, "_cookies", {}))
        if keep is not None:
            jar = {k: v for k, v in jar.items() if k[2] in keep}
        t._cookies = jar
        return t

    victim = app.test_client()
    lr = victim.post("/login", data={"username": "smoke_admin",
                                     "password": "Str0ng!passw0rd", "remember": "on"})
    check("real login succeeds (302 to app)", lr.status_code == 302, "got %d" % lr.status_code)
    names = _cookie_names(victim)
    check("login issued a session cookie", any("session" in n for n in names), str(names))
    check("login issued a remember_token cookie", "remember_token" in names, str(names))

    # Snapshot the cookies a thief would hold — BOTH cookies, and the remember_token
    # (the long-lived one) on its own — while the victim is still logged in.
    thief = _clone_cookies(victim)
    thief_rt = _clone_cookies(victim, keep={"remember_token"})
    check("stolen cookie works BEFORE logout (200)", thief.get("/").status_code == 200)

    # Log the victim out (bumps auth_epoch), then replay the snapshots.
    victim.post("/logout")
    check("REUSE BLOCKED: stolen cookie rejected AFTER logout (not 200)",
          thief.get("/").status_code != 200, "cookie still valid after logout!")
    check("REUSE BLOCKED: stolen remember_token rejected after logout (not 200)",
          thief_rt.get("/").status_code != 200, "remember_token still valid after logout!")

    # A login for a nonexistent user must not 5xx (it runs the anti-enumeration dummy
    # bcrypt path) and must not authenticate. One attempt stays under the throttle.
    r = app.test_client().post("/login", data={"username": "no_such_user_smoke",
                                               "password": "whatever"})
    check("login with unknown user -> not 5xx (dummy-check path)",
          r.status_code < 500, "got %d" % r.status_code)

    # 2FA backup code: after the password step, a valid one-time backup code signs the
    # user in — and can't be reused. (A success clears the login throttle for this IP.)
    b1 = app.test_client()
    s1 = b1.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
    check("2FA user: password step returns the 2FA prompt (200)", s1.status_code == 200,
          "got %d" % s1.status_code)
    s2 = b1.post("/login", data={"totp_code": bc_code})
    check("2FA backup code signs the user in (302)", s2.status_code == 302, "got %d" % s2.status_code)
    b2 = app.test_client()
    b2.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
    s3 = b2.post("/login", data={"totp_code": bc_code})
    check("2FA backup code is one-time (reuse rejected, not 302)", s3.status_code != 302,
          "got %d" % s3.status_code)

    # ── Security headers present on every response ────────────────
    hr = app.test_client().get("/login")
    check("security header: X-Frame-Options=SAMEORIGIN",
          hr.headers.get("X-Frame-Options") == "SAMEORIGIN",
          "got %r" % hr.headers.get("X-Frame-Options"))
    check("security header: X-Content-Type-Options=nosniff",
          hr.headers.get("X-Content-Type-Options") == "nosniff")
    check("security header: Referrer-Policy set", bool(hr.headers.get("Referrer-Policy")))
    check("security header: Permissions-Policy denies unused features",
          "camera=()" in (hr.headers.get("Permissions-Policy") or ""))
    check("security header: Content-Security-Policy set",
          bool(hr.headers.get("Content-Security-Policy")))
    check("security header: X-Robots-Tag noindex (keep out of search engines)",
          "noindex" in (hr.headers.get("X-Robots-Tag") or ""))
    _rb = app.test_client().get("/robots.txt")
    check("robots.txt is served (200)", _rb.status_code == 200, "got %d" % _rb.status_code)
    check("robots.txt disallows all crawling", b"Disallow: /" in _rb.data)
    check("icon webfont is preloaded (CLS fix)",
          b'rel="preload"' in hr.data and b"bootstrap-icons.woff2" in hr.data)
    check("Server header genericized (no framework/version leak)",
          hr.headers.get("Server") == "LinuxGSM Panel" and "Werkzeug" not in (hr.headers.get("Server") or ""))

    # ── CSRF protection rejects a tokenless mutating POST ─────────
    # This client has CSRF disabled for convenience; flip it back on for one
    # request and confirm a tokenless POST is refused (400) before the view runs.
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        cr = app.test_client().post("/api/server/1/action", json={"action": "start"})
        check("CSRF: tokenless mutating POST is rejected (400)", cr.status_code == 400,
              "got %d" % cr.status_code)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False

    # ── Login brute-force lockout kicks in after repeated failures ─
    from app import _LOGIN_FAILS, LOGIN_MAX_FAILS
    _LOGIN_FAILS.clear()
    lc = app.test_client()
    _locked = False
    for _ in range(LOGIN_MAX_FAILS + 2):
        lr = lc.post("/login", data={"username": "nobody_lockout", "password": "wrong"})
        if b"Too many failed attempts" in lr.data:
            _locked = True
            break
    check("login: brute-force lockout blocks after %d failures" % LOGIN_MAX_FAILS, _locked)
    _LOGIN_FAILS.clear()   # isolate: don't leave 127.0.0.1 locked for anything else

    # ── Database maintenance: stats + VACUUM/ANALYZE optimize ─────
    with app.app_context():
        from models import database_stats, optimize_database
        _st = database_stats()
        check("db-stats: reports a positive DB size", _st["size"] > 0,
              "got %r" % _st.get("size"))
        check("db-stats: audit_rows is an int count", isinstance(_st["audit_rows"], int))
        _ok, _msg, _info = optimize_database()
        check("optimize: VACUUM/ANALYZE runs cleanly", _ok is True)
        check("optimize: reports before/after sizes with a live file",
              "before" in _info and _info.get("after", 0) > 0)

        # ── Debug report: generates, and never leaks the session/credential secrets ──
        from system_ops import generate_debug_report
        _dr = generate_debug_report()
        check("debug report: returns report/summary/issues_url/filename",
              all(k in _dr for k in ("report", "summary", "issues_url", "filename")))
        check("debug report: issues_url is a github new-issue URL",
              _dr["issues_url"].startswith("https://github.com/")
              and _dr["issues_url"].endswith("/issues/new"))
        check("debug report: includes a Last-update section (surfaces failed/rolled-back updates)",
              "### Last update" in _dr["report"])
        for _sf in (SECRET_FILE, CRED_KEY_FILE):
            if _sf.exists():
                _sv = _sf.read_text(errors="replace").strip()
                if len(_sv) >= 12:
                    check("debug report: %s not leaked" % _sf.name, _sv not in _dr["report"])

    # ── Scenario: the database is FULL (like a full disk) ─────────
    # PRAGMA max_page_count caps the DB size on this one connection, so the next
    # write hits SQLITE_FULL ("database or disk is full") — exactly what a full
    # filesystem produces. We prove the failure is CLEAN (a caught error, not
    # corruption or a crash) and that writes RESUME once space is freed.
    with app.app_context():
        raw = db.engine.raw_connection()
        try:
            cur = raw.cursor()
            # Cap the DB at its current size: SQLite clamps a smaller max_page_count up
            # to the current page count, so this static statement leaves no room to grow
            # (and avoids any formatted SQL).
            cur.execute("PRAGMA max_page_count = 1")
            _full = False
            try:
                cur.execute("CREATE TABLE IF NOT EXISTS _fulltest (b TEXT)")
                for _ in range(2000):
                    cur.execute("INSERT INTO _fulltest (b) VALUES (?)", ("x" * 900,))
                raw.commit()
            except Exception:
                _full = True
                raw.rollback()
            check("db-full: a write fails cleanly (SQLITE_FULL) when the DB is full", _full)

            # Free the 'disk' and prove the SAME connection writes again — clean recovery.
            cur.execute("PRAGMA max_page_count = 1073741823")
            _recovered = False
            try:
                cur.execute("CREATE TABLE IF NOT EXISTS _fulltest (b TEXT)")
                cur.execute("INSERT INTO _fulltest (b) VALUES ('ok')")
                raw.commit()
                _recovered = True
            except Exception:
                raw.rollback()
            check("db-full: writes succeed again after space is freed (no corruption)", _recovered)
            try:
                cur.execute("DROP TABLE IF EXISTS _fulltest")
                raw.commit()
            except Exception:
                raw.rollback()
        finally:
            raw.close()
    # The process must still serve requests after a full-DB episode (Flask isolates
    # the failed request; the scoped session rolls back at teardown).
    _hz = app.test_client().get("/healthz")
    check("db-full: panel still serves requests afterward (healthz ok)", _hz.status_code == 200)

    # ── Scenario: updating from a FAR-BEHIND old version ──────────
    # Simulate a database created by an old release that predates a column, then run
    # the same light migrations the update runs. They must re-add what's missing,
    # preserve existing rows, and be safe to run repeatedly — so an install can jump
    # forward any number of versions without breaking.
    with app.app_context():
        from sqlalchemy import text as _t, inspect as _inspect
        from models import _run_light_migrations

        def _ucols():
            return {col["name"] for col in _inspect(db.engine).get_columns("user")}

        _dropped = False
        try:
            db.session.execute(_t("ALTER TABLE user DROP COLUMN backup_codes"))
            db.session.commit()
            _dropped = True
        except Exception:
            db.session.rollback()   # SQLite too old to DROP COLUMN — idempotency check still runs
        if _dropped:
            check("migrate: legacy DB is missing a newer column", "backup_codes" not in _ucols())
            _n0 = db.session.execute(_t("SELECT COUNT(*) FROM user")).scalar()
            _run_light_migrations()                       # <- the update path
            check("migrate: update re-adds the missing column", "backup_codes" in _ucols())
            _n1 = db.session.execute(_t("SELECT COUNT(*) FROM user")).scalar()
            check("migrate: existing rows preserved through the migration", _n0 == _n1)
        _run_light_migrations()
        _run_light_migrations()   # re-running must be a safe no-op (far-behind upgrades re-apply)
        check("migrate: repeated migrations stay a safe no-op",
              "backup_codes" in _ucols() and "totp_secret" in _ucols())

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
