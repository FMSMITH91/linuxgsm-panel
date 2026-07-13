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

from config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE

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


# Every url_for('endpoint') referenced in a template must resolve to a real route — otherwise the
# page 500s the moment it renders. Catches a nav link / redirect pointing at a renamed or removed
# endpoint (the template-side companion to the data-action button-wiring test).
def _check_template_url_for():
    import pathlib
    import re
    endpoints = {r.endpoint for r in app.url_map.iter_rules()}
    bad = []
    for p in sorted(pathlib.Path("templates").glob("*.html")):
        for m in re.finditer(r"""url_for\(\s*['"]([A-Za-z_][\w]*)['"]""", p.read_text(encoding="utf-8")):
            if m.group(1) not in endpoints:
                bad.append("%s -> url_for('%s')" % (p.name, m.group(1)))
    check("templates: every url_for() endpoint exists", not bad, "; ".join(sorted(set(bad))))


_check_template_url_for()


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
                        game_type="csgo", port=27015, installed=True, status="offline")
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
    for path in ["/", "/users", "/groups", "/logs", "/remotes", "/tailscale", "/account",
                 "/notifications", "/settings"]:
        code = c.get(path).status_code
        check("GET %s renders (200)" % path, code == 200, "got %d" % code)

    # ── Sidebar active-state must use request.endpoint, NOT request.path == url_for(...) — the
    #    latter breaks under a URL mount prefix (e.g. /lgsm), where url_for includes the prefix but
    #    request.path doesn't, so nothing highlights. Exactly the current page's link is active. ──
    import re as _nre
    def _active_navs(html):
        return [m.strip() for m in _nre.findall(r'class="active">\s*<i[^>]*></i>\s*([^<]+?)\s*</a>', html)]
    check("nav active: Dashboard on /", _active_navs(c.get("/").get_data(as_text=True)) == ["Dashboard"],
          _active_navs(c.get("/").get_data(as_text=True)))
    check("nav active: Users on /users", _active_navs(c.get("/users").get_data(as_text=True)) == ["Users"])
    check("nav active: Settings on /settings",
          _active_navs(c.get("/settings").get_data(as_text=True)) == ["Settings"])

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

    # An un-installed (still-installing) server has no console/files yet — those routes must redirect
    # away, not render, so you can't reach them before the install finishes.
    with app.app_context():
        _inst = GameServer(remote_id=remote.id, name="smoke-installing", short_name="instserver",
                           game_type="gmod", port=27099, installed=False, status="installing")
        db.session.add(_inst); db.session.commit()
        _inst_id = _inst.id
    check("console of an installing server redirects (not 200)",
          c.get("/server/%d" % _inst_id).status_code in (302, 303))
    check("files of an installing server redirects (not 200)",
          c.get("/server/%d/files" % _inst_id).status_code in (302, 303))

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

    # The login page (unauthenticated) offers a language switcher so the UI language can be
    # changed before signing in — set-language works pre-login (session-scoped).
    lg = app.test_client().get("/login")
    check("GET /login renders with a language switcher",
          lg.status_code == 200 and b"/set-language/" in lg.data and b"bi-translate" in lg.data,
          "got %d" % lg.status_code)

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

    # ── Data-dir hardening: sensitive files must be owner-only. chmod only sets POSIX bits, so
    #    this is a no-op check off-Linux (Windows dev boxes); CI runs on Linux and enforces it.
    if os.name == "posix":
        import stat as _stat
        dmode = _stat.S_IMODE(os.stat(DATA_DIR).st_mode)
        check("perms: data/ is 0700 (owner-only)", dmode == 0o700, "got %o" % dmode)
        if DB_PATH.exists():
            dbmode = _stat.S_IMODE(os.stat(DB_PATH).st_mode)
            check("perms: panel.db is 0600", dbmode == 0o600, "got %o" % dbmode)
        for _kf in (SECRET_FILE, CRED_KEY_FILE):
            if _kf.exists():
                _km = _stat.S_IMODE(os.stat(_kf).st_mode)
                check("perms: %s is 0600" % _kf.name, _km == 0o600, "got %o" % _km)

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

    # ── Bulk action endpoint: guards + dispatch bookkeeping ───────
    ba_bad = c.post("/api/servers/bulk-action", json={"action": "nope", "server_ids": [gs_id]})
    check("bulk-action: unsupported action -> 400", ba_bad.status_code == 400)
    ba_empty = c.post("/api/servers/bulk-action", json={"action": "restart", "server_ids": []})
    check("bulk-action: empty selection -> 400", ba_empty.status_code == 400)
    # An unknown id is reported as skipped and dispatches nothing (keeps this test free of
    # real background SSH); with no valid ids left, success is False.
    ba_unknown = c.post("/api/servers/bulk-action", json={"action": "start", "server_ids": [999999]})
    _bu = ba_unknown.get_json() or {}
    check("bulk-action: unknown id is skipped, nothing queued",
          ba_unknown.status_code == 200 and _bu.get("success") is False
          and len(_bu.get("queued", [])) == 0 and len(_bu.get("skipped", [])) == 1,
          "got %s" % _bu)
    # A caller lacking the action's permission is refused before anything is dispatched.
    ba_perm = client_as(mru_id).post("/api/servers/bulk-action",
                                     json={"action": "start", "server_ids": [gs_id]})
    check("bulk-action: caller lacking the permission -> 403", ba_perm.status_code == 403,
          "got %d" % ba_perm.status_code)

    # A game with no LinuxGSM update command (e.g. the cod family) must be SKIPPED by a bulk
    # update, not dispatched — enforced server-side even if the client sends it.
    with app.app_context():
        noupd = GameServer(remote_id=remote_id, name="noupd", short_name="noupdsrv",
                           game_type="cod", port=28960, installed=True,
                           commands='[{"cmd":"start"},{"cmd":"stop"}]')
        db.session.add(noupd)
        db.session.commit()
        noupd_id = noupd.id
    ba_up = c.post("/api/servers/bulk-action", json={"action": "update", "server_ids": [noupd_id]})
    _bup = ba_up.get_json() or {}
    check("bulk-action: update skips a game with no update command (not dispatched)",
          ba_up.status_code == 200 and not _bup.get("queued")
          and any(s.get("reason") == "no update support" for s in _bup.get("skipped", [])),
          "got %s" % _bup)

    # ── Per-server backups info (data for the Files & Config tab), superadmin only ──
    bi = c.get("/api/panel/backup/game/%d/info" % gs_id)
    _bi = bi.get_json() or {}
    check("backup-info: returns schedule/backups/disk/default for the server",
          bi.status_code == 200 and all(k in _bi for k in ("schedule", "backups", "disk", "default")),
          "got %d %s" % (bi.status_code, sorted(_bi)))
    bi_denied = client_as(mru_id).get("/api/panel/backup/game/%d/info" % gs_id)
    check("backup-info: non-superadmin is denied (redirect/403, not 200)",
          bi_denied.status_code in (301, 302, 303, 403),
          "got %d" % bi_denied.status_code)

    # ── On-demand DB health check (read-only integrity_check), superadmin only ──
    dh = c.get("/api/panel/db-health")
    _dh = dh.get_json() or {}
    check("db-health: reports the test DB as healthy",
          dh.status_code == 200 and _dh.get("healthy") is True, "got %d %s" % (dh.status_code, _dh))
    dh_denied = client_as(mru_id).get("/api/panel/db-health")
    check("db-health: non-superadmin is denied", dh_denied.status_code in (301, 302, 303, 403),
          "got %d" % dh_denied.status_code)

    # ── Players + in-game moderation ──
    plr = c.get("/api/server/%d/playerlist" % gs_id)
    _pl = plr.get_json() or {}
    check("playerlist: returns players + caps + queryable + unknown/console_capable flags",
          plr.status_code == 200 and all(k in _pl for k in
              ("players", "caps", "queryable", "unknown", "console_capable")),
          "got %d %s" % (plr.status_code, sorted(_pl)))
    check("playerlist: caps reflect the game (csgo -> kick + say)",
          _pl.get("caps", {}).get("kick") is True and _pl.get("caps", {}).get("say") is True)
    mod_bad = c.post("/api/server/%d/moderate" % gs_id, json={"action": "nope"})
    check("moderate: unknown action -> 400", mod_bad.status_code == 400)
    # A user with server access but no moderate/console permission is refused (mru can reach the
    # server via its group's remote, but lacks moderate_server / send_command).
    mod_denied = client_as(mru_id).post("/api/server/%d/moderate" % gs_id,
                                        json={"action": "kick", "target": "x"})
    check("moderate: caller without moderate/console permission -> 403",
          mod_denied.status_code == 403, "got %d" % mod_denied.status_code)

    # ── gamedig query-type override (fix games the built-in map gets wrong, e.g. cod) ──
    qt = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": "cod"})
    _qt = qt.get_json() or {}
    check("query-type: an override can be set and takes effect",
          qt.status_code == 200 and _qt.get("success") is True and _qt.get("query_type") == "cod"
          and _qt.get("queryable") is True, "got %d %s" % (qt.status_code, _qt))
    qt_bad = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": "bad; rm -rf"})
    check("query-type: an unsafe/invalid type is rejected (400)", qt_bad.status_code == 400)
    qt_clear = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": ""})
    check("query-type: blank clears the override",
          qt_clear.status_code == 200 and (qt_clear.get_json() or {}).get("query_type") == "")

    # ── Discover / import existing LinuxGSM servers on a host ──
    dsc = c.get("/api/remote/%d/discover" % remote_id)
    check("discover: superadmin gets a servers list (SSH to the fixture host yields none)",
          dsc.status_code == 200 and isinstance((dsc.get_json() or {}).get("servers"), list),
          "got %d" % dsc.status_code)
    imp_empty = c.post("/api/remote/%d/import" % remote_id, json={"servers": []})
    check("import: empty selection -> 400", imp_empty.status_code == 400)
    # Import validates each entry like a fresh install: a bad username or unknown game is
    # skipped (so an imported short_name can never carry shell metacharacters); a valid one is added.
    imp = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
        {"user": "importedcs", "game_type": "csgo", "port": 27015},
        {"user": "BAD NAME", "game_type": "csgo", "port": 1},
        {"user": "okuser", "game_type": "notarealgame", "port": 1}]})
    _im = imp.get_json() or {}
    check("import: adds the valid server, skips the bad name + unknown game",
          imp.status_code == 200 and _im.get("added") == ["importedcs"] and len(_im.get("skipped", [])) == 2,
          "got %s" % _im)
    imp_denied = client_as(mru_id).post("/api/remote/%d/import" % remote_id,
                                        json={"servers": [{"user": "x", "game_type": "csgo"}]})
    check("import: caller without manage_servers is denied",
          imp_denied.status_code in (301, 302, 303, 403), "got %d" % imp_denied.status_code)

    # ── Session management: per-device login sessions + individual revoke ──
    from models import UserSession

    def _real_login(username="smoke_admin", pw="Str0ng!passw0rd"):
        cc = app.test_client()
        rr = cc.post("/login", data={"username": username, "password": pw}, follow_redirects=False)
        return cc, rr

    s1, r1 = _real_login()
    check("session: real login lands in (redirect away from /login)",
          r1.status_code in (301, 302, 303) and "/login" not in (r1.headers.get("Location") or ""),
          "status=%d loc=%s" % (r1.status_code, r1.headers.get("Location") or ""))
    with app.app_context():
        n1 = UserSession.query.filter_by(user_id=admin_id).count()
    check("session: login created a server-side session row", n1 >= 1, "rows=%d" % n1)

    j1 = (s1.get("/api/account/sessions").get_json() or {})
    sess1 = j1.get("sessions", [])
    check("session: API lists the current session, flagged current",
          any(s.get("current") for s in sess1), "n=%d" % len(sess1))

    s2, _ = _real_login()   # a second device for the same account
    all2 = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
    check("session: a second login shows two sessions", len(all2) == 2, "n=%d" % len(all2))

    other = next((s for s in all2 if not s.get("current")), None)
    rv = s1.post("/api/account/sessions/%d/revoke" % other["id"]) if other else None
    rvj = rv.get_json() if rv is not None else {}
    check("session: revoke a non-current session -> ok",
          rv is not None and rv.status_code == 200 and rvj.get("ok") and not rvj.get("current"))

    acc2 = s2.get("/account", follow_redirects=False)
    check("session: the revoked device is signed out (loader rejects its sid)",
          acc2.status_code in (301, 302, 303) and "/login" in (acc2.headers.get("Location") or ""),
          "status=%d" % acc2.status_code)
    with app.app_context():
        n_after = UserSession.query.filter_by(user_id=admin_id).count()
        os_ = UserSession(user_id=mru_id, sid="smoke_other_sid", ip="", user_agent="")
        db.session.add(os_)
        db.session.commit()
        other_uid_sess = os_.id
    check("session: revoked row is gone (one left)", n_after == 1, "rows=%d" % n_after)

    xrv = s1.post("/api/account/sessions/%d/revoke" % other_uid_sess)
    check("session: can't revoke another user's session (404)", xrv.status_code == 404,
          "status=%d" % xrv.status_code)

    with app.app_context():
        epoch_before = db.session.get(User, admin_id).auth_epoch or 0
    s1.post("/account/sessions/revoke")   # sign out everywhere
    with app.app_context():
        u_after = db.session.get(User, admin_id)
        n_all = UserSession.query.filter_by(user_id=admin_id).count()
        epoch_after = u_after.auth_epoch or 0
    check("session: sign-out-everywhere clears all rows and bumps the epoch",
          n_all == 0 and epoch_after > epoch_before,
          "rows=%d epoch %d->%d" % (n_all, epoch_before, epoch_after))

    # ── perf regression guard: NO N+1 on the hot paths ────────────
    # Seed 50 game servers across 5 hosts — enough that a per-server (rather than
    # per-host) query pattern would blow the budget — then assert the dashboard render
    # and the /api/servers status poll each stay within a small, host-bounded query
    # budget. This is the class of regression that let /api/servers balloon to 53
    # queries before the joinedload fix (now ~3); a budget here fails the build if it
    # ever comes back. run_command is stubbed so the port scan does no real SSH.
    from sqlalchemy import event as _sa_event
    _appmod = sys.modules["app"]
    with app.app_context():
        for _r in range(5):
            _rem = RemoteServer(name="qc-host%d" % _r, host="10.20.0.%d" % _r, port=22,
                                username="root", auth_method="key", auth_credential="",
                                public_ip="203.0.113.%d" % _r)
            db.session.add(_rem)
            db.session.flush()
            for _g in range(10):
                db.session.add(GameServer(remote_id=_rem.id, name="qc%d-%d" % (_r, _g),
                                          short_name="qc%d_%d" % (_r, _g), game_type="gmod",
                                          port=27100 + _g, installed=True, status="offline"))
        db.session.commit()
        _seeded = GameServer.query.count()
        _engine = db.engine

    _Q = {"n": 0}

    def _count_query(*_a, **_k):
        _Q["n"] += 1

    _orig_rc = _appmod.run_command
    _appmod.run_command = lambda *a, **k: ("", "", 0)   # port scan: no real SSH, no matches
    _sa_event.listen(_engine, "after_cursor_execute", _count_query)
    try:
        def _qcount(path):
            _appmod._port_scan_cache.clear()   # force the (stubbed) scan each time, for consistency
            _Q["n"] = 0
            resp = c.get(path)
            return _Q["n"], resp.status_code

        c.get("/api/servers")                  # warm one-time caches so the count is steady
        _api_q, _api_code = _qcount("/api/servers")
        _dash_q, _dash_code = _qcount("/")
        check("perf: /api/servers renders with 50 servers", _api_code == 200, "got %d" % _api_code)
        check("perf: /api/servers query count is host-bounded, not per-server (no N+1)",
              _api_q <= 15, "%d queries for %d servers" % (_api_q, _seeded))
        check("perf: dashboard renders with 50 servers", _dash_code == 200, "got %d" % _dash_code)
        check("perf: dashboard query count stays small (no N+1)",
              _dash_q <= 20, "%d queries for %d servers" % (_dash_q, _seeded))

        # Regression: the /api/servers status poll must NOT clobber an in-progress install's
        # status. The port scan (stubbed empty here) finds nothing listening for a still-installing
        # server, so the old code flipped "installing" -> "offline" — which made the progress row
        # vanish and show "Not installed" the moment you navigated back to the page.
        with app.app_context():
            _rid = RemoteServer.query.first().id
            _inst = GameServer(remote_id=_rid, name="inst-cs", short_name="instcs",
                               game_type="gmod", port=27099, installed=False, status="installing")
            db.session.add(_inst)
            db.session.commit()
            _inst_id = _inst.id
        _appmod._port_scan_cache.clear()
        c.get("/api/servers")   # the poll that reconcileServerList / the dashboard fires
        with app.app_context():
            _after_status = db.session.get(GameServer, _inst_id).status
        check("install: /api/servers poll does NOT clobber an installing server's status",
              _after_status == "installing", "status became %r after the poll" % _after_status)
    finally:
        _sa_event.remove(_engine, "after_cursor_execute", _count_query)
        _appmod.run_command = _orig_rc

    # ── Light-migration coverage ──────────────────────────────────────────────────────────────────
    # The ALTER-TABLE list in models.py is what upgrades a database created by an OLDER panel version
    # (create_all() never ALTERs existing tables). Assert it references only real columns and that it
    # actually restores a column that's gone missing — a model column added WITHOUT a matching entry
    # here is the class of bug that once shipped a broken api_token migration.
    with app.app_context():
        import re as _re_mig
        import pathlib as _pl_mig
        import sqlite3 as _sqlite_mig
        from sqlalchemy import inspect as _sa_inspect, text as _sa_text
        from models import _run_light_migrations as _rlm
        _models_src = (_pl_mig.Path(__file__).resolve().parent.parent / "models.py").read_text(encoding="utf-8")
        _mig = _re_mig.findall(r'\(\s*"(\w+)"\s*,\s*"(\w+)"\s*\)\s*:\s*"(ALTER TABLE [^"]+)"', _models_src)
        check("migration: the light-migration list parses out of models.py", len(_mig) > 5)
        _cols = {t: {c["name"] for c in _sa_inspect(db.engine).get_columns(t)}
                 for t in _sa_inspect(db.engine).get_table_names()}
        _stale = [(t, c) for t, c, _ in _mig if c not in _cols.get(t, set())]
        check("migration: no entry targets a table/column that no longer exists", not _stale, str(_stale))
        try:
            _rlm(); _rlm()   # commits internally; a no-op on an already-current schema, run twice
            _idem_ok, _idem_err = True, ""
        except Exception as _e:
            db.session.rollback(); _idem_ok, _idem_err = False, repr(_e)
        check("migration: _run_light_migrations is a safe idempotent no-op on a current DB",
              _idem_ok, _idem_err)
        # Prove one entry's DDL really restores a dropped column (SQLite >= 3.35 supports DROP COLUMN).
        if _sqlite_mig.sqlite_version_info >= (3, 35, 0) and "notify_when_empty" in _cols.get("game_server", set()):
            try:
                db.session.execute(_sa_text("ALTER TABLE game_server DROP COLUMN notify_when_empty"))
                db.session.commit()
                _gone = "notify_when_empty" not in {c["name"] for c in _sa_inspect(db.engine).get_columns("game_server")}
                _rlm()
                _back = "notify_when_empty" in {c["name"] for c in _sa_inspect(db.engine).get_columns("game_server")}
                check("migration: a dropped column is restored by _run_light_migrations", _gone and _back)
            except Exception as _e:
                db.session.rollback()
                check("migration: a dropped column is restored by _run_light_migrations", False, repr(_e))

    # ── Monitor + player-count poller transition logic ────────────────────────────────────────────
    # These background passes drive the admin notifications. create_app() does NOT start the watcher
    # threads, so we run a pass by hand — single-threaded, with the host/SSH helpers stubbed — to
    # exercise the real up/down, suppression, and notify-when-empty branches in _monitor_pass /
    # _refresh_player_counts and confirm each fires (or stays silent) exactly when it should.
    with app.app_context():
        import time as _time_mon
        _am = sys.modules["app"]
        _r1 = RemoteServer.query.filter_by(name="smoke-host").first()
        _mon = GameServer(remote_id=_r1.id, name="mon-srv", short_name="monserver",
                          game_type="csgo", port=27100, installed=True, status="online")
        db.session.add(_mon); db.session.commit()
        _mon_id, _r1_id = _mon.id, _r1.id
        _rec = []
        _saved = {n: getattr(_am, n) for n in ("_host_reachable", "_remote_listening_ports",
                  "_host_disk_pct", "_host_load_mem", "_server_slots", "_server_max_config")}
        _saved_notify = _am.notifications.notify
        _saved_mstate = _am._monitor_state
        _saved_exp = dict(_am._expected_offline)
        _saved_full = dict(_am._server_full_alerted)
        _saved_peak = dict(_am._server_peak_notified)
        _saved_pc = dict(_am._player_counts)
        try:
            _am.notifications.notify = lambda key, title, body="": _rec.append(key)
            _am._host_reachable = lambda r: True
            _am._host_disk_pct = lambda r: 40
            _am._host_load_mem = lambda r: (10, 10)
            _am._server_max_config = lambda gs: 16

            def _reset_mon():
                _am._monitor_state = {"remotes": {}, "servers": {}, "disk": {}, "load": {}}

            # The very first pass only records a baseline — nothing alerts on startup.
            _reset_mon()
            _am._remote_listening_ports = lambda r: {27100}
            _rec.clear(); _am._monitor_pass()
            check("monitor: the first pass is a silent baseline (no startup alerts)",
                  not any(k in _rec for k in ("server_down", "server_up", "remote_unreachable")),
                  "fired: %s" % _rec)

            # A server that was up and is no longer listening -> server_down.
            _am._remote_listening_ports = lambda r: set()
            _rec.clear(); _am._monitor_pass()
            check("monitor: server_down fires on an up->down transition", "server_down" in _rec)

            # ...but a panel-issued stop (inside the expected-offline window) suppresses it.
            _reset_mon()
            _am._monitor_state["servers"][_mon_id] = True
            _am._expected_offline[_mon_id] = _time_mon.time()
            _am._remote_listening_ports = lambda r: set()
            _rec.clear(); _am._monitor_pass()
            check("monitor: a panel-issued stop suppresses server_down", "server_down" not in _rec)
            _am._expected_offline.pop(_mon_id, None)

            # A reachable host that stops responding -> remote_unreachable.
            _reset_mon()
            _am._monitor_state["remotes"] = {_r1_id: True}
            _am._host_reachable = lambda r: r.id != _r1_id
            _rec.clear(); _am._monitor_pass()
            check("monitor: remote_unreachable fires when a host stops responding",
                  "remote_unreachable" in _rec)
            _am._host_reachable = lambda r: True

            # Poller: notify_when_empty is a one-shot on a CONFIRMED 0 that then disarms itself.
            _mon.notify_when_empty = True; db.session.commit()
            _am._server_slots = lambda gs: (0, 16, None)
            _rec.clear(); _am._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("poller: notify_when_empty fires server_empty at a confirmed 0", "server_empty" in _rec)
            check("poller: notify_when_empty is one-shot (clears its own flag)",
                  _mon.notify_when_empty is False)

            # ...but it must NEVER fire on an unknown count (a running server the panel can't read).
            _mon.notify_when_empty = True; db.session.commit()

            def _unreadable(gs):
                raise RuntimeError("count unavailable")
            _am._server_slots = _unreadable
            _rec.clear(); _am._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("poller: notify_when_empty does NOT fire on an unknown count", "server_empty" not in _rec)
            check("poller: notify_when_empty stays armed when the count is unknown",
                  _mon.notify_when_empty is True)

            # server_full fires when a server reaches its cap.
            _am._server_full_alerted.pop(_mon_id, None)
            _am._server_slots = lambda gs: (16, 16, None)
            _rec.clear(); _am._refresh_player_counts(app)
            check("poller: server_full fires when a server hits its cap", "server_full" in _rec)
        finally:
            _am.notifications.notify = _saved_notify
            for _n, _v in _saved.items():
                setattr(_am, _n, _v)
            _am._monitor_state = _saved_mstate
            _am._expected_offline.clear(); _am._expected_offline.update(_saved_exp)
            _am._server_full_alerted.clear(); _am._server_full_alerted.update(_saved_full)
            _am._server_peak_notified.clear(); _am._server_peak_notified.update(_saved_peak)
            _am._player_counts.clear(); _am._player_counts.update(_saved_pc)
            db.session.delete(_mon); db.session.commit()

    # ── Auto-block reconcile: attempts-threshold selection + whitelist exemption ───────────────────
    # Drive _autoblock_reconcile against a stubbed offender list / UFW so no SSH or real firewall is
    # touched, proving it blocks by 7-day attempt count (not rank), skips whitelisted IPs, and
    # releases its own stale blocks.
    with app.app_context():
        import ipaddress as _ipa_ab
        _am = sys.modules["app"]
        _r = RemoteServer.query.filter_by(name="smoke-host").first()
        _was_local = _r.is_local
        _r.is_local = True          # exercise the local (so.*) branch — no SSH
        db.session.commit()
        _denied, _undenied = [], []
        _sv = {n: getattr(_am.so, n) for n in ("fail2ban_top_ips", "ufw_blocked_ips",
               "ufw_deny_ip", "ufw_undeny_ip")}
        _sv_tn, _sv_th, _sv_wl = _am.tailnet_exempt_ips, _am._autoblock_threshold, _am._whitelist_networks
        try:
            _am.so.fail2ban_top_ips = lambda limit=100, days=7: [
                {"ip": "203.0.113.10", "attempts": 80, "bans": 0},   # over threshold  -> block
                {"ip": "203.0.113.11", "attempts": 5, "bans": 0},    # under threshold -> ignore
                {"ip": "10.9.9.9", "attempts": 500, "bans": 0},      # over, but WHITELISTED -> skip
            ]
            _am.so.ufw_blocked_ips = lambda: {"203.0.113.99": "panel-autoblock"}   # our stale block
            _am.so.ufw_deny_ip = lambda ip, tag=None: (_denied.append(ip), (True, "ok"))[1]
            _am.so.ufw_undeny_ip = lambda ip: (_undenied.append(ip), (True, "ok"))[1]
            _am.tailnet_exempt_ips = lambda remote, ips: set()
            _am._autoblock_threshold = lambda: 20
            _am._whitelist_networks = lambda: [_ipa_ab.ip_network("10.0.0.0/8")]
            _added, _removed = _am._autoblock_reconcile(_r)
            check("autoblock: an IP at/above the 7-day attempt threshold is blocked", "203.0.113.10" in _denied)
            check("autoblock: an IP below the threshold is NOT blocked", "203.0.113.11" not in _denied)
            check("autoblock: a whitelisted IP is never blocked even far over threshold", "10.9.9.9" not in _denied)
            check("autoblock: a stale auto-block that no longer qualifies is released", "203.0.113.99" in _undenied)
        finally:
            for _n, _v in _sv.items():
                setattr(_am.so, _n, _v)
            _am.tailnet_exempt_ips, _am._autoblock_threshold, _am._whitelist_networks = _sv_tn, _sv_th, _sv_wl
            _r.is_local = _was_local
            db.session.commit()

    # ── Global ban list endpoints (fan-out to servers stubbed, so no SSH) ──────────────────────────
    with app.app_context():
        from models import GlobalBan
        _am = sys.modules["app"]
        _saved_fan = _am._fan_out_global_ban
        _am._fan_out_global_ban = lambda a, sid, unban=False: None
        try:
            _gc = client_as(admin_id)
            _r1 = _gc.post("/global-bans/add", data={"steamid": "STEAM_0:1:99", "reason": "cheating"})
            check("global-ban: add returns a redirect", _r1.status_code in (302, 303))
            _gb = GlobalBan.query.filter_by(steamid="STEAM_0:1:99").first()
            check("global-ban: add persists the SteamID + reason", _gb is not None and _gb.reason == "cheating")
            _cnt = GlobalBan.query.count()
            _gc.post("/global-bans/add", data={"steamid": "not-a-steamid"})
            check("global-ban: an invalid SteamID is rejected (not stored)", GlobalBan.query.count() == _cnt)
            _pg = _gc.get("/global-bans")
            check("global-ban: page lists the ban", _pg.status_code == 200 and b"STEAM_0:1:99" in _pg.data)
            _del = _gc.post("/global-bans/%d/delete" % _gb.id)
            check("global-ban: delete removes it",
                  _del.status_code in (302, 303) and db.session.get(GlobalBan, _gb.id) is None)
        finally:
            _am._fan_out_global_ban = _saved_fan

    # ── Telegram command bot: server-name resolution for /start /stop /restart /players ────────────
    with app.app_context():
        from app import _tg_find_server
        _g, _e = _tg_find_server("smoke-cs")               # by display name
        check("telegram: resolve a server by name", _g is not None and _e is None)
        _g2, _e2 = _tg_find_server("csgoserver")           # by short_name
        check("telegram: resolve a server by short_name", _g2 is not None)
        _g3, _e3 = _tg_find_server("no-such-server-xyz")   # unknown
        check("telegram: an unknown server name returns a helpful error", _g3 is None and "No server" in (_e3 or ""))

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
