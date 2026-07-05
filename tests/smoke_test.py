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

from config import DB_PATH, DATA_DIR, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE

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
    except Exception:
        pass
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
        db.session.commit()
        admin_id, remote_id = admin.id, remote.id
        remote2_id, mru_id = remote2.id, mru.id

    c = client_as(admin_id)

    # ── Every main page must RENDER (200) — not 500, and not a silent redirect
    #    to /setup or /login (which would mean the check isn't really exercising
    #    the page). We skip pages that shell out to host-only tooling
    #    (/server-management runs ufw/systemctl), so the test stays portable.
    for path in ["/", "/users", "/groups", "/logs", "/remotes", "/tailscale"]:
        code = c.get(path).status_code
        check("GET %s renders (200)" % path, code == 200, "got %d" % code)

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

    # ── Cookie-reuse defense: a session/remember cookie captured before logout must
    #    NOT work after logout. We log in for real (so we get genuine signed session +
    #    remember_token cookies), copy them the way a thief would, log out, then replay
    #    the copied cookies against a fresh client. They must be rejected. This proves
    #    logout invalidates cookies server-side (epoch bump), not just in the browser. ──
    victim = app.test_client()
    lr = victim.post("/login", data={"username": "smoke_admin",
                                     "password": "Str0ng!passw0rd", "remember": "on"})
    check("real login succeeds (302 to app)", lr.status_code == 302, "got %d" % lr.status_code)
    # Rebuild the raw Cookie header from the login response's Set-Cookie(s) — this is
    # exactly what an attacker who sniffed/exfiltrated the cookies would hold.
    set_cookies = lr.headers.getlist("Set-Cookie")
    stolen = "; ".join(sc.split(";", 1)[0] for sc in set_cookies if "=" in sc.split(";", 1)[0])
    check("login issued a session cookie", "session=" in stolen, stolen[:40])
    check("login issued a remember_token cookie", "remember_token=" in stolen, stolen[:60])

    # Sanity: the stolen cookies ARE a valid bearer token *before* logout.
    thief_before = app.test_client()
    check("stolen cookie works BEFORE logout (200)",
          thief_before.get("/", headers={"Cookie": stolen}).status_code == 200)

    # Log the victim out, then replay the pre-logout cookies from a fresh client.
    victim.post("/logout")
    thief_after = app.test_client()
    reused = thief_after.get("/", headers={"Cookie": stolen})
    check("REUSE BLOCKED: stolen cookie rejected AFTER logout (not 200)",
          reused.status_code != 200, "got %d — cookie still valid!" % reused.status_code)
    # And the remember_token alone (the long-lived one) must also be dead.
    remember_only = "; ".join(p for p in stolen.split("; ") if p.startswith("remember_token="))
    reused_rt = app.test_client().get("/", headers={"Cookie": remember_only})
    check("REUSE BLOCKED: stolen remember_token rejected after logout (not 200)",
          reused_rt.status_code != 200, "got %d" % reused_rt.status_code)

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
