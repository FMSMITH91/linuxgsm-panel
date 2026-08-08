"""Automated RBAC enforcement test — proves permissions are enforced server-side and
cannot be bypassed by calling endpoints directly.

Run it against a configured install (from anywhere):

    ./venv/bin/python tests/rbac_test.py      # exits 0 if all checks pass

It creates a throwaway limited group + user (view-only, access to ONE host),
exercises the real HTTP endpoints via Flask's test client, and deletes the fixtures
again. Privileged actions are asserted to be BLOCKED *before* they execute, so it has
no side effects on your game servers. Use it as a regression guard after auth changes.

IMPORTANT: HTTP requests run WITHOUT an outer app_context. flask-login caches the
loaded user on the app-context global `g`; a single shared app_context would leak the
first authenticated user's identity into every later test client. Each test_client
request pushes its own context, so we keep DB work in short, separate app_context
blocks and never hold one open across HTTP calls.
"""
import glob
import os
import secrets
import sys

# Allow running as `python tests/rbac_test.py` from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from app import create_app
from models import db, User, Group, RemoteServer, GameServer, SetupState
import auth

# Snapshot the data files BEFORE create_app() opens/creates them — so if we seed a fresh (empty) DB
# we can delete exactly what we created and leave a dev's real data/ untouched.
_DATA = os.path.join(_ROOT, "data")


def _managed_files():
    fs = set(glob.glob(os.path.join(_DATA, "panel.db*")))
    for _n in ("config.json", "secret_key", "cred_key"):
        _p = os.path.join(_DATA, _n)
        if os.path.exists(_p):
            fs.add(_p)
    return fs


_files_before = _managed_files()

app = create_app()
app.config["WTF_CSRF_ENABLED"] = False   # test client posts without a browser-issued token
app.config["SESSION_PROTECTION"] = None  # tests inject the session directly (no IP/UA fingerprint)
app.config["SESSION_COOKIE_SECURE"] = False  # test client talks http://; Secure cookies wouldn't round-trip
results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


# Rows we seed on an empty DB (so this runs standalone in CI); cleaned up at the end. Empty against a
# live install → we seed nothing and delete nothing but our own throwaway users/groups.
seeded = {"users": [], "remotes": [], "servers": [], "setup": []}

# ── Phase 1: gather ids + create throwaway fixtures (own context) ──
with app.app_context():
    from collections import defaultdict

    # Self-seed a minimal fixture set when the database is empty (e.g. a fresh CI checkout), so the
    # test can run in CI as well as against a configured install. Only touches a DB with no servers
    # or no superadmin — a real install already has both, so nothing is seeded there.
    if GameServer.query.first() is None or User.query.filter_by(is_superadmin=True).first() is None:
        if SetupState.query.first() is None:
            _st = SetupState(step="complete", complete=True)
            db.session.add(_st); db.session.flush(); seeded["setup"].append(_st.id)
        if User.query.filter_by(is_superadmin=True).first() is None:
            _sa = User(username="rbac_seed_admin", display_name="RBAC seed admin",
                       password_hash=auth.hash_password(secrets.token_hex(16)),
                       is_superadmin=True, is_active=True)
            db.session.add(_sa); db.session.flush(); seeded["users"].append(_sa.id)
        for _i, (_n, _p) in enumerate((("rbac-seed-h1", 27015), ("rbac-seed-h2", 27016))):
            _r = RemoteServer(name=_n, host="127.0.0.1", port=22, username="root",
                              auth_method="key", auth_credential="")
            db.session.add(_r); db.session.flush(); seeded["remotes"].append(_r.id)
            _g = GameServer(remote_id=_r.id, name="%s-s" % _n, short_name="rbacseed%d" % _i,
                            game_type="gmod", port=_p, installed=True, status="offline")
            db.session.add(_g); db.session.flush(); seeded["servers"].append(_g.id)
        db.session.commit()
        # is_setup_complete() = SetupState(complete) AND cfg["setup_complete"]; set the config flag too
        # (like smoke_test does) or every request 302s to /setup.
        from config import load_config, save_config
        _cfg = load_config()
        _cfg["setup_complete"] = True
        save_config(_cfg)

    by_remote = defaultdict(list)
    for s in GameServer.query.all():
        by_remote[s.remote_id].append(s)
    rids = [rid for rid, l in by_remote.items() if l]
    if not rids:
        print("No game servers to test against — aborting.")
        sys.exit(2)
    granted_remote = rids[0]
    other_remote = next((r for r in rids if r != granted_remote), None)
    accessible_id = by_remote[granted_remote][0].id
    other_id = by_remote[other_remote][0].id if other_remote else None
    admin_id = User.query.filter_by(is_superadmin=True).first().id

    tag = "rbactest_" + secrets.token_hex(3)
    grp = Group(name=tag, description="RBAC test (auto)", is_default=False)
    grp.set_permissions([auth.VIEW_SERVERS, auth.VIEW_CONSOLE])   # NO action/manage perms
    grp.servers.append(RemoteServer.query.get(granted_remote))    # access to ONE remote only
    db.session.add(grp)
    db.session.flush()
    u = User(username=tag, password_hash=auth.hash_password(secrets.token_hex(16)),
             display_name=tag, is_superadmin=False, is_active=True)
    u.groups.append(grp)
    db.session.add(u)
    db.session.commit()
    uid = u.id

    # Second fixture: HAS MANAGE_REMOTES but access to ONE remote only — proves that
    # remote management is scoped per host, not granted globally by the permission.
    tag2 = tag + "_mr"
    grp2 = Group(name=tag2, description="RBAC test MR (auto)", is_default=False)
    grp2.set_permissions([auth.MANAGE_REMOTES])
    grp2.servers.append(RemoteServer.query.get(granted_remote))
    db.session.add(grp2)
    db.session.flush()
    u2 = User(username=tag2, password_hash=auth.hash_password(secrets.token_hex(16)),
              display_name=tag2, is_superadmin=False, is_active=True)
    u2.groups.append(grp2)
    db.session.add(u2)
    db.session.commit()
    uid2 = u2.id

    # Third fixture: a group whose stored permissions still contain the legacy "super_admin"
    # string, as an install from before it stopped being grantable would have. It must confer
    # NOTHING — that grant used to pass @permission_required(SUPER_ADMIN) on ~61 routes while every
    # flag-based gate and the whole nav refused the same account.
    tag3 = tag + "_legacy_sa"
    grp3 = Group(name=tag3, description="RBAC test legacy SA (auto)", is_default=False)
    grp3.set_permissions([auth.VIEW_SERVERS, "super_admin"])
    db.session.add(grp3)
    db.session.flush()
    u3 = User(username=tag3, password_hash=auth.hash_password(secrets.token_hex(16)),
              display_name=tag3, is_superadmin=False, is_active=True)
    u3.groups.append(grp3)
    db.session.add(u3)
    db.session.commit()
    uid3 = u3.id

    # Fourth fixture: a DELEGATED group admin — MANAGE_GROUPS and nothing else. They can edit a
    # group they belong to, so _grantable_perms is the only thing between them and self-promotion.
    tag4 = tag + "_grpadm"
    grp4 = Group(name=tag4, description="RBAC test group-admin (auto)", is_default=False)
    grp4.set_permissions([auth.VIEW_SERVERS, auth.MANAGE_GROUPS])
    grp4.servers.append(RemoteServer.query.get(granted_remote))
    db.session.add(grp4)
    db.session.flush()
    u4 = User(username=tag4, password_hash=auth.hash_password(secrets.token_hex(16)),
              display_name=tag4, is_superadmin=False, is_active=True)
    u4.groups.append(grp4)
    db.session.add(u4)
    db.session.commit()
    uid4 = u4.id

    # A group that already holds a permission the delegated admin CANNOT grant, to prove an edit
    # by them preserves it instead of silently stripping it.
    tag5 = tag + "_holds_mu"
    grp5 = Group(name=tag5, description="RBAC test preserve (auto)", is_default=False)
    grp5.set_permissions([auth.MANAGE_USERS])
    db.session.add(grp5)
    db.session.commit()
    gid5 = grp5.id

print("Fixtures: limited user id=%d, group grants remote %d only." % (uid, granted_remote))
print("Accessible server id=%d (remote %d); non-granted server id=%s (remote %s)\n"
      % (accessible_id, granted_remote, other_id, other_remote))

def client_as(user_id=None):
    c = app.test_client()
    if user_id is not None:
        with c.session_transaction() as s:
            s["_user_id"] = str(user_id)
            s["_fresh"] = True
    return c


try:
    # ── Limited user (VIEW_SERVERS + VIEW_CONSOLE, access to ONE remote) ──
    c = client_as(uid)
    for p in ["/users", "/groups", "/logs", "/remotes", "/server-management",
              "/tailscale", "/api/tailscale", "/settings", "/notifications",
              "/api/remote/%d/specs" % granted_remote, "/api/panel/update-status"]:
        code = c.get(p).status_code
        check("limited user DENIED %s" % p, code != 200, "got %d" % code)

    if other_id:
        check("IDOR: console of non-granted server BLOCKED",
              c.get("/api/console/%d" % other_id).status_code != 200)
        check("IDOR: stats of non-granted server BLOCKED",
              c.get("/api/server/%d/stats" % other_id).status_code != 200)
        check("IDOR: action on non-granted server BLOCKED",
              c.post("/api/server/%d/action" % other_id, json={"action": "start"}).status_code != 200)

    check("action 'start' without START_SERVER -> 403",
          c.post("/api/server/%d/action" % accessible_id, json={"action": "start"}).status_code == 403)
    check("send command without SEND_COMMAND -> 403",
          c.post("/api/command/%d" % accessible_id, json={"command": "status"}).status_code == 403)
    check("read file without MANAGE_SERVERS -> 403",
          c.get("/api/server/%d/file?path=.bashrc" % accessible_id).status_code == 403)
    check("list cron without MANAGE_SERVERS -> 403",
          c.get("/api/server/%d/cron" % accessible_id).status_code == 403)
    check("add cron without MANAGE_SERVERS -> 403",
          c.post("/api/server/%d/cron" % accessible_id,
                 json={"schedule": "@daily", "command": "/bin/true"}).status_code == 403)
    check("update cron without MANAGE_SERVERS -> 403",
          c.post("/api/server/%d/cron/update" % accessible_id,
                 json={"raw": "x", "schedule": "@daily", "command": "/bin/true"}).status_code == 403)
    check("delete cron without MANAGE_SERVERS -> 403",
          c.post("/api/server/%d/cron/delete" % accessible_id, json={"raw": "x"}).status_code == 403)
    check("autostart toggle without RESTART_SERVER -> 403",
          c.post("/api/server/%d/autostart" % accessible_id, json={"enabled": False}).status_code == 403)
    # Tags are install-wide, so WRITING one needs MANAGE_SERVERS even on a server you can see.
    check("create tag without MANAGE_SERVERS -> 403",
          c.post("/api/tags", json={"name": "sneaky"}).status_code == 403)
    check("delete tag without MANAGE_SERVERS -> 403",
          c.post("/api/tags/1/delete").status_code == 403)
    check("assign tags without MANAGE_SERVERS -> 403",
          c.post("/api/server/%d/tags" % accessible_id, json={"tag_ids": [1]}).status_code == 403)
    if other_id:
        check("IDOR: assigning tags on a non-granted server BLOCKED",
              c.post("/api/server/%d/tags" % other_id, json={"tag_ids": []}).status_code != 200)
    # Reading the tag list is deliberately open to any signed-in user: it is what decorates and
    # filters rows they can already see.
    check("tag list is readable without MANAGE_SERVERS -> 200",
          c.get("/api/tags").status_code == 200)

    # ── A legacy "super_admin" group grant confers nothing ────────────────────────────────────
    c3 = client_as(uid3)
    for p3 in ["/settings", "/notifications", "/server-management", "/users"]:
        _code = c3.get(p3).status_code
        check("legacy super_admin grant DENIED %s" % p3, _code != 200, "got %d" % _code)
    check("legacy super_admin grant cannot reboot the panel host",
          c3.post("/api/server-management/reboot").status_code != 200)
    check("legacy super_admin grant cannot publish an install-wide layout",
          c3.post("/api/settings/ui-default").status_code == 403)
    # ...and it is no longer offered in the Groups UI at all.
    check("super_admin is not a grantable permission any more",
          "super_admin" not in auth.ALL_PERMISSIONS)

    # ── A denial must be readable by whoever asked ────────────────────────────────────────────
    # The decorators used to flash + 302 unconditionally. An in-page fetch follows that redirect,
    # gets HTML, fails to parse it, and base.html's fallback turned the refusal into a SUCCESS
    # toast. So: JSON callers get JSON, browser navigations still get the redirect.
    # A DECORATOR-gated /api/ route (this one is @permission_required(MANAGE_REMOTES)) — the routes
    # that already answered with an inline jsonify 403 would pass either way, so they prove nothing
    # about the decorator.
    _api_denied = c.get("/api/remote/%d/specs" % granted_remote)
    check("denial (API, decorator-gated): status is 403, not a redirect",
          _api_denied.status_code == 403, "got %d" % _api_denied.status_code)
    check("denial (API, decorator-gated): body is JSON with success=false",
          (_api_denied.get_json() or {}).get("success") is False,
          _api_denied.get_data(as_text=True)[:100])
    _fetch_denied = c.post("/servers/%d/delete" % accessible_id,
                           headers={"X-Requested-With": "XMLHttpRequest"})
    check("denial (in-page fetch): JSON, so it cannot be mistaken for success",
          _fetch_denied.status_code == 403
          and (_fetch_denied.get_json() or {}).get("success") is False,
          "status=%d" % _fetch_denied.status_code)
    _browser_denied = c.post("/servers/%d/delete" % accessible_id,
                             headers={"Accept": "text/html"})
    check("denial (browser form): still a redirect, not JSON",
          _browser_denied.status_code in (301, 302, 303),
          "got %d" % _browser_denied.status_code)


    check("view console WITH VIEW_CONSOLE + access -> 200",
          c.get("/api/console/%d" % accessible_id).status_code == 200)

    # Pages must actually RENDER for a non-superadmin (regression: a template calling a
    # context-processor helper with the wrong arity 500'd only for limited users).
    check("dashboard (/) renders for limited user -> 200", c.get("/").status_code == 200)

    # Remote management is scoped PER HOST: MANAGE_REMOTES lets you manage remotes,
    # but only the ones your groups grant — not any remote by id (remote-level IDOR).
    cmr = client_as(uid2)
    check("MANAGE_REMOTES user can open /remotes -> 200", cmr.get("/remotes").status_code == 200)
    if other_remote:
        check("IDOR: managing a NON-granted remote is blocked (403)",
              cmr.get("/api/remote/%d/firewall" % other_remote).status_code == 403)
        check("IDOR: rebooting a non-granted remote is blocked (403)",
              cmr.post("/api/remote/%d/reboot" % other_remote).status_code == 403)

    r = c.get("/api/servers")
    ids = [x.get("id") for x in (r.get_json() or [])] if r.status_code == 200 else []
    check("/api/servers -> 200", r.status_code == 200, "got %d" % r.status_code)
    check("/api/servers INCLUDES granted server", accessible_id in ids, str(ids))
    if other_id:
        check("/api/servers HIDES non-granted server", other_id not in ids, str(ids))

    # ── Unauthenticated ──
    cu = client_as(None)
    check("unauth GET / -> redirect to login", cu.get("/").status_code == 302)
    check("unauth GET /users -> redirect", cu.get("/users").status_code == 302)
    check("unauth GET /api/servers -> not 200", cu.get("/api/servers").status_code != 200)

    # CRITICAL: /setup POST must NOT create a superadmin once setup is complete.
    pwn = "pwned_" + tag
    r = cu.post("/setup", data={"step": "admin_user", "username": pwn,
                                "password": "hackme123", "confirm_password": "hackme123"})
    with app.app_context():
        created = User.query.filter_by(username=pwn).first()
        was_created = created is not None
        if created:
            db.session.delete(created)
            db.session.commit()
    check("/setup POST CANNOT create a superadmin (unauth)", not was_created,
          "ACCOUNT WAS CREATED (status %d)" % r.status_code if was_created else "blocked")
    check("unauth GET /setup -> redirect", cu.get("/setup").status_code == 302)

    # ── Privilege escalation: a delegated group admin cannot grant what they don't hold ──────────
    # They have MANAGE_GROUPS, so they may create and edit groups — including groups they are in.
    # _grantable_perms is the whole defence, and nothing exercised it for a non-superadmin
    # permission. The existing "can't grant super_admin" check passes even with the guard removed,
    # because super_admin was dropped from ALL_PERMISSIONS and is filtered separately.
    c4 = client_as(uid4)
    esc_name = tag + "_escalation"
    c4.post("/groups/add", data={"name": esc_name, "description": "",
                                 "permissions": [auth.MANAGE_USERS, auth.UNINSTALL_SERVER,
                                                 auth.VIEW_SERVERS]})
    with app.app_context():
        made = Group.query.filter_by(name=esc_name).first()
        got = set(made.get_permissions()) if made else None
    check("escalation: a MANAGE_GROUPS admin cannot grant permissions they lack",
          made is not None and auth.MANAGE_USERS not in got and auth.UNINSTALL_SERVER not in got,
          "granted: %s" % sorted(got or []))
    check("escalation: they CAN grant a permission they do hold",
          made is not None and auth.VIEW_SERVERS in (got or set()), "granted: %s" % sorted(got or []))

    # ...and editing a group must not silently strip a permission they cannot grant.
    c4.post("/groups/%d/edit" % gid5, data={"name": tag5, "description": "",
                                            "permissions": [auth.VIEW_SERVERS]})
    with app.app_context():
        kept = set(Group.query.get(gid5).get_permissions())
    check("escalation: an edit PRESERVES a permission the editor cannot grant",
          auth.MANAGE_USERS in kept, "after edit: %s" % sorted(kept))

    # ── Bulk actions are access-checked per id ────────────────────────────────────────────────────
    # /api/servers/bulk-action is not an /<int:server_id> route, so the structural sweep below
    # never sees it, and it carries no @server_access_required — the check is hand-written in the
    # loop. A break here fans a power action out over SSH to every server in the install.
    if other_id:
        import app as _appmod
        _ran = []
        _sv_rag = _appmod.run_as_game_user
        try:
            _appmod.run_as_game_user = lambda *a, **k: (_ran.append(a), ("", "", 0))[1]
            grpb = None
            with app.app_context():
                grpb = Group(name=tag + "_bulk", description="RBAC bulk (auto)", is_default=False)
                grpb.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER])
                grpb.servers.append(RemoteServer.query.get(granted_remote))
                db.session.add(grpb)
                db.session.flush()
                ub = User(username=tag + "_bulk", password_hash=auth.hash_password(secrets.token_hex(16)),
                          display_name=tag + "_bulk", is_superadmin=False, is_active=True)
                ub.groups.append(grpb)
                db.session.add(ub)
                db.session.commit()
                uidb, gidb = ub.id, grpb.id
            rb = client_as(uidb).post("/api/servers/bulk-action",
                                      json={"action": "start", "server_ids": [other_id]})
            jb = rb.get_json() or {}
            check("bulk-action: a server on a non-granted host is refused, not queued",
                  not jb.get("queued")
                  and any(sk.get("reason") == "no access" for sk in jb.get("skipped") or []),
                  "queued=%s skipped=%s" % (jb.get("queued"), jb.get("skipped")))
            import time as _t
            _t.sleep(0.3)   # the action runs in a background thread; give it time to have fired
            check("bulk-action: and nothing was actually run on it", not _ran, "ran: %s" % _ran[:1])
            with app.app_context():
                db.session.delete(User.query.get(uidb))
                db.session.delete(Group.query.get(gidb))
                db.session.commit()
        finally:
            _appmod.run_as_game_user = _sv_rag

    # ── Superadmin sanity: still full access ──
    ca = client_as(admin_id)
    for p in ["/users", "/groups", "/logs", "/remotes", "/server-management", "/tailscale",
              "/settings", "/notifications"]:
        code = ca.get(p).status_code
        check("superadmin CAN access %s" % p, code == 200, "got %d" % code)
finally:
    if any(seeded.values()):
        # The whole DB was seeded by us (it started empty) — drop the throwaway DB file(s) entirely,
        # so nothing is left behind (a leftover empty panel.db would make smoke_test skip next run).
        try:
            with app.app_context():
                db.session.remove()
                db.engine.dispose()
        except Exception:
            pass   # best-effort teardown of a throwaway DB — nothing to recover if it fails
        for _f in _managed_files() - _files_before:
            try:
                os.remove(_f)
            except OSError:
                pass
    else:
        # Live/configured install: remove ONLY our throwaway users/groups, never real data.
        with app.app_context():
            for _uid in (uid, locals().get("uid2"), locals().get("uid3")):
                if _uid:
                    _u = User.query.get(_uid)
                    if _u:
                        db.session.delete(_u)
            for _tag in (tag, tag + "_mr", tag + "_legacy_sa"):
                _g = Group.query.filter_by(name=_tag).first()
                if _g:
                    db.session.delete(_g)
            db.session.commit()
    print("Fixtures cleaned up.\n")

# ── Structural: EVERY <int:server_id> route must check server access ───────────────────────────
# A permission decorator is not enough — get_game() is a bare get_or_404, so a user holding e.g.
# UNINSTALL_SERVER for their own server could otherwise act on someone else's. Checked structurally
# rather than by probing each route: firing /servers/<id>/delete to prove a guard exists would
# UNINSTALL A REAL SERVER on a configured install if the guard were ever missing.
with app.app_context():
    _unguarded = []
    for _rule in app.url_map.iter_rules():
        if "<int:server_id>" not in str(_rule):
            continue
        _fn = app.view_functions.get(_rule.endpoint)
        _seen, _superadmin_only = False, False
        while _fn is not None:                                # walk the stacked decorators
            _seen = _seen or getattr(_fn, "_checks_server_access", False)
            _perms = getattr(_fn, "_required_perms", ())
            # SUPER_ADMIN-only routes are exempt: a superadmin reaches every server by definition.
            _superadmin_only = _superadmin_only or (_perms == (auth.SUPER_ADMIN,))
            _fn = getattr(_fn, "__wrapped__", None)
        if not (_seen or _superadmin_only):
            _unguarded.append("%s %s" % (sorted(_rule.methods & {"GET", "POST", "PUT", "DELETE"}), _rule))
    check("every <server_id> route enforces server access (not just a permission)",
          not _unguarded, "; ".join(sorted(_unguarded)[:6]))

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)
