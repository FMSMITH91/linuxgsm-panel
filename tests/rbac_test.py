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
import ast
import glob
import inspect
import os
import pathlib
import secrets
import sys
import textwrap

# Allow running as `python tests/rbac_test.py` from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from panel.ops.ssh_manager import _core as _sm_core   # the stub seam: stubbed by MODULE,
# because every caller now reaches these through the module rather than binding them.

from app import create_app
from panel.db.models import db, User, Group, RemoteServer, GameServer, SetupState
from panel.security import auth

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
        from panel.core.config import load_config, save_config
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
    # An ACTIVE one, lowest id first. The invite block below plants a deactivated superadmin that
    # sorts first, and a configured install can hold one of its own (a retired setup-time admin):
    # acting as that account, every "superadmin CAN" check below fails for the wrong reason.
    admin_id = (User.query.filter_by(is_superadmin=True, is_active=True)
                .order_by(User.id).first().id)

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
    gid4_for_scope = grp4.id

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

def _run_fixture_rows():
    """Every row this run leaves on a configured install, found by name — what the final cleanup
    deletes. A fixture named from `tag` is in here BY CONSTRUCTION, so a block that raises halfway
    through still leaves nothing in the operator's panel. One named any other way is not: the
    invite block's deactivated SUPERADMIN and its "pre-existing" invite were named "inv_<hex>",
    deleted only on the success path, and left behind by any exception. Needs an app context."""
    from panel.db.models import CustomCommand, Invite
    _like = tag + "%"
    return (Invite.query.filter(Invite.note.like(_like)).all()
            + User.query.filter(User.username.like(_like)).all()
            + Group.query.filter(Group.name.like(_like)).all()
            + CustomCommand.query.filter(CustomCommand.name.like(_like)).all())


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

    # ── Two guards that each redirect to the other are an infinite loop ────────────────────────
    # A failed install sends the console to Files & Config, because that is where the LinuxGSM
    # config the failure talks about lives. Files & Config sends a user without MANAGE_SERVERS to
    # the console. For a user who is BOTH — can see the server, cannot manage files, and the
    # install failed — the two bounce off each other until the browser gives up with
    # ERR_TOO_MANY_REDIRECTS. Reproduced before this was written: twelve hops and still going.
    #
    # So the check is not "does it redirect somewhere sensible" but "does the chain END".
    with app.app_context():
        _loopfail = GameServer(remote_id=granted_remote, name="rbac-failed-install",
                               short_name="bsserver", game_type="bs", port=27145,
                               installed=False, status="failed")
        db.session.add(_loopfail)
        db.session.commit()
        _loopfail_id = _loopfail.id
    try:
        _path, _chain = "/server/%d" % _loopfail_id, []
        for _ in range(12):
            _r = c.get(_path)
            _chain.append("%s -> %s" % (_path, _r.status_code))
            if _r.status_code not in (301, 302, 303, 307, 308):
                break
            _loc = _r.headers.get("Location") or ""
            _path = _loc.split("localhost", 1)[-1] if _loc.startswith("http") else _loc
        check("failed install + no MANAGE_SERVERS: the redirect chain terminates",
              len(_chain) < 12, " | ".join(_chain[:6]))
        check("failed install + no MANAGE_SERVERS: ...on a page that actually renders",
              _chain and _chain[-1].endswith("200"), _chain[-1] if _chain else "no response")
        # And the same from the other end, for someone who followed a Files & Config link.
        _path, _chain2 = "/server/%d/files" % _loopfail_id, []
        for _ in range(12):
            _r = c.get(_path)
            _chain2.append("%s -> %s" % (_path, _r.status_code))
            if _r.status_code not in (301, 302, 303, 307, 308):
                break
            _loc = _r.headers.get("Location") or ""
            _path = _loc.split("localhost", 1)[-1] if _loc.startswith("http") else _loc
        check("failed install + no MANAGE_SERVERS: ...and from the Files & Config side too",
              len(_chain2) < 12 and _chain2[-1].endswith("200"), " | ".join(_chain2[:6]))
    finally:
        with app.app_context():
            _row = db.session.get(GameServer, _loopfail_id)
            if _row is not None:
                db.session.delete(_row)
                db.session.commit()

    # ── a successful uninstall must not land on a page the uninstaller cannot open ─────────────
    # Every exit of uninstall_server redirected to /servers/manage, which needs MANAGE_SERVERS or
    # INSTALL_SERVER — neither of which an UNINSTALL_SERVER-only operator has. The dashboard's
    # Uninstall form is a native POST, so the browser follows the redirect: the uninstall worked
    # and the page they landed on said "You do not have permission to do that."
    with app.app_context():
        _ug = Group(name=tag + "_un", description="RBAC test UNINSTALL only (auto)",
                    is_default=False)
        _ug.set_permissions([auth.VIEW_SERVERS, auth.UNINSTALL_SERVER])
        _ug.servers.append(RemoteServer.query.get(granted_remote))
        db.session.add(_ug); db.session.flush()
        _uu = User(username=tag + "_un", password_hash=auth.hash_password(secrets.token_hex(16)),
                   display_name=tag + "_un", is_superadmin=False, is_active=True)
        _uu.groups.append(_ug)
        db.session.add(_uu)
        _ugs = GameServer(remote_id=granted_remote, name="rbac-uninstall", short_name="rbacuninst",
                          game_type="gmod", port=28970, installed=False, status="installing")
        db.session.add(_ugs)
        db.session.commit()
        _uu_id, _ugs_id = _uu.id, _ugs.id
    try:
        _uc = client_as(_uu_id)
        # The 409 "still installing" exit is the one an uninstall-only user can reach without any
        # SSH at all, and it takes the same redirect as the success path.
        _ur = _uc.post("/servers/%d/delete" % _ugs_id, follow_redirects=True)
        _utext = _ur.get_data(as_text=True)
        check("uninstall-only user: the page they land on is one they may open",
              "do not have permission" not in _utext.lower(), "landed on a refusal")
        check("uninstall-only user: ...and it actually rendered", _ur.status_code == 200,
              "got %d" % _ur.status_code)
    finally:
        with app.app_context():
            for _obj in (db.session.get(GameServer, _ugs_id), db.session.get(User, _uu_id)):
                if _obj is not None:
                    db.session.delete(_obj)
            db.session.commit()

    # ── the Retry button and the route it posts to must agree about who may press it ───────────
    # The dashboard renders "Retry install" on the can_install flag, which is
    # INSTALL_SERVER *or* MANAGE_SERVERS — the same pair /servers/install and /servers/add accept.
    # retry-install was added requiring INSTALL_SERVER alone, so a MANAGE_SERVERS holder was shown
    # a button that answered "You do not have permission to do that." It runs the very same
    # install job, so the narrower guard was the outlier, not the flag.
    with app.app_context():
        _msg = Group(name=tag + "_ms", description="RBAC test MANAGE_SERVERS (auto)",
                     is_default=False)
        _msg.set_permissions([auth.VIEW_SERVERS, auth.MANAGE_SERVERS])   # NOT install_server
        _msg.servers.append(RemoteServer.query.get(granted_remote))
        db.session.add(_msg); db.session.flush()
        _msu = User(username=tag + "_ms", password_hash=auth.hash_password(secrets.token_hex(16)),
                    display_name=tag + "_ms", is_superadmin=False, is_active=True)
        _msu.groups.append(_msg)
        db.session.add(_msu)
        _rt = GameServer(remote_id=granted_remote, name="rbac-retry", short_name="bsserver",
                         game_type="bs", port=27146, installed=False, status="failed")
        _rt.install_error = "Downloading game server files: the mirror was unreachable."
        _rt.install_retryable = True
        db.session.add(_rt)
        db.session.commit()
        _msu_id, _rt_id = _msu.id, _rt.id
    try:
        _msc = client_as(_msu_id)
        _dash_ms = _msc.get("/")
        _shown = ("/servers/%d/retry-install" % _rt_id) in _dash_ms.get_data(as_text=True)
        _posted = _msc.post("/servers/%d/retry-install" % _rt_id,
                            headers={"X-Requested-With": "XMLHttpRequest"})
        check("MANAGE_SERVERS: the dashboard offers Retry install on a failed row", _shown,
              "the button was not rendered, so this proves nothing about the route")
        check("MANAGE_SERVERS: ...and the route it posts to accepts them",
              _posted.status_code != 403, "got %d" % _posted.status_code)
    finally:
        with app.app_context():
            _r = db.session.get(GameServer, _rt_id)
            if _r is not None:
                db.session.delete(_r)
            _u2 = db.session.get(User, _msu_id)
            if _u2 is not None:
                db.session.delete(_u2)
            db.session.commit()

    # ── VPS-preparation routes must refuse the panel's OWN host ────────────────────────────────
    # manage_remotes.html hides Prepare / Tailscale for the local host, but the ROUTES accepted a
    # POST carrying its id. Those actions apt full-upgrade the machine, rewrite its sshd config,
    # pipe an installer into a root shell and reboot it — aimed at the panel's own host, that
    # reboots the panel out from under the request. A UI-only restriction on a destructive
    # privileged action is not a restriction, so this drives the real routes as a superadmin.
    with app.app_context():
        _local = RemoteServer.query.filter_by(auth_method="local").first()
        _local_made = _local is None
        if _local_made:
            _local = RemoteServer(name="rbac-local-probe", host="127.0.0.1", port=22,
                                  username="root", auth_method="local", auth_credential="")
            db.session.add(_local)
            db.session.commit()
        _local_id = _local.id
        _rem = RemoteServer.query.filter(RemoteServer.auth_method != "local").first()
        _rem_id = _rem.id if _rem else None
    _ac = client_as(admin_id)
    for _path, _label in (("/api/remote/%d/bootstrap" % _local_id, "VPS bootstrap"),
                          ("/api/remote/%d/tailscale-install" % _local_id, "Tailscale install"),
                          ("/api/remote/%d/tailscale-bootstrap" % _local_id, "Tailscale join"),
                          # tailscale-up is the OTHER half of the join — the UI offers the two as
                          # "Get login link" and "Connect with key" in one dialog — and it was the
                          # one that never got the server-side guard. Aimed at the panel's own host
                          # it ran `tailscale up --ssh` there and returned the login URL, so the
                          # caller chose which tailnet the panel host joined.
                          ("/api/remote/%d/tailscale-up" % _local_id, "Tailscale join (login link)")):
        _r = _ac.post(_path, json={"auth_key": "tskey-auth-abcdefghij"})
        check("%s is REFUSED on the panel's own host" % _label,
              _r.status_code == 400, "%s -> %d" % (_path, _r.status_code))
        check("%s refusal says why, in JSON" % _label,
              b"panel's own host" in _r.data, _r.data[:120])
    # A remote host must NOT be refused by that guard — refusing everything is the easy way to make
    # the assertions above pass for the wrong reason.
    if _rem_id is not None:
        _r2 = _ac.post("/api/remote/%d/tailscale-install" % _rem_id)
        check("a REMOTE host is not refused by that guard",
              b"panel's own host" not in _r2.data, "%d %s" % (_r2.status_code, _r2.data[:80]))
    if _local_made:
        with app.app_context():
            _l = db.session.get(RemoteServer, _local_id)
            if _l is not None:
                db.session.delete(_l)
                db.session.commit()

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
    # The download is the one file-browser route that hands bytes OUT, and it is a plain link
    # rather than an /api/ route — so its refusal is a redirect, not a 403 body.
    #
    # "is a redirect" alone is NOT enough to prove the guard is there. Every other failure in that
    # route also redirects, so deleting the permission check entirely still produced a 302 — the
    # host is unreachable from a test run — and the check passed anyway. Reading the flash does not
    # separate them either: the /files page it redirects to refuses with the SAME message.
    #
    # WHERE it sends you does separate them. A permission refusal goes back to the server page,
    # exactly as /server/<id>/files itself does; every in-route failure goes back to /files.
    _dl = c.get("/server/%d/download?path=.bashrc" % accessible_id)
    check("download file without MANAGE_SERVERS -> refused, and no file is sent",
          _dl.status_code in (301, 302, 303) and "Content-Disposition" not in _dl.headers,
          "got %d %s" % (_dl.status_code, dict(_dl.headers)))
    check("download denial is the PERMISSION refusal, not an incidental failure",
          _dl.headers.get("Location", "").rstrip("/").endswith("/server/%d" % accessible_id),
          _dl.headers.get("Location", ""))
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
    # ...but it names only the servers the caller can access. It listed every server's id under
    # every tag: an inventory of what they cannot open, and what it is tagged with.
    if other_id:
        from panel.db.models import ServerTag as _TagR
        with app.app_context():
            _tr = _TagR(name=tag + "tagleak")
            _tr.servers.extend([db.session.get(GameServer, accessible_id),
                                db.session.get(GameServer, other_id)])
            db.session.add(_tr)
            db.session.commit()
            _tr_id = _tr.id
        try:
            _tr_ids = next((t["server_ids"] for t in (c.get("/api/tags").get_json() or {})["tags"]
                            if t["id"] == _tr_id), None)
            check("tag list: (control) a tag on a server the caller CAN access lists that server",
                  _tr_ids is not None and accessible_id in _tr_ids, "got %r" % (_tr_ids,))
            check("IDOR: the tag list does not name a server the caller cannot access",
                  _tr_ids is not None and other_id not in _tr_ids, "got %r" % (_tr_ids,))
            _tr_admin = next((t["server_ids"] for t in
                              (client_as(admin_id).get("/api/tags").get_json() or {})["tags"]
                              if t["id"] == _tr_id), None)
            check("tag list: ...while a superadmin still sees every server on it",
                  _tr_admin is not None and other_id in _tr_admin, "got %r" % (_tr_admin,))
        finally:
            with app.app_context():
                db.session.delete(db.session.get(_TagR, _tr_id))
                db.session.commit()

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

    # ── …and the same escalation from the MEMBERSHIP side ────────────────────────────────────────
    # _grantable_perms stops a delegated admin giving a GROUP a permission they lack. It said
    # nothing about which groups a user may JOIN, and /users/<id>/edit set user.groups straight
    # from the form — so a MANAGE_USERS holder edited their own account, ticked a privileged group,
    # and held its permissions on the next request. is_superadmin was guarded; membership was not.
    with app.app_context():
        _mu_grp = Group(name=tag + "_mu_admin", description="RBAC test MU admin (auto)",
                        is_default=False)
        _mu_grp.set_permissions([auth.MANAGE_USERS])
        db.session.add(_mu_grp)
        db.session.flush()
        _mu_user = User(username=tag + "_mu_admin",
                        password_hash=auth.hash_password(secrets.token_hex(16)),
                        display_name="MU admin", is_superadmin=False, is_active=True)
        _mu_user.groups.append(_mu_grp)
        db.session.add(_mu_user)
        db.session.commit()
        _mu_uid, _mu_gid = _mu_user.id, _mu_grp.id
        # A group holding something they do NOT have — the prize.
        _prize = Group(name=tag + "_prize", description="RBAC test prize (auto)", is_default=False)
        _prize.set_permissions([auth.UNINSTALL_SERVER, auth.MANAGE_REMOTES])
        db.session.add(_prize)
        db.session.commit()
        _prize_gid = _prize.id

    cmu = client_as(_mu_uid)
    cmu.post("/users/%d/edit" % _mu_uid,
             data={"display_name": "MU admin", "is_active": "on",
                   "groups": [str(_mu_gid), str(_prize_gid)]})
    with app.app_context():
        _now = auth.get_user_permissions(db.session.get(User, _mu_uid))
    check("escalation: MANAGE_USERS cannot join a group holding permissions they lack",
          auth.UNINSTALL_SERVER not in _now and auth.MANAGE_REMOTES not in _now,
          "ended up with: %s" % sorted(_now))
    check("escalation: ...and keeps the group they legitimately had",
          auth.MANAGE_USERS in _now, "ended up with: %s" % sorted(_now))

    # ── ...and cannot join a group whose PERMISSIONS they hold but whose HOSTS they do not ──────
    # grantable_groups tested `set(g.get_permissions()) <= mine` and nothing else, while
    # can_access_server unions Group.servers (whole-host grants) and Group.game_servers. So a
    # group carrying a host you were never granted passed the check, and you held that host on the
    # next request — with your permission set unchanged, which is why the test above stayed green.
    with app.app_context():
        _reach = Group(name=tag + "_reach", description="RBAC test reach (auto)", is_default=False)
        _reach.set_permissions([auth.MANAGE_USERS])          # a SUBSET of what the MU admin holds
        _reach.servers.append(RemoteServer.query.get(other_remote))   # ...carrying a host they lack
        db.session.add(_reach)
        db.session.commit()
        _reach_gid = _reach.id
    cmu.post("/users/%d/edit" % _mu_uid,
             data={"display_name": "MU admin", "is_active": "on",
                   "groups": [str(_mu_gid), str(_reach_gid)]})
    with app.app_context():
        _mu_after = db.session.get(User, _mu_uid)
        _got_host = auth.can_access_server(_mu_after, other_id)
    check("escalation: joining a permission-subset group does not hand over its hosts",
          _got_host is False, "gained access to server %s on an ungranted host" % other_id)

    # ── ...and the FORM must offer only the groups the POST will actually accept ────────────────
    # /users passed `Group.query.all()` to the template, which renders a checkbox per group in the
    # Add User, Edit User and Invite modals. grantable_groups then silently dropped the ones out of
    # reach on save, and the route answered "User 'bob' created." regardless — the delegated admin
    # ticked two groups, saw success, and the account landed in neither, with no signal at all.
    _mu_page = cmu.get("/users").get_data(as_text=True)
    check("manage_users offers only the groups this admin can actually grant",
          ('name="groups" value="%d"' % _prize_gid) not in _mu_page
          and ('name="groups" value="%d"' % _reach_gid) not in _mu_page,
          "a group grantable_groups would discard is still rendered as a checkbox")
    # Positive control: the scoping must not empty the form. The group they legitimately hold is
    # within their own reach, so it has to stay tickable.
    check("manage_users still offers the groups they CAN grant",
          ('name="groups" value="%d"' % _mu_gid) in _mu_page,
          "their own group vanished from the Add/Edit User form")
    # ...and a superadmin still sees every group, since grantable_groups short-circuits for them.
    _sa_page = client_as(admin_id).get("/users").get_data(as_text=True)
    check("manage_users still offers every group to a superadmin",
          ('name="groups" value="%d"' % _prize_gid) in _sa_page
          and ('name="groups" value="%d"' % _reach_gid) in _sa_page,
          "the scoping also hid groups from a superadmin")
    # ...and the same rule for the Super Administrator switch. add_user answers _form_err when a
    # non-superadmin ticks it, so the control could only ever throw the whole filled-in form away
    # — the username, the email and the group choices with it.
    check("manage_users does not offer the superadmin switch to a delegated user admin",
          'name="is_superadmin"' not in _mu_page,
          "a control the route always refuses is still rendered")
    check("manage_users still offers the superadmin switch to a superadmin",
          'name="is_superadmin"' in _sa_page,
          "the switch vanished for the one role that may actually use it")

    # ── MANAGE_USERS must not reach an account holding permissions the actor lacks ──────────────
    # The superadmin flag was the ONLY actor-vs-target test, so MANAGE_USERS alone edited every
    # other account — and reset_password mints a new one and hands the plaintext straight back,
    # while reset_2fa clears their second factor. One request took over a more-privileged peer and
    # walked around _grantable_perms/grantable_groups entirely: not by acquiring the permission,
    # but by becoming someone who already had it.
    with app.app_context():
        _vic_grp = Group(name=tag + "_vic", description="RBAC test victim (auto)", is_default=False)
        _vic_grp.set_permissions([auth.UNINSTALL_SERVER, auth.MANAGE_REMOTES])
        db.session.add(_vic_grp)
        db.session.flush()
        _vic = User(username=tag + "_victim",
                    password_hash=auth.hash_password(secrets.token_hex(16)),
                    display_name="victim", is_superadmin=False, is_active=True)
        _vic.groups.append(_vic_grp)
        db.session.add(_vic)
        db.session.commit()
        _vic_id, _vic_hash = _vic.id, _vic.password_hash
    _r_take = cmu.post("/users/%d/edit" % _vic_id,
                       data={"display_name": "victim", "is_active": "on",
                             "reset_password": "on", "reset_2fa": "on"})
    with app.app_context():
        _vic_now = db.session.get(User, _vic_id)
        _hash_changed = _vic_now.password_hash != _vic_hash
    check("escalation: MANAGE_USERS cannot reset the password of a more-privileged account",
          not _hash_changed, "the victim's password hash was replaced")
    check("escalation: ...and the response does not hand back a credential",
          "lgsm_" not in _r_take.get_data(as_text=True),
          "a credential appeared in the refusal body")
    # The control must still work where it legitimately applies: a LESS-privileged target.
    with app.app_context():
        _low = User(username=tag + "_low", password_hash=auth.hash_password(secrets.token_hex(16)),
                    display_name="low", is_superadmin=False, is_active=True)
        db.session.add(_low)
        db.session.commit()
        _low_id, _low_hash = _low.id, _low.password_hash
    cmu.post("/users/%d/edit" % _low_id,
             data={"display_name": "low", "is_active": "on", "reset_password": "on"})
    with app.app_context():
        _low_changed = db.session.get(User, _low_id).password_hash != _low_hash
    check("escalation: ...but MAY still administer an account within their own permissions",
          _low_changed, "a legitimate reset was refused too — the guard is too broad")

    # ── ...and the same door, opened with OBJECTS instead of permissions ──────────────────────
    # Permissions were the whole test, and they are only half of what an account carries. Two
    # delegated admins can hold the IDENTICAL permission set and be granted different hosts: the
    # subset test passes in both directions, so either could reset the other's password, read the
    # new one straight off the response (_form_credential returns it so the page can show it once)
    # and sign in as them — reaching a host they were never granted. Not by acquiring a
    # permission, but by becoming someone who has the access, which is the escalation the block
    # above exists to close.
    with app.app_context():
        _peer_grp = Group(name=tag + "_peer", description="RBAC test peer (auto)", is_default=False)
        # The SAME permissions the acting admin's group holds, so only the objects differ.
        _peer_grp.set_permissions(list(auth.get_user_permissions(db.session.get(User, _mu_uid))))
        _peer_other = db.session.get(GameServer, other_id)
        if _peer_other is not None and _peer_other.remote is not None:
            _peer_grp.servers.append(_peer_other.remote)     # a host the actor cannot reach
        db.session.add(_peer_grp)
        db.session.flush()
        _peer = User(username=tag + "_peer_admin",
                     password_hash=auth.hash_password(secrets.token_hex(16)),
                     display_name="peer", is_superadmin=False, is_active=True)
        _peer.groups.append(_peer_grp)
        db.session.add(_peer)
        db.session.commit()
        _peer_id, _peer_hash = _peer.id, _peer.password_hash
        _actor_now = db.session.get(User, _mu_uid)
        _peer_now = db.session.get(User, _peer_id)
        # The premise: permissions really are equal, so this is testing the OBJECT half alone.
        _perms_equal = (set(auth.get_user_permissions(_peer_now))
                        == set(auth.get_user_permissions(_actor_now)))
        _reach_wider = not (auth.accessible_remote_ids(_peer_now)
                            <= auth.accessible_remote_ids(_actor_now))
    check("escalation: (premise) the peer holds equal permissions but a host the actor cannot reach",
          _perms_equal and _reach_wider,
          "perms_equal=%s reach_wider=%s — the check below would prove nothing"
          % (_perms_equal, _reach_wider))
    cmu.post("/users/%d/edit" % _peer_id,
             data={"display_name": "peer", "is_active": "on", "reset_password": "on"})
    with app.app_context():
        _peer_changed = db.session.get(User, _peer_id).password_hash != _peer_hash
    check("escalation: MANAGE_USERS cannot take over a peer who can reach hosts the actor cannot",
          not _peer_changed, "the peer's password hash was replaced")

    # ── ...and with CUSTOM COMMANDS, which need no permission at all to run ──────────────────
    # can_run_custom_command authorises on group membership alone, and the reach tests compared
    # permissions, hosts and game servers — never Group.custom_commands. So a group whose
    # permissions sit inside the actor's but which carries a superadmin-authored `exec {}` was
    # joinable, and a member of one could be taken over, by a delegated user admin.
    with app.app_context():
        from panel.db.models import CustomCommand as _CCmd
        _mu_cmd = _CCmd(name=tag + "_cmd", command_template="exec {}", enabled=True)
        db.session.add(_mu_cmd)
        _cmd_grp = Group(name=tag + "_cmdgrp", description="RBAC test command grant (auto)",
                         is_default=False)
        _cmd_grp.set_permissions([auth.MANAGE_USERS])       # a SUBSET of what the actor holds
        _cmd_grp.custom_commands.append(_mu_cmd)
        _plain_grp = Group(name=tag + "_plaingrp", description="RBAC test same, no command (auto)",
                           is_default=False)
        _plain_grp.set_permissions([auth.MANAGE_USERS])
        db.session.add_all([_cmd_grp, _plain_grp])
        db.session.flush()
        _cmd_peer = User(username=tag + "_cmd_peer",
                         password_hash=auth.hash_password(secrets.token_hex(16)),
                         display_name="cmd peer", is_superadmin=False, is_active=True)
        _cmd_peer.groups.append(_cmd_grp)
        _plain_peer = User(username=tag + "_plain_peer",
                           password_hash=auth.hash_password(secrets.token_hex(16)),
                           display_name="plain peer", is_superadmin=False, is_active=True)
        _plain_peer.groups.append(_plain_grp)
        db.session.add_all([_cmd_peer, _plain_peer])
        db.session.commit()
        _mu_cmd_id, _cmd_gid, _plain_gid = _mu_cmd.id, _cmd_grp.id, _plain_grp.id
        _cmd_peer_id, _cmd_peer_hash = _cmd_peer.id, _cmd_peer.password_hash
        _plain_peer_id, _plain_peer_hash = _plain_peer.id, _plain_peer.password_hash
    cmu.post("/users/%d/edit" % _mu_uid,
             data={"display_name": "MU admin", "is_active": "on",
                   "groups": [str(_mu_gid), str(_cmd_gid), str(_plain_gid)]})
    with app.app_context():
        _mu_row = db.session.get(User, _mu_uid)
        _mu_cmds, _mu_gids = auth.custom_command_ids(_mu_row), {g.id for g in _mu_row.groups}
    check("escalation: MANAGE_USERS cannot join a group to pick up its custom command",
          _mu_cmd_id not in _mu_cmds and _cmd_gid not in _mu_gids,
          "now in groups %s, holding commands %s" % (sorted(_mu_gids), sorted(_mu_cmds)))
    check("escalation: ...while the same group WITHOUT the command is still joined",
          _plain_gid in _mu_gids, "the plain group was refused too — the guard is too broad")
    cmu.post("/users/%d/edit" % _cmd_peer_id,
             data={"display_name": "cmd peer", "is_active": "on", "reset_password": "on"})
    cmu.post("/users/%d/edit" % _plain_peer_id,
             data={"display_name": "plain peer", "is_active": "on", "reset_password": "on"})
    with app.app_context():
        _cmd_peer_changed = db.session.get(User, _cmd_peer_id).password_hash != _cmd_peer_hash
        _plain_peer_changed = (db.session.get(User, _plain_peer_id).password_hash
                               != _plain_peer_hash)
    check("escalation: MANAGE_USERS cannot take over a peer whose extra reach is a command",
          not _cmd_peer_changed, "the command holder's password hash was replaced")
    check("escalation: ...but may still reset a peer with the same permissions and no command",
          _plain_peer_changed, "a legitimate reset was refused — the guard is too broad")

    # ── VIEW_LOGS is scoped to what the viewer can reach ─────────────────────────────────────
    # It was install-wide: a moderator given view_logs with ONE server read every server's console
    # commands (`rcon_password …`), every admin's sign-in address, and the attempted username of
    # every failed login — where people paste their password by mistake.
    if other_id is not None:
        from panel.db.models import AuditLog as _AL
        from panel.core.clock import utcnow as _al_now
        with app.app_context():
            _lv_grp = Group(name=tag + "_logs", description="RBAC test log viewer (auto)",
                            is_default=False)
            _lv_grp.set_permissions([auth.VIEW_LOGS, auth.VIEW_SERVERS])
            _lv_grp.game_servers.append(db.session.get(GameServer, accessible_id))
            db.session.add(_lv_grp)
            db.session.flush()
            _lv = User(username=tag + "_logviewer",
                       password_hash=auth.hash_password(secrets.token_hex(16)),
                       display_name="log viewer", is_superadmin=False, is_active=True)
            _lv.groups.append(_lv_grp)
            db.session.add(_lv)
            db.session.flush()
            _lv_id = _lv.id
            _mine_name = db.session.get(GameServer, accessible_id).name
            _other_name = db.session.get(GameServer, other_id).name
            _lt = tag + "LOGROW"
            for _uid_, _who, _act, _tgt, _det, _ip in (
                    (admin_id, "admin", "send_command", _mine_name, _lt + "_mine_srv", "198.51.100.1"),
                    (admin_id, "admin", "send_command", _other_name,
                     _lt + "_other_srv rcon_password S3cret", "198.51.100.5"),
                    (None, tag + "Sup3rSecretPw", "login_failed", "", _lt + "_failed", "198.51.100.2"),
                    (admin_id, "admin", "login", "", _lt + "_adminlogin", "198.51.100.3"),
                    # An ACCOUNT row whose free-text target happens to name their server (an
                    # invite's note is whatever the minter typed): still not theirs to read.
                    (admin_id, "admin", "invite_created", _mine_name, _lt + "_invite",
                     "198.51.100.6"),
                    (_lv_id, tag + "_logviewer", "logout", "", _lt + "_own", "198.51.100.4")):
                db.session.add(_AL(user_id=_uid_, username=_who, action=_act, target=_tgt,
                                   detail=_det, ip_address=_ip, success=True,
                                   timestamp=_al_now()))
            db.session.commit()
        try:
            _lv_page = client_as(_lv_id).get("/logs?q=" + _lt).get_data(as_text=True)
            _sa_logs = client_as(admin_id).get("/logs?q=" + _lt).get_data(as_text=True)
            check("view_logs: a scoped viewer sees rows about the server they can access",
                  _lt + "_mine_srv" in _lv_page and _lt + "_own" in _lv_page,
                  "their own server's / their own row is missing — the scope is too tight")
            check("view_logs: ...but not another server's console commands",
                  _lt + "_other_srv" not in _lv_page and "S3cret" not in _lv_page,
                  "a server outside their grants leaked its console history")
            check("view_logs: ...nor anyone's sign-ins or failed-login usernames",
                  _lt + "_failed" not in _lv_page and _lt + "_adminlogin" not in _lv_page
                  and (tag + "Sup3rSecretPw") not in _lv_page,
                  "account rows (or the failed-login username in the filter list) leaked")
            check("view_logs: ...nor an account row whose target merely names their server",
                  _lt + "_invite" not in _lv_page,
                  "an invite row reached a server-scoped viewer by its target")
            check("view_logs: ...nor another user's address, while their own is shown",
                  "198.51.100.1" not in _lv_page and "198.51.100.4" in _lv_page,
                  "another admin's IP is visible, or the viewer's own is hidden")
            check("view_logs: a superadmin still sees every row and address (control)",
                  all(_lt + s in _sa_logs for s in ("_mine_srv", "_other_srv", "_failed",
                                                    "_adminlogin", "_own", "_invite"))
                  and "198.51.100.1" in _sa_logs and (tag + "Sup3rSecretPw") in _sa_logs,
                  "the scoping also narrowed the superadmin's view")
        finally:
            with app.app_context():
                for _row in _AL.query.filter(_AL.detail.like(_lt + "%")).all():
                    db.session.delete(_row)
                db.session.commit()
    check("view_logs: (premise) the fixture has a second host to be scoped out",
          other_id is not None, "the scoping checks above did not run")

    # The same via /users/add — creating the account in the privileged group, then logging in as it
    # (the generated password is handed straight back to the caller).
    _new_name = tag + "_mu_made"
    cmu.post("/users/add", data={"username": _new_name, "display_name": _new_name,
                                 "groups": [str(_prize_gid)]})
    with app.app_context():
        _made = User.query.filter_by(username=_new_name).first()
        _made_perms = auth.get_user_permissions(_made) if _made else set()
    check("escalation: ...nor create a NEW user in that group",
          _made is None or (auth.UNINSTALL_SERVER not in _made_perms
                            and auth.MANAGE_REMOTES not in _made_perms),
          "the new account holds: %s" % sorted(_made_perms))

    # ── A delegated group admin must not widen a group's HOST/SERVER reach ───────────────────────
    # The permission list was filtered; the object grants beside it were not, so the same admin
    # could grant their own group every host in the install. Permissions unchanged — which is why
    # the checks above still passed — while can_access_remote started returning True for all of it.
    with app.app_context():
        _all_remote_ids = [r.id for r in RemoteServer.query.all()]
    c4.post("/groups/%d/edit" % gid4_for_scope,
            data={"name": tag4, "description": "",
                  "permissions": [auth.VIEW_SERVERS, auth.MANAGE_GROUPS],
                  "servers": [str(i) for i in _all_remote_ids]})
    with app.app_context():
        _granted = {r.id for r in db.session.get(Group, gid4_for_scope).servers}
    check("escalation: a MANAGE_GROUPS admin cannot grant hosts they cannot reach",
          _granted <= {granted_remote}, "group now grants hosts: %s" % sorted(_granted))

    # ── ...and the PAGE must not offer them what the POST will refuse ────────────────────────────
    # /groups rendered every host and every game server on the panel, with a tick box beside each,
    # to any MANAGE_GROUPS holder. The write path above refuses the ones outside their reach — so
    # ticking one did nothing and said nothing, and the names of hosts they have no access to were
    # disclosed on the way. Asserted on the tick boxes (value="<id>"), not on names, because a
    # group's EXISTING grants are listed separately and legitimately.
    with app.app_context():
        _unreachable = [r.id for r in RemoteServer.query.all() if r.id != granted_remote]
        _unreach_games = [g.id for g in GameServer.query.all()
                          if g.remote_id in set(_unreachable)]
    _gp = c4.get("/groups")
    _gp_html = _gp.get_data(as_text=True)

    def _boxes(name, ids):
        """The ids this page offers as <input name=...> tick boxes."""
        import re as _re
        found = set()
        for _m in _re.finditer(r'<input[^>]*name="%s"[^>]*>' % name, _gp_html):
            _v = _re.search(r'value="(\d+)"', _m.group(0))
            if _v:
                found.add(int(_v.group(1)))
        return found & set(ids)

    check("groups page: it renders for a delegated admin at all",
          _gp.status_code == 200, "status %d — the checks below would prove nothing" % _gp.status_code)
    check("groups page: ...and offers the host the admin CAN reach (positive control)",
          granted_remote in _boxes("servers", [granted_remote]),
          "the page offers no host at all, so the check below would pass with the form removed")
    check("groups page: a delegated admin is not offered hosts they cannot reach",
          not _boxes("servers", _unreachable),
          "offers host ids %s — ticking one is silently dropped by the POST guard, and the "
          "names are disclosed either way" % sorted(_boxes("servers", _unreachable)))
    if _unreach_games:
        check("groups page: ...nor the game servers on them",
              not _boxes("game_servers", _unreach_games),
              "offers server ids %s" % sorted(_boxes("game_servers", _unreach_games)))
    # A superadmin still sees everything — the filter is per-viewer, not a blanket narrowing.
    _sa_html = _ac.get("/groups").get_data(as_text=True)
    _sa_missing = [i for i in _unreachable if ('value="%d"' % i) not in _sa_html]
    check("groups page: ...while a superadmin is still offered every host",
          not _sa_missing, "a superadmin is missing host ids %s" % _sa_missing)

    # ── ...and the same for the PERMISSION boxes, which were offered unfiltered ────────────────
    # The host and game-server lists were narrowed to what the POST accepts; the permission list
    # beside them still rendered every entry in ALL_PERMISSIONS as an ordinary tick box.
    # _grantable_perms drops a requested permission the actor does not hold and PRESERVES one the
    # group already holds, so the control was inert in both directions — and the un-tick case is
    # the dangerous one: unticking "Open a shell on a host" on a group that holds it answered
    # "Group 'X' updated." and revoked nothing, while every member kept that shell. grp5 holds
    # MANAGE_USERS, which this admin cannot grant, and VIEW_SERVERS, which they can.
    def _perm_box(html, gid, perm):
        import re as _re
        _m = _re.search(r'<input[^>]*id="perm-%d-%s"[^>]*>' % (gid, perm), html)
        return _m.group(0) if _m else ""

    _pb_locked = _perm_box(_gp_html, gid5, auth.MANAGE_USERS)
    _pb_free = _perm_box(_gp_html, gid5, auth.VIEW_SERVERS)
    check("groups page: the permission tick boxes are where this check thinks they are",
          bool(_pb_locked) and bool(_pb_free),
          "locked=%r free=%r — the checks below would prove nothing" % (_pb_locked, _pb_free))
    check("groups page: a permission the admin cannot grant is not an ENABLED tick box",
          "disabled" in _pb_locked,
          "offers %r — unticking it reports 'updated' and revokes nothing" % _pb_locked)
    check("groups page: ...but is still shown, ticked, so the group's real power stays visible",
          "checked" in _pb_locked,
          "the box was hidden instead: %r — the page now understates what the group can do"
          % _pb_locked)
    check("groups page: ...while one they DO hold stays editable (positive control)",
          "disabled" not in _pb_free,
          "every permission box is disabled, so the check above passes for the wrong reason: %r"
          % _pb_free)

    # ── A per-server grant the form cannot SHOW is stripped by any save ────────────────────────
    # all_remotes (whole-host grants only) buckets the per-server tick boxes, but the write path's
    # allow-set is get_user_servers() — which also includes servers granted INDIVIDUALLY, whose
    # host carries no grant. grantable_object_ids preserves only ids outside the allow-set, so an
    # id that is allowed but was never rendered is neither requested nor preserved: it is dropped.
    # Driven the way the page actually submits — the ids its own form renders as checked — because
    # that is the request a browser sends when the admin edits the description and nothing else.
    with app.app_context():
        _ind_grp = Group(name=tag + "_indadm", description="RBAC individual-grant admin (auto)",
                         is_default=False)
        _ind_grp.set_permissions([auth.MANAGE_GROUPS])
        # NO whole-host grant — access to this one server and nothing else.
        _ind_grp.game_servers.append(db.session.get(GameServer, accessible_id))
        db.session.add(_ind_grp)
        db.session.flush()
        _ind_u = User(username=tag + "_indadm",
                      password_hash=auth.hash_password(secrets.token_hex(16)),
                      display_name="individual grant admin", is_superadmin=False, is_active=True)
        _ind_u.groups.append(_ind_grp)
        db.session.add(_ind_u)
        _ind_tgt = Group(name=tag + "_indtgt", description="RBAC individual-grant target (auto)",
                         is_default=False)
        _ind_tgt.game_servers.append(db.session.get(GameServer, accessible_id))
        db.session.add(_ind_tgt)
        db.session.commit()
        _ind_uid, _ind_tid = _ind_u.id, _ind_tgt.id
    _ic = client_as(_ind_uid)
    _ind_page = _ic.get("/groups")
    _ind_html = _ind_page.get_data(as_text=True)

    def _form_game_servers(html, gid):
        """The game_servers ids THIS page renders as checked for that group's edit form."""
        import re as _re
        out = []
        for _m in _re.finditer(r'<input[^>]*name="game_servers"[^>]*id="g%d-gs-(\d+)"[^>]*>'
                               % gid, html):
            if "checked" in _m.group(0):
                out.append(_m.group(1))
        return out

    _ind_offered = _form_game_servers(_ind_html, _ind_tid)
    check("groups page: it renders for an admin whose only access is a per-server grant",
          _ind_page.status_code == 200,
          "status %d — the checks below would prove nothing" % _ind_page.status_code)
    # ...and the host list's empty state must not make a claim about the INSTALL. It is filtered
    # to what this admin may grant, and it told them the panel had no hosts at all.
    check("groups page: an empty host list says none are GRANTABLE, not none configured",
          "No hosts configured yet." not in _ind_html and "No hosts you can grant." in _ind_html,
          "the page still tells a delegated admin the install has no hosts")
    check("groups page: ...and offers the server they were granted individually",
          str(accessible_id) in _ind_offered,
          "the form offers %s — server %d has no box anywhere, so the browser submits nothing "
          "for it" % (_ind_offered, accessible_id))
    _ic.post("/groups/%d/edit" % _ind_tid,
             data={"name": tag + "_indtgt", "description": "description changed",
                   "game_servers": _ind_offered})
    with app.app_context():
        _ind_kept = {g.id for g in db.session.get(Group, _ind_tid).game_servers}
        _ind_desc = db.session.get(Group, _ind_tid).description
    check("groups edit: an edit submitted as the page renders it keeps that per-server grant",
          accessible_id in _ind_kept,
          "group now grants %s — an edit that only changed the description revoked it, with no "
          "message and an audit row that just says edit_group" % sorted(_ind_kept))
    check("groups edit: ...and the edit itself went through (positive control)",
          _ind_desc == "description changed",
          "description is %r — the POST did nothing at all, so the check above proves nothing"
          % _ind_desc)

    # ── Bulk actions are access-checked per id ────────────────────────────────────────────────────
    # /api/servers/bulk-action is not an /<int:server_id> route, so the structural sweep below
    # never sees it, and it carries no @server_access_required — the check is hand-written in the
    # loop. A break here fans a power action out over SSH to every server in the install.
    if other_id:
        _ran = []
        _sv_rag = _sm_core.run_as_game_user
        try:
            _sm_core.run_as_game_user = lambda *a, **k: (_ran.append(a), ("", "", 0))[1]
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
            _sm_core.run_as_game_user = _sv_rag

    # ── The setup-only endpoints must stay shut when config.json is LOST ───────────────────────────
    # /api/setup/tailscale/{status,install,up,serve} are deliberately unauthenticated — during a fresh
    # install there is no user to authenticate. They are safe only for as long as their "setup is still
    # open" test is. That test used to be is_setup_complete(), which is (DB row AND config flag), and
    # the config half fails open: load_config() swallows JSONDecodeError/OSError and hands back
    # DEFAULT_CONFIG, where setup_complete is False.
    #
    # So this is the scenario: a fully configured panel whose data/config.json is deleted, truncated by
    # a full disk, or hand-edited into invalid JSON. Setup is unambiguously finished — the DB says so —
    # but the config flag reads False, and all four unlocked to anyone who could reach the port.
    # /install runs the Tailscale installer as root, and /up hands the caller an auth URL that joins
    # THIS HOST to their tailnet with SSH enabled.
    #
    # The config file is never touched here: CONFIG_FILE is pointed at a path that does not exist,
    # which is precisely the OSError branch, and restored in the finally.
    #
    # WARNING if you verify this by mutation (removing the guard to watch these fail): with the
    # guard gone these four requests REALLY RUN. tools/nosudo_runner.py will not save you — it
    # refuses sudo, but `tailscale up` and `tailscale serve` run as the operator user without it,
    # so /up and /serve reconfigure the tailnet of whatever machine you are sitting at, and /serve
    # writes a config file through the redirected CONFIG_FILE path. Mutate this one on a throwaway
    # host, or read the 403 and take it on faith.
    from panel.core import config as _cfg_mod

    with app.app_context():
        # Either the suite seeded one (empty DB) or the install has a real one. If neither, the
        # scenario doesn't exist and there is nothing to assert — say so rather than pass silently.
        _have_complete_row = SetupState.query.filter_by(complete=True).first() is not None
    check("probe: a completed setup row exists to test against", _have_complete_row)

    _real_config_file = _cfg_mod.CONFIG_FILE
    _real_cache = dict(_cfg_mod._cfg_cache)
    try:
        _cfg_mod.CONFIG_FILE = _real_config_file.parent / "does-not-exist-rbac-probe.json"
        _cfg_mod._cfg_cache["key"] = None
        # The precondition itself is worth asserting — without it the four checks below could pass
        # because the config was fine all along, which would prove nothing.
        check("probe: a missing config.json really does read back as setup_complete=False",
              _cfg_mod.load_config().get("setup_complete") is False)

        _anon = app.test_client()
        for _p, _m, _label in (("/api/setup/tailscale/status", "get", "status"),
                               ("/api/setup/tailscale/install", "post", "install (runs an installer as root)"),
                               ("/api/setup/tailscale/up", "post", "up (returns a tailnet auth URL)"),
                               ("/api/setup/tailscale/serve", "post", "serve (rewrites bind_host)")):
            _r = getattr(_anon, _m)(_p)
            check("setup endpoint stays SHUT with config.json gone: %s" % _label,
                  _r.status_code == 403, "%s -> %d %s" % (_p, _r.status_code, _r.data[:80]))
        # ...and the wizard it shares a lock with stays shut too, so the two agree.
        _rw = _anon.get("/setup")
        check("the setup wizard stays locked with config.json gone",
              _rw.status_code in (301, 302), "/setup -> %d" % _rw.status_code)
    finally:
        _cfg_mod.CONFIG_FILE = _real_config_file
        _cfg_mod._cfg_cache.clear()
        _cfg_mod._cfg_cache.update(_real_cache)

    # ...and now DRIVEN, not read. The check above asserts the call exists in the source; it cannot
    # tell whether the route acts on the answer, and the whole acceptance path (the 61 lines from the
    # token lookup to the committed account) was executed by nothing. An invite is the one flow where
    # an unauthenticated caller creates an account — and can be handed superadmin — so the guards on
    # it are worth running rather than grepping.
    from panel.db.models import Invite as _Inv   # noqa: E402
    from panel.core.clock import utcnow as _inv_utcnow   # noqa: E402
    from datetime import timedelta as _inv_timedelta   # noqa: E402

    _anon_inv = app.test_client()          # nobody: this route is reachable without a session


    def _mint(creator, superadmin=False, hours=24):
        with app.app_context():
            inv, tok = _Inv.mint(creator, hours=hours, superadmin=superadmin)
            db.session.add(inv)
            db.session.commit()
            return inv.id, tok


    def _accept(tok, username, password="Sufficient1!pass"):
        return _anon_inv.post("/invite/%s" % tok,
                              data={"username": username, "password": password,
                                    "confirm_password": password})


    def _user(username):
        with app.app_context():
            return User.query.filter_by(username=username).first()


    _inv_tag = tag + "_inv"      # from `tag`, so the final cleanup removes it even if this raises
    # This block borrows a REAL superadmin as the minter and toggles is_superadmin / is_active on
    # it, and this suite is documented to run against a configured install. It used to take the
    # first superadmin row whatever its state, restore it to (True, True) regardless, and delete
    # every invite in the database — so a deactivated setup-time admin came back ACTIVE, with its
    # old password, and the operator's outstanding invites were gone. Now: an ACTIVE minter, its
    # exact state snapshotted and restored, and only this run's invites removed.
    #
    # The dormant superadmin below is the fixture that case needs: deactivated, and sorting FIRST
    # (below every existing id), exactly where `.first()` found the setup-time account. Not a
    # literal 0: a run killed before its cleanup leaves that row, and the next run's insert then
    # died on the primary key, at this line, on every run until someone deleted it by hand.
    with app.app_context():
        _lowest = db.session.query(db.func.min(User.id)).scalar()      # 0 is falsy: no `or`
        _dormant = User(id=(1 if _lowest is None else _lowest) - 1,
                        username=_inv_tag + "_dormant",
                        password_hash=auth.hash_password(secrets.token_hex(16)),
                        display_name="dormant", is_superadmin=True, is_active=False)
        db.session.add(_dormant)
        _pre_inv, _ = _Inv.mint(db.session.get(User, admin_id), note=_inv_tag + " pre-existing")
        db.session.add(_pre_inv)
        db.session.commit()
        _pre_inv_id, _dormant_id = _pre_inv.id, _dormant.id
        _sa = User.query.filter_by(is_superadmin=True, is_active=True).order_by(User.id).first()
        _sa_id = _sa.id
        _sa_before = (_sa.is_superadmin, _sa.is_active, [_g.id for _g in _sa.groups])
        _inv_before = {_i.id for _i in _Inv.query.all()}
        _swept = {(type(_r).__name__, _r.id) for _r in _run_fixture_rows()}
    check("invite fixtures: the planted superadmin and invite are ones the final cleanup removes, "
          "so an exception anywhere in this block cannot leave them in the operator's panel",
          ("User", _dormant_id) in _swept and ("Invite", _pre_inv_id) in _swept,
          "dormant swept=%s, pre-existing invite swept=%s"
          % (("User", _dormant_id) in _swept, ("Invite", _pre_inv_id) in _swept))
    check("invite fixtures: ...and that cleanup finds this run's ordinary fixtures too (positive "
          "control)", ("User", uid) in _swept, "swept %s" % sorted(_swept)[:6])
    try:
        # 1. The happy path, so the refusals below are not passing for the wrong reason.
        _iid, _tok = _mint(_sa)
        check("invite route: a valid invite is accepted and creates the account",
              _accept(_tok, _inv_tag + "_ok").status_code in (200, 302)
              and _user(_inv_tag + "_ok") is not None,
              "the positive control failed — every refusal below proves nothing")
        check("invite route: ...and does NOT grant superadmin unless the invite said so",
              getattr(_user(_inv_tag + "_ok"), "is_superadmin", None) is False,
              "an ordinary invite minted a superadmin")

        # 2. The same link twice. The route claims the invite with UPDATE ... WHERE used_at IS NULL
        #    precisely so two submissions cannot both make an account.
        _r2 = _accept(_tok, _inv_tag + "_twice")
        check("invite route: the same link cannot be redeemed twice",
              _user(_inv_tag + "_twice") is None,
              "a second account was created from one invite (status %s)" % _r2.status_code)

        # 2b. ...and the RACE, which the sequential case above does not reach. A used invite is
        #     already refused by the early is_usable check, so that check is what makes 2 pass —
        #     the claim's `UPDATE ... WHERE used_at IS NULL` exists for two submissions in flight
        #     at once. Deterministic stand-in for the race: password_problem() is the last call
        #     before the claim, so marking the row used from inside it puts the invite in exactly
        #     the state a competing request would have left it in.
        import panel.routes.admin_notifications as _anmod
        _pw_real = _anmod.password_problem
        _iid_race, _tok_race = _mint(_sa)

        def _pw_then_steal(pw):
            with app.app_context():
                _row = db.session.get(_Inv, _iid_race)
                if _row is not None and _row.used_at is None:
                    _row.used_at = _inv_utcnow()
                    db.session.commit()
            return _pw_real(pw)

        _anmod.password_problem = _pw_then_steal
        try:
            _r_race = _accept(_tok_race, _inv_tag + "_race")
        finally:
            _anmod.password_problem = _pw_real
        check("invite route: an invite claimed mid-request makes no second account",
              _user(_inv_tag + "_race") is None,
              "the claim is not conditional on used_at, so two requests in flight both win "
              "(status %s)" % _r_race.status_code)

        # 2c. The OTHER half of that same race, which the claim did not ask about. is_usable tests
        #     used_at, revoked_at and expiry; the claim tested used_at alone — so an admin clicking
        #     Revoke between the is_usable check and the UPDATE did not stop the redemption. The
        #     account was created anyway, the row ended up stamped BOTH revoked and used, and the
        #     admin was told "the link no longer works" about a link that had just worked.
        #     revoke_invite already claims its side on both columns; same window, same stub.
        _iid_rev, _tok_rev = _mint(_sa)

        def _pw_then_revoke(pw):
            with app.app_context():
                _row = db.session.get(_Inv, _iid_rev)
                if _row is not None and _row.revoked_at is None:
                    _row.revoked_at = _inv_utcnow()
                    db.session.commit()
            return _pw_real(pw)

        _anmod.password_problem = _pw_then_revoke
        try:
            _r_rev = _accept(_tok_rev, _inv_tag + "_revoked")
        finally:
            _anmod.password_problem = _pw_real
        with app.app_context():
            _rev_row = db.session.get(_Inv, _iid_rev)
            _rev_stamped = _rev_row is not None and _rev_row.revoked_at is not None
            _rev_used = _rev_row is not None and _rev_row.used_at is not None
        check("invite route: (premise) the revocation really did land mid-request",
              _rev_stamped, "the window never opened, so the checks below prove nothing")
        check("invite route: an invite revoked mid-request creates no account",
              _user(_inv_tag + "_revoked") is None,
              "the claim asks only about used_at, so a revoke in flight loses the race "
              "(status %s)" % _r_rev.status_code)
        check("invite route: ...and the row is not left stamped both revoked and used",
              not _rev_used,
              "the redemption claimed a revoked invite — the admin is told the link no longer "
              "works about one that had just worked")

        # 3. The delegation must not outlive the authority behind it. A superadmin-granting invite
        #    from someone since DEMOTED must not still hand out the rank they lost.
        _iid_sa, _tok_sa = _mint(_sa, superadmin=True)
        with app.app_context():
            db.session.get(User, _sa_id).is_superadmin = False
            db.session.commit()
        _r3 = _accept(_tok_sa, _inv_tag + "_demoted")
        check("invite route: a superadmin invite from a DEMOTED admin is refused",
              _user(_inv_tag + "_demoted") is None,
              "an offboarded admin's outstanding invite still created an account "
              "(status %s)" % _r3.status_code)
        check("invite route: ...and the form is not even shown for it",
              _anon_inv.get("/invite/%s" % _tok_sa).status_code == 404,
              "a dead invite still renders its form")
        with app.app_context():                      # put the fixture back before the next case
            db.session.get(User, _sa_id).is_superadmin = True
            db.session.commit()

        # 3b. A GROUP grant is the same rank, and it used to survive demotion. Minting is
        #     superadmin-only and the groups are validated against the minter AT MINT TIME —
        #     which for a superadmin is everything — so a superadmin who minted an invite into a
        #     privileged group and was then demoted (while staying active) left a live link that
        #     still created an account holding the permissions they had just lost. Whoever kept
        #     the link, including them, could redeem it.
        with app.app_context():
            _priv_grp = Group(name=_inv_tag + "_priv", description="privileged (auto)",
                              is_default=False)
            _priv_grp.set_permissions([auth.MANAGE_USERS, auth.MANAGE_REMOTES])
            db.session.add(_priv_grp)
            db.session.commit()
            _priv_gid = _priv_grp.id
            _ginv, _tok_grp = _Inv.mint(_sa, group_ids=[_priv_gid])
            db.session.add(_ginv)
            db.session.commit()
        with app.app_context():                    # the minter loses the rank behind the grant
            db.session.get(User, _sa_id).is_superadmin = False
            db.session.commit()
        _r_grp = _accept(_tok_grp, _inv_tag + "_grp")

        def _groups_of(username):
            # INSIDE a context: _user() hands back a detached row, and touching .groups on it
            # raises DetachedInstanceError rather than answering.
            with app.app_context():
                _u = User.query.filter_by(username=username).first()
                return None if _u is None else sorted(g.name for g in _u.groups)

        _grp_got = _groups_of(_inv_tag + "_grp")
        check("invite route: a GROUP grant does not outlive its minter's authority either",
              _grp_got is None,
              "a demoted admin's invite still created an account carrying %s (status %s)"
              % (_grp_got, _r_grp.status_code))
        with app.app_context():
            db.session.get(User, _sa_id).is_superadmin = True
            db.session.commit()
            _ginv2, _tok_grp2 = _Inv.mint(_sa, group_ids=[_priv_gid])
            db.session.add(_ginv2)
            db.session.commit()
        _accept(_tok_grp2, _inv_tag + "_grp_ok")
        _grp_ok = _groups_of(_inv_tag + "_grp_ok")
        check("invite route: ...while an intact minter's group invite still works",
              _grp_ok is not None and (_inv_tag + "_priv") in _grp_ok,
              "the control failed (%s) — the refusal above proves nothing" % (_grp_ok,))

        # 3c. The same rule on the OBJECT axis, which this re-validation never asked about.
        #     grantable_groups' _within_my_reach tests three things — permissions, whole-host
        #     grants (Group.servers) and per-server grants (Group.game_servers) — and the copy in
        #     redeem_invite tested the permissions subset alone. A group carrying NO permissions
        #     makes `set() <= _mine` trivially true, so a pure-ACCESS group sailed straight through
        #     with its whole-host grant intact and the new account could reach every server on a
        #     host the minter had just lost. /users (grantable_groups) and /groups
        #     (grantable_object_ids) both refuse that same grant to that same person; the invite
        #     was the one door left open. 3b cannot catch this — its group's permissions are what
        #     the demotion takes away.
        with app.app_context():
            _host_grp = Group(name=_inv_tag + "_host", description="host access only (auto)",
                              is_default=False)
            _host_grp.set_permissions([])          # none at all: the subset test cannot catch it
            _host_grp.servers.append(db.session.get(RemoteServer, granted_remote))
            db.session.add(_host_grp)
            db.session.commit()
            _host_gid = _host_grp.id
            _hinv, _tok_host = _Inv.mint(db.session.get(User, _sa_id), group_ids=[_host_gid])
            db.session.add(_hinv)
            db.session.commit()
        with app.app_context():                    # the minter loses the reach behind the grant
            db.session.get(User, _sa_id).is_superadmin = False
            db.session.commit()
        _r_host = _accept(_tok_host, _inv_tag + "_host")
        _host_got = _groups_of(_inv_tag + "_host")
        check("invite route: a WHOLE-HOST group grant does not outlive its minter's reach either",
              _host_got is None,
              "a demoted minter's invite still created an account carrying %s — a group with no "
              "permissions at all, so a permissions-only subset test waves it through (status %s)"
              % (_host_got, _r_host.status_code))
        # ...and that is a REACH test, not a blanket refusal for anyone who is not a superadmin:
        # hand the (still demoted) minter that same host through a group of their own, and the
        # identical invite works again.
        with app.app_context():
            _reach_grp = Group(name=_inv_tag + "_reach", description="minter's own reach (auto)",
                               is_default=False)
            _reach_grp.set_permissions([])
            _reach_grp.servers.append(db.session.get(RemoteServer, granted_remote))
            db.session.add(_reach_grp)
            _sa_row = db.session.get(User, _sa_id)
            _sa_row.groups.append(_reach_grp)
            db.session.commit()
            _hinv2, _tok_host2 = _Inv.mint(_sa_row, group_ids=[_host_gid])
            db.session.add(_hinv2)
            db.session.commit()
        _accept(_tok_host2, _inv_tag + "_host_ok")
        _host_ok = _groups_of(_inv_tag + "_host_ok")
        check("invite route: ...while a minter who still reaches that host can hand it out",
              _host_ok is not None and (_inv_tag + "_host") in _host_ok,
              "the control failed (%s) — the refusal above proves nothing" % (_host_ok,))
        with app.app_context():                    # restore the fixture the next case expects
            _sa_row = db.session.get(User, _sa_id)
            _sa_row.groups = [_g for _g in _sa_row.groups
                              if _g.name != _inv_tag + "_reach"]
            _sa_row.is_superadmin = True
            db.session.commit()

        # 3d. The fourth axis, custom commands: a group holding nothing but a superadmin-authored
        #     command passes the permission, host and server tests trivially, and membership alone
        #     authorises the command.
        with app.app_context():
            from panel.db.models import CustomCommand as _ICC
            _inv_cmd = _ICC(name=_inv_tag + "_cmd", command_template="exec {}", enabled=True)
            db.session.add(_inv_cmd)
            _icmd_grp = Group(name=_inv_tag + "_cmdgrp", description="a command only (auto)",
                              is_default=False)
            _icmd_grp.set_permissions([])
            _icmd_grp.custom_commands.append(_inv_cmd)
            db.session.add(_icmd_grp)
            db.session.commit()
            _inv_cmd_id, _icmd_gid = _inv_cmd.id, _icmd_grp.id
            _cinv, _tok_cmd = _Inv.mint(db.session.get(User, _sa_id), group_ids=[_icmd_gid])
            db.session.add(_cinv)
            db.session.commit()
        with app.app_context():                    # the minter loses the command with the demotion
            db.session.get(User, _sa_id).is_superadmin = False
            db.session.commit()
        _r_cmd = _accept(_tok_cmd, _inv_tag + "_cmd")
        check("invite route: a CUSTOM-COMMAND group grant does not outlive its minter's reach",
              _groups_of(_inv_tag + "_cmd") is None,
              "a demoted minter's invite created an account carrying %s (status %s)"
              % (_groups_of(_inv_tag + "_cmd"), _r_cmd.status_code))
        with app.app_context():                    # positive control: the minter holds it too
            _own_cmd = Group(name=_inv_tag + "_owncmd", description="minter's command (auto)",
                             is_default=False)
            _own_cmd.set_permissions([])
            _own_cmd.custom_commands.append(db.session.get(_ICC, _inv_cmd_id))
            db.session.add(_own_cmd)
            _sa_row = db.session.get(User, _sa_id)
            _sa_row.groups.append(_own_cmd)
            db.session.commit()
            _cinv2, _tok_cmd2 = _Inv.mint(_sa_row, group_ids=[_icmd_gid])
            db.session.add(_cinv2)
            db.session.commit()
        _accept(_tok_cmd2, _inv_tag + "_cmd_ok")
        _cmd_ok = _groups_of(_inv_tag + "_cmd_ok")
        check("invite route: ...while a minter who holds that command can hand it out",
              _cmd_ok is not None and (_inv_tag + "_cmdgrp") in _cmd_ok,
              "the control failed (%s) — the refusal above proves nothing" % (_cmd_ok,))
        with app.app_context():                    # restore the fixture the next case expects
            _sa_row = db.session.get(User, _sa_id)
            _sa_row.groups = [_g for _g in _sa_row.groups
                              if _g.name != _inv_tag + "_owncmd"]
            _sa_row.is_superadmin = True
            db.session.commit()

        # 4. Deactivated, not merely demoted: nobody is standing behind the invite at all.
        _iid_d, _tok_d = _mint(_sa)
        with app.app_context():
            db.session.get(User, _sa_id).is_active = False
            db.session.commit()
        _r4 = _accept(_tok_d, _inv_tag + "_inactive")
        check("invite route: an invite from a DEACTIVATED admin is refused",
              _user(_inv_tag + "_inactive") is None,
              "status %s" % _r4.status_code)
        with app.app_context():
            db.session.get(User, _sa_id).is_active = True
            db.session.commit()

        # 5. An expired invite, and a token nobody minted, answer the SAME way — a link that said
        #    "already used" would confirm to a stranger that the token was real.
        _iid_x, _tok_x = _mint(_sa, hours=1)
        with app.app_context():
            _x = db.session.get(_Inv, _iid_x)
            _x.expires_at = _inv_utcnow() - _inv_timedelta(hours=2)
            db.session.commit()
        _r_exp = _anon_inv.get("/invite/%s" % _tok_x)
        _r_bogus = _anon_inv.get("/invite/%s" % ("z" * 43))
        check("invite route: an expired invite is refused",
              _r_exp.status_code == 404 and _user(_inv_tag + "_exp") is None)
        # Per-REQUEST values are normalised out before comparing: the CSP nonce and the CSRF
        # token are fresh every response by design and say nothing about the invite. Everything
        # else must match, because a page that said "already used" would confirm to a stranger
        # that a guessed token was real.
        #
        # The nonce alone was not enough. CI failed this where the machine that wrote it passed:
        # the CSRF token is time-based, so two requests in the same second produce the same one
        # and two that straddle a second do not. A test that depends on how fast the machine is
        # is not a test.
        import difflib as _dl
        import re as _inv_re

        def _no_nonce(t):
            t = _inv_re.sub(r'nonce="[^"]*"', 'nonce="X"', t)
            t = _inv_re.sub(r'window\.CSRF\s*=\s*"[^"]*"', 'window.CSRF = "X"', t)
            t = _inv_re.sub(r'name="csrf_token"[^>]*value="[^"]*"',
                            'name="csrf_token" value="X"', t)
            return t

        _d_exp, _d_bog = _no_nonce(_r_exp.get_data(as_text=True)), \
            _no_nonce(_r_bogus.get_data(as_text=True))
        _diff = [l for l in _dl.unified_diff(_d_exp.split("\n"), _d_bog.split("\n"),
                                             lineterm="", n=0)
                 if l[:1] in "+-" and l[:3] not in ("---", "+++")]
        check("invite route: ...and a guessed token is refused the SAME way, telling it nothing",
              _r_bogus.status_code == _r_exp.status_code and _d_bog == _d_exp,
              "status %s vs %s; differing lines: %s"
              % (_r_exp.status_code, _r_bogus.status_code, " || ".join(_diff[:4])[:400]))
    finally:
        with app.app_context():
            for _n in ("_ok", "_twice", "_demoted", "_inactive", "_exp", "_race", "_revoked",
                       "_grp", "_grp_ok", "_host", "_host_ok", "_cmd", "_cmd_ok"):
                _u = User.query.filter_by(username=_inv_tag + _n).first()
                if _u is not None:
                    db.session.delete(_u)
            for _row in _Inv.query.all():
                if _row.id not in _inv_before:     # this run's invites only, never the operator's
                    db.session.delete(_row)
            _sa_row = db.session.get(User, _sa_id)
            if _sa_row is not None:
                # The reach fixture is a group ON the superadmin, so it has to come off before the
                # groups are deleted — the rest of this suite runs against that account. Restored
                # to exactly what it was, not to a literal (True, True).
                _sa_row.groups = [_g for _g in (db.session.get(Group, _i) for _i in _sa_before[2])
                                  if _g is not None]
                _sa_row.is_superadmin, _sa_row.is_active = _sa_before[0], _sa_before[1]
            db.session.commit()
            for _g in Group.query.filter(Group.name.like(_inv_tag + "%")).all():
                db.session.delete(_g)
            db.session.commit()
            from panel.db.models import CustomCommand as _ICC_rm
            for _c in _ICC_rm.query.filter(_ICC_rm.name.like(_inv_tag + "%")).all():
                db.session.delete(_c)
            db.session.commit()
    with app.app_context():
        _dorm = User.query.filter_by(username=_inv_tag + "_dormant").first()
        check("invite fixtures: a DEACTIVATED superadmin is still deactivated after the run",
              _dorm is not None and _dorm.is_active is False,
              "the suite re-enabled a dormant superadmin: %r" % (getattr(_dorm, "is_active", None),))
        check("invite fixtures: an invite that predates the run survives it",
              db.session.get(_Inv, _pre_inv_id) is not None, "the operator's invite was deleted")
        check("invite fixtures: ...while every invite this run minted is gone (positive control)",
              {_i.id for _i in _Inv.query.all()} <= _inv_before,
              "left behind: %s" % sorted({_i.id for _i in _Inv.query.all()} - _inv_before))
        _minter = db.session.get(User, _sa_id)
        check("invite fixtures: the borrowed minter is back exactly as it was",
              _minter is not None and (_minter.is_superadmin, _minter.is_active,
                                       [_g.id for _g in _minter.groups]) == _sa_before,
              "%r vs %r" % (_sa_before, _minter and (_minter.is_superadmin, _minter.is_active,
                                                     [_g.id for _g in _minter.groups])))
        for _gone in (_dorm, db.session.get(_Inv, _pre_inv_id)):
            if _gone is not None:
                db.session.delete(_gone)
        db.session.commit()

    # ── deleting a user ───────────────────────────────────────────────────────────────────────
    # /users/<id>/delete had no test executing it at all. It refuses on four counts, but only two
    # of them are REACHABLE: the explicit "only a superadmin may delete a superadmin" is already
    # covered by can_administer_user (a superadmin's permissions are never a subset of a delegated
    # admin's), and "never the last one" needs a caller who is a superadmin AND a target who is
    # the only superadmin — which can only be the caller, caught first by the self check. Both are
    # belt-and-braces. So these assert the OUTCOME rather than which line produced it: removing
    # any single guard changes nothing, which is the point of having them.
    _del_tag = tag + "_del"      # from `tag`: its victim is an ACTIVE superadmin, if it survives
    with app.app_context():
        from panel.core.config import encrypt_secret
        _victim_sa = User(username=_del_tag + "_sa",
                          password_hash=auth.hash_password(secrets.token_hex(16)),
                          display_name="victim sa", is_superadmin=True, is_active=True,
                          email=encrypt_secret("victim-sa@rbac.invalid"))
        _victim_ord = User(username=_del_tag + "_ord",
                           password_hash=auth.hash_password(secrets.token_hex(16)),
                           display_name="victim ord", is_superadmin=False, is_active=True)
        db.session.add_all([_victim_sa, _victim_ord])
        db.session.commit()
        _vsa_id, _vord_id = _victim_sa.id, _victim_ord.id

    def _alive(uid):
        with app.app_context():
            return db.session.get(User, uid) is not None

    ca_del = client_as(admin_id)

    # 0. ...and the users page does not OFFER what these refuse. It rendered Edit and Delete on
    #    every row and put every account's email and 2FA state in #users-data, so a delegated admin
    #    was handed superadmins' contact details and controls whose every save is refused.
    import json as _ua_json
    import re as _ua_re
    _ua_html = cmu.get("/users").get_data(as_text=True)
    _ua_m = _ua_re.search(r'id="users-data"[^>]*>(.*?)</script>', _ua_html, _ua_re.S)
    _ua_ids = {r.get("id") for r in (_ua_json.loads(_ua_m.group(1)) if _ua_m else [])}
    check("users page: (control) a delegated admin gets Edit and Delete for an account they may administer",
          'data-action="openEditUser" data-args=\'[%d]\'' % _vord_id in _ua_html and ("/users/%d/delete" % _vord_id) in _ua_html
          and _vord_id in _ua_ids, "the administerable row lost its controls")
    check("users page: ...but neither control for a superadmin they may not",
          'data-action="openEditUser" data-args=\'[%d]\'' % _vsa_id not in _ua_html and ("/users/%d/delete" % _vsa_id) not in _ua_html,
          "Edit/Delete offered on an account edit_user/delete_user refuse")
    check("users page: ...and that superadmin's email and 2FA state are not in the page data",
          _vsa_id not in _ua_ids and "victim-sa@rbac.invalid" not in _ua_html,
          "the page carries the email of an account the viewer cannot administer")
    check("users page: nobody is offered Delete on their own account",
          ("/users/%d/delete" % _mu_uid) not in _ua_html)

    # 1. A delegated admin must not remove a superadmin.
    cmu.post("/users/%d/delete" % _vsa_id)
    check("delete user: MANAGE_USERS alone cannot delete a SUPERADMIN", _alive(_vsa_id),
          "a non-superadmin removed a superadmin account")

    # 2. The control that makes 1 mean something: a real superadmin CAN delete that same account,
    #    so the refusal above is authorization and not "deleting a superadmin never works".
    ca_del.post("/users/%d/delete" % _vsa_id)
    check("delete user: ...while a superadmin CAN delete that same account", not _alive(_vsa_id),
          "the control failed, so the refusal above proves nothing")

    # 3. And an ordinary account, the plain path.
    ca_del.post("/users/%d/delete" % _vord_id)
    check("delete user: a superadmin can delete an ordinary account", not _alive(_vord_id))

    # 4. Nobody deletes themselves — the one guard here that is reachable on its own, and the one
    #    standing between a panel and having no administrator at all.
    ca_del.post("/users/%d/delete" % admin_id)
    check("delete user: you cannot delete your own account", _alive(admin_id),
          "the acting superadmin deleted themselves — the panel would have no admin left")

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
        #
        # EVERY fixture, not just the first three. uid4 (the delegated group-admin) and the groups
        # for the escalation tests were created but never cleaned up, so running this suite against
        # a configured install left a real user account — in a group holding MANAGE_GROUPS — plus
        # three groups sitting in the operator's panel. Driven off the `tag` prefix rather than a
        # hand-kept list, so a fixture added later is cleaned up by construction.
        with app.app_context():
            for _uid in (uid, locals().get("uid2"), locals().get("uid3"), locals().get("uid4")):
                if _uid:
                    _u = User.query.get(_uid)
                    if _u:
                        db.session.delete(_u)
            # Belt and braces: anything whose name starts with this run's unique tag is ours.
            for _row in _run_fixture_rows():
                db.session.delete(_row)
            db.session.commit()
    print("Fixtures cleaned up.\n")

# The configured-install cleanup above is what the invite block's "the final cleanup removes it"
# check vouches for, and no CI run reaches it: an empty database is seeded and dropped whole. So
# that it deletes every row _run_fixture_rows names is read from the source.
_fx_deletes = [
    _n for _t in ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8")).body
    if isinstance(_t, ast.Try) for _f in _t.finalbody for _n in ast.walk(_f)
    if isinstance(_n, ast.For) and isinstance(_n.iter, ast.Call)
    and getattr(_n.iter.func, "id", None) == "_run_fixture_rows"
    and any(isinstance(_c, ast.Call) and getattr(_c.func, "attr", None) == "delete"
            for _s in _n.body for _c in ast.walk(_s))]
check("fixtures: the configured-install cleanup deletes every row _run_fixture_rows names",
      len(_fx_deletes) == 1,
      "found %d such loop(s) in a top-level finally — the invite and delete-user blocks rely on "
      "it to remove a planted superadmin if they raise" % len(_fx_deletes))

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

# ── ...and the same for <int:remote_id>, which is the BIGGER family ────────────────────────────
# get_remote()'s docstring says "Every remote-scoped route goes through here, so a direct API call
# to another remote's id is a 403". That was true when checked by hand (51 of 51) — but it was
# only a docstring: nothing failed if the next route skipped it, which is exactly the state
# <server_id> was in before the gate above was written. MANAGE_REMOTES is a global permission, so
# a route that reads remote_id without get_remote() hands every holder every OTHER host's name,
# patch state and firewall config.
#
# Read from the SOURCE rather than an attribute: there is no decorator to mark, the enforcement is
# a get_remote() call in the body. Accepting accessible_remote_ids()/can_access_remote() too,
# because the list endpoints filter by the allowed set instead of fetching one row.
#
# Matched as an AST CALL, not as text. A substring search passed on a route whose check had been
# removed, because a COMMENT four lines down still said the words "get_remote() has already looked
# the host up" — the gate read the explanation as the thing it explains. Verified by mutation:
# swapping one route's get_remote() for a bare query now fails this.
_remote_unguarded = []
for _rule in app.url_map.iter_rules():
    if "<int:remote_id>" not in str(_rule):
        continue
    _fn, _perms = app.view_functions.get(_rule.endpoint), ()
    while _fn is not None:
        _perms = _perms or getattr(_fn, "_required_perms", ())
        _nxt = getattr(_fn, "__wrapped__", None)
        if _nxt is None:
            break
        _fn = _nxt
    _GUARDS = {"get_remote", "can_access_remote", "accessible_remote_ids"}
    try:
        _tree = ast.parse(textwrap.dedent(inspect.getsource(_fn)))
    except (OSError, TypeError, SyntaxError):
        _tree = None
    _guarded = bool(_tree) and any(
        isinstance(_n, ast.Call)
        and (getattr(_n.func, "id", None) in _GUARDS or getattr(_n.func, "attr", None) in _GUARDS)
        for _n in ast.walk(_tree))
    if not (_guarded or _perms == (auth.SUPER_ADMIN,)):
        _remote_unguarded.append("%s %s" % (sorted(_rule.methods & {"GET", "POST", "PUT", "DELETE"}), _rule))
check("every <remote_id> route enforces per-host access (not just MANAGE_REMOTES)",
      not _remote_unguarded, "; ".join(sorted(_remote_unguarded)[:6]))

# ── ...and a mutating route must check a PERMISSION, not just access to the object ─────────────
# The two gates above answer "may this user reach THIS object?". Neither answers "may they CHANGE
# it?" — so refresh_server_commands carried @server_access_required alone, and any account that
# could see a server could make the panel SSH to its host and overwrite the stored command list,
# with no audit row. Its neighbours on the same page all gate inline, which is why nothing looked
# odd.
#
# Derived from the url map so a mutating route added later has to answer for itself. The allowlist
# is the routes whose lack of a permission gate is the design.
_MUT_NO_PERM_OK = {
    # Self-service: the object IS the caller.
    "account_update_profile", "account_change_password", "account_2fa_enable",
    "account_2fa_disable", "account_2fa_verify", "account_revoke_sessions",
    "account_revoke_session", "account_api_token_generate", "account_api_token_revoke",
    "account_regenerate_backup_codes", "api_account_ui_order", "api_account_prefs", "logout",
    "account_2fa_setup", "account_set_language", "api_account_session_revoke",
    "api_account_ui_order_reset", "account_dismiss_otp_nag",
    # The viewer's own UI language. POST because the PROFILE write is a stored state change and
    # csrf.protect() is a no-op on safe methods; it is still self-service, and it is reachable
    # pre-login (the switcher is on the login page), so there is no permission to require.
    "set_language",
    # Unauthenticated by design: login, the setup wizard, an invite redemption. The two setup
    # Tailscale endpoints carry their own gate — _setup_open() — because no login exists yet.
    "login", "login_2fa", "redeem_invite", "force_password_change",
    "api_setup_ts_install", "api_setup_ts_serve", "api_setup_ts_up",
}
_mut_unguarded, _mut_seen = [], []


def _mut_scanned():
    return len(_mut_seen)


_GATE_TOKENS = ("permission_required", "superadmin_required", "has_permission",
                "can_moderate_action", "can_run_custom_command", "_can_manage_files",
                "_can_edit_tags", "is_superadmin", "_required_perms")
for _rule in app.url_map.iter_rules():
    if not ({"POST", "PUT", "PATCH", "DELETE"} & set(_rule.methods or ())):
        continue
    _mut_seen.append(_rule.endpoint)
    if _rule.endpoint in _MUT_NO_PERM_OK or _rule.endpoint == "static":
        continue
    _fn = app.view_functions.get(_rule.endpoint)
    _perms = ()
    _inner = _fn
    while _inner is not None:
        _perms = _perms or getattr(_inner, "_required_perms", ())
        _nxt = getattr(_inner, "__wrapped__", None)
        if _nxt is None:
            break
        _inner = _nxt
    try:
        _src = inspect.getsource(_inner)
    except (OSError, TypeError):
        _src = ""
    if not (_perms or any(_t in _src for _t in _GATE_TOKENS)):
        _mut_unguarded.append(str(_rule))
# The positive control: a walk that finds no mutating routes at all would pass silently.
check("rbac: the mutating-route scan found routes to check", _mut_scanned() > 40,
      "only %d mutating routes seen — the gate below proves nothing" % _mut_scanned())
check("every mutating route checks a PERMISSION, not just object access",
      not _mut_unguarded, "no permission gate on: %s" % sorted(_mut_unguarded)[:6])

# ── an invite must not outlive the authority behind it ────────────────────────────────────────
# An invite is a delegation. Without this the delegation survives its grantor: an admin who is
# offboarded — demoted, deactivated, deleted — leaves live invites behind for up to the 30-day
# maximum TTL, and whoever holds one still gets the account they were promised, up to and
# including SUPERADMIN. Demonstrated against the code before it was fixed.
#
# Checked HERE, at the route, not only on Invite.authority_intact: deleting the call from
# redeem_invite left every model-level test green, which is the whole failure mode this guards.
_redeem = app.view_functions.get("redeem_invite")
while getattr(_redeem, "__wrapped__", None) is not None:
    _redeem = _redeem.__wrapped__
try:
    _redeem_src = inspect.getsource(_redeem)
except (OSError, TypeError):
    _redeem_src = ""
_calls_authority = any(
    isinstance(_n, ast.Call)
    and getattr(_n.func, "attr", getattr(_n.func, "id", None)) == "authority_intact"
    for _n in ast.walk(ast.parse(textwrap.dedent(_redeem_src))) ) if _redeem_src else False
check("redeem_invite refuses an invite whose creator lost their authority",
      _calls_authority,
      "it must call Invite.authority_intact(creator) — without it an offboarded admin's "
      "outstanding invite still creates the account it promised, superadmin included")


# ── every MUTATING endpoint leaves an audit trail ─────────────────────────────────────────────
# The audit log is the only record of who changed what. api_remote_bootstrap had none at all —
# and it is the most invasive thing the panel does to a machine: updates, UFW, SSH hardening,
# swap, fail2ban, a new user, a reboot. remote_tailscale_finalize (opens tailscale0 in the
# remote's UFW) had none either, while the four Tailscale actions beside it in the same file all
# logged. Nothing failed in either case; the rows simply were not there.
#
# Resolved through HELPERS, because plenty of routes log via one — api_server_action looks silent
# until you follow _run_action, and both whitelist endpoints log inside _whitelist_mutate. A
# shallow check would accuse all three.
#
# The listed endpoints genuinely have nothing to audit; each says why, so a real gap cannot hide
# among them.
_NO_AUDIT_OK = {
    "api_account_ui_order",          # the viewer's own dashboard tile order — a UI preference
    "api_remote_bootstrap_dismiss",  # dismisses a banner
    "api_server_install_dismiss",    # dismisses a banner (it does carry a permission gate now)
    "api_server_upload_check",       # pre-flight check before an upload; changes nothing
    "api_tailscale_check_peer",      # connectivity probe; changes nothing
    "set_language",                  # the viewer's own UI language; usable pre-login
    "test_remote",                   # SSH reachability probe; changes nothing
    "notifications_test",            # sends one test notification to the configured channel
}
_calls, _logs_direct = {}, set()
for _f in pathlib.Path(_ROOT, "panel").rglob("*.py"):
    try:
        _tree = ast.parse(_f.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        continue
    _stack = []

    class _V(ast.NodeVisitor):
        def visit_FunctionDef(self, n):
            _stack.append(n.name)
            self.generic_visit(n)
            _stack.pop()
        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, n):
            _nm = getattr(n.func, "id", getattr(n.func, "attr", None))
            if _stack and _nm:
                if _nm == "log_action":
                    _logs_direct.add(_stack[-1])
                else:
                    _calls.setdefault(_stack[-1], set()).add(_nm)
            self.generic_visit(n)
    _V().visit(_tree)
_logs = set(_logs_direct)
for _ in range(6):                       # transitive: a view logs if what it calls logs
    _grew = False
    for _fn, _callees in _calls.items():
        if _fn not in _logs and (_callees & _logs):
            _logs.add(_fn)
            _grew = True
    if not _grew:
        break
_unaudited, _seen_ep = [], set()
for _rule in app.url_map.iter_rules():
    if not (_rule.methods & {"POST", "PUT", "DELETE", "PATCH"}) or _rule.endpoint in _seen_ep:
        continue
    _seen_ep.add(_rule.endpoint)
    if _rule.endpoint not in _logs and _rule.endpoint not in _NO_AUDIT_OK:
        _unaudited.append("%s (%s)" % (_rule, _rule.endpoint))
check("every mutating endpoint writes an audit entry (or is listed as having nothing to audit)",
      not _unaudited,
      "; ".join(sorted(_unaudited)[:5]) + " — call log_action(), or add the endpoint to "
      "_NO_AUDIT_OK with the reason it has nothing to record")
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
# `results and`, like every other suite has: with results == [] the comparison is 0 == 0 and the
# suite exits 0 having asserted nothing at all.
sys.exit(0 if results and passed == len(results) else 1)
