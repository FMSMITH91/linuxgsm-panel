"""Automated RBAC enforcement test: permissions are enforced server-side.

It proves they cannot be bypassed by calling endpoints directly.

Run it against a configured install (from anywhere):

    ./venv/bin/python tests/rbac_test.py      # exits 0 if all checks pass

It creates a throwaway limited group + user (view-only, access to ONE host),
exercises the real HTTP endpoints via Flask's test client, and deletes the fixtures
again. Privileged actions are asserted to be BLOCKED *before* they execute — and every
destructive action a probe here aims at (Tailscale install/join, VPS bootstrap, a panel-host or
remote reboot, an uninstall) is TRAPPED for the whole run, so a guard that regresses fails its
check instead of doing the thing on your hosts. Use it as a regression guard after auth changes.

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
    """Every row this run leaves on a configured install, found by name.

    It is what the final cleanup deletes. A fixture named from `tag` is in here BY CONSTRUCTION,
    so a block that raises halfway through still leaves nothing in the operator's panel. One named
    any other way is not: the invite block's deactivated SUPERADMIN and its "pre-existing" invite
    were named "inv_<hex>", deleted only on the success path, and left behind by any exception.
    Needs an app context.
    """
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


# ── Traps: nothing this suite drives may DO the privileged thing it probes ────────────────────────
# The refusal under test used to be the only thing between a probe and the action. A regressed
# guard would have bootstrapped (apt full-upgrade, sshd rewrite, reboot) or rebooted the panel's
# own host, or rebooted a real remote — and the "a REMOTE host is not refused" control ran its
# action for real on every run: `apt-get install curl`, then the upstream Tailscale installer piped
# into a root shell, on the first real remote of the configured install this is documented to run
# against. Each of those is a recorder for the whole run instead, bound where the route looks it
# up, and the checks below assert which ones were (and were not) reached.
import panel.routes.remote_bootstrap as _rb_mod  # noqa: E402
import panel.routes.remote_tailscale as _rts_mod  # noqa: E402
import panel.routes.remote_vps as _rvps_mod  # noqa: E402
from panel.ops import system_ops as _so_mod  # noqa: E402
_trapped = []


def _trap(name, ret):
    def _trapped_call(*a, **k):
        _trapped.append(name)
        return ret
    return _trapped_call


_TRAPS = ((_rts_mod, "remote_install_tailscale", (False, "trapped by rbac_test", "")),
          (_rts_mod, "remote_bootstrap_tailscale", (False, "trapped by rbac_test", "")),
          (_rts_mod, "remote_tailscale_up_url", (False, "trapped by rbac_test")),
          (_rb_mod, "_begin_bootstrap", (False, "trapped by rbac_test")),
          (_so_mod, "server_reboot", (False, "trapped by rbac_test")),
          (_rvps_mod, "remote_reboot", (False, "trapped by rbac_test")))
_traps_saved = [(_m, _n, getattr(_m, _n)) for _m, _n, _r in _TRAPS]
for _m, _n, _r in _TRAPS:
    setattr(_m, _n, _trap(_n, _r))
# ...and the install job's worker thread, which retry-install starts: a bare
# `threading.Thread(target=_run)` in manage_servers, so it is captured through that module's
# `threading` and never started. Unstubbed, the Retry probe below ran a real install of `bsserver`
# (useradd, LinuxGSM, apt) on the first host of the install this is run against.
import threading as _thr_rb  # noqa: E402
import panel.routes.manage_servers as _ms_rb  # noqa: E402


class _TrappedThread:
    def __init__(self, target=None, **kw):
        self.target = target
        _trapped.append("install job")

    def start(self):
        """Trapped: never run."""


class _ThreadingTrap:
    Thread = _TrappedThread

    def __getattr__(self, name):
        return getattr(_thr_rb, name)


_ms_threading_saved = _ms_rb.threading
_ms_rb.threading = _ThreadingTrap()


def _specs_as_installer_and_as_manager():
    """The /specs answers, with the host's specs stubbed, for each of the two users."""
    _sp_rv.host_specs = lambda r, force=False: {"os": "Ubuntu 22.04", "kernel": "6.8.0-rbac",
                                                "hostname": "rbac-host"}
    _sp_hosts.host_os_slug = lambda r: "ubuntu-22.04"
    _spr = client_as(_spu_id).get("/api/remote/%d/specs" % granted_remote)
    check("specs: an INSTALL_SERVER user gets the host's OS for the install picker",
          _spr.status_code == 200 and (_spr.get_json() or {}).get("os_slug") == "ubuntu-22.04",
          "got %d %s" % (_spr.status_code, _spr.get_data(as_text=True)[:80]))
    check("specs: ...and nothing of the hardware card",
          set((_spr.get_json() or {"x": 1}).keys()) == {"os_slug"},
          "keys %r" % sorted((_spr.get_json() or {}).keys()))
    _spmr = client_as(_spmu_id).get("/api/remote/%d/specs" % granted_remote)
    check("specs: ...while MANAGE_REMOTES still gets the full specs",
          _spmr.status_code == 200 and (_spmr.get_json() or {}).get("kernel") == "6.8.0-rbac"
          and (_spmr.get_json() or {}).get("os_slug") == "ubuntu-22.04",
          "got %d %s" % (_spmr.status_code, _spmr.get_data(as_text=True)[:80]))


def _redirect_chain_from_the_console():
    """Follow the redirects from the console of the failed install; the chain must end."""
    global _, _chain2, _loc, _path, _r
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


def _redirect_chain_from_files_and_config():
    """...and from its Files & Config page, the other end of the same loop."""
    global _, _loc, _path, _r
    for _ in range(12):
        _r = c.get(_path)
        _chain2.append("%s -> %s" % (_path, _r.status_code))
        if _r.status_code not in (301, 302, 303, 307, 308):
            break
        _loc = _r.headers.get("Location") or ""
        _path = _loc.split("localhost", 1)[-1] if _loc.startswith("http") else _loc
    check("failed install + no MANAGE_SERVERS: ...and from the Files & Config side too",
          len(_chain2) < 12 and _chain2[-1].endswith("200"), " | ".join(_chain2[:6]))


def _tag_list_as_caller_and_superadmin():
    """The tag list's server ids, for the caller and for a superadmin."""
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


def _tag_list_counts_for_a_scoped_admin():
    """The tag list's server counts, for a scoped admin who may delete it and one who may not."""
    # A MANAGE_SERVERS holder scoped to one host can DELETE the tag, which strips it from
    # every server panel-wide — so the count they are shown is every server's. The Tags
    # card printed the length of the filtered ids: "0 server(s)" on a tag other hosts'
    # servers carry, one click from removing it (and its alert muting) from all of them.
    _tr_ci = next((t for t in (_ci.get("/api/tags").get_json() or {})["tags"]
                   if t["id"] == _tr_id), None)
    check("tag list: a scoped admin who can delete a tag is told how many servers carry it",
          _tr_ci is not None and _tr_ci.get("server_count") == 2
          and _tr_ci.get("server_ids") == [accessible_id], "got %r" % (_tr_ci,))
    _tr_c = next((t for t in (c.get("/api/tags").get_json() or {})["tags"]
                  if t["id"] == _tr_id), None)
    check("tag list: ...while a caller who cannot delete it gets only their own count",
          _tr_c is not None and _tr_c.get("server_count") == 1, "got %r" % (_tr_c,))


def _check_tag_list_names_only_reachable():
    """The tag list names only the servers the caller can access (with a second server)."""
    global _tr_id
    from panel.db.models import ServerTag as _TagR
    with app.app_context():
        _tr = _TagR(name=tag + "tagleak")
        _tr.servers.extend([db.session.get(GameServer, accessible_id),
                            db.session.get(GameServer, other_id)])
        db.session.add(_tr)
        db.session.commit()
        _tr_id = _tr.id
    try:
        _tag_list_as_caller_and_superadmin()
        _tag_list_counts_for_a_scoped_admin()
    finally:
        with app.app_context():
            db.session.delete(db.session.get(_TagR, _tr_id))
            db.session.commit()


def _tailscale_page_as_scoped_admin():
    """The /tailscale page as the scoped admin, with the panel host's Tailscale state stubbed."""
    global _rts_admin
    _rts.get_tailscale_info = lambda force_refresh=False: _rts_info
    _rts_page = cmr.get("/tailscale")
    _rts_html = _rts_page.get_data(as_text=True)
    check("tailscale page: a scoped MANAGE_REMOTES admin can still open it (200)",
          _rts_page.status_code == 200, "got %d" % _rts_page.status_code)
    check("tailscale page: ...but is shown none of the PANEL HOST's tailnet inventory",
          not [x for x in _rts_leaks if x in _rts_html],
          repr([x for x in _rts_leaks if x in _rts_html]))
    _rts_api = _rts_json.dumps(cmr.get("/api/tailscale").get_json() or {})
    check("/api/tailscale: ...nor does its JSON carry it",
          not [x for x in _rts_leaks if x in _rts_api], repr([x for x in _rts_leaks if x in _rts_api]))
    _rts_admin = client_as(admin_id).get("/tailscale").get_data(as_text=True)


def _tailscale_page_as_superadmin():
    """...and as a superadmin, who still sees all of it."""
    check("tailscale page: a superadmin still sees all of it (control)",
          all(x in _rts_admin for x in _rts_leaks),
          repr([x for x in _rts_leaks if x not in _rts_admin]))


def _view_logs_as_viewer_and_superadmin():
    """Read the log page as the scoped viewer and as a superadmin."""
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


def _check_view_logs_with_a_second_host():
    """Plant audit rows about two hosts, read them as a scoped viewer and a superadmin."""
    global _lt, _lv_id, _row
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
        # The server rows carry the server's id, as log_action records it from server=; audit_scope
        # reads that, never the target's name (the rows' names below are what a name match used).
        for _uid_, _who, _act, _tgt, _det, _ip, _gsid in (
                (admin_id, "admin", "send_command", _mine_name, _lt + "_mine_srv", "198.51.100.1",
                 accessible_id),
                (admin_id, "admin", "send_command", _other_name,
                 _lt + "_other_srv rcon_password S3cret", "198.51.100.5", other_id),
                (None, tag + "Sup3rSecretPw", "login_failed", "", _lt + "_failed", "198.51.100.2",
                 None),
                (admin_id, "admin", "login", "", _lt + "_adminlogin", "198.51.100.3", None),
                # An ACCOUNT row whose free-text target happens to name their server (an
                # invite's note is whatever the minter typed): still not theirs to read.
                (admin_id, "admin", "invite_created", _mine_name, _lt + "_invite",
                 "198.51.100.6", None),
                (_lv_id, tag + "_logviewer", "logout", "", _lt + "_own", "198.51.100.4", None)):
            db.session.add(_AL(user_id=_uid_, username=_who, action=_act, target=_tgt,
                               detail=_det, ip_address=_ip, success=True,
                               timestamp=_al_now(), game_server_id=_gsid))
        db.session.commit()
    try:
        _view_logs_as_viewer_and_superadmin()
    finally:
        with app.app_context():
            for _row in _AL.query.filter(_AL.detail.like(_lt + "%")).all():
                db.session.delete(_row)
            db.session.commit()


def _invite_happy_path_and_replays():
    """An invite redeems once; replaying or racing it is refused."""
    global _anmod, _pw_real, _r2
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


def _invite_revoked_during_the_race():
    """An invite revoked while its redemption is in flight is refused."""
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


def _invite_accept_with_form_hook(tok, username, hook):
    """Redeem `tok` with `hook()` run where the route first reads the form, then the real read."""
    _form_real = _anmod._invite_form

    def _hooked():
        hook()
        return _form_real()

    _anmod._invite_form = _hooked
    try:
        return _accept(tok, username)
    finally:
        _anmod._invite_form = _form_real


def _invite_minter_demoted_mid_request():
    """A superadmin invite whose minter is demoted while the body is in flight creates nothing."""
    # Aikido 745379189. The authority checks run BEFORE the form is read, and a Bearer-headed
    # request skips csrf.protect(), which is what otherwise reads the body in before_request. So
    # the body is first read in _invite_form(), after authority_intact said yes — and under
    # eventlet a client can withhold it for as long as it likes while the minter is demoted and
    # deactivated. The claim then went through on the stale creator the session had loaded, and
    # an ACTIVE SUPERADMIN account appeared after its minter's offboarding. The hook stands in
    # for the held body: it demotes the minter where the real request would be waiting.
    with app.app_context():
        _tsa = User(username=_inv_tag + "_tsa", display_name="throwaway minter",
                    password_hash=auth.hash_password(secrets.token_hex(16)),
                    is_superadmin=True, is_active=True)
        db.session.add(_tsa)
        db.session.commit()
        _tsa_id = _tsa.id

    def _minted_by_tsa():
        with app.app_context():
            _i, _t = _Inv.mint(db.session.get(User, _tsa_id), superadmin=True)
            db.session.add(_i)
            db.session.commit()
            return _i.id, _t

    def _demote():
        with app.app_context():
            _c = db.session.get(User, _tsa_id)
            _c.is_superadmin, _c.is_active = False, False
            db.session.commit()

    # Control: the same hook shape with nothing changed still redeems, so the refusal below is
    # the demotion's doing and not the hook's.
    _, _tok_ok = _minted_by_tsa()
    _invite_accept_with_form_hook(_tok_ok, _inv_tag + "_midok", lambda: None)
    check("invite route: (control) a superadmin invite redeems through the form hook",
          getattr(_user(_inv_tag + "_midok"), "is_superadmin", None) is True,
          "the control failed — the refusal below proves nothing")
    _, _tok_mid = _minted_by_tsa()
    _r_mid = _invite_accept_with_form_hook(_tok_mid, _inv_tag + "_midsa", _demote)
    with app.app_context():
        _c = db.session.get(User, _tsa_id)
        _demoted = _c is not None and not _c.is_superadmin and not _c.is_active
    check("invite route: (premise) the minter really was demoted mid-request", _demoted,
          "the window never opened")
    check("invite route: a minter demoted while the body is in flight mints no superadmin",
          _user(_inv_tag + "_midsa") is None,
          "an active superadmin account was created after its minter lost the rank (status %s)"
          % _r_mid.status_code)


def _invite_expired_mid_request():
    """An invite that expires while its body is in flight creates nothing."""
    # The claim's WHERE asked about used_at and revoked_at and not the expiry, so the same held
    # body outlived the invite's TTL too.
    _iid_e, _tok_e = _mint(_sa)

    def _expire():
        with app.app_context():
            db.session.get(_Inv, _iid_e).expires_at = _inv_utcnow() - _inv_timedelta(minutes=1)
            db.session.commit()

    _r_e = _invite_accept_with_form_hook(_tok_e, _inv_tag + "_midexp", _expire)
    check("invite route: an invite that expires mid-request creates no account",
          _user(_inv_tag + "_midexp") is None,
          "the claim does not ask about expires_at (status %s)" % _r_e.status_code)


def _invite_superadmin_from_a_demoted_minter():
    """A superadmin-granting invite from a since-demoted minter is refused."""
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


def _invite_group_from_a_demoted_minter():
    """A GROUP grant from a since-demoted minter is refused."""
    global _groups_of, _grp_ok
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


def _invite_host_outside_the_minters_reach():
    """A group reaching a host outside the minter's reach is refused."""
    global _host_gid
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


def _invite_host_inside_the_minters_reach():
    """...while the same host, once inside the minter's reach, is accepted."""
    global _host_ok, _sa_row
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


def _invite_custom_command_axis():
    """A group holding a custom command the minter cannot run is refused."""
    global _cmd_ok, _sa_row
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


def _invite_deactivated_expired_and_guessed():
    """A deactivated minter's invite is refused; an expired and a guessed token look alike."""
    global _dl, _sa_row, _x
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
    _diff = [_ln for _ln in _dl.unified_diff(_d_exp.split("\n"), _d_bog.split("\n"),
                                             lineterm="", n=0)
             if _ln[:1] in "+-" and _ln[:3] not in ("---", "+++")]
    check("invite route: ...and a guessed token is refused the SAME way, telling it nothing",
          _r_bogus.status_code == _r_exp.status_code and _d_bog == _d_exp,
          "status %s vs %s; differing lines: %s"
          % (_r_exp.status_code, _r_bogus.status_code, " || ".join(_diff[:4])[:400]))


def _invite_cleanup_rows():
    """Delete the invite users, invites and groups, and restore the borrowed superadmin."""
    global _ICC_rm, _g, _n, _row, _sa_row, _u
    for _n in ("_ok", "_twice", "_demoted", "_inactive", "_exp", "_race", "_revoked",
               "_grp", "_grp_ok", "_host", "_host_ok", "_cmd", "_cmd_ok", "_midok", "_midsa",
               "_midexp", "_tsa"):
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


def _invite_cleanup_commands():
    """Delete this run's invite custom commands."""
    global _c
    for _c in _ICC_rm.query.filter(_ICC_rm.name.like(_inv_tag + "%")).all():
        db.session.delete(_c)
    db.session.commit()


def _invite_cleanup():
    """Remove this run's invite users, invites, groups and commands; restore the superadmin."""
    with app.app_context():
        _invite_cleanup_rows()
        _invite_cleanup_commands()


def _check_limited_user_denied_pages():
    """A limited user (VIEW_SERVERS + VIEW_CONSOLE, one remote) is denied the admin pages."""
    global c, code, p
    # ── Limited user (VIEW_SERVERS + VIEW_CONSOLE, access to ONE remote) ──
    c = client_as(uid)
    for p in ["/users", "/groups", "/logs", "/remotes", "/server-management",
              "/tailscale", "/api/tailscale", "/settings", "/notifications",
              "/api/remote/%d/specs" % granted_remote, "/api/panel/update-status"]:
        code = c.get(p).status_code
        check("limited user DENIED %s" % p, code != 200, "got %d" % code)


def _check_specs_os_slug_for_installers():
    """/specs gives an INSTALL_SERVER user the OS slug, and only MANAGE_REMOTES the hardware."""
    global _obj, _sp_hosts, _sp_rv, _spmu_id, _spu_id
    # ── the install picker's OS filter must answer the people who install ──────────────────────
    # /specs was MANAGE_REMOTES only, but its os_slug is what manage_servers.js greys out games
    # with, on a page for INSTALL_SERVER / MANAGE_SERVERS. They got 403, the filter read "OS unknown"
    # and left every game selectable. They now get os_slug — and ONLY os_slug: the hardware card
    # (kernel, hostname, CPU, disk) stays with MANAGE_REMOTES.
    _sp_rv = _rvps_mod                   # panel.routes.remote_vps, imported once above
    import panel.ops.ssh_manager.hosts as _sp_hosts
    _sp_saved = (_sp_rv.host_specs, _sp_hosts.host_os_slug)
    with app.app_context():
        _spg = Group(name=tag + "_sp", description="RBAC test INSTALL_SERVER (auto)", is_default=False)
        _spg.set_permissions([auth.VIEW_SERVERS, auth.INSTALL_SERVER])      # NOT manage_remotes
        _spg.servers.append(RemoteServer.query.get(granted_remote))
        _spm = Group(name=tag + "_spm", description="RBAC test MANAGE_REMOTES (auto)", is_default=False)
        _spm.set_permissions([auth.VIEW_SERVERS, auth.MANAGE_REMOTES])
        _spm.servers.append(RemoteServer.query.get(granted_remote))
        db.session.add_all([_spg, _spm]); db.session.flush()
        _spu = User(username=tag + "_sp", password_hash=auth.hash_password(secrets.token_hex(16)),
                    display_name=tag + "_sp", is_superadmin=False, is_active=True)
        _spu.groups.append(_spg)
        _spmu = User(username=tag + "_spm", password_hash=auth.hash_password(secrets.token_hex(16)),
                     display_name=tag + "_spm", is_superadmin=False, is_active=True)
        _spmu.groups.append(_spm)
        db.session.add_all([_spu, _spmu])
        db.session.commit()
        _spu_id, _spmu_id = _spu.id, _spmu.id
    try:
        _specs_as_installer_and_as_manager()
    finally:
        _sp_rv.host_specs, _sp_hosts.host_os_slug = _sp_saved
        with app.app_context():
            for _obj in (db.session.get(User, _spu_id), db.session.get(User, _spmu_id)):
                if _obj is not None:
                    db.session.delete(_obj)
            db.session.commit()


def _check_failed_install_redirects_terminate():
    """A failed install seen without MANAGE_SERVERS: the redirect chain ends on a page."""
    global _loopfail_id, _row
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
        _redirect_chain_from_the_console()
        _redirect_chain_from_files_and_config()
    finally:
        with app.app_context():
            _row = db.session.get(GameServer, _loopfail_id)
            if _row is not None:
                db.session.delete(_row)
                db.session.commit()


def _check_uninstall_lands_on_openable_page():
    """A successful uninstall redirects to a page the uninstaller can open."""
    global _obj
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
    # The route now takes its 409 exit only for a LIVE job (an _install_jobs entry), not for the
    # row's status — so with none, this "no SSH at all" probe ran the real uninstall on the install's
    # first host (pkill -u, userdel -r -f). A live entry is seeded, and the host side is trapped so a
    # probe that stops taking that exit fails below instead of reaching a host.
    import time as _un_time
    from panel.core.panel_state import _install_jobs as _un_jobs, _install_lock as _un_lock
    with _un_lock:
        _un_jobs[_ugs_id] = {"status": "running", "step": 0, "total": 8, "step_name": "Queued",
                             "message": "", "log": [], "started": _un_time.time(),
                             "updated": _un_time.time(), "name": "rbac-uninstall"}
    _un_exec = (_sm_core.run_privileged, _sm_core.run_as_game_user, _sm_core.run_command)
    _un_trapped_at = len(_trapped)
    try:
        _sm_core.run_privileged = _sm_core.run_as_game_user = _sm_core.run_command = (
            lambda *a, **k: (_trapped.append("uninstall"), ("", "trapped by rbac_test", 1))[1])
        _uc = client_as(_uu_id)
        # The 409 "still installing" exit is the one an uninstall-only user can reach without any
        # SSH at all, and it takes the same redirect as the success path.
        _ur = _uc.post("/servers/%d/delete" % _ugs_id, follow_redirects=True)
        _utext = _ur.get_data(as_text=True)
        check("uninstall-only user: the page they land on is one they may open",
              "do not have permission" not in _utext.lower(), "landed on a refusal")
        check("uninstall-only user: ...and it actually rendered", _ur.status_code == 200,
              "got %d" % _ur.status_code)
        check("uninstall-only user: ...through the still-installing exit, reaching no host",
              not _trapped[_un_trapped_at:], "reached: %r" % (_trapped[_un_trapped_at:],))
    finally:
        _sm_core.run_privileged, _sm_core.run_as_game_user, _sm_core.run_command = _un_exec
        with _un_lock:
            _un_jobs.pop(_ugs_id, None)
        with app.app_context():
            for _obj in (db.session.get(GameServer, _ugs_id), db.session.get(User, _uu_id)):
                if _obj is not None:
                    db.session.delete(_obj)
            db.session.commit()


def _check_retry_install_matches_its_route():
    """The Retry install button and the route it posts to agree about who may press it."""
    global _r
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
        check("MANAGE_SERVERS: ...starting the install job, which is trapped and never run",
              _trapped.count("install job") == 1, "trapped: %r" % (_trapped,))
    finally:
        with app.app_context():
            _r = db.session.get(GameServer, _rt_id)
            if _r is not None:
                db.session.delete(_r)
            _u2 = db.session.get(User, _msu_id)
            if _u2 is not None:
                db.session.delete(_u2)
            db.session.commit()


def _check_vps_prep_refuses_panel_host():
    """The VPS-preparation routes refuse the panel's OWN host."""
    global _ac, _label, _local_id, _local_made, _path, _r, _rem_id, _trapped_at
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
    _trapped_at = len(_trapped)
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
    check("...and none of those four reached the action on the panel's own host",
          not _trapped[_trapped_at:], "reached: %r" % (_trapped[_trapped_at:],))


def _check_tailscale_migrate_refuses_panel_host():
    """Tailscale migrate/finalize refuse the panel's own host, and still run for a remote one."""
    # migrate rewrites a host record onto Tailscale SSH and then deletes its public 22/tcp rule;
    # finalize opens tailscale0 in its firewall. Both are for a REMOTE that just joined the
    # tailnet, and they were the two Tailscale routes here without the host-kind check the other
    # three carry — so the panel host's own firewall was one request away. The actions are
    # stubbed to SUCCEED: unstubbed they fail on their own ("local" is not an SSH user), and a
    # bare "400" would then pass on today's code as easily as on the fixed one.
    _calls = []
    _saved = (_rts_mod.remote_migrate_to_tailscale, _rts_mod.remote_tailscale_finalize,
              _rts_mod.close_connection)
    _rts_mod.remote_migrate_to_tailscale = lambda r: (
        _calls.append(("migrate", r.id)) or ("100.64.0.9", {"tailscale_ip": "100.64.0.9"}))
    _rts_mod.remote_tailscale_finalize = lambda r: (
        _calls.append(("finalize", r.id)) or ({"running": True}, "tailscale0 allowed"))
    _rts_mod.close_connection = lambda r: None
    with app.app_context():
        _loc = RemoteServer.query.filter_by(is_local=True).first()
        _made_local = _loc is None
        if _made_local:
            _loc = RemoteServer(name="rbac-ts-local", host="127.0.0.1", port=22, username="local",
                                auth_method="local", auth_credential="", is_local=True)
            db.session.add(_loc)
        _probe = RemoteServer(name="rbac-ts-migrate-probe", host="192.0.2.77", port=2222,
                              username="root", auth_method="key", auth_credential="")
        db.session.add(_probe)
        db.session.commit()
        _loc_id, _probe_id = _loc.id, _probe.id
        _loc_before = (_loc.host, _loc.auth_method, _loc.port)
    try:
        _cl = client_as(admin_id)
        for _ep, _what in (("tailscale-migrate", "Tailscale migration"),
                           ("tailscale-finalize", "Tailscale finalize")):
            _rr = _cl.post("/api/remote/%d/%s" % (_loc_id, _ep), json={})
            _msg = (_rr.get_json(silent=True) or {}).get("message") or ""
            check("%s is REFUSED on the panel's own host" % _what,
                  _rr.status_code == 400 and "panel's own host" in _msg and _what in _msg,
                  "%d %s" % (_rr.status_code, _msg[:120]))
            check("%s's refusal does not claim it would reboot the panel" % _what,
                  "reboot the panel" not in _msg, _msg[:160])
        check("...and neither reached the action on the panel's own host",
              not [c for c in _calls if c[1] == _loc_id], repr(_calls))
        with app.app_context():
            _l = db.session.get(RemoteServer, _loc_id)
            check("...and the panel host's row is unchanged",
                  (_l.host, _l.auth_method, _l.port) == _loc_before,
                  repr((_l.host, _l.auth_method, _l.port)))
        # A REMOTE host still gets both — refusing everything would pass the checks above.
        _rr = _cl.post("/api/remote/%d/tailscale-migrate" % _probe_id, json={})
        _rf = _cl.post("/api/remote/%d/tailscale-finalize" % _probe_id, json={})
        check("a REMOTE host still migrates and finalizes (positive control)",
              _rr.status_code == 200 and _rf.status_code == 200
              and _calls == [("migrate", _probe_id), ("finalize", _probe_id)],
              "%d/%d %r" % (_rr.status_code, _rf.status_code, _calls))
    finally:
        (_rts_mod.remote_migrate_to_tailscale, _rts_mod.remote_tailscale_finalize,
         _rts_mod.close_connection) = _saved
        with app.app_context():
            for _rid in ([_probe_id] + ([_loc_id] if _made_local else [])):
                _row = db.session.get(RemoteServer, _rid)
                if _row is not None:
                    db.session.delete(_row)
            db.session.commit()


def _check_vps_prep_allows_a_remote_host():
    """...but not a remote host: refusing everything would pass the checks above too."""
    global _ci, _r2
    # A remote host must NOT be refused by that guard — refusing everything is the easy way to make
    # the assertions above pass for the wrong reason.
    if _rem_id is not None:
        _r2 = _ac.post("/api/remote/%d/tailscale-install" % _rem_id)
        check("a REMOTE host is not refused by that guard",
              b"panel's own host" not in _r2.data, "%d %s" % (_r2.status_code, _r2.data[:80]))
        check("...it reaches the install, which is trapped here and never run",
              _trapped[_trapped_at:] == ["remote_install_tailscale"],
              "reached: %r" % (_trapped[_trapped_at:],))
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
        # Probed as a user who HOLDS the action's permission (and MANAGE_SERVERS, for the tag
        # probe below) on the granted host only. As `c`, who holds neither, the route answered 403
        # "Permission denied" whatever the server-access result, so the check could not fail on
        # the cross-host regression it is named for. The payloads are invalid ON PURPOSE: the
        # access decorator runs first, so a refused server is a 403, and a server that got past
        # it is a 400 for the payload — nothing starts and nothing is written on either branch.
        # The same request on the accessible server is the control that the 400 is reachable.
        with app.app_context():
            _ig = Group(name=tag + "_idor", description="RBAC IDOR (auto)", is_default=False)
            _ig.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER, auth.MANAGE_SERVERS])
            _ig.servers.append(RemoteServer.query.get(granted_remote))
            db.session.add(_ig)
            db.session.flush()
            _iu = User(username=tag + "_idor", password_hash=auth.hash_password(secrets.token_hex(16)),
                       display_name=tag + "_idor", is_superadmin=False, is_active=True)
            _iu.groups.append(_ig)
            db.session.add(_iu)
            db.session.commit()
            _idor_uid = _iu.id
        _ci = client_as(_idor_uid)
        _ia = _ci.post("/api/server/%d/action" % other_id, json={"action": "not-an-action"})
        check("IDOR: action on non-granted server BLOCKED (for a START_SERVER holder)",
              _ia.status_code == 403, "got %d" % _ia.status_code)
        _ia = _ci.post("/api/server/%d/action" % accessible_id, json={"action": "not-an-action"})
        check("IDOR: ...while the same request on the granted server gets past access (control)",
              _ia.status_code == 400, "got %d" % _ia.status_code)
        _it = _ci.post("/api/server/%d/tags" % other_id, json={"tag_ids": "not-a-list"})
        check("IDOR: assigning tags on a non-granted server BLOCKED (for a MANAGE_SERVERS holder)",
              _it.status_code == 403, "got %d" % _it.status_code)
        _it = _ci.post("/api/server/%d/tags" % accessible_id, json={"tag_ids": "not-a-list"})
        check("IDOR: ...while tagging the granted server gets past access (control)",
              _it.status_code == 400, "got %d" % _it.status_code)


def _check_limited_user_server_actions():
    """The limited user's server actions and file/cron/tag writes are refused; tag reads scoped."""
    global _dl
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
    # (The cross-host tag probe is with the other IDOR probes above, as a MANAGE_SERVERS holder.)
    # Reading the tag list is deliberately open to any signed-in user: it is what decorates and
    # filters rows they can already see.
    check("tag list is readable without MANAGE_SERVERS -> 200",
          c.get("/api/tags").status_code == 200)
    # ...but it names only the servers the caller can access. It listed every server's id under
    # every tag: an inventory of what they cannot open, and what it is tagged with.
    if other_id:
        _check_tag_list_names_only_reachable()


def _check_legacy_super_admin_grant():
    """A legacy "super_admin" group grant confers nothing."""
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


def _check_denials_and_limited_pages():
    """Denials read right for any caller; pages render for the limited user; hosts are per host."""
    global cmr
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
    # These post an UNINSTALL of a real server of the install (accessible_id), refused only by the
    # permission guard under test. The host side of the uninstall is trapped around them — every
    # exec primitive answers a failure, so a regressed guard fails the check below and keeps the
    # row (the route deletes it only on rc 0) instead of removing the server.
    _o_exec = (_sm_core.run_privileged, _sm_core.run_as_game_user, _sm_core.run_command)
    _sm_core.run_privileged = _sm_core.run_as_game_user = _sm_core.run_command = (
        lambda *a, **k: (_trapped.append("uninstall"), ("", "trapped by rbac_test", 1))[1])
    try:
        _fetch_denied = c.post("/servers/%d/delete" % accessible_id,
                               headers={"X-Requested-With": "XMLHttpRequest"})
        _browser_denied = c.post("/servers/%d/delete" % accessible_id,
                                 headers={"Accept": "text/html"})
    finally:
        _sm_core.run_privileged, _sm_core.run_as_game_user, _sm_core.run_command = _o_exec
    check("denial (in-page fetch): JSON, so it cannot be mistaken for success",
          _fetch_denied.status_code == 403
          and (_fetch_denied.get_json() or {}).get("success") is False,
          "status=%d" % _fetch_denied.status_code)
    check("denial (browser form): still a redirect, not JSON",
          _browser_denied.status_code in (301, 302, 303),
          "got %d" % _browser_denied.status_code)


    check("view console WITH VIEW_CONSOLE + access -> 200",
          c.get("/api/console/%d" % accessible_id).status_code == 200)

    # Pages must actually RENDER for a non-superadmin (regression: a template calling a
    # context-processor helper with the wrong arity 500'd only for limited users).
    check("dashboard (/) renders for limited user -> 200", c.get("/").status_code == 200)
    # ...and offers Uninstall only to someone the route above would let use it. Rendering it for
    # everyone left every suite green when index was split (the flag is _install_controls' now):
    # the button 403s, so nothing was ever removed, but it is still an offer the POST refuses.
    # The superadmin's page is the positive control: the same row, with the form.
    _un_action = 'action="/servers/%d/delete"' % accessible_id
    check("dashboard: no Uninstall form for a viewer without UNINSTALL_SERVER",
          _un_action not in c.get("/").get_data(as_text=True))
    check("dashboard: ...while the superadmin's page has it for the same server",
          _un_action in client_as(admin_id).get("/").get_data(as_text=True),
          "the form is not rendered for anyone, so the check above proves nothing")

    # Remote management is scoped PER HOST: MANAGE_REMOTES lets you manage remotes,
    # but only the ones your groups grant — not any remote by id (remote-level IDOR).
    cmr = client_as(uid2)
    check("MANAGE_REMOTES user can open /remotes -> 200", cmr.get("/remotes").status_code == 200)


def _check_tailscale_page_is_host_scoped():
    """/tailscale shows a per-host MANAGE_REMOTES admin nothing about the panel host."""
    global _rts, _rts_info, _rts_json, _rts_leaks, ids, r
    # /tailscale is gated on MANAGE_REMOTES, which is granted PER HOST — this user holds it for one
    # remote. The page reported on the PANEL HOST instead: its tailnet name and IPs, its Serve
    # mappings with their backends, and every peer on the operator's tailnet (personal devices
    # included) with address, OS and last-seen. None of that is a host this user was granted.
    import json as _rts_json
    import panel.ops.tailscale_integration as _rts
    _rts_saved = _rts.get_tailscale_info
    _rts_info = _rts.TailscaleInfo(
        installed=True, running=True, backend_state="Running", hostname="gamepanel",
        dns_name="gamepanel.tail1234.ts.net", tailscale_ips=["100.101.102.103"],
        serve_config={"services": [{"url": "https://gamepanel.tail1234.ts.net", "funnel": False,
                                    "routes": [{"mount": "/", "target": "http://127.0.0.1:3999"}]}],
                      "raw": "x"},
        peers=[{"id": "p1", "hostname": "alice-iphone", "dns_name": "alice-iphone.tail1234.ts.net",
                "ips": ["100.64.7.7"], "os": "iOS", "online": True, "last_seen": "", "relay": ""}])
    _rts_leaks = ("alice-iphone", "100.64.7.7", "100.101.102.103", "gamepanel.tail1234.ts.net",
                  "127.0.0.1:3999")
    try:
        _tailscale_page_as_scoped_admin()
        _tailscale_page_as_superadmin()
    finally:
        _rts.get_tailscale_info = _rts_saved
        _rts._cache["info"] = None
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


def _check_unauthenticated():
    """An unauthenticated client is refused, and /setup cannot mint a superadmin after setup."""
    global r
    # ── Unauthenticated ──
    cu = client_as(None)
    check("unauth GET / -> redirect to login", cu.get("/").status_code == 302)
    check("unauth GET /users -> redirect", cu.get("/users").status_code == 302)
    check("unauth GET /api/servers -> not 200", cu.get("/api/servers").status_code != 200)

    # CRITICAL: /setup POST must NOT create a superadmin once setup is complete.
    pwn = "pwned_" + tag
    r = cu.post("/setup", data={"step": "admin_user", "username": pwn,
                                "password": "hackme123", "confirm_password": "hackme123"})  # nosec B105 - posted by an anonymous probe that must be refused
    with app.app_context():
        created = User.query.filter_by(username=pwn).first()
        was_created = created is not None
        if created:
            db.session.delete(created)
            db.session.commit()
    check("/setup POST CANNOT create a superadmin (unauth)", not was_created,
          "ACCOUNT WAS CREATED (status %d)" % r.status_code if was_created else "blocked")
    check("unauth GET /setup -> redirect", cu.get("/setup").status_code == 302)


def _check_group_admin_cannot_grant_more():
    """A delegated group admin cannot grant a permission they do not hold."""
    global c4
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

    # ...and editing a group must not silently strip a permission they cannot grant. It used to be
    # PRESERVED by _grantable_perms while the rest of the edit went through; a group holding one is
    # now outside the editor's reach, so the whole edit is refused (_may_manage_group) and this
    # asserts the refusal — the description is what shows whether the edit landed at all.
    c4.post("/groups/%d/edit" % gid5, data={"name": tag5, "description": "changed by grpadm",
                                            "permissions": [auth.VIEW_SERVERS]})
    with app.app_context():
        kept = set(Group.query.get(gid5).get_permissions())
        kept_desc = Group.query.get(gid5).description
    check("escalation: an edit of a group holding a permission the editor cannot grant is refused",
          auth.MANAGE_USERS in kept and kept_desc == "RBAC test preserve (auto)",
          "after edit: %s, description %r" % (sorted(kept), kept_desc))


def _check_membership_escalation():
    """...and cannot escalate from the MEMBERSHIP side either."""
    global _mu_gid, _mu_uid, _prize_gid, cmu
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


def _check_superadmin_edit_refused_by_name():
    """A MANAGE_USERS holder editing a superadmin is refused by name, and nothing changes."""
    # A superadmin account is refused BY NAME, before anything else is weighed. The refusal alone
    # proves nothing about this guard: the superadmin-flag and reach checks behind it refuse the
    # same edit in other words, so deleting it left every suite green when edit_user was split
    # (it is _edit_user_refusal's first test now). The message is what only this guard produces.
    with app.app_context():
        _sa_row = db.session.get(User, admin_id)
        _sa_before = (_sa_row.display_name, _sa_row.password_hash, _sa_row.is_superadmin)
    _r_sa = cmu.post("/users/%d/edit" % admin_id,
                     data={"display_name": "taken", "is_active": "on", "is_superadmin": "on"},
                     headers={"X-Requested-With": "XMLHttpRequest"})
    with app.app_context():
        _sa_row = db.session.get(User, admin_id)
        _sa_after = (_sa_row.display_name, _sa_row.password_hash, _sa_row.is_superadmin)
    check("escalation: MANAGE_USERS editing a superadmin is refused as exactly that, and nothing changes",
          (_r_sa.get_json(silent=True) or {}).get("message")
          == "Only a superadmin can modify a superadmin account." and _sa_after == _sa_before,
          repr((_r_sa.status_code, _r_sa.get_json(silent=True), _sa_after == _sa_before)))


def _check_join_needs_the_hosts_too():
    """...and cannot join a group whose permissions they hold but whose hosts they do not."""
    global _reach, _reach_gid
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


def _check_user_form_offers_only_joinable():
    """...and the /users form offers only the groups the POST will accept."""
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


def _check_manage_users_needs_the_perms():
    """MANAGE_USERS does not reach an account holding permissions the actor lacks."""
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
                             "reset_password": "on", "reset_2fa": "on"})  # nosec B105 - a checkbox value
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
             data={"display_name": "low", "is_active": "on", "reset_password": "on"})  # nosec B105 - a checkbox value
    with app.app_context():
        _low_changed = db.session.get(User, _low_id).password_hash != _low_hash
    check("escalation: ...but MAY still administer an account within their own permissions",
          _low_changed, "a legitimate reset was refused too — the guard is too broad")


def _check_manage_users_needs_the_objects():
    """...nor one reaching hosts or servers the actor cannot."""
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
             data={"display_name": "peer", "is_active": "on", "reset_password": "on"})  # nosec B105 - a checkbox value
    with app.app_context():
        _peer_changed = db.session.get(User, _peer_id).password_hash != _peer_hash
    check("escalation: MANAGE_USERS cannot take over a peer who can reach hosts the actor cannot",
          not _peer_changed, "the peer's password hash was replaced")


def _check_manage_users_custom_commands():
    """...nor one holding custom commands the actor cannot run."""
    global _cmd_peer_hash, _cmd_peer_id, _plain_peer_hash, _plain_peer_id
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
             data={"display_name": "cmd peer", "is_active": "on", "reset_password": "on"})  # nosec B105 - a checkbox value
    cmu.post("/users/%d/edit" % _plain_peer_id,
             data={"display_name": "plain peer", "is_active": "on", "reset_password": "on"})  # nosec B105 - a checkbox value


def _check_custom_command_peers_untouched():
    """...which leaves the refused peers' passwords exactly as they were."""
    with app.app_context():
        _cmd_peer_changed = db.session.get(User, _cmd_peer_id).password_hash != _cmd_peer_hash
        _plain_peer_changed = (db.session.get(User, _plain_peer_id).password_hash
                               != _plain_peer_hash)
    check("escalation: MANAGE_USERS cannot take over a peer whose extra reach is a command",
          not _cmd_peer_changed, "the command holder's password hash was replaced")
    check("escalation: ...but may still reset a peer with the same permissions and no command",
          _plain_peer_changed, "a legitimate reset was refused — the guard is too broad")


def _check_view_logs_scope_and_users_add():
    """VIEW_LOGS shows only what the viewer can reach; /users/add cannot fill the prize group."""
    # ── VIEW_LOGS is scoped to what the viewer can reach ─────────────────────────────────────
    # It was install-wide: a moderator given view_logs with ONE server read every server's console
    # commands (`rcon_password …`), every admin's sign-in address, and the attempted username of
    # every failed login — where people paste their password by mistake.
    if other_id is not None:
        _check_view_logs_with_a_second_host()
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


def _check_group_admin_cannot_widen_reach():
    """A delegated group admin cannot widen a group's host or server reach."""
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


def _check_groups_page_offers_only_grantable():
    """...and the /groups page does not offer them what the POST will refuse."""
    global _gp_html, _unreachable
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


def _check_group_summaries_name_nothing_hidden():
    """...and the group summaries do not name hosts or servers they cannot see."""
    # ...and the group SUMMARIES do not name them either. The tick boxes were filtered for exactly
    # this reason, while each group's summary still printed every host and game server it grants.
    if other_remote and other_id:
        import html as _sg_html
        with app.app_context():
            _sg = Group(name=tag + "_sumleak", description="", is_default=False)
            _sg.servers.append(db.session.get(RemoteServer, granted_remote))
            _sg.servers.append(db.session.get(RemoteServer, other_remote))
            _sg.game_servers.append(db.session.get(GameServer, other_id))
            db.session.add(_sg)
            db.session.commit()
            _sg_id = _sg.id
            _sg_mine = ">%s</span>" % _sg_html.escape(db.session.get(RemoteServer, granted_remote).display_name)
            _sg_host = ">%s</span>" % _sg_html.escape(db.session.get(RemoteServer, other_remote).display_name)
            _sg_game = ">%s</span>" % _sg_html.escape(db.session.get(GameServer, other_id).name)
        try:
            _sg_page = c4.get("/groups").get_data(as_text=True)
            _sg_card = _sg_page[_sg_page.index(tag + "_sumleak"):]
            # Up to the NEXT card: this group is outside the viewer's reach, so it has no edit
            # form to stop at, and the next group's edit form would drag its names in.
            _sg_card = _sg_card[:min(_i for _i in (_sg_card.find('<div class="card mb-3">'),
                                                   _sg_card.find("<!-- /#groups-list -->"),
                                                   len(_sg_card)) if _i >= 0)]
            check("groups page: (control) a group's summary names the host the viewer CAN reach",
                  _sg_mine in _sg_card, "the summary names nothing — the check below is vacuous")
            check("groups page: a group's summary does not name hosts or servers outside the viewer's reach",
                  _sg_host not in _sg_card and _sg_game not in _sg_card,
                  "the summary discloses what the tick boxes were filtered to hide")
            check("groups page: ...and says how many it is not naming, so the reach is not understated",
                  "+2 <span>outside your access</span>" in _sg_card)
        finally:
            with app.app_context():
                db.session.delete(db.session.get(Group, _sg_id))
                db.session.commit()
    # A superadmin still sees everything — the filter is per-viewer, not a blanket narrowing.
    _sa_html = _ac.get("/groups").get_data(as_text=True)
    _sa_missing = [i for i in _unreachable if ('value="%d"' % i) not in _sa_html]
    check("groups page: ...while a superadmin is still offered every host",
          not _sa_missing, "a superadmin is missing host ids %s" % _sa_missing)


def _check_permission_boxes_are_filtered():
    """...and the permission boxes are filtered the same way."""
    # ── ...and the same for the PERMISSION boxes, which were offered unfiltered ────────────────
    # The host and game-server lists were narrowed to what the POST accepts; the permission list
    # beside them still rendered every entry in ALL_PERMISSIONS as an ordinary tick box.
    # _grantable_perms drops a requested permission the actor does not hold and PRESERVES one the
    # group already holds, so the control was inert in both directions — and the un-tick case is
    # the dangerous one: unticking "Open a shell on a host" on a group that holds it answered
    # "Group 'X' updated." and revoked nothing, while every member kept that shell.
    #
    # A group that HOLDS a permission the admin cannot grant is now outside their reach, so it has
    # no edit form at all (_manageable_group_ids) — grp5 holds MANAGE_USERS, which this admin
    # lacks. Its power must still be VISIBLE on the card. The boxes are read off the admin's own
    # group instead, which they may edit: MANAGE_USERS is still a box they cannot tick.
    def _perm_box(html, gid, perm):
        import re as _re
        _m = _re.search(r'<input[^>]*id="perm-%d-%s"[^>]*>' % (gid, perm), html)
        return _m.group(0) if _m else ""

    _pb_locked = _perm_box(_gp_html, gid4_for_scope, auth.MANAGE_USERS)
    _pb_free = _perm_box(_gp_html, gid4_for_scope, auth.VIEW_SERVERS)
    check("groups page: the permission tick boxes are where this check thinks they are",
          bool(_pb_locked) and bool(_pb_free),
          "locked=%r free=%r — the checks below would prove nothing" % (_pb_locked, _pb_free))
    check("groups page: a permission the admin cannot grant is not an ENABLED tick box",
          "disabled" in _pb_locked,
          "offers %r — ticking it would be silently dropped" % _pb_locked)
    # Anchored on the card's own heading: a flash from an earlier POST ("Group '<tag5>' updated.")
    # also names the group, above the list.
    _g5_card = _gp_html[_gp_html.index(">%s</strong>" % tag5):]
    _g5_card = _g5_card[:min(_i for _i in (_g5_card.find('<div class="card mb-3">'),
                                           _g5_card.find("<!-- /#groups-list -->"),
                                           len(_g5_card)) if _i >= 0)]
    check("groups page: a group holding one they cannot grant offers no edit form for it",
          ('id="edit-group-%d"' % gid5) not in _gp_html and not _perm_box(_gp_html, gid5,
                                                                            auth.MANAGE_USERS),
          "the page offers an edit the POST refuses")
    check("groups page: ...but its real power stays visible on the card",
          auth.ALL_PERMISSIONS[auth.MANAGE_USERS] in _g5_card,
          "the card no longer names MANAGE_USERS — the page understates what the group can do")
    check("groups page: a group's permission labels wrap instead of widening the page",
          "badge bg-secondary text-wrap" in _g5_card,
          "use_terminal's label is a sentence; unwrapped it ran 579px wide and scrolled a phone "
          "sideways")
    check("groups page: ...while one they DO hold stays editable (positive control)",
          "disabled" not in _pb_free,
          "every permission box is disabled, so the check above passes for the wrong reason: %r"
          % _pb_free)


def _check_unshowable_server_grant_survives():
    """A per-server grant the form cannot show survives a save by someone who cannot see it."""
    global _ic, _ind_html, _ind_offered, _ind_tid
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


def _check_empty_host_list_wording():
    """An empty host list says none are grantable, not that none are configured."""
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


def _gsx_group(name, perms, hosts=(), commands=()):
    """A fixture group for the group-scope checks, named from `tag`. Needs an app context."""
    _g = Group(name=tag + name, description="orig", is_default=False)
    _g.set_permissions(perms)
    for _h in hosts:
        _g.servers.append(db.session.get(RemoteServer, _h))
    for _c in commands:
        _g.custom_commands.append(_c)
    db.session.add(_g)
    return _g


def _gsx_user(name, groups):
    """A fixture account in `groups`, named from `tag`. Needs an app context."""
    _u = User(username=tag + name, password_hash=auth.hash_password(secrets.token_hex(16)),
              display_name=name, is_superadmin=False, is_active=True)
    _u.groups.extend(groups)
    db.session.add(_u)
    return _u


def _group_scope_fixtures():
    """Two tenants, a delegated admin in one, and the groups the scope checks edit and delete."""
    global _gsx
    from panel.db.models import CustomCommand as _GCC, Invite as _GInv
    with app.app_context():
        _cmd = _GCC(name=tag + "_gsx_cmd", command_template="exec {}", enabled=True)
        db.session.add(_cmd)
        _g = {
            # dana: a tenant-A admin, holding what she could hand out.
            "a_adm": _gsx_group("_gsx_a_adm", [auth.MANAGE_GROUPS, auth.SEND_COMMAND,
                                               auth.USE_TERMINAL, auth.VIEW_SERVERS,
                                               auth.VIEW_CONSOLE], hosts=[granted_remote]),
            "b_view": _gsx_group("_gsx_b_view", [auth.VIEW_SERVERS], hosts=[other_remote]),
            "b_adm": _gsx_group("_gsx_b_adm", [auth.VIEW_SERVERS, auth.SEND_COMMAND],
                                hosts=[other_remote]),
            "b_empty": _gsx_group("_gsx_b_empty", [auth.VIEW_SERVERS], hosts=[other_remote]),
            "a_view": _gsx_group("_gsx_a_view", [auth.VIEW_SERVERS], hosts=[granted_remote]),
            "a_inv": _gsx_group("_gsx_a_inv", []),
            "a_free": _gsx_group("_gsx_a_free", [auth.VIEW_SERVERS], hosts=[granted_remote]),
            "a_del": _gsx_group("_gsx_a_del", [auth.VIEW_SERVERS]),
            "a_mixdel": _gsx_group("_gsx_a_mixdel", [auth.VIEW_SERVERS], hosts=[granted_remote]),
            "cmd": _gsx_group("_gsx_cmdgrp", [auth.VIEW_SERVERS], commands=[_cmd]),
        }
        _u = {"dana": _gsx_user("_gsx_dana", [_g["a_adm"]]),
              "vic": _gsx_user("_gsx_vic", [_g["b_view"]]),
              "vera": _gsx_user("_gsx_vera", [_g["b_adm"]]),
              # mia is in tenant A's viewers AND tenant B's: permissions are flat, so anything
              # added to a_view she holds on hostB too.
              "mia": _gsx_user("_gsx_mia", [_g["a_view"], _g["b_view"], _g["a_mixdel"]]),
              "alice": _gsx_user("_gsx_alice", [_g["a_free"]]),
              "carl": _gsx_user("_gsx_carl", [_g["cmd"]])}
        db.session.flush()
        # A live superadmin invite naming an EMPTY tenant-A group together with a tenant-B one:
        # its future member is someone dana cannot administer either.
        _inv, _ = _GInv.mint(db.session.get(User, admin_id),
                             group_ids=[_g["a_inv"].id, _g["b_view"].id], note=tag + "_gsx_inv")
        db.session.add(_inv)
        # ...while a SUPERADMIN invite naming the editable group beside a tenant-B one blocks
        # nothing: its account holds everything whatever the groups say (the control below).
        _sainv, _ = _GInv.mint(db.session.get(User, admin_id), superadmin=True,
                               group_ids=[_g["a_free"].id, _g["b_view"].id],
                               note=tag + "_gsx_sainv")
        db.session.add(_sainv)
        db.session.commit()
        _gsx = {k: v.id for k, v in _g.items()}
        _gsx.update({k: v.id for k, v in _u.items()})
        _gsx.update(cmd_id=_cmd.id, inv_id=_inv.id, sainv_id=_sainv.id)
        _dflt = Group.query.filter_by(is_default=True).first()
        _gsx["dflt"] = _dflt.id if _dflt is not None else None
        _gsx["dflt_before"] = ((_dflt.name, _dflt.description, _dflt.get_permissions())
                               if _dflt is not None else None)


def _gsx_perms(key):
    """The effective permissions of the fixture account `key`."""
    with app.app_context():
        return auth.get_user_permissions(db.session.get(User, _gsx[key]))


def _gsx_row(key):
    """(name, description, permissions) of the fixture group `key`, or None once it is gone."""
    with app.app_context():
        _g = db.session.get(Group, _gsx[key])
        return None if _g is None else (_g.name, _g.description, sorted(_g.get_permissions()))


def _gsx_edit(client, key, perms, hosts=()):
    """POST an edit of fixture group `key` the way the page submits it."""
    return client.post("/groups/%d/edit" % _gsx[key],
                       data={"name": _gsx_row(key)[0], "description": "changed",
                             "permissions": perms, "servers": [str(h) for h in hosts]})


def _check_group_edit_refusals():
    """A delegated admin cannot edit a group whose members or future members they cannot administer."""
    _dc = client_as(_gsx["dana"])
    _grant = [auth.VIEW_SERVERS, auth.SEND_COMMAND, auth.USE_TERMINAL]
    # 1. A group outside her reach gains use_terminal: vic, a tenant-B viewer, would get a shell on
    #    hostB from an admin who cannot reach hostB.
    _gsx_edit(_dc, "b_view", _grant)
    check("group scope: a delegated admin cannot add a permission to a group outside their reach",
          auth.USE_TERMINAL not in _gsx_perms("vic") and _gsx_row("b_view")[1] == "orig",
          "vic now holds %s; group reads %r" % (sorted(_gsx_perms("vic")), _gsx_row("b_view")))
    # 2. ...nor strip one: permissions=[] would take send_command off tenant B's admins.
    _gsx_edit(_dc, "b_adm", [])
    check("group scope: ...nor strip a permission they hold off a group outside their reach",
          auth.SEND_COMMAND in _gsx_perms("vera"), "vera lost send_command")
    # 2b. An out-of-reach group with NO members: only the group's own reach refuses it.
    _gsx_edit(_dc, "b_empty", _grant)
    check("group scope: ...nor edit an out-of-reach group that has no members yet",
          _gsx_row("b_empty") == (tag + "_gsx_b_empty", "orig", [auth.VIEW_SERVERS]),
          "b_empty now reads %r" % (_gsx_row("b_empty"),))
    # 3. A group WITHIN her reach, whose member also sits in a tenant-B group: permissions are
    #    flat, so mia would hold use_terminal on hostB.
    _gsx_edit(_dc, "a_view", _grant, hosts=[granted_remote])
    check("group scope: ...nor a within-reach group whose member reaches more than they do",
          auth.USE_TERMINAL not in _gsx_perms("mia"),
          "mia holds %s — use_terminal on hostB" % sorted(_gsx_perms("mia")))
    # 5. An EMPTY within-reach group that a live superadmin invite names beside a tenant-B group.
    _gsx_edit(_dc, "a_inv", _grant)
    check("group scope: ...nor an empty group a live invite names beside an out-of-reach group",
          _gsx_row("a_inv")[2] == [],
          "a_inv now holds %s — the invitee would redeem it on hostB" % (_gsx_row("a_inv")[2],))
    with app.app_context():
        from panel.db.models import AuditLog as _GAL
        _refused_rows = _GAL.query.filter_by(user_id=_gsx["dana"], action="edit_group",
                                             success=False).count()
    check("group scope: ...and each refusal is audited", _refused_rows >= 5,
          "%d refused edit_group rows" % _refused_rows)
    # Positive control: a group whose members she can administer still edits.
    _gsx_edit(_dc, "a_free", _grant, hosts=[granted_remote])
    check("group scope: an in-reach group whose members are in reach still edits, a superadmin "
          "invite naming it notwithstanding (control)",
          auth.USE_TERMINAL in _gsx_perms("alice") and _gsx_row("a_free")[1] == "changed",
          "the edit was refused too — the checks above prove nothing (%r)" % (_gsx_row("a_free"),))


def _check_group_edit_default_group():
    """4. The default group, within reach of nearly every admin, with an out-of-reach member."""
    if _gsx["dflt"] is None:
        check("group scope: (premise) the install has a default group", False, "none found")
        return
    with app.app_context():
        _dflt = db.session.get(Group, _gsx["dflt"])
        _dflt.users.append(db.session.get(User, _gsx["vic"]))
        db.session.commit()
        _within = auth._group_within_reach(_dflt, auth._my_group_reach(
            db.session.get(User, _gsx["dana"])))
    check("group scope: (premise) the default group is within the delegated admin's reach",
          _within, "the check below would pass on the group's own reach, not on its members")
    _name, _desc, _perms = _gsx["dflt_before"]
    try:
        client_as(_gsx["dana"]).post("/groups/%d/edit" % _gsx["dflt"], data={
            "name": _name, "description": _desc or "",
            "permissions": sorted(set(_perms) | {auth.USE_TERMINAL, auth.SEND_COMMAND})})
        check("group scope: ...nor the DEFAULT group, which holds every account",
              auth.USE_TERMINAL not in _gsx_perms("vic"),
              "vic holds %s after one POST to the default group" % sorted(_gsx_perms("vic")))
    finally:
        with app.app_context():
            _dflt = db.session.get(Group, _gsx["dflt"])
            _dflt.name, _dflt.description = _name, _desc
            _dflt.set_permissions(_perms)
            _dflt.users = [u for u in _dflt.users if u.id != _gsx["vic"]]
            db.session.commit()


def _check_group_delete_refusals():
    """A delegated admin deletes only a group wholly within their reach, whose members they administer."""
    from panel.db.models import Invite as _GInv
    _dc = client_as(_gsx["dana"])
    # 745378983: a group holding a superadmin-authored custom command dana does not hold.
    _dc.post("/groups/%d/delete" % _gsx["cmd"])
    with app.app_context():
        _carl_cmds = auth.custom_command_ids(db.session.get(User, _gsx["carl"]))
    check("group scope: a delegated admin cannot delete a group holding a command they lack",
          _gsx_row("cmd") is not None and _gsx["cmd_id"] in _carl_cmds,
          "the group is gone and carl lost the command")
    _dc.post("/groups/%d/delete" % _gsx["a_mixdel"])
    check("group scope: ...nor one whose member reaches more than they do",
          _gsx_row("a_mixdel") is not None, "a_mixdel was deleted, stripping mia")
    _dc.post("/groups/%d/delete" % _gsx["a_inv"])
    with app.app_context():
        _inv = db.session.get(_GInv, _gsx["inv_id"])
        _inv_live = _inv is not None and _inv.revoked_at is None
    check("group scope: ...nor one a live invite names beside an out-of-reach group",
          _gsx_row("a_inv") is not None and _inv_live,
          "the group was deleted, which also revoked the superadmin's invite")
    _dc.post("/groups/%d/delete" % _gsx["a_del"])
    check("group scope: an in-reach group with no members still deletes (control)",
          _gsx_row("a_del") is None, "every delegated delete is refused, so the above prove nothing")


def _check_group_scope_page_and_superadmin():
    """The page offers Edit/Delete only where the POST allows it; a superadmin keeps both."""
    _page = client_as(_gsx["dana"]).get("/groups").get_data(as_text=True)
    _sa_page = client_as(admin_id).get("/groups").get_data(as_text=True)

    def _has_edit(html, key):
        return ('id="edit-group-%d"' % _gsx[key]) in html

    def _has_delete(html, key):
        return ('action="/groups/%d/delete"' % _gsx[key]) in html

    check("groups page: no Edit form for a group the admin may not edit",
          not _has_edit(_page, "b_view") and not _has_edit(_page, "a_view"),
          "the page offers an edit the POST refuses")
    check("groups page: ...nor a Delete button for one they may not delete",
          (tag + "_gsx_cmdgrp") in _page and not _has_delete(_page, "cmd")
          and not _has_delete(_page, "a_mixdel"),
          "the page offers a delete the POST refuses (or the group is not on the page at all)")
    check("groups page: ...while an editable group keeps both (control)",
          _has_edit(_page, "a_free") and _has_delete(_page, "a_free"),
          "the page offers nothing at all, so the two checks above are vacuous")
    check("groups page: ...and a superadmin is offered Edit and Delete on every group",
          all(_has_edit(_sa_page, k) and _has_delete(_sa_page, k)
              for k in ("b_view", "a_view", "cmd", "a_mixdel", "a_free")),
          "the manageable set narrowed the superadmin's page")
    # A superadmin's edit of an out-of-reach group is not affected.
    client_as(admin_id).post("/groups/%d/edit" % _gsx["b_view"], data={
        "name": tag + "_gsx_b_view", "description": "sa-changed",
        "permissions": [auth.VIEW_SERVERS], "servers": [str(other_remote)]})
    check("group scope: a superadmin still edits any group (control)",
          _gsx_row("b_view") == (tag + "_gsx_b_view", "sa-changed", [auth.VIEW_SERVERS]),
          "got %r" % (_gsx_row("b_view"),))


def _group_scope_cleanup():
    """Remove the group-scope fixtures. The final sweep would too; this keeps later blocks clean."""
    from panel.db.models import CustomCommand as _GCC, Invite as _GInv
    with app.app_context():
        for _ik in ("inv_id", "sainv_id"):
            _inv = db.session.get(_GInv, _gsx[_ik])
            if _inv is not None:
                db.session.delete(_inv)
        for _k in ("dana", "vic", "vera", "mia", "alice", "carl"):
            _u = db.session.get(User, _gsx[_k])
            if _u is not None:
                db.session.delete(_u)
        db.session.commit()
        for _g in Group.query.filter(Group.name.like(tag + "_gsx_%")).all():
            db.session.delete(_g)
        _c = db.session.get(_GCC, _gsx["cmd_id"])
        if _c is not None:
            db.session.delete(_c)
        db.session.commit()


def _check_group_edit_scope():
    """745379016 / 745378983: edit and delete are scoped to groups wholly within the admin's reach."""
    # _grantable_perms filtered WHICH permissions a delegated admin could toggle, and nothing asked
    # WHOSE: edit_group took any group id. So an admin scoped to hostA handed use_terminal to
    # tenant B's viewers on hostB, stripped tenant B's admins, and — through the default group,
    # which holds every account — gave the whole install a shell in one POST. /users refuses the
    # same change to the same people (can_administer_user); /groups did not.
    if not (other_remote and other_id):
        check("group scope: (premise) the fixture has a second host to be scoped out", False,
              "the scope checks did not run")
        return
    _group_scope_fixtures()
    try:
        _check_group_edit_refusals()
        _check_group_edit_default_group()
        _check_group_delete_refusals()
        _check_group_scope_page_and_superadmin()
    finally:
        _group_scope_cleanup()


_AUDIT_PW = "Rbac-audit-1!pw"   # nosec B105 - a throwaway fixture account's password, for a re-auth prompt


def _audit_fixtures():
    """Two fixture hosts whose game servers share a NAME, and two delegated log viewers."""
    global _ax
    with app.app_context():
        _hosts = {}
        for _k in ("hA", "hB"):
            _hosts[_k] = RemoteServer(name=tag + "_" + _k, host="127.0.0.1", port=22,
                                      username="root", auth_method="key", auth_credential="")
            db.session.add(_hosts[_k])
        db.session.flush()
        # The default-install collision: the same game on two hosts gets the same name.
        _srv = {"sA": GameServer(remote_id=_hosts["hA"].id, name=tag + "_cs2", short_name="rbaxsa",
                                 game_type="cs2", port=27115, installed=True, status="offline"),
                "sB": GameServer(remote_id=_hosts["hB"].id, name=tag + "_cs2", short_name="rbaxsb",
                                 game_type="cs2", port=27116, installed=True, status="offline"),
                "sB2": GameServer(remote_id=_hosts["hB"].id, name=tag + "_prod",
                                  short_name="rbaxsb2", game_type="cs2", port=27117,
                                  installed=True, status="offline")}
        db.session.add_all(_srv.values())
        db.session.flush()
        _liz_g = Group(name=tag + "_ax_liz", description="", is_default=False)
        _liz_g.set_permissions([auth.VIEW_LOGS, auth.VIEW_SERVERS])
        _liz_g.game_servers.append(_srv["sA"])          # ONE server, by an individual grant
        _dana_g = Group(name=tag + "_ax_dana", description="", is_default=False)
        _dana_g.set_permissions([auth.VIEW_LOGS, auth.VIEW_SERVERS, auth.MANAGE_SERVERS,
                                 auth.MANAGE_REMOTES])
        _dana_g.servers.append(_hosts["hA"])            # the whole of hostA
        db.session.add_all([_liz_g, _dana_g])
        _users = {}
        for _k, _grp in (("liz", _liz_g), ("dana", _dana_g)):
            _users[_k] = User(username=tag + "_ax_" + _k, display_name=_k,
                              password_hash=auth.hash_password(_AUDIT_PW),
                              is_superadmin=False, is_active=True)
            _users[_k].groups.append(_grp)
            db.session.add(_users[_k])
        db.session.commit()
        _ax = {k: v.id for d in (_hosts, _srv, _users) for k, v in d.items()}
        _ax.update(liz_g=_liz_g.id, dana_g=_dana_g.id, rows={})


def _ax_log(key, action, target, detail, server=None, remote=None, user_id=None):
    """Write an audit row through the real log_action and remember its id under `key`."""
    from panel.db.models import AuditLog as _AXL
    with app.test_request_context():
        _who = db.session.get(User, user_id or admin_id)
        auth.log_action(_who, action, target=target, detail=detail,
                        server=db.session.get(GameServer, _ax[server]) if server else None,
                        remote=db.session.get(RemoteServer, _ax[remote]) if remote else None)
        _ax["rows"][key] = db.session.query(db.func.max(_AXL.id)).scalar()


def _ax_sees(user_key, row_key):
    """Whether `user_key`'s audit_scope includes the row remembered as `row_key` (rows, not page text)."""
    from panel.db.models import AuditLog as _AXL
    from panel.routes.audit import audit_scope as _ax_scope
    with app.app_context():
        _u = db.session.get(User, _ax[user_key] if user_key in _ax else user_key)
        _scope = _ax_scope(_u)
        _q = _AXL.query.filter(_AXL.id == _ax["rows"][row_key])
        return (_q if _scope is None else _q.filter(_scope)).count() == 1


def _check_audit_same_named_servers():
    """745379041 (a): the same game on two hosts shares a name; a viewer of one reads neither the other's."""
    _sa = client_as(admin_id)
    for _k in ("sA", "sB"):
        _sa.post("/api/server/%d/notify-empty" % _ax[_k], json={"enabled": True})
    from panel.db.models import AuditLog as _AXL
    with app.app_context():
        for _k in ("sA", "sB"):
            _ax["rows"]["notify_" + _k] = (db.session.query(db.func.max(_AXL.id))
                                           .filter(_AXL.action == "set_notify_when_empty",
                                                   _AXL.game_server_id == _ax[_k]).scalar())
    check("audit scope: (premise) the route recorded WHICH server each row is about",
          _ax["rows"]["notify_sA"] is not None and _ax["rows"]["notify_sB"] is not None,
          "set_notify_when_empty wrote no game_server_id — the checks below would prove nothing")
    _ax_log("rcon_sB", "send_command", tag + "_cs2", "rcon_password S3cretHostB", server="sB")
    check("audit scope: a viewer of one server sees its rows (control)",
          _ax_sees("liz", "notify_sA"), "the scope is too tight")
    check("audit scope: ...but not the same-named server's on another host",
          not _ax_sees("liz", "notify_sB") and not _ax_sees("liz", "rcon_sB"),
          "hostB's console commands, rcon_password included, reach a viewer of hostA's copy")


def _check_audit_rename_onto_other_targets():
    """745379041 (b, c) / 745379096: renaming your own server or host onto a target reads nothing new."""
    _ax_log("prod_sB2", "send_command", tag + "_prod", "sv_password TenantBpw", server="sB2")
    _ax_log("port_hB", "remote_port_open", "%s_hB:27015/udp" % tag, "opened", remote="hB")
    _ax_log("port_hA", "remote_port_open", "%s_hA:27015/udp" % tag, "opened", remote="hA")
    _ax_log("repair_db", "panel_repair_db", "database", "repaired")
    _ax_log("ufw_panel", "ufw_block", "198.51.100.7", "panel host")
    _dc = client_as(_ax["dana"])
    for _new in (tag + "_prod", "database", "198.51.100.7"):
        _dc.post("/servers/%d/edit" % _ax["sA"], data={"name": _new})
    with app.app_context():
        _renamed = db.session.get(GameServer, _ax["sA"]).name
    check("audit scope: (premise) the delegated admin really renamed their server",
          _renamed == "198.51.100.7", "server is named %r" % _renamed)
    check("audit scope: renaming your server onto another tenant's does not read its rows",
          not _ax_sees("dana", "prod_sB2"), "tenant B's sv_password reached tenant A's admin")
    check("audit scope: ...nor onto the panel host's own targets ('database', an IP)",
          not _ax_sees("dana", "repair_db") and not _ax_sees("dana", "ufw_panel"),
          "a server renamed 'database' or to an IP read the panel host's administration")
    _dc.post("/remotes/%d/edit" % _ax["hA"], data={
        "name": tag + "_hB", "host": "127.0.0.1", "ssh_port": "22", "ssh_user": "root"})
    with app.app_context():
        _hname = db.session.get(RemoteServer, _ax["hA"]).name
    check("audit scope: (premise) the delegated admin really renamed their host",
          _hname == tag + "_hB", "host is named %r" % _hname)
    check("audit scope: renaming your host onto another's does not read its 'host:port' rows",
          not _ax_sees("dana", "port_hB"), "hostB's firewall row reached hostA's admin")
    check("audit scope: ...while their own host's rows, and its servers', still reach them (control)",
          _ax_sees("dana", "port_hA") and _ax_sees("dana", "notify_sA"), "the scope is too tight")


def _check_audit_account_rows():
    """745379096: a server named like an account shows no reset of that account."""
    with app.app_context():
        _sa_row = db.session.get(GameServer, _ax["sA"])
        _sa_row.name = tag + "_ax_victim"
        db.session.commit()
    _ax_log("reset_pw", "reset_user_password", tag + "_ax_victim", "")
    _ax_log("reset_2fa", "2fa_reset", tag + "_ax_victim", "")
    # ...and one that names their server BY ID, as a call site passing server= wrongly would:
    # the account-action exclusion must still hold it back.
    _ax_log("reset_pw_id", "reset_user_password", tag + "_ax_victim", "", server="sA")
    check("audit scope: a viewer whose server shares an account's name sees no reset of it",
          not _ax_sees("liz", "reset_pw") and not _ax_sees("liz", "reset_2fa"),
          "another account's password/2FA reset reached a server-scoped viewer")
    check("audit scope: ...not even one carrying their server's id (account actions stay out)",
          not _ax_sees("liz", "reset_pw_id"),
          "reset_user_password is not treated as an account action")


def _check_audit_recycled_server_id():
    """745379041: a deleted server's rows do not pass to the server that inherits its id."""
    from panel.db.models import AuditLog as _AXL
    with app.app_context():
        _x = GameServer(remote_id=_ax["hB"], name=tag + "_gone", short_name="rbaxgone",
                        game_type="cs2", port=27118, installed=True, status="offline")
        db.session.add(_x)
        db.session.commit()
        _ax["sX"] = _x.id
    _ax_log("gone_sX", "send_command", tag + "_gone", "rcon_password GoneSecret", server="sX")
    with app.app_context():
        db.session.delete(db.session.get(GameServer, _ax["sX"]))
        db.session.commit()
        # WITH the freed id: game_server has AUTOINCREMENT now, so a plain INSERT no longer takes
        # it — but every install whose table predates that does, until its rebuild runs.
        _y = GameServer(id=_ax["sX"], remote_id=_ax["hA"], name=tag + "_heir",
                        short_name="rbaxheir", game_type="cs2", port=27119, installed=True,
                        status="offline")
        db.session.add(_y)
        db.session.commit()
        _ax["sY"] = _y.id
        _liz_g = db.session.get(Group, _ax["liz_g"])   # held: the identity map is weak
        _liz_g.game_servers.append(_y)
        db.session.commit()
        _detached = db.session.get(_AXL, _ax["rows"]["gone_sX"]).game_server_id is None
    check("audit scope: (premise) the next server holds the deleted server's id",
          _ax["sY"] == _ax["sX"], "ids %s / %s — the check below is not about reuse"
          % (_ax["sX"], _ax["sY"]))
    check("audit scope: a deleted server's rows are detached from its id",
          _detached, "the row still points at an id SQLite has recycled")
    check("audit scope: ...so the server that inherits the id does not inherit its history",
          not _ax_sees("liz", "gone_sX"), "a deleted tenant's rcon_password reached the heir's viewer")
    # A row written AFTER the delete, about the deleted instance — uninstall_server's failure row
    # and a background worker's outcome row are written that way. The listener has already run,
    # so only log_action itself can refuse to record the dead id.
    with app.test_request_context():
        _dead = GameServer(remote_id=_ax["hB"], name=tag + "_gone2",
                           short_name="rbaxgone2", game_type="cs2", port=27121)
        db.session.add(_dead)
        db.session.commit()
        db.session.delete(_dead)
        db.session.commit()
        auth.log_action(db.session.get(User, admin_id), "uninstall_server", target=tag + "_gone2",
                        detail="rcon_password AfterDelete", server=_dead)
        _ax["rows"]["after_delete"] = db.session.query(db.func.max(_AXL.id)).scalar()
        _after = db.session.get(_AXL, _ax["rows"]["after_delete"]).game_server_id
    check("audit scope: a row written after its server was deleted records no id for it",
          _after is None, "it recorded %r — an id SQLite will hand to the next server" % _after)


def _check_audit_recycled_host_ids():
    """...nor a deleted HOST's rows, whose servers go by bulk delete, to the ones that take their ids."""
    from panel.db.models import AuditLog as _AXL
    with app.app_context():
        _hc = RemoteServer(name=tag + "_hC", host="127.0.0.1", port=22, username="root",
                           auth_method="key", auth_credential="")
        db.session.add(_hc)
        db.session.flush()
        _sc = GameServer(remote_id=_hc.id, name=tag + "_onhc", short_name="rbaxsc",
                         game_type="cs2", port=27120, installed=True, status="offline")
        db.session.add(_sc)
        _dana_g = db.session.get(Group, _ax["dana_g"])  # held: the identity map is weak
        _dana_g.servers.append(_hc)
        db.session.commit()
        _ax.update(hC=_hc.id, sC=_sc.id)
    _ax_log("hc_row", "remote_port_open", tag + "_hC:27015/udp", "opened", remote="hC")
    _ax_log("sc_row", "send_command", tag + "_onhc", "rcon_password HostCSecret", server="sC")
    # Through the real route: its game servers go by a BULK delete that fires no ORM event.
    _rd = client_as(_ax["dana"]).post("/remotes/%d/delete" % _ax["hC"],
                                      json={"password": _AUDIT_PW})
    with app.app_context():
        _gone = db.session.get(RemoteServer, _ax["hC"]) is None
        _hc_row = db.session.get(_AXL, _ax["rows"]["hc_row"])
        _sc_row = db.session.get(_AXL, _ax["rows"]["sc_row"])
        _detached = (_hc_row.remote_id is None, _sc_row.game_server_id is None)
    check("audit scope: (premise) the host delete went through", _gone,
          "status %s" % _rd.status_code)
    check("audit scope: a deleted host's rows, and its bulk-deleted servers', are detached",
          _detached == (True, True), "remote_id/game_server_id detached: %s" % (_detached,))


def _check_audit_superadmin_sees_all():
    """The superadmin still reads every planted row."""
    check("audit scope: a superadmin still reads every row (control)",
          all(_ax_sees(admin_id, k) for k in _ax["rows"]),
          "missing: %s" % [k for k in _ax["rows"] if not _ax_sees(admin_id, k)])


def _ax_legacy_rows():
    """(key, action, target, expected (game_server_id key, remote_id key)) for the upgrade check."""
    return (("L_srv", "send_command", tag + "_cs2", ("sB", None)),        # one server by that name
            ("L_like", "moderate_kick", tag + "_cs2", ("sB", None)),      # a built action name
            ("L_dup", "start_server", tag + "_prod", (None, None)),       # two servers: ambiguous
            ("L_panel", "panel_repair_db", tag + "_cs2", (None, None)),   # not a server action
            ("L_acct", "invite_created", tag + "_cs2", (None, None)),     # an account action
            ("L_port", "remote_port_open", tag + "_hB:27015/udp", (None, "hB")),
            ("L_host", "edit_remote", tag + "_hA", (None, "hA")),
            ("L_ip", "ufw_block", tag + "_hA", (None, None)))            # call-only: never backfilled


def _ax_restore_audit_columns():
    """Put the two columns back by hand after a failed upgrade, so the rest of the suite can run."""
    from sqlalchemy import text as _t
    from panel.db.models import _LIGHT_MIGRATIONS
    for _c in ("game_server_id", "remote_id"):
        try:
            db.session.execute(_t(_LIGHT_MIGRATIONS[("audit_log", _c)]))
            db.session.commit()
        except Exception:   # nosec B110 - already there: the failure was after the ALTER
            db.session.rollback()


def _check_audit_backfill_on_upgrade():
    """The upgrade adds both columns to an old audit_log and backfills only what is unambiguous."""
    from sqlalchemy import text as _t, inspect as _ax_insp
    from panel.db.models import AuditLog as _AXL, _run_light_migrations
    # It drops two columns and replays the migration, so only on this run's own database.
    check("audit backfill: (premise) the database is this run's own, so the upgrade can be replayed",
          bool(any(seeded.values())), "not replayed on a configured install")
    if not any(seeded.values()):
        return
    with app.app_context():
        _hA, _sY = db.session.get(RemoteServer, _ax["hA"]), db.session.get(GameServer, _ax["sY"])
        _hA.name, _sY.name = tag + "_hA", tag + "_prod"     # hA unique again; tag_prod ambiguous
        db.session.commit()
        for _c in ("game_server_id", "remote_id"):
            db.session.execute(_t("DROP INDEX IF EXISTS ix_audit_log_%s" % _c))
            db.session.execute(_t("ALTER TABLE audit_log DROP COLUMN %s" % _c))
        db.session.commit()
        _ids = {}
        for _k, _act, _tgt, _ in _ax_legacy_rows():
            db.session.execute(_t("INSERT INTO audit_log (username, action, target, detail, success) "
                                  "VALUES ('legacy', :a, :t, :d, 1)"),
                               {"a": _act, "t": _tgt, "d": tag + "_legacy"})
            _ids[_k] = db.session.execute(_t("SELECT max(id) FROM audit_log")).scalar()
        db.session.commit()
        try:
            _run_light_migrations()                         # <- the update path
            _upgrade_err = None
        except Exception as _e:   # a locked or failed upgrade is this check's finding, not a crash
            db.session.rollback()
            _upgrade_err = "%s: %s" % (type(_e).__name__, str(_e)[:160])
            _ax_restore_audit_columns()
        _ax["rows"].update(_ids)
    check("audit backfill: the upgrade itself runs (an install upgrading to this starts at all)",
          _upgrade_err is None, _upgrade_err or "")
    if _upgrade_err is not None:
        return
    with app.app_context():
        _cols = {c["name"] for c in _ax_insp(db.engine).get_columns("audit_log")}
        _idx = {i["name"] for i in _ax_insp(db.engine).get_indexes("audit_log")}
        _got = {_k: (db.session.get(_AXL, _i).game_server_id, db.session.get(_AXL, _i).remote_id)
                for _k, _i in _ids.items()}
    check("audit backfill: the upgrade adds both columns back, indexed",
          {"game_server_id", "remote_id"} <= _cols
          and {"ix_audit_log_game_server_id", "ix_audit_log_remote_id"} <= _idx,
          "columns %s, indexes %s" % (sorted(_cols), sorted(_idx)))
    _want = {_k: tuple(_ax[_e] if _e else None for _e in _exp)
             for _k, _, _, _exp in _ax_legacy_rows()}
    check("audit backfill: only an unambiguous server or host action gets an id",
          _got == _want, "got %s, want %s" % (_got, _want))


def _audit_cleanup():
    """Remove the audit fixtures: rows, users, groups, servers, hosts."""
    from panel.db.models import AuditLog as _AXL
    with app.app_context():
        for _rid in _ax.get("rows", {}).values():
            _r = db.session.get(_AXL, _rid) if _rid else None
            if _r is not None:
                db.session.delete(_r)
        for _k in ("liz", "dana"):
            _u = db.session.get(User, _ax.get(_k))
            if _u is not None:
                db.session.delete(_u)
        for _k in ("liz_g", "dana_g"):
            _g = db.session.get(Group, _ax.get(_k))
            if _g is not None:
                db.session.delete(_g)
        db.session.commit()
        for _k in ("sA", "sB", "sB2", "sY"):
            _s = db.session.get(GameServer, _ax.get(_k)) if _ax.get(_k) else None
            if _s is not None:
                db.session.delete(_s)
        db.session.commit()
        for _k in ("hA", "hB"):
            _h = db.session.get(RemoteServer, _ax.get(_k)) if _ax.get(_k) else None
            if _h is not None:
                db.session.delete(_h)
        db.session.commit()


def _check_audit_scope_by_object():
    """745379041 / 745379096: a delegated viewer's rows are chosen by server/host id, never by name."""
    _audit_fixtures()
    try:
        _check_audit_same_named_servers()
        _check_audit_rename_onto_other_targets()
        _check_audit_account_rows()
        _check_audit_recycled_server_id()
        _check_audit_recycled_host_ids()
        _check_audit_superadmin_sees_all()
        _check_audit_backfill_on_upgrade()
    finally:
        _audit_cleanup()


def _check_bulk_actions_per_id():
    """Bulk actions are access-checked for every id."""
    global _t
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


def _check_setup_endpoints_stay_shut():
    """The setup-only endpoints stay shut when config.json is lost."""
    global _label, _m, _p, _r
    # ── The setup-only endpoints must stay shut when config.json is LOST ───────────────────────────
    # /api/setup/tailscale/{status,install,up,serve} carry no login — during a fresh install there is no
    # user to authenticate. They answer only the wizard's owner (the setup token before the admin
    # exists, the owner token after), and only for as long as their "setup is still open" test holds. That test used to be is_setup_complete(), which was then (DB row AND config flag),
    # and the config half failed open: load_config() swallows JSONDecodeError/OSError and hands back
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
        # ...and the rest of the panel still WORKS. Every page redirected to /setup (config flag
        # False), the locked wizard to /login, and /login sent a signed-in admin back to / —
        # ERR_TOO_MANY_REDIRECTS for everyone, including the admin who could have repaired it.
        _cg_dash = client_as(admin_id).get("/")
        check("config.json gone: a signed-in admin's dashboard renders instead of looping via /setup",
              _cg_dash.status_code == 200,
              "/ -> %d %s" % (_cg_dash.status_code, _cg_dash.headers.get("Location")))
        _cg_anon = _anon.get("/")
        check("config.json gone: a signed-out visitor is sent to /login, not into the /setup loop",
              _cg_anon.status_code in (301, 302) and "/setup" not in (_cg_anon.headers.get("Location") or ""),
              "/ -> %d %s" % (_cg_anon.status_code, _cg_anon.headers.get("Location")))
        check("config.json gone: /healthz still answers the monitor itself (no redirect)",
              _anon.get("/healthz").status_code == 200)
    finally:
        _cfg_mod.CONFIG_FILE = _real_config_file
        _cfg_mod._cfg_cache.clear()
        _cfg_mod._cfg_cache.update(_real_cache)


def _check_healthz_before_setup():
    """/healthz answers before setup is complete, instead of redirecting to /setup."""
    global _r
    # /healthz is a liveness probe, and it answers before setup has finished too: a first-run panel
    # redirected it to /setup, and a monitor reading "302" learned nothing about the process or DB.
    with app.app_context():
        _hz_rows = [r.id for r in SetupState.query.filter_by(complete=True).all()]
        for _r in SetupState.query.filter(SetupState.id.in_(_hz_rows)).all():
            _r.complete = False
        db.session.commit()
    try:
        check("first run: (control) the panel really is back in setup — / goes to /setup",
              "/setup" in (app.test_client().get("/").headers.get("Location") or ""))
        check("first run: /healthz answers 200 itself instead of redirecting to /setup",
              app.test_client().get("/healthz").status_code == 200)
    finally:
        with app.app_context():
            for _r in SetupState.query.filter(SetupState.id.in_(_hz_rows)).all():
                _r.complete = True
            db.session.commit()


def _check_invites():
    """Invites: helpers and planted fixtures, each refusal a redemption needs, the cleanup."""
    global _, _Inv, _accept, _anon_inv, _dormant, _inv_before, _inv_tag, _inv_timedelta
    global _inv_utcnow, _mint, _pre_inv_id, _sa, _sa_before, _sa_id, _user
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


    def _accept(tok, username, password="Sufficient1!pass"):  # nosec B107 - a throwaway invitee's password
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
        _invite_happy_path_and_replays()
        _invite_revoked_during_the_race()
        _invite_minter_demoted_mid_request()
        _invite_expired_mid_request()
        _invite_superadmin_from_a_demoted_minter()
        _invite_group_from_a_demoted_minter()
        _invite_host_outside_the_minters_reach()
        _invite_host_inside_the_minters_reach()
        _invite_custom_command_axis()
        _invite_deactivated_expired_and_guessed()
    finally:
        _invite_cleanup()


def _check_invite_fixtures_survive():
    """The dormant superadmin and the pre-existing invite are as they were after the run."""
    global _gone
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


def _check_delete_user_offers_only_allowed():
    """Deleting a user: the fixtures, and the users page offering only what the route allows."""
    global _alive, _del_tag, _vord_id, _vsa_id, ca_del
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


def _check_users_page_reach_and_sa_delete():
    """The users page computes reach once per account; a group admin cannot delete a superadmin."""
    global _, _gone, _x
    # ...and it decides that ONCE per account, with the viewer's own reach computed once. The
    # template asked per row twice (the table and #users-data), and every call recomputed the
    # viewer's server set as well as the target's: several queries per account, twice over, for a
    # delegated admin. Measured as a shape: three more administrable accounts must not add a single
    # call on the viewer's side, and no account is looked up twice.
    _ua_auth = auth                      # panel.security.auth, imported once above
    from collections import Counter as _UaCounter
    _ua_gus = _ua_auth.get_user_servers

    def _ua_render():
        _calls = []
        _ua_auth.get_user_servers = lambda u: (_calls.append(u.id), _ua_gus(u))[1]
        try:
            _html = cmu.get("/users").get_data(as_text=True)
        finally:
            _ua_auth.get_user_servers = _ua_gus
        return _html, _UaCounter(_calls)

    _ua_extra = []
    try:
        _, _ua_before = _ua_render()
        with app.app_context():
            for _k in range(3):
                _xu = User(username="%s_ua%d" % (_del_tag, _k),
                           password_hash=auth.hash_password(secrets.token_hex(16)),
                           display_name="ua %d" % _k, is_superadmin=False, is_active=True)
                db.session.add(_xu)
                db.session.flush()
                _ua_extra.append(_xu.id)
            db.session.commit()
        _ua_html3, _ua_after = _ua_render()
        check("users page: (control) the added accounts are offered Edit, so they were decided",
              all('data-action="openEditUser" data-args=\'[%d]\'' % _x in _ua_html3
                  for _x in _ua_extra), "an added account lost its controls")
        check("users page: more accounts add no lookups of the viewer's own servers",
              _ua_after[_mu_uid] == _ua_before[_mu_uid],
              "viewer's lookups %d -> %d with 3 more accounts"
              % (_ua_before[_mu_uid], _ua_after[_mu_uid]))
        check("users page: ...and each account's servers are looked up once, not twice",
              all(_ua_after[_x] == 1 for _x in _ua_extra)
              and max(n for u, n in _ua_after.items() if u != _mu_uid) == 1,
              repr(dict(_ua_after)))
    finally:
        with app.app_context():
            for _x in _ua_extra:
                _gone = db.session.get(User, _x)
                if _gone is not None:
                    db.session.delete(_gone)
            db.session.commit()

    # 1. A delegated admin must not remove a superadmin.
    cmu.post("/users/%d/delete" % _vsa_id)
    check("delete user: MANAGE_USERS alone cannot delete a SUPERADMIN", _alive(_vsa_id),
          "a non-superadmin removed a superadmin account")

    # 2. The control that makes 1 mean something: a real superadmin CAN delete that same account,
    #    so the refusal above is authorization and not "deleting a superadmin never works".
    ca_del.post("/users/%d/delete" % _vsa_id)
    check("delete user: ...while a superadmin CAN delete that same account", not _alive(_vsa_id),
          "the control failed, so the refusal above proves nothing")


def _check_delete_user_ordinary_and_self():
    """A superadmin deletes an ordinary account, nobody deletes themselves, and the traps held."""
    # 3. And an ordinary account, the plain path.
    ca_del.post("/users/%d/delete" % _vord_id)
    check("delete user: a superadmin can delete an ordinary account", not _alive(_vord_id))

    # 4. Nobody deletes themselves — the one guard here that is reachable on its own, and the one
    #    standing between a panel and having no administrator at all. Probed with a THROWAWAY
    #    superadmin acting on itself (named from `tag`, so the final cleanup finds it whatever
    #    happens): this used to post the delete as admin_id, the install's own first superadmin,
    #    so a regressed guard would have removed the operator's real account.
    with app.app_context():
        _self_sa = User(username=_del_tag + "_self",
                        password_hash=auth.hash_password(secrets.token_hex(16)),
                        display_name="self-delete probe", is_superadmin=True, is_active=True)
        db.session.add(_self_sa)
        db.session.commit()
        _self_id = _self_sa.id
    client_as(_self_id).post("/users/%d/delete" % _self_id)
    check("delete user: you cannot delete your own account", _alive(_self_id),
          "the acting superadmin deleted themselves — the panel would have no admin left")

    # Every trap except the two the controls above reach on purpose must still be untouched: the
    # reboot probes (legacy grant -> panel host, delegated admin -> a non-granted remote), the
    # denied uninstalls and the panel-host bootstraps all end here, refused before their action.
    _unexpected = [t for t in _trapped if t not in ("install job", "remote_install_tailscale")]
    check("traps: no refused probe reached a reboot, an uninstall or a bootstrap",
          not _unexpected, "reached: %r" % (_unexpected,))


# ── A body held back is authorized when it ARRIVES, not when the headers did ──────────────────────
# A route's checks ran before its body was read, and the body is read where the view first touches
# request.form, request.files or get_json(): under eventlet, a socket read the client controls. So
# a client could send the headers, hold the body, and wait while its token was revoked, its account
# deactivated or its group's permission removed, and the action then ran on the answer given
# before. csrf.protect() never covered it: a Bearer request with no cookie skips it, and it does
# not read a JSON body at all. _HeldBody stands in for that client. Its first read, wherever the
# panel makes it, commits the change the real request would be waiting through, from its own app
# context, as an admin's request on another greenlet would.
import io as _hb_io  # noqa: E402
import json as _hb_json  # noqa: E402
import panel.routes.server_files as _hb_sf  # noqa: E402


class _HeldBody(_hb_io.BytesIO):
    """A request body whose first read runs `on_arrival`: the moment a held-back body lands."""

    def __init__(self, data, on_arrival):
        super().__init__(data)
        self._on_arrival = on_arrival
        self.arrived = False

    def _arrive(self):
        if not self.arrived:
            self.arrived = True
            self._on_arrival()

    def read(self, *a):
        self._arrive()
        return super().read(*a)

    def read1(self, *a):
        self._arrive()
        return super().read1(*a)

    def readinto(self, b):
        self._arrive()
        return super().readinto(b)

    def readline(self, *a):
        self._arrive()
        return super().readline(*a)


def _hb_fixture():
    """A MANAGE_SERVERS user on the granted host, with an API token: (user id, group id, token)."""
    with app.app_context():
        grp = Group(name=tag + "_hb", description="RBAC held body (auto)", is_default=False)
        grp.set_permissions([auth.VIEW_SERVERS, auth.MANAGE_SERVERS])
        grp.servers.append(db.session.get(RemoteServer, granted_remote))
        db.session.add(grp)
        db.session.flush()
        u = User(username=tag + "_hb", display_name=tag + "_hb", is_superadmin=False,
                 is_active=True, password_hash=auth.hash_password(secrets.token_hex(16)))
        u.groups.append(grp)
        db.session.add(u)
        tok = u.generate_api_token()
        db.session.commit()
        return u.id, grp.id, tok


def _hb_user(uid_, **fields):
    """Commit `fields` onto the user from its own app context; return its row's auth state."""
    with app.app_context():
        u = db.session.get(User, uid_)
        for k, v in fields.items():
            setattr(u, k, v)
        db.session.commit()
        return {"token": u.api_token, "active": u.is_active, "sa": u.is_superadmin,
                "must_change": u.must_change_password}


def _hb_new_token(uid_):
    """Mint the user a fresh token (the revoke case clears it) and return the plaintext."""
    with app.app_context():
        tok = db.session.get(User, uid_).generate_api_token()
        db.session.commit()
        return tok


def _hb_perms(gid, perms=None):
    """Set the group's permissions (if given) from its own app context; return what is stored."""
    with app.app_context():
        grp = db.session.get(Group, gid)
        if perms is not None:
            grp.set_permissions(perms)
            db.session.commit()
        return sorted(grp.get_permissions())


def _hb_tag_made(name):
    from panel.db.models import ServerTag
    with app.app_context():
        return ServerTag.query.filter_by(name=name).first() is not None


def _hb_post_tag(client, name, on_arrival, headers=None):
    """POST /api/tags with its JSON body held back until `on_arrival` has run: (response, read?)."""
    body = _HeldBody(_hb_json.dumps({"name": name}).encode(), on_arrival)
    r = client.post("/api/tags", input_stream=body, content_type="application/json",
                    headers=headers or {})
    return r, body.arrived


def _check_held_json_body_with_a_token(hb_uid, tok):
    """Bearer + JSON: a token revoked, or an account deactivated, while the body is held."""
    _bearer = {"Authorization": "Bearer %s" % tok}
    r, read = _hb_post_tag(app.test_client(), tag + "_hbok", lambda: None, _bearer)
    check("held body: (control) a Bearer JSON request whose body arrives late still works",
          read and r.status_code == 200 and _hb_tag_made(tag + "_hbok"),
          "the control failed (read=%s, %d) — the refusals below prove nothing"
          % (read, r.status_code))
    # Each refusal also asserts its premise — the body was read, and the change had landed by the
    # end — so a window that never opened cannot pass as a refusal.
    r, read = _hb_post_tag(app.test_client(), tag + "_hbrev",
                           lambda: _hb_user(hb_uid, api_token=None), _bearer)
    check("held body: a token revoked while its body is held back is refused, and makes nothing",
          read and _hb_user(hb_uid)["token"] is None
          and r.status_code == 401 and not _hb_tag_made(tag + "_hbrev"),
          "a revoked token still created a tag (read=%s, %d)" % (read, r.status_code))
    _bearer = {"Authorization": "Bearer %s" % _hb_new_token(hb_uid)}
    r, read = _hb_post_tag(app.test_client(), tag + "_hbdeact",
                           lambda: _hb_user(hb_uid, is_active=False), _bearer)
    check("held body: an account deactivated while its body is held back is refused",
          read and _hb_user(hb_uid)["active"] is False
          and r.status_code == 401 and not _hb_tag_made(tag + "_hbdeact"),
          "a deactivated account's token still created a tag (read=%s, %d)" % (read, r.status_code))
    _hb_user(hb_uid, is_active=True)
    return _bearer


def _check_held_body_not_read_when_signed_out():
    """Not signed in: nothing can go stale, so a client about to get a 401 is not read."""
    r, read = _hb_post_tag(app.test_client(), tag + "_hbanon", lambda: None,
                           {"Authorization": "Bearer lgsm_" + "0" * 48})
    check("held body: a request that is not signed in is refused WITHOUT its body being read",
          not read and r.status_code == 401 and not _hb_tag_made(tag + "_hbanon"),
          "read=%s, %d — an unauthenticated client could make the panel buffer 50 MB per request"
          % (read, r.status_code))


def _check_held_json_body_demoted(hb_uid, hb_gid, bearer):
    """Bearer + JSON: a group permission, or the superadmin flag, removed mid-body."""
    r, read = _hb_post_tag(app.test_client(), tag + "_hbdemote",
                           lambda: _hb_perms(hb_gid, [auth.VIEW_SERVERS]), bearer)
    check("held body: a permission removed while the body is held back is refused",
          read and _hb_perms(hb_gid) == [auth.VIEW_SERVERS]
          and r.status_code == 403 and not _hb_tag_made(tag + "_hbdemote"),
          "the group lost MANAGE_SERVERS and the tag was created anyway (read=%s, %d)"
          % (read, r.status_code))
    # A superadmin demoted mid-body. The flag is not in the token lookup's WHERE, so only a fresh
    # read of the row can see it change. The group still lacks MANAGE_SERVERS from the case above,
    # so the flag is the only grant in play.
    _hb_user(hb_uid, is_superadmin=True)
    r, read = _hb_post_tag(app.test_client(), tag + "_hbsa",
                           lambda: _hb_user(hb_uid, is_superadmin=False), bearer)
    check("held body: a SUPERADMIN demoted while the body is held back is refused",
          read and _hb_user(hb_uid)["sa"] is False
          and r.status_code == 403 and not _hb_tag_made(tag + "_hbsa"),
          "the stale is_superadmin still created a tag (read=%s, %d)" % (read, r.status_code))
    _hb_perms(hb_gid, [auth.VIEW_SERVERS, auth.MANAGE_SERVERS])


def _check_held_body_meets_the_password_gate(hb_uid, bearer):
    """The password gate is a before_request check too, so the body must be in hand before it."""
    r, read = _hb_post_tag(app.test_client(), tag + "_hbpw",
                           lambda: _hb_user(hb_uid, must_change_password=True), bearer)
    check("held body: an account told to change its password mid-body meets the password gate",
          read and _hb_user(hb_uid)["must_change"] is True
          and r.status_code == 403 and r.headers.get("X-Password-Change-Required") == "1"
          and not _hb_tag_made(tag + "_hbpw"),
          "the gate ran on the identity loaded before the body (read=%s, %d)"
          % (read, r.status_code))
    _hb_user(hb_uid, must_change_password=False)


def _check_held_body_row_kept_alive(hb_uid, hb_gid, bearer):
    """The re-load re-reads the row even when something still holds the one loaded first."""
    # The superadmin case passes without expire_all() today only because nothing else references the
    # first-loaded User: the session's identity map is weak, so dropping flask-login's copy frees
    # the row and the re-load builds a new one. Anything that keeps it alive — a signal receiver, a
    # log record's args, a traceback — turns that re-load into a REUSE of the stale object, and the
    # old is_superadmin answers again. A receiver on flask-login's own signal stands in for it.
    from flask_login.signals import user_loaded_from_request
    _kept = []

    def _keep(_sender, user=None, **_kw):
        _kept.append(user)

    _hb_perms(hb_gid, [auth.VIEW_SERVERS])
    _hb_user(hb_uid, is_superadmin=True)
    user_loaded_from_request.connect(_keep, weak=False)
    try:
        r, read = _hb_post_tag(app.test_client(), tag + "_hbkept",
                               lambda: _hb_user(hb_uid, is_superadmin=False), bearer)
    finally:
        user_loaded_from_request.disconnect(_keep)
    check("held body: a demoted superadmin is refused even while the first-loaded row is held",
          read and _kept and _hb_user(hb_uid)["sa"] is False
          and r.status_code == 403 and not _hb_tag_made(tag + "_hbkept"),
          "the loaded rows were not expired, so the re-load reused the stale one (read=%s, kept=%d,"
          " %d)" % (read, len(_kept), r.status_code))
    _hb_perms(hb_gid, [auth.VIEW_SERVERS, auth.MANAGE_SERVERS])


def _check_held_json_body_with_a_cookie(hb_uid):
    """A signed-in browser's fetch: csrf.protect() does not read a JSON body, so it was open too."""
    r, read = _hb_post_tag(client_as(hb_uid), tag + "_hbcok", lambda: None)
    check("held body: (control) a session's JSON request whose body arrives late still works",
          read and r.status_code == 200 and _hb_tag_made(tag + "_hbcok"),
          "the control failed (read=%s, %d)" % (read, r.status_code))
    r, read = _hb_post_tag(client_as(hb_uid), tag + "_hbcdeact",
                           lambda: _hb_user(hb_uid, is_active=False))
    check("held body: a SESSION whose account is deactivated mid-body is refused too",
          read and _hb_user(hb_uid)["active"] is False
          and r.status_code == 401 and not _hb_tag_made(tag + "_hbcdeact"),
          "a deactivated account's session still created a tag (read=%s, %d)"
          % (read, r.status_code))
    _hb_user(hb_uid, is_active=True)


def _check_held_body_with_csrf_on(hb_uid):
    """With CSRF on, as in production: a fetch and a form post from a session both still work."""
    # The suite runs with CSRF off, so nothing above drives the order production has: csrf.protect()
    # parses a FORM body first, and the hook then finds it already read. A fetch's JSON body it does
    # not read, so there the hook is the first reader.
    import re as _hb_re
    c = client_as(hb_uid)
    _m = _hb_re.search(r'window\.CSRF = "([^"]+)"', c.get("/account").get_data(as_text=True))
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        r_json = c.post("/api/tags", json={"name": tag + "_hbcsrf"},
                        headers={"X-CSRFToken": _m.group(1) if _m else ""})
        r_form = c.post("/account/profile", data={"display_name": tag + " csrf form",
                                                  "csrf_token": _m.group(1) if _m else ""})
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        _shown = db.session.get(User, hb_uid).display_name
    check("held body: with CSRF on, a session's fetch still works (the hook reads its JSON)",
          _m and r_json.status_code == 200 and _hb_tag_made(tag + "_hbcsrf"),
          "token found=%s, %d" % (bool(_m), r_json.status_code))
    check("held body: ...and a form post csrf.protect() has already parsed keeps its fields",
          _m and r_form.status_code == 302 and _shown == tag + " csrf form",
          "got %d, display_name=%r" % (r_form.status_code, _shown))


def _hb_upload_recorder(seen):
    """A stand-in for server_files._store_upload that records how the upload reached the view."""
    from flask import jsonify, request as _rq

    def _store(gs, reldir, f, data, overwrite):
        seen.append({"raw_body_in_memory": len(getattr(_rq, "_cached_data", None) or b""),
                     "spooled_to_disk": getattr(f.stream, "_rolled", None), "size": len(data)})
        return jsonify({"success": True})
    return _store


def _check_held_upload(hb_uid, bearer):
    """An upload still streams to disk, and one whose token goes mid-body stores nothing."""
    from werkzeug.datastructures import FileStorage
    from werkzeug.test import encode_multipart
    url, seen = "/api/server/%d/upload" % accessible_id, []
    _saved = _hb_sf._store_upload
    _hb_sf._store_upload = _hb_upload_recorder(seen)
    try:
        r = app.test_client().post(url, headers=bearer, content_type="multipart/form-data", data={
            "path": "", "file": (_hb_io.BytesIO(b"x" * 600000), "big.cfg")})
        check("held body: (control) a Bearer multipart upload still works",
              r.status_code == 200 and len(seen) == 1 and seen[0]["size"] == 600000,
              "got %d, %r" % (r.status_code, seen))
        check("held body: ...and still STREAMS: the file part is spooled to disk, and the raw "
              "body is never held in memory",
              seen[:1] and seen[0]["spooled_to_disk"] is True
              and seen[0]["raw_body_in_memory"] == 0, repr(seen))
        _bd, _mp = encode_multipart({"path": "", "file": FileStorage(
            _hb_io.BytesIO(b"echo held\n"), filename="held.cfg")})
        _held = _HeldBody(_mp, lambda: _hb_user(hb_uid, api_token=None))
        r = app.test_client().post(url, headers=bearer, input_stream=_held,
                                   content_type="multipart/form-data; boundary=%s" % _bd)
        check("held body: an upload whose token is revoked mid-body is refused, and stores nothing",
              _held.arrived and _hb_user(hb_uid)["token"] is None
              and r.status_code == 401 and len(seen) == 1,
              "the upload was stored after its token was revoked (read=%s, %d, %r)"
              % (_held.arrived, r.status_code, seen))
    finally:
        _hb_sf._store_upload = _saved


def _check_held_body_forgets_the_grants_memo(hb_uid):
    """Forgetting the identity drops _groups_with_grants' per-request memo, under its real name."""
    with app.test_request_context("/"):
        from flask import g as _hb_g
        auth._groups_with_grants(db.session.get(User, hb_uid))
        _primed = "_groups_with_grants_cache" in _hb_g
        auth._heldbody_forget_identity()
        check("held body: re-loading the identity also drops the per-request grants memo",
              _primed and "_groups_with_grants_cache" not in _hb_g,
              "primed=%s — a stale memo would answer the checks ahead with the old groups"
              % _primed)


def _check_held_bodies():
    """Every held-body case, then the tags they may have made."""
    hb_uid, hb_gid, tok = _hb_fixture()
    try:
        bearer = _check_held_json_body_with_a_token(hb_uid, tok)
        _check_held_body_not_read_when_signed_out()
        _check_held_json_body_demoted(hb_uid, hb_gid, bearer)
        _check_held_body_meets_the_password_gate(hb_uid, bearer)
        _check_held_body_row_kept_alive(hb_uid, hb_gid, bearer)
        _check_held_json_body_with_a_cookie(hb_uid)
        _check_held_body_with_csrf_on(hb_uid)
        _check_held_upload(hb_uid, bearer)
        _check_held_body_forgets_the_grants_memo(hb_uid)
    finally:
        from panel.db.models import ServerTag
        with app.app_context():
            for _t in ServerTag.query.filter(ServerTag.name.like(tag + "_hb%")).all():
                db.session.delete(_t)
            db.session.commit()


def _check_superadmin_full_access():
    """A superadmin still has full access."""
    global code, p
    # ── Superadmin sanity: still full access ──
    ca = client_as(admin_id)
    for p in ["/users", "/groups", "/logs", "/remotes", "/server-management", "/tailscale",
              "/settings", "/notifications"]:
        code = ca.get(p).status_code
        check("superadmin CAN access %s" % p, code == 200, "got %d" % code)


try:
    _check_limited_user_denied_pages()
    _check_specs_os_slug_for_installers()
    _check_failed_install_redirects_terminate()
    _check_uninstall_lands_on_openable_page()
    _check_retry_install_matches_its_route()
    _check_vps_prep_refuses_panel_host()
    _check_tailscale_migrate_refuses_panel_host()
    _check_vps_prep_allows_a_remote_host()
    _check_limited_user_server_actions()
    _check_legacy_super_admin_grant()
    _check_denials_and_limited_pages()
    _check_tailscale_page_is_host_scoped()
    _check_unauthenticated()
    _check_group_admin_cannot_grant_more()
    _check_membership_escalation()
    _check_superadmin_edit_refused_by_name()
    _check_join_needs_the_hosts_too()
    _check_user_form_offers_only_joinable()
    _check_manage_users_needs_the_perms()
    _check_manage_users_needs_the_objects()
    _check_manage_users_custom_commands()
    _check_custom_command_peers_untouched()
    _check_view_logs_scope_and_users_add()
    _check_group_admin_cannot_widen_reach()
    _check_groups_page_offers_only_grantable()
    _check_group_summaries_name_nothing_hidden()
    _check_permission_boxes_are_filtered()
    _check_unshowable_server_grant_survives()
    _check_empty_host_list_wording()
    _check_group_edit_scope()
    _check_audit_scope_by_object()
    _check_bulk_actions_per_id()
    _check_setup_endpoints_stay_shut()
    _check_healthz_before_setup()
    _check_invites()
    _check_invite_fixtures_survive()
    _check_delete_user_offers_only_allowed()
    _check_users_page_reach_and_sa_delete()
    _check_delete_user_ordinary_and_self()
    _check_held_bodies()
    _check_superadmin_full_access()
finally:
    for _m, _n, _f in _traps_saved:
        setattr(_m, _n, _f)
    _ms_rb.threading = _ms_threading_saved
    if any(seeded.values()):
        # The whole DB was seeded by us (it started empty) — drop the throwaway DB file(s) entirely,
        # so nothing is left behind (a leftover empty panel.db would make smoke_test skip next run).
        try:
            with app.app_context():
                db.session.remove()
                db.engine.dispose()
        except Exception:  # nosec B110 - best-effort teardown of a throwaway DB
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
    # No login by design: login, the setup wizard, an invite redemption. The setup Tailscale
    # endpoints carry their own gate — _setup_ts_ok() — because no login exists yet.
    #
    # setup_wizard was never exempt here, and passed only because its admin step's
    # `filter_by(is_superadmin=True)` put a gate token in its source by accident. Its real gates are
    # the SetupState lock and _setup_owner_ok(), which no token here names; moving the admin step
    # into a helper (route_helpers.py) turned that coincidence red. Named, rather than kept passing
    # on a word that was never a permission check.
    "login", "login_2fa", "redeem_invite", "force_password_change", "setup_wizard",
    "api_setup_ts_install", "api_setup_ts_serve", "api_setup_ts_up",
    # The finished wizard's "Restart now". Gated on _setup_owner_ok() — the browser that ran the
    # wizard, or a signed-in superadmin — and it restarts only while a stored loopback bind is
    # waiting for the next start; setup_wizard_test drives both refusals.
    "setup_restart",
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
# And resolved to the function each call REALLY reaches, by tests/audit_callgraph.py. It followed
# callees by BARE NAME, so a view counted as audited when any function sharing a name with one of
# its callees logged. `subprocess.run` matched a function named `run` that logs, so a route that
# reached a subprocess passed (POST /setup and /setup/restart wrote no row and passed that way);
# the wizard's Tailscale routes passed on system_ops._run, named like two workers that log. Now a
# call counts only when that exact function, found through its imports, module attributes and
# scopes, reaches log_action. One the walk cannot resolve counts as silent, so a route that logs
# only through it fails here and has to be read.
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
    # SSH reachability probe. It records is_online / last_seen, and pins the key it met on a host
    # with no pin yet, exactly as that host's next connection from anywhere in the panel would
    # (_persist_host_key), and none of those write a row either.
    "test_remote",
    "notifications_test",            # sends one test notification to the configured channel
}
import importlib.util as _aud_iu  # noqa: E402
# Loaded by path: tests/ is not a package, so a regular `tests` package installed by some
# dependency would be imported instead of it.
_aud_spec = _aud_iu.spec_from_file_location("audit_callgraph",
                                            os.path.join(_ROOT, "tests", "audit_callgraph.py"))
_aud_cg = _aud_iu.module_from_spec(_aud_spec)
_aud_spec.loader.exec_module(_aud_cg)


def _aud_views():
    """{endpoint: view function, unwrapped} for every endpoint that accepts a mutating method."""
    out = {}
    for _r in app.url_map.iter_rules():
        if _r.methods & {"POST", "PUT", "DELETE", "PATCH"} and _r.endpoint not in out:
            out[_r.endpoint] = (str(_r), inspect.unwrap(app.view_functions[_r.endpoint]))
    return out


def _aud_key(graph, view):
    """The call-graph key of a view function: its module, __qualname__ and first line."""
    code = getattr(view, "__code__", None)
    if code is None:
        return None
    return graph.function_key(getattr(view, "__module__", ""), view.__qualname__,
                              code.co_firstlineno)


_aud_graph = _aud_cg.CallGraph.from_tree(_ROOT, sorted(
    {*pathlib.Path(_ROOT, "panel").rglob("*.py"), *pathlib.Path(_ROOT).glob("*.py")}))
_aud_eps = _aud_views()
_unaudited, _aud_indirect = [], []
for _ep, (_rule_s, _view) in sorted(_aud_eps.items()):
    _k = _aud_key(_aud_graph, _view)
    if _k is not None and len(_aud_graph.chain(_k)) > 2:
        _aud_indirect.append(_ep)
    if _ep not in _NO_AUDIT_OK and (_k is None or not _aud_graph.logs(_k)):
        _unaudited.append("%s (%s%s)" % (_rule_s, _ep, "" if _k else ", source not found"))
check("audit gate: the scan found mutating endpoints to check", len(_aud_eps) > 40,
      "only %d mutating endpoints seen" % len(_aud_eps))
check("audit gate: a view that logs only through a helper is followed into it (control)",
      {"api_server_action", "api_panel_security_whitelist"} <= set(_aud_indirect),
      repr(_aud_indirect))
check("every mutating endpoint writes an audit entry (or is listed as having nothing to audit)",
      not _unaudited,
      "; ".join(sorted(_unaudited)[:5]) + " — call log_action(), or add the endpoint to "
      "_NO_AUDIT_OK with the reason it has nothing to record")
_aud_stale = sorted(_e for _e in _NO_AUDIT_OK if _e not in _aud_eps
                    or _aud_key(_aud_graph, _aud_eps[_e][1]) is None
                    or _aud_graph.logs(_aud_key(_aud_graph, _aud_eps[_e][1])))
check("audit gate: every _NO_AUDIT_OK entry is a mutating endpoint that really writes no row",
      not _aud_stale, repr(_aud_stale))

# The resolver itself, on modules made for it: each route's only candidate for an audit row is a
# function whose NAME matches one that logs. By bare name every one of them was audited.
_AUD_FIXTURE = {
    "panel.security.auth": ("def log_action(user, action, **kw):\n    return None\n", False),
    "fx": ("", True),
    "fx.logs": ("from panel.security.auth import log_action\n"
                "def _run(cmd=None):\n    log_action(None, 'x')\n", False),
    "fx.quiet": ("def _run(cmd=None):\n    return cmd\n", False),
    "fx.pkg": ("from fx.pkg import a, b\n_MODULES = (a, b)\n"
               "def __getattr__(name):\n    return None\n", True),
    "fx.pkg.a": ("def helper():\n    return 1\n", False),
    "fx.pkg.b": ("from fx import logs\ndef helper():\n    logs._run()\n"
                 "def only_here():\n    logs._run()\n", False),
    "fx.routes": (textwrap.dedent('''
        import threading
        from fx import quiet as so, logs, pkg
        from fx.quiet import _run as _quiet_run
        from panel.security import auth

        def by_module_attr():
            so._run("ls")

        def by_from_import():
            _quiet_run("ls")

        def by_shadowing_parameter(logs):
            logs._run()

        def by_first_pep562_module():
            pkg.helper()

        def by_pep562_module():
            pkg.only_here()

        def by_real_worker():
            logs._run()

        def by_thread_target():
            threading.Thread(target=logs._run).start()

        def by_module_log_action():
            auth.log_action(None, "y")

        class Svc:
            def work(self):
                logs._run()

            def go(self):
                self.work()

        def register(app):
            def _inner():
                logs._run()

            def by_closure():
                _inner()
            return by_closure
        '''), False),
}
_aud_fx = _aud_cg.CallGraph(_AUD_FIXTURE)
_aud_fx_logs = {q: _aud_fx.logs(_aud_fx.function_key("fx.routes", q)) for q in (
    "by_module_attr", "by_from_import", "by_shadowing_parameter", "by_first_pep562_module",
    "by_real_worker", "by_thread_target", "by_module_log_action", "by_pep562_module", "Svc.go",
    "register.<locals>.by_closure")}
check("audit gate: a call that only shares its name with a function that logs is not an audit row",
      not any(_aud_fx_logs[q] for q in ("by_module_attr", "by_from_import",
                                         "by_shadowing_parameter", "by_first_pep562_module")),
      repr(_aud_fx_logs))
check("audit gate: ...while the function that does log is followed however it is reached (control)",
      all(_aud_fx_logs[q] for q in ("by_real_worker", "by_thread_target", "by_module_log_action",
                                    "by_pep562_module", "Svc.go", "register.<locals>.by_closure")),
      repr(_aud_fx_logs))
# ── an audit row about a server or host names it by ID ─────────────────────────────────────────
# audit_scope decides who reads a row from AuditLog.game_server_id / remote_id, which log_action
# records only from its server= / remote= arguments. A call whose target is a server's or a host's
# name and passes neither writes a row nobody but its actor can read; one that passes them with an
# action the upgrade's backfill does not know leaves that action's OLD rows unreadable; and one
# that passes them with an ACCOUNT action would put someone's sign-in history in front of a
# server's viewers. Read from the source, as an AST, across panel/ and app.py.
from panel.db import models as _axm  # noqa: E402
from panel.routes.audit import _ACCOUNT_ACTIONS as _AX_ACCOUNT  # noqa: E402


def _ax_like(pattern):
    """A regex for a SQL LIKE pattern written with a backslash escape."""
    import re as _ax_re
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out, i = out + _ax_re.escape(pattern[i + 1]), i + 2
            continue
        out += ".*" if ch == "%" else "." if ch == "_" else _ax_re.escape(ch)
        i += 1
    return _ax_re.compile(out + r"\Z")


def _ax_shapes(node):
    """Every action name an action expression can produce, with 'Q' for the parts built at run time."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _ax_shapes(node.body) + _ax_shapes(node.orelse)
    if isinstance(node, ast.JoinedStr):
        return ["".join(v.value if isinstance(v, ast.Constant) else "Q" for v in node.values)]
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)):
        return [node.left.value.replace("%s", "Q").replace("%d", "Q")]
    return [None]                               # a bare variable: named in _AX_ACTION_FROM_CALLER


def _ax_names(expr, var):
    return expr is not None and any(
        isinstance(n, ast.Attribute) and n.attr == "name" and isinstance(n.value, ast.Name)
        and n.value.id == var for n in ast.walk(expr))


# Calls whose action is a parameter, with where the real names come from.
_AX_ACTION_FROM_CALLER = {
    "_record_backup_outcome",   # its callers pass "scheduled_backup" / "queued_backup"
}
_ax_bad, _ax_counts = [], {"server": 0, "remote": 0}
_ax_srv = ([_ax_like(p) for p in _axm.AUDIT_SERVER_ACTION_LIKE], _axm.AUDIT_SERVER_ACTIONS)
_ax_host = ([_ax_like(p) for p in _axm.AUDIT_HOST_ACTION_LIKE],
            _axm.AUDIT_HOST_ACTIONS | _axm.AUDIT_HOST_ACTIONS_CALL_ONLY)
for _f in sorted({*pathlib.Path(_ROOT, "panel").rglob("*.py"), pathlib.Path(_ROOT, "app.py")}):
    _tree = ast.parse(_f.read_text(encoding="utf-8"))
    _fn_of = {}
    for _fd in ast.walk(_tree):
        if isinstance(_fd, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for _n in ast.walk(_fd):
                _fn_of.setdefault(id(_n), _fd.name)
    for _n in ast.walk(_tree):
        if not (isinstance(_n, ast.Call)
                and getattr(_n.func, "id", getattr(_n.func, "attr", None)) == "log_action"):
            continue
        _where = "%s:%d" % (_f.relative_to(_ROOT), _n.lineno)
        _kw = {k.arg: k.value for k in _n.keywords}
        _tgt = _kw.get("target", _n.args[2] if len(_n.args) > 2 else None)
        for _obj, _var in (("server", "gs"), ("remote", "remote")):
            if _ax_names(_tgt, _var) and _obj not in _kw:
                _ax_bad.append("%s names %s.name but passes no %s=" % (_where, _var, _obj))
        for _obj, (_likes, _exact) in (("server", _ax_srv), ("remote", _ax_host)):
            if _obj not in _kw:
                continue
            _ax_counts[_obj] += 1
            for _shape in _ax_shapes(_n.args[1] if len(_n.args) > 1 else _kw.get("action")):
                if _shape is None:
                    if _fn_of.get(id(_n)) not in _AX_ACTION_FROM_CALLER:
                        _ax_bad.append("%s: %s= with an action this gate cannot read" % (_where, _obj))
                elif _shape in _AX_ACCOUNT:
                    _ax_bad.append("%s: %s= on the ACCOUNT action %r" % (_where, _obj, _shape))
                elif _shape not in _exact and not any(_l.match(_shape) for _l in _likes):
                    _ax_bad.append("%s: %s= on %r, which models.AUDIT_%s_ACTIONS does not list"
                                   % (_where, _obj, _shape, "SERVER" if _obj == "server" else "HOST"))
check("audit ids: the scan found the server and host rows to check (positive control)",
      _ax_counts["server"] >= 40 and _ax_counts["remote"] >= 30,
      "server=%d remote=%d call sites — the check below proves nothing" % (
          _ax_counts["server"], _ax_counts["remote"]))
check("audit ids: every row about a server or host passes it, with an action the backfill knows",
      not _ax_bad, "; ".join(_ax_bad[:5]))

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
