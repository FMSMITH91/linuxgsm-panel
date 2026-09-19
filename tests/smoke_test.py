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
from panel.ops.ssh_manager import _core as _sm_core
from panel.ops.ssh_manager import cron as _sm_cron
from panel.ops.ssh_manager import game as _sm_game
from panel.ops.ssh_manager import hosts as _sm_hosts   # the stub seam: stubbed by MODULE,
# because every caller now reaches these through the module rather than binding them.

from panel.core.config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE
from panel.core.validation import password_problem as auth_password_problem

# Never clobber a real install: only run against a fresh, throwaway data dir.
if DB_PATH.exists():
    print("SKIP: %s already exists — the smoke test only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}

# A config that was already on disk is RESTORED BYTE-FOR-BYTE at the end. Every DB-owning suite
# has to edit config.json to boot the app, and deleting it only when the suite CREATED it is not
# enough: on a developer's tree the file is theirs and the edits stay behind. That is not
# hypothetical — a leftover ssh_timeout=1 makes the UNIT suite's "no override -> the documented
# default" check fail, in a different suite, pointing at config rather than at whoever wrote it.
# tools/smoke-local.sh sidesteps this by copying to a throwaway tree; running a suite in-tree
# (which CI does, where no config pre-exists) should not behave differently.
_CONFIG_SNAPSHOT = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

# Mark setup complete in config BEFORE the app loads it — is_setup_complete()
# requires both this flag and a SetupState(complete=True) row (added below).
from panel.core.config import load_config, save_config
_cfg = load_config()
_cfg["setup_complete"] = True
# Fixture hosts are 192.0.2.0/24 (TEST-NET-1) — reserved, and therefore BLACKHOLED rather than
# refused. Every connection to one costs the full ssh_timeout instead of returning instantly,
# and this suite makes 175 of them (5 hosts x 35 probes from the background watchers). At the
# 10s default that was the entire cost of CI: the "run all checks" step took 729s on a runner
# against ~21s locally, where tools/smoke-local.sh refuses egress and the same connects fail at
# once. Three matrix jobs made it ~37 minutes a push, spent waiting on addresses that are
# guaranteed unreachable BY DESIGN.
#
# Nothing here asserts on how LONG a host takes to be unreachable, only that it is — so 1s (the
# floor _ssh_connect_timeout() clamps to) buys the identical outcome. Set before the app loads,
# beside setup_complete, because the background watchers start inside create_app().
_cfg["ssh_timeout"] = 1
save_config(_cfg)

# LinuxGSM's serverlist is fetched at runtime rather than committed (see lgsm_data), and this
# suite runs with outbound access BLOCKED — as it should, since it must not depend on GitHub. Seed
# the cache so the game list is populated, otherwise every game_type validation below fails and the
# install/import assertions fail for a reason that has nothing to do with what they test.
from panel.services import lgsm_data as _lgsm_data
import tempfile as _lgsm_tempfile
import pathlib as _lgsm_pathlib
_lgsm_data._CACHE_DIR = _lgsm_pathlib.Path(_lgsm_tempfile.mkdtemp())
_lgsm_data._CACHE_DIR.mkdir(parents=True, exist_ok=True)
(_lgsm_data._CACHE_DIR / _lgsm_data.SERVERLIST).write_text(
    "shortname,gameservername,gamename,os\n"
    "csgo,csgoserver,Counter-Strike: Global Offensive,ubuntu-24.04\n"
    "gmod,gmodserver,Garry's Mod,ubuntu-24.04\n"
    "cod,codserver,Call of Duty,ubuntu-24.04\n"
    "rust,rustserver,Rust,ubuntu-24.04\n"
    # The GMod-mountable Source games. A real panel supports all of these, and the discovery and
    # import checks below are about telling mountable CONTENT from a server — with the list cut to
    # four games those rows were dropped as "unsupported" instead, so the assertions passed
    # whether or not the code under test did anything. Verified by mutation after adding them.
    "css,cssserver,Counter-Strike: Source,ubuntu-24.04\n"
    "tf2,tf2server,Team Fortress 2,ubuntu-24.04\n"
    "dods,dodsserver,Day of Defeat: Source,ubuntu-24.04\n"
    "l4d2,l4d2server,Left 4 Dead 2,ubuntu-24.04\n", encoding="utf-8")
(_lgsm_data._CACHE_DIR / _lgsm_data.DEPS).write_text(
    "all,bc,binutils,curl\nsteamcmd,lib32gcc-s1,steamcmd\ncsgo,lib32tinfo6\n", encoding="utf-8")
_lgsm_data._mem.clear()

from app import create_app
from panel.db.models import db, User, Group, RemoteServer, GameServer, SetupState, CustomCommand
from panel.security import auth
from panel.ops import backup as bk

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


def page_with_assets(client, path):
    """The page's HTML plus the text of every non-vendor static .js/.css it pulls in.

    base.html serves its own CSS and JS as cacheable static files rather than inlining them, so a
    check that greps a page for a handler or a rule has to follow the reference. That is a STRONGER
    assertion than the old inline grep, not a weaker one: it only passes if the asset is really
    linked from this page and really served."""
    import re as _re_pa
    html = client.get(path).get_data(as_text=True)
    parts = [html]
    for url in _re_pa.findall(r'(?:src|href)="([^"]+\.(?:js|css)(?:\?[^"]*)?)"', html):
        if url.startswith("/") and "/static/" in url and "/vendor/" not in url:
            r = client.get(url)
            if r.status_code == 200:
                parts.append(r.get_data(as_text=True))
    return "\n".join(parts)


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
    if _CONFIG_SNAPSHOT is not None:
        try:
            CONFIG_FILE.write_bytes(_CONFIG_SNAPSHOT)   # undo our edits to someone else's config
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
        from panel.core.config import encrypt_secret
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

    # ── The notifications page must actually OFFER each channel ───────────────────────────────
    # "/notifications renders 200" passes just as well with a channel's whole card missing, which
    # is how a half-wired provider ships: the backend supports it and nobody can reach it.
    _nt_html = c.get("/notifications").get_data(as_text=True)
    for _field in ("ntfy_enabled", "ntfy_topic", "ntfy_server", "ntfy_token"):
        check("notifications page: the ntfy form offers %s" % _field,
              ('name="%s"' % _field) in _nt_html)
    check("notifications page: ntfy has a Send test button wired to the dispatcher",
          'data-args=\'["ntfy", "@self"]\'' in _nt_html)
    check("notifications page: the stored ntfy token is NOT sent to the browser",
          "TESTONLY" not in _nt_html)

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

    # Every provider the endpoint advertises must be one the WRITE path will actually store. A
    # provider present in the GET but filtered out of the POST would render, accept input and
    # silently drop it \u2014 the read and write sides derive from the same list, and this is what
    # holds them together end to end.
    _al_provs = (al.get_json() or {}).get("providers") or []
    check("alerts: ntfy is offered to the per-server UI",
          any(_p.get("id") == "ntfy" for _p in _al_provs),
          str(sorted(_p.get("id") for _p in _al_provs)))
    # Asserted against the write path's OWN key set, not against the response: this endpoint
    # answers {"success": ...} whether or not it silently dropped a key, so a status-only check
    # would pass for a provider whose fields never get written.
    from panel.routes.server_files import _ALERT_KEY_SET as _AKS_SMOKE
    _al_keys = [k for _p in _al_provs for k in [_p["toggle"]] + [f["key"] for f in _p["fields"]]]
    _al_dropped = [k for k in _al_keys if k not in _AKS_SMOKE]
    check("alerts: POST accepts every key the GET advertises (no provider is write-only-in-name)",
          not _al_dropped, "the write path would silently drop: %s" % _al_dropped)

    # ── uninstall: a FAILED userdel must not delete the panel's row ───────────────────────────
    # This endpoint used to capture run_privileged's rc, hand it to log_action, and then delete the
    # row and answer {"success": true} no matter what it was. A userdel that failed therefore left
    # the account, its home and every game file on the host with no row left to manage them from —
    # firewall rules already removed, next install of that game colliding with the surviving user,
    # and the operator told it had worked. run_privileged RETURNS rc; it never raises, so nothing
    # else caught it.
    #
    # Driven through the real endpoint with run_privileged stubbed per exit code, because the bug
    # was in the branch AFTER the call, not in the call.
    from panel.db.models import GameServer as _UGS
    _uapp = sys.modules["app"]      # _appmod is not bound until later in this file
    _u_orig = _sm_core.run_privileged
    try:
        for _rc, _expect_gone, _label in ((1, False, "generic failure"),
                                          (4, False, "unexpected code"),
                                          (0, True, "removed"),
                                          (6, True, "no such user"),
                                          (12, True, "removed, home left")):
            with app.app_context():
                _rm = RemoteServer.query.first()
                _tmp = _UGS(remote_id=_rm.id, name="uninst%d" % _rc, short_name="uninst%d" % _rc,
                            game_type="gmod", port=28900 + _rc, installed=True, status="offline")
                db.session.add(_tmp); db.session.commit()
                _tid = _tmp.id
            _sm_core.run_privileged = (lambda rc: (lambda *a, **k: ("", "userdel: boom", rc)))(_rc)
            # X-Requested-With is what the page's fetch wrapper sends, and what _wants_json()
            # keys on — without it this endpoint answers with a flash+redirect instead.
            _resp = c.post("/servers/%d/delete" % _tid, json={},
                           headers={"X-Requested-With": "XMLHttpRequest"})
            with app.app_context():
                _still = _UGS.query.get(_tid) is not None
            check("uninstall: rc=%d (%s) -> row %s" % (_rc, _label, "deleted" if _expect_gone else "KEPT"),
                  _still != _expect_gone, "row %s" % ("survived" if _still else "was deleted"))
            if not _expect_gone:
                check("uninstall: rc=%d reports failure, not success" % _rc,
                      (_resp.get_json() or {}).get("success") is False,
                      "got %r" % ((_resp.get_json() or {}).get("success"),))
            with app.app_context():   # clean up whatever survived
                _left = _UGS.query.get(_tid)
                if _left: db.session.delete(_left); db.session.commit()
    finally:
        _sm_core.run_privileged = _u_orig

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
    # Retention is TYPED in the UI now rather than picked from a list, which changes two things the
    # API has to hold up: the browser needs the server's own bounds (it cannot invent them and stay
    # in step), and an out-of-range number has to come back CLAMPED in the response so the page can
    # show what was really stored instead of echoing what was typed.
    check("backups: the response carries the retention bounds the UI enforces",
          isinstance(_blj.get("limits"), dict)
          and _blj["limits"].get("full_keep", {}).get("max") == bk.MAX_FULL_KEEP
          and _blj["limits"].get("keep_days", {}).get("max") == bk.MAX_KEEP_DAYS,
          str(_blj.get("limits"))[:80])
    _over = c.post("/api/panel/backup/settings",
                   json={"enabled": True, "keep_days": 99999, "full_interval_days": 7,
                         "full_keep": 999}).get_json() or {}
    check("backups: an out-of-range keep comes back clamped, not echoed",
          _over.get("settings", {}).get("keep_days") == bk.MAX_KEEP_DAYS
          and _over.get("full", {}).get("keep") == bk.MAX_FULL_KEEP,
          "%s / %s" % (_over.get("settings"), _over.get("full")))
    c.post("/api/panel/backup/settings", json={"enabled": True, "keep_days": 7,
                                               "full_interval_days": 7, "full_keep": 2})

    # A per-server override is set by typing a number and CLEARED by emptying the box. A <select>
    # could carry a labelled "Default" option; a number input says it by being empty, so "" has to
    # mean the same thing to the endpoint as the old "default" did.
    _sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
                  json={"interval": "default", "keep": "5"}).get_json() or {}
    check("backups: a typed per-server keep sets an override",
          _sch.get("schedule", {}).get("keep") == 5 and _sch["schedule"].get("keep_set") is True,
          str(_sch.get("schedule")))
    _sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
                  json={"interval": "default", "keep": "999"}).get_json() or {}
    check("backups: a per-server keep over the maximum is clamped",
          _sch.get("schedule", {}).get("keep") == bk.MAX_FULL_KEEP, str(_sch.get("schedule")))
    _sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
                  json={"interval": "default", "keep": ""}).get_json() or {}
    check("backups: an EMPTY per-server keep clears the override (inherits the default)",
          _sch.get("schedule", {}).get("keep_set") is False, str(_sch.get("schedule")))

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
    # reset_password=on is the real reset path now (the password is generated, never posted), so
    # this has to drive THAT to still be testing the superadmin guard rather than an ignored field.
    dc.post("/users/%d/edit" % admin2_id,
            data={"is_superadmin": "on", "is_active": "on", "reset_password": "on"})
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

    # ── Editing a host must drop its pooled SSH client ────────────────────────────────────────
    # A pooled client is valid only while the row it was opened from still names the same host and
    # the same credential. edit_remote rewrote username/host/port/auth_method/auth_credential and
    # committed without closing anything, so: a ROTATED CREDENTIAL kept authenticating with the old
    # one for as long as the 30s keepalive held the socket open, and a REPOINTED host orphaned its
    # cache entry for the life of the process (close_connection builds the key from the row's
    # CURRENT values, so the old key was no longer spellable). Asserted through the real route, not
    # the listener, because the route is what regressed.
    class _FakePooled:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    def _pool_one(rid):
        """Put a fake client in the pool under the key that host currently spells."""
        with app.app_context():
            _r = db.session.get(RemoteServer, rid)
            _k = _sm_core._conn_key(_r.username, _r.host, _r.port)
        _c = _FakePooled()
        _sm_core._connections[_k] = _c
        _sm_core._remote_conn_keys[rid] = _k
        return _k, _c

    _ek, _ec = _pool_one(remote2_id)
    c.post("/remotes/%d/edit" % remote2_id,
           data={"name": "smoke-host-2", "host": "127.0.0.1", "ssh_port": "22",
                 "ssh_user": "root", "auth_method": "password", "credential": "rotated-secret"})
    check("edit_remote: rotating the credential closes the pooled SSH client", _ec.closed)
    check("edit_remote: ...and drops it from the pool", _ek not in _sm_core._connections)

    _ek2, _ec2 = _pool_one(remote2_id)
    c.post("/remotes/%d/edit" % remote2_id,
           data={"name": "smoke-host-2", "host": "127.0.0.2", "ssh_port": "22",
                 "ssh_user": "root", "auth_method": "password"})
    check("edit_remote: repointing the host closes the client opened under the OLD key", _ec2.closed)
    check("edit_remote: ...leaving no entry under a key nothing can name again",
          _ek2 not in _sm_core._connections)

    _ek3, _ec3 = _pool_one(remote2_id)
    c.post("/remotes/%d/edit" % remote2_id,
           data={"name": "renamed-only", "host": "127.0.0.2", "ssh_port": "22",
                 "ssh_user": "root", "auth_method": "password"})
    check("edit_remote: a rename alone does NOT churn the pool",
          not _ec3.closed and _ek3 in _sm_core._connections)
    _sm_core._connections.pop(_ek3, None)
    _sm_core._remote_conn_keys.pop(remote2_id, None)

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

    # ── The firewall PAGE survives a host it cannot reach ────────────────────────────────────
    # A down / rebooting host makes remote_ufw_status() raise ConnectionError. The API route has
    # always caught that and answered "unreachable"; the page route called the same function bare
    # and rendered a 500 — so the one page whose job is managing a remote broke precisely when
    # that remote had a problem. Stub the raise rather than depending on a host being down, and
    # restore it in finally: this file is a flat script, so a leaked stub changes every later check.
    import panel.routes.remote_vps as _rvps
    _real_ufw = _rvps.remote_ufw_status
    try:
        def _refuse(_server):
            raise ConnectionError("smoke: host is down")
        _rvps.remote_ufw_status = _refuse
        _fw = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
        check("firewall page: an unreachable host renders, not 500",
              _fw.status_code == 200, "got %d" % _fw.status_code)
        check("firewall page: ...and says it couldn't read the firewall, not that UFW is missing",
              b"can't reach this host" in _fw.data and b"UFW is not installed" not in _fw.data,
              "the unreachable banner is what should render")
    finally:
        _rvps.remote_ufw_status = _real_ufw

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

    # A TOTP code is valid for ~90s (its step plus one either side for skew). Accepting it on
    # "is it valid" alone lets a code observed once — a phishing proxy, a shoulder-surf, a leaked
    # log — be replayed for the rest of that window. Each step must be spendable exactly once.
    import pyotp as _po
    with app.app_context():
        _u2 = User.query.filter_by(username="smoke_2fa").first()
        _sec2 = _u2.totp_secret_plain
    _code = _po.TOTP(_sec2).now()
    t1 = app.test_client()
    t1.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
    r1 = t1.post("/login", data={"totp_code": _code})
    check("2FA: a valid TOTP code signs the user in (302)", r1.status_code == 302,
          "got %d" % r1.status_code)
    t2 = app.test_client()
    t2.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
    r2 = t2.post("/login", data={"totp_code": _code})
    check("2FA: the SAME TOTP code cannot be replayed while still in its window",
          r2.status_code != 302, "got %d" % r2.status_code)
    with app.app_context():
        _u2 = User.query.filter_by(username="smoke_2fa").first()
        check("2FA: the spent timestep is recorded", (_u2.last_totp_step or 0) > 0,
              "last_totp_step=%r" % _u2.last_totp_step)

    # The setup wizard is UNAUTHENTICATED by necessity. Its lock must not depend on config.json:
    # load_config() falls back to DEFAULT_CONFIG (setup_complete=False) on any unreadable/invalid
    # file, so gating on is_setup_complete() reopened the wizard on a configured install, where
    # step=welcome rewrites bind_host/port and step=remote_server makes the panel SSH out.
    _cfg_backup = CONFIG_FILE.read_bytes()
    try:
        CONFIG_FILE.write_text("{ not valid json")
        from panel.core.config import load_config as _lc
        check("setup lock: the corrupt-config precondition really does hold",
              _lc().get("setup_complete") is False, "config still reads as complete")
        _sw = app.test_client().post("/setup", data={"step": "welcome", "site_title": "pwned",
                                                     "bind_host": "0.0.0.0", "port": "9999"})
        check("setup lock: a completed install refuses step=welcome even with config.json unreadable",
              _lc().get("bind_host") != "0.0.0.0" and _lc().get("site_title") != "pwned",
              "bind_host=%r title=%r" % (_lc().get("bind_host"), _lc().get("site_title")))
        _sw2 = app.test_client().post("/setup", data={"step": "remote_server", "action": "add",
                                                      "name": "evil-smoke", "host": "192.0.2.66"})
        with app.app_context():
            check("setup lock: ...and refuses step=remote_server too",
                  RemoteServer.query.filter_by(name="evil-smoke").first() is None)
        check("setup lock: both are redirects, not 5xx",
              _sw.status_code < 500 and _sw2.status_code < 500,
              "%d/%d" % (_sw.status_code, _sw2.status_code))
    finally:
        CONFIG_FILE.write_bytes(_cfg_backup)

    # Every one of these maps is keyed by a database row id, and SQLite hands a deleted row's id
    # to the next INSERT — so a new server inherits the old one's alert flags and, via
    # _max_players_cache, its CAPACITY. #81 pruned one such map; these are its siblings.
    _am2 = sys.modules["app"]
    _monmod = sys.modules["panel.services.monitoring"]   # functions moved here resolve their deps HERE
    _ps = sys.modules["panel.core.panel_state"]      # the shared caches now live here
    _dead_r, _dead_s = 987654, 876543
    _ps._monitor_state["remotes"][_dead_r] = True
    _ps._monitor_state["disk"][_dead_r] = True
    _ps._monitor_state["load"][_dead_r] = {"cpu_alerted": True}
    _ps._monitor_state["servers"][_dead_s] = True
    _ps._server_full_alerted[_dead_s] = True
    _ps._server_peak_notified[_dead_s] = 1.0
    _ps._expected_offline[_dead_s] = 1.0
    _ps._cron_restart_pending[_dead_s] = True
    _ps._max_players_cache[_dead_s] = 64
    _ps._player_counts[_dead_s] = {"count": 7, "ts": 1.0}
    _ps._reboot_when_empty[_dead_r] = {"by": "x", "since": 1.0}
    # #85's snapshot: pruned by its own sweep once a day, but it is read on every page load by
    # /api/os-updates/summary, so it is pruned here too.
    _ps._os_update_seen[_dead_r] = {"name": "ghost-host", "count": 3, "security": 1,
                                     "packages": [], "at": 1.0}
    with app.app_context():
        _live_r = {r.id for r in RemoteServer.query.all()}
        _live_s = {row[0] for row in db.session.query(GameServer.id).all()}
        _monmod._forget_deleted_rows(_live_r, _live_s)
    _leftover = [n for n, m, k in (
        ("_monitor_state[remotes]", _ps._monitor_state["remotes"], _dead_r),
        ("_monitor_state[disk]", _ps._monitor_state["disk"], _dead_r),
        ("_monitor_state[load]", _ps._monitor_state["load"], _dead_r),
        ("_monitor_state[servers]", _ps._monitor_state["servers"], _dead_s),
        ("_server_full_alerted", _ps._server_full_alerted, _dead_s),
        ("_server_peak_notified", _ps._server_peak_notified, _dead_s),
        ("_expected_offline", _ps._expected_offline, _dead_s),
        ("_cron_restart_pending", _ps._cron_restart_pending, _dead_s),
        ("_max_players_cache", _ps._max_players_cache, _dead_s),
        ("_player_counts", _ps._player_counts, _dead_s),
        ("_reboot_when_empty", _ps._reboot_when_empty, _dead_r),
        ("_os_update_seen", _ps._os_update_seen, _dead_r),
    ) if k in m]
    check("deleted rows: no per-row state survives for an id that no longer exists",
          not _leftover, "still holding: %s" % _leftover)
    # ...and it must not evict LIVE rows, which would silently reset every alert each sweep.
    _ps._monitor_state["servers"][gs_id] = True
    with app.app_context():
        _monmod._forget_deleted_rows({r.id for r in RemoteServer.query.all()},
                                  {row[0] for row in db.session.query(GameServer.id).all()})
    check("deleted rows: state for a LIVE server is kept",
          gs_id in _ps._monitor_state["servers"])

    # Session fixation: the authenticated session must not inherit whatever the pre-login one
    # carried. An attacker who can get a victim to browse with a cookie value of the attacker's
    # choosing would otherwise end up holding a cookie that is now authenticated as the victim.
    _fx = app.test_client()
    with _fx.session_transaction() as _sess:
        _sess["planted"] = "attacker-value"
        _sess["lang"] = "fr"
    _fx.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
    with _fx.session_transaction() as _sess:
        check("login clears pre-login session state (session fixation)",
              "planted" not in _sess, "leftover keys: %s" % sorted(_sess.keys()))
        check("login is established (the clear did not break sign-in)",
              "_user_id" in _sess, sorted(_sess.keys()))
        # The language is chosen ON the login page, so it is the one thing that must survive.
        check("login keeps the language chosen before signing in",
              _sess.get("lang") == "fr", "lang=%r" % _sess.get("lang"))
    # Log this client out again. It signed in as smoke_admin, and the session-management checks
    # further down count that account's registry rows and expect an exact number — an extra
    # logged-in client left behind here fails them from a distance. logout deletes just this
    # device's row, which is precisely the cleanup wanted.
    _fx.post("/logout")

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

        # The Bearer exemption is justified by "an API-token request carries no cookie, so there is
        # nothing for a cross-site page to ride". Exempting on the HEADER alone did not test that:
        # a request sending both a Bearer header and a session cookie skipped CSRF while flask-login
        # authenticated it from the COOKIE — the stated reason no longer held and the code could not
        # tell. (Not reachable from a browser today: a custom header forces a CORS preflight and a
        # SameSite=Lax cookie is not sent cross-site. This is the exemption resting on the condition
        # it claims, which is what makes the reasoning above check out.)
        _cookieless = app.test_client().post("/api/server/1/action", json={"action": "start"},
                                             headers={"Authorization": "Bearer not-a-real-token"})
        check("CSRF: a genuinely cookie-less Bearer POST is exempt (not a 400)",
              _cookieless.status_code != 400, "got %d" % _cookieless.status_code)

        _with_cookie = client_as(admin_id)
        _both = _with_cookie.post("/api/server/1/action", json={"action": "start"},
                                  headers={"Authorization": "Bearer not-a-real-token"})
        check("CSRF: a Bearer header alongside a SESSION COOKIE is still protected",
              _both.status_code == 400, "got %d" % _both.status_code)
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
        from panel.db.models import database_stats, optimize_database
        _st = database_stats()
        check("db-stats: reports a positive DB size", _st["size"] > 0,
              "got %r" % _st.get("size"))
        check("db-stats: audit_rows is an int count", isinstance(_st["audit_rows"], int))
        _ok, _msg, _info = optimize_database()
        check("optimize: VACUUM/ANALYZE runs cleanly", _ok is True)
        check("optimize: reports before/after sizes with a live file",
              "before" in _info and _info.get("after", 0) > 0)

        # ── Debug report: generates, and never leaks the session/credential secrets ──
        from panel.ops.system_ops import generate_debug_report
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
        from panel.db.models import _run_light_migrations

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

        # invite.revoked_at: an install that upgrades INTO revocation must get the column, or every
        # invite page 500s on a column the model expects and the table does not have.
        def _icols():
            return {col["name"] for col in _inspect(db.engine).get_columns("invite")}
        try:
            db.session.execute(_t("ALTER TABLE invite DROP COLUMN revoked_at"))
            db.session.commit()
            _idropped = True
        except Exception:
            db.session.rollback()
            _idropped = False
        if _idropped:
            check("migrate: a pre-feature DB really is missing invite.revoked_at",
                  "revoked_at" not in _icols())
            _run_light_migrations()
            check("migrate: update re-adds invite.revoked_at", "revoked_at" in _icols(),
                  "an upgraded install would 500 on every invite page without it")

        # ...and the same for INDEXES, which create_all() only ever puts on a FRESH database.
        # The history charts query metric_sample/host_sample by (id, ts) together; without the
        # composite index SQLite falls back to a single-column one and either sorts the whole
        # slice in a temp B-tree or scans half the table. Measured at the real 1/min cadence over
        # the 14-day retention window: metric_sample 3.6ms -> 2.5ms, host_sample 7.7ms -> 2.7ms.
        # An upgraded install keeps the slow plans forever if the migration does not add these,
        # and nothing else would ever say so — the pages still work, just slower as history grows.
        def _idx(table):
            return {ix["name"] for ix in _inspect(db.engine).get_indexes(table)}
        _want = {"metric_sample": "ix_metric_sample_server_ts",
                 "host_sample": "ix_host_sample_remote_ts"}
        for _tbl, _name in _want.items():
            db.session.execute(_t("DROP INDEX IF EXISTS %s" % _name))
        db.session.commit()
        check("migrate: a pre-feature DB really is missing the history composite indexes",
              all(n not in _idx(t) for t, n in _want.items()),
              "the drop did not take, so the re-add below would prove nothing")
        _run_light_migrations()
        for _tbl, _name in _want.items():
            check("migrate: update adds %s.%s" % (_tbl, _name), _name in _idx(_tbl),
                  "history charts fall back to a temp sort or a half-table scan without it")
        # The single-column ts index must SURVIVE: the retention prune deletes on `ts < cutoff`
        # alone and would go to a full scan without it.
        check("migrate: the prune's single-column ts index is still there",
              "ix_metric_sample_ts" in _idx("metric_sample"),
              "_prune_metric_samples filters on ts alone")

        # user_session.remember decides when a login row expires, so an install that upgrades
        # into this feature must GET the column — and its existing rows must survive, backfilled
        # to the longer window rather than swept out from under whoever is signed in.
        from panel.core.clock import utcnow as _utcnow_s

        def _scols():
            return {col["name"] for col in _inspect(db.engine).get_columns("user_session")}
        try:
            db.session.execute(_t("ALTER TABLE user_session DROP COLUMN remember"))
            db.session.commit()
            _sdropped = True
        except Exception:
            db.session.rollback()
            _sdropped = False
        if _sdropped:
            db.session.execute(_t("INSERT INTO user_session (user_id, sid, created_at, last_seen, "
                                  "ip, user_agent) VALUES (1, 'smoke_migrate_sid', :n, :n, '', '')"),
                               {"n": _utcnow_s()})
            db.session.commit()
            check("migrate: a pre-feature DB really is missing user_session.remember",
                  "remember" not in _scols())
            _run_light_migrations()
            check("migrate: the update adds user_session.remember", "remember" in _scols())
            _back = db.session.execute(_t("SELECT remember FROM user_session WHERE sid = "
                                          "'smoke_migrate_sid'")).scalar()
            check("migrate: an existing login row survives, on the longer expiry window",
                  bool(_back), "remember=%r" % (_back,))
            db.session.execute(_t("DELETE FROM user_session WHERE sid = 'smoke_migrate_sid'"))
            db.session.commit()

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
    # ── Upload collisions: ask before replacing ──────────────────────────────────────────────────
    # The browser pre-flights the filenames it is about to send so it can show old-vs-new and ask.
    # The remote here is unreachable, so this asserts the CONTRACT (shape, gating, validation) —
    # the parsing and the overwrite refusal are unit-tested against canned `find` output.
    _uc = c.post("/api/server/%d/upload-check" % gs_id, json={"path": "", "names": ["server.cfg"]})
    check("upload-check: returns an 'existing' list", _uc.status_code == 200
          and isinstance(_uc.get_json().get("existing"), list),
          "%d %s" % (_uc.status_code, _uc.get_data(as_text=True)[:90]))
    # This remote is unreachable, which is the ordinary case for this endpoint — and it must not
    # answer "nothing exists", because the UI would read that as "no conflicts" and upload straight
    # over a file it never looked at.
    check("upload-check: an unreachable host reports checked=false, not a false all-clear",
          _uc.get_json().get("checked") is False, str(_uc.get_json())[:110])
    _uc_bad = c.post("/api/server/%d/upload-check" % gs_id, json={"path": "", "names": "notalist"})
    check("upload-check: a non-list 'names' is rejected, not iterated as a string",
          _uc_bad.status_code == 400, "got %d" % _uc_bad.status_code)
    _uc_big = c.post("/api/server/%d/upload-check" % gs_id,
                     json={"path": "", "names": ["f%d" % i for i in range(501)]})
    check("upload-check: an absurd batch is refused", _uc_big.status_code == 400,
          "got %d" % _uc_big.status_code)
    _uc_empty = c.post("/api/server/%d/upload-check" % gs_id, json={})
    check("upload-check: a missing 'names' is a 400, not a 500", _uc_empty.status_code == 400,
          "got %d" % _uc_empty.status_code)
    _uc_anon = app.test_client().post("/api/server/%d/upload-check" % gs_id,
                                      json={"path": "", "names": ["x"]})
    check("upload-check: it is not reachable without a session",
          _uc_anon.status_code in (302, 401, 403), "got %d" % _uc_anon.status_code)

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

    # ── 2FA must not switch itself off when its secret cannot be decrypted ────────────────────
    # totp_secret_plain returns "" on any decryption failure, and the login used to test
    # `totp_enabled AND totp_secret_plain` — so an account with 2FA ON whose secret would not
    # decrypt was logged straight in on the password alone. Not remotely triggerable (it needs
    # damage to data/cred_key), but a control that silently disables itself is the wrong failure
    # direction, and a hand-rolled migration that copies panel.db without the key does exactly it.
    # A REAL Fernet token under a key this panel does not have — which is what "copied panel.db
    # without data/cred_key" actually leaves behind. A syntactically invalid blob was the older
    # fixture and tested a different thing: config.is_encrypted() requires the remainder to be
    # shaped like a Fernet token, so a malformed one is (correctly) treated as legacy plaintext
    # and handed back whole, never reaching the decrypt path this is about.
    from cryptography.fernet import Fernet as _AlienFernet
    from panel.core.config import is_encrypted as _is_enc
    _alien_totp = "enc:v1:" + _AlienFernet(_AlienFernet.generate_key()).encrypt(
        b"JBSWY3DPEHPK3PXP").decode()
    check("2fa: the fixture is a real ciphertext, just not one this panel can read",
          _is_enc(_alien_totp), _alien_totp[:30])
    with app.app_context():
        _tf = User(username="tfa_fail_open",
                   password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="2FA", is_superadmin=False, is_active=True,
                   totp_enabled=True, totp_secret=_alien_totp)
        _tf.set_backup_codes(["abcde-fghjk"])
        db.session.add(_tf)
        db.session.commit()
        _tf_id = _tf.id
        check("2fa: the fixture's secret really is undecryptable",
              db.session.get(User, _tf_id).totp_secret_plain == "")
    _tc = app.test_client()
    _r2 = _tc.post("/login", data={"username": "tfa_fail_open", "password": "Str0ng!passw0rd"},
                   follow_redirects=False)
    check("2fa: a password alone does NOT create a session when 2FA is on",
          _r2.status_code == 200, "status=%d loc=%s" % (_r2.status_code, _r2.headers.get("Location") or ""))
    _after2 = _tc.get("/account", follow_redirects=False)
    check("2fa: ...the caller is still anonymous",
          _after2.status_code in (301, 302, 303) and "/login" in (_after2.headers.get("Location") or ""),
          "status=%d" % _after2.status_code)
    check("2fa: ...and the 2FA prompt is what came back", b"totp_code" in _r2.data)
    # A backup code is bcrypt-hashed in its own column, so it still works without the cred key —
    # the recovery path survives, which is what makes refusing the password-only login safe.
    _r3 = _tc.post("/login", data={"totp_code": "abcde-fghjk"}, follow_redirects=False)
    check("2fa: a backup code still gets them in (no lock-out)",
          _r3.status_code in (301, 302, 303) and "/login" not in (_r3.headers.get("Location") or ""),
          "status=%d loc=%s" % (_r3.status_code, _r3.headers.get("Location") or ""))

    # ── Admin-issued passwords: generated, shown once, and forced to be replaced ──────────────
    # An admin creating an account, or resetting someone's password, hands over a credential TWO
    # people know. The panel generates it (so it is not a house pattern), returns it exactly once,
    # and refuses the account everything except replacing it.
    _add = c.post("/users/add", data={"username": "handover", "display_name": "Handover"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    _aj = _add.get_json() or {}
    _issued = (_aj.get("credential") or {}).get("password") or ""
    check("add user: succeeds with NO password in the form",
          _aj.get("success") is True, str(_aj)[:120])
    check("add user: the response carries the generated password, once",
          bool(_issued) and (_aj["credential"].get("username") == "handover"), str(_aj)[:160])
    check("add user: what it generated satisfies the panel's own password policy",
          auth_password_problem(_issued) is None, "%r -> %s" % (_issued, auth_password_problem(_issued)))
    with app.app_context():
        _hu = User.query.filter_by(username="handover").first()
        _hu_id = _hu.id
        check("add user: the issued password actually authenticates",
              auth.check_password(_issued, _hu.password_hash))
        check("add user: ...and the account is flagged to replace it", _hu.must_change_password is True)

    # The gate: signed in, and able to reach exactly one page.
    hc = app.test_client()
    _lg = hc.post("/login", data={"username": "handover", "password": _issued},
                  follow_redirects=False)
    check("handover login: the issued password gets them in",
          _lg.status_code in (301, 302, 303) and "/login" not in (_lg.headers.get("Location") or ""),
          "status=%d loc=%s" % (_lg.status_code, _lg.headers.get("Location") or ""))
    _dash = hc.get("/", follow_redirects=False)
    check("gate: every page redirects to the change-password page",
          _dash.status_code in (301, 302, 303)
          and "/password/change" in (_dash.headers.get("Location") or ""),
          "status=%d loc=%s" % (_dash.status_code, _dash.headers.get("Location") or ""))
    _acct = hc.get("/account", follow_redirects=False)
    check("gate: ...including the account page it would otherwise change it from",
          "/password/change" in (_acct.headers.get("Location") or ""))
    _api = hc.get("/api/servers", headers={"X-Requested-With": "XMLHttpRequest"})
    check("gate: an in-page fetch gets a 403 it can act on, not a login page",
          _api.status_code == 403 and _api.headers.get("X-Password-Change-Required") == "1",
          "status=%d" % _api.status_code)
    check("gate: ...in the standard envelope",
          (_api.get_json() or {}).get("error") == "password_change_required",
          _api.get_data(as_text=True)[:120])
    _page = hc.get("/password/change")
    check("gate: the change-password page itself is reachable", _page.status_code == 200,
          "status=%d" % _page.status_code)
    check("gate: ...and is rendered without the app chrome that would bounce them back",
          b'class="sidebar"' not in _page.data and b"cmdk-backdrop" not in _page.data)

    # The handed-over password is not an acceptable choice for the password that replaces it.
    # Otherwise the forced change is theatre: you type the admin's password into all three boxes
    # and the account is still secured by a credential two people know.
    _same = hc.post("/account/password", data={"current_password": _issued,
                                               "new_password": _issued, "confirm_password": _issued},
                    follow_redirects=True)
    check("reuse: the generated password cannot be kept as the new one",
          b"used before" in _same.data, _same.data[-400:].decode("utf-8", "replace")[:200])
    with app.app_context():
        _hu_r = db.session.get(User, _hu_id)
        check("reuse: ...the account is still flagged", _hu_r.must_change_password is True)
        check("reuse: ...and the password is unchanged",
              auth.check_password(_issued, _hu_r.password_hash))

    # Wrong current password must not clear the flag — the gate is not a formality.
    hc.post("/account/password", data={"current_password": "not-the-one",
                                       "new_password": "Ch0sen!pass1", "confirm_password": "Ch0sen!pass1"})
    with app.app_context():
        check("gate: a wrong current password leaves the account still flagged",
              db.session.get(User, _hu_id).must_change_password is True)

    _chg = hc.post("/account/password", data={"current_password": _issued,
                                              "new_password": "Ch0sen!pass1",
                                              "confirm_password": "Ch0sen!pass1"},
                   follow_redirects=False)
    with app.app_context():
        _hu2 = db.session.get(User, _hu_id)
        check("change: setting their own password clears the flag",
              _hu2.must_change_password is False)
        check("change: ...and it is really the new password",
              auth.check_password("Ch0sen!pass1", _hu2.password_hash))
    check("change: they are sent into the panel, not back to the form",
          "/password/change" not in (_chg.headers.get("Location") or ""),
          _chg.headers.get("Location") or "")
    _after = hc.get("/", follow_redirects=False)
    check("change: ...and the panel opens normally afterwards", _after.status_code == 200,
          "status=%d" % _after.status_code)

    # History, end to end: the password they just left cannot come straight back. Without this,
    # "change your password" is satisfied by changing it and changing it back, which is what
    # someone does when made to replace a password they were happy with.
    _back1 = hc.post("/account/password", data={"current_password": "Ch0sen!pass1",
                                                "new_password": _issued, "confirm_password": _issued},
                     follow_redirects=True)
    check("history: the admin-issued password cannot be returned to later",
          b"used before" in _back1.data)
    hc.post("/account/password", data={"current_password": "Ch0sen!pass1",
                                       "new_password": "Ch0sen!pass2", "confirm_password": "Ch0sen!pass2"})
    _back2 = hc.post("/account/password", data={"current_password": "Ch0sen!pass2",
                                                "new_password": "Ch0sen!pass1",
                                                "confirm_password": "Ch0sen!pass1"},
                     follow_redirects=True)
    check("history: nor the one before this one", b"used before" in _back2.data)
    with app.app_context():
        check("history: ...and none of those refusals changed the password",
              auth.check_password("Ch0sen!pass2", db.session.get(User, _hu_id).password_hash))
    # Far enough back and it is allowed again — the window is a window, not an archive.
    for _n in (3, 4, 5):
        hc.post("/account/password", data={"current_password": "Ch0sen!pass%d" % (_n - 1),
                                           "new_password": "Ch0sen!pass%d" % _n,
                                           "confirm_password": "Ch0sen!pass%d" % _n})
    _old_ok = hc.post("/account/password", data={"current_password": "Ch0sen!pass5",
                                                 "new_password": "Ch0sen!pass1",
                                                 "confirm_password": "Ch0sen!pass1"},
                      follow_redirects=True)
    with app.app_context():
        check("history: a password older than the window can be used again",
              auth.check_password("Ch0sen!pass1", db.session.get(User, _hu_id).password_hash),
              _old_ok.data[-300:].decode("utf-8", "replace")[:160])

    # Admin reset of SOMEONE ELSE's password: generated, flagged, old password dead.
    _rst = c.post("/users/%d/edit" % _hu_id,
                  data={"display_name": "Handover", "is_active": "on", "reset_password": "on"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    _rj = _rst.get_json() or {}
    _reissued = (_rj.get("credential") or {}).get("password") or ""
    check("reset: the response carries a new generated password", bool(_reissued), str(_rj)[:140])
    check("reset: it is not the one they had chosen", _reissued != "Ch0sen!pass1")
    with app.app_context():
        _hu3 = db.session.get(User, _hu_id)
        check("reset: the account must replace it again", _hu3.must_change_password is True)
        check("reset: their chosen password no longer works",
              not auth.check_password("Ch0sen!pass1", _hu3.password_hash))
        check("reset: the issued one does", auth.check_password(_reissued, _hu3.password_hash))

    # An edit that does NOT tick reset must leave the password alone — renaming someone is not a
    # reason to invalidate their login.
    _noreset = c.post("/users/%d/edit" % _hu_id,
                      data={"display_name": "Renamed", "is_active": "on"},
                      headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit: an ordinary edit mints nothing",
          (_noreset.get_json() or {}).get("credential") is None, str(_noreset.get_json())[:120])
    with app.app_context():
        check("edit: ...and leaves the password working",
              auth.check_password(_reissued, db.session.get(User, _hu_id).password_hash))

    # Resetting your OWN password from the Users page: you already know it, and there is nobody to
    # take it back from, so it does not flag you out of your own panel. On a THROWAWAY superadmin —
    # resetting the account the rest of this suite logs in with would break every later sign-in.
    c.post("/users/add", data={"username": "selfrst", "display_name": "Self Reset",
                               "is_superadmin": "on"},
           headers={"X-Requested-With": "XMLHttpRequest"})
    with app.app_context():
        _sr = User.query.filter_by(username="selfrst").first()
        _sr_id = _sr.id
        _sr.must_change_password = False   # pretend they have already set their own
        db.session.commit()
    _selfrst = client_as(_sr_id).post(
        "/users/%d/edit" % _sr_id,
        data={"display_name": "Self Reset", "is_active": "on", "is_superadmin": "on",
              "reset_password": "on"},
        headers={"X-Requested-With": "XMLHttpRequest"})
    _sj = _selfrst.get_json() or {}
    check("self-reset: still issues a generated password",
          bool((_sj.get("credential") or {}).get("password")), str(_sj)[:120])
    with app.app_context():
        check("self-reset: ...but does not force yourself through the change screen",
              db.session.get(User, _sr_id).must_change_password is False)

    # ── An install that predates the `sha256$` format signs in, and is upgraded in place ──
    # Every existing installation hits this branch on its first login after the hash format
    # changed, and it was covered only at the level of check_password()/needs_rehash(): the route
    # that calls them had no test. Each property below is a distinct regression if it stops
    # holding — locked out of an upgraded panel, re-upgraded on every login, signed out of every
    # other device by a format change nobody asked for, or the quiet one: the legacy hash pushed
    # into a 3-deep history, evicting the oldest entry and quietly freeing a real old password
    # for reuse. That last one is what set_password() would do here, which is why the route
    # assigns the hash directly.
    import bcrypt as _lb
    import json as _lj
    _LEGACY_PW = "Ancient!pass1"
    # Byte-for-byte what the pre-change code wrote: bcrypt over the raw password, no prefix.
    _legacy_hash = _lb.hashpw(_LEGACY_PW.encode(), _lb.gensalt(4)).decode()
    # A FULL history window (PASSWORD_HISTORY_LEN == 3), so nothing can be added without evicting.
    _legacy_hist = [_lb.hashpw(("Ancient!pass%d" % _n).encode(), _lb.gensalt(4)).decode()
                    for _n in (2, 3, 4)]
    _legacy_hist_json = _lj.dumps(_legacy_hist)
    with app.app_context():
        _lu = User(username="legacyhash", password_hash=_legacy_hash,
                   password_history=_legacy_hist_json, auth_epoch=7, is_active=True)
        db.session.add(_lu)
        db.session.commit()
        _lu_id = _lu.id
    check("legacy login: the fixture really is an old-format hash",
          _legacy_hash.startswith("$2") and not _legacy_hash.startswith("sha256$"),
          _legacy_hash[:12])

    _lc2 = app.test_client()
    _llogin = _lc2.post("/login", data={"username": "legacyhash", "password": _LEGACY_PW},
                        follow_redirects=False)
    check("legacy login: a pre-upgrade password still signs in",
          _llogin.status_code in (301, 302, 303)
          and "/login" not in (_llogin.headers.get("Location") or ""),
          "status=%d loc=%s" % (_llogin.status_code, _llogin.headers.get("Location") or ""))
    check("legacy login: ...and the session it just created is usable",
          _lc2.get("/", follow_redirects=False).status_code == 200)

    with app.app_context():
        _lu2 = db.session.get(User, _lu_id)
        check("legacy login: the stored hash was upgraded to the new format",
              _lu2.password_hash.startswith("sha256$"), _lu2.password_hash[:14])
        check("legacy login: ...and the same password verifies against it",
              auth.check_password(_LEGACY_PW, _lu2.password_hash))
        check("legacy login: ...so it is not flagged for upgrade a second time",
              not auth.needs_rehash(_lu2.password_hash))
        # The two things the upgrade must NOT touch.
        check("legacy login: auth_epoch is untouched, so no device is signed out",
              _lu2.auth_epoch == 7, "epoch=%r" % (_lu2.auth_epoch,))
        check("legacy login: the reuse history is untouched, byte for byte",
              (_lu2.password_history or "") == _legacy_hist_json,
              "%r" % ((_lu2.password_history or "")[:80],))
        # The consequence of that, stated as behaviour: the OLDEST remembered password is the one
        # an extra history entry would have evicted, and it is still refused.
        check("legacy login: ...so the oldest remembered password is still refused for reuse",
              _lu2.password_reused("Ancient!pass4"))

    # A second sign-in now runs entirely on the new format.
    _lc3 = app.test_client()
    check("legacy login: signing in again works against the upgraded hash",
          _lc3.post("/login", data={"username": "legacyhash", "password": _LEGACY_PW},
                    follow_redirects=False).status_code in (301, 302, 303))

    # A WRONG password must not rewrite anything — the upgrade happens only once the plaintext has
    # been proven correct, never on the way to rejecting it.
    with app.app_context():
        _lu3 = User(username="legacyhash2", password_hash=_legacy_hash, is_active=True)
        db.session.add(_lu3)
        db.session.commit()
        _lu3_id = _lu3.id
    app.test_client().post("/login", data={"username": "legacyhash2", "password": "wrong-one"})
    with app.app_context():
        check("legacy login: a failed attempt leaves the old hash exactly as it was",
              db.session.get(User, _lu3_id).password_hash == _legacy_hash)

    # ── a password longer than bcrypt's 72 bytes survives the whole stack ────────────────────
    # The unit suite proves hash_password()/check_password() handle any length. This proves the
    # PATH does: form -> validator -> set_password -> column -> login. Truncation anywhere in
    # there is invisible until someone with a passphrase in a password manager cannot sign in,
    # and the decoy below is what makes it visible — two passwords sharing their first 72 bytes
    # must not be interchangeable.
    _PW_PREFIX = "Str0ng!" + "a" * 70          # 77 bytes; already over bcrypt's limit
    _LONG_PW = _PW_PREFIX + "ENDING1!"
    _DECOY_PW = _PW_PREFIX + "OTHER2@"         # same first 77 bytes, different password
    check("long password: the fixture is genuinely over bcrypt's 72-byte limit",
          len(_LONG_PW.encode()) > 72 and _LONG_PW.encode()[:72] == _DECOY_PW.encode()[:72],
          "%d bytes" % len(_LONG_PW.encode()))
    check("long password: the panel's own validator sets no upper bound",
          auth_password_problem(_LONG_PW) is None, str(auth_password_problem(_LONG_PW)))

    _START_PW = "Start1ng!pw"
    with app.app_context():
        _lpu = User(username="longpw", password_hash=auth.hash_password(_START_PW),
                    is_active=True, must_change_password=False)
        db.session.add(_lpu)
        db.session.commit()
        _lpu_id = _lpu.id
    _lpc = app.test_client()
    _lpc.post("/login", data={"username": "longpw", "password": _START_PW})
    _setlong = _lpc.post("/account/password",
                         data={"current_password": _START_PW, "new_password": _LONG_PW,
                               "confirm_password": _LONG_PW}, follow_redirects=True)
    with app.app_context():
        _lpu2 = db.session.get(User, _lpu_id)
        check("long password: the change form accepts it",
              auth.check_password(_LONG_PW, _lpu2.password_hash),
              _setlong.data[-300:].decode("utf-8", "replace")[:160])
        check("long password: ...and it was NOT stored truncated to 72 bytes",
              not auth.check_password(_DECOY_PW, _lpu2.password_hash))

    # The one that matters to the person: they can actually sign in with it afterwards.
    _lpc2 = app.test_client()
    _lpl = _lpc2.post("/login", data={"username": "longpw", "password": _LONG_PW},
                      follow_redirects=False)
    check("long password: signing in with the full passphrase works",
          _lpl.status_code in (301, 302, 303)
          and "/login" not in (_lpl.headers.get("Location") or ""),
          "status=%d loc=%s" % (_lpl.status_code, _lpl.headers.get("Location") or ""))
    _lpd = app.test_client().post("/login", data={"username": "longpw", "password": _DECOY_PW},
                                  follow_redirects=False)
    check("long password: a password sharing its first 72 bytes is refused at login",
          not (_lpd.status_code in (301, 302, 303)
               and "/login" not in (_lpd.headers.get("Location") or "")),
          "status=%d loc=%s" % (_lpd.status_code, _lpd.headers.get("Location") or ""))

    # ── hostnames, SSH usernames and session IPs are ciphertext at rest ──────────────────────
    # A stolen panel.db should not also be a map of the machines it manages. These columns are
    # EncryptedString, which is transparent in Python, so the only way to prove it is doing
    # anything is to go around the ORM and read the raw bytes.
    from sqlalchemy import text as _enc_sql
    _SECRET_HOST, _SECRET_USER = "vault.internal.example", "deploybot"
    with app.app_context():
        _er = RemoteServer(name="enc-host", host=_SECRET_HOST, port=2222,
                           username=_SECRET_USER, auth_method="key", auth_credential="",
                           linuxgsm_user="lgsm-secret", public_ip="203.0.113.77",
                           host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5SECRETKEY")
        db.session.add(_er)
        db.session.commit()
        _er_id = _er.id
        db.session.expire_all()          # force a real re-read, not the identity map
        _back = db.session.get(RemoteServer, _er_id)
        check("at-rest: a hostname round-trips through the ORM unchanged",
              _back.host == _SECRET_HOST, repr(_back.host))
        check("at-rest: ...and so do the username, lgsm user, public IP and host key",
              (_back.username, _back.linuxgsm_user, _back.public_ip) ==
              (_SECRET_USER, "lgsm-secret", "203.0.113.77")
              and _back.host_key.endswith("SECRETKEY"),
              "%r %r %r" % (_back.username, _back.linuxgsm_user, _back.public_ip))
        # The point: the raw column is ciphertext.
        _raw = db.session.execute(_enc_sql(
            "SELECT host, username, linuxgsm_user, public_ip, host_key FROM remote_server"
            " WHERE id = :i"), {"i": _er_id}).fetchone()
        check("at-rest: the stored hostname is ciphertext, not the hostname",
              _raw[0] != _SECRET_HOST and _raw[0].startswith("enc:v1:"), str(_raw[0])[:40])
        check("at-rest: no plaintext survives in ANY of the five columns",
              not any(v in (_raw[0] or "") + (_raw[1] or "") + (_raw[2] or "")
                             + (_raw[3] or "") + (_raw[4] or "")
                      for v in (_SECRET_HOST, _SECRET_USER, "lgsm-secret", "203.0.113.77",
                                "SECRETKEY")),
              str(_raw)[:120])

        # A row written by an OLDER panel is plaintext. It must keep working — an upgrade that
        # locked someone out of their own hosts until a migration ran would be worse than the leak.
        db.session.execute(_enc_sql(
            "INSERT INTO remote_server (name, host, port, username, auth_method, auth_credential,"
            " is_local, is_online) VALUES ('legacy-host', 'legacy.example', 22, 'oldroot', 'key',"
            " '', 0, 0)"))
        db.session.commit()
        db.session.expire_all()
        _leg = RemoteServer.query.filter_by(name="legacy-host").first()
        check("at-rest: a legacy PLAINTEXT row still reads correctly",
              _leg is not None and _leg.host == "legacy.example" and _leg.username == "oldroot",
              "%r / %r" % (getattr(_leg, "host", None), getattr(_leg, "username", None)))
        # An ordinary save does NOT convert it: SQLAlchemy writes only the columns that changed,
        # so editing the port leaves the hostname in plaintext. Worth pinning, because it is the
        # reason the migration below has to exist at all rather than being left to happen by use.
        _leg.port = 2200
        db.session.commit()
        _leg_raw = db.session.execute(_enc_sql(
            "SELECT host FROM remote_server WHERE name = 'legacy-host'")).fetchone()[0]
        check("at-rest: an unrelated edit leaves a legacy row plaintext (so a migration is needed)",
              _leg_raw == "legacy.example", str(_leg_raw)[:40])

        # The migration is what converts it, and it is idempotent.
        from panel.db.models import encrypt_at_rest_columns as _enc_mig
        _n1 = _enc_mig()
        _leg_raw2 = db.session.execute(_enc_sql(
            "SELECT host, username FROM remote_server WHERE name = 'legacy-host'")).fetchone()
        check("at-rest: the migration encrypts the legacy row", _n1 >= 1
              and _leg_raw2[0].startswith("enc:v1:") and "legacy.example" not in _leg_raw2[0]
              and "oldroot" not in (_leg_raw2[1] or ""), "touched=%s raw=%.40s" % (_n1, _leg_raw2[0]))
        db.session.expire_all()
        _leg2 = RemoteServer.query.filter_by(name="legacy-host").first()
        check("at-rest: ...and the row still reads back as the same host",
              _leg2.host == "legacy.example" and _leg2.username == "oldroot",
              "%r / %r" % (_leg2.host, _leg2.username))
        check("at-rest: ...and running it again rewrites nothing", _enc_mig() == 0)

    # Sessions carry the same treatment: IP and user-agent are PII on every signed-in device.
    with app.app_context():
        from panel.db.models import UserSession as _US
        _sess_raw = db.session.execute(_enc_sql(
            "SELECT ip, user_agent FROM user_session WHERE ip != '' LIMIT 1")).fetchone()
        _any_sess = db.session.query(_US).filter(_US.ip != "").first()
        # Its ABSENCE is a failure, not a skip. Dozens of logins have happened by this point, so no
        # row with an IP means the check is testing nothing — which must be loud, not green.
        check("at-rest: there is a session row to inspect at all",
              _sess_raw is not None and _any_sess is not None,
              "no user_session row carried an IP — this block would prove nothing")
        check("at-rest: session IP and user-agent are ciphertext",
              _sess_raw is not None and (_sess_raw[0] or "").startswith("enc:v1:")
              and (not _sess_raw[1] or _sess_raw[1].startswith("enc:v1:")),
              str(_sess_raw)[:60])
        check("at-rest: ...and still read back as the real values",
              _any_sess is not None and bool(_any_sess.ip)
              and not _any_sess.ip.startswith("enc:v1:"),
              repr(getattr(_any_sess, "ip", None)))

    # ── audit IPs age out into network prefixes ──────────────────────────────────────────────
    # The audit log kept a full IP for every action forever, which makes it an indefinite record
    # of where each admin was. The ROW is what the log is for, so the entry stays and only the
    # identifying part of the address goes.
    from panel.db.models import AuditLog as _AL, anonymise_audit_ips as _anon, _anonymise_ip as _aip
    from datetime import timedelta as _td
    from panel.core.clock import utcnow as _utcnow
    check("audit-ip: an IPv4 address reduces to its /24",
          _aip("203.0.113.77") == "203.0.113.0/24", _aip("203.0.113.77"))
    check("audit-ip: an IPv6 address reduces to its /64",
          _aip("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64", _aip("2001:db8:1:2:3:4:5:6"))
    check("audit-ip: something that is not an address is dropped, not kept",
          _aip("not-an-ip") == "" and _aip("") == "")
    with app.app_context():
        _now = _utcnow()
        _old_row = _AL(username="olduser", action="login", ip_address="198.51.100.42",
                       timestamp=_now - _td(days=200))
        _new_row = _AL(username="newuser", action="login", ip_address="198.51.100.43",
                       timestamp=_now - _td(days=1))
        db.session.add_all([_old_row, _new_row])
        db.session.commit()
        _old_id, _new_id = _old_row.id, _new_row.id
        _n = _anon(90)
        check("audit-ip: an entry older than the window is reduced", _n >= 1
              and db.session.get(_AL, _old_id).ip_address == "198.51.100.0/24",
              "%s / %r" % (_n, db.session.get(_AL, _old_id).ip_address))
        check("audit-ip: ...and a recent one is left alone",
              db.session.get(_AL, _new_id).ip_address == "198.51.100.43",
              repr(db.session.get(_AL, _new_id).ip_address))
        check("audit-ip: the ROW survives — only the address is reduced",
              db.session.get(_AL, _old_id).username == "olduser"
              and db.session.get(_AL, _old_id).action == "login")
        # Idempotent, and cheap on restart: an already-reduced row must not be rewritten again.
        check("audit-ip: running it again rewrites nothing", _anon(90) == 0)
        check("audit-ip: 0 disables it entirely", _anon(0) == 0)
        # config.json is hand-editable and "90" (quoted) is an easy thing to write. Comparing a
        # str to an int raises TypeError, app.py swallows it with a bare except, and the control
        # then silently never runs while the config still says it is on. A privacy control that
        # fails quietly is worse than one that is off, because nobody goes looking.
        _old2 = _AL(username="olduser2", action="login", ip_address="198.51.100.44",
                    timestamp=_now - _td(days=200))
        db.session.add(_old2)
        db.session.commit()
        _old2_id = _old2.id
        # Both calls are caught: without the coercion they raise TypeError, and an exception here
        # aborts the part before the summary prints — hiding this verdict AND every check after
        # it. The failure has to be legible as a FAIL, not as a suite that produced no output.
        def _anon_safely(val):
            try:
                return _anon(val), None
            except Exception as _e:                      # noqa: BLE001 - the thing under test
                return None, "%s: %s" % (type(_e).__name__, _e)

        _n_str, _err_str = _anon_safely("90")
        check("audit-ip: a NUMERIC STRING in config.json still works, rather than raising",
              _err_str is None and _n_str >= 1
              and db.session.get(_AL, _old2_id).ip_address == "198.51.100.0/24",
              _err_str or repr(db.session.get(_AL, _old2_id).ip_address))
        _n_junk, _err_junk = _anon_safely("ninety")
        check("audit-ip: junk in config.json disables it and does not raise",
              _err_junk is None and _n_junk == 0, _err_junk or repr(_n_junk))
        # The brute-force counter reads a 300-SECOND window, so it can never see a reduced row.
        # This is the check that says the privacy control cannot weaken login throttling.
        _recent = _AL.query.filter(_AL.action == "login_failed",
                                   _AL.timestamp >= _now - _td(seconds=300)).count()
        _anon(90)
        check("audit-ip: ...and the throttle's own window is untouched by it",
              _AL.query.filter(_AL.action == "login_failed",
                               _AL.timestamp >= _now - _td(seconds=300)).count() == _recent)

    # ── one server table: /servers/manage folded into the dashboard ──────────────────────────
    # The two pages showed seven of the same eight columns and shared no code at all — doAction vs
    # msrvAction, sortDashCol vs sortServers — so one was a second implementation of the other.
    # The checks that asserted the old page are replaced here, not dropped: what they tested is
    # gone, and what replaced it is below.
    _ms = c.get("/servers/manage", follow_redirects=False)
    check("one-table: /servers/manage redirects rather than 404s",
          _ms.status_code in (301, 302, 303), "status=%d" % _ms.status_code)
    check("one-table: ...to the dashboard",
          (_ms.headers.get("Location") or "").rstrip("/").endswith("") and
          (_ms.headers.get("Location") or "/") in ("/", "http://localhost/"),
          "Location=%s" % _ms.headers.get("Location"))
    # Everything that lived only on the old page has to be on the dashboard now.
    _dash = c.get("/").get_data(as_text=True)
    check("one-table: the dashboard carries the per-server Files & Config link",
          "/files" in _dash, "server_files was reachable from the old row and nowhere else")
    check("one-table: ...the per-server tag button",
          'data-action="editServerTags"' in _dash)
    # Split the <head> off first. This check passed while the Tags card was accidentally emitted
    # INSIDE {% block title %} — the string was in the HTML, so a whole-document substring test
    # was true, the tab title was full of raw markup and the card rendered nowhere. A page-level
    # assertion has to look at the page.
    _dash_body = _dash.split("</head>", 1)[-1]
    check("one-table: the dashboard's <title> is a title, not markup",
          "<details" not in _dash.split("</title>")[0],
          _dash.split("</title>")[0][-120:])
    check("one-table: ...and the Tags card is in the BODY", 'id="sec-tags"' in _dash_body)
    check("one-table: ...rendered once, not twice",
          _dash_body.count("bi-tags-fill") == 1,
          "%d tag headers — the <summary> replaced the card-header, both should not remain"
          % _dash_body.count("bi-tags-fill"))
    check("one-table: ...with the script that makes those buttons work",
          "server_tags.js" in _dash, "the tag handlers would be dead without it")

    # ── the palette offers only actions the user may actually run ────────────────────────────
    # The palette can now START/RESTART/STOP from the search box, which makes /api/palette an
    # authorization surface rather than a list of names. The rule it has to keep: never name an
    # action the caller would be refused for. Checked against a REAL restricted user, because a
    # superadmin passes every permission test and would prove nothing.
    _pal = c.get("/api/palette")
    check("palette: the index still loads", _pal.status_code == 200, "status=%d" % _pal.status_code)
    _pj = _pal.get_json() or []
    check("palette: it lists the servers", len(_pj) >= 1, "%d entries" % len(_pj))
    check("palette: a superadmin is offered all three verbs",
          any(sorted(e.get("actions") or []) == ["restart", "start", "stop"]
              for e in _pj if e.get("installed")),
          str([(e["name"], e.get("actions")) for e in _pj])[:200])
    # An account that can SEE a server but has no action permissions must get names and no verbs.
    # The group is given ACCESS to the game server as well as VIEW_SERVERS. Without the access
    # grant the user sees an empty list, and `all(... for e in [])` is True — so the check below
    # passed while examining nothing, and stripping the permission filter entirely failed no test.
    # Mutation caught it. The non-emptiness is now asserted before the claim that rests on it.
    with app.app_context():
        _vg = Group(name="smoke-viewonly")
        _vg.set_permissions([auth.VIEW_SERVERS])
        _vg.game_servers.append(db.session.get(GameServer, gs_id))
        db.session.add(_vg)
        db.session.flush()
        _viewer = User(username="paletteviewer",
                       password_hash=auth.hash_password("Str0ng!passw0rd"),
                       is_superadmin=False, is_active=True)
        _viewer.groups.append(_vg)
        db.session.add(_viewer)
        db.session.commit()
        _viewer_id = _viewer.id
    _pal2 = client_as(_viewer_id).get("/api/palette")
    check("palette: a view-only user still reaches it", _pal2.status_code == 200,
          "status=%d" % _pal2.status_code)
    _pj2 = _pal2.get_json() or []
    check("palette: the view-only user actually SEES a server, so the next check examines one",
          len(_pj2) >= 1, "%d entries — an empty list would pass the next check vacuously"
          % len(_pj2))
    check("palette: ...and is offered NO actions at all",
          _pj2 and all(not (e.get("actions") or []) for e in _pj2),
          str([(e["name"], e.get("actions")) for e in _pj2])[:200])
    # An un-installed server has nothing to start, even for an admin.
    check("palette: an un-installed server carries no verbs",
          all(not (e.get("actions") or []) for e in _pj if not e.get("installed")),
          str([(e["name"], e.get("actions")) for e in _pj if not e.get("installed")])[:200])
    # And the endpoint's answer must agree with the one the ACTION route enforces, or the palette
    # is offering a button that 403s.
    _act_denied = client_as(_viewer_id).post("/api/server/%d/action" % gs_id,
                                             json={"action": "start"},
                                             headers={"X-Requested-With": "XMLHttpRequest"})
    check("palette: the action route refuses that same user, so the empty list was honest",
          _act_denied.status_code in (403, 302, 401),
          "status=%d" % _act_denied.status_code)

    # ── the install form lives on its own page now ───────────────────────────────────────────
    # It used to sit on /servers/manage above the list of servers you already have. Splitting it
    # out is only safe if the form still WORKS from its new home, so this checks the controls and
    # the submit target came with it, not merely that the page returns 200.
    _inst = c.get("/servers/install")
    check("install page: renders", _inst.status_code == 200, "status=%d" % _inst.status_code)
    _ih = _inst.get_data(as_text=True)
    check("install page: carries the install form's controls",
          all(x in _ih for x in ("remote-select", "game-type-select", "port-input")))
    check("install page: ...and still posts to the install endpoint",
          "/servers/add" in _ih, "no form action pointing at the install route")
    # The page it came from must no longer carry it, or the split achieved nothing.
    # The list lives on the DASHBOARD now, so that is where "the form is not embedded, but is
    # reachable" has to hold. Reading /servers/manage here would read a redirect body and assert
    # nothing — it passed for a while precisely because an empty body contains no form either.
    _mh = c.get("/", follow_redirects=True).get_data(as_text=True)
    check("install page: the server list no longer embeds the form",
          "game-type-select" not in _mh and "remote-select" not in _mh)
    check("install page: ...but the list links to it", "/servers/install" in _mh)
    # Same permission pair as the POST it submits to: reaching the form and using it are one
    # decision. A user with neither must be refused the page, not shown a form that 403s on submit.
    with app.app_context():
        _nog = Group(name="smoke-noinstall")
        _nog.set_permissions([auth.VIEW_SERVERS])
        db.session.add(_nog)
        db.session.flush()
        _noinst = User(username="noinstall", password_hash=auth.hash_password("Str0ng!passw0rd"),
                       is_superadmin=False, is_active=True)
        _noinst.groups.append(_nog)
        db.session.add(_noinst)
        db.session.commit()
        _noinst_id = _noinst.id
    # A one-host panel must not ask which host. The placeholder is a required field whose only
    # valid answer is the single option under it — a click that can only be made one way. With two
    # or more the placeholder stays, because then the choice is real and a silent default would
    # install onto whichever host happened to sort first.
    def _host_options(html):
        """The <option>s inside the target-host select, so a count means hosts and not markup."""
        if 'id="remote-select"' not in html:
            return ""
        return html.split('id="remote-select"')[1].split("</select>")[0]

    _multi_sel = _host_options(_ih)
    _multi_n = _multi_sel.count("<option")
    check("install page: the superadmin fixture really does have several hosts",
          _multi_n >= 3, "%d options — with fewer the next check proves nothing" % _multi_n)
    check("install page: with SEVERAL hosts it still asks which one",
          "Select a server" in _multi_sel and "selected" not in _multi_sel,
          "%d options: %.140s" % (_multi_n, _multi_sel))
    with app.app_context():
        _1hg = Group(name="smoke-onehost")
        _1hg.set_permissions([auth.INSTALL_SERVER])
        _1hg.servers.append(db.session.get(RemoteServer, remote_id))
        db.session.add(_1hg)
        db.session.flush()
        _1hu = User(username="onehost", password_hash=auth.hash_password("Str0ng!passw0rd"),
                    is_superadmin=False, is_active=True)
        _1hu.groups.append(_1hg)
        db.session.add(_1hu)
        db.session.commit()
        _1hu_id = _1hu.id
    _one = client_as(_1hu_id).get("/servers/install")
    check("install page: a single-host user reaches it", _one.status_code == 200,
          "status=%d" % _one.status_code)
    _oh = _one.get_data(as_text=True)
    _sel_block = _oh.split('id="remote-select"')[1].split("</select>")[0] if 'id="remote-select"' in _oh else ""
    check("install page: ...and sees exactly one host option",
          _sel_block.count("<option") == 1, "%d options: %.120s" % (_sel_block.count("<option"), _sel_block))
    check("install page: ...pre-selected, with no 'Select a server...' to click past",
          "selected" in _sel_block and "Select a server" not in _sel_block, _sel_block[:160])

    _denied = client_as(_noinst_id).get("/servers/install", follow_redirects=False)
    check("install page: a user without install/manage permission is refused",
          _denied.status_code in (302, 303, 403),
          "status=%d — a user who cannot install must not reach the form" % _denied.status_code)

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

    # ── A host's servers are keyed on the Linux user, so one account can only ever be one server.
    # Seven games under one account (what a GMod content box looks like) used to import the first
    # and silently drop six as duplicates — a panel row for whichever game happened to sort first.
    imp_multi = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
        {"user": "srcds", "game_type": "css", "port": 27015},
        {"user": "srcds", "game_type": "tf2", "port": 27015},
        {"user": "srcds", "game_type": "dods", "port": 27015}]})
    _imm = imp_multi.get_json() or {}
    check("import: one account claiming several games is refused outright, not partly applied",
          _imm.get("added") == [] and len(_imm.get("skipped") or []) == 3, str(_imm)[:140])
    with app.app_context():
        _srcds_rows = GameServer.query.filter_by(remote_id=remote_id, short_name="srcds").count()
    check("import: ...and no arbitrary winner was written to the database", _srcds_rows == 0,
          "rows=%d" % _srcds_rows)

    # ── GMod content is filtered out of discovery ──
    # Each mountable game is installed through LinuxGSM, so the host scan cannot tell it from a
    # server. The panel can: content_box_users classifies by shape, and the endpoint reports what
    # it left out instead of listing one account once per game.
    # discover.py binds discover_linuxgsm_servers by name at import, so the stub goes on THAT
    # module — it follows the handler, not the name (same rule as remote_security below).
    from panel.routes import discover as _disc_mod
    _orig_disc = _disc_mod.discover_linuxgsm_servers
    try:
        def _fake_disc(_server):
            rows = [{"user": "contentbox", "lgsm_name": n, "port": 27015, "backups": 0,
                     "mods": 0, "cron": 14, "autostart": False}
                    for n in ("cssserver", "tf2server", "dodsserver", "l4d2server")]
            rows.append({"user": "realgmod", "lgsm_name": "gmodserver", "port": 27015,
                         "backups": 1, "mods": 0, "cron": 2, "autostart": True})
            return rows
        _disc_mod.discover_linuxgsm_servers = _fake_disc
        _d2 = (c.get("/api/remote/%d/discover" % remote_id).get_json() or {})
        _users = [x["user"] for x in (_d2.get("servers") or [])]
        check("discover: a content box is not offered as importable servers",
              "contentbox" not in _users, "users=%s" % _users)
        check("discover: ...while a real server on the same host still is",
              _users == ["realgmod"], "users=%s" % _users)
        _content = _d2.get("content") or []
        check("discover: ...and the content it skipped is reported, not silently dropped",
              len(_content) == 1 and _content[0]["user"] == "contentbox"
              and len(_content[0]["games"]) == 4, str(_content)[:160])
    finally:
        _disc_mod.discover_linuxgsm_servers = _orig_disc

    # ── Session management: per-device login sessions + individual revoke ──
    from panel.db.models import UserSession

    def _real_login(username="smoke_admin", pw="Str0ng!passw0rd"):
        cc = app.test_client()
        rr = cc.post("/login", data={"username": username, "password": pw}, follow_redirects=False)
        return cc, rr

    s1, r1 = _real_login()
    # The login cookie must be PERSISTENT (carry Expires/Max-Age). A bare session cookie dies with
    # the browser process — and on Android the browser is killed constantly — which shows up as
    # "it forgets my login every time", with a new server-side session row per re-login.
    _login_cookies = {h.split("=", 1)[0]: h for h in r1.headers.getlist("Set-Cookie")}
    _sess_cookie = _login_cookies.get("lgpanel_session", "")
    check("session: the login cookie is persistent, not a browser-session cookie",
          "Expires=" in _sess_cookie or "Max-Age=" in _sess_cookie,
          "Set-Cookie: %s" % (_sess_cookie[:160] or "(none issued)"))
    check("session: real login lands in (redirect away from /login)",
          r1.status_code in (301, 302, 303) and "/login" not in (r1.headers.get("Location") or ""),
          "status=%d loc=%s" % (r1.status_code, r1.headers.get("Location") or ""))
    with app.app_context():
        n1 = UserSession.query.filter_by(user_id=admin_id).count()
    check("session: login created a server-side session row", n1 >= 1, "rows=%d" % n1)

    # One response envelope. These three routes used an `ok` key, which the universal
    # `d.success === false` client guard cannot see — so account.html reported "Session revoked"
    # even for a 404 "Session not found".
    _rev404 = s1.post("/api/account/sessions/999999/revoke")
    check("session: revoking a session that does not exist is a 404", _rev404.status_code == 404)
    check("session: ...and says success=false in the standard envelope",
          (_rev404.get_json() or {}).get("success") is False
          and "ok" not in (_rev404.get_json() or {}),
          _rev404.get_data(as_text=True)[:120])
    _lang = s1.get("/set-language/es?ajax=1")
    check("language: the ajax save answers in the standard envelope",
          (_lang.get_json() or {}).get("success") is True
          and "ok" not in (_lang.get_json() or {}),
          _lang.get_data(as_text=True)[:120])
    s1.get("/set-language/en?ajax=1")   # put it back

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
    check("session: revoke a non-current session succeeds",
          rv is not None and rv.status_code == 200 and rvj.get("success") is True
          and not rvj.get("current"), str(rvj)[:120])

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

    # ── "Sign out everywhere else" keeps the device that pressed it ──
    # It used to bump the epoch and delete every row, including the caller's — so the one button
    # meant to evict an intruder also evicted you, onto the login page, on the phone you were
    # holding. The epoch bump stays (it is the only thing that kills a legacy no-sid cookie and
    # every remember cookie); this device is re-admitted with a cookie carrying the new epoch.
    s3, _ = _real_login()                 # a second device to be signed out
    with app.app_context():
        epoch_before = db.session.get(User, admin_id).auth_epoch or 0
        n_before = UserSession.query.filter_by(user_id=admin_id).count()
    check("session: two devices signed in before the sweep", n_before == 2, "rows=%d" % n_before)
    _rev = s1.post("/account/sessions/revoke", follow_redirects=False)
    with app.app_context():
        n_all = UserSession.query.filter_by(user_id=admin_id).count()
        epoch_after = db.session.get(User, admin_id).auth_epoch or 0
    check("session: sign-out-everywhere-else bumps the epoch and leaves exactly one row",
          n_all == 1 and epoch_after > epoch_before,
          "rows=%d epoch %d->%d" % (n_all, epoch_before, epoch_after))
    check("session: ...and lands back on the account page, not the login page",
          _rev.status_code in (301, 302, 303) and "/login" not in (_rev.headers.get("Location") or ""),
          "status=%d loc=%s" % (_rev.status_code, _rev.headers.get("Location") or ""))
    _still_in = s1.get("/account", follow_redirects=False)
    check("session: the device that pressed it is STILL signed in",
          _still_in.status_code == 200, "status=%d" % _still_in.status_code)
    _kicked = s3.get("/account", follow_redirects=False)
    check("session: the other device was signed out",
          _kicked.status_code in (301, 302, 303) and "/login" in (_kicked.headers.get("Location") or ""),
          "status=%d" % _kicked.status_code)
    _sess_after = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
    check("session: the survivor is listed, and flagged as this device",
          len(_sess_after) == 1 and _sess_after[0].get("current"), "n=%d" % len(_sess_after))

    # ── An expired login is gone, not listed as active ──
    # Rows used to be pruned only after 45 days of silence, so a session whose cookie died hours
    # (or weeks) ago still sat on the account page labelled active, with a Revoke button that
    # revoked something already gone. Age one row past the session-cookie window and it must
    # vanish from the list — and its cookie must stop authenticating.
    from panel.db.models import prune_expired_sessions as _prune
    from datetime import timedelta as _td
    from panel.core.clock import utcnow as _utcnow_s
    s4, _ = _real_login()
    with app.app_context():
        _sids = {r.sid: r.id for r in UserSession.query.filter_by(user_id=admin_id).all()}
    _live = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
    _stale = next((x for x in _live if not x.get("current")), None)
    with app.app_context():
        _row = db.session.get(UserSession, _stale["id"]) if _stale else None
        if _row is not None:
            _row.remember = False
            # One second past PERMANENT_SESSION_LIFETIME + the last_seen write throttle.
            _life = app.config.get("PERMANENT_SESSION_LIFETIME", 8 * 3600)
            _life = _life.total_seconds() if hasattr(_life, "total_seconds") else float(_life)
            _row.last_seen = _utcnow_s() - _td(seconds=_life + 301)
            db.session.commit()
    _listed = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
    check("session: an expired login is not listed as active",
          _stale is not None and all(x["id"] != _stale["id"] for x in _listed),
          "ids=%s expired=%s" % ([x["id"] for x in _listed], _stale and _stale["id"]))
    with app.app_context():
        _gone = db.session.get(UserSession, _stale["id"]) if _stale else "n/a"
    check("session: ...and its row is deleted, not merely hidden", _gone is None, repr(_gone))
    _dead = s4.get("/account", follow_redirects=False)
    check("session: ...and its cookie no longer authenticates",
          _dead.status_code in (301, 302, 303) and "/login" in (_dead.headers.get("Location") or ""),
          "status=%d" % _dead.status_code)
    # The loader has to reject an expired session on its own, with no sweep having run first —
    # otherwise the only thing stopping a captured "remember me" cookie (which carries no
    # timestamp of any kind) is whether somebody happened to open the account page.
    s5, _ = _real_login()
    with app.app_context():
        _r5 = (UserSession.query.filter_by(user_id=admin_id)
               .order_by(UserSession.created_at.desc()).first())
        _r5.remember = False
        _r5.last_seen = _utcnow_s() - _td(seconds=_life + 301)
        _r5_id = _r5.id
        db.session.commit()
    _dead5 = s5.get("/account", follow_redirects=False)
    check("session: the loader rejects an expired cookie without waiting for a sweep",
          _dead5.status_code in (301, 302, 303) and "/login" in (_dead5.headers.get("Location") or ""),
          "status=%d" % _dead5.status_code)
    with app.app_context():
        check("session: ...and drops the row on the way past",
              db.session.get(UserSession, _r5_id) is None)
    # A "remember me" login gets the longer window, not the session-cookie one — otherwise every
    # remembered login would be swept an hour into a three-day life.
    with app.app_context():
        _r = UserSession(user_id=admin_id, sid="smoke_rem_sid", remember=True,
                         last_seen=_utcnow_s() - _td(seconds=_life + 301))
        db.session.add(_r)
        db.session.commit()
        _rid = _r.id
        _swept = _prune(admin_id)
        _survives = db.session.get(UserSession, _rid) is not None
    check("session: a remembered login is not swept on the session-cookie clock",
          _survives, "swept=%d" % _swept)
    with app.app_context():
        _rem = db.session.get(UserSession, _rid)
        _rem.last_seen = _utcnow_s() - _td(days=400)
        db.session.commit()
        _prune(admin_id)
        _rem_gone = db.session.get(UserSession, _rid) is None
    check("session: ...but it is swept once the remember window is past too", _rem_gone)

    # ── An expired cookie must bounce an in-page call, not hand it the login page ──
    # This is what made a stale tab throw on every click: @login_required answered the fetch with
    # a 302 to /login, fetch followed it, and the caller got 200 text/html where it expected JSON.
    _anon = app.test_client()
    _nav = _anon.get("/account", follow_redirects=False)
    check("auth: a browser navigation still redirects to the login page",
          _nav.status_code in (301, 302, 303) and "/login" in (_nav.headers.get("Location") or ""),
          "status=%d" % _nav.status_code)
    check("auth: ...carrying where to come back to",
          "next=" in (_nav.headers.get("Location") or ""), _nav.headers.get("Location") or "")
    _xhr = _anon.get("/api/account/sessions", headers={"X-Requested-With": "XMLHttpRequest"})
    check("auth: an in-page fetch gets a 401, not the login page",
          _xhr.status_code == 401 and _xhr.headers.get("X-Auth-Required") == "1",
          "status=%d ct=%s" % (_xhr.status_code, _xhr.headers.get("Content-Type")))
    check("auth: ...in the standard JSON envelope the client already understands",
          (_xhr.get_json() or {}).get("success") is False
          and (_xhr.get_json() or {}).get("error") == "auth_required",
          _xhr.get_data(as_text=True)[:120])
    _ping = s1.get("/api/auth/ping")
    check("auth: the wake-up ping confirms a live session",
          _ping.status_code == 200 and (_ping.get_json() or {}).get("success") is True,
          "status=%d" % _ping.status_code)
    _ping_anon = _anon.get("/api/auth/ping")
    check("auth: ...and answers a dead one with the flagged 401",
          _ping_anon.status_code == 401 and _ping_anon.headers.get("X-Auth-Required") == "1",
          "status=%d" % _ping_anon.status_code)
    _page = s1.get("/account")
    check("auth: a signed-in page is never served from the browser cache unrevalidated",
          "no-cache" in (_page.headers.get("Cache-Control") or ""),
          "Cache-Control: %s" % (_page.headers.get("Cache-Control") or "(none)"))

    # A legacy cookie (client_as injects a plain _user_id with no sid, like a pre-feature login) is
    # adopted on first list — so you never see an empty list while logged in.
    lc = client_as(deleg_id)
    lsess = ((lc.get("/api/account/sessions").get_json() or {}).get("sessions", []))
    check("session: a legacy (no-sid) login is adopted and shown as current",
          len(lsess) == 1 and lsess[0].get("current"), "n=%d" % len(lsess))
    with app.app_context():
        n_leg = UserSession.query.filter_by(user_id=deleg_id).count()
    check("session: adoption created a row for the legacy login", n_leg == 1, "rows=%d" % n_leg)
    with app.app_context():
        _leg_rem = UserSession.query.filter_by(user_id=deleg_id).first().remember
    check("session: a legacy login with no remember cookie is adopted on the SHORT window",
          _leg_rem is False or _leg_rem == 0, "remember=%r" % (_leg_rem,))

    # …and one that IS still sending a remember cookie gets the long window. Guessing "plain" for
    # it would delete the row — and sign the device out — hours into a three-day login. Presence of
    # the cookie is the only signal available for a login issued before the column existed.
    with app.app_context():
        UserSession.query.filter_by(user_id=deleg_id).delete()
        db.session.commit()
    lc2 = client_as(deleg_id)
    lc2.set_cookie(app.config.get("REMEMBER_COOKIE_NAME", "remember_token"), "anything-non-empty")
    lc2.get("/api/account/sessions")
    with app.app_context():
        _row2 = UserSession.query.filter_by(user_id=deleg_id).first()
    check("session: a legacy login that still holds a remember cookie is adopted on the LONG window",
          _row2 is not None and bool(_row2.remember), "row=%r" % (_row2 and _row2.remember,))

    # ── History endpoint: a player peak must survive down-sampling (not be decimated away) ──
    from panel.db.models import MetricSample
    from datetime import timedelta as _td
    from panel.core.clock import utcnow as _utcnow
    with app.app_context():
        _base = _utcnow() - _td(hours=6)
        # 500 samples so sstep = 500//240 = 2; players is 0 everywhere except a single spike of 5 at an
        # ODD index — which plain srows[::2] decimation skips. The max-over-window fix must keep it.
        db.session.add_all([
            MetricSample(server_id=gs_id, ts=_base + _td(seconds=i * 30),
                         cpu=1.0, ram_mb=100, players=(5 if i == 101 else 0))
            for i in range(500)])
        db.session.commit()
    _hist = c.get("/api/server/%d/history?range=24h" % gs_id)
    _pl = [p.get("players") for p in (_hist.get_json() or {}).get("server", [])]
    _pmax = max([x for x in _pl if x is not None] or [0])
    check("history: player peak survives down-sampling (max==5, not decimated to 0)",
          _hist.status_code == 200 and _pmax == 5, "status=%d max=%s" % (_hist.status_code, _pmax))
    with app.app_context():
        MetricSample.query.filter_by(server_id=gs_id).delete()
        db.session.commit()

    # ── The dashboard metrics poll, which fans out over a thread pool ─────────────────────────────
    # Each worker used to open its own app context and re-fetch the server + its host: two queries
    # per server, every few seconds, on a page that polls. It now reads frozen values from rows the
    # request already loaded, so this asserts the data still ARRIVES — per-server figures keyed by
    # id, and the host block named from the same rows rather than a fresh lookup.
    # The route calls _host_metrics_work -> _query_host_metrics, both of which live in monitoring.py
    # and resolve these two names in THAT module. Patching app's copies would no-op and the stubs
    # would never run — the poll would try to reach the fixture host for real.
    #
    # host_live_metrics, not server_live_metrics: the poll takes ONE sample per host and slices it
    # per game, so the stub has to sit at the seam the route actually calls. The assertions below
    # are unchanged — they are about what the ENDPOINT returns, which is the contract that matters.
    _dmapp = sys.modules["panel.services.monitoring"]
    _sv_slm, _sv_map = _dmapp.host_live_metrics, _dmapp.game_map
    try:
        _dmapp.host_live_metrics = lambda remote, force=False: {
            "host": {"cpu_percent": 30.0, "ram_used": 4, "ram_total": 8, "disk_used": 1,
                     "disk_total": 4, "uptime_secs": 86400, "cores": 4},
            # Keyed by the game's Linux user, which is how the batched sample reports per-game
            # figures — "csgoserver" is this fixture's short_name (see the GameServer above).
            "users": {"csgoserver": {"game_procs": 2, "game_cpu_percent": 12.5,
                                     "game_ram_mb": 2048, "game_uptime_secs": 900}},
            "ports": set()}
        _dmapp.game_map = lambda *a, **k: "de_dust2"
        _dm = c.get("/api/dashboard/metrics")
        _dj = _dm.get_json() or {}
        _one = (_dj.get("servers") or {}).get(str(gs_id)) or {}
        check("dashboard metrics: the poll answers with per-server figures keyed by id",
              _dm.status_code == 200 and _one.get("ram_mb") == 2048 and _one.get("cpu") == 12.5
              and _one.get("up") is True, "%d %s" % (_dm.status_code, str(_one)[:90]))
        check("dashboard metrics: the running server's map comes back with it",
              _one.get("map") == "de_dust2", str(_one)[:90])
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _want, _rid = _g.remote.display_name, _g.remote_id
        _hostblk = (_dj.get("hosts") or {}).get(str(_rid)) or {}
        check("dashboard metrics: the host block is named from the rows already loaded",
              _hostblk.get("name") == _want, "got %r want %r" % (_hostblk.get("name"), _want))
        check("dashboard metrics: host CPU/RAM/disk percentages are derived, not passed through",
              _hostblk.get("cpu") == 30.0 and _hostblk.get("ram_pct") == 50.0
              and _hostblk.get("disk_pct") == 25.0, str(_hostblk)[:110])
    finally:
        _dmapp.host_live_metrics, _dmapp.game_map = _sv_slm, _sv_map

    # ── perf regression guard: NO N+1 on the hot paths ────────────
    # Seed 50 game servers across 5 hosts — enough that a per-server (rather than
    # per-host) query pattern would blow the budget — then assert the dashboard render
    # and the /api/servers status poll each stay within a small, host-bounded query
    # budget. This is the class of regression that let /api/servers balloon to 53
    # queries before the joinedload fix (now ~3); a budget here fails the build if it
    # ever comes back. run_command is stubbed so the port scan does no real SSH.
    from sqlalchemy import event as _sa_event
    _appmod = sys.modules["app"]
    from panel.ops import ssh_manager as _sm_mod   # the port-scan cache lives here now
    with app.app_context():
        for _r in range(5):
            # 192.0.2.0/24 is RFC 5737 TEST-NET-1: reserved for documentation and guaranteed never
            # routed, like the public_ip below it. 10.20.0.0/24 is ordinary RFC 1918 space that is a
            # LIVE network on plenty of developer machines — the stub on the next line covers the
            # port scan, but the background threads create_app() starts do not go through it, and
            # they opened real SSH connections to a developer's own hosts. Repeated failed auth is
            # exactly what the fail2ban this panel installs on remotes exists to ban.
            _rem = RemoteServer(name="qc-host%d" % _r, host="192.0.2.%d" % _r, port=22,
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

    _orig_rc = _sm_core.run_command
    _sm_core.run_command = lambda *a, **k: ("", "", 0)   # port scan: no real SSH, no matches
    _sa_event.listen(_engine, "after_cursor_execute", _count_query)
    try:
        def _qcount(path, client=None):
            _sm_mod._port_scan_cache.clear()   # force the (stubbed) scan each time, for consistency
            _Q["n"] = 0
            resp = (client or c).get(path)
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

        # The dashboard polls this one every few seconds. Each worker used to open its own session
        # and re-fetch the server + host, so it cost 2 queries PER SERVER — 104 at 50 servers, and
        # ~1000 on a big install, every poll. It is the most expensive thing to get wrong here
        # because nobody has to click anything for it to run.
        _sv_slm2 = _sm_core.server_live_metrics
        _sm_core.server_live_metrics = lambda *a, **k: {"game_procs": 0, "cpu_percent": 1.0}
        try:
            _met_q, _met_code = _qcount("/api/dashboard/metrics")
            check("perf: /api/dashboard/metrics renders with 50 servers", _met_code == 200,
                  "got %d" % _met_code)
            check("perf: the metrics poll does NOT query per server (it polls on a timer)",
                  _met_q <= 15, "%d queries for %d servers" % (_met_q, _seeded))

            # Every budget above is measured as a SUPERADMIN, and is_superadmin short-circuits
            # get_user_servers — so the permission-resolution path that every ORDINARY account goes
            # through was never once counted. Measure it as one.
            # The OS-updates banner calls /api/os-updates/summary on EVERY page load, and the
            # endpoint loops can_access_remote over each host it knows about. That is the shape
            # that turns into an N+1 the moment someone makes the access check hit the database
            # per host — and unlike /api/servers and /, it had no budget guarding it. It returns
            # early (0 queries) while its snapshot is empty, so the snapshot has to be populated
            # for the measurement to mean anything.
            _sv_seen = dict(_appmod._os_update_seen)
            try:
                with app.app_context():
                    for _r in RemoteServer.query.all():
                        _appmod._os_update_seen[_r.id] = {
                            "name": _r.name, "count": 3, "security": 1,
                            "packages": [{"name": "openssl", "suite": "noble-security"}],
                            "at": 1.0}
                _sum_q, _sum_code = _qcount("/api/os-updates/summary")
                check("perf: the OS-updates banner endpoint renders", _sum_code == 200,
                      "got %d" % _sum_code)
                # 5 and 8, not 10 and 15: it really costs 3 and 5, and there are 5 hosts in
                # the snapshot, so a per-host query would add 5. A looser budget would leave the
                # N+1 this guards against comfortably inside it — a gate with too much headroom
                # passes exactly when it matters.
                check("perf: the banner endpoint does NOT query per host",
                      _sum_q <= 5, "%d queries for %d hosts"
                      % (_sum_q, len(_appmod._os_update_seen)))
                _usum_q, _usum_code = _qcount("/api/os-updates/summary", client_as(mru_id))
                # Weaker than the superadmin check by nature, and worth saying so: this user is
                # scoped to one host, so the loop skips the rest and a per-host regression only
                # costs it one query. The superadmin budget above is the one that bites.
                check("perf: ...and stays in budget for a NON-superadmin, whose access check is real",
                      _usum_code == 200 and _usum_q <= 8,
                      "%d queries (status %d)" % (_usum_q, _usum_code))
            finally:
                _appmod._os_update_seen.clear()
                _appmod._os_update_seen.update(_sv_seen)

            _uc = client_as(mru_id)
            _uapi_q, _uapi_code = _qcount("/api/servers", _uc)
            _umet_q, _umet_code = _qcount("/api/dashboard/metrics", _uc)
            check("perf: /api/servers stays in budget for a NON-superadmin too",
                  _uapi_code == 200 and _uapi_q <= 20,
                  "%d queries (status %d)" % (_uapi_q, _uapi_code))
            check("perf: the metrics poll stays in budget for a NON-superadmin too",
                  _umet_code == 200 and _umet_q <= 20,
                  "%d queries (status %d)" % (_umet_q, _umet_code))
        finally:
            _sm_core.server_live_metrics = _sv_slm2

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
        _sm_mod._port_scan_cache.clear()
        c.get("/api/servers")   # the poll that reconcileServerList / the dashboard fires
        with app.app_context():
            _after_status = db.session.get(GameServer, _inst_id).status
        check("install: /api/servers poll does NOT clobber an installing server's status",
              _after_status == "installing", "status became %r after the poll" % _after_status)
    finally:
        _sa_event.remove(_engine, "after_cursor_execute", _count_query)
        _sm_core.run_command = _orig_rc

    # escapeHtml must exist BEFORE a page's own scripts run — five templates had grown local copies
    # because it did not, and two of those returned the RAW string when the global was missing,
    # turning innerHTML sinks into injection points. Assert the definition is in <head>, ahead of
    # the content, and that no fail-open fallback remains.
    _home = c.get("/").get_data(as_text=True)
    _head_end = _home.find("</head>")
    check("escaping: escapeHtml is defined inside <head>",
          0 < _home.find("window.escapeHtml = function") < _head_end,
          "at %d, </head> at %d" % (_home.find("window.escapeHtml = function"), _head_end))
    check("escaping: it is defined exactly once",
          _home.count("window.escapeHtml = function") == 1)
    import pathlib as _pl_esc
    _tpl_dir = _pl_esc.Path(__file__).resolve().parent.parent / "templates"
    _failopen = [p.name for p in _tpl_dir.glob("*.html")
                 if "window.escapeHtml ?" in p.read_text(encoding="utf-8")]
    check("escaping: no template falls back to the raw string", not _failopen, str(_failopen))

    # ── Tags: install-wide labels, their guards, and orphan cleanup ────────────────────────────────
    _tg_new = c.post("/api/tags", json={"name": "production", "color": "#22aa55", "notify": True})
    check("tags: create returns the new tag", _tg_new.status_code == 200
          and (_tg_new.get_json() or {}).get("tag", {}).get("name") == "production",
          _tg_new.get_data(as_text=True)[:140])
    _tag_id = (_tg_new.get_json() or {})["tag"]["id"]
    _tg_mute = c.post("/api/tags", json={"name": "staging", "notify": False})
    _mute_id = (_tg_mute.get_json() or {}).get("tag", {}).get("id")
    check("tags: a muted tag stores notify=False", _tg_mute.status_code == 200 and _mute_id
          and (_tg_mute.get_json() or {})["tag"]["notify"] is False)
    check("tags: a duplicate name is refused (409, not a second row)",
          c.post("/api/tags", json={"name": "PRODUCTION"}).status_code == 409)
    _bad_tag = c.post("/api/tags", json={"name": "<script>x</script>"})
    check("tags: a name the model rejects is a 400, not a 500", _bad_tag.status_code == 400)
    # The message must be the FIXED help text, never the exception's own string: echoing str(exc)
    # back to a client is how internals leak into API responses (CodeQL py/stack-trace-exposure —
    # this exact endpoint tripped that rule once already).
    _bad_msg = (_bad_tag.get_json() or {}).get("message", "")
    check("tags: the rejection message is fixed help text, not exception internals",
          _bad_msg.startswith("A tag name must start with")
          and "<script>" not in _bad_msg and "Traceback" not in _bad_msg, _bad_msg[:120])
    check("tags: a nameless tag is refused", c.post("/api/tags", json={"name": "  "}).status_code == 400)
    check("tags: an invalid colour is dropped, not stored",
          (c.post("/api/tags", json={"name": "nocolor", "color": "javascript:x"})
           .get_json() or {}).get("tag", {}).get("color") == "")
    # Assignment replaces the whole set, and unknown ids are dropped rather than erroring.
    _as = c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": [_tag_id, 999999, "junk"]})
    check("tags: assignment keeps the real ids and drops the rest",
          _as.status_code == 200 and [t["id"] for t in (_as.get_json() or {}).get("tags", [])] == [_tag_id])
    check("tags: a repeated id cannot create a duplicate association",
          [t["id"] for t in (c.post("/api/server/%d/tags" % gs_id,
                                    json={"tag_ids": [_tag_id, _tag_id]}).get_json() or {}).get("tags", [])]
          == [_tag_id])
    check("tags: assignment rejects a non-list payload",
          c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": "production"}).status_code == 400)
    # Assert the CHIP's own markup, not just "data-tag-id appears somewhere" — the filter bar emits
    # that attribute too, and "data-no-i18n" appears in base.html's own i18n JS on every page, so a
    # loose conjunction of the two would pass with no chips rendered at all.
    _dash_html = c.get("/").get_data(as_text=True)
    check("tags: the chip renders on the row with its name and do-not-translate marker",
          ('class="badge tag-chip" data-tag-id="%d" data-no-i18n' % _tag_id) in _dash_html
          and "production</span>" in _dash_html
          and 'class="d-block mt-1 srv-tags" data-no-i18n' in _dash_html,
          "chip markup missing from the rendered dashboard")
    # The muted-tag branch (bell-slash + title) only renders when a MUTED tag is actually assigned.
    c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": [_tag_id, _mute_id]})
    _muted_html = c.get("/").get_data(as_text=True)
    check("tags: a muted tag's chip says so (title + bell-slash icon)",
          'title="Alerts are muted for this tag"' in _muted_html
          and "bi-bell-slash" in _muted_html)
    c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": [_tag_id]})
    check("tags: the tag list endpoint reports which servers carry it",
          gs_id in next((t["server_ids"] for t in (c.get("/api/tags").get_json() or {})["tags"]
                         if t["id"] == _tag_id), []))
    with app.app_context():
        from panel.db.models import game_server_tags as _gst
        _n_assoc = len(db.session.execute(_gst.select()).fetchall())
    check("tags: exactly one association row exists for that pair", _n_assoc == 1, "rows=%d" % _n_assoc)
    # Deleting a tag must take its association rows with it: FKs are never enforced here and SQLite
    # reuses rowids, so an orphan would later be inherited by an unrelated server.
    check("tags: delete succeeds", c.post("/api/tags/%d/delete" % _tag_id).status_code == 200)
    with app.app_context():
        from panel.db.models import game_server_tags as _gst2
        _left = [r for r in db.session.execute(_gst2.select()).fetchall() if r.tag_id == _tag_id]
    check("tags: deleting a tag leaves no orphan association rows", not _left, str(_left))
    check("tags: deleting a tag that does not exist is a 404",
          c.post("/api/tags/999999/delete").status_code == 404)
    with app.app_context():
        from panel.db.models import ServerTag as _ST
        db.session.delete(db.session.get(_ST, _mute_id))
        for _t in _ST.query.filter_by(name="nocolor").all():
            db.session.delete(_t)
        db.session.commit()

    # ── Per-user dashboard layout: the saved order must be SERVER-rendered ─────────────────────────
    # The dashboard replaces #server-cards' innerHTML from its own poll and from another user's
    # install (a servers_changed broadcast), so an order applied only in JS silently reverts. These
    # checks assert the order is in the HTML the server sends, which is the only way it survives.
    with app.app_context():
        _lay_gs2 = GameServer(remote_id=remote2_id, name="smoke-tf2", short_name="tf2server",
                              game_type="tf2", port=27025, installed=True, status="offline")
        db.session.add(_lay_gs2)
        db.session.commit()
        _lay_gs2_id = _lay_gs2.id      # read it INSIDE the session; the instance detaches on exit

    def _card_order(html):
        """Host ids in the order their cards appear in #server-cards."""
        import re as _re_l
        return [int(m) for m in _re_l.findall(r'server-remote-card"\s+data-remote-id="(\d+)"', html)]

    # Deterministic baseline. A previous run that died mid-section can leave a published default in
    # config.json (which this suite only deletes if it created the file), and that would silently
    # redefine what "the default order" means for every check below.
    c.post("/api/settings/ui-default/clear")
    c.post("/api/account/ui-order/reset")
    _lay_default = _card_order(c.get("/").get_data(as_text=True))
    # ≥2 rather than ==2: the perf section above seeds extra hosts, and reordering has to work on
    # whatever is actually there.
    check("layout: every host card carries its id and the default order renders",
          len(_lay_default) >= 2 and remote_id in _lay_default and remote2_id in _lay_default,
          str(_lay_default))
    _flip = list(reversed(_lay_default))
    _lay_save = c.post("/api/account/ui-order", json={"host_order": _flip})
    check("layout: saving an order returns success",
          _lay_save.status_code == 200 and (_lay_save.get_json() or {}).get("success") is True,
          "status=%d body=%s" % (_lay_save.status_code, _lay_save.get_data(as_text=True)[:120]))
    check("layout: the saved order is rendered server-side on the next GET /",
          _card_order(c.get("/").get_data(as_text=True)) == _flip, str(_flip))
    # A refreshSection() swap re-fetches location.href with this header — the replacement HTML must
    # carry the order too, or the user's layout is wiped seconds after they set it.
    check("layout: order survives the in-page refresh path (X-Requested-With)",
          _card_order(c.get("/", headers={"X-Requested-With": "XMLHttpRequest"})
                      .get_data(as_text=True)) == _flip)
    # Ids the caller can't see are dropped rather than rejected, so a stale tab can't poison storage.
    c.post("/api/account/ui-order", json={"host_order": [999999, _flip[0], "junk", None]})
    with app.app_context():
        _stored = db.session.get(User, admin_id).get_ui_prefs().get("host_order")
    check("layout: unknown ids and junk are dropped, real ones kept", _stored == [_flip[0]], str(_stored))
    check("layout: a body with no recognised key is a 400, not a silent no-op",
          c.post("/api/account/ui-order", json={"nope": [1]}).status_code == 400)
    # Per-host row order (phase 2). The dashboard slices one flat list per host, so the risk is a
    # host's rows reordering correctly while some OTHER host's rows shift as a side effect.
    def _row_order(html, remote):
        """Server ids in the order their rows appear inside one host's card."""
        import re as _re_r
        card = _re_r.search(r'data-remote-id="%d".*?</table>' % remote, html, _re_r.S)
        return [int(m) for m in _re_r.findall(r'<tr data-server-id="(\d+)"', card.group(0))] if card else []

    _rows_default = _row_order(c.get("/").get_data(as_text=True), remote_id)
    check("layout: server rows carry their id", len(_rows_default) >= 2, str(_rows_default))
    _rows_flip = list(reversed(_rows_default))
    _other_before = _row_order(c.get("/").get_data(as_text=True), remote2_id)
    _sv = c.post("/api/account/ui-order", json={"server_order": {str(remote_id): _rows_flip}})
    check("layout: saving a per-host server order succeeds", _sv.status_code == 200)
    _html_sv = c.get("/").get_data(as_text=True)
    check("layout: that host's rows render in the saved order",
          _row_order(_html_sv, remote_id) == _rows_flip,
          "got %s want %s" % (_row_order(_html_sv, remote_id), _rows_flip))
    check("layout: another host's rows are NOT disturbed",
          _row_order(_html_sv, remote2_id) == _other_before)
    # A server id belonging to a different host must not be able to move it across cards.
    c.post("/api/account/ui-order", json={"server_order": {str(remote_id): _other_before}})
    _html_x = c.get("/").get_data(as_text=True)
    check("layout: a foreign server id cannot pull a row into another host's card",
          _row_order(_html_x, remote2_id) == _other_before
          and sorted(_row_order(_html_x, remote_id)) == sorted(_rows_default))
    # Movable stat tiles: order and hiding are RENDERED by the server, same as the card order.
    def _tile_order(html):
        import re as _re_t
        row = _re_t.search(r'id="dash-tiles".*?</div>\s*</div>\s*</div>\s*</div>', html, _re_t.S)
        return [m for m in _re_t.findall(r'data-panel="([a-z_]+)"', row.group(0))] if row else []

    _tiles_default = _tile_order(c.get("/").get_data(as_text=True))
    check("tiles: the default order renders with every tile keyed",
          _tiles_default[:2] == ["total", "online"] and len(_tiles_default) == 5, str(_tiles_default))
    _tp = c.post("/api/account/ui-order",
                 json={"panels": {"dash_tiles": ["host", "players", "total", "online", "offline"]}})
    check("tiles: saving a panel order succeeds", _tp.status_code == 200)
    check("tiles: the saved order is rendered server-side",
          _tile_order(c.get("/").get_data(as_text=True))
          == ["host", "players", "total", "online", "offline"])
    # Hiding: the panel must not be rendered at all, and a restore control must appear.
    c.post("/api/account/ui-order", json={"hidden": {"dash_tiles": ["offline", "host"]}})
    _hid_html = c.get("/").get_data(as_text=True)
    check("tiles: hidden tiles are not rendered",
          "offline" not in _tile_order(_hid_html) and "host" not in _tile_order(_hid_html),
          str(_tile_order(_hid_html)))
    # Scoped to the restore BAR: counting over the whole page would also match the inline JS, which
    # contains the literal selector '[data-action="showPanel"]'.
    def _restore_bar(html):
        import re as _re_h
        m = _re_h.search(r'id="dash-tiles-hidden".*?</div>', html, _re_h.S)
        return m.group(0) if m else ""

    _bar = _restore_bar(_hid_html)
    check("tiles: a restore control appears for each hidden tile",
          _bar.count('data-action="showPanel"') == 2
          and '["dash_tiles","offline","@self"]' in _bar
          and '["dash_tiles","host","@self"]' in _bar,
          "bar=%r" % _bar[:200])
    # The safety property, end to end: a stored key the page never declared cannot add a panel.
    c.post("/api/account/ui-order", json={"panels": {"dash_tiles": ["evil", "total"]},
                                          "hidden": {"dash_tiles": []}})
    _evil = _tile_order(c.get("/").get_data(as_text=True))
    check("tiles: an unknown stored key renders no panel", "evil" not in _evil and len(_evil) == 5,
          str(_evil))
    # Drag handles: the reorder LOGIC is JS (verified separately in a browser harness against the
    # real makeSortable), but these assert the wiring exists — a handle with no makeSortable call, or
    # a call with no handle, is a control that silently does nothing.
    _drag_html = page_with_assets(c, "/")
    import re as _re_d
    check("drag: the stat tiles have a handle inside a data-panel item",
          bool(_re_d.search(r'data-panel="\w+"[^>]*>\s*<div class="card[^"]*panel-movable"[^>]*>\s*'
                            r'<span class="panel-tools[^"]*"[^>]*>\s*<span[^>]*data-drag-handle',
                            _drag_html)))
    check("drag: each host card header has a handle",
          bool(_re_d.search(r'host-move[^>]*>\s*<span[^>]*data-drag-handle', _drag_html)))
    check("drag: each server row has a handle",
          bool(_re_d.search(r'srv-move[^>]*>\s*<span[^>]*data-drag-handle', _drag_html)))
    # Assert the three bindings by their actual targets. A bare count would also match base.html's
    # own doc comment ("makeSortable(container, {...})"), which is inlined into every page.
    # Pair each CALL with the DEFINITION: on its own, a call-site string proves only that the text
    # exists — it would still pass if makeSortable had been renamed or deleted.
    check("drag: makeSortable is actually defined on the page that calls it",
          "window.makeSortable = function(container, opts)" in _drag_html)
    # Editing controls must be INVISIBLE during normal use. They were absolutely positioned over the
    # card and revealed on hover, with @media (hover: none) making them permanent on touch — which
    # put a row of buttons on top of every stat tile's value on a phone. Verified in a browser at
    # 375px: the old rules overlapped all five tiles, these overlap none.
    check("layout: the editing controls are hidden until edit mode",
          ".panel-tools, .host-move, .srv-move { display: none; }" in _drag_html)
    check("layout: nothing makes them visible again on touch",
          "@media (hover: none) { .panel-tools" not in _drag_html)
    check("layout: in edit mode they sit IN FLOW, so they cannot overlay the content",
          "body.layout-edit .panel-tools { position: static;" in _drag_html)
    check("layout: the dashboard offers a way to turn edit mode on",
          'data-action="toggleLayoutEdit"' in _drag_html
          and "window.toggleLayoutEdit = function" in _drag_html)
    check("layout: edit mode survives the reload that restoring a panel triggers",
          "sessionStorage.getItem('layoutEdit')" in _drag_html)
    check("drag: nested sortables cannot both claim one handle",
          "handle.closest('[data-sortable]') !== container" in _drag_html)
    check("drag: non-rendered siblings are skipped as drop targets",
          "!el.getClientRects().length" in _drag_html)
    check("drag: the tile row is bound",
          "makeSortable(document.getElementById('dash-tiles')" in _drag_html)
    check("drag: the host-card region is bound",
          "makeSortable(document.getElementById('server-cards')" in _drag_html)
    check("drag: each host's row body is bound",
          "makeSortable(tb, {itemSelector: 'tr[data-server-id]'" in _drag_html)
    check("drag: handles are touch-safe and keyboard-neutral",
          'class="btn btn-outline-secondary sort-handle" data-drag-handle aria-hidden="true"' in _drag_html)
    # ── The install default: a superadmin publishes their layout, OTHER accounts inherit it ───────
    # The point of the feature is cross-account, so it is asserted with a second client.
    c.post("/api/account/ui-order", json={"panels": {"dash_tiles": ["host", "total", "online",
                                                                    "offline", "players"]}})
    _pub = c.post("/api/settings/ui-default")
    check("default: a superadmin can publish their layout", _pub.status_code == 200,
          _pub.get_data(as_text=True)[:120])
    # smoke_mr, not smoke_deleg: the latter has no server access, so its dashboard renders the
    # empty-state with no tiles to order at all.
    _other = client_as(mru_id)            # a non-superadmin with server access, no layout of its own
    check("default: another account inherits the published order",
          _tile_order(_other.get("/").get_data(as_text=True))[0] == "host",
          str(_tile_order(_other.get("/").get_data(as_text=True))))
    # ...but a user's own arrangement still wins over the house one.
    _other.post("/api/account/ui-order", json={"panels": {"dash_tiles": ["players", "total"]}})
    check("default: a user's own layout beats the published default",
          _tile_order(_other.get("/").get_data(as_text=True))[0] == "players")
    # Resetting returns them to the HOUSE layout, not to bare defaults — the whole reason an admin
    # publishes one.
    _other.post("/api/account/ui-order/reset")
    check("default: reset lands on the house layout, not the built-in order",
          _tile_order(_other.get("/").get_data(as_text=True))[0] == "host")
    check("default: publishing is superadmin-only",
          _other.post("/api/settings/ui-default").status_code == 403)
    check("default: clearing is superadmin-only",
          _other.post("/api/settings/ui-default/clear").status_code == 403)
    check("default: clearing it returns everyone to the built-in order",
          c.post("/api/settings/ui-default/clear").status_code == 200
          and _tile_order(_other.get("/").get_data(as_text=True))[0] == "total")
    # ── server_detail console-tab panel order ─────────────────────────────────────────────────────
    # The interesting property here is NEGATIVE: two of that page's panels only exist behind a
    # condition (custom commands assigned; game_type == 'gmod'), so a stored key for one of them must
    # render nothing at all. This smoke server has neither, which is exactly the case to assert.
    def _detail_panels(html):
        """Panel keys inside #detail-console, in render order. Walks div depth to find the region's
        real end — a non-greedy match on '</div>' stops inside the FIRST card and silently reports
        one panel, which makes every assertion built on it vacuous."""
        i = html.find('id="detail-console"')
        if i < 0:
            return []
        depth, j = 0, html.find(">", i) + 1
        while j < len(html):
            nxt_open, nxt_close = html.find("<div", j), html.find("</div>", j)
            if nxt_close < 0:
                break
            if 0 <= nxt_open < nxt_close:
                depth += 1
                j = nxt_open + 4
            else:
                if depth == 0:
                    break                      # this </div> closes the region itself
                depth -= 1
                j = nxt_close + 6
        region = html[i:j]
        return _re_d.findall(r'data-panel="([a-z_]+)"', region)

    _det = c.get("/server/%d" % gs_id).get_data(as_text=True)
    _det_default = _detail_panels(_det)
    check("detail: the console panels render with keys",
          _det_default == ["controls", "console", "players"], str(_det_default))
    _dp = c.post("/api/account/ui-order",
                 json={"panels": {"detail_console": ["players", "console", "controls"]}})
    check("detail: saving the console panel order succeeds", _dp.status_code == 200)
    check("detail: the saved order is rendered server-side",
          _detail_panels(c.get("/server/%d" % gs_id).get_data(as_text=True))
          == ["players", "console", "controls"])
    # The safety property: 'commands' and 'content' are not declared for this server, so no stored
    # value may summon them.
    c.post("/api/account/ui-order",
           json={"panels": {"detail_console": ["commands", "content", "controls", "console", "players"]}})
    _det_evil = _detail_panels(c.get("/server/%d" % gs_id).get_data(as_text=True))
    check("detail: a stored key for a gated panel renders NOTHING",
          "commands" not in _det_evil and "content" not in _det_evil
          and _det_evil == ["controls", "console", "players"], str(_det_evil))
    # Hiding works the same as on the dashboard, and the restore bar is tab-scoped so it cannot leak
    # onto the History/Details tabs.
    c.post("/api/account/ui-order", json={"panels": {"detail_console": ["controls", "console", "players"]},
                                          "hidden": {"detail_console": ["players"]}})
    _det_hid = c.get("/server/%d" % gs_id).get_data(as_text=True)
    check("detail: a hidden panel is not rendered", "players" not in _detail_panels(_det_hid))
    check("detail: the restore bar is scoped to the console tab",
          bool(_re_d.search(r'id="detail-console-hidden"[^>]*data-mtab="console"', _det_hid)))
    # Hiding the Controls panel removes the stats canvas. initChart() must survive that: it used to
    # dereference the canvas unguarded, and the resulting TypeError aborted the REST of the inline
    # script — including the handlers that undo a hide, so the page had no way back.
    c.post("/api/account/ui-order", json={"panels": {"detail_console": ["controls", "console", "players"]},
                                          "hidden": {"detail_console": ["controls"]}})
    _no_ctrl = c.get("/server/%d" % gs_id).get_data(as_text=True)
    # The page's own script is a cacheable file now, so the JS assertions below have to follow the
    # reference. The markup check above stays on the HTML alone — that is what it is about.
    _no_ctrl_js = page_with_assets(c, "/server/%d" % gs_id)
    check("detail: the server page offers the same edit-mode toggle",
          'data-action="toggleLayoutEdit"' in _det)
    check("detail: hiding Controls removes the stats canvas", 'id="stats-chart"' not in _no_ctrl)
    check("detail: initChart is guarded against the missing canvas",
          "var canvas = document.getElementById('stats-chart');\n  if (!canvas) return;" in _no_ctrl_js)
    # "initChart();" (the CALL) — "function initChart() {" is a different string, so this anchors on
    # the bootstrap, not the definition.
    check("detail: the undo-a-hide handlers are defined BEFORE the bootstrap calls",
          "initChart();" in _no_ctrl_js
          and _no_ctrl_js.index("window.showDetailPanel = function") < _no_ctrl_js.index("initChart();"),
          "showDetailPanel at %s, initChart() call at %s"
          % (_no_ctrl_js.find("window.showDetailPanel = function"), _no_ctrl_js.find("initChart();")))
    c.post("/api/account/ui-order", json={"hidden": {"detail_console": []}})
    # Each page only knows its OWN regions, so the endpoint must merge rather than replace the map.
    # Before this was fixed, saving on the dashboard deleted the server page's layout and vice versa.
    c.post("/api/account/ui-order", json={"panels": {"detail_console": ["players", "console", "controls"]},
                                          "declared": {"detail_console": ["controls", "console", "players"]}})
    c.post("/api/account/ui-order", json={"panels": {"dash_tiles": ["host", "total", "online",
                                                                    "offline", "players"]},
                                          "declared": {"dash_tiles": ["total", "online", "offline",
                                                                      "players", "host"]}})
    with app.app_context():
        _both = db.session.get(User, admin_id).get_ui_prefs().get("panels") or {}
    check("regions: saving one page's layout does not wipe the other's",
          _both.get("detail_console") == ["players", "console", "controls"]
          and _both.get("dash_tiles", [""])[0] == "host", str(_both))
    check("regions: the other page's order still renders",
          _detail_panels(c.get("/server/%d" % gs_id).get_data(as_text=True))
          == ["players", "console", "controls"])
    # Within a region, keys the page could not have sent are preserved: a server without the gated
    # Commands panel must not erase where that panel sits on servers that DO have it.
    c.post("/api/account/ui-order", json={"panels": {"detail_console": ["commands", "controls",
                                                                        "console", "players"]},
                                          "declared": {"detail_console": ["controls", "console",
                                                                          "players", "commands"]}})
    c.post("/api/account/ui-order", json={"panels": {"detail_console": ["players", "controls", "console"]},
                                          "declared": {"detail_console": ["controls", "console", "players"]}})
    with app.app_context():
        _kept = (db.session.get(User, admin_id).get_ui_prefs().get("panels") or {}).get("detail_console")
    check("regions: a gated key the page never offered is kept, not erased",
          "commands" in (_kept or []), str(_kept))
    _lay_reset = c.post("/api/account/ui-order/reset")
    check("layout: reset returns success", _lay_reset.status_code == 200
          and (_lay_reset.get_json() or {}).get("success") is True)
    with app.app_context():
        check("layout: reset clears the keys entirely (absent == default)",
              db.session.get(User, admin_id).get_ui_prefs() == {})
    check("layout: after reset the default order is back",
          _card_order(c.get("/").get_data(as_text=True)) == _lay_default)
    _lay_anon = app.test_client().post("/api/account/ui-order", json={"host_order": [1]})
    check("layout: saving requires a login", _lay_anon.status_code != 200, "got %d" % _lay_anon.status_code)
    with app.app_context():
        db.session.delete(db.session.get(GameServer, _lay_gs2_id))
        db.session.commit()

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
        from panel.db.models import _run_light_migrations as _rlm
        _models_src = (_pl_mig.Path(__file__).resolve().parent.parent
               / "panel" / "db" / "models.py").read_text(encoding="utf-8")
        _mig = _re_mig.findall(r'\(\s*"(\w+)"\s*,\s*"(\w+)"\s*\)\s*:\s*"(ALTER TABLE [^"]+)"', _models_src)
        check("migration: the light-migration list parses out of models.py", len(_mig) > 5)
        _cols = {t: {c["name"] for c in _sa_inspect(db.engine).get_columns(t)}
                 for t in _sa_inspect(db.engine).get_table_names()}
        _stale = [(t, c) for t, c, _ in _mig if c not in _cols.get(t, set())]
        check("migration: no entry targets a table/column that no longer exists", not _stale, str(_stale))
        # The INVERSE check, which is the one that actually protects upgraded installs: a column added
        # to a model WITHOUT a migration entry is invisible here (create_all builds CI's DB fresh, so
        # it is always present) and then throws "no such column" on every request of every upgraded
        # install — including /login, i.e. a total outage nobody can log in to fix. Columns present in
        # the very first release need no entry, hence the baseline.
        # Columns that shipped in the initial release (16cff95) — extracted from that commit's
        # models.py, not hand-listed, so it is a fact rather than a guess. Anything a later version
        # added must carry an entry; note api_token, commands, daily_restart and public_ip appear
        # here AND in the map, which is harmless.
        _baseline = {
            "user": {"api_token", "created_at", "display_name", "email", "id", "is_active",
                     "is_superadmin", "last_login", "password_hash", "username"},
            "game_server": {"autostart", "commands", "created_at", "daily_restart", "game_display",
                            "game_type", "id", "installed", "name", "port", "query_port",
                            "remote_id", "short_name", "status"},
            "remote_server": {"auth_credential", "auth_method", "created_at", "host", "id",
                              "is_local", "is_online", "last_seen", "linuxgsm_user", "name",
                              "port", "public_ip", "sudo_enabled", "username"},
        }
        _have_entry = {(t, c) for t, c, _ in _mig}
        _unmigrated = sorted((t, c) for t, base in _baseline.items()
                             for c in _cols.get(t, set())
                             if c not in base and (t, c) not in _have_entry)
        check("migration: every added column on a core table has an ALTER entry (upgrade safety)",
              not _unmigrated, "missing entries for: %s" % str(_unmigrated))
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

    # ── A deleted row must not leave its history for the next row to inherit ──────────────────────
    # MetricSample and HostSample carry no FK — deliberately, so the ~1/min write stays cheap — and
    # the docstring called the orphans harmless ("just age out"). They are not: SQLite hands a deleted
    # row's id to the next INSERT, so for up to 14 days a freshly-installed server whose id was
    # recycled showed the DELETED server's CPU, RAM and player counts on its history chart. Measured
    # before the fix: 3 rows survived the delete and the new server's chart returned all three.
    from panel.db.models import (db as _hs_db, GameServer as _HSGame,                  # noqa: E402
                                 RemoteServer as _HSRemote, MetricSample as _HSMetric,
                                 HostSample as _HSHost)
    with app.app_context():
        _hs_r = _HSRemote(name="hs-host", host="192.0.2.77", port=22, username="u",
                          auth_method="key", auth_credential="")
        _hs_db.session.add(_hs_r); _hs_db.session.commit()
        _hs_g = _HSGame(name="hs-cod", short_name="hscodserver", game_type="cod", port=28961,
                        remote_id=_hs_r.id)
        _hs_db.session.add(_hs_g); _hs_db.session.commit()
        for _ in range(3):
            _hs_db.session.add(_HSMetric(server_id=_hs_g.id, cpu=99.0, ram_mb=4096, players=31))
            _hs_db.session.add(_HSHost(remote_id=_hs_r.id, cpu=97.5, ram_pct=91.0, disk_pct=88.0))
        _hs_db.session.commit()
        _hs_gid, _hs_rid = _hs_g.id, _hs_r.id
        _hs_db.session.delete(_hs_g); _hs_db.session.commit()
        check("history: deleting a game server clears its metric samples",
              _hs_db.session.query(_HSMetric).filter_by(server_id=_hs_gid).count() == 0,
              "%d rows survived" % _hs_db.session.query(_HSMetric).filter_by(server_id=_hs_gid).count())
        _hs_db.session.delete(_hs_r); _hs_db.session.commit()
        check("history: deleting a host clears its host samples",
              _hs_db.session.query(_HSHost).filter_by(remote_id=_hs_rid).count() == 0,
              "%d rows survived" % _hs_db.session.query(_HSHost).filter_by(remote_id=_hs_rid).count())

    # ── Monitor + player-count poller transition logic ────────────────────────────────────────────
    # These background passes drive the admin notifications. create_app() does NOT start the watcher
    # threads, so we run a pass by hand — single-threaded, with the host/SSH helpers stubbed — to
    # exercise the real up/down, suppression, and notify-when-empty branches in _monitor_pass /
    # _refresh_player_counts and confirm each fires (or stays silent) exactly when it should.
    with app.app_context():
        import time as _time_mon
        _am = sys.modules["app"]
        # _monitor_pass lives in monitoring.py now and looks its helpers up in THAT module's
        # namespace, so stubbing app's copy would silently no-op and the probes would run for
        # real. Patch where the function actually resolves the name.
        _monmod = sys.modules["panel.services.monitoring"]
        _ps = sys.modules["panel.core.panel_state"]
        _r1 = RemoteServer.query.filter_by(name="smoke-host").first()
        _mon = GameServer(remote_id=_r1.id, name="mon-srv", short_name="monserver",
                          game_type="csgo", port=27100, installed=True, status="online")
        db.session.add(_mon); db.session.commit()
        _mon_id, _r1_id = _mon.id, _r1.id
        _rec = []
        _saved = {n: getattr(_monmod, n) for n in ("_host_reachable", "_remote_listening_ports",
                  "_host_disk_pct", "_host_load_mem", "_server_slots", "_server_max_config")}
        _saved_notify = _am.notifications.notify
        _saved_mstate = {k: dict(v) for k, v in _ps._monitor_state.items()}
        _saved_exp = dict(_ps._expected_offline)
        _saved_full = dict(_ps._server_full_alerted)
        _saved_peak = dict(_ps._server_peak_notified)
        _saved_pc = dict(_ps._player_counts)
        try:
            _am.notifications.notify = lambda key, title, body="": _rec.append(key)
            _monmod._host_reachable = lambda r: True
            _monmod._host_disk_pct = lambda r: 40
            _monmod._host_load_mem = lambda r: (10, 10)
            _monmod._server_max_config = lambda gs: 16

            def _reset_mon():
                # Cleared IN PLACE, never rebound: monitoring.py holds a direct reference to
                # this dict (`from panel_state import _monitor_state`), so assigning a fresh one
                # here would leave the monitor reading the old object and the reset would silently
                # do nothing. See the contract in panel_state's docstring.
                for _bucket in _ps._monitor_state.values():
                    _bucket.clear()

            # The very first pass only records a baseline — nothing alerts on startup.
            _reset_mon()
            _monmod._remote_listening_ports = lambda r: {27100}
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: the first pass is a silent baseline (no startup alerts)",
                  not any(k in _rec for k in ("server_down", "server_up", "remote_unreachable")),
                  "fired: %s" % _rec)

            # A server that was up and is no longer listening -> server_down.
            _monmod._remote_listening_ports = lambda r: set()
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: server_down fires on an up->down transition", "server_down" in _rec)

            # ...but a panel-issued stop (inside the expected-offline window) suppresses it.
            _reset_mon()
            _ps._monitor_state["servers"][_mon_id] = True
            _ps._expected_offline[_mon_id] = _time_mon.time()
            _monmod._remote_listening_ports = lambda r: set()
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: a panel-issued stop suppresses server_down", "server_down" not in _rec)
            _ps._expected_offline.pop(_mon_id, None)

            # ── The sweep must WRITE DOWN what it measured ────────────────────────────────────
            # It computed `up` from a live port scan every 60s and kept it only in an in-memory
            # dict. gs.status — what the chat bots' /servers and /status render, and what
            # _query_server_slots uses to decide whether a server is worth querying at all — was
            # written only by the three browser-polled endpoints. With nobody on the dashboard the
            # column froze, so a server that died (or came back) while no one was looking kept
            # reporting its last browser-observed state indefinitely.
            def _status_after_pass(start_status):
                """gs.status as it survives a sweep — COMMITTED, not merely assigned.

                The monitor shares this session, so a plain refresh would autoflush its pending
                write and read it straight back: the check would pass with the commit deleted. The
                rollback discards anything the sweep left uncommitted, so only a real commit shows
                up here."""
                _mon.status = start_status
                db.session.commit()
                _monmod._monitor_pass()
                db.session.rollback()
                db.session.refresh(_mon)
                return _mon.status

            _reset_mon()
            _monmod._remote_listening_ports = lambda r: set()
            _st_down = _status_after_pass("online")
            check("monitor: a sweep persists a server that has gone down",
                  _st_down == "offline", "status=%r" % _st_down)
            # Start from "offline" so this can only pass on an actual write, not on the value the
            # previous case left behind.
            _monmod._remote_listening_ports = lambda r: {27100}
            _st_up = _status_after_pass("offline")
            check("monitor: ...and persists it coming back up", _st_up == "online",
                  "status=%r" % _st_up)
            # An in-progress install must never be flipped to online/offline by a port scan — it
            # isn't listening yet, and that would erase the progress row.
            _monmod._remote_listening_ports = lambda r: set()
            _st_inst = _status_after_pass("installing")
            check("monitor: an installing server's status is left alone",
                  _st_inst == "installing", "status=%r" % _st_inst)
            _mon.status = "online"; db.session.commit()

            # A reachable host that stops responding -> remote_unreachable.
            _reset_mon()
            _ps._monitor_state["remotes"].clear()
            _ps._monitor_state["remotes"][_r1_id] = True
            _monmod._host_reachable = lambda r: r.id != _r1_id
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: remote_unreachable fires when a host stops responding",
                  "remote_unreachable" in _rec)
            _monmod._host_reachable = lambda r: True

            # gs.status is an INPUT to the poller: _query_server_slots answers a server it believes
            # offline with a confident 0 players and never queries it. The monitor now keeps that
            # column honest instead of leaving it to whatever a browser last polled, so these cases
            # have to state which state they mean rather than inherit the last pass's measurement.
            def _mon_running():
                _mon.status = "online"
                db.session.commit()

            # ...and _rec only records the alert KEY, so scope the stub to this server: a second
            # server going empty or full would otherwise satisfy (or break) a check about this one.
            def _slots_for_mon(mon):
                """`mon` is (count, max, name) for THIS server; every other reports a quiet 1/16."""
                return lambda gs: mon if gs.id == _mon_id else (1, 16, None)

            # Poller: notify_when_empty is a one-shot on a CONFIRMED 0 that then disarms itself.
            _mon.notify_when_empty = True; _mon_running()
            _monmod._server_slots = _slots_for_mon((0, 16, None))
            _rec.clear(); _monmod._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("poller: notify_when_empty fires server_empty at a confirmed 0", "server_empty" in _rec)
            check("poller: notify_when_empty is one-shot (clears its own flag)",
                  _mon.notify_when_empty is False)

            # ...but it must NEVER fire on an unknown count (a running server the panel can't read).
            _mon.notify_when_empty = True; _mon_running()

            def _unreadable(gs):
                if gs.id == _mon_id:
                    raise RuntimeError("count unavailable")
                return (1, 16, None)
            _monmod._server_slots = _unreadable
            _rec.clear(); _monmod._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("poller: notify_when_empty does NOT fire on an unknown count", "server_empty" not in _rec)
            check("poller: notify_when_empty stays armed when the count is unknown",
                  _mon.notify_when_empty is True)

            # server_full fires when a server reaches its cap.
            _ps._server_full_alerted.pop(_mon_id, None)
            _mon_running()
            _monmod._server_slots = _slots_for_mon((16, 16, None))
            _rec.clear(); _monmod._refresh_player_counts(app)
            check("poller: server_full fires when a server hits its cap", "server_full" in _rec)

            # ── The sweep probes hosts concurrently, not one after another ────────────────────
            # It used to walk them serially, so its duration was the SUM of every host's latency and
            # one unreachable host (an SSH connect timeout) held up the checks for all the others.
            import time as _mt
            _sv_probes = (_monmod._host_reachable, _monmod._host_disk_pct, _monmod._host_load_mem,
                          _monmod._remote_listening_ports, _monmod._host_restart_flags)
            try:
                _DWELL = 0.05
                _monmod._host_reachable = lambda r: (_mt.sleep(_DWELL), True)[1]
                _monmod._host_disk_pct = lambda r: (_mt.sleep(_DWELL), 40)[1]
                _monmod._host_load_mem = lambda r: (_mt.sleep(_DWELL), (10, 10))[1]
                _monmod._remote_listening_ports = lambda r: (_mt.sleep(_DWELL), set())[1]
                _monmod._host_restart_flags = lambda r: (_mt.sleep(_DWELL), set())[1]
                with app.app_context():
                    _nhosts = RemoteServer.query.count()
                _reset_mon()
                _t0 = _mt.time(); _monmod._monitor_pass(); _elapsed = _mt.time() - _t0
                # Serial would be hosts x 4 probes x dwell; concurrent is ~4 x dwell regardless of
                # how many hosts there are. Half of serial is a wide margin either way.
                _serial = _nhosts * 5 * _DWELL
                check("monitor: hosts are probed concurrently, so one slow host holds up no others",
                      _nhosts >= 3 and _elapsed < _serial / 2,
                      "%d hosts: %.2fs elapsed vs %.2fs if serial" % (_nhosts, _elapsed, _serial))
            finally:
                (_monmod._host_reachable, _monmod._host_disk_pct, _monmod._host_load_mem,
                 _monmod._remote_listening_ports, _monmod._host_restart_flags) = _sv_probes

            # ── The sweep records which servers the BOX has queued for restart ────────────────
            # One `ls /home/*/.restart-pending` per host, mapped back to the game user. Without
            # this the banner test above would pass while nothing ever populated the dict.
            _sv_rf = _monmod._host_restart_flags
            try:
                with app.app_context():
                    _mon_user = db.session.get(GameServer, _mon_id).short_name
                _monmod._host_restart_flags = lambda r: {_mon_user}
                _ps._cron_restart_pending.clear()
                _reset_mon()
                _monmod._monitor_pass()
                check("monitor: a server whose box has the restart flag is recorded",
                      _ps._cron_restart_pending.get(_mon_id) is True,
                      str(dict(list(_ps._cron_restart_pending.items())[:3])))
                _others = [v for k, v in _ps._cron_restart_pending.items() if k != _mon_id]
                check("monitor: and servers without the flag are recorded as not pending",
                      _others and not any(_others), str(_others[:5]))
                _monmod._host_restart_flags = lambda r: set()
                _monmod._monitor_pass()
                check("monitor: clearing the flag on the box clears it here too",
                      _ps._cron_restart_pending.get(_mon_id) is False)
            finally:
                _monmod._host_restart_flags = _sv_rf
                _ps._cron_restart_pending.clear()

            # ── A scheduled LinuxGSM update must not read as a crash ───────────────────────────
            # Stock LinuxGSM installs carry their own cron (e.g. "30 4 * * * ./gmodserver
            # force-update"). That takes the server down without telling the panel, so the monitor
            # alerted "went offline unexpectedly" every single night at the same minute.
            _saved_maint = _monmod._lgsm_maintenance_running
            _key_notify = lambda key, title, body="": _rec.append(key)          # noqa: E731
            _probes = []
            try:
                _reset_mon()
                _ps._monitor_state["servers"][_mon_id] = True
                _monmod._remote_listening_ports = lambda r: set()
                _monmod._lgsm_maintenance_running = lambda remote, gs: _probes.append(gs.id) or True
                _rec.clear(); _monmod._monitor_pass()
                check("maintenance: a scheduled update does not alert as a crash",
                      "server_down" not in _rec, str(_rec))
                check("maintenance: the recorded state is left alone, so recovery is not an 'up' alert",
                      _ps._monitor_state["servers"].get(_mon_id) is True)
                # Record bodies too: _rec holds only event KEYS, and the fixture has other servers
                # whose own transitions would otherwise be read as this one's.
                _bodies = []
                _am.notifications.notify = lambda k, t, b="": (_rec.append(k), _bodies.append((k, b)))[0]
                _monmod._remote_listening_ports = lambda r: {27100}
                _monmod._monitor_pass()
                _am.notifications.notify = _key_notify
                check("maintenance: coming back from an update is silent too",
                      not [b for k, b in _bodies if k == "server_up" and "mon-srv" in b],
                      str([b for k, b in _bodies if k == "server_up"])[:120])
                # The probe is an SSH round trip: it must fire ONLY on a down transition, never on a
                # baseline pass, a steady-state pass, or a recovery — otherwise every monitor tick
                # pays for it once per server.
                _reset_mon()
                _probes.clear()
                _monmod._remote_listening_ports = lambda r: {27100}
                _monmod._monitor_pass(); _monmod._monitor_pass()     # baseline, then steady-state up
                check("maintenance: no SSH probe unless a server actually went down", not _probes,
                      "probed %s" % _probes)
                # A stop the PANEL issued is already known locally — that must not cost a probe either.
                _monmod._remote_listening_ports = lambda r: set()
                _am._mark_expected_offline(_mon_id)
                _probes.clear(); _rec.clear(); _monmod._monitor_pass()
                check("maintenance: a panel-issued stop is handled locally, with no probe",
                      _mon_id not in _probes and "server_down" not in _rec,
                      "probed %s / fired %s" % (_probes, _rec))
                # ...and a REAL crash still alerts: same down transition, no maintenance running.
                _reset_mon()
                _ps._expected_offline.pop(_mon_id, None)
                _ps._monitor_state["servers"][_mon_id] = True
                _monmod._remote_listening_ports = lambda r: set()
                _monmod._lgsm_maintenance_running = lambda remote, gs: False
                _rec.clear(); _monmod._monitor_pass()
                check("maintenance: a genuine crash still alerts", "server_down" in _rec, str(_rec))
            finally:
                _monmod._lgsm_maintenance_running = _saved_maint
                _am.notifications.notify = _key_notify
                _ps._expected_offline.pop(_mon_id, None)

            # ── A tag with notify=False silences that server's alerts ──────────────────────────
            # This is the only user-visible behaviour tags add beyond decoration, and it is wired
            # into five separate notify() sites — so it is asserted through the REAL passes here.
            # (Verified by mutation: with the _alerts_muted guards removed, every check below fails.)
            from panel.db.models import ServerTag as _STm
            _mute_tag = _STm(name="muted-smoke", notify=False)
            db.session.add(_mute_tag)
            _mon.tags = [_mute_tag]
            db.session.commit()

            _reset_mon()
            _ps._monitor_state["servers"][_mon_id] = True
            _monmod._remote_listening_ports = lambda r: set()
            _rec.clear(); _monmod._monitor_pass()
            check("mute: a muted tag suppresses server_down", "server_down" not in _rec, str(_rec))
            _reset_mon()
            _ps._monitor_state["servers"][_mon_id] = False
            _monmod._remote_listening_ports = lambda r: {27100}
            _rec.clear(); _monmod._monitor_pass()
            check("mute: a muted tag suppresses server_up", "server_up" not in _rec, str(_rec))

            _mon.notify_when_empty = True; _mon_running()
            _monmod._server_slots = _slots_for_mon((0, 16, None))
            _rec.clear(); _monmod._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("mute: a muted tag suppresses server_empty", "server_empty" not in _rec, str(_rec))
            # The request must stay ARMED: muting hides the alert, it does not consume the ask, so
            # it still fires the first time the server empties after the tag comes off.
            check("mute: notify_when_empty stays armed while muted", _mon.notify_when_empty is True)

            _ps._server_full_alerted.pop(_mon_id, None)
            _mon_running()
            _monmod._server_slots = _slots_for_mon((16, 16, None))
            _rec.clear(); _monmod._refresh_player_counts(app)
            check("mute: a muted tag suppresses server_full", "server_full" not in _rec, str(_rec))
            # ...but it IS marked alerted, so unmuting later doesn't fire retroactively about a
            # server that has been sitting at its cap the whole time.
            check("mute: server_full is still marked alerted while muted",
                  _ps._server_full_alerted.get(_mon_id) is True)

            _ps._server_peak_notified.pop(_mon_id, None)
            _mon.peak_players = 1; _mon_running()
            _monmod._server_slots = _slots_for_mon((9, 16, None))
            _rec.clear(); _monmod._refresh_player_counts(app)
            db.session.refresh(_mon)
            check("mute: a muted tag suppresses server_peak", "server_peak" not in _rec, str(_rec))
            check("mute: the peak is still RECORDED while muted (data, not an alert)",
                  _mon.peak_players == 9, "peak=%s" % _mon.peak_players)

            # Remove the tag and the same transition alerts again — proving the silence above came
            # from the tag and not from some unrelated state the passes left behind.
            _mon.tags = []
            db.session.commit()
            _reset_mon()
            _ps._monitor_state["servers"][_mon_id] = True
            _monmod._remote_listening_ports = lambda r: set()
            _rec.clear(); _monmod._monitor_pass()
            check("mute: removing the tag restores server_down", "server_down" in _rec, str(_rec))
            db.session.delete(_mute_tag); db.session.commit()
        finally:
            _am.notifications.notify = _saved_notify
            for _n, _v in _saved.items():
                setattr(_monmod, _n, _v)
            for _k, _v in _saved_mstate.items():
                _ps._monitor_state[_k].clear(); _ps._monitor_state[_k].update(_v)
            _ps._expected_offline.clear(); _ps._expected_offline.update(_saved_exp)
            _ps._server_full_alerted.clear(); _ps._server_full_alerted.update(_saved_full)
            _ps._server_peak_notified.clear(); _ps._server_peak_notified.update(_saved_peak)
            _ps._player_counts.clear(); _ps._player_counts.update(_saved_pc)
            db.session.delete(_mon); db.session.commit()

    # ── An unreachable host is a normal condition, not a panel fault ──────────────────────────────
    # The fixture hosts point at 127.0.0.1:22 with nothing listening, so every endpoint below has to
    # reach a host it cannot open a connection to — exactly what happens when a real VPS is powered
    # off, rebooting, or behind a broken link.
    #
    # Six of these used to answer 500. That is wrong twice over: the browser console fills with
    # errors on a page nobody broke, and any 5xx alerting on the panel fires for someone else's
    # downtime. api_remote_live_stats already answered 200-with-an-error-field and said why in a
    # comment; its siblings just never followed. ssh_manager raises ConnectionError specifically for
    # unreachable, which is what lets these stay separable from a genuine bug — anything that is NOT
    # a ConnectionError still returns 500 on purpose.
    with app.app_context():
        _ur_id = RemoteServer.query.filter_by(name="smoke-host").first().id
    _urc = client_as(admin_id)
    for _ep in ("live", "live-stats", "pro-status", "uptime", "firewall",
                "check-updates", "tailscale-check", "specs", "ssh-status"):
        _r = _urc.get("/api/remote/%d/%s" % (_ur_id, _ep))
        check("unreachable host: /api/remote/<id>/%s does not 5xx" % _ep,
              _r.status_code < 500, "%s -> %d" % (_ep, _r.status_code))

    # ── Auto-block reconcile: attempts-threshold selection + whitelist exemption ───────────────────
    # Drive _autoblock_reconcile against a stubbed offender list / UFW so no SSH or real firewall is
    # touched, proving it blocks by 7-day attempt count (not rank), skips whitelisted IPs, and
    # releases its own stale blocks.
    with app.app_context():
        import ipaddress as _ipa_ab
        _am = sys.modules["app"]
        _monmod = sys.modules["panel.services.monitoring"]   # _autoblock_reconcile resolves these here
        _r = RemoteServer.query.filter_by(name="smoke-host").first()
        _was_local = _r.is_local
        _r.is_local = True          # exercise the local (so.*) branch — no SSH
        db.session.commit()
        _denied, _undenied = [], []
        _sv = {n: getattr(_am.so, n) for n in ("fail2ban_top_ips", "ufw_blocked_ips",
               "ufw_deny_ip", "ufw_undeny_ip")}
        _sv_tn, _sv_th, _sv_wl = _monmod.tailnet_exempt_ips, _monmod._autoblock_threshold, _monmod._whitelist_networks
        try:
            _am.so.fail2ban_top_ips = lambda limit=100, days=7: [
                {"ip": "203.0.113.10", "attempts": 80, "bans": 0},   # over threshold  -> block
                {"ip": "203.0.113.11", "attempts": 5, "bans": 0},    # under threshold -> ignore
                {"ip": "10.9.9.9", "attempts": 500, "bans": 0},      # over, but WHITELISTED -> skip
            ]
            _am.so.ufw_blocked_ips = lambda: {"203.0.113.99": "panel-autoblock"}   # our stale block
            _am.so.ufw_deny_ip = lambda ip, tag=None: (_denied.append(ip), (True, "ok"))[1]
            _am.so.ufw_undeny_ip = lambda ip: (_undenied.append(ip), (True, "ok"))[1]
            _monmod.tailnet_exempt_ips = lambda remote, ips: set()
            _monmod._autoblock_threshold = lambda: 20
            _monmod._whitelist_networks = lambda: [_ipa_ab.ip_network("10.0.0.0/8")]
            _added, _removed = _monmod._autoblock_reconcile(_r)
            check("autoblock: an IP at/above the 7-day attempt threshold is blocked", "203.0.113.10" in _denied)
            check("autoblock: an IP below the threshold is NOT blocked", "203.0.113.11" not in _denied)
            check("autoblock: a whitelisted IP is never blocked even far over threshold", "10.9.9.9" not in _denied)
            check("autoblock: a stale auto-block that no longer qualifies is released", "203.0.113.99" in _undenied)
        finally:
            for _n, _v in _sv.items():
                setattr(_am.so, _n, _v)
            _monmod.tailnet_exempt_ips, _monmod._autoblock_threshold, _monmod._whitelist_networks = _sv_tn, _sv_th, _sv_wl
            _r.is_local = _was_local
            db.session.commit()

    # ── Global ban list endpoints (fan-out to servers stubbed, so no SSH) ──────────────────────────
    with app.app_context():
        from panel.db.models import GlobalBan
        _am = sys.modules["app"]
        # Stub the ROUTE MODULE's binding, not app's. `from app import _fan_out_global_ban`
        # copies the function object at import time, so rebinding app's name afterwards leaves
        # the handler still calling the original — the stub assigns cleanly and intercepts
        # nothing. Here that meant the real fan-out ran, spawned SSH threads against the fixture
        # hosts, and held two pooled DB connections for the rest of the suite; the player-poll
        # check three hundred lines later is what noticed, as a peak of 4 against a ceiling of 2.
        from panel.routes import custom_commands as _cc_mod
        _saved_fan = _cc_mod._fan_out_global_ban
        _cc_mod._fan_out_global_ban = lambda a, sid, unban=False: None
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
            _cc_mod._fan_out_global_ban = _saved_fan

    # ── Telegram command bot: server-name resolution for /start /stop /restart /players ────────────
    with app.app_context():
        from panel.services.bots.commands import _find_server
        _g, _e = _find_server("smoke-cs")               # by display name
        check("telegram: resolve a server by name", _g is not None and _e is None)
        _g2, _e2 = _find_server("csgoserver")           # by short_name
        check("telegram: resolve a server by short_name", _g2 is not None)
        _g3, _e3 = _find_server("no-such-server-xyz")   # unknown
        check("telegram: an unknown server name returns a helpful error", _g3 is None and "No server" in (_e3 or ""))

    # ── The panel's own CSS/JS are cacheable files, not 64KB re-sent on every navigation ──────────
    # They used to be inline in base.html, so every page load re-sent them and no browser could ever
    # cache them. A long cache is only safe if the URL changes when the bytes do, so all three parts
    # are asserted together: linked, served with a content hash, and cached hard.
    _pg = c.get("/").get_data(as_text=True)
    import re as _re_as
    _assets = [u for u in _re_as.findall(r'(?:src|href)="([^"]+)"', _pg)
               if "/static/" in u and "/vendor/" not in u and (".js" in u or ".css" in u)]
    check("assets: base.html links its own CSS and JS as static files",
          any(".css" in a for a in _assets) and any(".js" in a for a in _assets),
          "linked: %s" % _assets[:4])
    check("assets: each carries a content hash, so a stale copy cannot survive an update",
          _assets and all(_re_as.search(r"\?v=[0-9a-f]{6,}", a) for a in _assets),
          "no ?v= on: %s" % [a for a in _assets if "?v=" not in a][:3])
    for _a in _assets[:4]:
        _ar = c.get(_a)
        check("assets: %s is served" % _a.split("/")[-1].split("?")[0],
              _ar.status_code == 200, "got %d" % _ar.status_code)
        check("assets: %s is cached hard" % _a.split("/")[-1].split("?")[0],
              "max-age=" in _ar.headers.get("Cache-Control", ""),
              "Cache-Control: %r" % _ar.headers.get("Cache-Control"))
    # The shared bundle must be in the FILE and not in the page. Measuring total inline bytes would
    # measure each page's own scripts too; these markers are specifically base.html's shared code.
    # (Each page's own scripts are files now as well — what is left inline anywhere is the ~1.4KB of
    # per-request config: the i18n catalog, MOUNT, the CSRF token and the ids of the thing shown.)
    # BY NAME, not "the first .js on the page": base.html loads i18n.js above panel.js, and picking
    # positionally made this assert that panel.js's markers live in the i18n bundle.
    _shared = c.get(next(a for a in _assets if "panel.js" in a)).get_data(as_text=True)
    _shared_css = c.get(next(a for a in _assets if "panel.css" in a)).get_data(as_text=True)
    for _marker, _where, _text in (("window.makeSortable = function", "panel.js", _shared),
                                   ("window.toggleLayoutEdit = function", "panel.js", _shared),
                                   ("body.layout-edit .panel-tools", "panel.css", _shared_css)):
        check("assets: %r is served from %s..." % (_marker[:34], _where), _marker in _text)
        check("assets: ...and is NOT also inlined into the page", _marker not in _pg,
              "still inline: %r" % _marker)

    # ── The player poll must not hold database connections across its network calls ───────────────
    # Each worker used to run inside its own app context, so it held a pooled connection for the
    # whole gamedig/SSH round trip. SQLAlchemy's default QueuePool here is 5 + 10 overflow, and 8
    # workers pinned 9 of those 15 for as long as one slow host took to answer — every web request
    # in that window queues behind them. Measured 9 before, 1 after.
    import time as _t
    with app.app_context():
        _eng = db.engine          # captured in a context; the pool object itself needs none, which
                                  # is what lets the stub below read it from a worker thread safely
    # _refresh_player_counts and both slot helpers live in monitoring.py; the stubs must be
    # installed where the function looks them up, not on app's re-export.
    _sv_slots2, _sv_max2 = _monmod._server_slots, _monmod._server_max_config
    _held = []
    try:
        # The stub has to DWELL. A real gamedig/SSH call takes hundreds of ms, which is what makes
        # the workers overlap and their connections pile up; a stub that returns instantly never
        # reproduces that, and the check passes against the very code it is meant to catch.
        def _dwell():
            _held.append(_eng.pool.checkedout())
            _t.sleep(0.05)

        def _slots_probe(gs):
            _dwell()
            return (3, 16, "probe")

        def _max_probe(gs):
            # The seeded servers are "offline", so the worker takes the early branch and calls this
            # one instead of _server_slots — same thread, same question, so measure in both.
            _dwell()
            return 16
        _monmod._server_slots = _slots_probe
        _monmod._server_max_config = _max_probe
        _monmod._refresh_player_counts(app)
        check("player poll: every installed server is still queried",
              len(_held) >= 1, "workers ran: %d" % len(_held))
        check("player poll: no DB connection is held while the network call runs",
              _held and max(_held) <= 2, "peak checked-out during the call: %s" % (max(_held) if _held else "n/a"))
    finally:
        _monmod._server_slots, _monmod._server_max_config = _sv_slots2, _sv_max2

    # ── Login redirect: ?next= must stay on this site ─────────────────────────────────────────────
    # The guard rejects absolute URLs, protocol-relative "//host", an embedded scheme and the
    # backslash trick — four distinct bypasses, none of them previously asserted. A hit here sends
    # someone who just typed their password to an attacker's copy of the login page.
    for _nx in ("//evil.example", "https://evil.example", "http://evil.example",
                "/\\evil.example", "\\evil.example", "javascript:alert(1)",
                "https:/\\evil.example", "////evil.example"):
        _lc = app.test_client()
        _lr = _lc.post("/login?next=" + _nx,
                       data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
        _loc = _lr.headers.get("Location", "")
        check("login redirect: %r cannot send the user off-site" % _nx,
              _lr.status_code != 302 or (_loc.startswith("/") and not _loc.startswith("//")
                                         and "\\" not in _loc and "://" not in _loc),
              "Location: %r" % _loc)
        _lc.get("/logout")

    # ── A JSON endpoint must answer JSON, whatever went wrong ─────────────────────────────────
    # There was no errorhandler anywhere in this project, so an exception in a route came back as
    # Werkzeug's HTML 500 — and every caller here is `.then(r => r.json())`, which then fails to
    # parse it. The user sees a generic "failed" instead of the reason and the log fills with
    # tracebacks that read like the panel is broken. The ordinary trigger is not a bug at all:
    # run_privileged raises ConnectionError for a host that is down and VerbError for an argument
    # a verb refuses, and nothing between the ops layer and the browser catches either.
    #
    # Driven against a host that cannot be reached (192.0.2.x is TEST-NET-1, and the runner's
    # egress guard refuses it anyway), and against the paths that must NOT change.
    _eh_c = app.test_client()
    _eh_c.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
    with app.app_context():
        _eh_r = RemoteServer(name="eh-down", host="192.0.2.10", port=22, username="u",
                             auth_method="key", auth_credential="", sudo_enabled=True)
        db.session.add(_eh_r)
        db.session.commit()
        _eh_rid = _eh_r.id
    _eh_html = []
    for _p, _b in (("/api/remote/%d/firewall/open" % _eh_rid, {"port": 27015}),
                   ("/api/remote/%d/reboot" % _eh_rid, {}),
                   ("/api/remote/%d/run-updates" % _eh_rid, {})):
        _resp = _eh_c.post(_p, json=_b)
        if "json" not in (_resp.headers.get("Content-Type") or ""):
            _eh_html.append("%s -> %s %s" % (_p, _resp.status_code,
                                             (_resp.headers.get("Content-Type") or "")[:24]))
    check("errors: a mutating API route answers JSON when the host is unreachable",
          not _eh_html, "; ".join(_eh_html))
    # An abort(404) on an API path is the same unparseable body, one status code over.
    _resp = _eh_c.get("/api/server/99999/history")
    check("errors: an abort() on an API path answers JSON too",
          "json" in (_resp.headers.get("Content-Type") or "") and _resp.status_code == 404,
          "%s %s" % (_resp.status_code, _resp.headers.get("Content-Type")))
    # ...and a PAGE keeps the plain HTML error it has always had.
    _resp = _eh_c.get("/no-such-page-at-all")
    check("errors: a page render still gets the ordinary HTML error",
          _resp.status_code == 404 and "html" in (_resp.headers.get("Content-Type") or ""),
          "%s %s" % (_resp.status_code, _resp.headers.get("Content-Type")))
    # The one status the handler must not reshape: panel.js reads it and X-Auth-Required to
    # decide the session has expired.
    _eh_anon = app.test_client()
    _resp = _eh_anon.get("/api/servers")
    check("errors: an unauthenticated API call keeps its 401 contract",
          _resp.status_code in (401, 302), "%s" % _resp.status_code)
    _eh_c.get("/logout")
    # ...and a genuine same-site destination is still honoured, or the guard is just breaking things.
    _okc = app.test_client()
    _okr = _okc.post("/login?next=/settings",
                     data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
    check("login redirect: a same-site path is still followed",
          _okr.status_code == 302 and _okr.headers.get("Location", "").endswith("/settings"),
          "%d %r" % (_okr.status_code, _okr.headers.get("Location")))
    _okc.get("/logout")
    with app.app_context():
        from app import (_LOGIN_FAILS as _LF)
        _LF.clear()   # those logins were all successful, but keep the throttle clean for later tests

    # ── Files & Config carries the same control bar as the detail page ────────────────────────────
    # It tells you to "restart the server to apply" a config change, and for a long time offered no
    # way to do it. Both pages include _server_actions.html now, so this asserts they really render
    # the same buttons — a shared include is only shared until someone edits one copy.
    import re as _re_ab

    def _act_btns(html):
        # No trailing quote in the pattern — the capture group stops at it anyway, and including
        # it makes the Python literal ambiguous.
        return _re_ab.findall(r'''data-action="serverAction" data-args='\["([\w-]+)''', html)

    _det_html = c.get("/server/%d" % gs_id).get_data(as_text=True)
    _fil_html = c.get("/server/%d/files" % gs_id).get_data(as_text=True)
    check("actions: Files & Config offers the same server actions as the detail page",
          _act_btns(_fil_html) == _act_btns(_det_html) and len(_act_btns(_det_html)) > 0,
          "detail=%s files=%s" % (_act_btns(_det_html), _act_btns(_fil_html)))
    check("actions: ...and the handler for them is actually served to that page",
          "server_actions.js" in _fil_html and "var SERVER_NAME" in _fil_html)
    check("actions: Clear Console stays on the console page only",
          'data-action="clearConsole"' in _det_html
          and 'data-action="clearConsole"' not in _fil_html)

    # ── The Autostart switch must follow the crontab, not a stale column ──────────────────────────
    # What "Autostart" MEANS is "is `*/5 * * * * ./server monitor` scheduled". It was stored as a
    # column that three paths never updated — install, import, and deleting the line by hand — so
    # the Details page could read Off while monitor was scheduled and running every 5 minutes.
    _sv_lcj = _sm_cron.list_cron_jobs
    try:
        _mon = {"raw": "*/5 * * * * /home/csgoserver/csgoserver monitor", "schedule": "*/5 * * * *",
                "command": "/home/csgoserver/csgoserver monitor", "managed": False,
                "role": "autostart", "last_run": None, "ok": None, "error": ""}
        with app.app_context():
            db.session.get(GameServer, gs_id).autostart = False      # the stale column
            db.session.commit()
        _sm_cron.list_cron_jobs = lambda *a, **k: [_mon]
        c.get("/api/server/%d/cron" % gs_id)
        with app.app_context():
            _now = db.session.get(GameServer, gs_id).autostart
        check("autostart: reading the cron corrects a switch that said Off while monitor is scheduled",
              _now is True, "still %r" % _now)

        _sm_cron.list_cron_jobs = lambda *a, **k: []                       # monitor line gone
        c.get("/api/server/%d/cron" % gs_id)
        with app.app_context():
            _now = db.session.get(GameServer, gs_id).autostart
        check("autostart: and turns it back Off once the line is no longer there", _now is False,
              "still %r" % _now)

        # The card's help text promises this; now it is true.
        _sv_del = _sm_cron.delete_cron_job
        try:
            with app.app_context():
                db.session.get(GameServer, gs_id).autostart = True
                db.session.commit()
            _sm_cron.delete_cron_job = lambda *a, **k: (True, "Deleted")
            _sm_cron.list_cron_jobs = lambda *a, **k: []
            c.post("/api/server/%d/cron/delete" % gs_id, json={"raw": _mon["raw"]})
            with app.app_context():
                _now = db.session.get(GameServer, gs_id).autostart
            check("autostart: deleting the monitor line turns the switch off, as the card promises",
                  _now is False, "still %r" % _now)
        finally:
            _sm_cron.delete_cron_job = _sv_del
    finally:
        _sm_cron.list_cron_jobs = _sv_lcj

    # ── The pending banner must know about the DAILY-RESTART cron too ─────────────────────────────
    # Two mechanisms queue a restart-when-empty: the panel's column, and the cron set_daily_restart
    # writes, which touches ~/.restart-pending on the box and restarts from there. The panel wrote
    # the second one and then could not see it, so the banner stayed hidden while a restart really
    # was queued. This is display-only — the column is never written from the flag, so the two
    # queues stay independent and nothing gets restarted twice.
    with app.app_context():
        _g = db.session.get(GameServer, gs_id)
        _g.restart_pending = _g.stop_pending = False
        db.session.commit()
    _ps._cron_restart_pending.pop(gs_id, None)
    def _banner_tag(html):
        # By id — the first alert-warning on the page may be an unrelated flash message.
        m = _re_ab.search(r'<div[^>]*id="restart-pending-banner"[^>]*>', html)
        return m.group(0) if m else ""

    check("pending banner: hidden when neither the panel nor the box has one queued",
          "d-none" in _banner_tag(c.get("/server/%d" % gs_id).get_data(as_text=True)))
    _ps._cron_restart_pending[gs_id] = True
    try:
        _bh = c.get("/server/%d" % gs_id).get_data(as_text=True)
        _banner = _banner_tag(_bh)
        check("pending banner: shown when the BOX has one queued, not just the panel",
              "d-none" not in _banner, _banner[:80])
        check("pending banner: and it says which schedule queued it",
              "by the daily-restart schedule" in _bh)
        with app.app_context():
            check("pending banner: the column is left alone, so the panel's own queue is untouched",
                  db.session.get(GameServer, gs_id).restart_pending is False)
    finally:
        _ps._cron_restart_pending.pop(gs_id, None)

    # ── The users page renders ONE edit modal, not one per user ───────────────────────────────────
    # It used to emit a full 2KB modal per row — 670KB of HTML at 100 accounts, all of it for a
    # dialog you can only have open once. The rows now carry an id and the data comes from a single
    # JSON island. These assert the shape holds AND that the data is actually right, because a
    # smaller page that opens the wrong user's details would be a much worse bug than a big one.
    import json as _json_u
    _uh = c.get("/users").get_data(as_text=True)
    check("users page: exactly one edit modal, however many accounts exist",
          _uh.count('id="editUserModal"') == 1 and 'id="editUserModal-' not in _uh,
          "found %d" % _uh.count('id="editUserModal'))
    _isl = _re_ab.search(r'<script type="application/json" id="users-data"[^>]*>(.*?)</script>',
                         _uh, _re_ab.S)
    check("users page: the JSON island is present", _isl is not None)
    if _isl:
        _rows = _json_u.loads(_isl.group(1))     # must be VALID json, not just present
        with app.app_context():
            # Materialise inside the context: .groups is a lazy relationship and reading it after
            # the context closes raises DetachedInstanceError.
            _want = {u.username: (bool(u.is_superadmin), bool(u.is_active),
                                  sorted(g.id for g in u.groups)) for u in User.query.all()}
        check("users page: one island entry per account", len(_rows) == len(_want),
              "%d rows vs %d users" % (len(_rows), len(_want)))
        _bad = [r["username"] for r in _rows
                if (r["is_superadmin"], r["is_active"], sorted(r["groups"])) != _want[r["username"]]]
        check("users page: each entry matches that account's real flags and groups", not _bad,
              "wrong: %s" % _bad[:3])
        check("users page: every row's Edit button opens the shared modal by id",
              _uh.count('data-action="openEditUser"') == len(_rows),
              "%d buttons for %d users" % (_uh.count('data-action="openEditUser"'), len(_rows)))
        check("users page: no password is ever put in the island",
              not any("password" in r for r in _rows))

    # ── OS updates: tell me once, not every day ───────────────────────────────────────────────────
    # The panel checks each host daily and messages the chat bots when packages appear. The alert
    # fires on the TRANSITION and re-arms when the host is clean, because "the same 12 packages are
    # still waiting" every morning is how an alert becomes something you filter out.
    _sv_reach, _sv_loc, _sv_rem = _am._host_reachable, _am.so.os_update_available, _sm_hosts.remote_os_check_updates
    _sv_notify2 = _am.notifications.notify
    try:
        # Called with NO app context, exactly as the update-check ticker calls it — that thread has
        # none. Wrapping this in app.app_context() would hide a RuntimeError the real caller hits.
        _osu = app._maybe_alert_os_updates

        _bodies2 = []
        _am.notifications.notify = lambda k, t, b="": (_rec.append(k), _bodies2.append((k, t, b)))[0]
        _am._host_reachable = lambda r: True
        _pkgs = {"n": [], "ok": True}
        # A failed check yields no output, which is indistinguishable from a clean host — that is
        # the whole reason "ok" exists, so the stub has to fail that way too. Returning the packages
        # alongside ok=False makes the check unfalsifiable (mutation testing said so).
        _res = lambda: {"ok": True, "packages": _pkgs["n"]} if _pkgs["ok"] else {"ok": False, "packages": []}  # noqa: E731
        _am.so.os_update_available = lambda refresh=True: _res()
        _sm_hosts.remote_os_check_updates = lambda r: _res()

        _rec.clear()
        _osu(force=True)
        check("os updates: a host with nothing waiting says nothing", "os_updates" not in _rec, str(_rec))

        _pkgs["n"] = [{"name": "openssl", "suite": "jammy-security"},
                      {"name": "curl", "suite": "jammy-security"},
                      {"name": "vim", "suite": "jammy-updates"}]
        _osu(force=True)
        check("os updates: packages appearing raises the alert", "os_updates" in _rec, str(_rec))
        _hit = [x for x in _bodies2 if x[0] == "os_updates"]
        check("os updates: security ones are called out in the title and the count",
              _hit and "Security" in _hit[0][1] and "2 security updates of 3" in _hit[0][2],
              str(_hit[:1])[:130])
        check("os updates: the message names the packages", _hit and "openssl" in _hit[0][2])

        _rec.clear(); _bodies2.clear()
        _osu(force=True)
        check("os updates: the SAME packages next day do not alert again", "os_updates" not in _rec,
              str(_rec))

        # Security updates routinely land on a host that ALREADY has ordinary ones pending. Keying
        # the transition on the total count alone swallows them — 2 waiting -> 3 waiting is not a
        # 0 -> N edge — so a host's first security update would never be announced. Start from a
        # host carrying only routine updates, then land one security package on top.
        _pkgs["n"] = []
        _osu(force=True)
        _pkgs["n"] = [{"name": "vim", "suite": "jammy-updates"},
                      {"name": "nano", "suite": "jammy-updates"}]
        _rec.clear(); _bodies2.clear()
        _osu(force=True)
        _hit = [x for x in _bodies2 if x[0] == "os_updates"]
        check("os updates: a routine batch is announced without the security wording",
              "os_updates" in _rec and _hit and "Security" not in _hit[0][1], str(_hit[:1])[:120])
        _pkgs["n"] = _pkgs["n"] + [{"name": "openssl", "suite": "jammy-security"}]
        _rec.clear(); _bodies2.clear()
        _osu(force=True)
        _hit = [x for x in _bodies2 if x[0] == "os_updates"]
        check("os updates: security ones alert even when updates were already pending",
              "os_updates" in _rec and _hit and "Security" in _hit[0][1]
              and "1 security update of 3" in _hit[0][2], str(_hit[:1])[:150])

        _pkgs["n"] = []
        _osu(force=True)     # host cleaned -> re-arm
        _pkgs["n"] = [{"name": "bash", "suite": "jammy-updates"}]
        _rec.clear()
        _osu(force=True)
        check("os updates: after the host is patched, a NEW batch alerts again", "os_updates" in _rec)
        _hit = [x for x in _bodies2 if x[0] == "os_updates"]
        check("os updates: a non-security batch is not announced as security",
              _hit and "Security" not in _hit[-1][1], str(_hit[-1:])[:110])

        # A check that FAILED returns no packages, exactly like a clean host. If that re-armed the
        # transition guard, the next successful check would re-announce the identical list — the
        # repeat-alert this whole event exists to avoid. ok=False must leave the state alone.
        _pkgs["ok"] = False
        _osu(force=True)                     # apt lock held, say — no output, reads as zero packages
        _pkgs["ok"] = True
        _rec.clear()
        _osu(force=True)                     # same single package as before
        check("os updates: a FAILED check does not re-arm the alert", "os_updates" not in _rec,
              str(_rec))

        # The daily throttle. This has to be set up so that a re-check WOULD alert: leave the host
        # clean (so the transition guard is armed), then make packages appear and call WITHOUT
        # force. Throttled means no check and no alert; unthrottled means an immediate one. The
        # first version of this check ran with the host already alerted, so the transition guard
        # hid the throttle and removing it changed nothing.
        _pkgs["n"] = []
        _osu(force=True)                     # host clean, and last_run is now
        _pkgs["n"] = [{"name": "sudo", "suite": "jammy-security"}]
        _rec.clear()
        _osu()                               # no force — must be skipped by the throttle
        check("os updates: the check is throttled to once a day, not once a tick",
              "os_updates" not in _rec, str(_rec))
        _osu(force=True)                     # and force still works, proving the setup was live
        check("os updates: ...but a forced check still sees them", "os_updates" in _rec, str(_rec))

        # A remote that is deleted must not leave its count behind: SQLite hands the freed row id to
        # the next host added, which would inherit "already told you about 1 package" and go silent
        # on its own first batch. Nothing outward can see that leak, so plant a dead host's id in
        # the sweep's own state. (This used to have to reach through
        # _osu.__code__.co_freevars/__closure__ because the state was a closure cell inside
        # register_routes; it is module-level now, so it is simply an attribute.)
        _st_hosts = _ps._os_update_state["hosts"]
        _st_hosts[999999] = (7, 7)
        _osu(force=True)
        check("os updates: a deleted host's count is not left behind for the next one",
              999999 not in _st_hosts, str(sorted(_st_hosts))[:80])

        # ── ...and the same fact IN THE PANEL, not only in the chat ───────────────────────────
        # The sweep is the only thing that asks every host, so the login banner and the OS Updates
        # card read its answer. Before this they read nothing: the card sat blank until you pressed
        # Check, and there was no banner at all. The sweep above just ran with one security package
        # waiting on every host.
        _sum = c.get("/api/os-updates/summary")
        _sj = _sum.get_json() or {}
        _mine = [h for h in (_sj.get("hosts") or []) if h["id"] == remote_id]
        check("os updates: the sweep's answer is what the login banner reads",
              _sum.status_code == 200 and _mine, str(_sj)[:160])
        check("os updates: the banner is told the count and the security count",
              _mine and _mine[0]["count"] == 1 and _mine[0]["security"] == 1, str(_mine[:1])[:120])

        # The summary names hosts, so it is scoped like every other remote route: MANAGE_REMOTES
        # grants the hosts in your groups, not all of them. smoke_mr holds it for remote #1 only.
        _mrj = client_as(mru_id).get("/api/os-updates/summary").get_json() or {}
        _mrids = [h["id"] for h in (_mrj.get("hosts") or [])]
        check("os updates: the banner only names hosts you can actually manage",
              remote_id in _mrids and remote2_id not in _mrids, str(_mrids)[:80])

        # The card fills from that same memory — the whole point is that a PAGE LOAD costs nothing.
        # Assert on the probe: a version that just re-ran the check would also return the right
        # numbers, so numbers alone cannot tell the two apart.
        _probed0 = []
        _am.so.os_update_available = lambda refresh=True: (_probed0.append("local"), _res())[1]
        _sm_hosts.remote_os_check_updates = lambda r: (_probed0.append("remote"), _res())[1]
        _cj = c.get("/api/remote/%d/updates-cached" % remote_id).get_json() or {}
        check("os updates: the card is filled on page load, without running apt",
              _cj.get("known") and _cj.get("count") == 1 and not _probed0,
              "%s probed=%s" % (str(_cj)[:100], _probed0))
        check("os updates: and it carries the package list the card lists",
              [p.get("name") for p in (_cj.get("packages") or [])] == ["sudo"], str(_cj)[:120])

        # Installing the updates has to take the banner down. A clean check does that; the throttle
        # must not leave a stale count sitting in the banner for the rest of the day.
        _pkgs["n"] = []
        _osu(force=True)
        _sj2 = c.get("/api/os-updates/summary").get_json() or {}
        check("os updates: a patched host drops out of the banner",
              not [h for h in (_sj2.get("hosts") or []) if h["id"] == remote_id], str(_sj2)[:120])

        # An unreachable host is the monitor's problem — this must not even probe it. Assert on the
        # PROBE, not on silence: _os_updates_for swallows exceptions by design, so a stub that
        # raises proves nothing — the check would pass with the guard deleted.
        _probed = []
        _am._host_reachable = lambda r: False
        _am.so.os_update_available = lambda refresh=True: (_probed.append("local"), {"ok": True, "packages": []})[1]
        _sm_hosts.remote_os_check_updates = lambda r: (_probed.append("remote"), {"ok": True, "packages": []})[1]
        _rec.clear()
        _osu(force=True)
        check("os updates: an unreachable host is skipped, not probed",
              not _probed and "os_updates" not in _rec, "probed %s" % _probed)

        # The daily throttle must not be spent by an attempt that did no work. The sweep reads its
        # host list FIRST; if that fails (a locked DB), arming last_run anyway buys a full day of
        # silence for a tick that checked nothing — a transient error becomes 24h of it. Nothing
        # outward can see the window, so drive it through the closure like the pruning check above.
        _osu_state = _ps._os_update_state

        class _RaisingQuery:
            @staticmethod
            def all():
                raise RuntimeError("database is locked")

        class _RaisingRemoteServer:
            query = _RaisingQuery

        # _maybe_alert_os_updates moved to panel/routes/os_updates with its section, and that
        # module imports RemoteServer straight from panel.db.models — so the raising stub has to
        # go THERE. On `app` it would assign cleanly and intercept nothing, leaving this check
        # asserting that a sweep which never failed did not set the throttle.
        from panel.routes import os_updates as _osu_mod
        _sv_rs = _osu_mod.RemoteServer
        _osu_state["last_run"] = 0.0
        try:
            _osu_mod.RemoteServer = _RaisingRemoteServer
            _osu()          # a real (unforced) tick whose host-list lookup fails
        finally:
            _osu_mod.RemoteServer = _sv_rs
        check("os updates: a sweep that could not read the host list leaves the throttle open",
              _osu_state["last_run"] == 0.0, "last_run=%r" % _osu_state["last_run"])

        # ...and one that DOES get the list arms it. Without this the check above would also pass
        # with the throttle deleted outright, which is the opposite bug.
        _osu()
        check("os updates: a sweep that ran does arm the throttle",
              _osu_state["last_run"] > 0.0, "last_run=%r" % _osu_state["last_run"])
    finally:
        _am._host_reachable, _am.so.os_update_available = _sv_reach, _sv_loc
        _sm_hosts.remote_os_check_updates = _sv_rem
        _am.notifications.notify = _sv_notify2

    # ── The hoisted error helpers still work where they are actually called ──────────────────────
    # _log_and_generic and _unreachable moved out of register_routes to module level, and their
    # `app.logger` became `current_app.logger`. That is only equivalent inside a request context —
    # outside one it raises "Working outside of application context", which would turn the panel's
    # generic-error path into a 500 with a traceback: the exact leak _log_and_generic exists to
    # prevent. Every caller is a route view, so the context is guaranteed; assert it rather than
    # assume it, in a REQUEST context (not merely an app context, which is weaker).
    # They now live in panel/core/http.py — they were app.py's when this check was written, and
    # moved out with the rest of the pure layer. The reasoning above is unchanged by the move.
    from panel.core import http as _am_http
    with app.test_request_context("/api/servers"):
        _lg = _am_http._log_and_generic("smoke probe — expected, not a real failure")
        check("hoisted helpers: _log_and_generic returns the generic string, not the exception",
              _lg == "Internal server error", repr(_lg))
        _ur_resp, _ur_code = _am_http._unreachable("smoke probe")
        _ur_body = _ur_resp.get_json() or {}
        check("hoisted helpers: _unreachable answers 200 with an unreachable flag",
              _ur_code == 200 and _ur_body.get("unreachable") is True
              and _ur_body.get("success") is False, "%s %s" % (_ur_code, _ur_body))
    # ...and they really are module level now, reachable without going through register_routes.
    check("hoisted helpers: both are module-level attributes of panel/core/http.py",
          callable(getattr(_am_http, "_log_and_generic", None))
          and callable(getattr(_am_http, "_unreachable", None)))
    # And NOT reachable through app.py any more. The cycle grew because app.py was a place other
    # modules could import anything from; a name app.py does not itself use should not be re-exported
    # from it. See the docstrings in panel/core/http.py and panel/core/validation.py.
    check("hoisted helpers: app.py no longer re-exports them",
          not hasattr(_am, "_log_and_generic") and not hasattr(_am, "_unreachable"))

    # ── Changing the panel port must not drop the fail2ban whitelist ─────────────────────────────
    # ensure_panel_fail2ban REWRITES the jail whenever the port changes, and its ignore_ips argument
    # is what becomes `ignoreip`. The port-change route called it without one, so the jail came back
    # with localhost only and every whitelisted IP/CIDR silently lost its exemption — until the next
    # boot re-applied it, or indefinitely if the restart that follows failed. Its two sibling call
    # sites (startup, and the whitelist editor) always passed the whitelist; this one did not.
    #
    # Asserted on the ARGUMENTS, not the outcome: the jail write needs fail2ban on the host, so a
    # result-based check would just skip on a dev box and prove nothing.
    _f2b_calls = []
    _sv_f2b = _am.so.ensure_panel_fail2ban
    _sv_restart = _am.so.restart_panel
    # api_panel_change_port now lives in panel/routes/remote_security, which binds
    # _security_whitelist by name — so that is where the stub goes. This target moved once
    # already during the split; it follows the HANDLER, not the name.
    from panel.routes import remote_security as _rs_mod
    _sv_wl = _rs_mod._security_whitelist
    try:
        _am.so.ensure_panel_fail2ban = lambda log, port, ignore=None: (
            _f2b_calls.append((port, list(ignore) if ignore is not None else None)), (True, "ok"))[1]
        _am.so.restart_panel = lambda *a, **k: (True, "stubbed")
        # remote_security, not app: api_panel_change_port lives there now and resolves
        # _security_whitelist from THAT module's scope. app, host_local and _shared each bind the
        # same name for their own handlers — which is the point: the right stub target is decided
        # by WHICH handler the test drives, not by the name.
        _rs_mod._security_whitelist = lambda: ["203.0.113.8", "10.0.0.0/8"]
        with app.app_context():
            _cp_cfg = _am.load_config()
            _cp_port = _cp_cfg.get("port", 5000)
            # NOT _cp_port + 1. The route refuses a port that is already in use, and the next port
            # up from the panel's own is exactly where a spare dev instance tends to be sitting.
            # When one was, the route answered 400, ensure_panel_fail2ban was never called, and
            # the whitelist check below passed VACUOUSLY over the empty list — an unrelated
            # process on the machine quietly turning two of these three checks into assertions
            # about nothing. Ask for a port the route will actually accept.
            _cp_new = next((_p for _p in range(_cp_port + 1, _cp_port + 60)
                            if not _am.so.port_in_use(_p)), None)
        check("change-port: a free port was found to move the panel to", _cp_new is not None,
              "nothing free in %d-%d; the checks below would prove nothing"
              % (_cp_port + 1, _cp_port + 59))
        # bind_host, not bind: the route reads data.get("bind_host"), so the old key was dropped on
        # the floor and this half of the request was never actually exercised.
        _cpr = c.post("/api/panel/change-port",
                      json={"port": _cp_new, "bind_host": _cp_cfg.get("bind_host", "")})
        # 200, not "any of 200/400/409". The port was just confirmed free and the bind is the one
        # already in use, so there is nothing left for the route to legitimately refuse — and
        # accepting a refusal here is what let a 400 read as "the route answered".
        check("change-port: the route accepted a move to a free port", _cpr.status_code == 200,
              "got %d: %s" % (_cpr.status_code, _cpr.get_data(as_text=True)[:160]))
        check("change-port: the fail2ban jail is rewritten for the new port",
              any(p == _cp_new for p, _ in _f2b_calls), str(_f2b_calls))
        check("change-port: ...and it is rewritten WITH the security whitelist, not without",
              _f2b_calls and all(ig and "203.0.113.8" in ig for _p, ig in _f2b_calls),
              str(_f2b_calls))
    finally:
        _am.so.ensure_panel_fail2ban = _sv_f2b
        _am.so.restart_panel = _sv_restart
        _rs_mod._security_whitelist = _sv_wl
        # Put the port back: the route saved the bumped one to config.json.
        try:
            _am.update_config(lambda cfg: cfg.update({"port": _cp_port}))
        except Exception:
            pass

    # ── Bearer API tokens: the other way into every route ─────────────────────────────────────────
    # A token authenticates AS its owner and inherits exactly that user's RBAC, and app.py exempts
    # Bearer requests from CSRF — so this is a full authentication path that had no test at all.
    def _bearer(tok):
        return app.test_client().get("/api/servers", headers={"Authorization": "Bearer %s" % tok})


    with app.app_context():
        _au = db.session.get(User, admin_id)
        _admin_tok = _au.generate_api_token()
        _stored = _au.api_token
        db.session.commit()
    _ok = _bearer(_admin_tok)
    check("api token: a valid token authenticates with no session cookie",
          _ok.status_code == 200, "got %d" % _ok.status_code)
    check("api token: an unknown token does not authenticate",
          _bearer("lgsm_" + "0" * 48).status_code != 200)
    # The property that makes storing only a hash worth anything: whoever reads the DB holds the
    # hash, and replaying it must NOT authenticate.
    check("api token: replaying the STORED hash does not authenticate",
          _bearer(_stored).status_code != 200, "the stored value logged in")
    check("api token: an empty bearer does not authenticate", _bearer("").status_code != 200)

    # The bearer path is the panel's other way in and had no throttle at all, so an attacker could
    # try tokens as fast as the network allowed. Exercise it end-to-end through a real request,
    # not just the helper: a valid token must keep working, a blocked IP must lose its token
    # identity, and — importantly — a browser session from that same IP must still work, because
    # the loader returns None rather than aborting the request.
    from panel.security import auth as _auth_mod
    _auth_mod._TOKEN_FAILS.clear()
    try:
        for _i in range(_auth_mod.TOKEN_MAX_FAILS):
            app.test_client().get("/api/servers", headers={"Authorization": "Bearer lgsm_deadbeef"})
        _blocked = _bearer(_admin_tok)
        check("token throttle: a valid token is refused once its IP is blocked",
              _blocked.status_code != 200, "got %d" % _blocked.status_code)
        check("token throttle: ...but a SESSION from the same IP still works",
              c.get("/api/servers").status_code == 200)
    finally:
        _auth_mod._TOKEN_FAILS.clear()
    check("token throttle: clearing the block restores token access",
          _bearer(_admin_tok).status_code == 200)

    # A token inherits its owner's scope — no more. mru can see host #1 only.
    with app.app_context():
        _mu = db.session.get(User, mru_id)
        _mru_tok = _mu.generate_api_token()
        db.session.commit()
    _mine = _bearer(_mru_tok)
    check("api token: a restricted user's token sees only that user's servers",
          _mine.status_code == 200
          and 0 < len(_mine.get_json() or []) < len(_ok.get_json() or []),
          "restricted=%s admin=%s" % (len(_mine.get_json() or []), len(_ok.get_json() or [])))

    # Deactivating the owner must kill the token — by_api_token filters on is_active, and an
    # offboarded account keeping API access is exactly the failure nobody would notice.
    with app.app_context():
        db.session.get(User, mru_id).is_active = False
        db.session.commit()
    check("api token: deactivating the owner kills their token",
          _bearer(_mru_tok).status_code != 200, "a disabled user's token still worked")
    with app.app_context():
        _mu2 = db.session.get(User, mru_id)
        _mu2.is_active = True
        _mu2.revoke_api_token()
        db.session.commit()
    check("api token: a revoked token stops working", _bearer(_mru_tok).status_code != 200)

    # ── The Telegram bot's /start must reach the server action, not the help text ────────────
    # `if cmd in ("help", "start")` matched the word alone, so `/start codserver` — which
    # TG_COMMANDS puts in Telegram's own '/' menu and _tg_help_text documents — answered with help
    # and never started anything. A BARE /start is Telegram's open-the-chat command and must still
    # answer with help, so both shapes are asserted; Discord's twin has always matched "help" only.
    # The bots moved to panel/services/bots/. The stub seam follows the HANDLER: every name
    # stubbed below is resolved by the module that defines it, so stubbing that module is
    # what the routers actually see.
    from panel.services.bots import telegram as _tgmod
    from panel.services.bots import discord as _dcmod
    _tg_sent, _tg_acted, _tg_acks = [], [], []
    # _tg_ack is a SECOND send seam, not a variant of _tg_reply: it goes out before the work and
    # deliberately carries no _reply_header. Captured separately so a test can assert on the
    # answer without the ack in the way — and so nothing here reaches api.telegram.org.
    _tg_saved = (_tgmod._tg_reply, _tgmod._tg_server_action, _tgmod._tg_ack)

    class _InlineWorker(object):
        """Runs queued work immediately, on the calling thread.

        Commands run on a background worker now, and a test that asserts on what a command said
        would otherwise race it. Inlining keeps the ORDER the real worker guarantees while making
        it synchronous — what is under test here is what each command says, not the queue; the
        queue has gates of its own below."""

        def __init__(self):
            self.submitted = 0

        def submit(self, fn):
            self.submitted += 1
            fn()
            return True

    _tg_inline = _InlineWorker()
    _tg_saved_worker = _tgmod._TG_WORKER
    _tgmod._TG_WORKER = _tg_inline
    try:
        _tgmod._tg_ack = lambda tok, chat, text: _tg_acks.append(text)
        _tgmod._tg_reply = lambda tok, chat, text: _tg_sent.append(text)
        _tgmod._tg_server_action = lambda a, tok, chat, action, arg, sender=None: _tg_acted.append(
            (action, arg))
        _tgmod._handle_telegram_command(app, "1:tok", "1", "/start smoke-cs")
        check("telegram: /start <name> runs the start action",
              _tg_acted == [("start", "smoke-cs")], "acted=%s sent=%s" % (_tg_acted, _tg_sent[:1]))
        _tg_acted.clear(); _tg_sent.clear()
        _tgmod._handle_telegram_command(app, "1:tok", "1", "/start")
        check("telegram: a bare /start still answers with help",
              not _tg_acted and _tg_sent and "Commands" in _tg_sent[0],
              "acted=%s sent=%s" % (_tg_acted, _tg_sent[:1]))
        _tg_acted.clear(); _tg_sent.clear()
        _tgmod._handle_telegram_command(app, "1:tok", "1", "/stop smoke-cs")
        check("telegram: /stop <name> still works", _tg_acted == [("stop", "smoke-cs")])

        # `/update <name>` parsed the argument and then threw it away, so asking to update ONE game
        # server updated the panel and restarted it instead. An argument names a server here, the
        # way it does for every other command that takes one.
        _tg_upd = []
        _tg_saved_upd = _tgmod._telegram_do_update
        try:
            _tgmod._telegram_do_update = lambda a, tok, chat: _tg_upd.append("panel")
            _tg_acted.clear(); _tg_sent.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/update smoke-cs")
            check("telegram: /update <name> updates THAT SERVER, not the panel",
                  _tg_acted == [("update", "smoke-cs")] and not _tg_upd,
                  "acted=%s panel=%s" % (_tg_acted, _tg_upd))
            _tg_acted.clear(); _tg_upd.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/update")
            check("telegram: a bare /update still updates the panel",
                  _tg_upd == ["panel"] and not _tg_acted,
                  "acted=%s panel=%s" % (_tg_acted, _tg_upd))
        finally:
            _tgmod._telegram_do_update = _tg_saved_upd

        # ── The four commands added alongside the /update fix ────────────────────────────────
        # /console is the missing half of the power commands: start/stop/restart run in the
        # background and discard their output, so a failed start could be reported but never
        # explained without opening the panel.
        _tg_cap, _tg_mod = [], []
        _tg_saved_new = (_sm_game.capture_console, _sm_game.moderate)
        try:
            _sm_game.capture_console = lambda r, u, selfname=None, lines=180: (
                _tg_cap.append(lines), ("\x1b[32mAlready up to date\x1b[0m\nServer started\n", "", 0))[1]
            _sm_game.moderate = lambda r, u, gt, action, target="", message="", selfname=None, \
                steamid="", num="": (_tg_mod.append((action, message)), (True, "announced"))[1]

            _tg_sent.clear(); _tg_acks.clear()
            # _tg_dispatch, not _handle_telegram_command: the ack is the dispatcher's job now,
            # because queueing it with the work would put it behind whatever is already running.
            _tgmod._tg_dispatch(app, "1:tok", "1", "/console smoke-cs")
            check("telegram: /console tails the game console",
                  _tg_sent and "Server started" in _tg_sent[0], "sent=%s" % _tg_sent[:1])
            # /console is an SSH capture: on a slow or unreachable host the chat sat silent for
            # the whole round trip, which reads as a dead bot. It has to say something first.
            check("telegram: /console says it is working before it goes to the host",
                  _tg_acks and "console" in _tg_acks[0].lower(), "acks=%s" % _tg_acks)
            check("telegram: ...with the ANSI escapes stripped",
                  _tg_sent and "\x1b[" not in _tg_sent[0], "sent=%r" % (_tg_sent[:1],))
            _tg_sent.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/console no-such-server-xyz")
            check("telegram: /console on an unknown server explains itself",
                  _tg_sent and "No server" in _tg_sent[0], "sent=%s" % _tg_sent[:1])

            _tg_sent.clear(); _tg_mod.clear(); _tg_acks.clear()
            _tgmod._tg_dispatch(app, "1:tok", "1", "/say csgoserver restarting in 5")
            check("telegram: /say announces the whole message, not just the first word",
                  _tg_mod == [("say", "restarting in 5")], "moderate=%s" % _tg_mod)
            check("telegram: /say acks before it reaches the game", _tg_acks, "acks=%s" % _tg_acks)
            _tg_sent.clear(); _tg_mod.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/say csgoserver")
            check("telegram: /say with no message asks for one instead of announcing nothing",
                  not _tg_mod and _tg_sent and "announce" in _tg_sent[0], "sent=%s" % _tg_sent[:1])

            _tg_sent.clear(); _tg_acks.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/connect smoke-cs")
            check("telegram: /connect gives the joinable address",
                  _tg_sent and ":27015" in _tg_sent[0], "sent=%s" % _tg_sent[:1])
            # The other half of the rule: /connect, /status, /servers and /hosts answer out of the
            # database in the same breath, so acking them would be two notifications for one
            # answer. Acking everything is as wrong as acking nothing.
            for _inst in ("/connect smoke-cs", "/status", "/servers", "/hosts"):
                _tg_acks.clear()
                _tgmod._tg_dispatch(app, "1:tok", "1", _inst)
                check("telegram: %s answers instantly and does not ack" % _inst.split()[0],
                      not _tg_acks, "acks=%s" % _tg_acks)

            _tg_acted.clear()
            _tgmod._handle_telegram_command(app, "1:tok", "1", "/backup smoke-cs")
            check("telegram: /backup runs the backup action", _tg_acted == [("backup", "smoke-cs")],
                  "acted=%s" % _tg_acted)
        finally:
            _sm_game.capture_console, _sm_game.moderate = _tg_saved_new
    finally:
        _tgmod._tg_reply, _tgmod._tg_server_action, _tgmod._tg_ack = _tg_saved
        _tgmod._TG_WORKER = _tg_saved_worker

    # ── Instant feedback: ack first, then say how it ended ────────────────────────────────────
    # Every action a bot can send runs in the background, so run_action returns "'restart' issued"
    # the moment the work is handed to a thread — and that was the LAST thing the chat ever heard.
    # A /backup went quiet for minutes; a /restart never said whether it worked. The exchange is
    # two messages now, and all three properties below are load-bearing: the ack comes BEFORE the
    # dispatch (start/stop probe the host first, which is the delay being papered over), nothing
    # else is said while the work runs (relaying "issued" as well would make one restart three
    # messages), and the completion names what happened.
    _fb_acks, _fb_sent, _fb_at_dispatch, _fb_cb = [], [], [], {}
    _fb_saved = (_tgmod._tg_ack, _tgmod._tg_reply, getattr(app, "_run_action", None))
    try:
        _tgmod._tg_ack = lambda tok, chat, text: _fb_acks.append(text)
        _tgmod._tg_reply = lambda tok, chat, text: _fb_sent.append(text)

        def _fb_run_action(gs, remote, action, actor, origin=None, on_done=None):
            _fb_at_dispatch.append(list(_fb_acks))    # what had been said by the time we were called
            _fb_cb["fn"] = on_done
            return True, "'%s' issued — status updates in a few seconds." % action

        app._run_action = _fb_run_action
        _tgmod._tg_server_action(app, "1:tok", "1", "restart", "smoke-cs")
        check("telegram: a server action acks BEFORE it dispatches the action",
              _fb_at_dispatch and _fb_at_dispatch[0]
              and "restarting" in _fb_at_dispatch[0][0].lower(),
              "acks-at-dispatch=%s" % (_fb_at_dispatch,))
        check("telegram: the ack names the server it is acting on",
              _fb_acks and "smoke-cs" in _fb_acks[0], "acks=%s" % _fb_acks)
        check("telegram: nothing further is said while the action is still running",
              _fb_sent == [], "sent=%s" % (_fb_sent,))
        check("telegram: run_action is handed a completion callback",
              callable(_fb_cb.get("fn")), "cb=%r" % (_fb_cb.get("fn"),))
        # Not _fb_cb["fn"] directly: if the callback ever stops being passed, the check above is
        # the honest report and the rest of the suite should still run. Calling None here would
        # abort smoke_test entirely and hide every check after this point.
        _fb_fire = _fb_cb.get("fn") or (lambda ok, detail: None)
        _fb_fire(True, "Server restarted")
        check("telegram: the completion names the server and says it finished",
              len(_fb_sent) == 1 and "smoke-cs" in _fb_sent[0]
              and "restart finished" in _fb_sent[0], "sent=%s" % (_fb_sent,))
        _fb_sent[:] = []
        _fb_fire(False, "Failed to start")
        check("telegram: a failed action says so, and says why",
              len(_fb_sent) == 1 and "failed" in _fb_sent[0]
              and "Failed to start" in _fb_sent[0], "sent=%s" % (_fb_sent,))
        # A REFUSAL backgrounds nothing, so the callback never runs and nothing else will ever
        # speak. Staying quiet here would leave the chat holding an ack for a restart that was
        # never going to happen.
        app._run_action = lambda gs, remote, action, actor, origin=None, on_done=None: (
            False, "already running. Use 'restart' if you want it bounced.")
        _fb_sent[:] = []; _fb_acks[:] = []
        _tgmod._tg_server_action(app, "1:tok", "1", "start", "smoke-cs")
        check("telegram: a refused action corrects its own ack instead of going quiet",
              len(_fb_sent) == 1 and "already running" in _fb_sent[0], "sent=%s" % (_fb_sent,))
        # backup/update are the ones worth warning about: minutes, not seconds.
        for _slow in ("backup", "update"):
            _fb_acks[:] = []
            app._run_action = _fb_run_action
            _tgmod._tg_server_action(app, "1:tok", "1", _slow, "smoke-cs")
            check("telegram: the %s ack warns that it takes a while" % _slow,
                  _fb_acks and "few minutes" in _fb_acks[0], "acks=%s" % _fb_acks)
    finally:
        _tgmod._tg_ack, _tgmod._tg_reply = _fb_saved[0], _fb_saved[1]
        if _fb_saved[2] is not None:
            app._run_action = _fb_saved[2]

    # ── The command runs off the poll thread, and the ack does not ──────────────────────────────
    # The poll loop used to RUN each command, so a /console on an unreachable host held up every
    # command sent behind it for the whole connect timeout. Work is queued now — but the ack must
    # NOT be, or a command sent while a slow one was running would stay silent until the slow one
    # finished, which is the same silence moved rather than removed. Ordering is the whole point,
    # so it is asserted directly.
    _wq_order, _wq_sent, _wq_queued = [], [], []
    _wq_saved = (_tgmod._tg_ack, _tgmod._tg_reply, _tgmod._TG_WORKER)

    class _RecordingWorker(object):
        """Records the submission instead of running it — so 'was this queued or run inline?' is
        answerable, which a worker that ran things would hide."""

        def __init__(self, accept=True):
            self.accept = accept

        def submit(self, fn):
            _wq_order.append("submit")
            _wq_queued.append(fn)
            return self.accept

    try:
        _tgmod._tg_ack = lambda tok, chat, text: _wq_order.append("ack")
        _tgmod._tg_reply = lambda tok, chat, text: (_wq_order.append("reply"), _wq_sent.append(text))
        _tgmod._TG_WORKER = _RecordingWorker()
        _tgmod._tg_dispatch(app, "1:tok", "1", "/console smoke-cs")
        check("telegram: the command is handed to the worker, not run on the poll thread",
              _wq_queued and callable(_wq_queued[0]), "order=%s" % (_wq_order,))
        check("telegram: the ack goes out BEFORE the command is queued",
              _wq_order == ["ack", "submit"], "order=%s" % (_wq_order,))
        # An instant command still queues — it just has nothing to ack.
        _wq_order[:] = []; _wq_queued[:] = []
        _tgmod._tg_dispatch(app, "1:tok", "1", "/status")
        check("telegram: an instant command is queued too, silently",
              _wq_order == ["submit"], "order=%s" % (_wq_order,))
        # A refused submit means the command will never run, so it has to be said out loud.
        _wq_order[:] = []; _wq_sent[:] = []
        _tgmod._TG_WORKER = _RecordingWorker(accept=False)
        _tgmod._tg_dispatch(app, "1:tok", "1", "/console smoke-cs")
        check("telegram: a command that did not make the queue is answered, not dropped silently",
              _wq_sent and "again" in _wq_sent[0], "sent=%s" % (_wq_sent,))
    finally:
        _tgmod._tg_ack, _tgmod._tg_reply, _tgmod._TG_WORKER = _wq_saved
    # Every command the bot advertises must be one it handles — that menu is what made the /start
    # bug reachable in the first place.
    from panel.services import notifications as _notif
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Each router now lives in its own module, so read the file that actually holds it — pointing
    # this at app.py would make both gates below pass vacuously on a string that is never there.
    _tg_src = open(os.path.join(_repo_root, "panel", "services", "bots", "telegram.py"),
                   encoding="utf-8").read()
    _dc_src = open(os.path.join(_repo_root, "panel", "services", "bots", "discord.py"),
                   encoding="utf-8").read()
    _tg_handler = _tg_src[_tg_src.index("def _handle_telegram_command"):]
    _tg_handler = _tg_handler[:_tg_handler.index("\ndef ", 10)]
    _unhandled = [_cmd for _cmd, _ in _notif.TG_COMMANDS
                  if ('"%s"' % _cmd) not in _tg_handler]
    check("telegram: every command in the '/' menu is handled by the router",
          not _unhandled, "unhandled: %s" % _unhandled)

    # ── The Discord router, which had no coverage at all ──────────────────────────────────────
    # The two bots are twins by design and drift is how the /start bug survived: one router grew a
    # branch the other didn't. Both are asserted from here on, and the parity gate below is the
    # part that catches the next one.
    _dc_sent, _dc_acted, _dc_upd, _dc_acks = [], [], [], []
    _dc_saved = (_dcmod._dc_reply, _dcmod._dc_server_action, _dcmod._discord_do_update,
                 _dcmod._dc_ack)
    try:
        _dcmod._dc_ack = lambda tok, chan, text: _dc_acks.append(text)
        _dcmod._dc_reply = lambda tok, chan, text: _dc_sent.append(text)
        _dcmod._dc_server_action = lambda a, tok, chan, action, arg, sender=None: _dc_acted.append(
            (action, arg))
        _dcmod._discord_do_update = lambda a, tok, chan: _dc_upd.append("panel")
        _dcmod._handle_discord_command(app, "tok", "1", "!start smoke-cs")
        check("discord: !start <name> runs the start action", _dc_acted == [("start", "smoke-cs")],
              "acted=%s" % _dc_acted)
        _dc_acted.clear(); _dc_sent.clear()
        _dcmod._handle_discord_command(app, "tok", "1", "!update smoke-cs")
        check("discord: !update <name> updates THAT SERVER, not the panel",
              _dc_acted == [("update", "smoke-cs")] and not _dc_upd,
              "acted=%s panel=%s" % (_dc_acted, _dc_upd))
        _dc_acted.clear(); _dc_upd.clear()
        _dcmod._handle_discord_command(app, "tok", "1", "!update")
        check("discord: a bare !update still updates the panel",
              _dc_upd == ["panel"] and not _dc_acted, "acted=%s panel=%s" % (_dc_acted, _dc_upd))
        _dc_sent.clear()
        _dcmod._handle_discord_command(app, "tok", "1", "!help")
        check("discord: !help answers with the command list",
              _dc_sent and "Commands" in _dc_sent[0], "sent=%s" % _dc_sent[:1])
        _dc_sent.clear()
        _dcmod._handle_discord_command(app, "tok", "1", "!nonsense")
        check("discord: an unknown command is refused, not silently dropped",
              _dc_sent and "Unknown command" in _dc_sent[0], "sent=%s" % _dc_sent[:1])
    finally:
        (_dcmod._dc_reply, _dcmod._dc_server_action,
         _dcmod._discord_do_update, _dcmod._dc_ack) = _dc_saved

    # The same two-message exchange on Discord. The bots are twins by design and drift is how the
    # /start bug survived — a behaviour added to one and not the other is the shape that keeps
    # recurring, so this is asserted rather than assumed from the shared wording table.
    _dfb_acks, _dfb_sent, _dfb_cb = [], [], {}
    _dfb_saved = (_dcmod._dc_ack, _dcmod._dc_reply, getattr(app, "_run_action", None))
    try:
        _dcmod._dc_ack = lambda tok, chan, text: _dfb_acks.append(text)
        _dcmod._dc_reply = lambda tok, chan, text: _dfb_sent.append(text)

        def _dfb_run_action(gs, remote, action, actor, origin=None, on_done=None):
            _dfb_cb["fn"] = on_done
            return True, "'%s' issued" % action

        app._run_action = _dfb_run_action
        _dcmod._dc_server_action(app, "tok", "1", "restart", "smoke-cs")
        check("discord: a server action acks, then stays quiet until it finishes",
              _dfb_acks and "smoke-cs" in _dfb_acks[0] and _dfb_sent == [],
              "acks=%s sent=%s" % (_dfb_acks, _dfb_sent))
        check("discord: run_action is handed a completion callback",
              callable(_dfb_cb.get("fn")), "cb=%r" % (_dfb_cb.get("fn"),))
        (_dfb_cb.get("fn") or (lambda ok, detail: None))(True, "Server restarted")
        check("discord: the completion message arrives when the action lands",
              len(_dfb_sent) == 1 and "restart finished" in _dfb_sent[0], "sent=%s" % _dfb_sent)
    finally:
        _dcmod._dc_ack, _dcmod._dc_reply = _dfb_saved[0], _dfb_saved[1]
        if _dfb_saved[2] is not None:
            app._run_action = _dfb_saved[2]

    # Both bots must ack the same commands, and exactly the ones the shared table names. Driven,
    # not read off the source: the routers ask commands.working_ack() now, so what matters is what
    # each one DOES with the answer. Every text helper is stubbed, so this reaches no host — the
    # gate is about which commands announce themselves, not about what they reply.
    from panel.services.bots.commands import _WORKING_ACK as _WACK, _ACTION_ACK as _AACK
    _ackp_cmds = {"players": "%splayers srv", "console": "%sconsole srv", "say": "%ssay srv hi",
                  "status": "%sstatus", "servers": "%sservers", "hosts": "%shosts",
                  "connect": "%sconnect srv"}
    _ackp_helpers = ("_players_text", "_console_text", "_say_text", "_status_text",
                     "_servers_text", "_hosts_text", "_connect_text")
    _ackp_bots = (("telegram", _tgmod, "/", "_tg_ack", "_tg_reply",
                   lambda t: _tgmod._tg_dispatch(app, "1:tok", "1", t)),
                  ("discord", _dcmod, "!", "_dc_ack", "_dc_reply",
                   lambda t: _dcmod._dc_dispatch(app, "tok", "1", t)))
    _ackp_seen, _ackp_save = {}, []
    _ackp_workers = (_tgmod._TG_WORKER, _dcmod._DC_WORKER)
    _tgmod._TG_WORKER = _dcmod._DC_WORKER = _InlineWorker()
    try:
        for _bname, _mod, _pfx, _ackn, _replyn, _drive in _ackp_bots:
            for _h in _ackp_helpers + (_ackn, _replyn):
                _ackp_save.append((_mod, _h, getattr(_mod, _h)))
            for _h in _ackp_helpers:
                setattr(_mod, _h, lambda *a, **k: "stubbed")
            setattr(_mod, _replyn, lambda *a, **k: None)
            _seen = set()
            for _cmd, _tmpl in _ackp_cmds.items():
                _hit = []
                setattr(_mod, _ackn, lambda *a, **k: _hit.append(1))
                _drive(_tmpl % _pfx)
                if _hit:
                    _seen.add(_cmd)
            _ackp_seen[_bname] = _seen
    finally:
        for _mod, _h, _fn in _ackp_save:
            setattr(_mod, _h, _fn)
        _tgmod._TG_WORKER, _dcmod._DC_WORKER = _ackp_workers
    check("bots: both routers ack the same set of slow commands",
          _ackp_seen.get("telegram") == _ackp_seen.get("discord") == set(_WACK),
          "telegram=%s discord=%s table=%s" % (sorted(_ackp_seen.get("telegram") or []),
                                               sorted(_ackp_seen.get("discord") or []),
                                               sorted(_WACK)))
    # Every action the bots can dispatch needs ack wording, or it falls back to "working on it…"
    # and the user is told nothing about what is happening.
    _bot_actions = {"start", "stop", "restart", "backup", "update"}
    check("bots: every dispatchable action has its own ack wording",
          _bot_actions <= set(_AACK), "missing: %s" % sorted(_bot_actions - set(_AACK)))

    # Both routers must handle the same verbs. Neither is the source of truth, so compare the
    # quoted command words in each router body — a branch added to one and not the other is
    # exactly the shape of the /start and /update bugs.
    _dc_handler = _dc_src[_dc_src.index("def _handle_discord_command"):]
    _dc_handler = _dc_handler[:_dc_handler.index("\ndef ", 10)]
    _verbs = set(_nre.findall(r'"([a-z][a-z-]{1,15})"', _tg_handler))
    _dc_verbs = set(_nre.findall(r'"([a-z][a-z-]{1,15})"', _dc_handler))
    _only_tg = sorted(_verbs - _dc_verbs - {"help"})      # a bare /start is Telegram-only, by design
    _only_dc = sorted(_dc_verbs - _verbs)
    check("bots: the Telegram and Discord routers handle the same commands",
          not _only_tg and not _only_dc,
          "telegram-only: %s  discord-only: %s" % (_only_tg, _only_dc))

    # ── A power action the panel already knows is a no-op must say so, not report success ────
    # /servers listed a server as online and the very next /start answered
    # "✅ 'start' issued — status updates in a few seconds". _run_action never consulted the status
    # it had just rendered, and start/stop run in the background with their output discarded, so
    # LinuxGSM's own "Server already started" never reached anyone either. Both halves matter, so
    # both are asserted: the refusal AND the cases that must still go through — a stale "online"
    # (the server actually died), a hung server the column calls offline, an unreadable host, and
    # 'restart', which is deliberately never guarded because it is the way out of a wrong refusal.
    import time as _pt
    # Each stub goes where its NAME resolves, which the split made different per name:
    # run_as_game_user and set_game_priority moved to panel/routes/server_detail with _run_action,
    # while server_live_metrics is still read by _live_run_state in app.py. Stubbing the wrong
    # module does not error — the assignment succeeds and simply intercepts nothing, turning these
    # power checks into proof that a stub was never called. unit_test's stub-target gate names it.
    _pa_saved = (_sm_core.server_live_metrics, _sm_core.run_as_game_user, _sm_core.set_game_priority)
    _pa_ran, _pa_prio = [], []

    def _pa_rag(remote, short, cmd, *a, **k):
        _pa_ran.append(cmd)
        return ("", "", 0)

    def _pa_metrics(up, readable=True):
        """The live-metrics shape _live_run_state reads. ram_total==0 is its 'SSH blip' sentinel."""
        return lambda *a, **k: {"ram_total": (8 << 30) if readable else 0,
                                "port_open": up, "game_procs": 1 if up else 0}

    def _pa_status(st):
        with app.app_context():
            db.session.get(GameServer, gs_id).status = st
            db.session.commit()

    def _pa_wait(bucket, secs=5.0):
        """Block until the background power-action thread records its call — so the stubs are never
        restored out from under it (a real run_as_game_user here would SSH to 127.0.0.1)."""
        _dl = _pt.time() + secs
        while _pt.time() < _dl and not bucket:
            _pt.sleep(0.02)
        return bool(bucket)

    def _pa_post(action):
        _pa_ran.clear(); _pa_prio.clear()
        return c.post("/api/server/%d/action" % gs_id, json={"action": action}).get_json() or {}

    try:
        _sm_core.run_as_game_user = _pa_rag
        # set_game_priority resolves in panel/routes/server_detail now, not app — a stub on app
        # would be installed on a name nothing reads.
        _sm_core.set_game_priority = lambda *a, **k: _pa_prio.append(1)

        # Online in the column AND confirmed running on the host: refuse, and don't touch the host.
        _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(True)
        _j = _pa_post("start")
        check("power: start on a running server is refused, not reported as issued",
              _j.get("success") is False and "already running" in (_j.get("message") or ""),
              "got %s" % _j)
        check("power: the refused start never reached the host", not _pa_ran, "ran %s" % _pa_ran)
        # The same lie in the other direction.
        _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
        _j = _pa_post("stop")
        check("power: stop on a stopped server is refused, not reported as issued",
              _j.get("success") is False and "already stopped" in (_j.get("message") or ""),
              "got %s" % _j)
        check("power: the refused stop never reached the host", not _pa_ran, "ran %s" % _pa_ran)

        # A STALE "online" — the column says up, the host says down — must not block the recovery.
        _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(False)
        _j = _pa_post("start")
        check("power: a stale 'online' does not block starting a server that has died",
              _j.get("success") is True and "issued" in (_j.get("message") or ""), "got %s" % _j)
        check("power: that start really ran on the host", _pa_wait(_pa_ran) and _pa_wait(_pa_prio),
              "ran %s" % _pa_ran)
        # A hung server: nothing listening, but processes alive. The column calls that offline —
        # refusing the stop would leave the one command that fixes it unreachable.
        _pa_status("offline")
        _sm_core.server_live_metrics = lambda *a, **k: {"ram_total": 8 << 30, "port_open": False,
                                                       "game_procs": 3}
        _j = _pa_post("stop")
        check("power: a hung server (offline column, live processes) can still be stopped",
              _j.get("success") is True and _pa_wait(_pa_ran), "got %s ran %s" % (_j, _pa_ran))
        # An unreadable host proves nothing, so it can never be grounds for a refusal. Checked on
        # the stop side: start is trivially safe (a falsy read lets it through either way), while
        # losing the "couldn't read" sentinel would turn an SSH blip into "already stopped".
        _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False, readable=False)
        _j = _pa_post("stop")
        check("power: an unreadable host fails open — the stop is not refused",
              _j.get("success") is True and _pa_wait(_pa_ran), "got %s" % _j)
        # restart is the escape hatch; it is correct from either state and must never be guarded.
        _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(True)
        _j = _pa_post("restart")
        check("power: restart is never refused, whatever the status says",
              _j.get("success") is True and _pa_wait(_pa_ran) and _pa_wait(_pa_prio), "got %s" % _j)

        # ── The panel half of the chat bots' "I'll tell you when it's done" ──────────────────
        # run_action returns as soon as the work is handed to a thread, so (True, "issued") means
        # ACCEPTED, not finished. The web UI has a status column to watch; a chat bot has nothing,
        # so it was left announcing a restart and never able to say how it went. on_done closes
        # that — and it has to fire on BOTH outcomes, because a callback that only reports success
        # leaves a failure indistinguishable from a bot that died.
        _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
        _done_ok = []
        with app.app_context():
            _pa_gs = db.session.get(GameServer, gs_id)
            app._run_action(_pa_gs, _pa_gs.remote, "start", None,
                            on_done=lambda ok, detail: _done_ok.append((ok, detail)))
        check("run_action: a backgrounded power action reports back when it finishes",
              _pa_wait(_done_ok) and _done_ok[0][0] is True, "done=%s" % (_done_ok,))
        _done_fail = []
        _sm_core.run_as_game_user = lambda *a, **k: (
            "[ LinuxGSM ] banner\nStarting…\nFailed to start\n", "", 1)
        _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
        with app.app_context():
            _pa_gs = db.session.get(GameServer, gs_id)
            app._run_action(_pa_gs, _pa_gs.remote, "start", None,
                            on_done=lambda ok, detail: _done_fail.append((ok, detail)))
        check("run_action: a FAILED backgrounded action reports the failure, not silence",
              _pa_wait(_done_fail) and _done_fail[0][0] is False, "done=%s" % (_done_fail,))
        # LinuxGSM prints its logo first and its verdict last, so the LAST non-empty line is the
        # one worth putting in a chat message — reporting the head would report the banner.
        check("run_action: the completion detail is LinuxGSM's verdict, not its banner",
              _done_fail and _done_fail[0][1] == "Failed to start", "done=%s" % (_done_fail,))
        _sm_core.run_as_game_user = _pa_rag
        # The OTHER background branch. backup/update go through _bg_action, not _bg_power_action,
        # and those are the slow ones — a /backup was the longest silence of the lot.
        _done_long = []
        with app.app_context():
            _pa_gs = db.session.get(GameServer, gs_id)
            app._run_action(_pa_gs, _pa_gs.remote, "backup", None,
                            on_done=lambda ok, detail: _done_long.append((ok, detail)))
        check("run_action: a long action (backup) reports back too, not just power actions",
              _pa_wait(_done_long) and _done_long[0][0] is True, "done=%s" % (_done_long,))
        # The promise only holds because every action a bot can send is backgrounded. If one ever
        # became synchronous, the bot would ack it and then wait for a callback that never comes.
        from app import LONG_ACTIONS as _LONG
        _bg_verbs = {"start", "stop", "restart"} | set(_LONG)
        check("run_action: every action a chat bot can send is a backgrounded one",
              {"start", "stop", "restart", "backup", "update"} <= _bg_verbs,
              "not backgrounded: %s" % sorted({"start", "stop", "restart", "backup", "update"}
                                              - _bg_verbs))
    finally:
        (_sm_core.server_live_metrics, _sm_core.run_as_game_user,
         _sm_core.set_game_priority) = _pa_saved
        _pa_status("offline")

    # ── A long action's output reaches the console the panel told you to watch ───────────────
    # Accepting an update answers "'update' started — watch the live console for progress." That
    # was not true of any of the six LONG_ACTIONS. The command ran on its own SSH channel and its
    # output went into a Python variable, surfacing only in the audit log afterwards, truncated to
    # 300 characters; the console the message points at is a tail of the GAME's console log, which
    # an update never writes to. So an operator watching it saw NOTHING for the whole download —
    # reported as "it says to watch the console for updates, there is nothing that gets sent".
    #
    # Four things have to hold, and each is a different way it silently went back to being empty:
    # the command must redirect through a file, the file must be registered while it runs, the
    # drain must send only what is new, and the POLLER must actually call the drain.
    from panel.core.panel_state import _action_output as _ao
    from panel.routes._shared import (_action_log_path, _begin_action_tail, _drain_action_output,
                                      _end_action_tail)
    from panel.routes import server_files as _r_sf
    import re as _lat_re
    _ao.clear()
    _lat_saved = (_sm_core.run_as_game_user, _sm_core.run_command)
    _lat_cmds, _lat_seen = [], []

    def _lat_emit(event, payload=None, **kw):
        _lat_seen.append((event, payload, kw.get("room")))

    _lat_sio_saved = app.socketio.emit
    try:
        app.socketio.emit = _lat_emit

        # 1. The command LinuxGSM is asked to run, and what was registered while it ran.
        _lat_during = []

        def _lat_rag(remote, short, cmd, *a, **k):
            _lat_cmds.append(cmd)
            _lat_during.append(dict(_ao.get(gs_id) or {}))
            return ("Local build: 1\nRemote build: 2\nUpdate complete\n", "", 0)

        _sm_core.run_as_game_user = _lat_rag
        _sm_core.run_command = lambda *a, **k: ("0", "", 0)   # nothing to tail; drains are no-ops
        with app.app_context():
            _lat_gs = db.session.get(GameServer, gs_id)
            _lat_user = _lat_gs.short_name
            app._run_action(_lat_gs, _lat_gs.remote, "update", None)
        check("long action: it really ran", _pa_wait(_lat_cmds), "cmds=%s" % _lat_cmds)
        _lat_logf = _action_log_path(_lat_user, "update")
        check("long action: its output is redirected through a file the console can tail",
              _lat_cmds and ("> %s 2>&1" % _lat_logf) in _lat_cmds[0],
              "ran %r" % (_lat_cmds[0] if _lat_cmds else None))
        # ...and the whole output must still come BACK to this thread: the audit log entry and the
        # chat bots' completion message are both built from it, so a redirect that swallowed it
        # would trade one silence for another.
        check("long action: the redirect still hands the full output back (cat + LinuxGSM's own rc)",
              _lat_cmds and "cat %s" % _lat_logf in _lat_cmds[0] and "exit $rc" in _lat_cmds[0],
              "ran %r" % (_lat_cmds[0] if _lat_cmds else None))
        check("long action: the output file is registered for tailing WHILE it runs",
              _lat_during and _lat_during[0].get("path") == _lat_logf
              and _lat_during[0].get("action") == "update"
              and _lat_during[0].get("user") == _lat_user,
              "registered %s" % (_lat_during,))
        _lat_dl = _pt.time() + 3.0
        while _pt.time() < _lat_dl and gs_id in _ao:
            _pt.sleep(0.02)
        check("long action: ...and deregistered once it's over, so the poller stops asking",
              gs_id not in _ao, "still registered: %s" % (_ao.get(gs_id),))
        _lat_markers = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        check("long action: the console is told it started and how it ended",
              any("update started" in (m or "") for m in _lat_markers)
              and any("update finished successfully" in (m or "") for m in _lat_markers),
              "markers=%s" % _lat_markers)
        check("long action: the markers go to THIS server's console room only",
              all(r == "console_%d" % gs_id for (e, p, r) in _lat_seen if e == "console_output"),
              "rooms=%s" % [r for (e, p, r) in _lat_seen])

        # 2. The drain itself: new bytes only. A tail that re-sent its window every tick would
        # fill the console with the same SteamCMD spool over and over.
        _lat_seen.clear()
        _lat_file = {"text": ""}

        def _lat_rc(server, command, timeout=30, sudo=None):
            if "stat -c%s" in command and ".panel-" in command:
                t = _lat_file["text"]
                # What the real one-round-trip script prints: the size, then the new bytes.
                _m = _lat_re.search(r"tail -c \+(\d+)", command)
                _pos = (int(_m.group(1)) - 1) if _m else 0
                body = t[_pos:] if len(t) > _pos else ""
                return ("%d\n%s" % (len(t), body)).strip(), "", 0
            return ("0", "", 0)

        _sm_core.run_command = _lat_rc
        with app.app_context():
            _lat_remote = db.session.get(GameServer, gs_id).remote
            _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)
            _lat_seen.clear()
            _lat_file["text"] = "Update required\nDownloading 12%\n"
            _drain_action_output(app, _lat_remote, gs_id)
            _lat_first = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
            _lat_seen.clear()
            _drain_action_output(app, _lat_remote, gs_id)          # nothing new since
            _lat_repeat = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
            _lat_file["text"] += "Downloading 97%\nSuccess\n"
            _lat_seen.clear()
            _drain_action_output(app, _lat_remote, gs_id)
            _lat_second = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
            # The file is TRUNCATED under the tail. Running the same action again re-opens its log
            # with `>`, and _begin_action_tail resets the offset — but only after the SSH call is
            # issued, so a tick landing between the two leaves the poller holding an offset past
            # the end of a brand-new file. The drain noticed that already; what it then did was
            # advance the offset to the NEW file's size without ever sending those bytes, so the
            # first chunk of the re-run's output was dropped on the floor and nothing said so.
            _lat_file["text"] = "Second run: validating\n"
            _lat_seen.clear()
            _drain_action_output(app, _lat_remote, gs_id)     # sees size < pos
            _lat_trunc_now = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
            _lat_trunc_pos = dict(_ao.get(gs_id) or {}).get("pos")
            _lat_seen.clear()
            _drain_action_output(app, _lat_remote, gs_id)     # ...and re-reads from the start
            _lat_trunc_next = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
            _end_action_tail(app, gs_id, _lat_remote, "update", 0)
        check("console tail: the first drain sends what the action has written so far",
              _lat_first and "Downloading 12%" in _lat_first[0], "sent %s" % _lat_first)
        check("console tail: a drain with nothing new sends nothing (no repeated window)",
              not _lat_repeat, "re-sent %s" % _lat_repeat)
        check("console tail: the next drain sends ONLY the new lines",
              _lat_second and "Downloading 97%" in _lat_second[0]
              and "Downloading 12%" not in _lat_second[0], "sent %s" % _lat_second)
        check("console tail: a truncated log rewinds the offset instead of skipping past it",
              _lat_trunc_pos == 0, "offset left at %r after the truncation" % (_lat_trunc_pos,))
        check("console tail: ...so the re-run's output is still delivered, one tick later",
              any("Second run: validating" in (m or "")
                  for m in (_lat_trunc_now + _lat_trunc_next)),
              "now=%s next=%s" % (_lat_trunc_now, _lat_trunc_next))

        # 3. The CALLER. Every assertion above passes just as well with a drain nothing invokes —
        # which is exactly the shape of the original bug. So drive the real console poller: give
        # it a viewer, register an action, and wait for the bytes to come out of it.
        _lat_seen.clear()
        _lat_file["text"] = "SteamCMD: validating\n"
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.setdefault(gs_id, set()).add("test-sid")
        try:
            _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
            _lat_seen.clear()
            _lat_polled = []
            _dl = _pt.time() + 8.0
            while _pt.time() < _dl and not _lat_polled:
                _lat_polled = [p.get("data") for (e, p, r) in _lat_seen
                               if e == "console_output" and "validating" in (p.get("data") or "")]
                _pt.sleep(0.05)
            check("console poller: it drains a running action's output on its own ticks",
                  bool(_lat_polled), "the poller never sent it: %s" % _lat_seen)
        finally:
            _ao.pop(gs_id, None)
            with _r_sf._viewers_lock:
                _r_sf._console_viewers.pop(gs_id, None)
    finally:
        app.socketio.emit = _lat_sio_saved
        (_sm_core.run_as_game_user, _sm_core.run_command) = _lat_saved
        _ao.clear()

    # ── The sweep prunes even when the last host is gone ───────────────────────────────────────
    # _forget_deleted_rows is what keeps every row-keyed map honest, and it was the LAST statement
    # in _monitor_pass — after `if not remotes: return`. So in the one state where it has the most
    # to forget (every host deleted) it never ran at all, and the next host added takes id 1 again
    # and inherits the lot. Driven with an empty host list, which is exactly that state.
    from panel.services import monitoring as _mp_mon
    from panel.core import panel_state as _mp_ps
    _mp_saved = _mp_mon.RemoteServer

    class _NoRemotes:
        class query:
            @staticmethod
            def all():
                return []
    try:
        with app.app_context():
            _mp_mon._player_counts[91919] = {"count": 3, "max": 8, "name": "ghost", "ts": 0}
            _mp_ps._max_players_cache[91919] = 64
            _mp_mon.RemoteServer = _NoRemotes
            _mp_mon._monitor_pass()
        check("monitor sweep: it still forgets deleted rows when NO hosts are left",
              91919 not in _mp_mon._player_counts and 91919 not in _mp_ps._max_players_cache,
              "left: counts=%s max=%s" % (91919 in _mp_mon._player_counts,
                                          91919 in _mp_ps._max_players_cache))
    finally:
        _mp_mon.RemoteServer = _mp_saved
        _mp_mon._player_counts.pop(91919, None)
        _mp_ps._max_players_cache.pop(91919, None)

    # ── Deleting a host forgets everything keyed on its id ─────────────────────────────────────
    # SQLite hands a deleted row's id straight to the next INSERT, and delete_remote is the one
    # route that removes a host — taking its game servers with it, without uninstall_server ever
    # running. Three kinds of state were left behind:
    #
    #   * config["autoblock_hosts"] — a LIST OF REMOTE IDS, persisted, so a restart does not clear
    #     it. The hourly sweep looks each id up; once it is live again that is the NEW host, and
    #     the panel starts adding `ufw deny` rules to a machine nobody enabled auto-blocking on.
    #   * config["game_schedules"] — per-server backup overrides, keyed by game-server id.
    #     uninstall_server already removes these deliberately; the cascade never did.
    #   * ssh_manager's per-remote caches. _specs_cache has NO expiry, so a recycled id reported
    #     the deleted machine's CPU/RAM/disk/OS until the panel restarted.
    with app.app_context():
        _dr_remote = RemoteServer(name="smoke-delhost", host="127.0.0.1", port=22,
                                  username="root", auth_method="key", auth_credential="")
        db.session.add(_dr_remote)
        db.session.flush()
        _dr_gs = GameServer(remote_id=_dr_remote.id, name="smoke-delgame",
                            short_name="delgameserver", game_type="csgo", port=27099,
                            installed=True, status="offline")
        db.session.add(_dr_gs)
        db.session.commit()
        _dr_rid, _dr_gid = _dr_remote.id, _dr_gs.id
    from panel.core.config import load_config as _dr_cfg, update_config as _dr_upd
    from panel.ops import backup as _dr_bk
    from panel.ops.ssh_manager import _core as _dr_core, firewall as _dr_fw, hosts as _dr_hosts
    _dr_upd(lambda c: c.__setitem__("autoblock_hosts",
                                    sorted(set(c.get("autoblock_hosts") or []) | {_dr_rid})))
    _dr_bk.set_game_schedule(_dr_gid, 3, 2)
    _dr_fw._specs_cache[_dr_rid] = {"os": "deleted host"}
    _dr_hosts._pro_status_cache[_dr_rid] = (9e18, {"attached": True})
    _dr_core._gamedig_host_cache[_dr_rid] = (9e18, "203.0.113.9")
    check("delete host: the fixtures really armed (autoblock + schedule + caches)",
          _dr_rid in (_dr_cfg().get("autoblock_hosts") or [])
          and str(_dr_gid) in (_dr_cfg().get("game_schedules") or {})
          and _dr_rid in _dr_fw._specs_cache,
          "autoblock=%s schedules=%s" % (_dr_cfg().get("autoblock_hosts"),
                                         list((_dr_cfg().get("game_schedules") or {}))))
    # ...and a FAILED install job for that server, exactly as _run_install_job leaves one. This is
    # the half that is visible to a user: the monitor's sweep prunes it, but only on its next pass,
    # so until then /api/server/<id>/install-status answers for whatever server takes the freed row
    # id with the DELETED one's failure. Driven end to end below rather than asserted from the map.
    from panel.core.panel_state import _install_jobs as _dr_jobs, _install_lock as _dr_jlock
    with _dr_jlock:
        _dr_jobs[_dr_gid] = {"status": "failed", "step": 3, "total": 8, "step_name": "Downloading",
                             "message": "SteamCMD could not log in", "log": ["boom"],
                             "started": _pt.time(), "updated": _pt.time(), "name": "smoke-delgame"}
    _dr_resp = c.post("/remotes/%d/delete" % _dr_rid, json={"password": "Str0ng!passw0rd"},
                      headers={"X-Requested-With": "XMLHttpRequest"})
    check("delete host: the request succeeds",
          (_dr_resp.get_json() or {}).get("success") is True,
          "%d %s" % (_dr_resp.status_code, _dr_resp.get_data(as_text=True)[:120]))
    _dr_after = _dr_cfg()
    check("delete host: its auto-block opt-in is gone from config (a reused id would inherit it)",
          _dr_rid not in (_dr_after.get("autoblock_hosts") or []),
          "still listed: %s" % (_dr_after.get("autoblock_hosts"),))
    check("delete host: its game server's backup schedule is gone from config too",
          str(_dr_gid) not in (_dr_after.get("game_schedules") or {}),
          "still present: %s" % (list(_dr_after.get("game_schedules") or {}),))
    # Named individually, NOT walked off _core._remote_caches: iterating the registry makes this
    # pass vacuously the moment a cache stops being registered — which is the exact regression it
    # is here to catch. (Verified: it passed against an unregistered build before this changed.)
    _dr_stale = [n for n, _m in (("host specs", _dr_fw._specs_cache),
                                 ("ubuntu pro", _dr_hosts._pro_status_cache),
                                 ("gamedig host", _dr_core._gamedig_host_cache))
                 if _dr_rid in _m]
    check("delete host: the per-remote SSH caches forgot it",
          not _dr_stale, "still cached by: %s" % ", ".join(_dr_stale))
    # The row id is now free. Re-create a server — SQLite hands it straight back — and ask the
    # endpoint about the NEW one. Anything but "none" is the deleted server's job answering.
    with app.app_context():
        _dr_r2 = RemoteServer(name="smoke-freshhost", host="127.0.0.1", port=22, username="root",
                              auth_method="key", auth_credential="")
        db.session.add(_dr_r2)
        db.session.flush()
        _dr_gs2 = GameServer(remote_id=_dr_r2.id, name="smoke-brandnew", short_name="newgameserver",
                             game_type="gmod", port=27098, installed=True, status="offline")
        db.session.add(_dr_gs2)
        db.session.commit()
        _dr_gid2, _dr_rid2 = _dr_gs2.id, _dr_r2.id
    _dr_is = c.get("/api/server/%d/install-status" % _dr_gid2).get_json() or {}
    check("delete host: a server reusing the freed id does NOT inherit its install outcome",
          _dr_is.get("status") == "none",
          "id reused=%s, install-status=%r" % (_dr_gid2 == _dr_gid, _dr_is))
    with app.app_context():                       # tidy up
        for _m, _i in ((GameServer, _dr_gid2), (RemoteServer, _dr_rid2)):
            _row = db.session.get(_m, _i)
            if _row:
                db.session.delete(_row)
        db.session.commit()
    with _dr_jlock:
        _dr_jobs.pop(_dr_gid, None)
        _dr_jobs.pop(_dr_gid2, None)

    # ── join_console and leave_console must agree on the KEY ────────────────────────────────
    # The viewer registry is what the console poller iterates: an id left in it costs an SSH round
    # trip every two seconds for a console nobody is watching. join_console coerces the id to int
    # before using it — deliberately, and with a comment saying why the room name and the map key
    # have to be the same value — and leave_console did not, so a client that spelled the id as a
    # string left the ROOM (the f-string reads the same either way) and left its sid behind in the
    # map. Only a socket disconnect cleaned that up.
    #
    # Driven through the real socket, not by calling the handler: the coercion only matters
    # because a client chooses the spelling, and that is the half a direct call cannot exercise.
    _sio_err = ""
    try:
        _sio_c = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
        _sio_ok = _sio_c.is_connected()
    except Exception as _e:                      # never a silent skip — a gate that cannot run failed
        _sio_c, _sio_ok, _sio_err = None, False, "%s: %s" % (type(_e).__name__, _e)
    check("console socket: an authenticated test client connects", _sio_ok, _sio_err)
    if _sio_ok:
        try:
            with _r_sf._viewers_lock:
                _r_sf._console_viewers.pop(gs_id, None)
            _sio_c.emit("join_console", {"server_id": gs_id})
            check("console socket: joining registers the viewer",
                  bool(_r_sf._console_viewers.get(gs_id)),
                  "viewers=%r" % (_r_sf._console_viewers.get(gs_id),))
            _sio_c.emit("leave_console", {"server_id": str(gs_id)})   # the string spelling
            check("console socket: leaving deregisters it however the id was spelled",
                  not _r_sf._console_viewers.get(gs_id),
                  "left behind: %r" % (_r_sf._console_viewers.get(gs_id),))
        finally:
            with _r_sf._viewers_lock:
                _r_sf._console_viewers.pop(gs_id, None)
            try:
                _sio_c.disconnect()
            except Exception:
                pass

    # ── A long action's output survives a reload, and keeps LinuxGSM's colour ────────────────
    # Two follow-ups to the tail above, both reported straight after it shipped.
    #
    # "when you refresh the page after i did update...those messages went away" — and they did.
    # The socket reaches only the pages open at the time, and /api/console rebuilds a console by
    # tailing the GAME's console log, which a panel action never writes to. So the output existed
    # in exactly one place: the DOM of whichever tab happened to be open.
    #
    # "in putty when i run a linuxgsm command it will show it in color" — LinuxGSM colours its own
    # output ([  OK  ] green, [ FAIL ] red) and every display path ran it through strip_escapes,
    # which is right for the paths that PARSE this text and wrong for the one showing it to a
    # person.
    from panel.core.panel_state import _console_backlog as _cb
    from panel.routes._shared import (_CONSOLE_BACKLOG_MAX, _console_push)
    _cb.clear()
    _bl_saved = _sm_core.run_command
    try:
        _console_push(app, gs_id, "[panel] update started — its output follows.", ts=1700000000.0)
        _console_push(app, gs_id, "\x1b[32m[  OK  ]\x1b[0m Update complete", ts=1700000042.0)
        check("console backlog: what the panel pushed is remembered, not only broadcast",
              len(_cb.get(gs_id, [])) == 2, "backlog=%s" % (_cb.get(gs_id),))
        # The time rides ALONGSIDE the line, never inside it. The browser stitches its scrollback
        # by matching line strings between overlapping windows of the log, so a timestamp prefixed
        # onto the text would make every line unique and render the whole window twice per poll.
        check("console timestamps: the time is kept beside the line, not prefixed onto it",
              all(r["t"] and "1700000" not in r["line"] for r in _cb[gs_id]),
              "backlog=%s" % (_cb.get(gs_id),))
        check("console timestamps: ...and it is the time the panel actually saw that line",
              [r["t"] for r in _cb[gs_id]] == [1700000000.0, 1700000042.0],
              "times=%s" % [r["t"] for r in _cb[gs_id]])
        # A reload asks /api/console. The host is unreachable in this suite, which is the case
        # that matters most: an update's output is exactly what you still want to read when the
        # server it was updating is down.
        _sm_core.run_command = lambda *a, **k: ("", "", 1)
        _blj = c.get("/api/console/%d" % gs_id).get_json() or {}
        _bl_rows = _blj.get("panel_lines") or []
        check("console backlog: a reload gets it back from /api/console",
              any("update started" in (r.get("line") or "") for r in _bl_rows),
              "panel_lines=%s" % _bl_rows)
        check("console backlog: ...with the times, so a reload keeps them for the ONE source "
              "that has real ones",
              [r.get("t") for r in _bl_rows] == [1700000000.0, 1700000042.0],
              "times=%s" % [r.get("t") for r in _bl_rows])
        check("console backlog: ...in its OWN field, not spliced into the game log's window",
              _blj.get("lines") == [] and "panel_lines" in _blj,
              "lines=%s" % (_blj.get("lines"),))
        # THE ONE THAT MATTERS MOST, and the one every other check here passes without: the game
        # log's window must carry NO time. Those lines are a fresh tail of a file that records no
        # per-line time for most games — the panel is reading them now but they were written at
        # some unknowable point before that. Stamping them with the read time would put a
        # confident wrong time on a week of history, which is worse than a blank gutter, and it
        # looks exactly right until you notice every old line claims the moment you opened the
        # page. Asserted on a reachable host so `lines` is non-empty and the check has something
        # to be wrong about.
        _sm_core.run_command = lambda *a, **k: ("old line one\nold line two", "", 0)
        _blj2 = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console timestamps: (setup) the game-log window came back non-empty",
              len(_blj2.get("lines") or []) >= 2,
              "lines=%s — the check below would pass vacuously" % (_blj2.get("lines"),))
        check("console timestamps: an UNSTAMPED history line carries no invented time",
              all(r.get("t") is None for r in (_blj2.get("lines") or [])),
              "a line was dated to the moment the panel read it: %s" % (_blj2.get("lines"),))
        check("console backlog: the colour survives the round trip to the page",
              any("\x1b[32m" in (r.get("line") or "") for r in _bl_rows),
              "panel_lines=%s" % _bl_rows)
        # Bounded — this must never quietly become a second copy of the log.
        for _i in range(_CONSOLE_BACKLOG_MAX + 120):
            _console_push(app, gs_id, "line %d" % _i)
        check("console backlog: it is capped, and keeps the NEWEST lines",
              len(_cb[gs_id]) == _CONSOLE_BACKLOG_MAX
              and _cb[gs_id][-1]["line"] == "line %d" % (_CONSOLE_BACKLOG_MAX + 119),
              "len=%d last=%r" % (len(_cb[gs_id]), _cb[gs_id][-1]))

        # End to end: what the DRAIN sends for a LinuxGSM-coloured line. The words must be intact
        # and the colour must be canonical — the browser splits on ESC[<codes>m and nothing else,
        # so a stray erase-line or OSC reaching it renders as visible junk.
        _cb.clear()
        _col_file = {"text": "\x1b[0;32m[  OK  ]\x1b[0m Starting\x1b[K\n\x1b]0;steamcmd\x07done\n"}

        def _col_rc(server, command, timeout=30, sudo=None):
            if "stat -c%s" in command and ".panel-" in command:
                t = _col_file["text"]
                _m = _lat_re.search(r"tail -c \+(\d+)", command)
                _pos = (int(_m.group(1)) - 1) if _m else 0
                return ("%d\n%s" % (len(t), t[_pos:] if len(t) > _pos else "")).strip(), "", 0
            return ("0", "", 0)

        _sm_core.run_command = _col_rc
        with app.app_context():
            _col_remote = db.session.get(GameServer, gs_id).remote
            _begin_action_tail(app, gs_id, "update", "/home/x/.panel-update.log", "csgoserver")
            _drain_action_output(app, _col_remote, gs_id)
            _ao.pop(gs_id, None)
        _col_sent = "\n".join(r["line"] for r in _cb.get(gs_id, []))
        check("console colour: LinuxGSM's [  OK  ] reaches the page still green",
              "\x1b[32m[  OK  ]\x1b[0m" in _col_sent, "sent %r" % _col_sent)
        check("console colour: ...and the erase-line and window-title escapes do NOT",
              "\x1b[K" not in _col_sent and "\x1b]" not in _col_sent
              and "steamcmd" not in _col_sent, "sent %r" % _col_sent)
        # Everything that is not colour must be gone: the browser builds text nodes from what is
        # between the SGR sequences, so any other control byte would be rendered literally.
        _col_bare = _lat_re.sub(r"\x1b\[[0-9;]*m", "", _col_sent)
        check("console colour: no control byte but the colour itself survives the drain",
              not any(ord(ch) < 32 and ch != "\n" for ch in _col_bare), "bare %r" % _col_bare)
    finally:
        _sm_core.run_command = _bl_saved
        _cb.clear()
        _ao.clear()

    # ── Every stored timestamp on a page is rendered in the VIEWER's clock ──────────────────
    # The panel stores naive UTC everywhere (panel/core/clock.py) and localises on the CLIENT, so
    # two admins in different countries each read their own time off the same row. That only holds
    # for values emitted through the |datetime filter — three templates formatted a datetime with
    # .strftime() instead and showed raw UTC with nothing saying so, which reads as a wrong local
    # time rather than as a UTC one. Asserted as "no template renders a stored datetime without
    # going through the filter", so the next one added is caught rather than the three being
    # spot-checked forever.
    import glob as _tz_glob
    import re as _tz_re
    _tz_bad = []
    for _tz_path in sorted(_tz_glob.glob(os.path.join(_repo_root, "templates", "*.html"))):
        _tz_src = open(_tz_path, encoding="utf-8").read()
        _tz_src = _tz_re.sub(r"\{#.*?#\}", "", _tz_src, flags=_tz_re.S)   # Jinja comments
        for _tz_m in _tz_re.finditer(r"\{\{(.*?)\}\}", _tz_src, _tz_re.S):
            _tz_expr = _tz_m.group(1)
            if ".strftime(" in _tz_expr and "|datetime" not in _tz_expr:
                _tz_bad.append("%s: {{%s}}" % (os.path.basename(_tz_path), _tz_expr.strip()[:70]))
    check("time: no template formats a stored timestamp itself (it must go through |datetime)",
          not _tz_bad, "raw strftime in a template shows UTC as if it were local: %s" % _tz_bad[:3])
    # Vacuity guard: the scan must actually be finding the filter, or the check above passes on a
    # repo where nothing renders a timestamp at all.
    _tz_filtered = sum(1 for _p in _tz_glob.glob(os.path.join(_repo_root, "templates", "*.html"))
                       if "|datetime" in open(_p, encoding="utf-8").read())
    check("time: (setup) templates really do use the |datetime filter",
          _tz_filtered >= 4, "only %d templates use it — the gate above proves little" % _tz_filtered)
    # And the filter has to emit what the client-side localiser looks for, or it silently shows UTC.
    _tz_html = c.get("/logs").get_data(as_text=True)
    check("time: the filter emits a localtime span the browser can rewrite",
          'class="localtime" data-utc="' in _tz_html,
          "no .localtime[data-utc] in /logs — localizeTimes() has nothing to act on")
    check("time: ...and the value it carries is UTC-anchored, so the browser parses it as UTC",
          _tz_re.search(r'data-utc="\d{4}-\d{2}-\d{2}T[\d:]+Z"', _tz_html) is not None,
          "a naive ISO string with no Z is parsed as LOCAL time and is silently wrong by the offset")


    # ── A poll delta is a line the panel WATCHED ARRIVE, so it gets a time ───────────────────
    # The first cut stamped only socket pushes. /api/console's window was left unstamped whole —
    # but only its PRIMING pass is history; everything after is new output the panel just read,
    # accurate to the poll interval. Two consequences, and the second is why this was reported as
    # "I still don't see the timestamps in the console":
    #   * an install whose websocket cannot connect (a proxy that will not upgrade) falls back to
    #     this poll for everything, so NO line ever got a time at all;
    #   * on a quiet server every line on screen is the priming window, so the column is empty and
    #     the feature looks broken rather than correct.
    _pd_saved = _sm_core.run_command
    try:
        _sm_core.run_command = lambda *a, **k: ("first\nsecond", "", 0)
        _pdj = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console timestamps: the window carries the panel's clock for the browser to stamp "
              "its new lines with",
              isinstance(_pdj.get("now"), (int, float)) and _pdj["now"] > 1_700_000_000,
              "now=%r" % _pdj.get("now"))
        # Still not dated per line: an unstamped window is history until the browser knows which of
        # it is new, and dating the whole thing server-side is the mistake this guards against.
        check("console timestamps: ...but an unstamped window stays undated, as history",
              all(r.get("t") is None for r in (_pdj.get("lines") or [])),
              "lines=%s" % (_pdj.get("lines"),))
    finally:
        _sm_core.run_command = _pd_saved


    # ── A schedule is entered in YOUR clock and written in the HOST's ────────────────────────
    # cron fires on the host's clock. set_daily_restart wrote a literal `0 5 * * *`, the panel's
    # own bootstrap sets new hosts to UTC, no host's timezone was stored anywhere, and the UI
    # showed no time at all — so "daily restart" on a US Central operator's server fired at 23:00
    # local, in peak hours, with nothing on screen to notice it by.
    from panel.core import clock as _tzc
    _tz_saved = (_sm_core.run_command, _sm_core._rewrite_crontab)
    _tz_lines = []
    try:
        _sm_core._rewrite_crontab = lambda s, u, g, add, extra_pre="": (_tz_lines.extend(add),
                                                                        (True, "ok"))[1]
        # A host on UTC, which is what this panel's own bootstrap gives a new VPS.
        with app.app_context():
            db.session.get(RemoteServer, remote_id).timezone = "Etc/UTC"
            db.session.commit()
        # 05:00 America/Chicago is 10:00 or 11:00 UTC depending on the season, so compute the
        # expectation the same way rather than hardcoding one of them — a test that pins 11:00
        # goes red every spring for a reason that has nothing to do with the code.
        _tz_exp_h, _tz_exp_m = _tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC")
        _tz_lines.clear()
        _tzj = c.post("/api/server/%d/daily-restart" % gs_id,
                      json={"enabled": True, "time": "05:00", "tz": "America/Chicago"}).get_json() or {}
        check("schedule tz: the crontab line is written in the HOST's clock, not the viewer's",
              any(_l.startswith("%d %d * * *" % (_tz_exp_m, _tz_exp_h)) for _l in _tz_lines),
              "wrote %s, wanted the daily line at %02d:%02d UTC" % (_tz_lines, _tz_exp_h, _tz_exp_m))
        check("schedule tz: ...and the response says BOTH times, so the page can show which is which",
              _tzj.get("host_time") == "%02d:%02d" % (_tz_exp_h, _tz_exp_m)
              and _tzj.get("local_time") == "05:00" and _tzj.get("host_tz") == "Etc/UTC",
              "got %s" % _tzj)
        with app.app_context():
            check("schedule tz: the stored time is the host's, which is what the crontab says",
                  db.session.get(GameServer, gs_id).daily_restart_at
                  == "%02d:%02d" % (_tz_exp_h, _tz_exp_m),
                  "stored %r" % db.session.get(GameServer, gs_id).daily_restart_at)
        # Flicking the switch sends NO time. That must keep the schedule where it is — a toggle
        # that silently reset it to a default would move a restart into peak hours.
        _tz_lines.clear()
        c.post("/api/server/%d/daily-restart" % gs_id, json={"enabled": False})
        _tz_lines.clear()
        c.post("/api/server/%d/daily-restart" % gs_id, json={"enabled": True})
        check("schedule tz: toggling off and on again does not move the time",
              any(_l.startswith("%d %d * * *" % (_tz_exp_m, _tz_exp_h)) for _l in _tz_lines),
              "wrote %s" % _tz_lines)
        # An UNREADABLE host must leave the time exactly where the operator put it. Converting
        # against a guessed zone would silently shift every schedule on that host.
        with app.app_context():
            db.session.get(RemoteServer, remote_id).timezone = ""
            db.session.commit()
        _sm_core.run_command = lambda *a, **k: ("", "", 1)      # timezone unreadable
        _tz_lines.clear()
        _tzj2 = c.post("/api/server/%d/daily-restart" % gs_id,
                       json={"enabled": True, "time": "07:30", "tz": "America/Chicago"}).get_json() or {}
        check("schedule tz: an unreadable host timezone leaves the time alone, it does not guess",
              any(_l.startswith("30 7 * * *") for _l in _tz_lines) and _tzj2.get("host_tz") == "",
              "wrote %s, said %s" % (_tz_lines, _tzj2))
        # The conversion itself, including the direction that matters and the no-ops.
        check("schedule tz: (unit) a wall time converts between zones",
              _tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC")[0] in (10, 11),
              "got %s" % (_tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC"),))
        check("schedule tz: (unit) the same zone, or an unknown one, is a no-op",
              _tzc.convert_wall_time(5, 0, "Etc/UTC", "Etc/UTC") == (5, 0)
              and _tzc.convert_wall_time(5, 0, "Nope/Nope", "Etc/UTC") == (5, 0)
              and _tzc.convert_wall_time(5, 0, "", "Etc/UTC") == (5, 0))
        # The zone name arrives from the browser AND from a remote host's timedatectl, and ends
        # up indexing the zone database, in a stored column and on the page — so what matters is
        # that a non-zone never survives, whichever layer refuses it (this module's shape check,
        # or zoneinfo's own rejection of absolute paths and `..`).
        check("schedule tz: a zone name that is not one is refused, path traversal included",
              _tzc.valid_timezone("../../etc/passwd") == ""
              and _tzc.valid_timezone("Etc/../../x") == ""
              and _tzc.valid_timezone("A" * 80) == ""
              and _tzc.valid_timezone("America/Chicago") == "America/Chicago")
        check("schedule tz: (unit) a malformed time falls back rather than raising",
              _tzc.parse_hhmm("25:00") == (5, 0) and _tzc.parse_hhmm("") == (5, 0)
              and _tzc.parse_hhmm("7:05") == (7, 5))
    finally:
        (_sm_core.run_command, _sm_core._rewrite_crontab) = _tz_saved
        with app.app_context():
            db.session.get(RemoteServer, remote_id).timezone = ""
            db.session.commit()


    # ── LinuxGSM's own per-line stamp gives HISTORY a real time ─────────────────────────────
    # The panel tails the console log, so on its own it can only date what it watched arrive — an
    # idle server's whole history is blank, which is what "can you make it always keep track of
    # time" was asking about. LinuxGSM can stamp the log AT WRITE TIME (`logtimestamp="on"` pipes
    # the tmux capture through `gawk strftime`, command_start.sh), and that stamp survives in the
    # file. It is written in the HOST's local time with no offset, which is why this needs
    # RemoteServer.timezone — the whole reason that column exists.
    from panel.core import terminal as _lt_term
    from panel.routes._shared import _console_rows as _lt_rows
    _lt_saved = _sm_core.run_command
    try:
        check("log stamps: LinuxGSM's shape is parsed off the line, and stripped from the text",
              _lt_term.split_log_timestamp("[2026-09-18 05:09:57] ] Player connected")
              == ("2026-09-18 05:09:57", "] Player connected"),
              "got %s" % (_lt_term.split_log_timestamp("[2026-09-18 05:09:57] ] Player connected"),))
        # A game printing something bracket-shaped of its own must not be mistaken for a stamp and
        # have its first word eaten.
        check("log stamps: a bracketed line that is NOT a timestamp is left completely alone",
              _lt_term.split_log_timestamp("[PH:X Integrity Check] No errors found.")
              == (None, "[PH:X Integrity Check] No errors found."),
              "got %s" % (_lt_term.split_log_timestamp("[PH:X Integrity Check] No errors."),))
        # The conversion: written in the host's clock, stored as an epoch, rendered in the
        # viewer's. 05:09:57 in Tokyo is NOT 05:09:57 anywhere else.
        _lt_rowset = _lt_rows(["[2026-09-18 05:09:57] hello", "no stamp here"], "Asia/Tokyo")
        _lt_want = _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "Asia/Tokyo")
        check("log stamps: the stamp becomes a UTC epoch read in the HOST's timezone",
              _lt_rowset[0]["t"] == _lt_want and _lt_want is not None,
              "got %s, wanted %s" % (_lt_rowset[0]["t"], _lt_want))
        check("log stamps: ...and it is a DIFFERENT instant than the same wall time elsewhere",
              _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "Asia/Tokyo")
              != _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "America/Chicago"),
              "two zones produced the same epoch — the host timezone is being ignored")
        check("log stamps: an unstamped line beside a stamped one still carries no time",
              _lt_rowset[1]["t"] is None and _lt_rowset[1]["line"] == "no stamp here",
              "got %s" % (_lt_rowset[1],))
        # A host whose timezone is unknown must NOT have its stamps read against a guess: a line
        # dated nine hours wrong is worse than one with no date.
        check("log stamps: an unknown host timezone yields no time rather than a guessed one",
              _lt_rows(["[2026-09-18 05:09:57] hello"], "")[0]["t"] is None,
              "a stamp was converted against a guessed zone")

        # End to end through the endpoint the console actually calls.
        with app.app_context():
            db.session.get(RemoteServer, remote_id).timezone = "Asia/Tokyo"
            db.session.commit()
        _sm_core.run_command = lambda *a, **k: ("[2026-09-18 05:09:57] stamped line\nplain line", "", 0)
        _ltj = c.get("/api/console/%d" % gs_id).get_json() or {}
        _lt_got = _ltj.get("lines") or []
        check("log stamps: the console window carries the real time for a stamped line",
              len(_lt_got) == 2 and _lt_got[0]["t"] == _lt_want
              and _lt_got[0]["line"] == "stamped line",
              "got %s" % (_lt_got,))
        check("log stamps: ...and none for the unstamped one beside it",
              len(_lt_got) == 2 and _lt_got[1]["t"] is None, "got %s" % (_lt_got,))
        check("log stamps: the window says whether the log is stamped at all",
              _ltj.get("log_timestamps") is True, "log_timestamps=%r" % _ltj.get("log_timestamps"))

        # Turning it on is a LinuxGSM CONFIG edit, so it needs the config permission and it only
        # takes effect on the next start — both reported rather than assumed away.
        _lt_writes = []
        import panel.routes.server_files as _lt_sf
        _lt_wr = _lt_sf.lgsm_write_config
        try:
            _lt_sf.lgsm_write_config = lambda s, u, n, upd: (_lt_writes.append(upd), (True, "ok"))[1]
            _ltp2 = c.post("/api/server/%d/log-timestamps" % gs_id,
                           json={"enabled": False}).get_json() or {}
            check("log stamps: turning it OFF writes 'off', not a missing key",
                  _lt_writes and _lt_writes[0].get("logtimestamp") == "off"
                  and _ltp2.get("enabled") is False, "wrote %s got %s" % (_lt_writes, _ltp2))
            check("log stamps: ...and says it needs a restart, because pipe-pane is set up at start",
                  _ltp2.get("success") is True and _ltp2.get("needs_restart") is True,
                  "got %s" % _ltp2)
        finally:
            _lt_sf.lgsm_write_config = _lt_wr
    finally:
        _sm_core.run_command = _lt_saved
        with app.app_context():
            db.session.get(RemoteServer, remote_id).timezone = ""
            db.session.commit()


    # ── A burst bigger than the read cap must not lose output, or cut a line in half ─────────
    # The poller reads at most 64KB per tick and then set last_pos to the file's FULL size, so
    # everything past the cap was silently discarded — and the 64KB boundary itself landed
    # mid-line, which reached the screen as a bare "[20" where a timestamp had been sliced. A
    # server writing more than 64KB between two 2-second polls is not hypothetical: it is every
    # GMod start, loading hundreds of Lua modules, which is exactly when someone is watching.
    # Reported as "as the server loads it stops".
    _bs_log = "".join("[2026-09-18 06:22:08] MODULE: cc_module_%05d.lua\n" % i for i in range(3000))
    check("console burst: (setup) the fixture is bigger than one read", len(_bs_log) > 65536 * 2,
          "only %d bytes — the cap would never be hit" % len(_bs_log))

    # Drive the REAL reassembly, not a copy of it: _console_whole_lines is what the poller calls.
    # The first version of this test walked its own copy of the arithmetic and passed cheerfully
    # with the carry deleted from the production code it was meant to guard.
    from panel.routes.server_files import _console_whole_lines as _bs_whole_lines
    from panel.core.panel_state import _console_partial as _bs_partial_state
    _bs_partial_state.pop(-99, None)
    _bs_pos, _bs_seen = 0, []
    for _ in range(12):
        if _bs_pos >= len(_bs_log):
            break
        _bs_diff = min(len(_bs_log) - _bs_pos, 65536)
        # exactly what the shell returns: the byte range, plus the sentinel
        _bs_out = _bs_whole_lines(-99, _bs_log[_bs_pos:_bs_pos + _bs_diff] + "E")
        if _bs_out:
            _bs_seen.extend(_bs_out.split("\n"))
        _bs_pos = _bs_pos + _bs_diff          # the fix: advance by what was READ
    check("console burst: nothing is dropped — every line of the burst arrives",
          len(_bs_seen) == 3000, "saw %d of 3000 lines" % len(_bs_seen))
    check("console burst: ...and not one of them is a fragment",
          all(l.startswith("[2026-09-18 06:22:08] MODULE: ") and l.endswith(".lua")
              for l in _bs_seen),
          "a line was cut at a read boundary: %s"
          % [l for l in _bs_seen if not l.endswith(".lua")][:2])
    check("console burst: ...in order, with no duplicates",
          _bs_seen == [l for l in _bs_log.split("\n") if l],
          "the reassembled stream does not match the file")
    # The source of the bug, pinned directly: advancing to the file's size instead of to what was
    # read is what threw the rest away.
    _bs_src = open(os.path.join(_repo_root, "panel", "routes", "server_files.py"),
                   encoding="utf-8").read()
    check("console burst: the poller advances by bytes READ, not to the file's current size",
          "last_positions[server_id] = last_pos + diff" in _bs_src
          and "last_positions[server_id] = current_size\n" not in _bs_src.replace(
              "                                        last_positions[server_id] = current_size\n",
              "", 1),
          "it still jumps to current_size somewhere past the first-read case — that discards "
          "everything beyond the 64KB cap")
    check("console burst: a rotated log drops the half-line held from the old file",
          "_console_partial.pop(server_id, None)" in _bs_src,
          "the fragment from the previous log survives the rotation and is glued to the new one")


    # ── The panel must never OFFER to turn LinuxGSM's logtimestamp on ───────────────────────
    # It works, and the cost is the live console. LinuxGSM builds the capture as
    # `cat | gawk '{ print strftime(...), $0 }' >> consolelog`, and gawk writing to a FILE is BLOCK
    # buffered, not line buffered: measured at 0 lines reaching the log after 33 lines of input,
    # with everything appearing only once 4KB had accumulated. On a quiet server that is an
    # apparently frozen console for hours, which is how it was reported. The pipeline is built in
    # command_start.sh, so nothing in the panel can add an fflush or stdbuf.
    #
    # Shipped as a one-click offer before anyone measured that. The parsing stays (a log someone
    # stamped by hand still reads correctly) and the OFF switch stays (anyone who turned it on
    # needs the way back), but the invitation is gone and must not come back.
    _sd_html = c.get("/server/%d" % gs_id).get_data(as_text=True)
    check("log stamps: the page does not offer to TURN ON LinuxGSM's stamping",
          "enableLogTimestamps" not in _sd_html,
          "the enable control is back — it starves the live console (gawk block-buffers to a file)")
    check("log stamps: ...but it does offer the way back OFF",
          "disableLogTimestamps" in _sd_html,
          "no way to turn it off — anyone who enabled it is stuck with a frozen console")
    _sd_js_src = open(os.path.join(_repo_root, "static", "js", "server_detail.js"),
                      encoding="utf-8").read()
    check("log stamps: and no JS path enables it either",
          "enabled: true" not in _sd_js_src.replace(" ", "").replace("enabled:true", "enabled: true"),
          "some JS still POSTs enabled:true to the log-timestamps endpoint")

    # ── The Update button and the bulk endpoint must agree about who HAS an update ──────────
    # They didn't. GameServer.supports_update knows the Call of Duty family is not SteamCMD-based
    # and has no `update` command at all (_NO_UPDATE_GAMES exists for exactly that), and
    # /api/servers/bulk-action asks it and skips those servers with "no update support". The
    # control bar computed the same thing a second time, as `(not cmd_set) or ("update" in
    # cmd_set)` — which for a server whose command list has not been fetched yet fails open for
    # EVERY game, the cod family included.
    #
    # So the detail page offered Update on a cod server, accepted the click as a long action,
    # answered "watch the live console for progress", ran a command LinuxGSM does not have, and
    # threw the error away. One question, two answers, and the button had the wrong one.
    with app.app_context():
        _su_remote_id = db.session.get(GameServer, gs_id).remote_id
        _su_cod = GameServer(remote_id=_su_remote_id, name="smoke-cod", short_name="cod4server",
                             game_type="cod4", port=28960, installed=True, status="offline")
        db.session.add(_su_cod)
        db.session.commit()
        _su_cod_id = _su_cod.id
        # No commands cached — the state a freshly imported or installed server is in, and the
        # only one where the two implementations differed.
        check("update button: (setup) the cod server has no cached command list",
              not db.session.get(GameServer, _su_cod_id).get_commands(),
              "it has one, so this proves nothing about the un-fetched case")
        check("update button: the model says a cod server has no update command",
              db.session.get(GameServer, _su_cod_id).supports_update is False,
              "the model thinks it does")
        check("update button: ...and a SteamCMD game with no cached list still fails open",
              db.session.get(GameServer, gs_id).supports_update is True,
              "hiding Update for a game that has one is the worse failure")
    _su_html = c.get("/server/%d" % _su_cod_id).get_data(as_text=True)
    check("update button: the cod server's control bar does NOT offer Update",
          'data-args=\'["update", "@self", false]\'' not in _su_html,
          "the button is there — clicking it runs a command LinuxGSM does not have")
    _su_gmod_html = c.get("/server/%d" % gs_id).get_data(as_text=True)
    check("update button: ...while a SteamCMD game's bar still does",
          'data-args=\'["update", "@self", false]\'' in _su_gmod_html,
          "Update vanished for a game that supports it")
    # The two paths agree now, which is the actual property. Asked via the endpoint that reads
    # the model, so a regression in either implementation shows up as a disagreement.
    _su_bulk = (c.post("/api/servers/bulk-action",
                       json={"action": "update", "server_ids": [_su_cod_id, gs_id]}).get_json()
                or {})
    _su_skipped = [x.get("server_id") for x in _su_bulk.get("skipped", [])]
    _su_queued = [x.get("server_id") for x in _su_bulk.get("queued", [])]
    check("update button: the bulk endpoint skips the same server the bar hides it for",
          _su_cod_id in _su_skipped and gs_id in _su_queued,
          "skipped=%s queued=%s" % (_su_skipped, _su_queued))
    with app.app_context():
        db.session.delete(db.session.get(GameServer, _su_cod_id))
        db.session.commit()

    # ── Which build of the game is installed ────────────────────────────────────────────────
    # "Can you show the version of the game that's installed" — and no single source answers it
    # for the games this panel manages. SteamCMD records an exact buildid on disk and the running
    # game reports a friendlier string over its query protocol; the Call of Duty family has no
    # SteamCMD install at all (it is in _NO_UPDATE_GAMES for the same reason), so for those the
    # query is the ONLY answer that exists. Both are read, and the preference between them, the
    # fallbacks, and what happens when neither answers are each asserted — "unknown" is a real
    # outcome here and must not read as a confident wrong number.
    from panel.ops.ssh_manager import game as _gv_mod
    _gv_saved = _sm_core.run_command
    _gv_rag_saved = _sm_core.run_as_game_user
    _gv_mod.invalidate_game_version()
    try:
        # The manifest as steam really writes it — tab-separated quoted pairs — plus a DECOY that
        # sorts first. serverfiles/steamapps/ can hold a game's manifest and a dependency's, and
        # picking whichever globs first reports a build number that never moves on an update.
        _gv_acf = ('"AppState"\n{\n\t"appid"\t\t"4020"\n\t"name"\t\t"Garrys Mod DS"\n'
                   '\t"LastUpdated"\t\t"1757900000"\n\t"buildid"\t\t"19765832"\n}\n')
        _gv_calls = []

        def _gv_disk(with_manifest=True, appid_in_cfg=True):
            def _rc(server, command, timeout=30, sudo=None):
                _gv_calls.append(command)
                if "appmanifest" in command:      # the on-disk read
                    if not with_manifest:
                        return "", "", 0
                    out = []
                    if appid_in_cfg:
                        out.append("appid=4020")
                    out += ["build=19765832", "updated=1757900000"]
                    return "\n".join(out), "", 0
                if "gamedig" in command:          # the live query
                    return "", "", 0
                return "", "", 0
            return _rc

        _sm_core.run_command = _gv_disk()
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv_remote, _gv_user = _gv_gs.remote, _gv_gs.short_name
            _gv1 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name, force=True)
        check("game version: the Steam build on disk is read when the game isn't answering",
              _gv1.get("build") == "19765832" and _gv1.get("label") == "build 19765832",
              "got %s" % _gv1)
        check("game version: the build is dated, so a stale install is visible as one",
              "files updated 2025-09-15 (UTC)" in (_gv1.get("detail") or ""),
              "got %r" % _gv1.get("detail"))
        check("game version: the appid comes from LinuxGSM's own config, not whichever "
              "manifest globs first",
              any("lgsm/config-lgsm/%s/_default.cfg" % _gv_gs.lgsm_name in _c for _c in _gv_calls),
              "commands were %s" % [_c[:80] for _c in _gv_calls])

        # The running game's own answer wins: it is the version players see, and it is the only
        # one a non-SteamCMD game has.
        def _gv_with_query(server, command, timeout=30, sudo=None):
            if "gamedig" in command:
                return "1.7", "", 0
            return _gv_disk()(server, command, timeout, sudo)

        _sm_core.run_command = _gv_with_query
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv2 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name, force=True)
        check("game version: the version the running game reports is what's shown",
              _gv2.get("label") == "1.7" and _gv2.get("reported") == "1.7", "got %s" % _gv2)
        check("game version: ...and the exact build is kept alongside it, not discarded",
              _gv2.get("build") == "19765832"
              and "Steam build 19765832" in (_gv2.get("detail") or ""), "got %s" % _gv2)

        # A game with neither: no SteamCMD manifest, not answering. The page must show nothing
        # rather than a number carried over from another server or another read.
        _sm_core.run_command = _gv_disk(with_manifest=False)
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv3 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name, force=True)
        check("game version: neither source answering is an empty label, not a wrong number",
              _gv3.get("label") == "" and not _gv3.get("build"), "got %s" % _gv3)

        # ...and that miss must not be CACHED: an unreachable host and a mid-install server both
        # look like this, and pinning "unknown" for the whole TTL outlasts either.
        _sm_core.run_command = _gv_with_query
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv4 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name)
        check("game version: a total miss isn't cached — the next read tries again",
              _gv4.get("label") == "1.7", "got %s" % _gv4)

        # A real answer IS cached (this page is opened a lot, the answer moves a few times a
        # year) — and an update has to drop it, or the panel shows the pre-update build forever.
        _gv_calls.clear()
        _sm_core.run_command = lambda *a, **k: (_gv_calls.append(1), ("", "", 0))[1]
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv5 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name)
        check("game version: a known answer is served from cache, with no SSH at all",
              _gv5.get("label") == "1.7" and not _gv_calls, "calls=%d %s" % (len(_gv_calls), _gv5))
        _gv_mod.invalidate_game_version(_gv_remote.id, _gv_user)
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                 port=_gv_gs.port, query_type="csgo",
                                 selfname=_gv_gs.lgsm_name)
        check("game version: invalidating it forces a fresh read (what an update relies on)",
              bool(_gv_calls), "it still answered from cache")
        # An invalidation aimed at ANOTHER instance on the same host must not clear this one.
        _sm_core.run_command = _gv_with_query
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                 port=_gv_gs.port, query_type="csgo",
                                 selfname=_gv_gs.lgsm_name, force=True)
        _gv_mod.invalidate_game_version(_gv_remote.id, "some-other-instance")
        _gv_calls.clear()
        _sm_core.run_command = lambda *a, **k: (_gv_calls.append(1), ("", "", 0))[1]
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv6 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                        port=_gv_gs.port, query_type="csgo",
                                        selfname=_gv_gs.lgsm_name)
        check("game version: invalidating another instance on the host leaves this one cached",
              _gv6.get("label") == "1.7" and not _gv_calls, "calls=%d" % len(_gv_calls))

        # THE CALL SITE. Everything above passes just as well if nothing ever invokes the
        # invalidator — and then the panel serves the pre-update build for the rest of the TTL,
        # which is the one moment the number is guaranteed wrong. So run a real long action and
        # check the cached answer is gone afterwards. (A mutation removing the call from
        # _bg_action passed every other check in this block.)
        _sm_core.run_command = _gv_with_query
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                 port=_gv_gs.port, query_type="csgo",
                                 selfname=_gv_gs.lgsm_name, force=True)
        check("game version: (setup) there is a cached answer for the update to drop",
              bool(_gv_mod._version_cache), "nothing cached — the next check proves nothing")
        _gv_done = []
        _sm_core.run_as_game_user = lambda *a, **k: (_gv_done.append(1), ("Update complete", "", 0))[1]
        try:
            with app.app_context():
                _gv_gs = db.session.get(GameServer, gs_id)
                app._run_action(_gv_gs, _gv_gs.remote, "update", None)
            _pa_wait(_gv_done)
            _gv_dl = _pt.time() + 5.0
            while _pt.time() < _gv_dl and _gv_mod._version_cache:
                _pt.sleep(0.02)
            check("game version: running an update drops the cached build it just changed",
                  not _gv_mod._version_cache,
                  "still cached after the update: %s" % dict(_gv_mod._version_cache))
        finally:
            _sm_core.run_as_game_user = _gv_rag_saved

        # Deleting the host must forget its versions. SQLite hands a deleted row's id to the next
        # INSERT, so a new host can arrive with the same id — and a cache keyed by host id would
        # then show ITS game the deleted one's build. An event on the row's deletion, so it holds
        # however the host is removed rather than only through the route that was remembered.
        _sm_core.run_command = _gv_with_query
        with app.app_context():
            _gv_dead = RemoteServer(name="gv-doomed", host="192.0.2.77", port=22,
                                    username="root", auth_method="key", auth_credential="")
            db.session.add(_gv_dead)
            db.session.commit()
            _gv_dead_id = _gv_dead.id
            _gv_mod.game_version(_gv_dead, "gmodserver", game_type="gmod", port=27015,
                                 query_type="csgo", selfname="gmodserver", force=True)
            check("game version: (setup) the doomed host has a cached version",
                  any(k[0] == _gv_dead_id for k in _gv_mod._version_cache),
                  "nothing cached for it — the check below proves nothing")
            db.session.delete(db.session.get(RemoteServer, _gv_dead_id))
            db.session.commit()
        check("game version: deleting a host forgets its versions (its id gets reused)",
              not any(k[0] == _gv_dead_id for k in _gv_mod._version_cache),
              "a recycled host id would inherit: %s" % dict(_gv_mod._version_cache))

        # The endpoint the page actually calls. It passes the server's OWN query_type through,
        # so set one — csgo has no entry in the built-in gamedig map, and without the override
        # the route would be asserting a short-circuit rather than the query.
        with app.app_context():
            db.session.get(GameServer, gs_id).query_type = "csgo"
            db.session.commit()
        _gv_mod.invalidate_game_version()
        _sm_core.run_command = _gv_with_query
        _gvj = (c.get("/api/server/%d/version" % gs_id).get_json() or {})
        check("version api: it answers with the label the page shows",
              _gvj.get("label") == "1.7" and _gvj.get("build") == "19765832", "got %s" % _gvj)
        # An unreachable host is the normal case for this endpoint, not a server error: it is
        # fetched on every load of a page that is otherwise fine, and a 500 there is noise in the
        # log and an error in the browser console for something that is only ever a nicety.
        #
        # TWO checks, because the first one alone was vacuous. game_version swallows an SSH
        # failure itself, so an unreachable host never reaches the route's own handler — the
        # assertion below held with that handler deleted. The second stubs the read to raise, and
        # is the one that actually exercises it.
        _gv_mod.invalidate_game_version()

        def _gv_boom(*a, **k):
            raise ConnectionError("host unreachable")

        _sm_core.run_command = _gv_boom
        _gvr = c.get("/api/server/%d/version" % gs_id)
        check("version api: an unreachable host is 200 with an empty label, not a 500",
              _gvr.status_code == 200 and (_gvr.get_json() or {}).get("label") == "",
              "got %s %s" % (_gvr.status_code, _gvr.get_json()))
        _gv_real = _gv_mod.game_version
        try:
            _gv_mod.game_version = _gv_boom
            _gvr2 = c.get("/api/server/%d/version" % gs_id)
            check("version api: ...and a read that RAISES is handled there too, not a 500",
                  _gvr2.status_code == 200 and (_gvr2.get_json() or {}).get("label") == "",
                  "got %s %s" % (_gvr2.status_code, _gvr2.get_json()))
        finally:
            _gv_mod.game_version = _gv_real
    finally:
        _sm_core.run_command = _gv_saved
        _sm_core.run_as_game_user = _gv_rag_saved
        _gv_mod.invalidate_game_version()
        with app.app_context():
            db.session.get(GameServer, gs_id).query_type = None
            db.session.commit()

    # ── /api/server/<id> reports the player count the rest of the panel uses ────────────────
    # It used to run `cat <console_log> | grep -c '...'` over SSH and then look for a line holding
    # both "players" and "has". grep -c prints a bare number, so the match was impossible: 0/0 for
    # every server, forever, at the cost of a round trip that cats the whole console log.
    from panel.core.panel_state import _player_counts as _pc_cache
    _pc_cache[gs_id] = {"count": 7, "max": 24, "name": None, "ts": 9e9}
    try:
        _ss = c.get("/api/server/%d" % gs_id)
        _ssj = _ss.get_json() or {}
        check("server status api: reports the cached player count, not 0",
              _ssj.get("player_count") == 7 and _ssj.get("max_players") == 24,
              "got %s/%s" % (_ssj.get("player_count"), _ssj.get("max_players")))
        _pc_cache.pop(gs_id, None)
        _ssj2 = (c.get("/api/server/%d" % gs_id).get_json() or {})
        check("server status api: an unknown count is null, not a confident 0",
              _ssj2.get("player_count") is None, "got %r" % _ssj2.get("player_count"))
    finally:
        _pc_cache.pop(gs_id, None)
    # Scanned across the whole source tree, not one file. This used to read app.py, and the code
    # it guards against has not lived there for a long time — an absence assertion pointed at the
    # wrong file passes no matter what the panel actually does.
    _all_src = []
    for _d, _, _fs in os.walk(_repo_root):
        if any(_x in _d for _x in (".git", ".venv", "venv", "node_modules", "__pycache__", "/data")):
            continue
        for _f in _fs:
            if _f.endswith(".py") and not _f.endswith("_test.py"):
                try:
                    _all_src.append(open(os.path.join(_d, _f), encoding="utf-8").read())
                except OSError:
                    pass
    check("server status api: no longer cats the console log to count players",
          not any("grep -c 'ClientConnect" in _x for _x in _all_src))

    # ── Editing a game server validates, and refuses a port change it cannot honour ────────
    # /servers/<id>/edit wrote name, game_display and PORT straight from the form. The port write
    # moved only the panel's record: the firewall rule and LinuxGSM stayed on the old port, and the
    # monitor (`gs.port in <listening ports>`) then reported the server offline forever.
    _es = c.post("/servers/%d/edit" % gs_id, data={"name": "renamed-cs", "game_display": "CS:GO"},
                 headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit server: a valid rename succeeds", (_es.get_json() or {}).get("success") is True,
          _es.get_data(as_text=True)[:120])
    with app.app_context():
        _g = db.session.get(GameServer, gs_id)
        check("edit server: ...and is persisted", _g.name == "renamed-cs" and _g.game_display == "CS:GO")
        _port_before = _g.port
    _esb = c.post("/servers/%d/edit" % gs_id, data={"name": '<img src=x>', "game_display": ""},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit server: a name with HTML metacharacters is refused",
          _esb.status_code == 400 and (_esb.get_json() or {}).get("success") is False)
    _esp = c.post("/servers/%d/edit" % gs_id,
                  data={"name": "renamed-cs", "port": str(_port_before + 1)},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit server: a port change is refused rather than silently desyncing",
          _esp.status_code == 400 and "port can't be changed" in (_esp.get_json() or {}).get("message", ""),
          _esp.get_data(as_text=True)[:160])
    with app.app_context():
        _g = db.session.get(GameServer, gs_id)
        check("edit server: ...and the stored port is untouched", _g.port == _port_before)
        _g.name = "smoke-cs"          # put the fixture back for the checks that follow
        db.session.commit()

    # ── An edit that would leave no superadmin must really abort ───────────────────────────────
    # The guard used to be the LAST thing in edit_user, after the password-reset and 2FA branches —
    # and log_action() ends in db.session.commit(), so those branches had already committed the
    # demotion by the time it looked. Its rollback then had nothing to undo: the route answered
    # "That change would leave no active superadmin — aborted." with zero superadmins left and the
    # web UI locked for everyone, recoverable only through manage.py.
    #
    # Both controls sit in ONE form in manage_users.html, so this is a single ordinary submit.
    # Driven against a throwaway sole-superadmin so the suite's own fixtures stay intact.
    with app.app_context():
        for _u in User.query.filter(User.is_superadmin.is_(True), User.is_active.is_(True)).all():
            _u.is_active = False            # park the real ones so `sole` really is sole
        _sole = User(username="smoke_sole", display_name="Sole",
                     password_hash=auth.hash_password("Str0ng!passw0rd"),
                     is_superadmin=True, is_active=True)
        db.session.add(_sole)
        db.session.commit()
        _sole_id = _sole.id
        _parked = [u.id for u in User.query.filter(User.is_superadmin.is_(True),
                                                   User.is_active.is_(False)).all()]
    _sc = client_as(_sole_id)
    _lr = _sc.post("/users/%d/edit" % _sole_id,
                   data={"username": "smoke_sole", "reset_password": "on"},   # superadmin UNticked
                   headers={"X-Requested-With": "XMLHttpRequest"})
    with app.app_context():
        _left = User.query.filter_by(is_superadmin=True, is_active=True).count()
        _row = db.session.get(User, _sole_id)
        check("edit user: an edit that would leave no superadmin really aborts",
              _left >= 1, "the panel was left with %d active superadmin(s)" % _left)
        check("edit user: ...and the row is unchanged, not half-committed",
              _row.is_superadmin and _row.is_active,
              "is_superadmin=%s is_active=%s" % (_row.is_superadmin, _row.is_active))
        check("edit user: the refusal is reported as one", _lr.status_code == 400,
              "got %d" % _lr.status_code)
    # A junk group id is a refusal, not a 500 — and must not have committed a password reset that
    # the 500 then prevented anyone from ever seeing.
    _jr = _sc.post("/users/%d/edit" % _sole_id,
                   data={"username": "smoke_sole", "is_superadmin": "on", "is_active": "on",
                         "groups": "abc", "reset_password": "on"},
                   headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit user: a non-numeric group id does not 500", _jr.status_code < 500,
          "got %d" % _jr.status_code)
    check("edit user: ...and the reset password is actually handed back",
          bool((_jr.get_json() or {}).get("credential")), _jr.get_data(as_text=True)[:120])
    with app.app_context():                 # restore the suite's own superadmins
        for _i in _parked:
            _u = db.session.get(User, _i)
            if _u:
                _u.is_active = True
        _s = db.session.get(User, _sole_id)
        if _s:
            db.session.delete(_s)
        db.session.commit()

    # ── Renaming a group onto an existing name is a 400, not a 500 ─────────────────────
    # Group.name is unique=True. add_group has always checked for the collision; edit_group did not,
    # so a typo raised IntegrityError at commit.
    with app.app_context():
        _ga = Group(name="smoke_dupe_a", description="", is_default=False)
        _gb = Group(name="smoke_dupe_b", description="", is_default=False)
        db.session.add_all([_ga, _gb])
        db.session.commit()
        _ga_id, _gb_id = _ga.id, _gb.id
    _gd = c.post("/groups/%d/edit" % _gb_id, data={"name": "smoke_dupe_a", "description": ""},
                 headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit group: a duplicate name is refused with a 400, not a 500",
          _gd.status_code == 400 and "already exists" in (_gd.get_json() or {}).get("message", ""),
          "status=%d" % _gd.status_code)
    _gk = c.post("/groups/%d/edit" % _gb_id, data={"name": "smoke_dupe_b", "description": "same"},
                 headers={"X-Requested-With": "XMLHttpRequest"})
    check("edit group: keeping its OWN name is not a collision",
          (_gk.get_json() or {}).get("success") is True, _gk.get_data(as_text=True)[:120])
    with app.app_context():
        for _gid in (_ga_id, _gb_id):
            _gg = db.session.get(Group, _gid)
            if _gg:
                db.session.delete(_gg)
        db.session.commit()


    # ── A TOTP code is single-use on the password-change path too ────────────────────
    # The login path has recorded the spent step since single-use was introduced; this — the panel's
    # other route that accepts a live authenticator code — still asked the yes/no question, so an
    # observed code stayed usable here for the rest of its ~90s window.
    import pyotp as _pyotp
    with app.app_context():
        _t = db.session.get(User, admin2_id)
        _t.last_totp_step = 0
        _t.password_hash = auth.hash_password("Str0ng!passw0rd")
        db.session.commit()
        _secret = _t.totp_secret_plain
    _tc = client_as(admin2_id)
    _code = _pyotp.TOTP(_secret).now()
    _r1 = _tc.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                              "new_password": "Str0ng!passw0rd-2",
                                              "confirm_password": "Str0ng!passw0rd-2",
                                              "totp_code": _code})
    # The status matters as much as the result. `u = current_user` kept the LocalProxy, and
    # login_user(proxy) made flask-login store it as the session user — so the next current_user
    # resolution recursed and the request died with a RecursionError, AFTER the new password was
    # committed. A 500 on a password change that actually worked, with no audit entry.
    check("password change: succeeds with a redirect, not a 500",
          _r1.status_code in (301, 302, 303), "status=%d" % _r1.status_code)
    with app.app_context():
        _t = db.session.get(User, admin2_id)
        check("password change: a valid authenticator code is accepted",
              auth.check_password("Str0ng!passw0rd-2", _t.password_hash), "status=%d" % _r1.status_code)
        check("password change: ...and the step it used is recorded",
              (_t.last_totp_step or 0) > 0, "last_totp_step=%s" % _t.last_totp_step)
    _tc2 = client_as(admin2_id)   # the change revoked the old session
    _r2 = _tc2.post("/account/password", data={"current_password": "Str0ng!passw0rd-2",
                                               "new_password": "Str0ng!passw0rd-3",
                                               "confirm_password": "Str0ng!passw0rd-3",
                                               "totp_code": _code})
    with app.app_context():
        _t = db.session.get(User, admin2_id)
        check("password change: REPLAYING that same code is refused",
              auth.check_password("Str0ng!passw0rd-2", _t.password_hash),
              "the replayed code changed the password again")

    # ── The API-token card is reachable, and the mint actually shows the token ────────────
    # The Bearer path authenticates as its owner on every route (see the token checks above), but
    # the account page had no way to mint or revoke one — and the mint route rendered a template
    # that ignored `new_token`, so it stored a credential and threw the plaintext away.
    _acct = c.get("/account").get_data(as_text=True)
    check("account page: offers the API-token control", "api-token/generate" in _acct)
    _mint = c.post("/account/api-token/generate")
    _mint_body = _mint.get_data(as_text=True)
    _shown = _re_as.search(r"(lgsm_[0-9a-f]{48})", _mint_body)
    check("api token: minting one SHOWS it (once)", _shown is not None, "status=%d" % _mint.status_code)
    if _shown:
        check("api token: the token it showed actually authenticates",
              app.test_client().get("/api/servers", headers={
                  "Authorization": "Bearer %s" % _shown.group(1)}).status_code == 200)
    check("account page: offers Revoke once a token exists", "api-token/revoke" in _mint_body)
    _rev = c.post("/account/api-token/revoke", follow_redirects=True)
    check("api token: revoking it works", _rev.status_code == 200)
    if _shown:
        check("api token: ...and the revoked token stops authenticating",
              app.test_client().get("/api/servers", headers={
                  "Authorization": "Bearer %s" % _shown.group(1)}).status_code != 200)

    # ── can_run_custom_command: who may press a superadmin-authored console button ────────────────
    # Every branch of this decides whether a non-superadmin gets to run a console command on a
    # server, and none of it was asserted.
    from panel.security.auth import can_run_custom_command as _crcc
    with app.app_context():
        _gs = db.session.get(GameServer, gs_id)          # game_type "csgo" on host #1
        _cmd = CustomCommand(name="Say", command_template="say {}", scope_type="all", enabled=True)
        db.session.add(_cmd)
        _grp = Group(name="smoke_cc", description="", is_default=False)
        _grp.set_permissions([auth.VIEW_SERVERS])
        _grp.servers.append(db.session.get(RemoteServer, remote_id))
        db.session.add(_grp)
        db.session.flush()
        _cu = User(username="smoke_cc_user", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="CC", is_superadmin=False, is_active=True)
        _cu.groups.append(_grp)
        db.session.add(_cu)
        db.session.commit()
        _adm = db.session.get(User, admin_id)

        check("custom command: a superadmin may run an enabled, in-scope command",
              _crcc(_adm, _cmd, _gs) is True)
        # The core rule: having ACCESS to the server is not having the COMMAND.
        check("custom command: a user whose groups lack the command may NOT run it",
              _crcc(_cu, _cmd, _gs) is False, "access to the server leaked the command")
        _grp.custom_commands.append(_cmd)
        db.session.commit()
        check("custom command: granting it to the user's group lets them run it",
              _crcc(_cu, _cmd, _gs) is True)

        _cmd.enabled = False
        db.session.commit()
        check("custom command: a disabled command is refused even to a superadmin",
              _crcc(_adm, _cmd, _gs) is False)
        _cmd.enabled = True
        # Scope: this command is for a different game, so it must not appear on this server.
        _cmd.scope_type, _cmd.scope_value = "game", "minecraft"
        db.session.commit()
        check("custom command: a command scoped to another game is refused",
              _crcc(_adm, _cmd, _gs) is False)
        _cmd.scope_value = _gs.game_type
        db.session.commit()
        check("custom command: scoping it to THIS game allows it again",
              _crcc(_adm, _cmd, _gs) is True)

        # A user with no groups has no access to the host, so the access check must refuse first.
        _nu = User(username="smoke_cc_none", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="None", is_superadmin=False, is_active=True)
        db.session.add(_nu)
        db.session.commit()
        check("custom command: a user with no groups is refused", _crcc(_nu, _cmd, _gs) is False)
        check("custom command: a missing command is refused, not an exception",
              _crcc(_adm, None, _gs) is False)

except Exception:
    # A crash part-way through otherwise just prints fewer checks and still reads as green-ish.
    # That has hidden three separate mistakes while writing these; a crash is a FAILURE.
    import traceback as _tb
    _tb.print_exc()
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
