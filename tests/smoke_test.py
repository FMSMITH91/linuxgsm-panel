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
# The Funnel ban gate refreshes its set in a background thread after a failed login (where proxied
# traffic can arrive) and after Block / Unban / Whitelist. Left live, those threads outlive the
# check that started them and read whatever firewall stub a LATER check installed into the set.
# The refresh itself is driven directly, with its own stub, where it is tested.
from panel.security import banlist as _smoke_banlist
_smoke_banlist.refresh_soon = lambda *a, **k: None
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
    _tpls = sorted(pathlib.Path("templates").glob("*.html"))
    # A "no bad url_for anywhere" gate passes on an empty sweep. Floor, not an inventory.
    check("templates: the url_for sweep found templates to read", len(_tpls) >= 20,
          "%d templates — the check below would pass vacuously" % len(_tpls))
    for p in _tpls:
        for m in re.finditer(r"""url_for\(\s*['"]([A-Za-z_][\w]*)['"]""", p.read_text(encoding="utf-8")):
            if m.group(1) not in endpoints:
                bad.append("%s -> url_for('%s')" % (p.name, m.group(1)))
    check("templates: every url_for() endpoint exists", not bad, "; ".join(sorted(set(bad))))


_check_template_url_for()


def _console_window_stub(text):
    """run_command as the real shell answers /api/console's FRAMED tail: B<content>E, stripped.

    The route reads `printf B; tail -N log; printf E` so the window's first and last lines keep
    their whitespace; a stub that returned bare text for every command would now read as a failed
    (unframed) read. Any other command gets the bare text, as these stubs always gave it."""
    def _run(*a, **k):
        cmd = a[1] if len(a) > 1 else k.get("command", "")
        if "printf B;" in cmd:
            return ("B" + text + "\nE").strip(), "", 0
        return text.strip(), "", 0
    return _run


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

    # ── /tailscale's Disable takes down the PANEL's Serve mapping, not the first one listed ──
    # The button sent services[0].routes[0].mount, and Tailscale lists "/" first — on a node where
    # another app holds "/" and the panel sits at /lgsm, that was the other app. And the removal
    # ran `tailscale serve --bg --remove`, a flag no Tailscale version has, so it never worked.
    import panel.ops.tailscale_integration as _tsd
    from panel.core.config import load_config as _tsd_load, save_config as _tsd_save
    _tsd_saved = (_tsd.get_tailscale_info, _tsd._run_ts, _tsd.ensure_operator)
    _tsd_cfg0 = dict(_tsd_load())
    _tsd_port = _tsd_cfg0.get("port", 5000)
    _tsd_ran = []
    _tsd_info = _tsd.TailscaleInfo(
        installed=True, running=True, backend_state="Running", dns_name="node.example.ts.net",
        tailscale_ips=["100.64.0.9"],
        serve_config={"services": [{"url": "https://node.example.ts.net", "funnel": True, "routes": [
            {"mount": "/", "target": "http://127.0.0.1:3000"},
            {"mount": "/lgsm", "target": "http://127.0.0.1:%d" % _tsd_port}]}], "raw": "x"})
    try:
        _tsd.get_tailscale_info = lambda force_refresh=False: _tsd_info
        _tsd._run_ts = lambda args, timeout=5: (_tsd_ran.append(list(args)), ("", "", 0))[1]
        _tsd.ensure_operator = lambda: (True, "panel")
        _tsd_c = _tsd_load()
        # No stored mount: the button's mount has to come from the host's routes, which only the
        # route supplies — a stored "/lgsm" would let a route that passed nothing pass this too.
        # bind_host 0.0.0.0: the panel is reachable without Serve, so disabling it strands nothing
        # (the loopback case, where it does, is refused below).
        _tsd_c.update(tailscale_setup_done=True, tailscale_use_funnel=True, tailscale_mount="",
                      bind_host="0.0.0.0")
        _tsd_save(_tsd_c)
        _tsd_html = c.get("/tailscale").get_data(as_text=True)
        check("tailscale page: Disable targets the panel's own mount, not another app's '/'",
              'data-mount="/lgsm"' in _tsd_html and 'data-mount="/"' not in _tsd_html,
              repr([ln.strip() for ln in _tsd_html.splitlines() if "data-mount" in ln][:3]))
        _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/"})
        check("tailscale serve: disabling at another app's mount removes nothing and keeps the config",
              _tsd_r.status_code != 200 and _tsd_ran == []
              and _tsd_load().get("tailscale_setup_done") is True,
              "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
        # A loopback-bound panel is reached ONLY through Serve. Removing it ended the admin's session
        # and nothing could reach the process again — a restart re-binds 127.0.0.1 and no longer
        # re-applies Serve — so getting back in took host SSH. change-port refuses to create that
        # state; Disable created it with one click. Both a stored 127.0.0.1 and an unset bind that
        # boot resolved to 127.0.0.1 are that state.
        import app as _tsd_app
        _tsd_rb = dict(_tsd_app._RESOLVED_BIND)
        try:
            for _tsd_label, _tsd_bind, _tsd_resolved in (
                    ("a stored 127.0.0.1 bind", "127.0.0.1", None),
                    ("an unset bind that boot resolved to 127.0.0.1", "", "127.0.0.1")):
                _tsd_app._RESOLVED_BIND.clear()
                if _tsd_resolved:
                    _tsd_app._RESOLVED_BIND[_tsd_port] = _tsd_resolved
                _tsd_lb = _tsd_load()
                _tsd_lb["bind_host"] = _tsd_bind
                _tsd_save(_tsd_lb)
                _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/lgsm"})
                check("tailscale serve: Disable is refused with %s (it would lock the admin out)"
                      % _tsd_label,
                      _tsd_r.status_code == 400 and _tsd_ran == []
                      and _tsd_load().get("tailscale_setup_done") is True
                      and "0.0.0.0" in ((_tsd_r.get_json() or {}).get("message") or ""),
                      "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
        finally:
            _tsd_app._RESOLVED_BIND.clear()
            _tsd_app._RESOLVED_BIND.update(_tsd_rb)
        # The same POST with the panel reachable without Serve goes through: the control that the
        # refusal above is about the bind, not about Disable.
        _tsd_lb = _tsd_load()
        _tsd_lb["bind_host"] = "0.0.0.0"
        _tsd_save(_tsd_lb)
        _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/lgsm"})
        check("tailscale serve: disabling the panel's mount runs the CLI's `serve ... off` removal",
              _tsd_r.status_code == 200
              and _tsd_ran == [["serve", "--https=443", "--set-path=/lgsm", "off"]],
              "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
        check("tailscale serve: ...and the boot path will no longer re-apply it (control)",
              _tsd_load().get("tailscale_setup_done") is False
              and not _tsd_load().get("tailscale_use_funnel"))
    finally:
        _tsd.get_tailscale_info, _tsd._run_ts, _tsd.ensure_operator = _tsd_saved
        _tsd._cache["info"] = None
        _tsd_save(_tsd_cfg0)
    # ── window.MOUNT follows the LIVE mount, like url_for does ────────────────────────────────
    # It was the mount as it stood at boot, while PrefixMiddleware applies the live one to every
    # request: after Serve was enabled (or moved) at runtime the pages rendered with correct links,
    # and every fetch() and the console socket went to the old mount until a restart.
    _mt_saved = load_config()
    try:
        _mt_cfg = dict(_mt_saved)
        _mt_cfg["tailscale_mount"] = "/lgsm"
        save_config(_mt_cfg)
        _mt_r = c.get("/lgsm/account")
        _mt_html = _mt_r.get_data(as_text=True)
        check("mount: (control) the page is served under a mount set at runtime",
              _mt_r.status_code == 200 and 'href="/lgsm/' in _mt_html, "got %d" % _mt_r.status_code)
        check("mount: a mount set at runtime reaches window.MOUNT (not the boot-time one)",
              'window.MOUNT = "/lgsm";' in _mt_html,
              "fetch() and the socket would still use the boot-time mount")
    finally:
        save_config(_mt_saved)
    check("mount: ...and with no mount, window.MOUNT is empty again",
          'window.MOUNT = "";' in c.get("/account").get_data(as_text=True))

    # ── a banned client arriving through Tailscale Funnel (or a reverse proxy) is refused ──────
    # Funnel delivers every public client from 127.0.0.1 — the client's own connection ends at
    # Tailscale's relay — so fail2ban's and the auto-block's firewall bans never touch it: a banned
    # client carried on at 8 guesses per 5 minutes while the panel announced it banned. The gate is
    # the OUTERMOST WSGI layer, because the Socket.IO handshake and the static files never reach
    # Flask's request hooks. Driven through the real app stack.
    from panel.security import banlist as _gb
    _gb_saved = (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, dict(_gb._taken))
    try:
        _gb.set_f2b(["203.0.113.77", "100.101.102.103"])
        _gb.set_ufw({"198.51.100.0/24": "panel-autoblock"})
        _gb.set_whitelist([])
        _gb_c = app.test_client()
        _gb_ban = {"X-Forwarded-For": "203.0.113.77"}
        _gb_r = {"login": _gb_c.get("/login", headers=_gb_ban),
                 "socket": _gb_c.get("/socket.io/?EIO=4&transport=polling", headers=_gb_ban),
                 "static": _gb_c.get("/static/css/panel.css", headers=_gb_ban),
                 "ufw-net": _gb_c.get("/login", headers={"X-Forwarded-For": "198.51.100.40"})}
        check("funnel gate: a banned forwarded client is refused on a page, the Socket.IO handshake, "
              "a static file, and from a banned UFW network",
              all(r.status_code == 403 and r.get_data() == b"Forbidden\n" for r in _gb_r.values()),
              {k: r.status_code for k, r in _gb_r.items()})
        _gb_ok = {"other": _gb_c.get("/login", headers={"X-Forwarded-For": "192.0.2.10"}),
                  "banned-first-hop": _gb_c.get("/login",
                                                headers={"X-Forwarded-For": "203.0.113.77, 192.0.2.10"}),
                  "no-header": _gb_c.get("/login"),
                  "socket-other": _gb_c.get("/socket.io/?EIO=4&transport=polling",
                                            headers={"X-Forwarded-For": "192.0.2.10"}),
                  # A tailnet peer the jail banned (web port only) keeps its Serve access.
                  "tailnet": _gb_c.get("/login", headers={"X-Forwarded-For": "100.101.102.103"})}
        check("funnel gate: ...while any other client, a banned address that is not the LAST hop, "
              "a request with no forwarded address, and a banned TAILNET peer go through",
              all(r.status_code != 403 for r in _gb_ok.values())
              and _gb_ok["socket-other"].get_data(as_text=True).startswith("0{"),
              {k: r.status_code for k, r in _gb_ok.items()})
        _gb.set_whitelist(["203.0.113.77"])
        _gb_wl = _gb_c.get("/login", headers=_gb_ban).status_code
        _gb.set_whitelist([])
        _gb.set_f2b([])
        _gb.set_ufw([])
        _gb_lift = _gb_c.get("/login", headers=_gb_ban).status_code
        check("funnel gate: ...a whitelisted address is never refused, and a lifted ban lets it in",
              _gb_wl != 403 and _gb_lift != 403, "whitelisted=%s lifted=%s" % (_gb_wl, _gb_lift))
    finally:
        (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, _gb_t0) = _gb_saved
        _gb._taken.clear()
        _gb._taken.update(_gb_t0)

    # The set is kept current between the ban-watcher's 90 s ticks: a failed login that came
    # through a proxy (it may be the one fail2ban bans for), and an admin's Block / Unban /
    # Whitelist, each ask for one refresh. Recorded, not run — a refresh reads the firewall.
    _gb_calls = []
    _gb_rs = _gb.refresh_soon
    _gb_cfg0 = load_config()
    try:
        _gb.refresh_soon = lambda delay=3.0: _gb_calls.append(delay)
        for _proxied in (True, False):
            _gb_calls.clear()
            app.test_client().post("/login", data={"username": "nobody-here", "password": "x"},
                                   headers={"X-Forwarded-For": "192.0.2.77"} if _proxied else {})
            check("funnel gate: a failed login %s a refresh (%s)"
                  % ("asks for" if _proxied else "does not ask for",
                     "it came through a proxy" if _proxied else "it came straight in"),
                  bool(_gb_calls) is _proxied, repr(_gb_calls))
        from panel.ops import system_ops as _gb_so
        _gb_deny = _gb_so.ufw_deny_ip
        try:
            _gb_so.ufw_deny_ip = lambda ip: (True, "blocked")
            _gb_calls.clear()
            c.post("/api/panel/security/block", json={"ip": "203.0.113.200"})
            _gb_blk = list(_gb_calls)
        finally:
            _gb_so.ufw_deny_ip = _gb_deny
        check("funnel gate: an admin's Block IP refreshes the set at once", _gb_blk == [0],
              repr(_gb_blk))
    finally:
        _gb.refresh_soon = _gb_rs
        save_config(_gb_cfg0)
    _gb_app_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.py"),
                       encoding="utf-8").read()
    _gb_watch = _gb_app_src[_gb_app_src.index("def _f2b_ban_watch"):]
    _gb_watch = _gb_watch[:_gb_watch.index("time.sleep(90)")]
    check("funnel gate: the 90 s ban-watcher feeds the set from the reading it already takes",
          "_banlist.set_f2b(reading, _taken)" in _gb_watch
          and "_banlist.set_ufw(so.ufw_blocked_ips(), _taken)" in _gb_watch)

    # ── a socket opened BEFORE its client was banned is dropped when the ban lands ─────────────
    # A ban refuses new connections — the gate above, or the firewall — and nothing re-asked about
    # one already open: a live console or a root terminal opened by an address fail2ban then banned
    # kept streaming for as long as the browser stayed. Driven through the real socket stack.
    from panel.routes import server_files as _bs_sf
    _bs_saved = (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, dict(_gb._taken))
    _bs_socks = []

    def _bs_open(xff):
        _s = app.socketio.test_client(app, flask_test_client=client_as(admin_id),
                                      headers={"X-Forwarded-For": xff})
        _bs_socks.append(_s)
        return _s
    try:
        _gb.set_f2b([])
        _gb.set_ufw([])
        _gb.set_whitelist(["203.0.113.99"])
        _bs = {"banned": _bs_open("203.0.113.88"), "other": _bs_open("192.0.2.88"),
               "tailnet": _bs_open("100.101.102.104"), "whitelisted": _bs_open("203.0.113.99")}
        check("ban sweep: (control) every socket connects and is recorded by its address",
              all(_s.is_connected() for _s in _bs.values()) and len(_bs_sf._socket_addrs) >= 4,
              {k: _s.is_connected() for k, _s in _bs.items()})
        _gb.set_f2b(["203.0.113.88", "100.101.102.104", "203.0.113.99"])
        check("ban sweep: a fail2ban ban drops the open socket of the address it names",
              not _bs["banned"].is_connected())
        check("ban sweep: ...and leaves another client, a tailnet peer and a whitelisted address "
              "connected", all(_bs[k].is_connected() for k in ("other", "tailnet", "whitelisted")),
              {k: _s.is_connected() for k, _s in _bs.items()})
        _gb.set_ufw({"192.0.2.0/24": ""})
        check("ban sweep: a UFW deny of a whole network drops a socket inside it",
              not _bs["other"].is_connected())
        check("ban sweep: a dropped socket leaves no address behind (the disconnect handler ran)",
              not any(a[1] is not None and str(a[1]) in ("203.0.113.88", "192.0.2.88")
                      for a in _bs_sf._socket_addrs.values()), repr(_bs_sf._socket_addrs))
        check("ban sweep: a banned address cannot open a new socket either",
              not _bs_open("203.0.113.88").is_connected())
        # A socket is refused where a new request would be. A direct client meets the host
        # firewall, which bans the ADDRESS; a forwarded one meets the gate, which widens an IPv6
        # ban to its /64 (the throttle's unit). Judging the peer by the /64 cost a household
        # neighbour its console while every page still loaded.
        import ipaddress as _bs_ip
        _gb.set_f2b(["2001:db8:1:2::10"])
        _bs_n = _bs_ip.ip_address("2001:db8:1:2::11")
        _bs_v6 = [_bs_sf._addrs_banned((_bs_ip.ip_address("2001:db8:1:2::10"), None)),
                  _bs_sf._addrs_banned((_bs_n, None)), _bs_sf._addrs_banned((None, _bs_n))]
        check("ban sweep: an IPv6 ban drops the banned PEER but not a /64 neighbour the firewall "
              "still admits, while a FORWARDED neighbour is judged by its /64 as the gate judges it",
              _bs_v6 == [True, False, True], repr(_bs_v6))
    finally:
        for _s in _bs_socks:
            try:
                if _s.is_connected():
                    _s.disconnect()
            except Exception:
                pass
        (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, _bs_t0) = _bs_saved
        _gb._taken.clear()
        _gb._taken.update(_bs_t0)
    # panel.js arms its auth ping and session-expired redirect only where SIGNED_IN is true. They
    # ran on signed-out pages too, and threw an invitee (or the first-run admin) off a half-filled
    # form to /login with "Your session expired" — about a session that never existed.
    check("session: (control) a page rendered for a signed-in user says so",
          "window.SIGNED_IN = true;" in c.get("/account").get_data(as_text=True))
    check("session: a signed-out page does not claim a session panel.js could 'expire'",
          "window.SIGNED_IN = false;" in app.test_client().get("/login").get_data(as_text=True))

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

    # ── The audit log shows a detail's END, not just its first 100 characters ──
    # Start/stop/restart store the LAST 400 characters of LinuxGSM's output on purpose — the
    # [ OK ]/[FAIL] line and its reason are at the end — and the viewer cut every detail at 100
    # characters, so the part kept on purpose was never visible anywhere in the panel.
    from panel.db.models import AuditLog as _dtl_AL
    _dtl_head = "DTLHEAD" + "x" * 150
    _dtl_tail = "DTLTAIL_FAIL_REASON"
    with app.app_context():
        db.session.add(_dtl_AL(username="admin", action="server_start", target="dtl-probe",
                               detail=_dtl_head + " ... " + _dtl_tail, success=False))
        db.session.commit()
    _dtl_html = c.get("/logs?q=DTLHEAD").get_data(as_text=True)
    check("audit log: (control) the long entry is on the page at all",
          "DTLHEAD" in _dtl_html, "the probe row did not render — the check below proves nothing")
    check("audit log: a long detail's tail (where the outcome is) is rendered, not cut at 100 chars",
          _dtl_tail in _dtl_html, "the FAIL reason stored at the end of the detail is not on /logs")

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
    _inst_r = c.get("/server/%d" % _inst_id)
    check("console of an installing server redirects (not 200)",
          _inst_r.status_code in (302, 303))
    check("files of an installing server redirects (not 200)",
          c.get("/server/%d/files" % _inst_id).status_code in (302, 303))
    # ...and it must redirect somewhere the VIEWER can enter. It sent them to manage_servers,
    # which is @permission_required(MANAGE_SERVERS, INSTALL_SERVER) and whose whole body is
    # `redirect(url_for("index"))`. A VIEW_CONSOLE-only member failed that gate on a page they
    # never asked for, so the hop added a red "You do not have permission to do that." beside the
    # blue "still installing" notice — a false statement about their own rights — and landed them
    # on the dashboard anyway. Asserted on the LOCATION, not on the flash: a superadmin passes the
    # gate, so the extra hop is invisible to this client and only the target shows it.
    check("installing server: the redirect skips the permission-gated manage_servers hop",
          "/servers/manage" not in (_inst_r.headers.get("Location") or ""),
          "Location: %r — a viewer without MANAGE_SERVERS is told they lack a permission they "
          "never asked for" % (_inst_r.headers.get("Location"),))
    check("installing server: ...and goes straight to the dashboard (positive control)",
          (_inst_r.headers.get("Location") or "x").split("?")[0].endswith("/"),
          "Location: %r — expected the dashboard" % (_inst_r.headers.get("Location"),))

    # ── an install must not call a slow first boot a failure ────────────────────────────────────
    # The install started the server, then polled ~15s for its port and, if it wasn't up, finished
    # with "installed, but it didn't start". Measured while installing the LinuxGSM catalogue on
    # the test host: most games bind immediately, Nuclear Dawn took 20s and Insurgency 40s, and the
    # heavier Unreal/Unity titles are slower again. All of those ended an otherwise perfect install
    # with the one sentence that sends an operator hunting a fault that isn't there.
    #
    # Two things had to change together, so both are pinned: the window, and the fact that a start
    # LinuxGSM did not complain about is not a failed start.
    _ms_src2 = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
    check("install: the post-start port poll waits ~90s, not 15",
          "for _ in range(30):" in _ms_src2 and "for _ in range(5):" not in _ms_src2,
          "still polling 5 times")
    check("install: a start LinuxGSM did not complain about is reported as still coming up",
          "if reason or s_rc != 0:" in _ms_src2 and "installed and starting" in _ms_src2,
          "the didn't-start wording is still unconditional")
    check("install: ...and a start that DID report a problem still says it didn't start",
          "installed, but it didn't start" in _ms_src2)

    # ── a FAILED install must not be a dead end ─────────────────────────────────────────────────
    # The Game Servers page offers a failed row both "Console & stats" and "Files and config", and
    # both routes redirected away saying the server was "still installing". It was not: the install
    # had failed, and step 2 (`./linuxgsm.sh <game>`) had already written the whole
    # lgsm/config-lgsm/<game>/ tree — including the `steamuser="username"` line that the most common
    # failure tells you to change. So the panel pointed at a setting and then locked the door.
    #
    # Verified in a rendered panel before this was written: both links present, both dead.
    with app.app_context():
        _fi = GameServer(remote_id=db.session.get(GameServer, gs_id).remote_id,
                         name="failed-install", short_name="bsserver", game_type="bs",
                         port=27045, installed=False, status="failed")
        db.session.add(_fi); db.session.commit()
        _fi_id = _fi.id
    _ffr = c.get("/server/%d/files" % _fi_id)
    check("failed install: the Files & Config page OPENS (its LinuxGSM config is what survives)",
          _ffr.status_code == 200, _ffr.status_code)
    _ffh = _ffr.get_data(as_text=True)
    check("failed install: ...and says the game files never downloaded",
          "the game files never downloaded" in _ffh)
    # Nothing to browse, back up or install a mod into until the files exist.
    check("failed install: the file browser is not rendered over a directory that isn't there",
          'id="file-browser"' not in _ffh)
    check("failed install: nor the mods card, which installs INTO serverfiles",
          'id="mods-card"' not in _ffh)
    # The config editor is the whole point of the page in this state.
    check("failed install: the LinuxGSM config editor IS there", 'id="cfg-tabs"' in _ffh)
    # The console genuinely has nothing to show, but it must not claim the install is still running
    # — and it should hand the operator to the page that can fix it.
    _fdr = c.get("/server/%d" % _fi_id)
    check("failed install: the console redirects to Files & Config, not to a 'still installing' wait",
          _fdr.status_code in (302, 303)
          and ("/files" in (_fdr.headers.get("Location") or "")), _fdr.headers.get("Location"))
    # A server still genuinely installing keeps the old behaviour.
    with app.app_context():
        _fi2 = db.session.get(GameServer, _fi_id)
        _fi2.status = "installing"; db.session.commit()
    check("failed install: a server that really IS installing still gets the wait message",
          c.get("/server/%d/files" % _fi_id).status_code in (302, 303))
    # And the reconciler has to be looking at failed rows, or files that arrive after a repair
    # (the control bar's Update re-runs SteamCMD) are never adopted and the row stays unusable.
    _app_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "app.py"), encoding="utf-8").read()
    check("failed install: the reconcile ticker re-checks failed rows, so a repair is noticed",
          '("installing", "configuring", "failed")' in _app_src)
    with app.app_context():
        _d = db.session.get(GameServer, _fi_id)
        db.session.delete(_d); db.session.commit()

    # ── /api/server/<id> must never write a status it could not READ ────────────────────────────
    # get_server_status answers "unknown" when the host did not answer. That is not a third kind of
    # server, and this endpoint used to commit it. It arrives more easily than it looks: the read
    # runs LinuxGSM `details`, which does a full `du` of serverfiles — measured at 13s on a 6.5GB
    # server against a 30s timeout — and a timed-out command does not raise here, it returns
    # ("", "timed out", -1). So a big server wrote "unknown" over a perfectly good "online", and
    # the dashboard, the chat bots' /servers and _query_server_slots all repeated it.
    _stat_saved = _sm_core.run_as_game_user
    try:
        with app.app_context():
            _sg = db.session.get(GameServer, gs_id)
            _sg.installed, _sg.status = True, "online"
            db.session.commit()
        # THE BUG: the host did not answer. No raise, no output.
        _sm_core.run_as_game_user = lambda *a, **k: ("", "SSH command timed out", -1)
        _sr = c.get("/api/server/%d" % gs_id)
        check("status endpoint: an unreadable host reports unknown",
              (_sr.get_json() or {}).get("status") == "unknown", _sr.get_json())
        with app.app_context():
            check("status endpoint: ...and does NOT write it over the last known status",
                  db.session.get(GameServer, gs_id).status == "online",
                  db.session.get(GameServer, gs_id).status)
        # A status it really did read still lands, or the guard above would just freeze the column.
        _sm_core.run_as_game_user = lambda *a, **k: ("Status: STOPPED", "", 0)
        c.get("/api/server/%d" % gs_id)
        with app.app_context():
            check("status endpoint: a status it DID read is still persisted",
                  db.session.get(GameServer, gs_id).status == "offline",
                  db.session.get(GameServer, gs_id).status)
    finally:
        _sm_core.run_as_game_user = _stat_saved

    # ── /api/server/<id>/stats tells the page whether it actually READ anything ───────────────
    # This route already computes the ram_total sentinel — it uses it to refuse to PERSIST a
    # guess ("report what we last knew") — and then shipped `metrics` without it, so the detail
    # page painted a confident 0% CPU / 0 MB RAM for a host nobody could read and pushed those
    # zeros into the live chart as a dip that never happened. The route had no test at all.
    _st_saved = _sm_core.server_live_metrics
    try:
        _sm_core.server_live_metrics = lambda *a, **k: {
            "cpu_percent": 12.0, "ram_percent": 40, "ram_total": 8, "disk_percent": 20,
            "cores": 4, "game_procs": 2, "game_cpu_percent": 5.0, "game_ram_mb": 1024,
            "game_uptime_secs": 60, "port_open": True}
        _sj = (c.get("/api/server/%d/stats" % gs_id).get_json() or {})
        check("server stats: a real read is reported as readable",
              _sj.get("metrics_readable") is True, str(_sj)[:140])
        # ...and the all-zero dict, which is what the non-raising transports produce.
        _sm_core.server_live_metrics = lambda *a, **k: {
            "cpu_percent": 0.0, "ram_percent": 0, "ram_total": 0, "disk_percent": 0,
            "cores": 1, "game_procs": 0, "game_cpu_percent": 0.0, "game_ram_mb": 0,
            "game_uptime_secs": 0, "port_open": False}
        _sj2 = (c.get("/api/server/%d/stats" % gs_id).get_json() or {})
        check("server stats: an all-zero sample is reported as NOT readable",
              _sj2.get("metrics_readable") is False, str(_sj2)[:140])
    finally:
        _sm_core.server_live_metrics = _st_saved

    # Alerts endpoint: GET returns the provider list; POST filters to known keys and never 500s
    # (the config write to the game host fails on the test box, but returns gracefully).
    #
    # The GET needs a config read that SUCCEEDS now, and that is the point of the check below it.
    # This used to run against the test box's unreachable game host and still assert a rendered
    # provider list, because the route answered an unreadable config with `values: {}`. The card
    # paints those values into its inputs and Save posts every input back, so a blank form was one
    # click away from writing "" over the operator's real Discord/Telegram credentials.
    _al_saved = _sm_core.run_command
    try:
        from panel.ops.ssh_manager import files as _sm_files_al
        _sm_core.run_command = lambda s, cmd, **k: (
            'discordalert="on"\ndiscordwebhook="https://real/hook"\n' + _sm_files_al._READ_END, "", 0)
        al = c.get("/api/server/%d/alerts" % gs_id)
        check("alerts: GET returns the provider list",
              al.status_code == 200 and isinstance((al.get_json() or {}).get("providers"), list))
        check("alerts: GET returns the values it read",
              ((al.get_json() or {}).get("values") or {}).get("discordwebhook") == "https://real/hook",
              str(al.get_json())[:160])
        # ...and a read that did NOT happen is reported, not rendered as "nothing configured".
        # run_command does not raise on the tailscale/local transports, so this tuple — not an
        # exception — is what an unreachable host really produces.
        _sm_core.run_command = lambda s, cmd, **k: ("", "SSH command timed out", -1)
        alf = c.get("/api/server/%d/alerts" % gs_id)
        _alfj = alf.get_json() or {}
        check("alerts: an unreadable config is an error, not a blank form",
              bool(_alfj.get("error")) and "values" not in _alfj, str(_alfj)[:160])
    finally:
        _sm_core.run_command = _al_saved
    # `al` deliberately stays bound to the SUCCESSFUL read above: the provider cross-checks below
    # compare the GET's advertised providers against the POST's accepted keys, and they need a
    # response that actually carries a provider list.
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

    # ── a queued "stop/restart when empty" must not be thrown away ────────────────────────────
    # The deferred sweep asks get_server_status and treats "offline" as "already stopped, nothing
    # to do" — clearing BOTH flags. Once the port cross-check began answering "offline" for a
    # server whose session is alive but not serving, that swallowed the operator's request: a
    # "stop when empty" aimed at a crashed server (the exact state the cross-check detects) was
    # cleared without ever being performed, and so was one that landed in the seconds between a
    # restart and the port binding.
    #
    # Driven through the real sweep with the status stubbed, because the bug was in the CALLER:
    # the helper answers correctly when asked correctly, and the sweep was not asking.
    import panel.routes._shared as _shmod
    _sh_gss = _shmod.get_server_status
    try:
        with app.app_context():
            _rm = RemoteServer.query.first()
            _q = _UGS(remote_id=_rm.id, name="queued-stop", short_name="queuedstop",
                      game_type="gmod", port=28960, installed=True, status="online")
            _q.stop_pending = True
            db.session.add(_q); db.session.commit()
            _q_id = _q.id

        # A session that is alive but not serving. The stub answers the FOLDED word unless the
        # caller asks the finer question — so the flag surviving proves the sweep asked.
        _shmod.get_server_status = (lambda srv, gs, distinguish_unresponsive=False:
                                    "unresponsive" if distinguish_unresponsive else "offline")
        _shmod._run_due_restarts(app)
        with app.app_context():
            _still_queued = bool(db.session.get(_UGS, _q_id).stop_pending)
        check("queued stop: a server whose session is alive but not serving keeps the request",
              _still_queued,
              "the sweep cleared stop_pending without ever stopping anything")

        # ...and a genuinely stopped server still clears it — that is what 'idle' is for, and
        # this is the control that stops the fix above from being 'never clear anything'.
        _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: "offline"
        _shmod._run_due_restarts(app)
        with app.app_context():
            _cleared = not db.session.get(_UGS, _q_id).stop_pending
        check("queued stop: ...while a genuinely stopped server still clears it", _cleared,
              "a stopped server should not keep a pending stop for ever")
    finally:
        _shmod.get_server_status = _sh_gss
        with app.app_context():
            _l = db.session.get(_UGS, _q_id)
            if _l is not None:
                db.session.delete(_l); db.session.commit()

    # ── a queued stop that FAILED must stay queued, and the sweep must count with the override ─
    # The sweep discarded run_as_game_user's (out, err, rc) and cleared both flags whatever
    # happened. That call does not raise on the tailscale/local transports: a timeout comes back as
    # rc=-1, so a stop that never happened left the queue and nobody retried. It also counted
    # players without the server's gamedig override, so a Project Zomboid/ARK server read as None
    # ("unknown") on every tick and its queued restart never fired.
    from panel.db.models import AuditLog as _QAL
    _qa_saved = (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
                 _sm_core.set_game_priority)
    _qa_pc_args, _qa_rc = [], [-1]
    _qa_id = None
    try:
        with app.app_context():
            _rm = RemoteServer.query.first()
            _qa = _UGS(remote_id=_rm.id, name="queued-stop-rc", short_name="queuedstoprc",
                       game_type="pz", port=16261, installed=True, status="online")
            _qa.stop_pending = True
            _qa.query_type = "projectzomboid"
            db.session.add(_qa); db.session.commit()
            _qa_id = _qa.id
            _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
        _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: "online"

        def _qa_pc(*a, **k):
            if a[1] == "queuedstoprc":
                _qa_pc_args.append((a, k))
            return 0
        _shmod.sm_player_count = _qa_pc
        _sm_core.run_as_game_user = lambda *a, **k: (("", "SSH command timed out", _qa_rc[0])
                                                     if a[1] == "queuedstoprc" else ("", "", 0))
        _sm_core.set_game_priority = lambda *a, **k: None

        def _qa_state():
            with app.app_context():
                _g = db.session.get(_UGS, _qa_id)
                _rows = (_QAL.query.filter_by(target="queued-stop-rc", action="stop_server")
                         .order_by(_QAL.id).all())
                return bool(_g.stop_pending), [(r.success, r.detail) for r in _rows]

        _shmod._run_due_restarts(app)
        _qa_qt = [k.get("query_type", a[4] if len(a) > 4 else None) for a, k in _qa_pc_args]
        check("queued stop: the sweep counts players with the server's gamedig override",
              _qa_qt == ["projectzomboid"],
              "player_count got query_type %r — without it an overridden game reads as unknown "
              "and its queued action never fires" % (_qa_qt,))
        _qa_pend, _qa_rows = _qa_state()
        check("queued stop: a stop that timed out (rc=-1) stays queued for the next tick",
              _qa_pend is True, "stop_pending was cleared although the stop never happened")
        check("queued stop: ...and the failed attempt is audited as a failure",
              len(_qa_rows) == 1 and _qa_rows[0][0] is False and "still queued" in (_qa_rows[0][1] or ""),
              "audit rows %r" % (_qa_rows,))
        # The failure count belongs to the queued action: cancel it, and a later re-queue starts
        # from zero instead of being given up on early with the old attempts.
        _qa_count_before = _shmod._queued_action_failures.get(_qa_id)
        with app.app_context():
            db.session.get(_UGS, _qa_id).stop_pending = False
            db.session.commit()
        _shmod._run_due_restarts(app)
        _qa_count_after = _shmod._queued_action_failures.get(_qa_id)
        with app.app_context():
            db.session.get(_UGS, _qa_id).stop_pending = True
            db.session.commit()
            _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
        check("queued stop: cancelling the queue drops its failure count",
              _qa_count_before == 1 and _qa_count_after is None,
              "count %r before the cancel, %r after" % (_qa_count_before, _qa_count_after))
        # Bounded: a queued action that keeps failing is given up on, not retried for ever (a
        # restart LinuxGSM answers non-zero would otherwise bounce the server on every tick).
        _shmod._run_due_restarts(app)
        _shmod._run_due_restarts(app)
        _shmod._run_due_restarts(app)
        _qa_pend, _qa_rows = _qa_state()
        check("queued stop: ...and is given up on after %d failed attempts, saying so"
              % _shmod._QUEUED_ACTION_ATTEMPTS,
              _qa_pend is False and len(_qa_rows) == _shmod._QUEUED_ACTION_ATTEMPTS
              and "no longer queued" in (_qa_rows[-1][1] or ""),
              "pending=%r rows=%r" % (_qa_pend, _qa_rows))
        # Positive control: a stop that WORKED clears the queue at once and is audited as a success.
        with app.app_context():
            db.session.get(_UGS, _qa_id).stop_pending = True
            db.session.commit()
            _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
        _qa_rc[0] = 0
        # While the maintenance menu's Backup button is archiving the server, the queued stop
        # waits: that long action holds no flag the sweep used to read.
        from panel.core.panel_state import _action_output as _qa_ao
        _qa_ao[_qa_id] = {"action": "backup", "path": "/dev/null", "user": "queuedstoprc", "pos": 0}
        try:
            _shmod._run_due_restarts(app)
        finally:
            _qa_ao.pop(_qa_id, None)
        _qa_pend, _qa_rows = _qa_state()
        check("queued stop: ...waits while a Backup-button run is archiving the server",
              _qa_pend is True and not _qa_rows, "pending=%r rows=%r" % (_qa_pend, _qa_rows))
        _shmod._run_due_restarts(app)
        _qa_pend, _qa_rows = _qa_state()
        check("queued stop: one that exits 0 clears the queue and is audited as a success",
              _qa_pend is False and [r[0] for r in _qa_rows] == [True],
              "pending=%r rows=%r" % (_qa_pend, _qa_rows))
    finally:
        (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
         _sm_core.set_game_priority) = _qa_saved
        _shmod._queued_action_failures.pop(_qa_id, None)
        with app.app_context():
            _l = db.session.get(_UGS, _qa_id) if _qa_id else None
            if _l is not None:
                db.session.delete(_l); db.session.commit()

    # ── a queued restart LinuxGSM answers non-zero ran, and must not run again ─────────────────
    # Every rc but 0 read as "did not happen" and the restart was retried on each tick, up to the
    # attempt limit. But LinuxGSM's exit code is whatever its last log line set: a failed status
    # alert after a good restart ends it at 1. The next tick finds the server online and empty —
    # the very trigger — so it was restarted up to three times. Only a missing exit status (the
    # transport's -1, or ssh's own 255) may be retried; a stop still retries on LinuxGSM's
    # non-zero, because the next tick asks the server first and clears a stopped one.
    _qr_saved = (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
                 _sm_core.set_game_priority)
    _qr_calls, _qr_rc, _qr_status = [], [1], ["online"]
    _qr_id = None
    try:
        with app.app_context():
            _rm = RemoteServer.query.first()
            _qr = _UGS(remote_id=_rm.id, name="queued-restart-rc", short_name="queuedrestartrc",
                       game_type="pz", port=16261, installed=True, status="online")
            _qr.restart_pending = True
            db.session.add(_qr); db.session.commit()
            _qr_id = _qr.id
            _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()
        _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: _qr_status[0]
        _shmod.sm_player_count = lambda *a, **k: 0

        def _qr_run(*a, **k):
            if a[1] != "queuedrestartrc":
                return "", "", 0
            _qr_calls.append(a[2])
            return "Started queuedrestartrc\nSending Discord alert: FAIL", "", _qr_rc[0]
        _sm_core.run_as_game_user = _qr_run
        _sm_core.set_game_priority = lambda *a, **k: None

        def _qr_state():
            with app.app_context():
                _g = db.session.get(_UGS, _qr_id)
                _rows = (_QAL.query.filter(_QAL.target == "queued-restart-rc")
                         .order_by(_QAL.id).all())
                return (bool(_g.restart_pending), bool(_g.stop_pending),
                        [(r.action, r.success, r.detail) for r in _rows])

        def _qr_reset(restart=False, stop=False, rc=1):
            with app.app_context():
                _g = db.session.get(_UGS, _qr_id)
                _g.restart_pending, _g.stop_pending = restart, stop
                db.session.commit()
                _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()
            _shmod._queued_action_failures.pop(_qr_id, None)
            _qr_calls[:] = []
            _qr_rc[0] = rc
            _qr_status[0] = "online"

        _shmod._run_due_restarts(app)
        _shmod._run_due_restarts(app)   # still online and empty: a retry would restart it again
        _qr_rp, _qr_sp, _qr_rows = _qr_state()
        check("queued restart: LinuxGSM exiting 1 after it ran restarts the server ONCE",
              _qr_calls == ["restart"] and _qr_rp is False,
              "calls=%r restart_pending=%r" % (_qr_calls, _qr_rp))
        check("queued restart: ...and the audit row gives the exit code and its line, unqueued",
              len(_qr_rows) == 1 and _qr_rows[0][1] is False
              and "exited 1: " in (_qr_rows[0][2] or "")
              and "no longer queued" in (_qr_rows[0][2] or "")
              and "Discord alert: FAIL" in (_qr_rows[0][2] or ""),
              "rows %r" % (_qr_rows,))
        # Positive controls: no exit status at all is still retried — the hole the retry closed.
        for _qr_code in (-1, 255):
            _qr_reset(restart=True, rc=_qr_code)
            _shmod._run_due_restarts(app)
            _qr_rp, _qr_sp, _qr_rows = _qr_state()
            check("queued restart: one with no answer (rc=%d) stays queued for the next tick" % _qr_code,
                  _qr_calls == ["restart"] and _qr_rp is True
                  and len(_qr_rows) == 1 and "still queued" in (_qr_rows[0][2] or ""),
                  "calls=%r pending=%r rows=%r" % (_qr_calls, _qr_rp, _qr_rows))
        # A stop LinuxGSM answers non-zero stays queued without calling itself a failure, and is
        # cleared, not repeated, once the next tick sees the server stopped.
        _qr_reset(stop=True, rc=2)
        _shmod._run_due_restarts(app)
        _qr_rp, _qr_sp, _qr_rows = _qr_state()
        check("queued stop: LinuxGSM exiting 2 stays queued until the server is seen stopped",
              _qr_sp is True and len(_qr_rows) == 1
              and "exited 2" in (_qr_rows[0][2] or "") and "failed" not in (_qr_rows[0][2] or ""),
              "stop_pending=%r rows=%r" % (_qr_sp, _qr_rows))
        _qr_status[0] = "offline"
        _shmod._run_due_restarts(app)
        _qr_rp, _qr_sp, _qr_rows = _qr_state()
        check("queued stop: ...and a stopped server clears it without a second stop",
              _qr_sp is False and _qr_calls == ["stop"],
              "stop_pending=%r calls=%r" % (_qr_sp, _qr_calls))
    finally:
        (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
         _sm_core.set_game_priority) = _qr_saved
        _shmod._queued_action_failures.pop(_qr_id, None)
        with app.app_context():
            _l = db.session.get(_UGS, _qr_id) if _qr_id else None
            if _l is not None:
                db.session.delete(_l); db.session.commit()
            _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()

    # ── an install that dies EARLY must still leave a row you can act on ──────────────────────
    # Only the step-4 path wrote status="failed". Every earlier exit — a bad game type, an
    # unreachable host during LinuxGSM setup, an unhandled exception — wrote the REASON and left
    # the row saying "installing". The whole recovery design is keyed on status == "failed": no
    # banner, so the reason it had just written was never shown; no Retry; no Remove; and /delete
    # refused it outright with "still installing". The only exit was editing the database.
    #
    # Driven through record_install_failure, the one writer, because the closure that used to hold
    # this is unreachable from a test and re-implementing it here would pass with the fix deleted.
    from panel.routes.manage_servers import record_install_failure as _rif

    class _FakeRow(object):
        pass

    _fr = _FakeRow(); _fr.installed, _fr.status = True, "installing"
    _fr_reason = _rif(_fr, "LinuxGSM setup failed", "ssh: connect to host timed out")
    check("early install failure: the row is marked failed, not left saying 'installing'",
          _fr.status == "failed", "status=%r" % _fr.status)
    check("early install failure: ...and no longer claims to be installed",
          _fr.installed is False, "installed=%r" % _fr.installed)
    check("early install failure: ...and carries the reason and the retry verdict",
          "timed out" in _fr.install_error and _fr.install_retryable is True,
          "%r / %r" % (_fr.install_error, _fr.install_retryable))
    _fr2 = _FakeRow(); _fr2.installed, _fr2.status = True, "installing"
    _rif(_fr2, "The whole explanation.", "a noisy tool tail", retryable=False, explained=True)
    check("early install failure: an explained reason does not get the tool's tail appended",
          _fr2.install_error == "The whole explanation." and _fr2.install_retryable is False,
          _fr2.install_error)

    # ...and the row is removable. A panel restart mid-install strands one of these every time:
    # the worker thread dies with the process while the row keeps saying installing, and there is
    # no cancel route. /delete used to refuse on the STATUS COLUMN, so that row was undeletable.
    _u_orig2 = _sm_core.run_privileged
    try:
        _sm_core.run_privileged = lambda *a, **k: ("", "", 0)
        with app.app_context():
            _rm = RemoteServer.query.first()
            _st = _UGS(remote_id=_rm.id, name="stranded", short_name="stranded",
                       game_type="gmod", port=28950, installed=False, status="installing")
            db.session.add(_st); db.session.commit()
            _st_id = _st.id
        _sresp = c.post("/servers/%d/delete" % _st_id, json={},
                        headers={"X-Requested-With": "XMLHttpRequest"})
        with app.app_context():
            _st_left = _UGS.query.get(_st_id) is not None
        check("stranded install: a row stuck at 'installing' with no live job CAN be removed",
              not _st_left,
              "still there — %r" % ((_sresp.get_json() or {}).get("message"),))
        with app.app_context():
            _l = _UGS.query.get(_st_id)
            if _l: db.session.delete(_l); db.session.commit()
    finally:
        _sm_core.run_privileged = _u_orig2

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
    # A field LEFT OUT is left alone. Both pages posted both fields on a change to either, and
    # Files & Config's keep <select> has no option for 14, so it read '' and an interval change
    # cleared the keep override: the next backup pruned to the global 2 and deleted 12 archives.
    c.post("/api/panel/backup/game/%d/schedule" % gs_id, json={"interval": "7", "keep": "14"})
    _sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
                  json={"interval": "1"}).get_json() or {}
    check("backups: changing only the interval leaves the keep override where it was",
          _sch.get("schedule", {}).get("keep") == 14 and _sch["schedule"].get("keep_set") is True
          and _sch["schedule"].get("interval_days") == 1,
          str(_sch.get("schedule")))
    _sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
                  json={"keep": "4"}).get_json() or {}
    check("backups: ...and changing only keep leaves the interval override (both directions)",
          _sch.get("schedule", {}).get("interval_days") == 1
          and _sch["schedule"].get("interval_set") is True and _sch["schedule"].get("keep") == 4,
          str(_sch.get("schedule")))
    c.post("/api/panel/backup/game/%d/schedule" % gs_id, json={"interval": "", "keep": ""})

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
    # ...and the sidebar, on every page, lists only the hosts their groups grant. It listed every
    # remote's name and id to anyone holding the permission, undoing the per-host scoping above.
    _nav_html = mrc.get("/account").get_data(as_text=True)
    check("sidebar: (control) a host admin's sidebar links the host they are granted",
          ("/remote/%d/manage" % remote_id) in _nav_html, "no granted-host link — the check below is vacuous")
    check("sidebar: ...and does not name a host they are not granted",
          ("/remote/%d/manage" % remote2_id) not in _nav_html and "smoke-host-2" not in _nav_html,
          "the Infrastructure sidebar lists an ungranted host")
    # manage_remotes.html carries no is_local branch any more — six of them tested a flag that is
    # False for every row this route can hand it, including a "This Machine" badge and a "Runs
    # locally on this server" line no visitor was ever shown. That is only true while the route
    # keeps filtering, so the filter is pinned here rather than left as a comment: the panel's own
    # host is managed under System -> Panel Server, and listing it here would offer Test, Tailscale
    # and Prepare against the machine the panel is running on.
    # Seeded HERE and removed again, not added to the fixture: an is_local host changes the host
    # card count, the per-host groups and the dashboard's own tables, and this is the only check
    # that needs one.
    with app.app_context():
        _lh = RemoteServer(name="smoke-localhost", host="127.0.0.1", port=22,
                           username="root", auth_method="key", is_local=True)
        db.session.add(_lh)
        db.session.commit()
        _lh_id = _lh.id
    _rl = c.get("/remotes")
    _rlh = _rl.get_data(as_text=True)
    check("remotes: the page still renders with a local host in the table",
          _rl.status_code == 200 and "smoke-host" in _rlh,
          "status=%d — an empty body would pass the next check vacuously" % _rl.status_code)
    check("remotes: ...and it is not listed",
          "smoke-localhost" not in _rlh and ("/remote/%d/manage" % _lh_id) not in _rlh,
          "the local host is on a page whose template no longer has a branch for it")
    with app.app_context():
        db.session.delete(db.session.get(RemoteServer, _lh_id))
        db.session.commit()

    # ── the Edit form must not offer a transport this panel cannot run ───────────────────────
    # The Add form gates "Tailscale SSH" behind tailscale_installed; the per-remote Edit form
    # offered it unconditionally. edit_remote accepts the value and answers "Remote '…' updated."
    # — and every later command for that host then goes through `ssh 100.x.y.z`, which without
    # tailscaled returns ("", …, -1) WITHOUT raising, so the firewall page, the backups card and
    # ufw status read the host as reachable-but-empty rather than unreachable.
    import panel.routes.remotes as _ts_mod
    _ts_save = _ts_mod.ts

    class _FakeTsInfo:
        def __init__(self, installed):
            self.installed = installed

    class _FakeTs:
        def __init__(self, installed):
            self._installed = installed

        def get_tailscale_info(self):
            return _FakeTsInfo(self._installed)

    with app.app_context():
        _tsr_was = db.session.get(RemoteServer, remote2_id).auth_method
    try:
        _ts_mod.ts = _FakeTs(False)
        _rno = c.get("/remotes").get_data(as_text=True)
        check("remotes: the page renders with Tailscale absent",
              "smoke-host" in _rno,
              "an empty body would pass the next check having rendered nothing")
        check("remotes: no form offers Tailscale SSH when the panel has no Tailscale",
              _rno.count('value="tailscale"') == 0,
              "%d tailscale options on a host with no tailscaled" % _rno.count('value="tailscale"'))
        # A remote ALREADY on that transport keeps the option: hiding it there makes the select
        # submit "key" on the next save and silently repoints a working host.
        with app.app_context():
            _tsr = db.session.get(RemoteServer, remote2_id)
            _tsr.auth_method = "tailscale"
            db.session.commit()
        _rno2 = c.get("/remotes").get_data(as_text=True)
        check("remotes: ...but a remote already on Tailscale SSH keeps its own option",
              _rno2.count('value="tailscale"') == 1 and 'value="tailscale" selected' in _rno2,
              "%d options, selected=%s" % (_rno2.count('value="tailscale"'),
                                           'value="tailscale" selected' in _rno2))
        with app.app_context():
            _tsr = db.session.get(RemoteServer, remote2_id)
            _tsr.auth_method = _tsr_was
            db.session.commit()
        # POSITIVE CONTROL: with Tailscale installed the option is back on every form — the gate
        # is the panel's tailscaled, not a transport that was removed from the UI.
        _ts_mod.ts = _FakeTs(True)
        _rny = c.get("/remotes").get_data(as_text=True)
        check("remotes: ...and every form offers it again once Tailscale is installed",
              _rny.count('value="tailscale"') >= 2,
              "%d tailscale options" % _rny.count('value="tailscale"'))
    finally:
        _ts_mod.ts = _ts_save
        with app.app_context():
            _tsr = db.session.get(RemoteServer, remote2_id)
            if _tsr is not None and _tsr.auth_method != _tsr_was:
                _tsr.auth_method = _tsr_was
                db.session.commit()

    check("MANAGE_REMOTES user: non-granted remote -> 403",
          mrc.get("/api/remote/%d/firewall" % remote2_id).status_code == 403)
    check("MANAGE_REMOTES user: non-granted remote reboot -> 403",
          mrc.post("/api/remote/%d/reboot" % remote2_id).status_code == 403)

    # ── the host page offers a host operator only what their rights can do ──────────────────
    # remote_manage needs MANAGE_REMOTES alone. It offered this operator the game table's
    # Uninstall (a typed-name confirm, then refused) and Files & Config, the install-wide threshold
    # Save and whitelist Add/× (the endpoints ignore or 403 them, and the page said "saved" /
    # "removed"), and top-ips handed them the whole install's whitelist.
    import panel.routes.remote_security as _hp_rs
    _hp_saved = (_hp_rs.remote_fail2ban_top_ips, _hp_rs.remote_security_log)
    _hp_lid = None
    try:
        _hp_rs.remote_fail2ban_top_ips = lambda *a, **k: []
        _hp_rem = mrc.get("/remote/%d/manage" % remote_id).get_data(as_text=True)
        _hp_adm = c.get("/remote/%d/manage" % remote_id).get_data(as_text=True)
        _hp_files = "/server/%d/files" % gs_id
        check("host page: a MANAGE_REMOTES-only operator is not offered Uninstall or Files & Config",
              "smoke-cs" in _hp_rem and "uninstall-form" not in _hp_rem and _hp_files not in _hp_rem,
              "the game row offers controls whose routes refuse this user")
        check("host page: ...while a superadmin still is (positive control)",
              "uninstall-form" in _hp_adm and _hp_files in _hp_adm, "the gate hides them from everyone")
        check("host page: the install-wide threshold Save and whitelist Add are superadmin-only",
              'data-action="saveThreshold"' not in _hp_rem and 'data-action="addWhitelist"' not in _hp_rem
              and 'id="sec-wl-readonly"' in _hp_rem, "an operator is offered writes that are refused")
        check("host page: ...and a superadmin keeps them (positive control)",
              'data-action="saveThreshold"' in _hp_adm and 'data-action="addWhitelist"' in _hp_adm,
              "the superadmin lost the threshold/whitelist controls")
        _hp_ti = mrc.get("/api/remote/%d/security/top-ips" % remote_id).get_json(silent=True) or {}
        _hp_ta = c.get("/api/remote/%d/security/top-ips" % remote_id).get_json(silent=True) or {}
        check("top-ips: a host operator is not sent the install-wide whitelist",
              "whitelist" not in _hp_ti and "autoblock" in _hp_ti, repr(_hp_ti)[:200])
        check("top-ips: ...a superadmin is (positive control)", "whitelist" in _hp_ta, repr(_hp_ta)[:200])
        # An unanswered log read is not an empty log.
        _hp_rs.remote_security_log = lambda *a, **k: None
        _hp_lg = c.get("/api/remote/%d/security/log?which=ssh" % remote_id).get_json(silent=True) or {}
        check("security log: a read no host answered comes back as an error, not empty text",
              _hp_lg.get("error") and _hp_lg.get("text") == "", repr(_hp_lg))
        _hp_rs.remote_security_log = lambda *a, **k: ""
        _hp_lg = c.get("/api/remote/%d/security/log?which=ssh" % remote_id).get_json(silent=True) or {}
        check("security log: ...while an answered empty log is still just empty (positive control)",
              "error" not in _hp_lg and _hp_lg.get("text") == "", repr(_hp_lg))
        # The PANEL HOST's page, granted to the same operator (Groups offers it as a checkbox). Its
        # Security endpoints are all superadmin-only, and its Connection card's else-branch spoke
        # of an SSH login, a Migrate button and a pinned host key the panel host does not have.
        with app.app_context():
            _hp_l = RemoteServer(name="smoke-hp-local", host="127.0.0.1", port=22, username="local",
                                 auth_method="local", auth_credential="", is_local=True)
            db.session.add(_hp_l)
            db.session.flush()
            _hp_g = Group.query.filter_by(name="smoke_mr").first()   # held: a chained append
            _hp_g.servers.append(_hp_l)                              # loses it to the GC
            db.session.commit()
            _hp_lid = _hp_l.id
        _hp_loc = mrc.get("/remote/%d/manage" % _hp_lid).get_data(as_text=True)
        check("panel host page: a non-superadmin is not shown the Security tab its endpoints refuse",
              'id="ssh-port-input"' in _hp_loc and 'data-mtab-btn="security"' not in _hp_loc
              and 'id="sec-bans"' not in _hp_loc, "the tab renders 403s as an all-clear")
        check("panel host page: ...nor an SSH login, Migrate button or host key it does not have",
              "Migrate to Tailscale SSH" not in _hp_loc and "Panel connects via" not in _hp_loc
              and "Pinned SSH host key" not in _hp_loc, "remote-only copy on the panel host")
        check("host page: ...while a REMOTE's page keeps all of them (positive control)",
              'data-mtab-btn="security"' in _hp_rem and "Migrate to Tailscale SSH" in _hp_rem
              and "Pinned SSH host key" in _hp_rem, "the gate hides them on every host")
        _hp_loc_a = c.get("/remote/%d/manage" % _hp_lid).get_data(as_text=True)
        check("panel host page: ...and a superadmin still gets the Security tab there (positive control)",
              'data-mtab-btn="security"' in _hp_loc_a and 'id="sec-bans"' in _hp_loc_a,
              "the Security tab is gone for the superadmin too")
    finally:
        _hp_rs.remote_fail2ban_top_ips, _hp_rs.remote_security_log = _hp_saved
        if _hp_lid is not None:
            with app.app_context():
                _hp_row = db.session.get(RemoteServer, _hp_lid)
                if _hp_row is not None:
                    _hp_row.groups = []
                    db.session.delete(_hp_row)
                    db.session.commit()

    # ── a host you add has to be a host you can then reach ───────────────────────────────────
    # add_remote committed the row and granted it to nothing. Access is purely group-derived, so
    # for a non-superadmin creator the host was invisible on /remotes and answered 403 from its
    # manage page, its edit and its delete — while the panel held its SSH credential, the sweep
    # polled it, and on the "fresh" path a root bootstrap (apt full-upgrade, sshd_config rewrite,
    # reboot) was already running with no way to watch or stop it. The success copy compounded it:
    # "watch the progress on its card" about a card that never appears, and a redirect straight
    # into a 403.
    import panel.routes.remotes as _ar_mod
    _ar_ssh = _ar_mod.ssh_test_connection
    _ar_new_id = None
    try:
        _ar_mod.ssh_test_connection = lambda *a, **k: (True, "ok")
        _ar = mrc.post("/remotes/add",
                       data={"name": "smoke-added-by-mr", "host": "198.51.100.44",
                             "ssh_user": "root", "ssh_port": "22", "auth_method": "password",
                             "credential": "s3cret", "setup_type": "existing"},
                       follow_redirects=False)
        with app.app_context():
            _ar_row = RemoteServer.query.filter_by(name="smoke-added-by-mr").first()
            _ar_new_id = _ar_row.id if _ar_row else None
        check("add_remote: the row is created (the checks below need it)",
              _ar_new_id is not None, "no RemoteServer row was written")
        if _ar_new_id is not None:
            check("add_remote: a non-superadmin creator can reach the host they just added",
                  mrc.get("/remote/%d/manage" % _ar_new_id).status_code != 403,
                  "the creator is 403'd from their own new host")
            check("add_remote: ...and it is listed on the page the flash sends them to",
                  b"smoke-added-by-mr" in mrc.get("/remotes").data,
                  "the card the success message points at does not exist")
            check("add_remote: ...and the redirect goes to a page they can open",
                  _ar.status_code in (301, 302, 303)
                  and ("/remote/%d/manage" % _ar_new_id) in (_ar.headers.get("Location") or ""),
                  "Location: %r" % (_ar.headers.get("Location"),))
            # POSITIVE CONTROL: the grant is scoped to the row that was just created, not a
            # blanket widening — the host this user was never granted is still refused.
            check("add_remote: ...while a host they were never granted is still 403",
                  mrc.get("/api/remote/%d/firewall" % remote2_id).status_code == 403,
                  "the new grant widened access to hosts it should not have touched")
    finally:
        _ar_mod.ssh_test_connection = _ar_ssh
        if _ar_new_id is not None:
            with app.app_context():
                _ar_row = db.session.get(RemoteServer, _ar_new_id)
                if _ar_row is not None:
                    _ar_row.groups = []
                    db.session.delete(_ar_row)
                    db.session.commit()

    # ── ...but only with a credential the delegated admin SUPPLIED ───────────────────────────
    # add_remote decided a host was the creator's to have by logging in to it, then granted it to
    # their MANAGE_REMOTES groups. With auth_method=key the credential is a PATH on the panel host
    # (blank -> the panel user's ~/.ssh/id_rsa, and paramiko tries the agent and every ~/.ssh key
    # besides), and tailscale is the panel node's own tailnet identity: the login proved the PANEL
    # could reach the address, not the requester. edit_remote let the same user repoint a granted
    # row anywhere on those credentials. A password is the one method that proves the requester.
    _ar2_calls = []
    _ar2_ids = []
    _ar2_ssh = _ar_mod.ssh_test_connection
    _jh = {"Accept": "application/json"}
    with app.app_context():
        _ed_row = db.session.get(RemoteServer, remote_id)
        _ed_before = (_ed_row.name, _ed_row.host, _ed_row.port, _ed_row.username,
                      _ed_row.auth_method, _ed_row.auth_credential, _ed_row.sudo_enabled)
    try:
        _ar_mod.ssh_test_connection = lambda *a, **k: (_ar2_calls.append(a), (True, "ok"))[1]
        for _am in ("key", "tailscale"):
            _before_n = len(_ar2_calls)
            _r2 = mrc.post("/remotes/add", headers=_jh,
                           data={"name": "smoke-deleg-%s" % _am, "host": "198.51.100.45",
                                 "ssh_user": "root", "ssh_port": "22", "auth_method": _am,
                                 "credential": "", "setup_type": "existing"})
            with app.app_context():
                _made = RemoteServer.query.filter_by(name="smoke-deleg-%s" % _am).first()
                if _made is not None:
                    _ar2_ids.append(_made.id)
            check("add_remote: a delegated admin cannot add a host that signs in with the panel's "
                  "own %s" % _am,
                  _r2.status_code == 403 and _made is None and len(_ar2_calls) == _before_n,
                  "status=%d row=%s logins=%d — the panel's credential was used to prove the "
                  "requester's claim" % (_r2.status_code, _made is not None,
                                         len(_ar2_calls) - _before_n))
        # ...nor register the panel's own machine: that row is superadmin-only everywhere else
        # (host_local), and from here it landed outside every group the creator is in.
        _r2 = mrc.post("/remotes/add", headers=_jh,
                       data={"name": "smoke-deleg-local", "is_local": "1", "ssh_port": "22"})
        with app.app_context():
            _made = RemoteServer.query.filter_by(name="smoke-deleg-local").first()
            if _made is not None:
                _ar2_ids.append(_made.id)
        check("add_remote: ...nor register the panel's own machine as a host",
              _r2.status_code == 403 and _made is None,
              "status=%d row=%s" % (_r2.status_code, _made is not None))
        # POSITIVE CONTROL: a superadmin still adds a key-auth host (the refusal is scoped).
        _r2 = client_as(admin_id).post("/remotes/add", headers=_jh,
                                       data={"name": "smoke-sa-key", "host": "198.51.100.46",
                                             "ssh_user": "root", "ssh_port": "22",
                                             "auth_method": "key", "credential": "",
                                             "setup_type": "existing"})
        with app.app_context():
            _made = RemoteServer.query.filter_by(name="smoke-sa-key").first()
            if _made is not None:
                _ar2_ids.append(_made.id)
        check("add_remote: ...while a superadmin still adds a key-auth host (positive control)",
              _made is not None, "status=%d" % _r2.status_code)

        # edit_remote: the delegated admin's own granted row, repointed on the panel's key.
        def _ed(**f):
            d = {"name": _ed_before[0], "host": _ed_before[1], "ssh_port": str(_ed_before[2]),
                 "ssh_user": _ed_before[3], "auth_method": _ed_before[4], "credential": ""}
            d.update(f)
            return mrc.post("/remotes/%d/edit" % remote_id, headers=_jh, data=d)

        def _ed_now():
            with app.app_context():
                _x = db.session.get(RemoteServer, remote_id)
                return (_x.host, _x.port, _x.username, _x.auth_method)

        _e = _ed(host="198.51.100.99")
        check("edit_remote: a delegated admin cannot repoint a key-auth host to another address",
              _e.status_code == 403 and _ed_now()[0] == _ed_before[1],
              "status=%d now=%r" % (_e.status_code, _ed_now()))
        _e = _ed(auth_method="tailscale")
        check("edit_remote: ...nor switch it to the panel's tailnet identity",
              _e.status_code == 403 and _ed_now()[3] == _ed_before[4],
              "status=%d now=%r" % (_e.status_code, _ed_now()))
        _e = _ed(ssh_user="admin")
        check("edit_remote: ...nor change the SSH user the panel's key signs in as",
              _e.status_code == 403 and _ed_now()[2] == _ed_before[3],
              "status=%d now=%r" % (_e.status_code, _ed_now()))
        _e = _ed(credential="/home/panel/.ssh/other_key")
        check("edit_remote: ...nor point it at a different key file on the panel host",
              _e.status_code == 403, "status=%d" % _e.status_code)
        # POSITIVE CONTROLS: a rename is not a retarget, and a repoint that brings its own
        # password is the requester's credential, not the panel's.
        _e = _ed(name="smoke-host-renamed")
        with app.app_context():
            _nm = db.session.get(RemoteServer, remote_id).name
        check("edit_remote: ...while a rename still saves (positive control)",
              _e.status_code == 200 and _nm == "smoke-host-renamed",
              "status=%d name=%r" % (_e.status_code, _nm))
        _e = _ed(host="198.51.100.98", auth_method="password", credential="their-own-pw")
        check("edit_remote: ...and a repoint WITH a password they supply is theirs to make",
              _e.status_code == 200 and _ed_now()[0] == "198.51.100.98"
              and _ed_now()[3] == "password",
              "status=%d now=%r" % (_e.status_code, _ed_now()))
    finally:
        _ar_mod.ssh_test_connection = _ar2_ssh
        with app.app_context():
            _x = db.session.get(RemoteServer, remote_id)
            (_x.name, _x.host, _x.port, _x.username, _x.auth_method, _x.auth_credential,
             _x.sudo_enabled) = _ed_before
            for _rid in _ar2_ids:
                _row = db.session.get(RemoteServer, _rid)
                if _row is not None:
                    _row.groups = []
                    db.session.delete(_row)
            db.session.commit()

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
        # The Blocked IPs card shipped with no unreachable branch at all: block_groups is derived
        # from status.groups, which is [] on every unreachable path, so the same screen that said
        # "can't reach this host" went on to state "0 blocked" and "No IPs are blocked." An
        # operator checking whether an abusive address is still denied was told it is not, about a
        # firewall nothing read.
        check("firewall page: ...and does not state 'No IPs are blocked' about a host it never read",
              b"No IPs are blocked." not in _fw.data,
              "the Blocked IPs card contradicts the banner above it")
        check("firewall page: ...and neither count is an arithmetic claim about that host",
              b'id="rules-count">&mdash;<' in _fw.data and b'id="blocks-count">&mdash;<' in _fw.data,
              "a count is still printed for a firewall nothing read")
        # Positive control: a host that ANSWERS and genuinely has nothing must still say so, with
        # real counts — otherwise the three checks above pass by the page refusing to answer ever.
        def _empty(_server):
            return {"installed": True, "enabled": True, "rules": [], "groups": []}
        _rvps.remote_ufw_status = _empty
        _fw_ok = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
        check("firewall page: a REACHABLE host with nothing blocked still says so",
              _fw_ok.status_code == 200 and b"No IPs are blocked." in _fw_ok.data
              and b"No firewall rules yet." in _fw_ok.data,
              "status=%d — the empty states were lost" % _fw_ok.status_code)
        check("firewall page: ...and still counts, rather than dashing everything",
              b'id="blocks-count">0 <' in _fw_ok.data and b"&mdash;" not in _fw_ok.data,
              "the real empty case no longer reports a count")
        check("firewall page: ...and an ACTIVE firewall does not show the inactive note",
              b'class="text-warning d-none">While UFW is inactive' in _fw_ok.data
              and b"installed but inactive" not in _fw_ok.data, "the inactive copy shows on an active host")
        # An INACTIVE ufw (stock Ubuntu) prints only its Status line — stored rules are neither
        # listed nor enforced — so groups is [] and the page said "0 rules", "No firewall rules
        # yet." and "No IPs are blocked." over a block that denies nothing.
        def _inactive(_server):
            return {"installed": True, "enabled": False, "rules": [], "groups": []}
        _rvps.remote_ufw_status = _inactive
        _fw_in = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
        check("firewall page: an INACTIVE ufw is said to be inactive and unenforced",
              _fw_in.status_code == 200 and b"installed but inactive" in _fw_in.data
              and b"neither listed nor enforced" in _fw_in.data,
              "status=%d" % _fw_in.status_code)
        check("firewall page: ...with no rule or block count, and no 'none blocked' claim",
              b'id="rules-count">&mdash;<' in _fw_in.data and b'id="blocks-count">&mdash;<' in _fw_in.data
              and b"No IPs are blocked." not in _fw_in.data and b"No firewall rules yet." not in _fw_in.data,
              "an inactive firewall's empty listing is still counted")
        check("firewall page: ...and says a block there denies nothing",
              b'class="text-warning">While UFW is inactive' in _fw_in.data, "the block copy is unqualified")
        # A sudo refusal comes back as unreachable + permission_denied; the page blamed the network.
        def _sudo_refused(_server):
            return {"installed": False, "enabled": False, "rules": [], "groups": [],
                    "unreachable": True, "permission_denied": True}
        _rvps.remote_ufw_status = _sudo_refused
        _fw_pd = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
        check("firewall page: a sudo refusal names sudo, not an unreachable host",
              _fw_pd.status_code == 200 and b"sudo refused the firewall read" in _fw_pd.data
              and b"can't reach this host" not in _fw_pd.data
              and b"while this host is unreachable" not in _fw_pd.data,
              "status=%d" % _fw_pd.status_code)
    finally:
        _rvps.remote_ufw_status = _real_ufw

    # ── tailscale-finalize must report the UFW change it actually made ───────────────────────
    # The route's whole job is "allow tailscale0 in UFW", and it audited success=status["running"]
    # — tailscaled's BackendState, which says nothing about the firewall. remote_tailscale_finalize
    # only issues the allow when `ufw-status` came back ACTIVE; rc 127 (ufw absent, the normal case
    # for setup_type="existing") and the tailscale transport's silent ("", "…timed out", -1) both
    # make _ufw_is_active("") false, so the allow is skipped and `log` comes back empty. The route
    # received that empty log, forwarded it, and never looked at it — recording a successful
    # firewall change that never happened.
    import panel.routes.remote_tailscale as _rts
    from panel.db.models import AuditLog as _TSAudit
    _real_fin = _rts.remote_tailscale_finalize
    try:
        _rts.remote_tailscale_finalize = lambda _s: ({"running": True, "tailscale_ip": "100.1.2.3",
                                                      "dns_name": "h.ts.net"}, "")
        _tf = client_as(admin_id).post("/api/remote/%d/tailscale-finalize" % remote_id)
        _tfj = _tf.get_json() or {}
        check("tailscale-finalize: a skipped UFW allow is not reported as one that happened",
              _tfj.get("ufw_allowed") is False, "answered %r" % (_tfj,))
        with app.app_context():
            _tfa = (_TSAudit.query.filter_by(action="remote_tailscale_finalize")
                    .order_by(_TSAudit.id.desc()).first())
        check("tailscale-finalize: ...and the audit row does not record a firewall change",
              _tfa is not None and not _tfa.success,
              "audit row: %r" % (getattr(_tfa, "success", "no row"),))
        # POSITIVE CONTROL: when the allow really was issued, both say so.
        _rts.remote_tailscale_finalize = lambda _s: ({"running": True, "tailscale_ip": "100.1.2.3",
                                                      "dns_name": "h.ts.net"},
                                                     "UFW: allowed tailscale0 interface (in)")
        _tf2 = client_as(admin_id).post("/api/remote/%d/tailscale-finalize" % remote_id)
        _tfj2 = _tf2.get_json() or {}
        check("tailscale-finalize: a UFW allow that DID happen is reported and audited",
              _tfj2.get("ufw_allowed") is True and _tfj2.get("running") is True,
              "answered %r" % (_tfj2,))
        with app.app_context():
            _tfa2 = (_TSAudit.query.filter_by(action="remote_tailscale_finalize")
                     .order_by(_TSAudit.id.desc()).first())
        check("tailscale-finalize: ...with a success row, so the gate is not refusing everything",
              _tfa2 is not None and _tfa2.success,
              "audit row: %r" % (getattr(_tfa2, "success", "no row"),))
    finally:
        _rts.remote_tailscale_finalize = _real_fin

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

    from panel.core.panel_state import (_install_jobs as _install_jobs_sm,
                                        _install_lock as _install_lock_sm)
    # ── the recorded reason must be READABLE ────────────────────────────────────────────────────
    # LinuxGSM and SteamCMD colour their output, and the last 300 bytes of a failed install is
    # nearly all escape sequences. That is what the corner card showed, verbatim:
    #
    #   info...\x1b[0mOK \x1b[0mERROR! Failed to install app '222860' (Invalid platform)
    #   \x1b[0mUnloading Steam API...\x1b[0mOK \x1b[0m\x1b[31mFailure!\x1b[0m Installing l4d2server…
    #
    # The panel has had strip_escapes since the console was written; this path never called it.
    _raw_tail = ("info...\x1b[0mOK \x1b[0mERROR! Failed to install app '222860' (Invalid "
                 "platform)\r\n   \x1b[0m\x1b[31mFailure!\x1b[0m Installing l4d2server")
    # The PANEL'S function, not a copy of it rebuilt here. These three used to assert properties
    # of a local `" ".join(strip_escapes(raw).split())` the test wrote itself, so they passed with
    # the production line deleted — they were testing the test.
    from panel.routes.manage_servers import readable_reason as _clean_fn
    _clean = _clean_fn(_raw_tail)
    check("install failure: the recorded reason carries no ANSI escapes",
          "\x1b" not in _clean and "[0m" not in _clean, repr(_clean)[:120])
    check("install failure: ...and is one line, not the raw column padding",
          "\r" not in _clean and "\n" not in _clean and "   " not in _clean, repr(_clean)[:120])
    check("install failure: ...with the actual message still in it",
          "Invalid platform" in _clean and "l4d2server" in _clean, repr(_clean)[:120])
    _ms_esc = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
    # ...and _fail routes through it, so every caller benefits rather than just this one.
    check("install failure: _fail strips before recording, so every caller benefits",
          "detail = readable_reason(detail)" in _ms_esc)

    # A CLASSIFIED reason stands alone on the row. The raw tail is the tool's own last word, and
    # the tool is sometimes wrong: LinuxGSM ends an "Invalid platform" failure with "Check
    # steamcmdforcewindows setting and system architecture", which points at the host — and the
    # host is not the problem (the app publishes no Linux launch configuration; proven on the test
    # box, where forcing the platform fails identically). Appending that after the correct sentence
    # undoes it, so the row gets the explanation and the live job keeps the unabridged output.
    # Driven, not grepped: this used to assert that a particular line of source existed, which
    # says nothing about what the line does and broke the moment the logic moved into a function.
    from panel.routes.manage_servers import record_install_failure as _rif_tail

    class _TailRow(object):
        pass

    def _reason(name, detail, explained):
        _r = _TailRow(); _r.installed, _r.status = True, "installing"
        _rif_tail(_r, name, detail, True, explained)
        return _r.install_error

    check("install failure: a classified reason is not followed by the tool's own wrong hint",
          _reason("SteamCMD refused this game — a known SteamCMD bug.",
                  "Check steamcmdforcewindows setting and system architecture", True)
          == "SteamCMD refused this game — a known SteamCMD bug.",
          "the raw tail is still appended to a classified reason")
    check("install failure: ...while an UNclassified one still carries its tail, which is all it has",
          _reason("Downloading game server files", "mirror unreachable", False)
          == "Downloading game server files: mirror unreachable")
    check("install failure: ...and the classified call site is the one that asks for that",
          "explained=bool(why)" in _ms_esc,
          "step 4 no longer tells the recorder the reason is self-contained")

    # ── the install must not point two servers at one port ──────────────────────────────────────
    # resolve_free_port picks a genuinely free port at request time — it unions the host's live
    # listening ports with every panel server's reserved block. Step 6 then adopts whatever port
    # LinuxGSM REPORTS, because auto-install uses the game's default rather than the port the panel
    # wrote. That adoption had no conflict check.
    #
    # A game that ignores the panel's port key reports its own default there. Reproduced on the
    # test box with a Velocity proxy (it reads velocity.toml, not the LinuxGSM key): it reported
    # 25565, the host's Minecraft server already had it, and the proxy logged
    #
    #     [ERROR]: Can't bind to /0.0.0.0:25565
    #     bind(..) failed with error(-98): Address already in use
    #
    # while LinuxGSM still said STARTED. And the panel would then call that proxy ONLINE, because
    # something IS listening on 25565 — a port check cannot tell whose socket it is. So the clash
    # must not be created in the first place.
    # The first version of this checked for substrings in manage_servers.py, which says only that
    # some text is present. The decision is now its own function, so drive it: the panel's table,
    # a foreign listener, and a scan that could not answer are three different results.
    from panel.routes.manage_servers import decide_port_adoption as _dpa

    _scans = []

    def _live(value):
        def f():
            _scans.append(1)
            return value
        return f

    check("install: a reported port nobody holds is adopted",
          _dpa(25565, 25566, {}, _live({22, 80})) == (True, None, False))
    check("install: ...but not one another PANEL server on the host has",
          _dpa(25565, 25566, {25565: "mc"}, _live(set()))[0] is False)
    check("install: ...nor one a NON-panel process is already listening on",
          _dpa(25565, 25566, {}, _live({25565}))[0] is False,
          "adopting a foreign socket makes every status answer read that process, so a server "
          "that never bound anything is reported online for ever")
    check("install: ...nor when the port scan could not answer at all",
          _dpa(25565, 25566, {}, _live(None))[0] is False,
          "a failed scan is not an empty one — 'could not look' must not read as 'free'")
    check("install: ...and each refusal says which of the three it was",
          len({_dpa(25565, 25566, {25565: "mc"}, _live(set()))[1:],
               _dpa(25565, 25566, {}, _live({25565}))[1:],
               _dpa(25565, 25566, {}, _live(None))[1:]}) == 3,
          "two of the three reasons reach the user as the same sentence")
    # The third answer has to be distinguishable BY THE CALLER, not only by its wording. It used
    # to be carried in taken_by as the phrase "something the panel could not check for", so the
    # caller could not tell it from a real holder and printed "it wants port 25565, which
    # something the panel could not check for already uses" — plus a matching
    # `install_complete success=False ... clashes with` audit entry — about a port that is very
    # often free. So: a failed scan names NOBODY, and flags itself.
    _dpa_unread = _dpa(25565, 25566, {}, _live(None))
    check("install: ...and a scan that FAILED names no holder at all",
          _dpa_unread[1] is None and _dpa_unread[2] is True,
          "%r — a phrase here is spliced into 'which %%s already uses', a fact about the host "
          "that this very branch established it could not read" % (_dpa_unread,))
    check("install: ...while an observed holder is still named, and not flagged unreadable",
          _dpa(25565, 25566, {}, _live({25565}))[1] == "another process on this host"
          and _dpa(25565, 25566, {}, _live({25565}))[2] is False,
          repr(_dpa(25565, 25566, {}, _live({25565}))))
    _scans.clear()
    _dpa(25565, 25565, {}, _live(set()))
    _dpa(25565, 25566, {25565: "mc"}, _live(set()))
    check("install: ...without an SSH round trip the table could have answered",
          not _scans, "the host is scanned even when the panel already knows the port is taken")

    # ── SCP: Secret Laboratory asks two questions nobody can answer ─────────────────────────────
    # Found while walking the LinuxGSM catalogue: scpsl installed, LinuxGSM reported STARTED, and
    # the game never launched. Its launcher stops and asks, inside a tmux session with no input:
    #
    #   1. "Before starting please read and accept the SCP:SL EULA. Do you accept? [yes/no]"
    #   2. "Do you want to edit that configuration? [edit/keep]"
    #
    # The second is the subtle one: LocalAdmin keeps its config PER PORT, under
    # config/<port>/, and asks whenever a port has no config yet. The panel assigns a FREE port
    # rather than the game's default, so it walks into that on every install.
    #
    # The panel already writes Minecraft's eula.txt at the same step, so accepting is the
    # established pattern here rather than a new decision. Proven end to end through the panel's
    # own routes on the test host: SCPSL.x86_64 running, console at "Level loaded. Creating
    # match...", and the panel reporting the server online.
    _ms_sl = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
    # Assert what is actually SENT. These were whole-file substring greps, and every string they
    # looked for — "EulaAccepted", "config_localadmin.txt" — also appears in the COMMENTS that
    # explain the code, so all four passed with the EULA write deleted. The ordering one was worse:
    # .index() finds the FIRST occurrence, which is the comment, so it measured where a comment sat.
    from panel.routes.manage_servers import (scpsl_eula_payload as _sl_eula,
                                             scpsl_seed_config_payload as _sl_seed)
    _eula_cmd, _seed_cmd = _sl_eula(), _sl_seed(27031)
    check("scpsl: the EULA is accepted the way Minecraft's already is",
          "d['EulaAccepted']" in _eula_cmd and "localadmin_internal_data.json" in _eula_cmd,
          "the install still stops at the EULA prompt with nothing to answer it")
    check("scpsl: ...and the per-port config is seeded, or LocalAdmin asks about it instead",
          "config/27031" in _seed_cmd and "config_localadmin.txt" in _seed_cmd, _seed_cmd[:120])
    check("scpsl: ...into the directory named after THAT port, not a fixed one",
          "config/27032" in _sl_seed(27032), _sl_seed(27032)[:120])
    check("scpsl: ...and an existing config is left alone",
          '[ -f "$d/config_localadmin.txt" ] ||' in _seed_cmd,
          "it would overwrite a config the operator had edited")
    # AFTER step 6, not at step 5: the port is only final once step 6 has decided whether to adopt
    # the one LinuxGSM reports, and seeding the wrong directory helps nobody. Measured on the CALL,
    # which appears once, rather than on a string the comments also contain.
    check("scpsl: ...seeded once the port is final, not before step 6 can change it",
          _ms_sl.index("scpsl_seed_config_payload(gs.port)")
          > _ms_sl.index("# 6. Sync to LinuxGSM's real port"),
          "the per-port config is written before the port is settled")

    # ── the install works around SteamCMD's "Invalid platform" bug itself ───────────────────────
    # Left 4 Dead 2 refuses to install with "ERROR! Failed to install app '222860' (Invalid
    # platform)". It is not a missing Linux build — the app has a Linux depot (222863) — it is a
    # SteamCMD bug, and LinuxGSM's maintainer published the way through it in
    # GameServerManagers/LinuxGSM#4754: install with steamcmdforcewindows=yes (which gets SteamCMD
    # past its own refusal by pulling the Windows depot), unset it, then validate, which pulls the
    # Linux binaries.
    #
    # Proven on the test host before this was written: both steps reported "Success! App '222860'
    # fully installed", srcds_linux came out an ELF 32-bit LSB executable, and the server started
    # and listened on its port with VAC active. Telling an operator to go and read a GitHub thread
    # is the opposite of what this panel is for, so the install does it.
    _ms_w = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
    check("install: an Invalid-platform failure primes with the Windows depot instead of giving up",
          'why[0] == "steam_platform" and not primed_windows' in _ms_w
          and '{"steamcmdforcewindows": "yes"}' in _ms_w)
    check("install: ...then unsets the flag and validates, which is what pulls the Linux binaries",
          '{"steamcmdforcewindows": "no"}' in _ms_w and '"validate"' in _ms_w)
    check("install: ...and does it at most once, so a workaround that misses cannot loop",
          "primed_windows = True" in _ms_w and "primed_windows = False" in _ms_w)

    # ── a failed install has to say WHY, and offer the two things you can actually do ───────────
    # The row said "Failed" and nothing else. The reason lived in the install job's memory until
    # the panel restarted; Retry did not exist; and Remove was on the host page, a different page
    # from the one showing the failure. Worse, `busy = not installed` greyed out Files & Config on
    # exactly that row — the config the failure usually asks you to change.
    with app.app_context():
        _rf = db.session.get(GameServer, gs_id)
        _rf_before = (_rf.status, _rf.installed, _rf.install_error, _rf.install_retryable)
        _rf.status, _rf.installed = "failed", False
        _rf.install_error = "Downloading game server files: the mirror was unreachable."
        _rf.install_retryable = True
        db.session.commit()
    try:
        _dash = c.get("/").get_data(as_text=True)
        check("failed install: the dashboard says WHY it failed",
              "the mirror was unreachable" in _dash)
        check("failed install: ...and offers Retry when a retry could help",
              ("/servers/%d/retry-install" % gs_id) in _dash)
        check("failed install: ...and Remove, which used to live on another page entirely",
              ("/servers/%d/delete" % gs_id) in _dash)
        # The Files link is what #282 made reachable; greying it out here made that unreachable
        # from the one page that shows the failure.
        #
        # Find it by its CLASS, not by its href. There are TWO links to /server/<id>/files on this
        # page — the banner's "Edit its config" above the table, and the row's own button — and the
        # banner's comes first in the document and is never disabled. A check that took the first
        # href therefore passed whatever the row button did, which is no check at all. Only the row
        # button carries `srv-files`.
        _fi = _dash.find("srv-files")
        _ftag = _dash[_dash.rfind("<a", 0, _fi):_dash.find(">", _fi) + 1] if _fi != -1 else ""
        check("failed install: ...and Files & Config is NOT greyed out on a failed row",
              _fi != -1 and "disabled" not in _ftag,
              _ftag[:200] or "no srv-files button at all")
        check("failed install: ...and the banner offers the same page in words",
              'href="/server/%d/files"' % gs_id in _dash and "Edit its config" in _dash)

        # The retry itself. The real job runs in a background thread and its first step is an SSH
        # round trip to a host this suite does not run, so it fails — what is being checked here
        # is the ROUTE's contract: accepted, row back to installing, reason cleared.
        #
        # HELD at that first SSH call while the contract is read, and drained before the next
        # scenario is written. The crash path records the failure ON THE ROW now (it could not
        # before — the `with _app.app_context():` had already exited by the time the handler ran,
        # so db.session raised "Working outside of application context" into a debug log), and a
        # worker that reaches the row a few milliseconds after this POST returns would both race
        # this check and overwrite the scenario set up after it.
        import contextlib as _rt_ctx
        import threading as _rt_thr
        import time as _rt_time

        def _live_install_workers():
            """The threads still inside an install job's _run(), identified by their target.

            manage_servers spawns them as bare `threading.Thread(target=_run, daemon=True)` — no
            name, no handle kept — so the target function is the only thing there is to match on.
            """
            _out = []
            for _t in _rt_thr.enumerate():
                _tgt = getattr(_t, "_target", None)
                if (_tgt is not None and _t.is_alive()
                        and getattr(_tgt, "__module__", "") == "panel.routes.manage_servers"
                        and getattr(_tgt, "__qualname__", "").endswith("._run")):
                    _out.append(_t)
            return _out

        @_rt_ctx.contextmanager
        def _install_seam_closed(_what):
            """Hold every install worker at its first SSH call, and keep the transport closed
            until all of them have finished.

            Two separate things go wrong without this, and only the first is obvious.

            The obvious one: these jobs run in a background thread whose first step is an SSH
            round trip, and no suite has a host to answer it. Letting that reach the real
            transport costs a full TCP timeout per call on a CI runner — and with a key
            configured it does not even get that far ("No such file: /home/runner/.ssh/id_rsa").
            run_command is not enough on its own; get_connection is the one door all three
            transports go through, so closing it is what makes an unaccounted call fail here
            instead of dialling out.

            The one that actually broke CI: a worker that outlives the block that started it.
            The content-capture POST below starts a job, then deletes its row and pops its job
            dict — but the THREAD keeps running. SQLite hands the next INSERT the id it just
            freed, so the install-job block's own row is created with the SAME id, and the
            abandoned worker's _fail() writes "Install failed unexpectedly: SSH connection
            failed: ... id_rsa" into that row and that job dict. Four install-job checks then
            failed on a job that was walking through its steps perfectly well. It passed locally
            because the worker reached its SSH call before the next block began; on a slower
            runner it did not. This is the hazard _ij_wait's docstring describes, arriving
            through the id rather than through the stubs.

            So the seam does not reopen on a timer or on one row's status — it reopens when
            there is no install worker left alive, and says so loudly if that never happens.
            """
            _gate = _rt_thr.Event()
            _saved_rc, _saved_gc = _sm_core.run_command, _sm_core.get_connection

            def _blocked(*a, **k):
                _gate.wait(30)
                raise ConnectionError("no SSH host in this suite")
            _sm_core.run_command = _blocked
            _sm_core.get_connection = _blocked
            try:
                yield
            finally:
                _gate.set()
                for _ in range(3600):                 # 180s, as _ij_wait allows
                    if not _live_install_workers():
                        break
                    _rt_time.sleep(0.05)
                _sm_core.run_command = _saved_rc
                _sm_core.get_connection = _saved_gc
                _left = len(_live_install_workers())
                check("install seam: no worker outlives the %s block that started it" % _what,
                      _left == 0,
                      "%d still running after 180s — whatever it fails on next lands on the row "
                      "the NEXT block creates, which may hold this one's recycled id" % _left)

        def _retry_under_gate():
            with _install_seam_closed("retry"):
                _resp = c.post("/servers/%d/retry-install" % gs_id)
                with app.app_context():
                    _row = db.session.get(GameServer, gs_id)
                    return _resp, (_row.status, _row.install_error)

        _rr, _rr_state = _retry_under_gate()
        check("failed install: retry is accepted for a retryable failure",
              _rr.status_code in (200, 302), _rr.status_code)
        check("failed install: ...and the row goes back to installing, with the reason cleared",
              _rr_state[0] == "installing" and not _rr_state[1],
              "status=%s error=%r" % _rr_state)
        # ...and the job that then crashes leaves the row RECOVERABLE. The outer handler's own
        # comment promised "a reason on the row, status failed, and the dashboard told"; what it
        # did was set the in-memory job only, because the application context was already gone.
        # The two diverged, and the divergence is what hid it: the corner widget said failed while
        # the row said installing for ever — no reason, no Retry, and /delete refusing to remove
        # it, since /delete will not touch a row that says it is installing.
        with app.app_context():
            _cr = db.session.get(GameServer, gs_id)
            _cr_state = (_cr.status, _cr.install_error, _cr.install_retryable, _cr.installed)
        with _install_lock_sm:
            _cr_job = dict(_install_jobs_sm.get(gs_id) or {})
        check("failed install: a job that dies mid-install writes the failure to the ROW",
              _cr_state[0] == "failed" and bool(_cr_state[1]),
              "status=%r error=%r — the row is stranded at 'installing' with no reason, which "
              "/delete also refuses" % (_cr_state[0], _cr_state[1]))
        check("failed install: ...and offers a retry, since a dropped SSH is worth trying again",
              _cr_state[2] is True and _cr_state[3] is False, repr(_cr_state))
        check("failed install: ...the in-memory job agreeing with it, not instead of it",
              _cr_job.get("status") == "failed", repr(_cr_job.get("status")))
        # The row that actually reaches this state most often. Step 4 commits
        # installed=True/status="configuring"; a panel restart during steps 5-8 kills the worker,
        # and api.py's install-status poll reconciles it by writing status="failed" and leaving
        # installed alone. The dashboard's card is keyed on status ALONE, so it draws the Retry
        # button for that row — and the guard, which also demanded `not gs.installed`, answered
        # "That server's install didn't fail, so there's nothing to retry." to the button it had
        # just drawn. Remove was the only way out, which is the dead end this flow exists to end.
        with app.app_context():
            _ri = db.session.get(GameServer, gs_id)
            _ri.status, _ri.installed = "failed", True
            _ri.install_error = "Interrupted by a panel restart during setup."
            _ri.install_retryable = True
            db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(gs_id, None)
        _dash_ri = c.get("/").get_data(as_text=True)
        check("failed install: a failed row still marked installed is offered Retry",
              ("/servers/%d/retry-install" % gs_id) in _dash_ri,
              "the card is keyed on status alone, so this is the row the guard has to accept")
        _rr_i, _rr_i_state = _retry_under_gate()
        check("failed install: ...and the route accepts it instead of answering its own button",
              _rr_i.status_code in (200, 302) and _rr_i_state[0] == "installing",
              "status=%r http=%r — 'that server's install didn't fail' on a row that says failed"
              % (_rr_i_state[0], _rr_i.status_code))
        with app.app_context():
            _after = db.session.get(GameServer, gs_id)
            # put it back to failed, this time with a cause no retry can fix
            _after.status, _after.installed = "failed", False
            _after.install_error = "This game is not downloadable with an anonymous Steam login."
            _after.install_retryable = False
            db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(gs_id, None)
        _dash2 = c.get("/").get_data(as_text=True)
        check("failed install: a cause no retry can fix does NOT offer Retry",
              ("/servers/%d/retry-install" % gs_id) not in _dash2)
        check("failed install: ...and says so, instead of leaving you to guess",
              "Trying again won" in _dash2)
        _rr2 = c.post("/servers/%d/retry-install" % gs_id)
        with app.app_context():
            check("failed install: ...and the route refuses it too, not just the button",
                  db.session.get(GameServer, gs_id).status == "failed", _rr2.status_code)
    finally:
        with _install_lock_sm:
            _install_jobs_sm.pop(gs_id, None)
        with app.app_context():
            _rf = db.session.get(GameServer, gs_id)
            (_rf.status, _rf.installed, _rf.install_error, _rf.install_retryable) = _rf_before
            db.session.commit()

    # ── a retry must reproduce the install it is retrying ─────────────────────────────────────
    # The mounted-content games for a GMod server arrive on the install FORM and were never stored,
    # so retry_install re-ran the job with no seventh argument: `if content_games and game_type ==
    # "gmod"` was false, the content step was skipped, no mount.cfg was written, and the server
    # came back missing the maps and props that were asked for — with nothing on screen saying so.
    # The retry's progress bar also hardcoded 8 steps while the original derived 9 for these.
    with app.app_context():
        _cg = db.session.get(GameServer, gs_id)
        _cg_before = (_cg.content_games, _cg.status, _cg.installed,
                      _cg.install_error, _cg.install_retryable, _cg.game_type)
        _cg_remote_id = _cg.remote_id
        _cg.content_games = "cstrike,tf"          # real GMOD_CONTENT_GAMES keys
        _cg.game_type, _cg.status, _cg.installed = "gmod", "failed", False
        _cg.install_error, _cg.install_retryable = "mirror unreachable", True
        db.session.commit()
    try:
        # Gated, like the retries above: the crash path records the failure ON THE ROW now, so a
        # worker still running here writes status="failed" over whatever the `finally` below puts
        # back — and gs_id is the row the rest of this suite goes on using. The job dict survives
        # the drain, so `total` is still there to read.
        _retry_under_gate()
        with _install_lock_sm:
            _cgj = dict(_install_jobs_sm.get(gs_id) or {})
        check("retry: a GMod retry counts the content step the original did",
              _cgj.get("total") == 9,
              "total=%r — the progress bar is short by the content step" % (_cgj.get("total"),))
        with app.app_context():
            check("retry: ...and the selection survived on the row to be replayed",
                  (db.session.get(GameServer, gs_id).content_games or "") == "cstrike,tf",
                  db.session.get(GameServer, gs_id).content_games)
        # ...and it gets there from the FORM. Writing the column by hand above tests the replay
        # but not the capture, and the capture is the half that was missing: the selection arrived
        # on this POST and was dropped on the floor.
        # The route refuses when it cannot read the host's ports ("Can't reach ... right now"), and
        # this suite's remote is a 127.0.0.1 nothing answers on. Stub the scan for this POST only.
        _appmod_cg = sys.modules["app"]
        _cg_rlp = _appmod_cg._remote_listening_ports
        _appmod_cg._remote_listening_ports = lambda r: {22}
        # ...and the route now also asks the host whether the account already exists (an existing
        # one is someone else's, not a leftover), which the same dead host cannot answer either.
        import panel.routes.manage_servers as _cg_msmod
        _cg_has = _cg_msmod.host_account_state
        _cg_msmod.host_account_state = lambda r, n: "absent"
        # Under the seam, and drained before the row goes: this POST starts a real install thread,
        # and the row it belongs to is deleted a few lines down. SQLite then hands that freed id
        # to the next INSERT — the install-job block's row — and this worker, still running, wrote
        # its SSH failure onto it. See _install_seam_closed.
        with _install_seam_closed("content-capture"):
            _add = c.post("/servers/add", data={
                "remote_id": str(_cg_remote_id), "game_type": "gmod",
                "server_name": "cgcapture", "port": "28980",
                "content_games": ["cstrike", "tf"],
            }, follow_redirects=True)
        _appmod_cg._remote_listening_ports = _cg_rlp
        _cg_msmod.host_account_state = _cg_has
        with app.app_context():
            _new = GameServer.query.filter_by(short_name="cgcapture").first()
            _captured = (_new.content_games or "") if _new is not None else "<no row>"
            _new_id = _new.id if _new is not None else None
        check("retry: the content selection is captured from the install form in the first place",
              _captured == "cstrike,tf",
              "row stored %r (POST -> %s)" % (_captured, _add.status_code))
        if _new_id is not None:
            with app.app_context():
                _n = db.session.get(GameServer, _new_id)
                if _n is not None:
                    db.session.delete(_n); db.session.commit()
            with _install_lock_sm:
                _install_jobs_sm.pop(_new_id, None)
    finally:
        with app.app_context():
            # Restore what it WAS, including game_type — putting back a hardcoded "gmod" left
            # the row lying about itself and failed four unrelated checks further down the suite.
            _cg = db.session.get(GameServer, gs_id)
            (_cg.content_games, _cg.status, _cg.installed,
             _cg.install_error, _cg.install_retryable, _cg.game_type) = _cg_before
            db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(gs_id, None)

    # ── the install JOB itself, executed end to end ───────────────────────────────────────────
    # Coverage said manage_servers.py was 49% and named the gap: lines 499-948, which is the whole
    # of _run() — steps 2 through 8. Every suite's host is unreachable, so /servers/add started the
    # thread and it died at step 2; the panel's most consequential code path was held only by
    # source-level gates. Those gates read the file. This runs it.
    #
    # The host is stubbed to SUCCEED so the job walks the whole way: dependencies, download,
    # config, port adoption, firewall, autostart, start, and the post-start liveness poll.
    import panel.routes.manage_servers as _msmod
    import time as _ijw_time
    # Stub at the DEFINITION SITE, never on the package. panel/ops/ssh_manager/__init__.py exposes
    # these through __getattr__ precisely so there is one stub target, and its docstring says not
    # to bind names on it. Setting them on the package shadows the forwarding — and "restoring"
    # them afterwards makes that shadow permanent, so every later stub on _core stops being seen.
    # That is not hypothetical: doing it here broke six power-action checks further down the file.
    from panel.ops.ssh_manager import game as _ij_game, portscan as _ij_ps

    def _ij_wait(gid, secs=180):
        """Wait until the install job for `gid` is genuinely FINISHED.

        Both halves matter. The job dict can stop saying "running" while the worker still has work
        left, and the worker only touches the row at the end — so waiting on either one alone lets
        the block finish, restore its stubs, and leave a thread still running against whatever the
        NEXT block installs. That is not hypothetical: CI logged the first job adopting the second
        scenario's ports, because the first block had already handed the stubs back.
        """
        # int(), and a floor of one pass: a fractional or zero `secs` made range() empty, so the
        # loop never ran and the return below referenced an unbound name — the guard crashed the
        # suite instead of reporting the stall it exists to report. Found by mutating it.
        _row_status = "unread"
        _deadline = max(1, int(secs * 10))
        for _ in range(_deadline):
            with _install_lock_sm:
                j = dict(_install_jobs_sm.get(gid) or {})
            with app.app_context():
                _r = db.session.get(GameServer, gid)
                _row_status = _r.status if _r is not None else "gone"
            if j.get("status") not in ("running", None) and _row_status != "installing":
                return j, _row_status, True
            _ijw_time.sleep(0.1)
        with _install_lock_sm:
            j = dict(_install_jobs_sm.get(gid) or {})
        return j, _row_status, False

    _ij_saved, _ij_calls, _ij_state = {}, [], {"started": False}

    def _ij_stub(mod, name, fn):
        _ij_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    def _ij_ports(_remote):
        # Before the server starts, nothing of ours is listening — which is what makes the port
        # step 6 wants to adopt look free. After `start`, the port answers.
        return {28991} if _ij_state["started"] else set()

    def _ij_run_as(remote, user, action, **k):
        if action == "start":
            _ij_state["started"] = True
        _ij_calls.append(("run_as_game_user", action))
        return ("", "", 0)

    try:
        # Close the SSH seam outright. The stubs below cover every function this job is KNOWN to
        # call, and CI still reached paramiko — "SSH connection failed: Error reading SSH protocol
        # banner" / "No such file: /home/runner/.ssh/id_rsa" — on a runner where a real connect
        # gets further than it does here, which is why it reproduced there and not locally. It only
        # became visible when the install job's last-resort _fail() gained the app context it needs
        # to record anything: before that the failure was swallowed and the job kept its earlier
        # values, so the checks below passed on a job that had crashed.
        #
        # get_connection is the one door all three transports go through, so stubbing it makes any
        # call this block has NOT accounted for fail loudly and locally instead of dialling out.
        _ij_stub(_sm_core, "get_connection",
                 lambda *a, **k: (_ for _ in ()).throw(
                     AssertionError("the install job opened a real SSH connection — a call this "
                                    "block does not stub reached the transport")))
        _ij_stub(_sm_core, "read_as_game_user", lambda *a, **k: ("", "", 0))
        _ij_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
        _ij_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
        _ij_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
        _ij_stub(_sm_core, "run_as_game_user", _ij_run_as)
        _ij_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
        _ij_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop", "monitor"])
        _ij_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
        _ij_stub(_msmod, "_looks_installed", lambda *a, **k: True)
        _ij_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
        _ij_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
        _ij_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
        _ij_stub(_msmod, "install_game_cron", lambda *a, **k: None)
        _ij_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
        _ij_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
        _ij_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
        _ij_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
        _ij_stub(_msmod, "_remote_listening_ports", _ij_ports)
        _ij_stub(_msmod, "remote_ufw_allow_game_ports",
                 lambda r, ports, name: _ij_calls.append(("ufw_allow", tuple(sorted(ports)))))
        # LinuxGSM reports a port other than the one the panel allocated — the ordinary case for a
        # game that reads its own config — and nothing else holds it, so step 6 adopts it.
        _ij_stub(_msmod, "detect_game_ports",
                 lambda *a, **k: {"game_port": 28991, "open_ports": [28991, 28992]})
        _appmod_ij = sys.modules["app"]
        _ij_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
        _appmod_ij._remote_listening_ports = lambda r: {22}

        _ij_resp = c.post("/servers/add", data={
            "remote_id": str(_cg_remote_id), "game_type": "gmod",
            "server_name": "jobwalk", "port": "28990"}, follow_redirects=True)
        with app.app_context():
            _ij_row = GameServer.query.filter_by(short_name="jobwalk").first()
            _ij_id = _ij_row.id if _ij_row else None
        check("install job: the POST created a row to run the job against", _ij_id is not None,
              "no row — the job never started (POST %s)" % _ij_resp.status_code)

        if _ij_id is not None:
            _job, _row_st, _ij_settled = _ij_wait(_ij_id)
            _st = _job.get("status")
            # What the job itself said, so a failure here names the step it stopped on instead of
            # only the end state. CI failed this where the machine running it passed, and "status
            # is still installing" on its own does not say which stub the job walked past.
            _why_job = "job=%r step=%r/%r name=%r msg=%r" % (
                _st, _job.get("step"), _job.get("total"), _job.get("step_name"),
                (_job.get("message") or "")[:200])
            with app.app_context():
                _ij_done = db.session.get(GameServer, _ij_id)
                _ij_final = (_ij_done.status, _ij_done.installed, _ij_done.port,
                             _ij_done.install_error)
            check("install job: it runs to completion instead of dying at step 2",
                  _ij_settled, _why_job)
            check("install job: ...and the server ends up installed and online",
                  _ij_final[0] == "online" and _ij_final[1] is True,
                  "status=%r installed=%r error=%r | %s" % (_ij_final[0], _ij_final[1], _ij_final[3], _why_job))
            check("install job: ...having adopted the port LinuxGSM reported",
                  _ij_final[2] == 28991, "port=%r | %s" % (_ij_final[2], _why_job))
            check("install job: ...and started the server, not just installed it",
                  ("run_as_game_user", "start") in _ij_calls,
                  "calls: %s | %s" % (_ij_calls[:8], _why_job))
            _ij_opened = [c2 for c2 in _ij_calls if c2[0] == "ufw_allow"]
            check("install job: ...and opened the reported ports in the firewall",
                  any(28991 in c2[1] for c2 in _ij_opened), "ufw calls: %s | %s" % (_ij_opened, _why_job))
            with app.app_context():
                _d = db.session.get(GameServer, _ij_id)
                if _d is not None:
                    db.session.delete(_d); db.session.commit()
            with _install_lock_sm:
                _install_jobs_sm.pop(_ij_id, None)
    finally:
        for (_m, _n), _v in _ij_saved.items():
            setattr(_m, _n, _v)

    # ...and the branch where the reported port is ALREADY HELD by something that is not us.
    # Until now this was checked by reading the AST. Here it is executed: step 6 must keep the
    # port the panel allocated, and — the part that was actually broken — the firewall must not be
    # opened for the port it just refused, in either of the two places that open ports.
    _cf_saved, _cf_calls = {}, []

    def _cf_stub(mod, name, fn):
        _cf_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    try:
        _cf_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
        _cf_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
        _cf_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
        # The clash is about the port LinuxGSM REPORTS, not necessarily the one the game binds:
        # here the game honours the panel's config and comes up on 28994, while 28995 stays
        # someone else's. That also lets the post-start poll exit on its first tick instead of
        # running its full 30 x 3s — without which the job is still mid-poll when the checks run,
        # and the post-start re-detect (the second place that opens ports) is never reached. A
        # mutation proved that: reverting the re-detect's filter changed nothing until this did.
        _cf_state = {"started": False}

        def _cf_run_as(remote, user, action, **k):
            if action == "start":
                _cf_state["started"] = True
            return ("", "", 0)

        _cf_stub(_sm_core, "run_as_game_user", _cf_run_as)
        _cf_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
        _cf_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
        _cf_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
        _cf_stub(_msmod, "_looks_installed", lambda *a, **k: True)
        _cf_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
        _cf_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
        _cf_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
        _cf_stub(_msmod, "install_game_cron", lambda *a, **k: None)
        _cf_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
        _cf_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
        _cf_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
        _cf_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
        # 28995 is occupied by something the panel has no row for — a hand-installed server, a
        # container, anything never imported through /discover.
        _cf_stub(_msmod, "_remote_listening_ports",
                 lambda r: ({22, 28995, 28994} if _cf_state["started"] else {22, 28995}))
        _cf_stub(_msmod, "detect_game_ports",
                 lambda *a, **k: {"game_port": 28995, "open_ports": [28995, 28996]})
        _cf_stub(_msmod, "remote_ufw_allow_game_ports",
                 lambda r, ports, name: _cf_calls.append(tuple(sorted(ports))))
        _cf_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
        _appmod_ij._remote_listening_ports = lambda r: {22, 28995}

        c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                     "server_name": "jobclash", "port": "28994"},
               follow_redirects=True)
        with app.app_context():
            _cf_row = GameServer.query.filter_by(short_name="jobclash").first()
            _cf_id = _cf_row.id if _cf_row else None
        check("install job (clash): the POST created a row", _cf_id is not None)
        if _cf_id is not None:
            _cjob, _crow_st, _cf_settled = _ij_wait(_cf_id)
            check("install job (clash): the job finished before the stubs are handed back",
                  _cf_settled,
                  "job=%r row=%r — a thread still running here would walk into the next block's "
                  "stubs" % (_cjob.get("status"), _crow_st))
            with app.app_context():
                _cf_port = db.session.get(GameServer, _cf_id).port
            check("install job (clash): the panel KEEPS its own port, it does not adopt one "
                  "something else is on", _cf_port == 28994,
                  "port=%r — adopting it makes every status answer read the other process's "
                  "socket" % (_cf_port,))
            _cf_opened = sorted({p for call in _cf_calls for p in call})
            check("install job (clash): ...and never opens the refused port in the firewall",
                  28995 not in _cf_opened,
                  "ufw was asked to open %s — `ufw allow <port> comment <name>` REPLACES a rule "
                  "differing only by comment, so this retags the other server's rule" % (_cf_opened,))
            check("install job (clash): ...while still opening its own",
                  28994 in _cf_opened, "opened %s" % (_cf_opened,))
            with app.app_context():
                _d = db.session.get(GameServer, _cf_id)
                if _d is not None:
                    db.session.delete(_d); db.session.commit()
            with _install_lock_sm:
                _install_jobs_sm.pop(_cf_id, None)
    finally:
        for (_m, _n), _v in _cf_saved.items():
            setattr(_m, _n, _v)

    # ...and the THIRD answer, which used to be told as the second. decide_port_adoption returns
    # "could not look" as well as "taken" and "free", but it carried that answer only in the
    # WORDING of taken_by — the phrase "something the panel could not check for" — so the caller
    # could not tell it from a named holder. On a Tailscale host still busy from a 25-minute
    # SteamCMD run the 8-second `ss` times out, the transport returns ("", "…timed out", -1)
    # WITHOUT raising, and the operator was told: "it wants port 28998, which something the panel
    # could not check for already uses. ... or free that port on the host." The audit log recorded
    # `install_complete success=False detail="port 28998 clashes with something the panel could
    # not check for"`, and the firewall was narrowed over a clash nobody observed — so the query
    # port the game does need was left closed too. 28998 was very probably free.
    _ur_saved, _ur_calls = {}, []

    def _ur_stub(mod, name, fn):
        _ur_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    # time.sleep, skipped. The post-start verification polls 30 × 3s, and with the host
    # unreadable there is no early exit from it — 90 real seconds for one check. Only
    # manage_servers' own `time` is swapped, and only inside this block.
    import types as _ur_types
    _ur_fast = _ur_types.SimpleNamespace(sleep=lambda _s: None, time=_ijw_time.time)

    try:
        _ur_stub(_msmod, "time", _ur_fast)
        _ur_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
        _ur_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
        _ur_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
        _ur_stub(_sm_core, "run_as_game_user", lambda *a, **k: ("", "", 0))
        _ur_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
        _ur_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
        _ur_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
        _ur_stub(_msmod, "_looks_installed", lambda *a, **k: True)
        _ur_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
        _ur_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
        _ur_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
        _ur_stub(_msmod, "install_game_cron", lambda *a, **k: None)
        _ur_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
        _ur_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
        _ur_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
        _ur_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
        # The scan never answers — the failure mode the paramiko-only `except` below it misses.
        _ur_stub(_msmod, "_remote_listening_ports", lambda r: None)
        _ur_stub(_msmod, "detect_game_ports",
                 lambda *a, **k: {"game_port": 28998, "open_ports": [28998, 28999]})
        _ur_stub(_msmod, "remote_ufw_allow_game_ports",
                 lambda r, ports, name: _ur_calls.append(tuple(sorted(ports))))
        _ur_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
        _appmod_ij._remote_listening_ports = lambda r: {22}

        c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                     "server_name": "jobunread", "port": "28997"},
               follow_redirects=True)
        with app.app_context():
            _ur_row = GameServer.query.filter_by(short_name="jobunread").first()
            _ur_id, _ur_name = (_ur_row.id, _ur_row.name) if _ur_row else (None, "")
        check("install job (unreadable scan): the POST created a row", _ur_id is not None)
        if _ur_id is not None:
            _ujob, _urow_st, _ur_settled = _ij_wait(_ur_id)
            check("install job (unreadable scan): the job finished before the stubs are handed back",
                  _ur_settled, "job=%r row=%r" % (_ujob.get("status"), _urow_st))
            _ur_msg = _ujob.get("message") or ""
            with app.app_context():
                _ur_done = db.session.get(GameServer, _ur_id)
                _ur_port = _ur_done.port
                _ur_audit = [(a.success, a.detail or "") for a in
                             _TSAudit.query.filter_by(action="install_complete",
                                                      target=_ur_name).all()]
            check("install job (unreadable scan): the panel keeps its own port, as before",
                  _ur_port == 28997, "port=%r" % (_ur_port,))
            check("install job (unreadable scan): ...but does NOT report a clash it never saw",
                  "already uses" not in _ur_msg,
                  "the operator is sent to free a port off a process nobody observed: %r"
                  % (_ur_msg[:220],))
            check("install job (unreadable scan): ...it says it could not read the host",
                  "could not read" in _ur_msg, repr(_ur_msg[:220]))
            check("install job (unreadable scan): ...and the audit log records no clash either",
                  bool(_ur_audit) and all(_s and "clashes with" not in d for _s, d in _ur_audit),
                  "install_complete rows: %r — the trail said this install failed on a port "
                  "clash that was never observed" % (_ur_audit,))
            _ur_opened = sorted({p for call in _ur_calls for p in call})
            check("install job (unreadable scan): ...the unverified port is still not opened",
                  28998 not in _ur_opened,
                  "`ufw allow <port> comment <name>` REPLACES a rule differing only by comment, "
                  "and the panel cannot say this port is free: %s" % (_ur_opened,))
            check("install job (unreadable scan): ...while the ports never in question ARE opened",
                  28997 in _ur_opened and 28999 in _ur_opened,
                  "opened %s — query/rcon were closed over a clash nobody observed"
                  % (_ur_opened,))
            with app.app_context():
                _d = db.session.get(GameServer, _ur_id)
                if _d is not None:
                    db.session.delete(_d); db.session.commit()
            with _install_lock_sm:
                _install_jobs_sm.pop(_ur_id, None)
    finally:
        for (_m, _n), _v in _ur_saved.items():
            setattr(_m, _n, _v)

    # ...and the same read, in the OTHER place the install uses it: the 90-second wait after
    # `start`. That was `gs.port in (_remote_listening_ports(remote) or set())`, so a scan that
    # could not be read became the measured claim "nothing is listening" — thirty times. The
    # `except Exception: really_up = (s_rc == 0)` two lines below shows the author knew about an
    # unreachable host, but it only fires for paramiko, which RAISES; tailscale and local return
    # ("", "…timed out", -1). A running server was therefore committed gs.status="offline" and the
    # operator told "it hasn't opened port X yet", with `install_complete success=False detail=
    # "started; port X not open after 90s"` in the audit log. Here the scan works at step 6 (so
    # the port is adopted — the positive half) and stops answering from `start` onwards.
    _pu_saved, _pu_state = {}, {"started": False}

    def _pu_stub(mod, name, fn):
        _pu_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    def _pu_run_as(remote, user, action, **k):
        if action == "start":
            _pu_state["started"] = True
        return ("", "", 0)

    try:
        _pu_stub(_msmod, "time", _ur_fast)
        _pu_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
        _pu_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
        _pu_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
        _pu_stub(_sm_core, "run_as_game_user", _pu_run_as)
        _pu_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
        _pu_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
        _pu_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
        _pu_stub(_msmod, "_looks_installed", lambda *a, **k: True)
        _pu_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
        _pu_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
        _pu_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
        _pu_stub(_msmod, "install_game_cron", lambda *a, **k: None)
        _pu_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
        _pu_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
        _pu_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
        _pu_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
        _pu_stub(_msmod, "remote_ufw_allow_game_ports", lambda *a, **k: None)
        _pu_stub(_msmod, "_remote_listening_ports",
                 lambda r: (None if _pu_state["started"] else {22}))
        _pu_stub(_msmod, "detect_game_ports",
                 lambda *a, **k: {"game_port": 29002, "open_ports": [29002]})
        _pu_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
        _appmod_ij._remote_listening_ports = lambda r: {22}

        c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                     "server_name": "jobpoll", "port": "29001"},
               follow_redirects=True)
        with app.app_context():
            _pu_row = GameServer.query.filter_by(short_name="jobpoll").first()
            _pu_id = _pu_row.id if _pu_row else None
        check("install job (unreadable poll): the POST created a row", _pu_id is not None)
        if _pu_id is not None:
            _pjob, _prow_st, _pu_settled = _ij_wait(_pu_id)
            check("install job (unreadable poll): the job finished before the stubs are handed back",
                  _pu_settled, "job=%r row=%r" % (_pjob.get("status"), _prow_st))
            _pu_msg = _pjob.get("message") or ""
            with app.app_context():
                _pu_done = db.session.get(GameServer, _pu_id)
                _pu_status, _pu_port = _pu_done.status, _pu_done.port
            check("install job (unreadable poll): a scan that could be READ is still used",
                  _pu_port == 29002,
                  "port=%r — step 6 adopted nothing, so this says the stub, not the fix" % (_pu_port,))
            check("install job (unreadable poll): a start whose port could not be read is not "
                  "written offline",
                  _pu_status == "online",
                  "status=%r — thirty unreadable scans were counted as thirty readings of an "
                  "empty socket table, on a server that started fine (start rc 0)" % (_pu_status,))
            check("install job (unreadable poll): ...and the operator is not told the port is shut",
                  "hasn't opened port" not in _pu_msg, repr(_pu_msg[:220]))
            with app.app_context():
                _d = db.session.get(GameServer, _pu_id)
                if _d is not None:
                    db.session.delete(_d); db.session.commit()
            with _install_lock_sm:
                _install_jobs_sm.pop(_pu_id, None)
    finally:
        for (_m, _n), _v in _pu_saved.items():
            setattr(_m, _n, _v)

    # ── step 4: "couldn't tell" is not "not installed" ──────────────────────────────────────────
    # _looks_installed answers True / False / None, and step 4 tested `is True`, which sent None
    # down the False path. That path is destructive: it wipes /home/<n>/lgsm/tmp and re-runs the
    # 30-minute auto-install twice more, then writes installed=False / status="failed" with "the
    # download may be corrupt or the mirror unreachable" — a diagnosis of a download it never
    # managed to look at. On a Tailscale host the verification read right after a 20 GB download
    # times out without raising, so a fully installed Rust server got ~90 minutes of re-downloading
    # and then a failure. Commit 7d1d64f gave the helper its third state and taught app.py and
    # api.py to branch on it; this caller was missed. Both branches are driven here.
    _lv_saved, _lv_cmds = {}, []

    def _lv_stub(mod, name, fn):
        _lv_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    def _lv_run_command(remote, cmd, **k):
        _lv_cmds.append(cmd)
        return ("", "", 0)

    def _lv_install(short, verdict, port):
        """Run one install with _looks_installed pinned to `verdict`; -> (row state, commands).

        Re-pointed WITHOUT going through _lv_stub: that saves the current value, and by the second
        call the current value is the first call's lambda — restoring it would leave the stub on
        the module for every later check in this file. The real one is saved once, below."""
        del _lv_cmds[:]
        _msmod._looks_installed = lambda *a, **k: verdict
        c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                     "server_name": short, "port": str(port)},
               follow_redirects=True)
        with app.app_context():
            _row = GameServer.query.filter_by(short_name=short).first()
            _rid = _row.id if _row else None
        if _rid is None:
            return None, list(_lv_cmds)
        _ij_wait(_rid, 60)
        with app.app_context():
            _r = db.session.get(GameServer, _rid)
            _state = (_r.status, _r.installed, _r.install_error or "", _r.install_retryable)
            db.session.delete(_r); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_rid, None)
        return _state, list(_lv_cmds)

    try:
        _lv_stub(_msmod, "_looks_installed", _msmod._looks_installed)   # saved once, for restore
        _lv_stub(_msmod, "time", _ur_fast)
        _lv_stub(_sm_core, "run_command", _lv_run_command)
        _lv_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
        _lv_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
        _lv_stub(_sm_core, "run_as_game_user", lambda *a, **k: ("", "", 0))
        _lv_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
        _lv_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
        _lv_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
        _lv_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
        _lv_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
        _lv_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
        _lv_stub(_msmod, "_remote_listening_ports", lambda r: {22})
        _lv_stub(_msmod, "detect_game_ports", lambda *a, **k: {"game_port": 0, "open_ports": []})
        _lv_stub(_msmod, "remote_ufw_allow_game_ports", lambda *a, **k: None)
        _lv_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
        _appmod_ij._remote_listening_ports = lambda r: {22}

        _lv_none, _lv_none_cmds = _lv_install("jobcantsay", None, 29011)
        check("install step 4: a verification that could not be READ does not re-download",
              _lv_none is not None
              and sum(1 for _cmd in _lv_none_cmds if "auto-install" in _cmd) == 1,
              "auto-install ran %r times — up to 90 minutes spent on a host that may already hold "
              "the files" % (sum(1 for _cmd in _lv_none_cmds if "auto-install" in _cmd),))
        check("install step 4: ...and does not wipe the download it never looked at",
              not any("lgsm/tmp" in _cmd for _cmd in _lv_none_cmds),
              "the cached archive is deleted on the strength of a read that failed")
        check("install step 4: ...nor blame a corrupt download it never saw",
              _lv_none is not None and "may be corrupt" not in _lv_none[2],
              repr(_lv_none[2][:200]) if _lv_none else "no row")
        check("install step 4: ...saying it could not read the host, and staying retryable",
              _lv_none is not None and _lv_none[0] == "failed"
              and "could not read the host" in _lv_none[2] and _lv_none[3] is True,
              repr(_lv_none))
        # The positive control, and the branch that must NOT change: a host that answered and
        # said the files are not there really is a failed download — wiped, retried three times,
        # and reported as what it is.
        _lv_no, _lv_no_cmds = _lv_install("jobnofiles", False, 29012)
        check("install step 4: a host that ANSWERED 'not installed' still retries the download",
              sum(1 for _cmd in _lv_no_cmds if "auto-install" in _cmd) == 3,
              "auto-install ran %r times"
              % (sum(1 for _cmd in _lv_no_cmds if "auto-install" in _cmd),))
        check("install step 4: ...still wipes the cached archive between tries",
              any("lgsm/tmp" in _cmd for _cmd in _lv_no_cmds))
        check("install step 4: ...and still reports the corrupt download it did observe",
              _lv_no is not None and _lv_no[0] == "failed" and "may be corrupt" in _lv_no[2],
              repr(_lv_no))
    finally:
        for (_m, _n), _v in _lv_saved.items():
            setattr(_m, _n, _v)

    # ── /api/installs: the progress a corner widget can follow from any page ────────────────────
    # A game-server install runs for five to forty-five minutes, and its only progress row lived on
    # the Game Servers page. Start one from "Install a Server" and you got a toast reading
    # "Progress is shown live below" — below was nothing — and the dashboard then listed the server
    # as installing with no progress of any kind. Nothing answered "is anything installing", so
    # this endpoint does, and install_progress.js renders it wherever you are.
    #
    # The access filter is the part that matters: the socket ping that drives the widget carries no
    # payload precisely because authorization happens HERE.
    import time as _ij_time
    from panel.core.panel_state import _install_jobs as _ij, _install_lock as _il
    with _il:
        _ij[gs_id] = {"status": "running", "step": 3, "total": 8,
                      "step_name": "Installing dependencies", "message": "", "log": [],
                      "started": _ij_time.time() - 42, "updated": _ij_time.time(),
                      "name": "probe-install"}
    try:
        _ins = c.get("/api/installs")
        _ij_rows = (_ins.get_json() or {}).get("installs") or []
        check("installs: a running install is listed", _ins.status_code == 200 and len(_ij_rows) == 1,
              _ins.get_json())
        _row = _ij_rows[0] if _ij_rows else {}
        check("installs: ...with the step, the total and a percentage the widget can draw",
              _row.get("step") == 3 and _row.get("total") == 8 and _row.get("percent") == 37,
              _row)
        check("installs: ...and how long it has been going",
              isinstance(_row.get("elapsed"), int) and _row["elapsed"] >= 40, _row.get("elapsed"))
        # THE security property: a viewer who cannot see the server must not learn its name from
        # this endpoint, or an install would announce every server on the panel to everyone.
        # A user in NO group sees no remotes, so get_user_servers() is empty for them — the same
        # filter the dashboard and the palette use, which is the whole argument for the socket ping
        # that drives the widget carrying no payload of its own.
        with app.app_context():
            _nou = User(username="noaccess-installs",
                        password_hash=auth.hash_password("Str0ng!passw0rd-na"),
                        display_name="No Access", is_superadmin=False, is_active=True)
            db.session.add(_nou); db.session.commit()
            _nou_id = _nou.id
        try:
            _mine_ins = client_as(_nou_id).get("/api/installs")
            check("installs: a user without access to that server is told about NO install",
                  _mine_ins.status_code == 200
                  and not ((_mine_ins.get_json() or {}).get("installs") or []),
                  _mine_ins.get_json())
        finally:
            with app.app_context():
                _d = db.session.get(User, _nou_id)
                if _d:
                    db.session.delete(_d); db.session.commit()
        # A finished job is not an install in progress — the widget settles those through the
        # per-server endpoint, and leaving them here would pin a card open forever.
        with _il:
            _ij[gs_id]["status"] = "done"
        check("installs: a finished job drops out of the live list",
              not ((c.get("/api/installs").get_json() or {}).get("installs") or []))
    finally:
        with _il:
            _ij.pop(gs_id, None)


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

    # ── ...and logout must not CLAIM a revocation it did not make ──────────────────────────────
    # The handler's stated purpose is server-side invalidation — "clearing the client's copy alone
    # wouldn't stop a copy captured earlier from being replayed" — and the except swallowed the one
    # statement that achieves it. After the rollback the UserSession row was intact and auth_epoch
    # unchanged, so every cookie valid before the request was still valid after it, and the page
    # said "You have been logged out." with nothing logged for an operator to notice. A momentary
    # SQLite lock (a concurrent backup, a WAL checkpoint during a monitor sweep) is exactly this
    # shape, so it is driven that way: the commits raise, the rest of the request is real.
    import panel.routes.auth_routes as _lo_mod

    class _FlakyDB:
        """Stands in for the route module's own `db`: the first `fails` commits raise, the rest
        are the real ones. Only the logout body reaches this — log_action holds its own import."""

        def __init__(self, real, fails):
            self._real, self._left = real, fails

        @property
        def session(self):
            return self

        def commit(self):
            if self._left > 0:
                self._left -= 1
                raise RuntimeError("database is locked (simulated)")
            return self._real.session.commit()

        def rollback(self):
            return self._real.session.rollback()

    _lo_real_db = _lo_mod.db
    _lo_name, _lo_pw = "smoke_logout", "Str0ng!passw0rd"
    with app.app_context():
        _lo_u = User(username=_lo_name, password_hash=auth.hash_password(_lo_pw),
                     display_name=_lo_name, is_superadmin=False, is_active=True)
        db.session.add(_lo_u)
        db.session.commit()
        _lo_uid = _lo_u.id
    try:
        # (a) the row delete fails, the auth_epoch fallback lands — the revoke still happens, so
        #     "You have been logged out." is true and stays.
        _lo_a = app.test_client()
        _lo_a.post("/login", data={"username": _lo_name, "password": _lo_pw, "remember": "on"})
        _lo_thief = _clone_cookies(_lo_a)
        check("logout retry: the cloned cookie works before the sign-out (positive control)",
              _lo_thief.get("/").status_code == 200,
              "the login did not take, so the checks below would prove nothing")
        _lo_mod.db = _FlakyDB(_lo_real_db, 1)
        _lo_body_a = _lo_a.post("/logout", follow_redirects=True).get_data(as_text=True)
        _lo_mod.db = _lo_real_db
        check("logout: a failed revoke is retried, and the cookie really is dead afterwards",
              _lo_thief.get("/").status_code != 200,
              "the session outlived a sign-out the user was told had happened")
        check("logout: ...and that user is still told plainly that they were logged out",
              "could not revoke" not in _lo_body_a, _lo_body_a[:200])
        # (b) both attempts fail: say so, rather than asserting the revocation anyway.
        _lo_b = app.test_client()
        _lo_b.post("/login", data={"username": _lo_name, "password": _lo_pw, "remember": "on"})
        _lo_mod.db = _FlakyDB(_lo_real_db, 5)
        _lo_body_b = _lo_b.post("/logout", follow_redirects=True).get_data(as_text=True)
        _lo_mod.db = _lo_real_db
        check("logout: a revoke that could NOT be made is not reported as one that was",
              "could not revoke" in _lo_body_b,
              "the page claimed the session was revoked after both attempts failed")
    finally:
        _lo_mod.db = _lo_real_db
        with app.app_context():
            from panel.db.models import UserSession as _LoSess
            # (b) deliberately leaves its registry row behind — that IS the defect being driven —
            # so clear it by hand rather than orphaning it on a deleted user_id.
            _LoSess.query.filter_by(user_id=_lo_uid).delete()
            _lo_row = db.session.get(User, _lo_uid)
            if _lo_row is not None:
                db.session.delete(_lo_row)
            db.session.commit()

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

    # ...and a wrong six-digit code does NOT try the backup codes. Each try is a cost-12 bcrypt
    # per stored code (~2s for eight), for an entry that cannot match: anyone holding one password
    # could spend that on every wrong TOTP they submitted.
    import bcrypt as _bc_mod
    from app import _LOGIN_FAILS as _bc_fails
    _bc_real = _bc_mod.checkpw
    _bc_calls = []

    def _bc_count(*a):
        _bc_calls.append(1)
        return _bc_real(*a)
    b4 = app.test_client()
    b4.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
    _bc_mod.checkpw = _bc_count
    try:
        b4.post("/login", data={"totp_code": "123456"})
        _bc_totp = len(_bc_calls)
        b4.post("/login", data={"totp_code": "zzzzz-zzzzz"})
        _bc_shaped = len(_bc_calls) - _bc_totp
    finally:
        _bc_mod.checkpw = _bc_real
        _bc_fails.clear()      # two deliberate failures: don't leave this IP nearer the lockout
    check("2FA: (control) a backup-shaped wrong code does try the stored backup codes",
          _bc_shaped >= 1, "no bcrypt compare ran — the check below proves nothing")
    check("2FA: a wrong six-digit code does not run a bcrypt per backup code",
          _bc_totp == 0, "%d bcrypt compares for a mistyped TOTP" % _bc_totp)

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

    # ── ...and the code that ENROLS 2FA is spent too ─────────────────────────────────────────
    # Three routes in this panel consume a live authenticator code: login step 2, the password
    # change, and enrolment. The first two switched to verify_totp_STEP and record the step they
    # used, precisely so an observed code cannot be replayed for the rest of its ~90s window.
    # Enrolment was missed by that audit and still asked the yes/no question — and last_totp_step
    # defaults to 0, so the very code that turned 2FA on was step S against a guard of 0, and it
    # still logged the account in.
    _en_name = "smoke_2fa_enrol"
    with app.app_context():
        _en = User(username=_en_name, password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name=_en_name, is_superadmin=False, is_active=True)
        db.session.add(_en); db.session.commit()
        _en_id = _en.id
    try:
        _enc = client_as(_en_id)
        _enc.get("/account/2fa/enable")                    # seeds the pending secret in-session
        with _enc.session_transaction() as _sess:
            _en_in_cookie = _sess.get("_2fa_setup_secret") or ""
        from panel.core.config import decrypt_secret as _en_dec
        _en_secret = _en_dec(_en_in_cookie)
        check("2FA enrol: the page issues a pending secret", bool(_en_secret))
        # Flask's session is a SIGNED cookie, readable by anyone who holds it, and on success this
        # value becomes the account's permanent TOTP seed. A Set-Cookie captured during enrolment
        # handed over a second factor that survives password changes and sign-out-everywhere.
        check("2FA enrol: the pending secret is not in the session cookie in the clear",
              _en_secret and _en_secret not in _en_in_cookie,
              "the cookie carries the TOTP seed as plaintext")
        _en_code = _po.TOTP(_en_secret).now()
        # ── ...and enrolling needs the account holder's PASSWORD ───────────────────────────────
        # /account/2fa/enable carried @login_required and nothing else, while its mirror
        # /account/2fa/disable demands the password AND a live code and reasons in its docstring
        # about which direction is more dangerous. That was backwards: enrolment INSTALLS a factor
        # the holder does not have. Anyone in front of a signed-in session — an unlocked
        # workstation, a shared browser profile, a cookie captured before a password rotation —
        # could scan the QR with their own authenticator, submit the code, and take the account
        # ONE-WAY: the backup codes are rendered once, to them, and disable then refuses the real
        # owner because it wants the very code only the intruder holds.
        _en_bad = _enc.post("/account/2fa/enable",
                            data={"password": "wrong-password", "totp_code": _en_code})
        with app.app_context():
            check("2FA enrol: a valid code with the WRONG password does not enable 2FA",
                  not db.session.get(User, _en_id).totp_enabled,
                  "status=%s — a live session alone installed a second factor"
                  % _en_bad.status_code)
        _en_none = _enc.post("/account/2fa/enable", data={"totp_code": _en_code})
        with app.app_context():
            check("2FA enrol: ...nor does one with no password at all",
                  not db.session.get(User, _en_id).totp_enabled,
                  "status=%s" % _en_none.status_code)
        # Positive control: the same code, with the right password, still enrols — so the two
        # refusals above are a gate and not a broken route.
        _en_r = _enc.post("/account/2fa/enable",
                          data={"password": "Str0ng!passw0rd", "totp_code": _en_code})
        with app.app_context():
            _en_row = db.session.get(User, _en_id)
            check("2FA enrol: a valid code enables two-factor",
                  bool(_en_row.totp_enabled), "status=%s" % _en_r.status_code)
            check("2FA enrol: ...and the step it used is RECORDED, like the other two routes do",
                  (_en_row.last_totp_step or 0) > 0,
                  "last_totp_step=%r — the enrolling code is still unspent"
                  % _en_row.last_totp_step)
        # The property that matters: that same code must no longer log the account in.
        _en_t = app.test_client()
        _en_t.post("/login", data={"username": _en_name, "password": "Str0ng!passw0rd"})
        _en_login = _en_t.post("/login", data={"totp_code": _en_code})
        check("2FA enrol: the enrolling code cannot then be REPLAYED at login",
              _en_login.status_code != 302,
              "the code that turned 2FA on also signed in (status %s)" % _en_login.status_code)
        # ...and a fresh code still works, so the refusal above is single-use and not a break.
        _en_t2 = app.test_client()
        _en_t2.post("/login", data={"username": _en_name, "password": "Str0ng!passw0rd"})
        with app.app_context():
            db.session.get(User, _en_id).last_totp_step = 0     # simulate the next step arriving
            db.session.commit()
        _en_ok = _en_t2.post("/login", data={"totp_code": _po.TOTP(_en_secret).now()})
        check("2FA enrol: ...while an unspent code still signs in", _en_ok.status_code == 302,
              "got %s — the refusal above is blocking valid codes too" % _en_ok.status_code)
    finally:
        with app.app_context():
            _row = db.session.get(User, _en_id)
            if _row is not None:
                db.session.delete(_row); db.session.commit()

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

    # ...and it cannot be stepped around with a per-request X-Real-IP.
    #
    # The throttle keys on client_ip() and has no second dimension, so whoever chooses that string
    # chooses whether the throttle exists. The test client connects from loopback, which is the
    # Tailscale Serve shape exactly: Serve proxies to 127.0.0.1, so `behind_proxy` is True with no
    # configuration at all. Serve sets the X-Forwarded-* trio and does NOT set or strip X-Real-IP,
    # so a client-supplied one arrived verbatim — and client_ip() used to prefer it. Below, the
    # proxy-set header is constant (one real client) while the client-supplied one rotates: the
    # lockout has to follow the proxy's value.
    #
    # "Loopback" means Serve only when the socket is tailscaled's, i.e. root-owned; the test client
    # is not, so these two blocks declare that shape explicitly. The block after them drives the
    # other shape: a local account dialling 127.0.0.1 itself.
    from panel.security import auth as _xff_auth
    _xff_saved = _xff_auth._loopback_proxy_trusted
    _xff_auth._loopback_proxy_trusted = lambda: True
    _LOGIN_FAILS.clear()
    lc2 = app.test_client()
    _locked_hdr = False
    for _i in range(LOGIN_MAX_FAILS + 2):
        lr = lc2.post("/login", data={"username": "nobody_lockout2", "password": "wrong"},
                      headers={"X-Forwarded-For": "198.51.100.7",
                               "X-Real-IP": "203.0.113.%d" % _i})
        if b"Too many failed attempts" in lr.data:
            _locked_hdr = True
            break
    check("login: a rotating X-Real-IP does not mint a fresh throttle bucket per request",
          _locked_hdr, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
    # positive control: the throttle really is keyed on the proxy-set header, so a rotating
    # X-Forwarded-For (a proxy that appends, with the client's own copy to its LEFT) is still one
    # bucket per real peer rather than one per forged hop.
    _LOGIN_FAILS.clear()
    lc3 = app.test_client()
    _locked_xff = False
    for _i in range(LOGIN_MAX_FAILS + 2):
        lr = lc3.post("/login", data={"username": "nobody_lockout3", "password": "wrong"},
                      headers={"X-Forwarded-For": "203.0.113.%d, 198.51.100.8" % _i})
        if b"Too many failed attempts" in lr.data:
            _locked_xff = True
            break
    check("login: only the LAST X-Forwarded-For hop keys the throttle, so forged hops don't help",
          _locked_xff, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))

    # A local account on the panel host (a game-server user with a shell) dials loopback too.
    # Believing its X-Forwarded-For gave it a fresh throttle bucket per attempt — unlimited
    # password guessing — and let it name any address for fail2ban and the auto-block to ban.
    def _rotating_xff_locks():
        _LOGIN_FAILS.clear()
        _c = app.test_client()
        for _j in range(LOGIN_MAX_FAILS + 2):
            _r = _c.post("/login", data={"username": "nobody_lockout4", "password": "wrong"},
                         headers={"X-Forwarded-For": "198.51.100.%d" % (_j + 1)})
            if b"Too many failed attempts" in _r.data:
                return True
        return False

    try:
        _xff_auth._loopback_proxy_trusted = lambda: True
        _serve_locks = _rotating_xff_locks()
    finally:
        _xff_auth._loopback_proxy_trusted = _xff_saved     # the REAL check from here on
    _local_locks = _rotating_xff_locks()
    check("login: a NON-root local caller rotating X-Forwarded-For is still throttled",
          _local_locks, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
    check("login: ...while through Serve each forwarded client keeps its own bucket (control)",
          not _serve_locks, "Serve's distinct clients were pooled into one bucket")

    # An IPv6 client holds a whole /64. Keyed per ADDRESS, rotating the interface id gave a fresh
    # bucket every attempt; the throttle now counts the /64.
    _LOGIN_FAILS.clear()
    _v6 = app.test_client()
    _v6_locked = False
    for _j in range(LOGIN_MAX_FAILS + 2):
        _r = _v6.post("/login", data={"username": "nobody_lockout5", "password": "wrong"},
                      environ_overrides={"REMOTE_ADDR": "2001:db8:5:6::%x" % (_j + 1)})
        if b"Too many failed attempts" in _r.data:
            _v6_locked = True
            break
    check("login: rotating addresses inside one IPv6 /64 is still throttled", _v6_locked,
          "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
    _r = _v6.post("/login", data={"username": "nobody_lockout5", "password": "wrong"},
                  environ_overrides={"REMOTE_ADDR": "2001:db8:5:7::1"})
    check("login: ...while the neighbouring /64 is its own bucket (control)",
          b"Too many failed attempts" not in _r.data, "a different /64 was blocked too")
    _LOGIN_FAILS.clear()

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

        # ── the message must not assert a checkpoint nobody read ────────────────────────────────
        # `PRAGMA wal_checkpoint(TRUNCATE)` does not raise when it cannot complete: it returns
        # (busy, log, checkpointed) with busy = 1, which is exactly what TRUNCATE does while any
        # other connection is still reading. The row was discarded, and optimize_database went on
        # to say "Checkpointed the WAL and refreshed stats" — in the branch that is reached BECAUSE
        # the database was too busy for VACUUM, i.e. the state in which the checkpoint is most
        # likely to have been refused too. An operator chasing a growing panel.db was told the
        # cheap half had been done while the wal_size beside it never moved.
        import panel.db.models as _dbm
        _rm_real = _dbm._run_maintenance(str(DB_PATH))
        check("optimize: _run_maintenance reports the checkpoint AND the vacuum",
              isinstance(_rm_real, tuple) and len(_rm_real) == 2
              and _rm_real[0] in (True, False, None), "got %r" % (_rm_real,))
        _rm_saved = _dbm._run_maintenance
        try:
            _dbm._run_maintenance = lambda p: (False, False)      # checkpoint busy, VACUUM busy
            _ok_b, _msg_b, _ = _dbm.optimize_database()
            check("optimize: a REFUSED WAL checkpoint is not reported as one that happened",
                  "Checkpointed the WAL" not in _msg_b, _msg_b)
            check("optimize: ...and the operator is still told VACUUM was deferred",
                  "deferred" in _msg_b, _msg_b)
            # Positive control: a checkpoint that DID complete is still reported as one, so the
            # check above cannot pass by the message simply never mentioning the WAL.
            _dbm._run_maintenance = lambda p: (True, False)
            _ok_t, _msg_t, _ = _dbm.optimize_database()
            check("optimize: a checkpoint that completed is still reported as completed",
                  "Checkpointed the WAL" in _msg_t, _msg_t)
            # ...and a pragma that returned nothing to read claims neither outcome.
            _dbm._run_maintenance = lambda p: (None, False)
            _ok_n, _msg_n, _ = _dbm.optimize_database()
            check("optimize: an unreadable checkpoint result claims neither outcome",
                  "Checkpointed the WAL" not in _msg_n and _msg_n != _msg_b, _msg_n)
        finally:
            _dbm._run_maintenance = _rm_saved

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

        # game_server.content_games / install_error / install_retryable: the same for the install
        # failure and GMod-content columns. A column the MODEL declares and the TABLE lacks is a
        # 500 on every page that touches that row — and it only ever happens on an UPGRADED
        # install, never on the fresh one a developer tests with.
        def _gcols():
            return {col["name"] for col in _inspect(db.engine).get_columns("game_server")}

        for _col in ("content_games", "install_error", "install_retryable"):
            _gdropped = False
            try:
                db.session.execute(_t("ALTER TABLE game_server DROP COLUMN %s" % _col))
                db.session.commit()
                _gdropped = True
            except Exception:
                db.session.rollback()     # SQLite too old to DROP COLUMN
            if _gdropped:
                check("migrate: a legacy DB is missing game_server.%s" % _col,
                      _col not in _gcols())
                _run_light_migrations()
                check("migrate: ...and the update adds it back", _col in _gcols(),
                      "an upgraded install 500s on every page that reads this row")

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

    # ── A download the panel could not READ must not be reported as a deleted file ───────────
    # stat_path answers None for three different things: a path that escapes the home directory, a
    # path that is not there, and a read that never ran — on the non-raising transports (tailscale,
    # local) a failed read returns ("", "…timed out", -1), so its `parts` is empty and it returns
    # None exactly as it does for a file that really was deleted. The route's "Couldn't reach"
    # branch sits behind an `except`, which only paramiko reaches. So an operator whose link
    # flapped while downloading server.cfg was told the file was gone, and went looking for what
    # deleted it — or restored a backup over a newer copy.
    import panel.routes.server_files as _dl_mod
    _dl_saved = (_dl_mod.stat_path, _dl_mod.stream_path)
    try:
        _dl_mod.stat_path = lambda *a, **k: None
        c.get("/server/%d/download?path=cfg/server.cfg" % gs_id)
        with c.session_transaction() as _dl_s:
            _dl_msgs = [_m for _cat, _m in (_dl_s.get("_flashes") or [])]
            _dl_s.pop("_flashes", None)
        check("download: (setup) the refusal flashed something to read",
              bool(_dl_msgs), "no flash at all — the checks below would pass vacuously")
        check("download: a path the panel could not read is not called a deleted file",
              not any("there any more" in _m for _m in _dl_msgs),
              "flashed %r — it states a deletion the route never checked for" % (_dl_msgs,))
        check("download: ...and the refusal names the host not answering as a possibility",
              any("moved or deleted" in _m for _m in _dl_msgs),
              "flashed %r" % (_dl_msgs,))
        # The control: a stat that DID answer still serves the file, so the refusal above is the
        # unreadable case and not this route turning every download down.
        _dl_mod.stat_path = lambda *a, **k: {"type": "f", "size": 4, "name": "server.cfg",
                                             "rel": "cfg/server.cfg"}
        _dl_mod.stream_path = lambda *a, **k: iter([b"data"])
        _dl_ok = c.get("/server/%d/download?path=cfg/server.cfg" % gs_id)
        check("download: (control) a file the panel could stat is still served",
              _dl_ok.status_code == 200, "got %d" % _dl_ok.status_code)
    finally:
        (_dl_mod.stat_path, _dl_mod.stream_path) = _dl_saved
        with c.session_transaction() as _dl_s:
            _dl_s.pop("_flashes", None)

    # ── the file-save API must not write an empty file for a body with no text in it ─────────────
    # `data.get("content", "")` turned a missing key — an API script's typo like "contents" — into
    # "", and write_file does `(content or "").encode()`, so null/0/false/[] did the same: the
    # target was truncated to 0 bytes and the answer was {"success": true, "message": "Saved"}.
    _fs_writes = []
    _fs_saved = _dl_mod.write_file
    try:
        _dl_mod.write_file = lambda srv, user, rel, content: (_fs_writes.append((rel, content)), (True, ""))[1]
        for _fs_body in ({"path": "cfg/server.cfg", "contents": "typo"}, {"path": "cfg/server.cfg", "content": None},
                         {"path": "cfg/server.cfg", "content": 0}, {"path": "cfg/server.cfg", "content": []}):
            _fs_r = c.post("/api/server/%d/file" % gs_id, json=_fs_body)
            check("file save: %r is refused, not written as an empty file" % (sorted(_fs_body.items()),),
                  _fs_r.status_code == 400 and not _fs_writes
                  and (_fs_r.get_json() or {}).get("success") is False,
                  "status %d, writes %r" % (_fs_r.status_code, _fs_writes))
            del _fs_writes[:]
        # Positive control: an intentionally EMPTY file is still text, and is saved.
        _fs_ok = c.post("/api/server/%d/file" % gs_id, json={"path": "cfg/empty.cfg", "content": ""})
        check("file save: an intentionally empty file (content \"\") is still saved",
              _fs_ok.status_code == 200 and _fs_writes == [("cfg/empty.cfg", "")],
              "status %d, writes %r" % (_fs_ok.status_code, _fs_writes))
    finally:
        _dl_mod.write_file = _fs_saved

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

    # ── turning 2FA OFF needs the second factor, not just the password ────────────────────────
    # /account/2fa/disable asked for the password alone — a weaker gate than the one on CHANGING
    # the password in the same file, which demands the password AND a live code. That is
    # backwards: removing the second factor is the change that makes every later login easier.
    # A session someone else is sitting in front of, plus a password they already knew, could
    # strip it. The route had no test entering it at all.
    from panel.db.models import User as _TU

    with app.app_context():
        _td_codes = auth.generate_backup_codes()
        _td_secret = auth.generate_totp_secret()
        _td = _TU(username="tfa_disable", password_hash=auth.hash_password("Str0ng!passw0rd"),
                  display_name="2FA off", is_superadmin=False, is_active=True,
                  totp_enabled=True, totp_secret=encrypt_secret(_td_secret))
        _td.set_backup_codes(_td_codes)
        db.session.add(_td)
        db.session.commit()
        _td_id = _td.id

    def _td_still_on():
        with app.app_context():
            _row = db.session.get(_TU, _td_id)
            return bool(_row.totp_enabled and _row.totp_secret)

    _tdc = client_as(_td_id)
    _r = _tdc.post("/account/2fa/disable", data={"password": "Str0ng!passw0rd"},
                   follow_redirects=True)
    check("2fa disable: the password alone does NOT turn it off", _td_still_on(),
          "2FA was removed on a password a borrowed session already had")
    check("2fa disable: ...and the page says a code is needed",
          b"code didn&#39;t match" in _r.data or b"code didn't match" in _r.data,
          "no reason shown: %r" % _r.data[-200:])

    _r = _tdc.post("/account/2fa/disable",
                   data={"password": "wrong-password", "totp_code": _td_codes[1]},
                   follow_redirects=True)
    check("2fa disable: ...nor does a code with the wrong password", _td_still_on())
    with app.app_context():
        # Counted, not re-checked: use_backup_code CONSUMES, so asking "is it still valid" would
        # spend it. The password is verified first precisely so a one-time code is never burnt by
        # a request that fails for another reason.
        check("2fa disable: ...and that backup code was NOT spent on the failed attempt",
              db.session.get(_TU, _td_id).backup_codes_remaining == len(_td_codes),
              "%d of %d codes left — a one-time code was consumed by a request that failed for "
              "another reason" % (db.session.get(_TU, _td_id).backup_codes_remaining,
                                  len(_td_codes)))

    # The real thing: password + a backup code (what the card tells people to use when the
    # authenticator is gone).
    _r = _tdc.post("/account/2fa/disable",
                   data={"password": "Str0ng!passw0rd", "totp_code": _td_codes[0]},
                   follow_redirects=True)
    check("2fa disable: password + a valid backup code DOES turn it off (positive control)",
          not _td_still_on(),
          "the route now refuses everything, which would make the checks above meaningless")
    with app.app_context():
        _row = db.session.get(_TU, _td_id)
        check("2fa disable: ...and its backup codes are cleared with it",
              not (_row.backup_codes or ""), "codes left behind: %r" % (_row.backup_codes or "")[:40])

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

    # ...and it must not sign THIS device out before the password can be read. The reset bumps
    # auth_epoch, which is exactly what makes every other cookie for the account stop matching —
    # and it stopped matching the one that made the request too. panel.js runs
    # refreshSection('#users-list') BEFORE showCredential(), so that next request arrived
    # milliseconds later, was answered 401 + X-Auth-Required, and sessionExpired() replaced the tab
    # with /login while the generated password (only its hash is stored) was still behind the
    # modal. On a single-superadmin install that ends at manage.py reset-password.
    #
    # Driven through a REAL epoch-tagged cookie: client_as() injects a bare "<id>", which
    # load_user's legacy branch accepts on the id alone, so this bug is invisible to it.
    def _epoch_client(uid):
        """A client holding the cookie flask-login actually issues: '<id>:<epoch>:<sid>'."""
        import secrets as _ec_secrets
        from panel.db.models import UserSession as _ECUS
        with app.app_context():
            _u = db.session.get(User, uid)
            _sid = _ec_secrets.token_urlsafe(24)
            db.session.add(_ECUS(user_id=uid, sid=_sid, remember=False, ip="", user_agent=""))
            db.session.commit()
            _val = "%d:%d:%s" % (uid, _u.auth_epoch or 0, _sid)
        _cl = app.test_client()
        with _cl.session_transaction() as _s:
            _s["_user_id"] = _val
            _s["_fresh"] = True
        return _cl

    _sr_this = _epoch_client(_sr_id)      # the browser doing the reset
    _sr_other = _epoch_client(_sr_id)     # the same account signed in somewhere else
    check("self-reset: (premise) an epoch-tagged cookie is accepted before the reset",
          _sr_this.get("/users").status_code == 200,
          "the fixture client could not load /users, so the checks below prove nothing")
    _selfrst2 = _sr_this.post(
        "/users/%d/edit" % _sr_id,
        data={"display_name": "Self Reset", "is_active": "on", "is_superadmin": "on",
              "reset_password": "on"},
        headers={"X-Requested-With": "XMLHttpRequest"})
    _sj2 = _selfrst2.get_json() or {}
    check("self-reset: ...still hands back a generated password (positive control)",
          bool((_sj2.get("credential") or {}).get("password")), str(_sj2)[:120])
    # The request panel.js fires immediately afterwards, from the same browser.
    _sr_after = _sr_this.get("/users", headers={"X-Requested-With": "XMLHttpRequest"})
    check("self-reset: ...and does not sign this device out before the password can be read",
          _sr_after.status_code == 200 and "X-Auth-Required" not in _sr_after.headers,
          "the refresh panel.js fires after the reset answered %d %r — the credential modal opens "
          "and the tab navigates to /login" % (_sr_after.status_code,
                                               _sr_after.headers.get("X-Auth-Required")))
    # ...while every OTHER session for that account really is revoked, which is what the bump is for.
    _sr_elsewhere = _sr_other.get("/users", headers={"X-Requested-With": "XMLHttpRequest"})
    check("self-reset: ...while the account's other devices ARE signed out",
          _sr_elsewhere.status_code in (302, 401),
          "a reset left another device signed in (%d) — the epoch bump revoked nothing"
          % _sr_elsewhere.status_code)

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
    # ...for someone who may USE it. The row's three action buttons and both bulk bars hung off a
    # single can_control flag that was the UNION of start/stop/restart, and the Files button hung
    # off nothing at all — so a moderator holding only start_server was shown Stop and Restart on
    # every row, and every viewer got a Files button that round-trips to a red "You don't have
    # permission to manage server files."  Driven as a REAL restricted user, because a superadmin
    # satisfies every gate and would prove nothing; and asserting the button that must be THERE as
    # well as the ones that must not, because a route that computes the flags and forgets to pass
    # them to render_template leaves Jinja an Undefined that is silently falsy — which is exactly
    # what happened, and an absence-only check would have called that a pass.
    with app.app_context():
        _sog = Group(name="smoke-startonly")
        _sog.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER])
        _sog.game_servers.append(db.session.get(GameServer, gs_id))
        db.session.add(_sog)
        db.session.flush()
        _sou = User(username="startonly", password_hash=auth.hash_password("Str0ng!passw0rd"),
                    is_superadmin=False, is_active=True)
        _sou.groups.append(_sog)
        db.session.add(_sou)
        db.session.commit()
        _sou_id = _sou.id
    _sod = client_as(_sou_id).get("/").get_data(as_text=True)
    check("dashboard perms: the start-only user's row is rendered, so the checks below see one",
          'data-action="doAction"' in _sod,
          "no action buttons at all — every absence check below would pass vacuously")
    check("dashboard perms: ...and carries the Start button they hold",
          '[%d, "start", "@self"]' % gs_id in _sod, "start_server granted, no Start button")
    check("dashboard perms: ...but not Restart",
          '[%d, "restart", "@self"]' % gs_id not in _sod, "Restart offered without the permission")
    check("dashboard perms: ...nor Stop",
          '[%d, "stop", "@self"]' % gs_id not in _sod, "Stop offered without the permission")
    check("dashboard perms: the bulk bar offers Start", "'[\"start\"]'" in _sod,
          "the bulk bar dropped the one action they can run")
    check("dashboard perms: ...and not bulk Stop", "'[\"stop\"]'" not in _sod,
          "a bulk Stop across a tag group fails wholesale with Permission denied")
    check("dashboard perms: ...and no Files & Config button",
          "/server/%d/files" % gs_id not in _sod,
          "server_files is MANAGE_SERVERS; the button 403s for this user")
    _sof = client_as(_sou_id).get("/server/%d/files" % gs_id, follow_redirects=False)
    check("dashboard perms: ...because that route refuses them, so the absence was honest",
          _sof.status_code in (403, 302, 401), "status=%d" % _sof.status_code)
    # The other way in was the detail page's tab bar, which is the SAME permission
    # (_can_manage_files) and was equally unconditional — so gating only the dashboard row would
    # have moved the dead end rather than closed it. A superadmin must still see both, or the gate
    # is just a deletion.
    _sodet = client_as(_sou_id).get("/server/%d" % gs_id)
    check("dashboard perms: the detail page renders for the start-only user",
          _sodet.status_code == 200 and 'data-mtab-btn="console"' in
          _sodet.get_data(as_text=True), "status=%d" % _sodet.status_code)
    check("dashboard perms: ...and its Files & Config TAB is gone too",
          "/server/%d/files" % gs_id not in _sodet.get_data(as_text=True),
          "the tab bar still offers a page that flashes a permission error")
    _sadet = c.get("/server/%d" % gs_id).get_data(as_text=True)
    check("dashboard perms: ...while a superadmin still has that tab",
          "/server/%d/files" % gs_id in _sadet, "the gate removed it for everyone")
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
    # An un-installed server has nothing to start, even for an admin. Guarded, because
    # `all(... for e in <empty>)` is True: with no un-installed server in the fixture this check
    # would examine nothing and pass while the filter it tests was gone. The view-only check above
    # was found vacuous exactly this way.
    _pj_uninst = [e for e in _pj if not e.get("installed")]
    check("palette: the fixture HAS an un-installed server, so the next check examines one",
          len(_pj_uninst) >= 1, "no un-installed entry — the next check would pass vacuously")
    check("palette: an un-installed server carries no verbs",
          _pj_uninst and all(not (e.get("actions") or []) for e in _pj_uninst),
          str([(e["name"], e.get("actions")) for e in _pj_uninst])[:200])
    # And the endpoint's answer must agree with the one the ACTION route enforces, or the palette
    # is offering a button that 403s.
    _act_denied = client_as(_viewer_id).post("/api/server/%d/action" % gs_id,
                                             json={"action": "start"},
                                             headers={"X-Requested-With": "XMLHttpRequest"})
    check("palette: the action route refuses that same user, so the empty list was honest",
          _act_denied.status_code in (403, 302, 401),
          "status=%d" % _act_denied.status_code)

    # Bulk Update for a group holding update_server alone. The bar, the row checkboxes and
    # select-all were all behind can_control (start/stop/restart), so the Update button the bar
    # gates for exactly this user could never appear — they updated servers one page at a time.
    _vo_dash = client_as(_viewer_id).get("/").get_data(as_text=True)
    check("dashboard: a view-only user gets no bulk selection (the gate still exists)",
          'class="form-check-input srv-check"' not in _vo_dash and "bulk-update-btn" not in _vo_dash,
          "row checkboxes or the Update button rendered for a user who can do none of it")
    with app.app_context():
        Group.query.filter_by(name="smoke-viewonly").first().set_permissions(
            [auth.VIEW_SERVERS, auth.UPDATE_SERVER])
        db.session.commit()
    try:
        _up_dash = client_as(_viewer_id).get("/").get_data(as_text=True)
        check("dashboard: update_server alone is enough to select servers and bulk-Update them",
              'class="form-check-input srv-check"' in _up_dash and "bulk-update-btn" in _up_dash
              and "srv-check-all" in _up_dash,
              "checkboxes=%s select-all=%s update-button=%s — no way to select, so no bulk Update"
              % ('class="form-check-input srv-check"' in _up_dash, "srv-check-all" in _up_dash,
                 "bulk-update-btn" in _up_dash))
    finally:
        with app.app_context():
            Group.query.filter_by(name="smoke-viewonly").first().set_permissions(
                [auth.VIEW_SERVERS])
            db.session.commit()

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
    # The dashboard's empty state speaks for what THIS user can see. For an account with no host
    # or server grant `servers` is [], however many the install runs, and it was told "No game
    # servers are configured yet" — a claim about the install made to someone who sees none of it.
    _ng_dash = client_as(_noinst_id).get("/")
    _ng_html = _ng_dash.get_data(as_text=True)
    check("dashboard: a user with no grants is told nothing is shared with them, not that the "
          "install has no servers",
          _ng_dash.status_code == 200 and "No game servers have been shared with you yet." in _ng_html
          and "No game servers are configured yet." not in _ng_html,
          "status=%d shared-copy=%s configured-copy=%s"
          % (_ng_dash.status_code, "shared with you" in _ng_html,
             "are configured yet" in _ng_html))
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
    # The fixture host is a blackholed 192.0.2.x address, so the scan does not run — and an empty
    # scan is no longer reported as "no servers found". This check used to assert that old
    # behaviour, which is the bug: discover_linuxgsm_servers returns [] both for "nothing here"
    # and for "never ran", so the card printed a green tick about a host it had not read.
    dsc = c.get("/api/remote/%d/discover" % remote_id)
    check("discover: an unreachable host is reported as unread, not as having no servers",
          dsc.status_code == 200 and "error" in (dsc.get_json() or {})
          and "servers" not in (dsc.get_json() or {}),
          "got %d %s" % (dsc.status_code, str(dsc.get_json())[:120]))
    # ...and with the host answering, the list is a list again — the control that stops the check
    # above passing on a route that simply refuses everything.
    import panel.routes.discover as _dscmod
    _dsc_saved = _dscmod.run_command
    try:
        _dscmod.run_command = lambda r, cmd, **k: (_dscmod._PROBE_MARKER, "", 0)
        dsc_ok = c.get("/api/remote/%d/discover" % remote_id)
        check("discover: superadmin gets a servers list when the host answers",
              dsc_ok.status_code == 200
              and isinstance((dsc_ok.get_json() or {}).get("servers"), list),
              "got %d %s" % (dsc_ok.status_code, str(dsc_ok.get_json())[:120]))
    finally:
        _dscmod.run_command = _dsc_saved
    dsc = dsc_ok
    imp_empty = c.post("/api/remote/%d/import" % remote_id, json={"servers": []})
    check("import: empty selection -> 400", imp_empty.status_code == 400)
    # Import validates each entry like a fresh install: a bad username or unknown game is
    # skipped (so an imported short_name can never carry shell metacharacters); a valid one is added.
    # Discovery is stubbed, because import now re-SCANS and accepts only what the scan reports —
    # see the "root" check below for what that closes.
    from panel.routes import discover as _imp_mod
    _imp_orig = _imp_mod.discover_linuxgsm_servers
    try:
        _imp_mod.discover_linuxgsm_servers = lambda _s: [
            {"user": "importedcs", "lgsm_name": "csgoserver", "port": 27015,
             "backups": 0, "mods": 0, "cron": 0, "autostart": False}]
        imp = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
            {"user": "importedcs", "game_type": "csgo", "port": 27015},
            {"user": "BAD NAME", "game_type": "csgo", "port": 1},
            {"user": "okuser", "game_type": "notarealgame", "port": 1}]})
        _im = imp.get_json() or {}
        check("import: adds the valid server, skips the bad name + unknown game",
              imp.status_code == 200 and _im.get("added") == ["importedcs"]
              and len(_im.get("skipped", [])) == 2, "got %s" % _im)
        # The account name arrives from the CLIENT and INSTANCE_NAME_RE is a Linux-username
        # grammar, not an allowlist: "root", "ubuntu" and "postgres" all match it. Nothing in the
        # route contacted the host, so a POST naming any account created a GameServer row for it —
        # and a whole-host grant makes every GameServer on that host accessible, after which every
        # game op builds `sudo -u root bash -c ...`. The scan is the authority on what exists.
        check("import: the fixture's scan does not report root, so the next check means something",
              "root" not in [r["user"] for r in _imp_mod.discover_linuxgsm_servers(None)],
              "the stub would have to report root for this to be a real test")
        imp_root = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
            {"user": "root", "game_type": "csgo", "port": 27015}]})
        _imr = imp_root.get_json() or {}
        check("import: an account the scan never reported is refused, root included",
              _imr.get("added") == [] and _imr.get("skipped") == ["root"], str(_imr)[:140])
        with app.app_context():
            _root_rows = GameServer.query.filter_by(remote_id=remote_id, short_name="root").count()
        check("import: ...and no row was written for it", _root_rows == 0, "rows=%d" % _root_rows)

        # An account imported on the panel's OWN host goes into the panel's game-account group —
        # the step create_game_user takes for an account the panel makes. The import used to add
        # the row and nothing else, and on a narrow-grant install the helper refuses every
        # per-account verb (start, stop, update, downloads) for an account outside that group. An
        # account the helper will not enrol, because it can already reach root, is REPORTED.
        from panel.ops.ssh_manager import _core as _imp_core
        _imp_saved = (_imp_core.run_privileged, _imp_core.is_local_server,
                      _imp_mod._bg_cache_commands)
        _imp_calls = []

        def _imp_fake_rp(_s, verb, args=(), **_k):
            _imp_calls.append((verb, list(args)))
            if verb == "gameuser-group" and list(args) == ["importedsudo"]:
                return ("", "refusing to enrol importedsudo in lgsmpanel-games: it can already "
                            "run sudo\n", 1)
            return ("", "", 0)
        try:
            _imp_core.run_privileged = _imp_fake_rp
            _imp_core.is_local_server = lambda _s: True
            # No worker to outlive the stubs — and the call is RECORDED, because the command-list
            # read it starts runs as the game account and needs the membership granted first.
            _imp_bg_args = []
            _imp_mod._bg_cache_commands = lambda *a, **k: (
                _imp_calls.append(("bg-cache", [])), _imp_bg_args.append((a, k)))
            _imp_mod.discover_linuxgsm_servers = lambda _s: [
                {"user": _u, "lgsm_name": "csgoserver", "port": 27015, "backups": 0, "mods": 0,
                 "cron": 0, "autostart": False} for _u in ("importedplain", "importedsudo")]
            imp_en = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
                {"user": "importedplain", "game_type": "csgo", "port": 27016},
                {"user": "importedsudo", "game_type": "csgo", "port": 27017}]})
        finally:
            (_imp_core.run_privileged, _imp_core.is_local_server,
             _imp_mod._bg_cache_commands) = _imp_saved
        _ime = imp_en.get_json() or {}
        _ime_enrolled = sorted(_a for _v, _a in _imp_calls if _v == "gameuser-group")
        check("import: each account imported on the panel's own host is put in the game group",
              sorted(_ime.get("added") or []) == ["importedplain", "importedsudo"]
              and _ime_enrolled == [["importedplain"], ["importedsudo"]],
              "added=%s enrolled=%s" % (_ime.get("added"), _ime_enrolled))
        _ime_order = [_v for _v, _a in _imp_calls if _v in ("gameuser-group", "bg-cache")]
        check("import: ...BEFORE the background command-list read that runs as those accounts",
              _ime_order == ["gameuser-group", "gameuser-group", "bg-cache"], str(_ime_order))
        _ime_ne = _ime.get("not_enrolled") or []
        check("import: ...and the one the helper refuses is reported, with its reason; the other "
              "is not", [_n.get("user") for _n in _ime_ne] == ["importedsudo"]
              and "already run sudo" in (_ime_ne[0].get("reason") or ""), str(_ime_ne)[:160])
        # Autostart is turned on for imported servers, as an install does — but only where the
        # panel can write the account's crontab, so not for the account the helper refused.
        with app.app_context():
            _imp_ids = {g.short_name: g.id for g in GameServer.query.filter(
                GameServer.remote_id == remote_id,
                GameServer.short_name.in_(["importedplain", "importedsudo"])).all()}
            _imp_flags = {g.short_name: g.autostart for g in GameServer.query.filter(
                GameServer.remote_id == remote_id,
                GameServer.short_name.in_(["importedplain", "importedsudo"])).all()}
        _imp_as = set((_imp_bg_args[0][1].get("autostart_ids") if _imp_bg_args else None) or ())
        check("import: the background step is asked to turn Autostart on for the enrolled account, "
              "not the refused one",
              _imp_as == {_imp_ids.get("importedplain")} and None not in _imp_as,
              "autostart_ids=%s ids=%s" % (sorted(_imp_as), _imp_ids))
        check("import: ...and the flag stays off until the cron line is actually written",
              _imp_flags == {"importedplain": False, "importedsudo": False}, str(_imp_flags))

        # The background step itself, run synchronously (no worker outlives these stubs), against
        # every answer it can get: monitor present, absent, a failed command-list read, a failed
        # crontab write, and a server that was not asked for.
        from panel.routes import _shared as _as_shared
        import types as _as_types
        NSx = _as_types.SimpleNamespace
        _as_saved = (_as_shared._sm, _as_shared.threading)
        _as_writes = []
        _as_cmds = {"importedplain": [{"cmd": "start"}, {"cmd": "monitor"}],
                    "importedsudo": [{"cmd": "monitor"}]}

        def _as_set(_r, user, enabled, selfname=None):
            _as_writes.append((user, enabled, selfname))
            return (user != "failwrite", "crontab refused" if user == "failwrite" else "")
        try:
            _as_shared.threading = NSx(Thread=lambda target, daemon=None: NSx(start=target))
            _as_shared._sm = NSx(list_server_commands=lambda _r, u, _n: _as_cmds.get(u, []),
                                set_autostart=_as_set)
            _as_shared._bg_cache_commands(app, list(_imp_ids.values()),
                                          autostart_ids=[_imp_ids["importedplain"]])
            with app.app_context():
                _as_after = {g.short_name: g.autostart for g in GameServer.query.filter(
                    GameServer.id.in_(list(_imp_ids.values()))).all()}
            check("import: the background step writes monitor for the asked-for server and records it",
                  _as_writes == [("importedplain", True, "csgoserver")]
                  and _as_after == {"importedplain": True, "importedsudo": False},
                  "writes=%s after=%s" % (_as_writes, _as_after))
            # A game without monitor, a command list that could not be read, and a write that failed
            # all leave Autostart off, and only the failed write was attempted.
            _as_writes.clear()
            with app.app_context():
                for _sn in ("importedplain", "importedsudo"):
                    db.session.get(GameServer, _imp_ids[_sn]).autostart = False
                db.session.commit()
            _as_cmds = {"importedplain": [{"cmd": "start"}], "importedsudo": []}
            _as_shared._sm = NSx(list_server_commands=lambda _r, u, _n: _as_cmds.get(u, []),
                                set_autostart=_as_set)
            _as_shared._bg_cache_commands(app, list(_imp_ids.values()),
                                          autostart_ids=list(_imp_ids.values()))
            check("import: ...a game without monitor, or an unread command list, gets no cron line",
                  _as_writes == [], str(_as_writes))
            with app.app_context():
                _as_fw = db.session.get(GameServer, _imp_ids["importedplain"])
                _as_fw.short_name = "failwrite"
                db.session.commit()
            _as_cmds = {"failwrite": [{"cmd": "monitor"}]}
            _as_shared._bg_cache_commands(app, [_imp_ids["importedplain"]],
                                          autostart_ids=[_imp_ids["importedplain"]])
            with app.app_context():
                _as_fw_flag = db.session.get(GameServer, _imp_ids["importedplain"]).autostart
                db.session.get(GameServer, _imp_ids["importedplain"]).short_name = "importedplain"
                db.session.commit()
            check("import: ...and a crontab write that fails leaves the flag off",
                  _as_writes == [("failwrite", True, "csgoserver")] and _as_fw_flag is False,
                  "writes=%s flag=%s" % (_as_writes, _as_fw_flag))
        finally:
            _as_shared._sm, _as_shared.threading = _as_saved
        with app.app_context():
            GameServer.query.filter(GameServer.remote_id == remote_id, GameServer.short_name.in_(
                ["importedplain", "importedsudo"])).delete(synchronize_session=False)
            db.session.commit()
    finally:
        _imp_mod.discover_linuxgsm_servers = _imp_orig
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

    # ── A host the panel could not scan must not be reported as "nothing found" ───────────────
    # discover_linuxgsm_servers is best-effort and returns [] for BOTH "scanned, nothing new" and
    # "the scan never ran" — its own except branch swallows everything, and the tailscale and local
    # transports do not raise at all, they answer ("", "SSH command timed out", -1). The route then
    # returned {"servers": [], "content": []}, byte-for-byte what a healthy empty host looks like,
    # and remote_manage_backups.js rendered a green tick and "No new LinuxGSM servers found" about
    # a directory listing that never happened. An admin reads that and stops looking.
    _orig_disc2 = _disc_mod.discover_linuxgsm_servers
    _orig_disc_rc2 = _disc_mod.run_command
    try:
        _disc_mod.discover_linuxgsm_servers = lambda _s: []
        # The transport answer for a host that is powered off / whose tailnet route is down.
        _disc_mod.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
        _du = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
        check("discover: a host the panel could not reach is reported as unread, not as empty",
              bool(_du.get("error")) and not _du.get("servers"),
              "the card shows a tick and 'No new LinuxGSM servers found': %s" % (str(_du)[:160],))
        # rc 0 but no token back is the same thing wearing a success code — the `not in` form of
        # this check is satisfied by "" as well, so the token has to be POSITIVE.
        _disc_mod.run_command = lambda *a, **k: ("", "", 0)
        _du0 = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
        check("discover: ...and an rc 0 with nothing echoed back is not an answer either",
              bool(_du0.get("error")), str(_du0)[:160])
        # The control: a host that DID answer and genuinely has nothing new still reports nothing
        # new, with no error — otherwise the two checks above would pass on a route that refuses
        # every scan.
        _disc_mod.run_command = lambda *a, **k: ("LGSM_SCAN_OK", "", 0)
        _dok = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
        check("discover: a host that answered with nothing new is still 'nothing new' (control)",
              not _dok.get("error") and _dok.get("servers") == [], str(_dok)[:160])
        # ...and a host with servers is never probed at all: the confirmation only runs when the
        # scan came back empty, so a working scan costs no extra round trip.
        _dprobed = []
        _disc_mod.run_command = lambda *a, **k: (_dprobed.append(1), ("", "", -1))[1]
        _disc_mod.discover_linuxgsm_servers = lambda _s: [
            {"user": "smokedisc", "lgsm_name": "gmodserver", "port": 27015,
             "backups": 1, "mods": 0, "cron": 2, "autostart": False}]
        _dfull = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
        check("discover: a scan that found something is not re-probed",
              not _dprobed and [x["user"] for x in (_dfull.get("servers") or [])] == ["smokedisc"],
              "probes=%s %s" % (_dprobed, str(_dfull)[:120]))
    finally:
        _disc_mod.discover_linuxgsm_servers = _orig_disc2
        _disc_mod.run_command = _orig_disc_rc2

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
    # POST, like the switcher in panel.js now sends. The PROFILE write is POST-only: csrf.protect()
    # is a no-op on safe methods, so as a GET this was a stored state change any cross-site page
    # could make with <img src=".../set-language/zh">.
    _lang = s1.post("/set-language/es?ajax=1")
    check("language: the ajax save answers in the standard envelope",
          (_lang.get_json() or {}).get("success") is True
          and "ok" not in (_lang.get_json() or {}),
          _lang.get_data(as_text=True)[:120])
    with app.app_context():
        check("language: ...and a POST really writes the profile",
              (User.query.filter_by(username="smoke_admin").first().language or "") == "es",
              "language=%r" % (User.query.filter_by(username="smoke_admin").first().language,))
    _lang_get = s1.get("/set-language/fr?ajax=1")
    check("language: a GET still switches the session", _lang_get.status_code == 200,
          "status=%d" % _lang_get.status_code)
    with app.app_context():
        check("language: ...but a GET does NOT write the profile — CSRF cannot cover a GET",
              (User.query.filter_by(username="smoke_admin").first().language or "") == "es",
              "a cross-site <img> would have made this stick: language=%r"
              % (User.query.filter_by(username="smoke_admin").first().language,))
    s1.post("/set-language/en?ajax=1")   # put it back

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

    # ── "strong" session protection must actually bind the cookie to its client ──────────────
    # flask-login only acts on "strong" for a NON-permanent session, and every panel login is
    # permanent, so a copied cookie replayed from another IP and browser stayed signed in while
    # the settings page promised a re-check on an IP or device change. Driven through the real
    # /login with protection switched to strong for this block (the suite runs with it off).
    _sp_saved = app.config.get("SESSION_PROTECTION")
    app.config["SESSION_PROTECTION"] = "strong"
    try:
        _sp = app.test_client()
        _sp_ua = {"User-Agent": "SmokeBrowser/1.0", "X-Requested-With": "XMLHttpRequest"}
        _sp.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"},
                 headers=_sp_ua)
        _sp_ok = _sp.get("/api/account/sessions", headers=_sp_ua).status_code
        _sp_other_ua = _sp.get("/api/account/sessions",
                               headers=dict(_sp_ua, **{"User-Agent": "Stolen/9.9"})).status_code
        _sp_other_ip = _sp.get("/api/account/sessions", headers=_sp_ua,
                               environ_overrides={"REMOTE_ADDR": "203.0.113.77"}).status_code
        _sp_back = _sp.get("/api/account/sessions", headers=_sp_ua).status_code
        check("session protection: the signed-in client keeps its session (control)",
              _sp_ok == 200 and _sp_back == 200, "first %s, after replays %s" % (_sp_ok, _sp_back))
        check("session protection: strong refuses the cookie from another browser",
              _sp_other_ua == 401, "got %s" % _sp_other_ua)
        check("session protection: strong refuses the cookie from another address",
              _sp_other_ip == 401, "got %s" % _sp_other_ip)
        app.config["SESSION_PROTECTION"] = "basic"
        _sp_basic = _sp.get("/api/account/sessions",
                            headers=dict(_sp_ua, **{"User-Agent": "Stolen/9.9"})).status_code
        check("session protection: basic does not bind (the mode really is what decides)",
              _sp_basic == 200, "got %s" % _sp_basic)
        _sp.get("/logout", headers=_sp_ua)
        # IPv6: bound to the /64, as the login throttle counts it. A temporary ("privacy") address
        # rotates inside it about daily and each new connection takes the newest, so an exact
        # address signed every IPv6 user out whenever theirs rotated.
        app.config["SESSION_PROTECTION"] = "strong"
        _sp6 = app.test_client()
        _sp6.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"},
                  headers=_sp_ua, environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"})
        _sp6_same = _sp6.get("/api/account/sessions", headers=_sp_ua,
                             environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"}).status_code
        _sp6_rot = _sp6.get("/api/account/sessions", headers=_sp_ua,
                            environ_overrides={"REMOTE_ADDR": "2001:db8:1:2:a1b2:c3d4:e5f6:7"}
                            ).status_code
        _sp6_away = _sp6.get("/api/account/sessions", headers=_sp_ua,
                             environ_overrides={"REMOTE_ADDR": "2001:db8:1:3::10"}).status_code
        check("session protection: an IPv6 client keeps its session when its temporary address "
              "rotates inside the /64", _sp6_same == 200 and _sp6_rot == 200,
              "same address %s, rotated address %s" % (_sp6_same, _sp6_rot))
        check("session protection: ...and strong still refuses it from another /64 (control)",
              _sp6_away == 401, "got %s" % _sp6_away)
        _sp6.get("/logout", headers=_sp_ua, environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"})
    finally:
        app.config["SESSION_PROTECTION"] = _sp_saved
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
        check("dashboard metrics: a measured host says so",
              _hostblk.get("metrics") is True, str(_hostblk)[:110])

        # ── a host that answers NOTHING has to be reported, not omitted ───────────────────────
        # It used to fall out of the payload entirely: `if not m: continue` skipped every game on
        # it, so its host block was never built. The dashboard iterated the payload's own keys,
        # never reached that host's card, and left the last CPU/RAM/Disk line it had ever been
        # given sitting there — uptime included, no longer advancing — beside a summary tile that
        # had already fallen back to "—". Absence read as "unchanged" when it meant "unknown".
        #
        # The stub RAISES rather than returning None: that is the path an unreachable host takes
        # (_query_host_metrics catches and answers metrics=None for each of its games), and it is
        # the one this is about.
        def _dead_host(_remote, force=False):
            raise OSError("the host did not answer")

        _dmapp.host_live_metrics = _dead_host
        _dj2 = (c.get("/api/dashboard/metrics").get_json() or {})
        _hb2 = (_dj2.get("hosts") or {}).get(str(_rid))
        check("dashboard metrics: a host that answered nothing is still reported",
              _hb2 is not None, "the host block is missing, so the page cannot be told")
        check("dashboard metrics: ...said to be unmeasured, so the page clears its figures",
              (_hb2 or {}).get("metrics") is False, str(_hb2)[:110])
        check("dashboard metrics: ...carrying no stale numbers from the sample that worked",
              "cpu" not in (_hb2 or {}) and "uptime" not in (_hb2 or {}), str(_hb2)[:110])
        check("dashboard metrics: ...and the reachability the dashboard badge renders",
              "reachable" in (_hb2 or {}) and "probed" in (_hb2 or {}), str(_hb2)[:110])
        check("dashboard metrics: ...while its servers drop out rather than report old figures",
              str(gs_id) not in (_dj2.get("servers") or {}),
              "the server kept a sample nothing measured")

        # ── ...and the failure that does NOT raise, which is the common one ──────────────────
        # Only paramiko raises. The tailscale and local transports return ("", "…timed out", -1),
        # and host_live_metrics builds its answer UP FRONT and returns it unchanged when the
        # output is empty — so the real shape of an unreachable host on the transport the panel
        # steers people towards is this dict of zeros, which is fully populated and therefore
        # TRUTHY. It sailed through `if not m` and the dashboard rendered the host as
        # "Reachable · CPU 0% · RAM 0% · Disk 0%" — a host at 95% disk reading as idle.
        def _zero_host(_remote, force=False):
            return {"host": {"cpu_percent": 0.0, "ram_used": 0, "ram_total": 0, "disk_used": 0,
                             "disk_total": 0, "uptime_secs": 0, "cores": 1},
                    "users": {}, "ports": set()}

        _dmapp.host_live_metrics = _zero_host
        _dj3 = (c.get("/api/dashboard/metrics").get_json() or {})
        _hb3 = (_dj3.get("hosts") or {}).get(str(_rid))
        check("dashboard metrics: an all-zero sample is unmeasured, not a host idling at 0%",
              (_hb3 or {}).get("metrics") is False, str(_hb3)[:140])
        check("dashboard metrics: ...so it is not badged reachable on the strength of zeros",
              (_hb3 or {}).get("cpu") is None and (_hb3 or {}).get("disk_pct") is None,
              str(_hb3)[:140])
        check("dashboard metrics: ...and its servers report no figures either",
              str(gs_id) not in (_dj3.get("servers") or {}), str(_dj3.get("servers"))[:110])
    finally:
        _dmapp.host_live_metrics, _dmapp.game_map = _sv_slm, _sv_map

    # ── ...and the background metrics SAMPLER samples per host too ────────────────────────────
    # _record_metric_samples still built _metrics_work and mapped _query_server_metrics over it:
    # one SSH round trip PER SERVER, each carrying the 0.25s sampling sleep, every 60s forever —
    # to fetch whole-machine figures that are identical by definition and of which it writes
    # exactly one HostSample per host anyway. 100 servers on 5 hosts opened 100 executions where
    # 5 answer the same rows, in background threads competing with the console and the web
    # requests for the same SSH connections.
    from panel.db.models import HostSample as _HSs
    _sv_hlm2, _sv_slm2, _sv_map2 = (_dmapp.host_live_metrics, _dmapp.server_live_metrics,
                                    _dmapp.game_map)
    _host_calls, _srv_calls = [], []
    try:
        def _count_host(remote, force=False):
            _host_calls.append(getattr(remote, "id", None))
            return {"host": {"cpu_percent": 30.0, "ram_used": 4, "ram_total": 8, "disk_used": 1,
                             "disk_total": 4, "uptime_secs": 86400, "cores": 4},
                    "users": {"csgoserver": {"game_procs": 2, "game_cpu_percent": 12.5,
                                             "game_ram_mb": 2048, "game_uptime_secs": 900}},
                    "ports": set()}

        def _count_server(remote, short_name=None, game_port=None, force=False):
            _srv_calls.append(short_name)
            raise AssertionError("the sampler queried a SERVER, not its host")

        _dmapp.host_live_metrics, _dmapp.server_live_metrics = _count_host, _count_server
        _dmapp.game_map = lambda *a, **k: "de_dust2"
        with app.app_context():
            _ms_before = {r[0] for r in db.session.query(MetricSample.id).all()}
            _hs_before = {r[0] for r in db.session.query(_HSs.id).all()}
            # The same rows the sampler itself feeds to _host_metrics_work, which skips a server
            # with no host — so the expected counts below cannot drift from what it sampled.
            _samp_rows = [_g for _g in GameServer.query.filter_by(installed=True).all()
                          if _g.remote is not None]
            _samp_srv, _samp_hosts = len(_samp_rows), {_g.remote_id for _g in _samp_rows}
        _dmapp._record_metric_samples(app)
        check("metrics sampler: one SSH sample per HOST, not one per server",
              len(_host_calls) == len(_samp_hosts) and not _srv_calls,
              "%d sample(s) for %d host(s) / %d installed server(s); per-server calls: %s"
              % (len(_host_calls), len(_samp_hosts), _samp_srv, _srv_calls[:3]))
        # Positive control: the pass still writes the rows the history charts read, so the check
        # above cannot pass on a sampler that simply stopped sampling.
        with app.app_context():
            _ms_new = [r for r in MetricSample.query.all() if r.id not in _ms_before]
            _hs_new = [r for r in _HSs.query.all() if r.id not in _hs_before]
            check("metrics sampler: ...and still records a sample per server and one per host",
                  len(_ms_new) == _samp_srv and len(_hs_new) == len(_samp_hosts),
                  "%d metric / %d host rows for %d servers on %d hosts"
                  % (len(_ms_new), len(_hs_new), _samp_srv, len(_samp_hosts)))
            for _row in _ms_new + _hs_new:
                db.session.delete(_row)
            db.session.commit()
    finally:
        (_dmapp.host_live_metrics, _dmapp.server_live_metrics,
         _dmapp.game_map) = _sv_hlm2, _sv_slm2, _sv_map2

    # ── /api/servers must not COMMIT a status it could not read ───────────────────────────────
    # _remote_listening_ports answers None for a scan that failed, and its docstring lists what
    # happens when that is taken as "nothing listening": every server on the host written offline,
    # which the bots and the dashboard then repeat and the one-shot "notify when empty" reads.
    # This endpoint had the guard for it — `if ports is None: continue — this host's scan failed;
    # leave its statuses alone` — and defeated it twelve lines earlier with `or set()`, so it could
    # only ever fire on the except path.
    import panel.routes.api as _apimod
    _ap_saved = _apimod._remote_listening_ports
    try:
        with app.app_context():
            _gs0 = db.session.get(GameServer, gs_id)
            _gs0.installed, _gs0.status = True, "online"
            db.session.commit()
            _before_status = _gs0.status
        _apimod._remote_listening_ports = lambda r: None          # the scan failed
        c.get("/api/servers")
        with app.app_context():
            _after = db.session.get(GameServer, gs_id).status
        check("api/servers: a failed port scan leaves the stored status alone",
              _after == _before_status, "%s -> %s" % (_before_status, _after))
        # positive control: a scan that really answered still updates the status, so the check
        # above is measuring the guard and not an endpoint that stopped writing at all.
        _apimod._remote_listening_ports = lambda r: set()         # answered: nothing listening
        c.get("/api/servers")
        with app.app_context():
            _after2 = db.session.get(GameServer, gs_id).status
        check("api/servers: a scan that ANSWERED 'nothing listening' still writes offline",
              _after2 == "offline", "status is %s" % _after2)
    finally:
        _apimod._remote_listening_ports = _ap_saved

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
    _esc_tpls = sorted(_tpl_dir.glob("*.html"))
    check("escaping: the fallback sweep found templates to read", len(_esc_tpls) >= 20,
          "%d templates — the check below would pass vacuously" % len(_esc_tpls))
    _failopen = [p.name for p in _esc_tpls
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
          and ('id="srv-tags-%d" class="d-block srv-tags" data-no-i18n' % gs_id) in _dash_html,
          "chip markup missing from the rendered dashboard")
    # ...and the container is there even for a server with NO tags, because that is what
    # server_tags.js repaints into and what the dashboard's tag filter reads from.
    c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": []})
    _untagged_html = c.get("/").get_data(as_text=True)
    check("tags: the chip container is rendered even when the server has no tags",
          ('id="srv-tags-%d"' % gs_id) in _untagged_html
          and ('data-tag-id="%d"' % _tag_id) not in _untagged_html.split('id="srv-tags-%d"' % gs_id)[1][:400],
          "no container for an untagged server — its first tag could not appear without a reload")
    c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": [_tag_id]})
    # The muted-tag branch (bell-slash + title) only renders when a MUTED tag is actually assigned.
    _mute_resp = (c.post("/api/server/%d/tags" % gs_id, json={"tag_ids": [_tag_id, _mute_id]})
                  .get_json() or {})
    # server_tags.js repaints the row's chips from THIS response after a save; without `notify` in
    # it the repainted chip could not say alerts are muted, and the marker vanished from the row.
    _mute_flags = {t.get("id"): t.get("notify") for t in _mute_resp.get("tags") or []}
    check("tags: the save response says which assigned tags mute alerts (control: and which do not)",
          _mute_flags.get(_mute_id) is False and _mute_flags.get(_tag_id) is True,
          "got %r" % (_mute_flags,))
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
            # ...and the RECORDED state must not flip either. Only the alert was suppressed; the
            # pass still wrote False, so the next sweep read False -> True and pushed "Server back
            # online" for an outage the operator was deliberately never told about. With a 60s
            # sweep and a ~30s restart that lands on roughly half the restarts of a slow-booting
            # game — a channel showing recoveries from outages it never reported. This is the
            # treatment the maintenance branch already had.
            check("monitor: ...and leaves the recorded state alone, so there is no phantom recovery",
                  _ps._monitor_state["servers"].get(_mon_id) is True,
                  "recorded %r" % _ps._monitor_state["servers"].get(_mon_id))
            # Drive the next sweep for real: _rec holds only event KEYS and other fixture servers
            # transition too, so record the BODIES and look for this server by name.
            _exp_bodies = []
            _am.notifications.notify = lambda k, t, b="": (_rec.append(k), _exp_bodies.append((k, b)))[0]
            _monmod._remote_listening_ports = lambda r: {27100}
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: ...so coming back from a panel-issued restart is silent",
                  not [b for k, b in _exp_bodies if k == "server_up" and "mon-srv" in b],
                  str([b for k, b in _exp_bodies if k == "server_up"])[:140])
            # Positive control: a recovery the panel did NOT cause still announces itself, so the
            # silence above is the guard and not a monitor that stopped alerting.
            _reset_mon()
            _ps._expected_offline.pop(_mon_id, None)
            _ps._monitor_state["servers"][_mon_id] = False
            _exp_bodies.clear()
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: ...while a recovery the panel did not cause IS announced",
                  any(k == "server_up" and "mon-srv" in b for k, b in _exp_bodies),
                  str(_exp_bodies)[:140])
            _am.notifications.notify = lambda key, title, body="": _rec.append(key)
            _ps._expected_offline.pop(_mon_id, None)

            # ── A reboot the PANEL fires is not "went offline unexpectedly" ─────────────────────
            # Reboot-when-empty and Reboot now rebooted the host without marking its servers.
            # While the host was down the monitor skipped them, so they stayed "up"; when it
            # answered again the games were still waiting for LinuxGSM's */5 monitor cron, and
            # each read up -> down: one "offline unexpectedly" per server, then "back online".
            # Driven for real: the fire, then a sweep seven minutes later with the port still shut.
            import panel.routes.remote_vps as _rw_route
            _rw_saved = (_monmod.remote_reboot, _monmod.log_action, _monmod.time,
                         _monmod._remote_listening_ports, _rw_route.remote_reboot)
            _rw_bodies = []
            _rw_real_time = _monmod.time

            def _rw_sweep_later(secs):
                """One real monitor pass `secs` from now, the port still shut, mon-srv last seen up.
                Returns the server_down bodies that name mon-srv."""
                _later = _rw_real_time.time() + secs
                _monmod.time = type("_RwTime", (), {"time": staticmethod(lambda: _later),
                                                    "sleep": staticmethod(_rw_real_time.sleep)})
                try:
                    _reset_mon()
                    _ps._monitor_state["servers"][_mon_id] = True
                    _monmod._remote_listening_ports = lambda r: set()
                    _rw_bodies.clear(); _monmod._monitor_pass()
                finally:
                    _monmod.time = _rw_real_time
                return [b for k, t, b in _rw_bodies if k == "server_down" and "mon-srv" in b]

            try:
                _monmod.remote_reboot = lambda r: (True, "Reboot scheduled")
                _monmod.log_action = lambda *a, **k: None
                _am.notifications.notify = \
                    lambda k, t, b="": (_rec.append(k), _rw_bodies.append((k, t, b)))[0]
                _ps._expected_offline.pop(_mon_id, None)
                _monmod._fire_reboot_when_empty(RemoteServer.query.get(_r1_id), {"by": "admin"})
                _rw_down = _rw_sweep_later(420)
                check("monitor: a reboot the panel fired does not report its servers 'offline unexpectedly'",
                      not _rw_down, str(_rw_down)[:160])
                # Positive control: a reboot that was refused marks nothing and says it failed,
                # and the SAME sweep then does alert — a real outage in that window is still told.
                _ps._expected_offline.pop(_mon_id, None)
                _monmod.remote_reboot = lambda r: (False, "the host refused")
                _rw_bodies.clear()
                _monmod._fire_reboot_when_empty(RemoteServer.query.get(_r1_id), {"by": "admin"})
                _rw_titles = [t for k, t, b in _rw_bodies if k == "auto_reboot"]
                _rw_down = _rw_sweep_later(420)
                check("monitor: ...while a refused reboot leaves no mark, says it failed, and the outage alerts (control)",
                      _mon_id not in _ps._expected_offline and _rw_titles == ["Auto-reboot failed"]
                      and len(_rw_down) == 1, "%s %s" % (_rw_titles, _rw_down))

                # Reboot now, through the real route: the same marks, from the route's own
                # remote_reboot (stubbed where the route resolves it).
                _rw_c = app.test_client()
                _rw_c.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
                _ps._expected_offline.pop(_mon_id, None)
                _rw_route.remote_reboot = lambda r: (True, "Reboot command sent to remote")
                _rw_resp = _rw_c.post("/api/remote/%d/reboot" % _r1_id, json={})
                _rw_mark = _ps._expected_offline.get(_mon_id, 0)
                check("reboot now: the host's servers are marked expected-offline past boot and the monitor cron",
                      _rw_resp.status_code == 200 and _rw_mark >= _rw_real_time.time() + 250,
                      "%s mark=%r" % (_rw_resp.status_code, _rw_mark))
                _ps._expected_offline.pop(_mon_id, None)
                _rw_route.remote_reboot = lambda r: (False, "a password is required")
                _rw_resp = _rw_c.post("/api/remote/%d/reboot" % _r1_id, json={})
                check("reboot now: ...while a refused reboot marks nothing (control)",
                      _rw_resp.status_code == 200 and _mon_id not in _ps._expected_offline,
                      "%s %r" % (_rw_resp.status_code, _ps._expected_offline.get(_mon_id)))
                _rw_c.get("/logout")
            finally:
                (_monmod.remote_reboot, _monmod.log_action, _monmod.time,
                 _monmod._remote_listening_ports, _rw_route.remote_reboot) = _rw_saved
                _ps._expected_offline.pop(_mon_id, None)
                _am.notifications.notify = lambda key, title, body="": _rec.append(key)
            # ...and the watcher's loop is what calls it (by AST: comments name it too), with no
            # remote_reboot of its own left beside it.
            import ast as _rw_ast
            import inspect as _rw_inspect
            _rw_calls = [getattr(n.func, "id", "") for n in _rw_ast.walk(_rw_ast.parse(
                _rw_inspect.getsource(_monmod._reboot_when_empty_watch)))
                if isinstance(n, _rw_ast.Call)]
            check("monitor: the reboot-when-empty loop fires through _fire_reboot_when_empty",
                  "_fire_reboot_when_empty" in _rw_calls and "remote_reboot" not in _rw_calls,
                  repr(_rw_calls))

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

            # ── a scan that could not be READ is not a scan that found nothing ───────────────
            # _remote_listening_ports returned set() for both, and on a local or Tailscale-SSH
            # host a timed-out command does not raise — the transport answers ("", "...", -1) — so
            # one flaky `ss` read arrived at _probe_host as "reachable, nothing listening". The
            # sweep then declared every server on that host down: an alert each, gs.status written
            # offline (which the bots and the dashboard then repeated), the one-shot notify-when-
            # empty falsely fired AND consumed, and a matching "back online" storm 60s later.
            _reset_mon()
            _monmod._remote_listening_ports = lambda r: {27100}
            _rec.clear(); _monmod._monitor_pass()          # baseline: up
            _monmod._remote_listening_ports = lambda r: None    # the read FAILED
            _st_blip = _status_after_pass("online")
            check("monitor: a failed port scan does not fire server_down",
                  "server_down" not in _rec, "fired: %s" % _rec)
            check("monitor: ...and does not write the server offline",
                  _st_blip == "online", "status=%r" % _st_blip)
            # ...while a scan that really did come back empty still means the server is down.
            _monmod._remote_listening_ports = lambda r: set()
            _st_real = _status_after_pass("online")
            check("monitor: an EMPTY scan still means down, so the guard is not blanket",
                  _st_real == "offline", "status=%r" % _st_real)
            _mon.status = "online"; db.session.commit()
            _monmod._remote_listening_ports = lambda r: {27100}

            # A reachable host that stops responding -> remote_unreachable.
            _reset_mon()
            _ps._monitor_state["remotes"].clear()
            _ps._monitor_state["remotes"][_r1_id] = True
            # Start from True on the ROW as well, or the False below could be the value the
            # fixture already had and the check would pass with the write deleted.
            _r1.is_online = True
            db.session.commit()
            _monmod._host_reachable = lambda r: r.id != _r1_id
            _rec.clear(); _monmod._monitor_pass()
            check("monitor: remote_unreachable fires when a host stops responding",
                  "remote_unreachable" in _rec)
            # ...and the COLUMN follows, not just this pass's memory. is_online was written only by
            # host creation (hardcoded True), the manual Test button and a successful bootstrap, so
            # a host down for days rendered a green "Reachable" badge on the dashboard, the host
            # cards and the bots' /hosts — all of which branch on this column first.
            db.session.rollback()
            db.session.refresh(_r1)
            check("monitor: ...and writes is_online=False to the host row",
                  _r1.is_online is False, "is_online=%r" % _r1.is_online)
            _monmod._host_reachable = lambda r: True
            _rec.clear(); _monmod._monitor_pass()
            db.session.rollback()
            db.session.refresh(_r1)
            check("monitor: ...and back to True when it answers again",
                  _r1.is_online is True, "is_online=%r" % _r1.is_online)

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

            # ...and it must not SEND before it has persisted the disarm. notifications.notify
            # never raises — it dispatches on a thread of its own — so the only statement the
            # except could ever catch was the commit, and when it caught it the alert had already
            # gone out while the flag stayed armed in the database. This panel writes to one
            # SQLite file from four places at once, so "database is locked" here is ordinary, and
            # the 45s poller then re-sent the "one-shot" every 45s until a commit finally landed.
            _mon.notify_when_empty = True; _mon_running()
            _monmod._server_slots = _slots_for_mon((0, 16, None))
            _real_db = _monmod.db

            class _LockedDB:
                """A db whose commits raise. rollback is the REAL one, so the session is left in
                the state a genuine failed commit would leave it in."""
                class session:
                    @staticmethod
                    def commit():
                        raise RuntimeError("database is locked")

                    @staticmethod
                    def rollback():
                        return db.session.rollback()

            try:
                _monmod.db = _LockedDB
                _rec.clear(); _monmod._refresh_player_counts(app)
            finally:
                _monmod.db = _real_db
            db.session.rollback(); db.session.refresh(_mon)
            check("poller: a commit that fails does not send the one-shot empty alert",
                  "server_empty" not in _rec, str(_rec))
            check("poller: ...and the request stays armed rather than being silently consumed",
                  _mon.notify_when_empty is True)

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

            # ── The unattended reboot must not fire into an install ───────────────────────────
            # _host_idle_state is the gate on "reboot when empty", and it enumerated only
            # installed=True rows. Through install steps 1-4 — the SteamCMD download, the long
            # part — the row is installed=False / status="installing", so it was not in that query
            # at all and contributed neither "busy" nor "unknown": an install in flight was
            # indistinguishable from no server, the host answered a confident "idle", and the
            # watcher rebooted it inside 60s — steamcmd killed, a half-written serverfiles tree,
            # and the job reconciled later as "the panel restarted before this install finished".
            _sv_slots_idle = _monmod._server_slots
            _idle_extra = None
            # Settle every row already on this host first. This suite is a flat script and earlier
            # blocks leave rows behind mid-install; now that _host_idle_state enumerates ALL rows
            # rather than installed=True only, one of those makes the baseline "unknown" and the
            # checks below would be measuring the leftover instead of the change. Restored after.
            _idle_saved = []
            for _g in GameServer.query.filter_by(remote_id=_r1_id).all():
                _idle_saved.append((_g.id, _g.installed, _g.status))
                _g.installed, _g.status = True, "online"
            db.session.commit()
            try:
                _monmod._server_slots = lambda gs: (0, 16, None)   # every server: a confident 0
                check("idle state: a host whose servers all report 0 players is idle",
                      _monmod._host_idle_state(_r1) == "idle", _monmod._host_idle_state(_r1))
                _idle_extra = GameServer(remote_id=_r1_id, name="inst-srv", short_name="instserver",
                                         game_type="csgo", port=27101, installed=False,
                                         status="installing")
                db.session.add(_idle_extra); db.session.commit()
                check("idle state: a server mid-install makes the host NOT idle",
                      _monmod._host_idle_state(_r1) != "idle",
                      "answered %r — the watcher would reboot into a running install"
                      % _monmod._host_idle_state(_r1))
                # ...but a row that is merely not installed — a failed or abandoned install — is
                # not work in flight, and blocking on it would strand "reboot when empty" on that
                # host for as long as the row exists.
                _idle_extra.installed, _idle_extra.status = False, "failed"
                db.session.commit()
                check("idle state: ...while a failed install does not block the reboot forever",
                      _monmod._host_idle_state(_r1) == "idle", _monmod._host_idle_state(_r1))
                # ...and a server with players on it is still 'busy', so the gate is not blanket.
                _monmod._server_slots = lambda gs: (3, 16, None)
                check("idle state: a host with players connected is busy",
                      _monmod._host_idle_state(_r1) == "busy", _monmod._host_idle_state(_r1))
                # ...and a count the panel could not read is 'unknown', never 'idle'.
                _monmod._server_slots = lambda gs: (None, 16, None)
                check("idle state: an unreadable count is unknown, not idle",
                      _monmod._host_idle_state(_r1) == "unknown", _monmod._host_idle_state(_r1))
            finally:
                _monmod._server_slots = _sv_slots_idle
                if _idle_extra is not None:
                    db.session.delete(_idle_extra); db.session.commit()
                for _gid, _inst, _st in _idle_saved:
                    _g = db.session.get(GameServer, _gid)
                    if _g is not None:
                        _g.installed, _g.status = _inst, _st
                db.session.commit()

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

    # ── reboot-when-empty: the POP is the commit point ────────────────────────────────────────────
    # The watcher snapshots the pending hosts at the top of a tick, then spends tens of seconds of
    # SSH on _host_reachable + _host_idle_state before popping the entry. An operator who clicks
    # Cancel inside that window is told "Auto-reboot canceled." and reboot-required then reports
    # pending_empty=false — but the pop came back None and the watcher rebooted anyway, taking
    # every game server on the host with it, and logged it under actor "system" so the audit row
    # did not explain it either. The `(info or {})` fallback was the tell.
    with app.app_context():
        _rw_mod = sys.modules["panel.services.monitoring"]
        _rw_ps = sys.modules["panel.core.panel_state"]
        _rw_rid = RemoteServer.query.filter_by(name="smoke-host").first().id
        _rw_saved = {n: getattr(_rw_mod, n) for n in
                     ("time", "remote_reboot", "_host_reachable", "_host_idle_state", "log_action")}
        _rw_saved_notify = _rw_mod.notifications.notify
        _rw_saved_reg = dict(_rw_ps._reboot_when_empty)
        _rw_saved_exp = dict(_rw_ps._expected_offline)   # a fired reboot marks the host's servers
        _rw_reboots = []

        class _OneTick(Exception):
            """Breaks the watcher's `while True` after exactly one pass through the body."""

        def _rw_run(idle_probe):
            """Run ONE tick of the real watcher with the given _host_idle_state, and report what
            it rebooted. time.sleep is what ends the loop, so nothing is left running behind us."""
            _rw_reboots.clear()
            _ticks = {"n": 0}

            def _sleep(_secs):
                _ticks["n"] += 1
                if _ticks["n"] > 1:
                    raise _OneTick()

            _rw_mod.time = type(sys)("_rw_clock")
            _rw_mod.time.sleep, _rw_mod.time.time = _sleep, _rw_saved["time"].time
            _rw_mod._host_reachable = lambda r: True
            _rw_mod._host_idle_state = idle_probe
            _rw_mod.remote_reboot = lambda r: (_rw_reboots.append(r.id), (True, "rebooting"))[1]
            _rw_mod.log_action = lambda *a, **k: None
            _rw_mod.notifications.notify = lambda *a, **k: None
            try:
                _rw_mod._reboot_when_empty_watch(app)
            except _OneTick:
                pass
            return list(_rw_reboots)

        try:
            # The probe CANCELS mid-flight, exactly as the route's Cancel button does.
            def _idle_then_cancel(remote):
                with _rw_ps._rwe_lock:
                    _rw_ps._reboot_when_empty.pop(remote.id, None)
                return "idle"

            with _rw_ps._rwe_lock:
                _rw_ps._reboot_when_empty.clear()
                _rw_ps._reboot_when_empty[_rw_rid] = {"by": "smoke", "since": _time_mon.time()}
            check("reboot-when-empty: a reboot cancelled while the idle probe ran does not fire",
                  _rw_run(_idle_then_cancel) == [],
                  "rebooted %s after the operator was told it was cancelled" % _rw_reboots)
            # Positive control: still queued at the pop, so the host really does get rebooted.
            with _rw_ps._rwe_lock:
                _rw_ps._reboot_when_empty.clear()
                _rw_ps._reboot_when_empty[_rw_rid] = {"by": "smoke", "since": _time_mon.time()}
            check("reboot-when-empty: ...while a queued, idle host still reboots",
                  _rw_run(lambda remote: "idle") == [_rw_rid], str(_rw_reboots))
            check("reboot-when-empty: ...and firing removes it from the registry",
                  _rw_rid not in _rw_ps._reboot_when_empty)
            # ...and a host that is not idle is left alone, entry intact, as before.
            with _rw_ps._rwe_lock:
                _rw_ps._reboot_when_empty.clear()
                _rw_ps._reboot_when_empty[_rw_rid] = {"by": "smoke", "since": _time_mon.time()}
            check("reboot-when-empty: a busy host is not rebooted and stays queued",
                  _rw_run(lambda remote: "busy") == [] and _rw_rid in _rw_ps._reboot_when_empty,
                  str(_rw_reboots))
        finally:
            for _n, _v in _rw_saved.items():
                setattr(_rw_mod, _n, _v)
            _rw_mod.notifications.notify = _rw_saved_notify
            with _rw_ps._rwe_lock:
                _rw_ps._reboot_when_empty.clear()
                _rw_ps._reboot_when_empty.update(_rw_saved_reg)
            _rw_ps._expected_offline.clear()
            _rw_ps._expected_offline.update(_rw_saved_exp)

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
    # The OS-update watch polls this while apt runs; a read that failed answered done:true, and the
    # popup declared the update finished with errors and stopped watching a live dpkg run.
    _r = _urc.get("/api/remote/%d/os-update/status" % _ur_id)
    _rj = _r.get_json(silent=True) or {}
    check("unreachable host: an OS-update status read that failed is not 'done'",
          _r.status_code == 200 and _rj.get("done") is False and _rj.get("unread") is True,
          "%d %r" % (_r.status_code, _rj))

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
        _sv = {n: getattr(_am.so, n) for n in ("fail2ban_attempt_counts", "ufw_blocked_ips",
               "ufw_deny_ip", "ufw_undeny_ip")}
        _sv_tn, _sv_th, _sv_wl = _monmod.tailnet_exempt_ips, _monmod._autoblock_threshold, _monmod._whitelist_networks
        try:
            _am.so.fail2ban_attempt_counts = lambda days=7: {
                "203.0.113.10": 80,    # over threshold  -> block
                "203.0.113.11": 5,     # under threshold -> ignore
                "10.9.9.9": 500,       # over, but WHITELISTED -> skip
            }
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
            # The fan-out goes through each server's LIVE console, so a server stopped when the
            # ban is added never gets it until Sync is pressed while it runs. The page promised
            # "gone everywhere" and counted every installed Source server as covered.
            _pgt = _pg.get_data(as_text=True)
            check("global-ban: the page does not promise every server gets it, and says how a "
                  "stopped one does",
                  "gone everywhere" not in _pgt and "Currently propagates" not in _pgt
                  and "stopped or unreachable" in _pgt and "Sync to all servers" in _pgt,
                  "the page still claims a coverage the console fan-out cannot deliver")
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
    # ...and the guard answers in linear time. Its path group was `(?:[seg]+/?)*`, which split a
    # run of segment characters 2^n ways before failing: "/"+"a"*30+"!" held the one eventlet hub
    # for ~50s, freezing every other user, console and poller. 26 characters is ~3s with the old
    # pattern and microseconds with the new, so the bound below is far from either.
    import time as _rd_time
    _rd_c = app.test_client()
    _rd_t0 = _rd_time.monotonic()
    _rd_r = _rd_c.post("/login?next=/" + "a" * 26 + "!",
                       data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
    _rd_dt = _rd_time.monotonic() - _rd_t0
    check("login redirect: a pathological ?next= is refused without backtracking",
          _rd_dt < 0.75 and _rd_r.status_code == 302
          and _rd_r.headers.get("Location", "").split("localhost", 1)[-1] == "/",
          "%.2fs %s %r" % (_rd_dt, _rd_r.status_code, _rd_r.headers.get("Location")))
    _rd_c.get("/logout")
    # The unauthenticated twin: the login redirect's ?next= is built from the requested path by
    # the same kind of pattern, and an <int:> converter takes any number of digits.
    _rd_t0 = _rd_time.monotonic()
    _rd_r = app.test_client().get("/server/" + "0" * 26 + "?!")
    _rd_dt = _rd_time.monotonic() - _rd_t0
    check("auth redirect: an anonymous pathological path is answered without backtracking",
          _rd_dt < 0.75 and _rd_r.status_code in (301, 302, 303)
          and "/login" in (_rd_r.headers.get("Location") or ""),
          "%.2fs %s" % (_rd_dt, _rd_r.status_code))
    # Positive control for the rewrite: a nested same-site path with a query still survives both.
    _rd_c = app.test_client()
    _rd_r = _rd_c.post("/login?next=/server/1/files?tab=config",
                       data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
    check("login redirect: a nested path with a query is still followed intact",
          _rd_r.headers.get("Location", "").endswith("/server/1/files?tab=config"),
          _rd_r.headers.get("Location"))
    _rd_c.get("/logout")
    _rd_r = app.test_client().get("/server/5?tab=files")
    check("auth redirect: ...and the anonymous redirect still carries it back",
          "next=%2Fserver%2F5%3Ftab%3Dfiles" in (_rd_r.headers.get("Location") or ""),
          _rd_r.headers.get("Location"))
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

        # ── ...but a crontab it could not READ is not a crontab with nothing in it ────────────
        # list_cron_jobs discarded the rc, so an unreachable host produced "" and parsed to [] —
        # and the reconcile above writes the columns from an ABSENCE, so it read both panel lines
        # as "gone" and turned Autostart and Daily-restart OFF. Merely OPENING Files & Config for
        # a server whose host was briefly unreachable disabled its autostart, permanently: the
        # host's crontab still had the lines, and nothing ever reconciles the other way.
        # Verified in a rendered panel before the fix — seeded autostart=1, one page load, 0.
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _g.autostart, _g.daily_restart = True, True
            db.session.commit()
        _sm_cron.list_cron_jobs = lambda *a, **k: None          # the host did not answer
        _unread = c.get("/api/server/%d/cron" % gs_id)
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _auto, _daily = _g.autostart, _g.daily_restart
        check("autostart: a crontab that could not be READ leaves the switch alone",
              _auto is True, "opening the page turned it off; it is now %r" % _auto)
        check("daily restart: ...and the same for the daily-restart switch", _daily is True,
              "now %r" % _daily)
        _uj = _unread.get_json() or {}
        check("cron: an unreadable crontab is reported as an error, not as an empty list",
              bool(_uj.get("error")) and "jobs" not in _uj,
              "the page renders 'No scheduled tasks yet.' for a host it never reached: %s"
              % str(_uj)[:120])
        check("cron: ...and says it is not the same as there being none",
              "not the same as there being none" in (_uj.get("error") or ""),
              _uj.get("error") or "no message")
        # The reconcile's OWN guard, driven directly. The route returns before reaching it, so
        # with only the checks above, reverting `if jobs is None: return False` inside
        # _sync_toggles_from_cron changed nothing and the whole suite stayed green — measured.
        # It is the function that does the destructive write, three routes call it, and a second
        # caller that forgets the route's check would put the wipe straight back.
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _g.autostart, _g.daily_restart = True, True
            db.session.commit()
            _ret = sys.modules["app"]._sync_toggles_from_cron(_g, None)
            db.session.commit()
            _g = db.session.get(GameServer, gs_id)
            _kept = (_g.autostart, _g.daily_restart)
        check("cron reconcile: handed no reading at all, it changes nothing and says so",
              _ret is False and _kept == (True, True),
              "returned %r, columns %r — a failed read is being written as 'the lines are gone'"
              % (_ret, _kept))
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _g.autostart = True
            db.session.commit()
            sys.modules["app"]._sync_toggles_from_cron(_g, [])
            db.session.commit()
            _wiped = db.session.get(GameServer, gs_id).autostart
        check("cron reconcile: ...while an ACTUAL empty crontab still turns the switch off",
              _wiped is False,
              "the guard swallowed the real empty case too, so deleting the line stops working")
    finally:
        _sm_cron.list_cron_jobs = _sv_lcj

    # ── The daily cron pass reaches every game server, not only the ones someone opens ───────────
    # upgrade_managed_cron_tracking is what turns an existing restart-when-empty line into the one
    # set_daily_restart writes today: the PATH its gamedig call needs (cron's is /usr/bin:/bin; the
    # distro's npm puts gamedig in /usr/local/bin), and — for a line from before #331 — a restart
    # only on a COUNTED 0 and the host's address, where the old line restarted on any failed query
    # and the oldest queried 127.0.0.1, which a Source server never answers: those restarted it
    # every day with players on it. It ran only when someone opened a server's
    # Scheduled Tasks, and set_daily_restart only when the operator toggled the setting — so an old
    # line kept doing that on every server nobody opened. app._node_tools_cron_pass runs it for each
    # game server at start and daily, with that server's game type and port (what set_daily_restart
    # is given). Driven with both workers stubbed; the first server raises, and the rest must still
    # be reached, as must every host's weekly gamedig cron.
    _ntp_app = sys.modules["app"]
    _ntp_up, _ntp_hosts = [], []
    _sv_ntp = (_sm_cron.upgrade_managed_cron_tracking, _ntp_app.ensure_node_tools_cron)

    def _ntp_upgrade(remote, user, selfname=None, game_type=None, port=None):
        _ntp_up.append((str(getattr(remote, "id", None)), str(user), str(selfname), str(game_type),
                        str(port)))
        if len(_ntp_up) == 1:
            raise RuntimeError("this host did not answer")
        return False
    try:
        _sm_cron.upgrade_managed_cron_tracking = _ntp_upgrade
        _ntp_app.ensure_node_tools_cron = lambda r: _ntp_hosts.append(r.id) or True
        _ntp_err = None
        try:
            _ntp_app._node_tools_cron_pass(app)
        except Exception as _e:          # reported by the check below, not left to end the suite
            _ntp_err = _e
        with app.app_context():
            _ntp_want = sorted((str(_g.remote_id), str(_g.short_name), str(_g.lgsm_name),
                                str(_g.game_type), str(_g.port))
                               for _g in GameServer.query.all() if _g.remote is not None)
            _ntp_all_hosts = sorted(_r.id for _r in RemoteServer.query.all())
        check("daily cron pass: every game server's crontab gets the in-place upgrade, with its own "
              "game type and port, even after one fails", _ntp_err is None and len(_ntp_want) >= 2 and sorted(_ntp_up) == _ntp_want,
              "raised %r; upgraded %r, servers %r" % (_ntp_err, sorted(_ntp_up)[:4], _ntp_want[:4]))
        check("daily cron pass: ...and every host still gets the weekly gamedig cron",
              bool(_ntp_all_hosts) and sorted(_ntp_hosts) == _ntp_all_hosts,
              "ensured %r, hosts %r" % (sorted(_ntp_hosts), _ntp_all_hosts))
    finally:
        _sm_cron.upgrade_managed_cron_tracking, _ntp_app.ensure_node_tools_cron = _sv_ntp

    # ...and the other caller, the Scheduled Tasks read, gives it the same two things. Without them
    # the upgrade keeps the line's own port and type, which is not what set_daily_restart would
    # write for this server once either has changed. The switches' columns are put back afterwards:
    # an empty listing reads as "both lines gone" to the reconcile, which is not under test here.
    _rt_up = []
    _sv_rt = (_sm_cron.upgrade_managed_cron_tracking, _sm_cron.list_cron_jobs)
    with app.app_context():
        _g = db.session.get(GameServer, gs_id)
        _rt_cols = (_g.autostart, _g.daily_restart)
        _rt_want = [(_g.short_name, _g.lgsm_name, _g.game_type, _g.port)]
    try:
        _sm_cron.upgrade_managed_cron_tracking = (
            lambda remote, user, selfname=None, game_type=None, port=None:
            _rt_up.append((user, selfname, game_type, port)) and False)
        _sm_cron.list_cron_jobs = lambda *a, **k: []
        _rt_resp = c.get("/api/server/%d/cron" % gs_id)
    finally:
        _sm_cron.upgrade_managed_cron_tracking, _sm_cron.list_cron_jobs = _sv_rt
        with app.app_context():
            _g = db.session.get(GameServer, gs_id)
            _g.autostart, _g.daily_restart = _rt_cols
            db.session.commit()
    check("cron page: opening Scheduled Tasks upgrades that server's crontab with its game type and "
          "port", _rt_resp.status_code == 200 and _rt_up == _rt_want and _rt_want[0][3] is not None,
          "status %s; upgraded %r, want %r" % (_rt_resp.status_code, _rt_up, _rt_want))

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

    # ── "do it now" and the command-list refresh are offered only to who can use them ──────────
    # Both rendered for anyone who could open the page. The banner's button calls the action
    # endpoint (RESTART_SERVER / STOP_SERVER), and refresh_server_commands wants MODERATE_SERVER,
    # SEND_COMMAND or MANAGE_SERVERS — so a view-only member was told "you can do it now" and
    # "use the refresh button above", and both buttons answered with a refusal.
    with app.app_context():
        _g = db.session.get(GameServer, gs_id)
        _g.restart_pending = True
        _vo_grp = Group(name="smoke-detail-viewonly")
        _vo_grp.set_permissions([auth.VIEW_SERVERS, auth.VIEW_CONSOLE])
        _vo_grp.game_servers.append(_g)
        db.session.add(_vo_grp)
        db.session.flush()
        _vo = User(username="detailviewer", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   is_superadmin=False, is_active=True)
        _vo.groups.append(_vo_grp)
        db.session.add(_vo)
        db.session.commit()
        _vo_id, _vo_gid = _vo.id, _vo_grp.id
    try:
        _vo_resp = client_as(_vo_id).get("/server/%d" % gs_id)
        _voh = _vo_resp.get_data(as_text=True)
        _adh = c.get("/server/%d" % gs_id).get_data(as_text=True)
        _refresh_url = "/server/%d/refresh-commands" % gs_id
        check("server page: an admin is offered the banner's 'do it now' and the command refresh "
              "(positive control)",
              'data-action="bannerDoNow"' in _adh and _refresh_url in _adh
              and "d-none" not in _banner_tag(_adh),
              "button=%s refresh=%s" % ('data-action="bannerDoNow"' in _adh, _refresh_url in _adh))
        check("server page: a view-only member sees the queued restart but no 'Restart now' button",
              _vo_resp.status_code == 200 and "d-none" not in _banner_tag(_voh)
              and 'data-action="bannerDoNow"' not in _voh
              and "or you can do it now" not in _voh,
              "status=%d banner shown=%s button=%s 'do it now' copy=%s"
              % (_vo_resp.status_code, "d-none" not in _banner_tag(_voh),
                 'data-action="bannerDoNow"' in _voh, "or you can do it now" in _voh))
        check("server page: ...nor the command-list refresh the route would refuse them",
              _refresh_url not in _voh and "Use the refresh button above" not in _voh,
              "the refresh form is rendered for a viewer without moderate/send_command/manage")
        # The button's permission follows the QUEUED action, which showPendingBanner() switches
        # without a reload. Gated once at render on whatever was queued then, a stop-only member
        # on a page with a restart (or nothing) queued had no button to reveal after queueing a
        # stop. It is rendered for either permission, hidden unless it matches the queued one,
        # with both permissions on the banner for the switch to read.
        def _rpb(html):
            def _first(pat, text, grp=0):
                _m = _re_ab.search(pat, text)
                return _m.group(grp) if _m else None
            _t = _banner_tag(html)
            return (_first(r'<button[^>]*id="rpb-do"[^>]*>', html),
                    _first(r'<span id="rpb-now"[^>]*>', html),
                    _first(r'data-can-stop="(\d)"', _t, 1), _first(r'data-can-restart="(\d)"', _t, 1))
        try:
            with app.app_context():
                db.session.get(Group, _vo_gid).set_permissions([auth.VIEW_SERVERS, auth.STOP_SERVER])
                db.session.commit()
            _so_btn, _so_now, _so_cs, _so_cr = _rpb(client_as(_vo_id).get("/server/%d" % gs_id).get_data(as_text=True))
            check("server page: a stop-only member with a RESTART queued still gets the banner button, "
                  "hidden, for the stop they may queue",
                  _so_btn is not None and "d-none" in _so_btn and _so_now is not None
                  and "d-none" in _so_now and (_so_cs, _so_cr) == ("1", "0"),
                  "button=%r clause=%r can-stop=%r can-restart=%r" % (_so_btn, _so_now, _so_cs, _so_cr))
            with app.app_context():
                _g = db.session.get(GameServer, gs_id)
                _g.restart_pending, _g.stop_pending = False, True
                db.session.commit()
            _so_btn, _so_now, _so_cs, _so_cr = _rpb(client_as(_vo_id).get("/server/%d" % gs_id).get_data(as_text=True))
            check("server page: ...and with a STOP queued it is shown, with the 'do it now' clause "
                  "(positive control)",
                  _so_btn is not None and "d-none" not in _so_btn
                  and _so_now is not None and "d-none" not in _so_now,
                  "button=%r clause=%r" % (_so_btn, _so_now))
            with app.app_context():
                db.session.get(Group, _vo_gid).set_permissions([auth.VIEW_SERVERS, auth.RESTART_SERVER])
                db.session.commit()
            _ro_btn, _ro_now, _ro_cs, _ro_cr = _rpb(client_as(_vo_id).get("/server/%d" % gs_id).get_data(as_text=True))
            check("server page: a restart-only member with a STOP queued is not offered 'Stop now' "
                  "(the button is there, hidden, for a restart they queue)",
                  _ro_btn is not None and "d-none" in _ro_btn and "d-none" in (_ro_now or "")
                  and (_ro_cs, _ro_cr) == ("0", "1"),
                  "button=%r clause=%r can-stop=%r can-restart=%r" % (_ro_btn, _ro_now, _ro_cs, _ro_cr))
        finally:
            with app.app_context():
                _g = db.session.get(GameServer, gs_id)
                _g.restart_pending, _g.stop_pending = True, False
                db.session.get(Group, _vo_gid).set_permissions([auth.VIEW_SERVERS, auth.VIEW_CONSOLE])
                db.session.commit()

        # The Live Console panel without VIEW_CONSOLE. /api/console answers 403 with no lines, and
        # "Load older" wiped the screen and toasted "Loaded 0 lines from the log". A viewer with
        # neither view_console nor send_command gets no console panel; one with send_command
        # alone keeps the command box but not the log controls, and is told why it is empty.
        check("server page: a view_console holder is given the log controls (control for the next)",
              'data-action="loadMoreConsole"' in _voh and 'data-panel="console"' in _voh,
              "the console panel is missing for a viewer who may read it")
        with app.app_context():
            db.session.get(Group, _vo_gid).set_permissions([auth.VIEW_SERVERS])
            db.session.commit()
        _voh2 = client_as(_vo_id).get("/server/%d" % gs_id).get_data(as_text=True)
        check("server page: without view_console or send_command there is no console panel",
              'data-panel="console"' not in _voh2 and 'data-action="loadMoreConsole"' not in _voh2
              and "_CAN_VIEW_CONSOLE = false" in _voh2,
              "panel=%s load-older=%s" % ('data-panel="console"' in _voh2,
                                          'data-action="loadMoreConsole"' in _voh2))
        with app.app_context():
            db.session.get(Group, _vo_gid).set_permissions([auth.VIEW_SERVERS, auth.SEND_COMMAND])
            db.session.commit()
        _voh3 = client_as(_vo_id).get("/server/%d" % gs_id).get_data(as_text=True)
        check("server page: send_command alone keeps the command box, not the log controls",
              'id="command-form"' in _voh3 and 'data-action="loadMoreConsole"' not in _voh3
              and "permission to view this server's console" in _voh3,
              "command box=%s load-older=%s notice=%s"
              % ('id="command-form"' in _voh3, 'data-action="loadMoreConsole"' in _voh3,
                 "permission to view this server's console" in _voh3))
    finally:
        with app.app_context():
            db.session.get(GameServer, gs_id).restart_pending = False
            _u = db.session.get(User, _vo_id)
            if _u is not None:
                _u.groups = []
                db.session.delete(_u)
            _gr = db.session.get(Group, _vo_gid)
            if _gr is not None:
                _gr.game_servers = []
                db.session.delete(_gr)
            db.session.commit()

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

        # A RESTART must not re-announce this morning's list. `hosts` is in memory only and
        # nothing persists it, so after a restart every host read (0, 0) and the 0 -> N edge fired
        # for every update already pending — ~30 s after boot, with the identical package list, on
        # any restart at all (the "Update now" button restarts the panel itself). The first pass
        # after boot seeds instead. Driven through the sweep's own state, since nothing outward
        # can see the window, and UNFORCED — that is how the ticker calls it.
        _pkgs["n"] = [{"name": "openssl", "suite": "jammy-security"}]
        _st_hosts.clear()
        _ps._os_update_state["last_run"] = 0.0      # as if the panel had just come back up
        _rec.clear()
        _osu()
        check("os updates: the first sweep after a restart seeds, it does not re-announce",
              "os_updates" not in _rec, str(_rec))
        check("os updates: ...and that sweep still records what is waiting",
              _st_hosts.get(remote_id) == (1, 1), str(dict(_st_hosts))[:120])
        # POSITIVE CONTROL: seeding must not be a mute button — a batch that appears AFTER it
        # still alerts, or "no repeat after a restart" would be satisfied by never alerting again.
        _pkgs["n"] = []
        _osu(force=True)                     # host patched -> re-arm
        _pkgs["n"] = [{"name": "bash", "suite": "jammy-updates"}]
        _rec.clear()
        _osu(force=True)
        check("os updates: ...and a batch that appears after the seeding pass still alerts",
              "os_updates" in _rec, str(_rec))
        _pkgs["n"] = []
        _osu(force=True)                     # leave the host clean for the checks below

        # ...and seeding is PER HOST. Only the first sweep after a restart seeded, so a host that
        # did not answer THAT sweep (rebooting, apt locked) read (0, 0) the next day and had the
        # list it already had before the restart announced again.
        from datetime import datetime as _sd_dt
        from panel.core.clock import utcnow as _sd_now
        with app.app_context():
            _sd_created = {r.id: r.created_at for r in RemoteServer.query.all()}
            for _sd_r in RemoteServer.query.all():
                _sd_r.created_at = _sd_dt(2020, 1, 1)      # hosts that existed before this process
            db.session.commit()
        try:
            _pkgs["n"] = [{"name": "openssl", "suite": "jammy-security"}]
            _st_hosts.clear()
            _ps._os_update_state["last_run"] = 0.0
            _am._host_reachable = lambda r: r.id != remote_id     # this one is down for the seed pass
            _rec.clear()
            _osu()
            _am._host_reachable = lambda r: True
            _rec.clear()
            _osu(force=True)
            check("os updates: a host that missed the seeding pass seeds on its first reading",
                  "os_updates" not in _rec and _st_hosts.get(remote_id) == (1, 1),
                  "alerts %r, state %r" % (_rec, _st_hosts.get(remote_id)))
            # POSITIVE CONTROL: a host ADDED since the panel started has had nothing announced, so
            # its first batch is news, not a seed.
            with app.app_context():
                db.session.get(RemoteServer, remote_id).created_at = _sd_now()
                db.session.commit()
            _st_hosts.pop(remote_id, None)
            _rec.clear()
            _osu(force=True)
            check("os updates: ...while a host added since the panel started has its first batch "
                  "announced (positive control)", "os_updates" in _rec, str(_rec))
        finally:
            _am._host_reachable = lambda r: True
            with app.app_context():
                for _sd_id, _sd_at in _sd_created.items():
                    _sd_row = db.session.get(RemoteServer, _sd_id)
                    if _sd_row is not None:
                        _sd_row.created_at = _sd_at
                db.session.commit()
            _pkgs["n"] = []
            _osu(force=True)                 # leave every host clean again

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

    # ── change-port: a panel bound to the host's own public/LAN address keeps its port OPEN ──
    # Only the wildcard counted as public, so binding to the host's public IP deleted the allow
    # rule for the port the panel was about to listen on — UFW's default-deny then shut it — and
    # the answer said "kept tailnet-only". Its own seeded is_local row: none survives to here.
    from panel.routes import remote_security as _rs_bind
    _bind_saved = (_rs_bind.remote_ufw_open_port, _rs_bind.remote_ufw_close_port,
                   _am.so.host_has_ip, _am.so.restart_panel, _am.so.ensure_panel_fail2ban)
    _bind_fw = []
    with app.app_context():
        _bind_lh = RemoteServer(name="smoke-bind-local", host="127.0.0.1", port=22,
                                username="root", auth_method="key", is_local=True)
        db.session.add(_bind_lh)
        db.session.commit()
        _bind_lh_id = _bind_lh.id
        _bind_cfg0 = _am.load_config()
    _bind_port = _bind_cfg0.get("port", 5000)
    try:
        _rs_bind.remote_ufw_open_port = lambda srv, port, proto=None, comment="": (
            _bind_fw.append(("open", port)), (True, ""))[1]
        _rs_bind.remote_ufw_close_port = lambda srv, port, proto=None: (
            _bind_fw.append(("close", port)), (True, ""))[1]
        _am.so.host_has_ip = lambda ip: True
        _am.so.restart_panel = lambda *a, **k: (True, "stubbed")
        _am.so.ensure_panel_fail2ban = lambda *a, **k: (True, "ok")

        def _bind_post(addr):
            del _bind_fw[:]
            _r = c.post("/api/panel/change-port", json={"port": _bind_port, "bind_host": addr})
            return _r.status_code, (_r.get_json(silent=True) or {}).get("message", "")
        _bst, _bmsg = _bind_post("203.0.113.5")
        check("change-port: binding to the host's own PUBLIC address opens its port, not closes it",
              _bst == 200 and ("open", _bind_port) in _bind_fw and ("close", _bind_port) not in _bind_fw,
              "status=%d fw=%r msg=%r" % (_bst, _bind_fw, _bmsg))
        check("change-port: ...and does not call that tailnet-only",
              "tailnet-only" not in _bmsg, _bmsg)
        # Positive control: a Tailscale address really is reached without the public rule.
        _bst, _bmsg = _bind_post("100.101.102.103")
        check("change-port: ...while a Tailscale address still closes the public port (positive control)",
              _bst == 200 and ("close", _bind_port) in _bind_fw and ("open", _bind_port) not in _bind_fw
              and "kept tailnet-only" in _bmsg, "status=%d fw=%r msg=%r" % (_bst, _bind_fw, _bmsg))
        # The REAL host_has_ip, with `ip -o addr` timing out. It answered True on an unreadable
        # list, so a typo'd bind was saved and the panel restarted onto an address it could not
        # bind — down until linuxgsm-panel-recover. The kernel is asked instead now (stubbed here:
        # this machine's addresses are not the test's).
        _bind_so_saved = (_am.so._run, _am.so._kernel_has_ip)
        _am.so.host_has_ip = _bind_saved[2]
        try:
            _am.so._run = lambda cmd, **k: (("", "Command timed out", -1) if "ip -o addr" in cmd
                                            else _bind_so_saved[0](cmd, **k))
            _am.so._kernel_has_ip = lambda addr: str(addr) == "100.101.102.103"
            _bind_before = _am.load_config().get("bind_host")
            _bst, _bmsg = _bind_post("10.0.0.51")
            check("change-port: an unreadable address list does not let a foreign bind through",
                  _bst == 400 and "isn't an address on this host" in _bmsg
                  and _am.load_config().get("bind_host") == _bind_before,
                  "status=%d msg=%r" % (_bst, _bmsg))
            _am.update_config(lambda cfg: cfg.update({"bind_host": "0.0.0.0"}))
            _bst, _bmsg = _bind_post("100.101.102.103")
            check("change-port: ...while the host's own address still goes through (control)",
                  _bst == 200, "status=%d msg=%r" % (_bst, _bmsg))
        finally:
            _am.so._run, _am.so._kernel_has_ip = _bind_so_saved
    finally:
        (_rs_bind.remote_ufw_open_port, _rs_bind.remote_ufw_close_port,
         _am.so.host_has_ip, _am.so.restart_panel, _am.so.ensure_panel_fail2ban) = _bind_saved
        def _bind_restore(cfg):
            cfg["port"] = _bind_port
            if "bind_host" in _bind_cfg0:
                cfg["bind_host"] = _bind_cfg0["bind_host"]
            else:
                cfg.pop("bind_host", None)
        try:
            _am.update_config(_bind_restore)
        except Exception:
            pass
        with app.app_context():
            _bind_row = db.session.get(RemoteServer, _bind_lh_id)
            if _bind_row is not None:
                db.session.delete(_bind_row)
                db.session.commit()

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
    from panel.security import banlist as _tt_bl
    import logging as _tt_logging

    class _TTLines(_tt_logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())
    # What data/auth.log receives — the file fail2ban's panel-login jail tails.
    _tt_h = _TTLines()
    _tt_logging.getLogger("panel.auth").addHandler(_tt_h)
    _tt_rs, _tt_calls = _tt_bl.refresh_soon, []
    _tt_bl.refresh_soon = lambda delay=3.0: _tt_calls.append(delay)
    _auth_mod._TOKEN_FAILS.clear()
    _auth_mod._TOKEN_BLOCK_AUDITED.clear()

    def _tt_audits():
        from panel.db.models import AuditLog as _TTAL
        with app.app_context():
            return _TTAL.query.filter_by(action="api_token_blocked").count()
    _tt_audit0 = _tt_audits()
    try:
        for _i in range(_auth_mod.TOKEN_MAX_FAILS):
            app.test_client().get("/api/servers", headers={"Authorization": "Bearer lgsm_deadbeef"})
        _tt_tokenlines = [ln for ln in _tt_h.lines if "api token" in ln]
        check("token throttle: misses UNDER the limit write nothing fail2ban counts (a stale-token "
              "script retrying is not banned at the firewall)", _tt_tokenlines == [],
              repr(_tt_tokenlines))
        _blocked = _bearer(_admin_tok)
        check("token throttle: a valid token is refused once its IP is blocked",
              _blocked.status_code != 200, "got %d" % _blocked.status_code)
        _tt_tokenlines = [ln for ln in _tt_h.lines if "api token" in ln]
        check("token throttle: a REFUSED attempt goes to auth.log as the line the jail counts",
              _tt_tokenlines == ["panel api token blocked from 127.0.0.1"], repr(_tt_tokenlines))
        check("token throttle: ...and is audited", _tt_audits() == _tt_audit0 + 1,
              "%d -> %d" % (_tt_audit0, _tt_audits()))
        _bearer(_admin_tok)
        check("token throttle: every refusal is a line, but the audit row is once per window",
              len([ln for ln in _tt_h.lines if "api token" in ln]) == 2
              and _tt_audits() == _tt_audit0 + 1, repr(_tt_h.lines))
        check("token throttle: no forwarded client, no ban-gate refresh", _tt_calls == [],
              repr(_tt_calls))
        app.test_client().get("/api/servers", headers={"Authorization": "Bearer lgsm_deadbeef",
                                                       "X-Forwarded-For": "203.0.113.50"})
        check("token throttle: a refusal that came through a proxy asks the ban gate to refresh",
              len(_tt_calls) == 1, repr(_tt_calls))
        check("token throttle: ...but a SESSION from the same IP still works",
              c.get("/api/servers").status_code == 200)
    finally:
        _auth_mod._TOKEN_FAILS.clear()
        _auth_mod._TOKEN_BLOCK_AUDITED.clear()
        _tt_bl.refresh_soon = _tt_rs
        _tt_logging.getLogger("panel.auth").removeHandler(_tt_h)
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

    # ── Revoking Discord's "Accept commands" has to bite at the next MESSAGE ──────────────────
    # _on_message froze the channel id and the permission into its default args at IDENTIFY time,
    # and a Discord Gateway session is deliberately long-lived — heartbeat every ~41s, reconnect
    # only on op 7/9 or a dropped socket. So unticking the box re-rendered the settings page and
    # changed nothing else: the next `!stop codserver` in that channel still stopped the server,
    # with an audit row attributed to discord:<username>, for minutes or for days, and the panel
    # could put no bound on the window. Moving the bot to a new, locked-down channel had the
    # mirror-image bug — the OLD channel kept control and the new one was ignored. The Telegram
    # twin has always re-read its gate on every poll.
    _dcg_cfg = {"discord": {"enabled": True, "accept_commands": True,
                            "bot_token": "enc", "channel_id": "999"}}
    _dcg_ran = []

    class _DcgStop(Exception):
        """Raised from the watch loop's own backoff sleep, which sits OUTSIDE its try/except — the
        one clean way out of a `while True:` that swallows every other exception."""

    class _DcgClock(object):
        def sleep(self, _secs):
            raise _DcgStop()

    def _dcg_gateway(_tok, on_message, **_k):
        """Stands in for discord_gateway_run: the session is now live and the handler is fixed for
        the whole of its lifetime, which is the window the bug lived in."""
        on_message("999", False, "!status")                 # still authorised
        _dcg_cfg["discord"]["accept_commands"] = False       # the superadmin unticks the box
        on_message("999", False, "!stop codserver")          # must not reach the dispatcher
        _dcg_cfg["discord"]["accept_commands"] = True
        _dcg_cfg["discord"]["channel_id"] = "1000"           # ...or moves the bot elsewhere
        on_message("999", False, "!stop codserver")          # the old channel loses control
        on_message("1000", False, "!hosts")                  # and the new one gains it

    _dcg_saved = (_notif._cfg, _notif.discord_gateway_run, _dcmod._dc_dispatch,
                  _dcmod.decrypt_secret, _dcmod.time)
    try:
        _notif._cfg = lambda: _dcg_cfg
        _notif.discord_gateway_run = _dcg_gateway
        _dcmod._dc_dispatch = lambda a, tok, chan, text, sender=None: _dcg_ran.append((chan, text))
        _dcmod.decrypt_secret = lambda s: "A" * 50
        _dcmod.time = _DcgClock()
        try:
            _dcmod._discord_command_watch(app)
        except _DcgStop:
            pass                      # one pass through the loop is the whole test
    finally:
        (_notif._cfg, _notif.discord_gateway_run, _dcmod._dc_dispatch,
         _dcmod.decrypt_secret, _dcmod.time) = _dcg_saved
    check("discord: a command in the authorised channel is honoured (positive control)",
          ("999", "!status") in _dcg_ran, "dispatched=%s" % (_dcg_ran,))
    check("discord: unticking 'Accept commands' takes effect at the next message, not the next "
          "socket drop",
          not any(_t.startswith("!stop") for _c, _t in _dcg_ran), "dispatched=%s" % (_dcg_ran,))
    check("discord: ...and moving the bot to another channel takes control off the old one",
          ("1000", "!hosts") in _dcg_ran
          and not any(_c == "999" and _t.startswith("!stop") for _c, _t in _dcg_ran),
          "dispatched=%s" % (_dcg_ran,))

    # ── /status must not print a player total it never managed to read ───────────────────────
    # The total was built with `isinstance(count, int)` as its only handling of the unknown case,
    # so a server the panel could not ask contributed nothing and the remainder was then stated as
    # a fact. Right after a restart _player_counts is empty because the poller has not completed a
    # pass, and six servers with forty people on them answered "Players online: 0". /servers, six
    # lines away in the same file, prints "?" for exactly this state.
    from panel.services.bots import commands as _btc
    _bps = sys.modules["panel.core.panel_state"]._player_counts
    _bps_saved = dict(_bps)
    with app.app_context():
        _bst_ids = [_g.id for _g in GameServer.query.filter_by(installed=True).all()]
    check("bots: /status has installed servers to report on (the checks below need them)",
          len(_bst_ids) >= 1, "%d installed — the /status checks would prove nothing" % len(_bst_ids))
    try:
        _bps.clear()                       # nothing polled yet: the window after a restart
        _bst_none = _btc._status_text(app)
        check("bots: /status says the player total could not be read, instead of printing 0",
              "Players online: 0" not in _bst_none and "couldn't be queried" in _bst_none,
              _bst_none)
        _bps.clear()
        for _i in _bst_ids:
            _bps[_i] = {"count": 3, "max": 16}
        _bst_all = _btc._status_text(app)
        check("bots: ...and a total it DID read is still printed plainly (positive control)",
              "couldn't be queried" not in _bst_all
              and ("Players online: %d" % (3 * len(_bst_ids))) in _bst_all, _bst_all)
        # An offline server is a REAL zero (monitoring writes count=0 for it without querying), so
        # this must not start reporting every stopped server as unreadable.
        _bps.clear()
        for _i in _bst_ids:
            _bps[_i] = {"count": 0, "max": 16}
        _bst_zero = _btc._status_text(app)
        check("bots: ...and a confirmed zero is still a zero, not an unknown",
              "couldn't be queried" not in _bst_zero and "Players online: 0" in _bst_zero,
              _bst_zero)
    finally:
        _bps.clear()
        _bps.update(_bps_saved)

    # ── A list reply has to be capped where it is BUILT, not sliced by the transport ──────────
    # _BOT_BODY_MAX exists with a comment saying it belongs in every variable-length builder, and
    # was applied in one of the four. On Discord the end of an uncapped body is discord_bot_send's
    # bare text[:1900] — a hard slice, no ellipsis, mid-word, mid-row — so a panel with ~45 servers
    # answered !servers with a list that stopped part-way through a name and was missing roughly
    # the last ten, with nothing saying so.
    _cap_rows = ["row %03d %s" % (_i, "x" * 60) for _i in range(200)]
    _cap_body = _btc._join_capped(_cap_rows)
    _cap_lines = _cap_body.splitlines()
    check("bots: a long list reply fits one Discord message and says how many rows it dropped",
          len(_cap_body) < 1900 and _cap_lines[0].startswith("row 000")
          and _cap_lines[-1] == "… and %d more" % (200 - (len(_cap_lines) - 1)),
          "%d chars, %d lines, last=%r" % (len(_cap_body), len(_cap_lines), _cap_lines[-1:]))
    check("bots: ...and a list that already fits is left exactly as it was (positive control)",
          _btc._join_capped(["a", "b", "c"]) == "a\nb\nc",
          repr(_btc._join_capped(["a", "b", "c"])))
    import inspect as _bot_inspect
    for _capfn in ("_players_text", "_servers_text", "_hosts_text"):
        check("bots: %s caps its body before the transport can slice it" % _capfn,
              "_join_capped" in _bot_inspect.getsource(getattr(_btc, _capfn)),
              "uncapped — discord_bot_send will cut this at 1900 characters, mid-row")

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
    _lat_cmds, _lat_seen, _lat_kw = [], [], []

    def _lat_emit(event, payload=None, **kw):
        _lat_seen.append((event, payload, kw.get("room")))

    _lat_sio_saved = app.socketio.emit
    try:
        app.socketio.emit = _lat_emit

        # 1. The command LinuxGSM is asked to run, and what was registered while it ran.
        _lat_during = []

        def _lat_rag(remote, short, cmd, *a, **k):
            _lat_cmds.append(cmd)
            _lat_kw.append(dict(k))
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
        # The route used to hand run_as_game_user a whole shell line — the action, a redirect into
        # this file, a `cat` and an `exit $rc` — which is exactly why that call could not route
        # through a privileged verb. It passes the ACTION plus tee_log now, and run_as_game_user
        # renders the redirect (remote) or the helper writes the file itself (local). Both derive
        # the path from the same two values _action_log_path does; part05 holds that check and the
        # rendering ones, so what this asserts is that the ROUTE still asks for the tee'd log.
        check("long action: it asks for output tee'd through a file the console can tail",
              _lat_kw and _lat_kw[0].get("tee_log") is True,
              "kwargs %r" % (_lat_kw[0] if _lat_kw else None))
        check("long action: ...and passes a bare LinuxGSM action, not a shell fragment",
              _lat_cmds and _lat_cmds[0] == "update",
              "ran %r" % (_lat_cmds[0] if _lat_cmds else None))
        # ...and the whole output must still come BACK to this thread: the audit log entry and the
        # chat bots' completion message are both built from it, so a tee that swallowed it would
        # trade one silence for another. The stub above returns output, and the completion marker
        # checked below is built from it.
        check("long action: fastdl is the one that also needs its prompts answered",
              _lat_kw and "answers" in _lat_kw[0],
              "kwargs %r" % (_lat_kw[0] if _lat_kw else None))
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
        # Same vacuity guard: with no console_output captured, all(...) over the empty filter is
        # True and the room assertion tests nothing.
        _lat_rooms = [r for (e, p, r) in _lat_seen if e == "console_output"]
        check("long action: console_output was actually captured, so the room check sees some",
              len(_lat_rooms) >= 1, "no console_output events — the next check would be vacuous")
        check("long action: the markers go to THIS server's console room only",
              _lat_rooms and all(r == "console_%d" % gs_id for r in _lat_rooms),
              "rooms=%s" % _lat_rooms)

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

        # 2b. TWO long actions on one server, which nothing serialises: every maintenance button
        # posts /api/server/<id>/action, the route hands a LONG_ACTION to a thread and answers
        # within a second, and the button re-enables itself. _action_output is keyed by server_id
        # alone, so the second registration overwrites the first — and _end_action_tail popped
        # whatever was registered rather than its OWN entry. The shorter action finishing therefore
        # deregistered the one still running: every later poller tick returned immediately, so the
        # ten-minute SteamCMD download the panel had just told the operator to watch streamed
        # nothing at all, and the update's own final drain then found no entry either, losing the
        # last and most interesting lines as well.
        with app.app_context():
            _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
            _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)   # overwrites it
            _end_action_tail(app, gs_id, _lat_remote, "validate", 0)         # the OTHER one ends
            _lat_after_other = dict(_ao.get(gs_id) or {})
            _end_action_tail(app, gs_id, _lat_remote, "update", 0)           # ...then its owner
            _lat_after_own = dict(_ao.get(gs_id) or {})
        check("console tail: an action that ends does not deregister a DIFFERENT one still running",
              _lat_after_other.get("action") == "update",
              "left %r registered — the running update's output stops reaching the console the "
              "panel told the operator to watch" % (_lat_after_other or None,))
        # 2c. ...and two runs of the SAME action, each on its own worker, as _bg_action runs them.
        # Ownership was decided by the action NAME, so the first validate to finish popped the
        # registration of the second, still running. Each worker now ends only its own entry.
        import threading as _lat_thr
        _lat_go1, _lat_go2, _lat_b1, _lat_b2 = (_lat_thr.Event() for _ in range(4))

        def _lat_worker(began, go):
            with app.app_context():
                _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
                began.set()
                go.wait(10)
                _end_action_tail(app, gs_id, _lat_remote, "validate", 0)
        _lat_t1 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b1, _lat_go1))
        _lat_t1.start()
        _lat_b1.wait(10)
        _lat_t2 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b2, _lat_go2))
        _lat_t2.start()
        _lat_b2.wait(10)
        _lat_second = _ao.get(gs_id)
        _lat_go1.set()
        _lat_t1.join(10)                                   # the FIRST run finishes
        _lat_still = _ao.get(gs_id)
        _lat_go2.set()
        _lat_t2.join(10)
        check("console tail: a run that ends does not deregister a later run of the SAME action",
              _lat_second is not None and _lat_still is _lat_second,
              "after the first validate ended, %r was registered (the second run's entry was %r)"
              % (_lat_still, _lat_second))
        check("console tail: ...and that later run still deregisters itself when it ends",
              gs_id not in _ao, "left %r registered" % (_ao.get(gs_id),))
        # The other order, the finding's: the LATER run is refused fast and finishes first. It
        # had displaced the earlier run's registration, so popping it left the earlier validate —
        # still running — streaming nothing. The earlier run is registered again instead.
        _lat_go1, _lat_go2, _lat_b1, _lat_b2 = (_lat_thr.Event() for _ in range(4))
        _lat_t1 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b1, _lat_go1))
        _lat_t1.start()
        _lat_b1.wait(10)
        _lat_first = _ao.get(gs_id)
        _lat_t2 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b2, _lat_go2))
        _lat_t2.start()
        _lat_b2.wait(10)
        _lat_go2.set()
        _lat_t2.join(10)                                   # the LATER run finishes first
        _lat_back = _ao.get(gs_id)
        _lat_go1.set()
        _lat_t1.join(10)
        check("console tail: when the later run ends first, the earlier one still running is tailed again",
              _lat_first is not None and _lat_back is _lat_first,
              "after the second validate ended, %r was registered (the first run's entry was %r)"
              % (_lat_back, _lat_first))
        check("console tail: ...and once both have ended nothing is left registered",
              gs_id not in _ao, "left %r registered" % (_ao.get(gs_id),))
        # How an action that the TRANSPORT gave up on is announced. The local and Tailscale
        # transports answer a timeout with rc -1 (they do not raise), and so does paramiko's
        # silent-channel give-up; only a raise leaves rc None. -1 is never a real exit status.
        _lat_end = {}
        with app.app_context():
            for _lat_rc in (None, -1, 2, 0):
                _lat_seen.clear()
                _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)
                _end_action_tail(app, gs_id, _lat_remote, "update", _lat_rc)
                _lat_end[_lat_rc] = " ".join(p.get("data") or "" for (e, p, r) in _lat_seen
                                             if e == "console_output")
        check("console tail: a transport timeout (rc -1) is 'stopped reporting', not 'failed'",
              "stopped reporting" in _lat_end[-1] and "failed" not in _lat_end[-1],
              "said %r — an update still running on the host was declared failed" % _lat_end[-1])
        check("console tail: ...as a raised call (rc None) already was",
              "stopped reporting" in _lat_end[None], _lat_end[None])
        check("console tail: ...while a real non-zero exit is still a failure, and 0 a success",
              "failed (exit 2)" in _lat_end[2] and "finished successfully" in _lat_end[0],
              "2=%r 0=%r" % (_lat_end[2], _lat_end[0]))
        check("console tail: ...and the action that owns the entry still clears it (positive control)",
              not _lat_after_own,
              "still registered: %r — the poller would tail a finished action forever, so the "
              "check above would pass with the pop removed altogether" % (_lat_after_own,))

        # 3. The CALLER. Every assertion above passes just as well with a drain nothing invokes —
        # which is exactly the shape of the original bug. So drive the real console poller: give
        # it a viewer, register an action, and wait for the bytes to come out of it.
        _lat_seen.clear()
        _lat_file["text"] = "SteamCMD: validating\n"
        with _r_sf._viewers_lock:
            # {sid: user_id} now — the poller re-checks each viewer's access every tick,
            # so a viewer entry has to say WHOSE socket it is. None means "unknown", which
            # the re-check treats as not-allowed; this block is about the action tail, so
            # give it the seeded admin so it is not evicted mid-test.
            _r_sf._console_viewers.setdefault(gs_id, {})["test-sid"] = admin_id
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

    # ── a JSON field of the wrong TYPE is a bad request, not a panel fault ─────────────────────
    # _json_body guarantees the BODY is a dict and says nothing about the VALUES, so two dozen
    # handlers read `(body.get(k) or "").strip()` — safe against a missing key, and an
    # AttributeError on {"command": 5}. Every one answered 500 with "Something went wrong — see
    # the panel log", which is the panel accusing itself of a bug the caller caused, and which
    # makes 5xx alerting fire on a malformed request. Driven as a superadmin against every
    # mutating JSON endpoint the review named, with a NUMBER where a string belongs.
    # ── what the ban-watcher RECORDS, and at what threshold ──────────────────────────────────
    # The false notifications were half of what the unreadable-jail bug produced: an "IP banned on
    # the panel login" message per live ban, then a "Login attack in progress" alert once three
    # arrived together. _f2b_ban_events decides; this is what it emits, driven directly rather
    # than through the daemon thread.
    import app as _fre
    from panel.db.models import AuditLog as _fre_AL
    _fre_notes = []
    _fre_saved = _fre.notifications.notify
    try:
        _fre.notifications.notify = lambda ev, title, body, **k: _fre_notes.append((ev, title))
        with app.app_context():
            _n_before = _fre_AL.query.filter(_fre_AL.action.in_(
                ("fail2ban_ban", "fail2ban_unban"))).count()
        _fre._f2b_record_events(app, (), ())
        with app.app_context():
            _n_noop = _fre_AL.query.filter(_fre_AL.action.in_(
                ("fail2ban_ban", "fail2ban_unban"))).count()
        check("ban watcher: a tick with no events writes nothing and notifies nobody",
              _n_noop == _n_before and not _fre_notes, "rows %d->%d notes=%r"
              % (_n_before, _n_noop, _fre_notes))
        # Two bans is under the spike threshold: audit rows and per-IP notices, no attack alert.
        _fre._f2b_record_events(app, ("203.0.113.1", "203.0.113.2"), ("203.0.113.9",))
        with app.app_context():
            _bans = _fre_AL.query.filter_by(action="fail2ban_ban").count()
            _unbans = _fre_AL.query.filter_by(action="fail2ban_unban").count()
        check("ban watcher: real events are audited, bans and unbans alike",
              _bans >= 2 and _unbans >= 1, "bans=%d unbans=%d" % (_bans, _unbans))
        check("ban watcher: ...with one notice per banned IP",
              [e for e, _t in _fre_notes].count("ip_banned") == 2, repr(_fre_notes))
        check("ban watcher: ...and no attack alert below the spike threshold",
              "ban_spike" not in [e for e, _t in _fre_notes], repr(_fre_notes))
        # ...and at the threshold it fires exactly once.
        _fre_notes.clear()
        _fre._f2b_record_events(
            app, tuple("203.0.113.%d" % i for i in range(20, 20 + _fre._BAN_SPIKE_THRESHOLD)), ())
        check("ban watcher: a burst at the threshold raises one attack alert",
              [e for e, _t in _fre_notes].count("ban_spike") == 1, repr(_fre_notes))
    finally:
        _fre.notifications.notify = _fre_saved

    # ── the auto-block SETTINGS survive a host read that failed ───────────────────────────────
    # They come from config.json, not from the host, and they were inside the same try as the IP
    # read — so an exception answered {"ips": [], "error": ...} with no `autoblock` key, the card
    # repainted its toggle from the missing value (`!!(d && d.autoblock)`) and showed OFF, and
    # saveThreshold reads that toggle back "to preserve the on/off state". One failed read plus
    # one Save turned auto-blocking off on a host that had it on.
    import panel.ops.system_ops as _so_ab
    _ab_saved = _so_ab.fail2ban_top_ips
    try:
        _so_ab.fail2ban_top_ips = lambda *a, **k: (_ for _ in ()).throw(OSError("log unreadable"))
        _abj = (c.get("/api/panel/security/top-ips").get_json() or {})
        check("security card: a failed offender read still reports the auto-block setting",
              "autoblock" in _abj and "threshold" in _abj, str(_abj)[:160])
        check("security card: ...and says the log was unreadable rather than showing no activity",
              bool(_abj.get("error") or _abj.get("unreadable")), str(_abj)[:160])
        # None (the reader's "I could not read") is the same answer, without an exception.
        _so_ab.fail2ban_top_ips = lambda *a, **k: None
        _abj2 = (c.get("/api/panel/security/top-ips").get_json() or {})
        check("security card: a None offender read is flagged unreadable, not 'no activity'",
              _abj2.get("unreadable") is True and "autoblock" in _abj2, str(_abj2)[:160])
        # positive control: a real read still answers with the list and the settings.
        _so_ab.fail2ban_top_ips = lambda *a, **k: [{"ip": "203.0.113.5", "attempts": 3, "bans": 1}]
        _abj3 = (c.get("/api/panel/security/top-ips").get_json() or {})
        check("security card: a real read reports the offenders and is not flagged unreadable",
              len(_abj3.get("ips") or []) == 1 and not _abj3.get("unreadable")
              and "autoblock" in _abj3, str(_abj3)[:160])
    finally:
        _so_ab.fail2ban_top_ips = _ab_saved

    # The remote route is the same code with a different reader, and it had the same bug — so it
    # gets the same check rather than being taken on the strength of the panel-host one passing.
    import panel.routes.remote_security as _rs_ab
    _rs_saved = _rs_ab.remote_fail2ban_top_ips
    try:
        _rs_ab.remote_fail2ban_top_ips = lambda *a, **k: None
        _rabj = (c.get("/api/remote/%d/security/top-ips" % remote_id).get_json() or {})
        check("security card (remote): an unreadable log still reports the auto-block setting",
              "autoblock" in _rabj and _rabj.get("unreadable") is True, str(_rabj)[:160])
        _rs_ab.remote_fail2ban_top_ips = lambda *a, **k: [{"ip": "203.0.113.9", "attempts": 1}]
        _rabj2 = (c.get("/api/remote/%d/security/top-ips" % remote_id).get_json() or {})
        check("security card (remote): a real read is not flagged unreadable (positive control)",
              len(_rabj2.get("ips") or []) == 1 and not _rabj2.get("unreadable"), str(_rabj2)[:160])
    finally:
        _rs_ab.remote_fail2ban_top_ips = _rs_saved

    _typed = [
        ("/api/command/%d" % gs_id, {"command": 5}),
        ("/api/server/%d/action" % gs_id, {"action": 5}),
        ("/api/servers/bulk-action", {"action": 5, "ids": [gs_id]}),
        ("/api/server/%d/query-type" % gs_id, {"query_type": 5}),
        ("/api/server/%d/moderate" % gs_id, {"action": 5}),
        ("/api/server/%d/alerts" % gs_id, {"values": 5}),
        ("/api/server/%d/config" % gs_id, {"raw": 5}),
        ("/api/server/%d/mods" % gs_id, {"action": "install", "mod": 5}),
        ("/api/tags", {"name": 5}),
        ("/api/panel/security/block", {"ip": 5}),
        ("/api/panel/security/whitelist", {"ip": 5, "action": "add"}),
        ("/api/panel/backup/delete", {"name": 5}),
        ("/api/panel/backup/full", {"mode": 5}),
        ("/api/remote/%d/security/block" % remote_id, {"ip": 5}),
        ("/api/remote/%d/security/unban" % remote_id, {"jail": 5, "ip": 5}),
        ("/api/remote/%d/pro-service" % remote_id, {"service": 5, "action": 5}),
        ("/api/remote/%d/tailscale-bootstrap" % remote_id, {"auth_key": 5}),
        ("/api/tailscale/check-peer", {"host": 5}),
        ("/api/remote/%d/import" % remote_id, {"servers": [{"user": "u", "game_type": 5}]}),
        ("/api/notifications/test", {"channel": 5}),
    ]
    _typed_500, _typed_404 = [], []
    # Hold the backup lock across the sweep. /api/panel/backup/full is in the list and a POST to
    # it STARTS A REAL FULL BACKUP — a thread that outlives this block, walks every installed
    # server, and calls run_game_backup on whatever that name points at by the time it gets
    # there. It landed inside the per-server-retention test 1400 lines below, which stubs exactly
    # that name, and reported the stray call's keep as the one the route had used. Only the
    # slowest CI leg was slow enough to show it.
    #
    # Taken BLOCKING, so this also waits out any earlier straggler instead of racing it. mode is
    # read before the lock is consulted, so the type handling under test is still exercised.
    from panel.core.panel_state import _full_backup_lock as _typed_lock
    import panel.routes.panel_backup as _typed_bkmod
    # What a leaked worker DOES, recorded — not whether the lock happens to be held when asked.
    # The first version of this check polled the lock, and a full backup of one unreachable
    # server takes and releases it inside a single 50ms gap: removing the guard below left the
    # check green. See a-green-gate-is-not-evidence.
    _typed_bkcalls = []
    _typed_bkreal = _typed_bkmod.run_game_backup
    _typed_bkmod.run_game_backup = lambda *a, **k: (_typed_bkcalls.append(1), (True, "", False))[1]
    _typed_lock.acquire(timeout=60)
    try:
        for _path, _body in _typed:
            _tr = c.post(_path, json=_body, headers={"X-Requested-With": "XMLHttpRequest"})
            if _tr.status_code >= 500:
                _typed_500.append("%s -> %d" % (_path, _tr.status_code))
            if _tr.status_code == 404:
                _typed_404.append(_path)
    finally:
        try:
            _typed_lock.release()
        except RuntimeError:
            pass        # the acquire timed out; nothing of ours to release
    # Settle: a worker the sweep started returns from the route before it reaches the backup.
    for _ in range(40):
        if _typed_bkcalls:
            break
        _ijw_time.sleep(0.05)
    _typed_bkmod.run_game_backup = _typed_bkreal
    check("typed body: %d endpoints were driven, so this is not an empty sweep" % len(_typed),
          len(_typed) >= 20, "the list shrank — the check below would prove less")
    # ...and every one of them REACHES a handler. This list had "/notifications/test" while the
    # route is "/api/notifications/test", so Flask answered 404 — which is < 500, so the sweep
    # passed, and the count above reported it as driven. The endpoint's body was entered by
    # nothing in the suite while looking covered. Counting the LIST proves the list is long; only
    # this proves the paths still resolve, which is what a future rename would break.
    check("typed body: ...and every path in that list actually resolves to a route",
          not _typed_404,
          "404 — renamed or mistyped, so the sweep never reached them: %s" % ", ".join(_typed_404))
    check("typed body: a number where a string belongs never 500s",
          not _typed_500, "; ".join(_typed_500[:6]))
    # ...and the sweep left nothing running. A POST to /api/panel/backup/full starts a real
    # background full backup, and a suite that walks endpoints for validation must not leave one
    # RUNNING behind it — that thread outlives this block and calls into whatever the tests below
    # have stubbed by the time it gets there. That is what broke CI: it reached the
    # per-server-retention test 1400 lines down and was counted as that route's call.
    check("typed body: ...and the sweep did not leave a full backup running behind it",
          not _typed_bkcalls,
          "a background backup outlived this block — it walks every server and calls whatever "
          "run_game_backup points at by then, which is a stub in the tests below")

    # ── Deleting a user kills the invites they minted ──────────────────────────────────────────
    # authority_intact() resolves the creator with db.session.get(User, created_by_id) and fails
    # closed when it is gone — "a missing creator fails closed: the row is deleted or the id
    # dangles". But user.id is a bare INTEGER PRIMARY KEY, so SQLite hands the freed rowid to the
    # very next account created: the creator is then not missing, it is a DIFFERENT PERSON, and
    # the check says yes. Offboard an admin, create their replacement, and the dead invite is live
    # again — for a superadmin invite as soon as that replacement is promoted, which is exactly
    # what happens in that scenario. manage_users lists it as "Active" throughout.
    from panel.db.models import Invite as _InvS
    with app.app_context():
        _ivu = User(username="smoke_inviter", password_hash=auth.hash_password("Str0ng!passw0rd"),
                    is_superadmin=True, is_active=True)
        db.session.add(_ivu)
        db.session.commit()
        _ivu_id = _ivu.id
        _inv_row, _ = _InvS.mint(_ivu, hours=48, superadmin=True)
        db.session.add(_inv_row)
        # ...and an audit entry attributed to them, for the AuditLog half of the same delete.
        db.session.add(_AL(user_id=_ivu_id, username="smoke_inviter", action="login",
                           target="", detail="", success=True))
        db.session.commit()
        _inv_id = _inv_row.id
        check("invite: it is usable while its creator exists",
              _inv_row.is_usable and _inv_row.authority_intact(db.session.get(User, _ivu_id)),
              "the next check would prove nothing otherwise")
        db.session.delete(db.session.get(User, _ivu_id))
        db.session.commit()
        _inv_after = db.session.get(_InvS, _inv_id)
        check("invite: deleting its creator revokes it", _inv_after.revoked_at is not None,
              "revoked_at=%r" % _inv_after.revoked_at)
        check("invite: ...so it is not usable", not _inv_after.is_usable)
        # And prove the resurrection route really is open: take the recycled id deliberately.
        _heir = User(id=_ivu_id, username="smoke_replacement",
                     password_hash=auth.hash_password("Str0ng!passw0rd"),
                     is_superadmin=True, is_active=True)
        db.session.add(_heir)
        db.session.commit()
        check("invite: the replacement account really does take the freed id",
              _heir.id == _ivu_id, "id=%d want=%d" % (_heir.id, _ivu_id))
        check("invite: ...and authority_intact now says YES about a different person",
              _inv_after.authority_intact(db.session.get(User, _ivu_id)) is True,
              "if this ever says False the revocation above is no longer what closes the hole")
        check("invite: ...but the stamped revocation still holds", not _inv_after.is_usable,
              "a rowid cannot undo revoked_at")
        # Same delete, the other dangling pointer: AuditLog.user_id is a FK with no cascade, the
        # app never sets PRAGMA foreign_keys, and the rowid is recycled — so the deleted admin's
        # entries pointed at their replacement. The entries themselves must SURVIVE (username is
        # the auditable fact and is meant to outlive the account); only the pointer must not lie.
        _al_rows = _AL.query.filter_by(username="smoke_inviter").count()
        check("audit: the deleted user's entries are still there", _al_rows >= 1,
              "no rows to check — the next check would pass vacuously")
        check("audit: ...but none of them still points at the recycled id",
              _AL.query.filter_by(user_id=_ivu_id).count() == 0,
              "%d row(s) now resolve to smoke_replacement"
              % _AL.query.filter_by(user_id=_ivu_id).count())
        db.session.delete(db.session.get(_InvS, _inv_id))
        db.session.delete(db.session.get(User, _ivu_id))
        db.session.commit()

    # ── ...and deleting a GROUP kills the invites that grant it, for the same reason ────────────
    # Invite.group_ids is a JSON list of bare Group.id integers, frozen at mint time and resolved
    # at redemption purely by id — and Group.id is the same bare INTEGER PRIMARY KEY with the same
    # rowid recycling. Nothing downstream catches it: redeem_invite's group re-check is guarded by
    # `if _creator is not None and not _creator.is_superadmin`, and minting is @superadmin_required,
    # so for a creator who is still a superadmin the check is skipped and user.groups is assigned
    # from whatever rows hold those ids now. Driven with the freed id taken deliberately, the same
    # way the user half above proves its own resurrection route is open.
    with app.app_context():
        _gi_creator = User.query.filter_by(is_superadmin=True).first()
        _gi_grp = Group(name="smoke_trial_group", description="smoke (auto)", is_default=False)
        _gi_grp.set_permissions([auth.VIEW_SERVERS])
        db.session.add(_gi_grp)
        db.session.commit()
        _gi_gid = _gi_grp.id
        _gi_inv, _ = _InvS.mint(_gi_creator, hours=48, group_ids=[_gi_gid])
        db.session.add(_gi_inv)
        db.session.commit()
        _gi_iid = _gi_inv.id
        check("invite: it is usable while the group it grants exists",
              _gi_inv.is_usable and _gi_inv.groups_wanted == [_gi_gid],
              "the next check would prove nothing otherwise")
        db.session.delete(db.session.get(Group, _gi_gid))
        db.session.commit()
        _gi_after = db.session.get(_InvS, _gi_iid)
        check("invite: deleting a group it grants revokes it",
              _gi_after.revoked_at is not None, "revoked_at=%r" % _gi_after.revoked_at)
        check("invite: ...so it is not usable", not _gi_after.is_usable)
        # The resurrection route really is open: take the freed rowid with a group that grants far
        # more than the deleted one did.
        _gi_heir = Group(id=_gi_gid, name="smoke_server_owners", description="smoke (auto)",
                         is_default=False)
        _gi_heir.set_permissions([auth.MANAGE_USERS, auth.MANAGE_REMOTES, auth.MANAGE_SERVERS])
        db.session.add(_gi_heir)
        db.session.commit()
        check("invite: the replacement group really does take the freed id",
              _gi_heir.id == _gi_gid, "id=%d want=%d" % (_gi_heir.id, _gi_gid))
        check("invite: ...but the stamped revocation still holds", not _gi_after.is_usable,
              "a rowid cannot undo revoked_at")
        # Positive control: an invite that names OTHER groups is untouched by the delete, so the
        # listener is a targeted revoke and not a blanket one.
        _gi_keep = Group(name="smoke_keep_group", description="smoke (auto)", is_default=False)
        _gi_keep.set_permissions([auth.VIEW_SERVERS])
        db.session.add(_gi_keep)
        db.session.commit()
        _gi_keep_id = _gi_keep.id
        _gi_doomed = Group(name="smoke_doomed_group", description="smoke (auto)", is_default=False)
        _gi_doomed.set_permissions([auth.VIEW_SERVERS])
        db.session.add(_gi_doomed)
        db.session.commit()
        _gi_bystander, _ = _InvS.mint(_gi_creator, hours=48, group_ids=[_gi_keep_id])
        db.session.add(_gi_bystander)
        db.session.commit()
        _gi_by_id = _gi_bystander.id
        db.session.delete(db.session.get(Group, _gi_doomed.id))
        db.session.commit()
        check("invite: deleting an unrelated group leaves other invites alone",
              db.session.get(_InvS, _gi_by_id).is_usable,
              "a targeted revoke turned into a blanket one")
        db.session.delete(db.session.get(_InvS, _gi_iid))
        db.session.delete(db.session.get(_InvS, _gi_by_id))
        db.session.delete(db.session.get(Group, _gi_gid))
        db.session.delete(db.session.get(Group, _gi_keep_id))
        db.session.commit()

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
    # ...and a metric sample for that game server. _prune_host_game_samples listens on
    # RemoteServer's after_delete and deletes by `server_id IN (SELECT id FROM game_server WHERE
    # remote_id = ...)` — but delete_remote BULK-deletes the game servers first, so by the time it
    # fires the subquery matches nothing. Both rowids are then recycled and the next server created
    # serves the deleted one's history on /api/server/<id>/history for the 14-day prune window.
    from panel.db.models import MetricSample as _dr_MS
    from panel.core.clock import utcnow as _utcnow_mon
    with app.app_context():
        db.session.add(_dr_MS(server_id=_dr_gid, ts=_utcnow_mon(),
                              cpu=99.0, ram_mb=512, players=7))
        db.session.commit()
        _dr_samples_before = _dr_MS.query.filter_by(server_id=_dr_gid).count()
    check("delete host: the sample fixture armed", _dr_samples_before >= 1,
          "no MetricSample row — the check after the delete would pass vacuously")
    # ...and a saved LAYOUT position for both. ui_prefs holds host_order (remote ids) and
    # server_order ({remote_id: [server id]}), and nothing cleared them — so after the rowid is
    # recycled a brand-new host or server inherited the deleted one's slot in every user's
    # dashboard, for every user who had ever reordered.
    with app.app_context():
        _dr_u = User.query.filter_by(username="smoke_admin").first()
        _dr_u.set_ui_pref("host_order", [_dr_rid, 99999])
        _dr_u.set_ui_pref("server_order", {str(_dr_rid): [_dr_gid]})
        db.session.commit()
        _dr_prefs_before = _dr_u.get_ui_prefs()
    check("delete host: the layout fixture armed",
          _dr_rid in (_dr_prefs_before.get("host_order") or []),
          "no saved order — the check after the delete would pass vacuously")
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
    with app.app_context():
        _dr_samples_after = _dr_MS.query.filter_by(server_id=_dr_gid).count()
    with app.app_context():
        _dr_prefs_after = User.query.filter_by(username="smoke_admin").first().get_ui_prefs()
    check("delete host: it is gone from every saved dashboard order",
          _dr_rid not in (_dr_prefs_after.get("host_order") or [])
          and str(_dr_rid) not in (_dr_prefs_after.get("server_order") or {}),
          "still placed: %s / %s" % (_dr_prefs_after.get("host_order"),
                                     list(_dr_prefs_after.get("server_order") or {})))
    check("delete host: ...while another user's unrelated entries are left alone",
          99999 in (_dr_prefs_after.get("host_order") or []),
          "the sweep removed more than the deleted host: %s" % (_dr_prefs_after.get("host_order"),))
    check("delete host: its game servers' metric history goes with it",
          _dr_samples_after == 0,
          "%d sample(s) left — a recycled server id would serve the deleted one's history"
          % _dr_samples_after)
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

            # ── access is re-checked while the socket is OPEN ─────────────────────────────────
            # The join handler's check was the only one. After it passed, the poller streamed to
            # the room for as long as the browser stayed connected, so revoking a group, dropping
            # a permission or deactivating the account did not stop console output already
            # flowing. _evict_unauthorized_viewers is what the poller calls each tick.
            with _r_sf._viewers_lock:
                _r_sf._console_viewers[gs_id] = {"still-allowed": admin_id,
                                                 "gone-user": 10 ** 7,   # no such row
                                                 "unknown-user": None}
            with app.app_context():
                _n_dropped = _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
            _left = dict(_r_sf._console_viewers.get(gs_id) or {})
            check("console socket: a viewer whose account no longer exists is dropped mid-stream",
                  "gone-user" not in _left and "unknown-user" not in _left,
                  "still watching: %r" % (_left,))
            check("console socket: ...and the viewer who still qualifies is left alone",
                  "still-allowed" in _left, "still watching: %r" % (_left,))
            check("console socket: ...and it reports how many it dropped",
                  _n_dropped == 2, "dropped=%r" % (_n_dropped,))
            # ...and when the last qualifying viewer goes, the entry goes with it, so the poller
            # stops SSH-ing at the host on nobody's behalf.
            with app.app_context():
                _r_sf._console_viewers[gs_id] = {"gone-user": 10 ** 7}
                _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
            check("console socket: ...and an emptied console stops being polled at all",
                  not _r_sf._console_viewers.get(gs_id),
                  "left behind: %r" % (_r_sf._console_viewers.get(gs_id),))
            # A re-check that THREW must not evict. This runs every couple of seconds against the
            # database; a transient failure that dropped every viewer would turn a blip into
            # "the console stopped working", which is worse than the revocation being a tick late.
            # Unknown is not "revoked" — the same asymmetry the rest of this codebase applies to a
            # failed read, pointed the other way because here the safe answer is to keep serving.
            _acs_saved = _r_sf.can_access_server
            try:
                def _acs_boom(_user, _sid):
                    raise OSError("the database did not answer")

                _r_sf.can_access_server = _acs_boom
                with _r_sf._viewers_lock:
                    _r_sf._console_viewers[gs_id] = {"still-allowed": admin_id}
                with app.app_context():
                    _n_boom = _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
                check("console socket: a re-check that failed keeps the viewer, it does not evict",
                      _n_boom == 0 and "still-allowed" in (_r_sf._console_viewers.get(gs_id) or {}),
                      "dropped=%r left=%r" % (_n_boom, _r_sf._console_viewers.get(gs_id)))
            finally:
                _r_sf.can_access_server = _acs_saved
                with _r_sf._viewers_lock:
                    _r_sf._console_viewers.pop(gs_id, None)
        finally:
            with _r_sf._viewers_lock:
                _r_sf._console_viewers.pop(gs_id, None)
            try:
                _sio_c.disconnect()
            except Exception:
                pass

    # ── ...and so is the CREDENTIAL the socket joined with ───────────────────────────────────
    # The per-tick re-check asked only about the user ROW. None of the panel's revocation controls
    # change the row's answers: a device revoke deletes a UserSession row, "sign out everywhere"
    # bumps auth_epoch, revoking an API token clears its hash. load_user enforces all of them on
    # every socket EVENT — but the console is push-only, so after join_console nothing re-ran it,
    # and a stolen cookie that had been signed out everywhere kept receiving the console.
    import hashlib as _cv_hl
    from panel.db.models import UserSession as _CvUS
    with app.app_context():
        _cv_u = db.session.get(User, admin_id)
        _cv_saved = (_cv_u.auth_epoch, _cv_u.api_token, _cv_u.must_change_password)
        db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid", ip="", user_agent=""))
        db.session.commit()
        _cv_login = "%d:%d:smoke_console_sid" % (admin_id, _cv_u.auth_epoch or 0)

    def _cv_socket(**hdr):
        _fc = app.test_client()
        if not hdr:
            with _fc.session_transaction() as _ss:
                _ss["_user_id"] = _cv_login
                _ss["_fresh"] = True
        _c = app.socketio.test_client(app, flask_test_client=_fc, headers=hdr or None)
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
        _c.emit("join_console", {"server_id": gs_id})
        _vsid = next(iter(_r_sf._console_viewers.get(gs_id) or {}), None)
        _cv_sids.append(_vsid)
        return _c, _vsid

    def _cv_evict():
        with app.app_context():
            _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
        return bool(_r_sf._console_viewers.get(gs_id))

    _cv_clients, _cv_sids = [], []
    try:
        # A cookie tied to one UserSession row: revoking that device must end the stream.
        _cv_c, _cv_sid = _cv_socket()
        _cv_clients.append(_cv_c)
        check("console socket: a session-cookie viewer joins, and its login id is recorded",
              _cv_sid is not None and (_r_sf._viewer_creds.get(_cv_sid) or ("",))[0] == _cv_login,
              "viewer=%r cred=%r" % (_cv_sid, _r_sf._viewer_creds.get(_cv_sid)))
        check("console socket: ...and the re-check keeps it while that login stands (control)",
              _cv_evict(), "a valid viewer was evicted")
        with app.app_context():
            _CvUS.query.filter_by(sid="smoke_console_sid").delete()
            db.session.commit()
        check("console socket: revoking the viewer's DEVICE ends the stream at the next tick",
              not _cv_evict(), "the socket of a revoked session is still being streamed to")

        # "Sign out everywhere" / a password change: the epoch moves, every cookie stops matching.
        with app.app_context():
            db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid", ip="", user_agent=""))
            db.session.commit()
        _cv_c, _cv_sid = _cv_socket()
        _cv_clients.append(_cv_c)
        check("console socket: (control) a fresh viewer is kept before the epoch moves",
              _cv_evict(), "a valid viewer was evicted")
        with app.app_context():
            db.session.get(User, admin_id).auth_epoch = (_cv_saved[0] or 0) + 1
            db.session.commit()
        check("console socket: 'sign out everywhere' ends the stream at the next tick",
              not _cv_evict(), "the socket outlived a bumped auth_epoch")
        with app.app_context():
            db.session.get(User, admin_id).auth_epoch = _cv_saved[0]
            db.session.commit()

        # A bearer token: revoking it changes neither the epoch nor any session row.
        with app.app_context():
            db.session.get(User, admin_id).api_token = _cv_hl.sha256(b"smoke-console-token").hexdigest()
            db.session.commit()
        _cv_c, _cv_sid = _cv_socket(Authorization="Bearer smoke-console-token")
        _cv_clients.append(_cv_c)
        check("console socket: (control) a bearer-token viewer joins and is kept while the token "
              "stands", _cv_sid is not None and _cv_evict(),
              "viewer=%r cred=%r" % (_cv_sid, _r_sf._viewer_creds.get(_cv_sid)))
        with app.app_context():
            db.session.get(User, admin_id).api_token = None
            db.session.commit()
        check("console socket: revoking the API TOKEN ends the stream at the next tick",
              not _cv_evict(), "the socket outlived its revoked token")

        # A forced password change is refused at join; the re-check must refuse it too.
        with app.app_context():
            db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid2", ip="", user_agent=""))
            db.session.commit()
        _cv_login = "%d:%d:smoke_console_sid2" % (admin_id, _cv_saved[0] or 0)
        _cv_c, _cv_sid = _cv_socket()
        _cv_clients.append(_cv_c)
        with app.app_context():
            db.session.get(User, admin_id).must_change_password = True
            db.session.commit()
        check("console socket: a password reset mid-stream ends it at the next tick",
              _cv_sid is not None and not _cv_evict(),
              "the socket kept streaming to an account held at a forced password change")
        with app.app_context():
            db.session.get(User, admin_id).must_change_password = _cv_saved[2]
            db.session.commit()

        # The re-check must not itself keep the login alive. It ran load_user, a REQUEST hook that
        # writes UserSession.last_seen every ~5 minutes, and idle expiry is measured from
        # last_seen: a login with a console socket open (a stolen remember cookie included) never
        # idled out server-side.
        from datetime import timedelta as _cv_td
        from panel.core.clock import utcnow as _cv_now
        from panel.db.models import session_idle_limits as _cv_limits
        _cv_c, _cv_sid = _cv_socket()     # joining runs load_user itself: age the row AFTER it
        _cv_clients.append(_cv_c)
        _cv_old = (_cv_now() - _cv_td(seconds=400)).replace(microsecond=0)
        with app.app_context():
            _CvUS.query.filter_by(sid="smoke_console_sid2").update({"last_seen": _cv_old})
            db.session.commit()
        _cv_kept = _cv_sid is not None and _cv_evict()
        with app.app_context():
            _cv_seen = _CvUS.query.filter_by(sid="smoke_console_sid2").first().last_seen
        check("console socket: (control) a viewer whose login sat idle 400s is still kept",
              _cv_kept, "viewer=%r" % (_cv_sid,))
        check("console socket: the per-tick re-check does not refresh the login's last_seen",
              _cv_seen == _cv_old, "last_seen %r became %r" % (_cv_old, _cv_seen))

        # "Could not look" is not "revoked". load_user answers a database error with None (deny
        # this request), which the poller read as a revocation: a transient lock evicted a
        # legitimate viewer with "[access to this console was revoked]" until they reloaded.
        from sqlalchemy.exc import OperationalError as _cv_OpErr
        _cv_ie = _CvUS.is_expired

        def _cv_locked(self, now=None):
            raise _cv_OpErr("SELECT", {}, Exception("database is locked"))

        _CvUS.is_expired = _cv_locked
        try:
            _cv_kept_locked = _cv_evict()
        finally:
            _CvUS.is_expired = _cv_ie
        check("console socket: a database error in the credential re-check keeps the viewer",
              _cv_kept_locked, "a viewer was evicted as revoked because the session row could "
              "not be read")

        # ...while a login that HAS idled out still ends the stream (the check that last_seen
        # feeds, so the one a refreshing re-check had disabled).
        with app.app_context():
            _CvUS.query.filter_by(sid="smoke_console_sid2").update(
                {"last_seen": _cv_now() - _cv_td(seconds=max(_cv_limits()) + 60)})
            db.session.commit()
        check("console socket: a login that idled out ends the stream at the next tick",
              not _cv_evict(), "the socket outlived its session's idle expiry")

        # One definition of "still signed in": the side-effect-free check must agree with the
        # request hook on every login id, so a control added to one and not the other shows here.
        with app.app_context():
            db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid3", ip="", user_agent=""))
            db.session.commit()
        _cv_ep = _cv_saved[0] or 0
        _cv_cases = ["%d:%d:smoke_console_sid3" % (admin_id, _cv_ep),
                     "%d:%d:smoke_console_nosuch" % (admin_id, _cv_ep),
                     "%d:%d" % (admin_id, _cv_ep),
                     "%d:%d:smoke_console_sid3" % (admin_id, _cv_ep + 1),
                     "%d" % admin_id, "x:0", "%d:0" % (10 ** 7),
                     "%d:%d:smoke_console_sid2" % (admin_id, _cv_ep)]     # idled out, above
        _cv_mismatch, _cv_accepted = [], []
        _cv_load = app.login_manager.user_callback
        for _cv_inactive in (False, True):
            for _cv_lid in _cv_cases:
                with app.test_request_context("/"):
                    _cv_u = db.session.get(User, admin_id)
                    _cv_u.is_active = not _cv_inactive
                    try:
                        _cv_a = _r_sf._login_id_still_accepted(_cv_lid)
                        _cv_b = _cv_load(_cv_lid)
                    finally:
                        _cv_u.is_active = True
                        db.session.commit()
                    _cv_ida, _cv_idb = getattr(_cv_a, "id", None), getattr(_cv_b, "id", None)
                    if _cv_ida != _cv_idb:
                        _cv_mismatch.append((_cv_lid, _cv_inactive, _cv_ida, _cv_idb))
                    elif _cv_ida is not None:
                        _cv_accepted.append((_cv_lid, _cv_inactive))
        check("console socket: _login_id_still_accepted and load_user agree on every login id",
              not _cv_mismatch, "disagree (id, inactive, still_accepted, load_user): %r"
              % (_cv_mismatch,))
        check("console socket: (control) ...and both accept exactly the valid ones",
              _cv_accepted == [(_cv_cases[i], False) for i in (0, 2, 4)],
              "accepted by both: %r" % (_cv_accepted,))
    finally:
        for _c in _cv_clients:
            try:
                _c.disconnect()
            except Exception:
                pass
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
        with app.app_context():
            _cv_u = db.session.get(User, admin_id)
            (_cv_u.auth_epoch, _cv_u.api_token, _cv_u.must_change_password) = _cv_saved
            _CvUS.query.filter(_CvUS.sid.in_(["smoke_console_sid", "smoke_console_sid2",
                                               "smoke_console_sid3"])).delete(
                synchronize_session=False)
            db.session.commit()
    check("console socket: a disconnect forgets the socket's recorded credential",
          len([k for k in _cv_sids if k is not None]) == 5
          and not any(k in _r_sf._viewer_creds for k in _cv_sids),
          "sids=%r left behind: %r" % (_cv_sids, [k for k in _cv_sids if k in _r_sf._viewer_creds]))

    # ── The forced-password-change gate has to be asked ON THE SOCKET ────────────────────────
    # must_change_password is enforced by an @app.before_request (app.py), and a before_request
    # NEVER runs for a Socket.IO event — flask-socketio's middleware takes /socket.io/ ahead of the
    # Flask app. So the whole socket surface sat outside the gate: an account holding a password an
    # admin generated, read off a screen and relayed was answered 403 password_change_required by
    # every HTTP route in the panel, and could still emit join_console and be streamed that
    # server's live console — RCON output, admin commands, player names, connect lines.
    # host_terminal's _may_use_terminal asks this question for exactly this reason; the console
    # socket did not.
    _pw_sio, _pw_new, _pw_before = None, None, None
    try:
        _pw_err0 = ""
        try:
            _pw_sio = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
        except Exception as _e:
            _pw_err0 = "%s: %s" % (type(_e).__name__, _e)
        # The control, taken BEFORE the flag is set: this account gets a socket normally, so a
        # refusal below is the flag and not the harness refusing everything.
        check("console socket: (control) the account gets a socket while its password is its own",
              bool(_pw_sio is not None and _pw_sio.is_connected()), _pw_err0)
        with app.app_context():
            _pw_u = db.session.get(User, admin_id)
            _pw_before = _pw_u.must_change_password
            _pw_u.must_change_password = True
            db.session.commit()
        # An ALREADY-OPEN socket: connect does not run a second time, so join_console has to ask
        # as well — this is the socket that was open when the admin reset the password.
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
        if _pw_sio is not None and _pw_sio.is_connected():
            _pw_sio.emit("join_console", {"server_id": gs_id})
        check("console socket: an open socket cannot join a console once the account must change "
              "its password",
              not _r_sf._console_viewers.get(gs_id),
              "viewers=%r — the poller streams that console to a session the panel answers 403 "
              "on every other route" % (_r_sf._console_viewers.get(gs_id),))
        # ...and a NEW socket is refused at connect, which is what covers every event on the
        # namespace rather than the handful that remembered to check.
        _pw_conn, _pw_err = True, ""
        try:
            _pw_new = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
            _pw_conn = _pw_new.is_connected()
        except Exception as _e:
            _pw_conn, _pw_err = False, "%s: %s" % (type(_e).__name__, _e)
        check("console socket: ...and a new socket is refused at connect",
              _pw_conn is False,
              "connected — %s" % (_pw_err or "the connect gate admitted an account holding a "
                                             "handed-over temporary password"))
    finally:
        if _pw_before is not None:
            with app.app_context():
                db.session.get(User, admin_id).must_change_password = _pw_before
                db.session.commit()
        for _pw_cl in (_pw_sio, _pw_new):
            try:
                if _pw_cl is not None:
                    _pw_cl.disconnect()
            except Exception:
                pass
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)

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
    # What the panel pushes is NOT a line of the game's console log, and the payload must say so:
    # the browser de-duplicates the log by matching its own copy against each /api/console window,
    # and a line only the page holds can never match — the first poll after an update found no
    # overlap and appended the whole window again beneath "[panel] update finished".
    _pf_seen, _pf_emit = [], app.socketio.emit
    try:
        app.socketio.emit = lambda ev, payload, **k: _pf_seen.append((ev, payload))
        _console_push(app, gs_id, "[panel] probe line", ts=1700000000.0)
    finally:
        app.socketio.emit = _pf_emit
    check("console backlog: a panel push is marked as not coming from the console log",
          _pf_seen and _pf_seen[-1][0] == "console_output" and _pf_seen[-1][1].get("panel") is True
          and "rows" not in _pf_seen[-1][1],
          "emitted %r" % (_pf_seen,))
    _cb.clear()
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
        # A console the route COULD NOT READ must not be answered as a console that is empty.
        # rc != 0 (the non-raising transports), an exception (paramiko), a log that does not exist
        # and a genuinely empty log all left here as 200 with the same `lines: []`, and nothing in
        # the payload told them apart — so "Load older" emptied the browser's scrollback, which is
        # the only copy of it (the poller emits a sliding window and keeps nothing), and reported
        # "Loaded 0 lines from the log" about a log it never opened.
        check("console read: a console that could not be read says so",
              _blj.get("readable") is False,
              "readable=%r with lines=[] — indistinguishable from a server that has written "
              "nothing" % (_blj.get("readable"),))
        # THE ONE THAT MATTERS MOST, and the one every other check here passes without: the game
        # log's window must carry NO time. Those lines are a fresh tail of a file that records no
        # per-line time for most games — the panel is reading them now but they were written at
        # some unknowable point before that. Stamping them with the read time would put a
        # confident wrong time on a week of history, which is worse than a blank gutter, and it
        # looks exactly right until you notice every old line claims the moment you opened the
        # page. Asserted on a reachable host so `lines` is non-empty and the check has something
        # to be wrong about.
        _sm_core.run_command = _console_window_stub("old line one\nold line two")
        _blj2 = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console timestamps: (setup) the game-log window came back non-empty",
              len(_blj2.get("lines") or []) >= 2,
              "lines=%s — the check below would pass vacuously" % (_blj2.get("lines"),))
        check("console timestamps: an UNSTAMPED history line carries no invented time",
              all(r.get("t") is None for r in (_blj2.get("lines") or [])),
              "a line was dated to the moment the panel read it: %s" % (_blj2.get("lines"),))
        # The control for the readable=False check above: a read that DID run still says so, or
        # that gate would pass on a route that simply reported every console unreadable.
        check("console read: ...and a console that WAS read says so too",
              _blj2.get("readable") is True, "readable=%r" % (_blj2.get("readable"),))
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
        _sm_core.run_command = _console_window_stub("first\nsecond")
        _pdj = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console timestamps: the window carries the panel's clock for the browser to stamp "
              "its new lines with",
              isinstance(_pdj.get("now"), (int, float)) and _pdj["now"] > 1_700_000_000,
              "now=%r" % _pdj.get("now"))
        # Still not dated per line: an unstamped window is history until the browser knows which of
        # it is new, and dating the whole thing server-side is the mistake this guards against.
        # ...over lines that exist: an empty window makes all(...) True and the claim empty.
        _pd_lines = _pdj.get("lines") or []
        check("console timestamps: the unstamped window came back with lines in it",
              len(_pd_lines) >= 1, "no lines — the next check would pass vacuously")
        check("console timestamps: ...but an unstamped window stays undated, as history",
              _pd_lines and all(r.get("t") is None for r in _pd_lines),
              "lines=%s" % (_pd_lines,))

        # ── The window keeps its edge whitespace, because the page matches it EXACTLY ────────
        # run_command strips its output, so an unframed `tail` lost the window's LAST line's
        # trailing space and its FIRST line's indentation. The browser de-duplicates this window
        # against the lines the poller pushed — which are framed, and were not stripped — so
        # after Minecraft's "…players online: " the page found no overlap and appended the whole
        # window again under the reply, every poll. Reported as "the live console stops
        # responding till I load more of the old log"; measured on the test VPS as +29 and +33
        # repeated lines after each `list`.
        _sm_core.run_command = _console_window_stub(
            "    at lua/includes/init.lua:12\n[03:30:35] There are 0 of a max of 20 players online: ")
        _ws_lines = [r.get("line") for r in (c.get("/api/console/%d" % gs_id).get_json() or {})
                     .get("lines") or []]
        check("console window: the last line keeps its trailing whitespace",
              _ws_lines[-1:] == ["[03:30:35] There are 0 of a max of 20 players online: "],
              "last line %r — the page's exact-match stitching cannot find it" % (_ws_lines[-1:],))
        check("console window: ...and the first line keeps its indentation",
              _ws_lines[:1] == ["    at lua/includes/init.lua:12"], "first line %r" % (_ws_lines[:1],))
        check("console window: ...and the file's final newline is not an extra empty line",
              len(_ws_lines) == 2, "lines=%r" % (_ws_lines,))
        # tail's OWN status must survive the frame. Run the route's actual command through a
        # real bash — a stub cannot tell `…; printf E` from `…; printf E; exit $r`, and without
        # the exit a MISSING log (LinuxGSM's start is mv-then-touch) reads as "readable, empty",
        # which Load older answers by wiping the console.
        import subprocess as _rs_sp
        import tempfile as _rs_tmp
        with app.app_context():
            _rs_path = db.session.get(GameServer, gs_id).console_log
        _rs_dir = _rs_tmp.mkdtemp()
        _rs_target = [os.path.join(_rs_dir, "console.log")]
        _rs_saved = _sm_core.read_as_game_user

        def _rs_read(_server, _user, sh, timeout=30):
            r = _rs_sp.run(["bash", "-c", sh.replace(_rs_path, _rs_target[0])],
                           capture_output=True, text=True, timeout=10)
            return r.stdout.strip(), r.stderr.strip(), r.returncode   # .strip(): the transport
        try:
            _sm_core.read_as_game_user = _rs_read
            with open(_rs_target[0], "w") as _rs_fh:
                _rs_fh.write("first line\nThere are 0 of a max of 20 players online: \n")
            _rs_ok = c.get("/api/console/%d" % gs_id).get_json() or {}
            check("console window: (real shell) a present log is read, edge whitespace intact",
                  _rs_ok.get("readable") is True
                  and [r.get("line") for r in _rs_ok.get("lines") or []]
                  == ["first line", "There are 0 of a max of 20 players online: "],
                  "readable=%r lines=%r" % (_rs_ok.get("readable"), _rs_ok.get("lines")))
            _rs_target[0] = os.path.join(_rs_dir, "does-not-exist.log")
            _rs_missing = c.get("/api/console/%d" % gs_id).get_json() or {}
            check("console window: (real shell) a MISSING log is not reported as readable",
                  _rs_missing.get("readable") is False,
                  "readable=%r — Load older would wipe the console for a log that is not there"
                  % (_rs_missing.get("readable"),))
        finally:
            _sm_core.read_as_game_user = _rs_saved
            import shutil as _rs_sh
            _rs_sh.rmtree(_rs_dir, ignore_errors=True)
        # The frame is also the positive token that the read ran: output without it (a transport
        # that returned something else entirely) is not a window of the log.
        _sm_core.run_command = lambda *a, **k: ("sudo: a password is required", "", 0)
        _ws_bad = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console window: an unframed answer is reported unreadable, not shown as the log",
              _ws_bad.get("readable") is False and _ws_bad.get("lines") == [],
              "readable=%r lines=%r" % (_ws_bad.get("readable"), _ws_bad.get("lines")))
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
        _sm_core.run_command = _console_window_stub("[2026-09-18 05:09:57] stamped line\nplain line")
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
            # The page has no ON control; the endpoint must not have one either. Turning it on
            # routes the console through gawk, which block-buffers to the file — a console that
            # looks frozen until 4KB accumulate.
            _lt_writes.clear()
            _ltp_on = c.post("/api/server/%d/log-timestamps" % gs_id, json={"enabled": True})
            check("log stamps: the endpoint REFUSES to turn stamping on",
                  _ltp_on.status_code == 400 and not _lt_writes,
                  "status %s, wrote %s — one request still freezes every viewer's console"
                  % (_ltp_on.status_code, _lt_writes))
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
        # exactly what the shell returns: the byte range inside its B…E frame
        _bs_out = _bs_whole_lines(-99, "B" + _bs_log[_bs_pos:_bs_pos + _bs_diff] + "E")
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
    check("console burst: a rotated log drops the half-line held from the old file",
          "_console_partial.pop(server_id, None)" in _bs_src,
          "the fragment from the previous log survives the rotation and is glued to the new one")

    # ── The chunk is framed at BOTH ends, because run_command strips both ────────────────────
    # run_command returns `.strip()`ed output on every transport (_core.py: `out.strip()`,
    # `r.stdout.strip()`, `(out or "").strip()`), and strip() is not rstrip(). Only the trailing
    # 'E' sentinel existed, which covered exactly half the problem. When a byte-range chunk BEGAN
    # with the newline that terminated the previous chunk's last line, that newline was deleted in
    # transit and the held fragment was concatenated straight onto the next line's text: two real
    # log lines reached the console as one, with a second timestamp welded into the middle of it —
    # which also defeats _console_rows' stamp parsing for that line.
    _bs_partial_state.pop(-98, None)
    _lb_seen = []
    for _lb_chunk in ("[2026-09-18 06:22:08] MODULE: cc_foo.lua",      # cut on a line boundary…
                      "\n[2026-09-18 06:22:08] MODULE: cc_bar.lua\n"):  # …so the next byte is \n
        # .strip() is what the transport does to the framed chunk before the route ever sees it
        _lb_out = _bs_whole_lines(-98, ("B" + _lb_chunk + "E").strip())
        if _lb_out:
            _lb_seen.extend(_lb_out.split("\n"))
    check("console chunk: a chunk that STARTS with a newline is not glued to the held fragment",
          _lb_seen == ["[2026-09-18 06:22:08] MODULE: cc_foo.lua",
                       "[2026-09-18 06:22:08] MODULE: cc_bar.lua"],
          "reassembled as %r — a line that never existed in the log" % (_lb_seen,))
    _bs_partial_state.pop(-98, None)
    check("console chunk: ...and the poller frames the read at both ends to make that true",
          "printf B; {" in _bs_src and "}; printf E" in _bs_src,
          "the command sentinels only one end, so the transport's leading strip still bites")

    # ── A read that never RAN must not advance the offset ────────────────────────────────────
    # tailscale (_run_via_ssh_cli) and local do NOT raise: a 64KB `tail | head` that exceeds the
    # 5s timeout returns ("", "SSH command timed out", -1), while the 20-byte stat in the same tick
    # succeeded. "" was indistinguishable from "the chunk held no complete line", so the poller
    # advanced last_pos by `diff` bytes the host never sent — gone permanently, because last_pos
    # only moves forward and the browser only ever sees what the poller emitted. The frame is the
    # positive token that proves the read ran; its ABSENCE must not read as success.
    _bs_partial_state.pop(-97, None)
    _bs_partial_state[-97] = "[2026-09-18 06:22:08] MODULE: cc_hal"   # half a line, held
    _ur_out = _bs_whole_lines(-97, "")
    check("console chunk: a read that did not run answers None, not an empty chunk",
          _ur_out is None,
          "answered %r — the caller cannot tell it from a log that wrote nothing" % (_ur_out,))
    check("console chunk: ...and it does not consume the fragment held from the last read",
          _bs_partial_state.get(-97) == "[2026-09-18 06:22:08] MODULE: cc_hal",
          "held fragment is now %r — the next tick cannot re-read the range"
          % (_bs_partial_state.get(-97),))
    # The control: a framed chunk that is EMPTY is a reading — the log wrote nothing this tick —
    # and must still come back as "", not None, or the poller would stall on an idle server.
    check("console chunk: (control) a framed empty chunk is a reading, not a failure",
          _bs_whole_lines(-97, "BE") == "",
          "an idle server's empty read now looks like a failed one, and the offset never advances")
    _bs_partial_state.pop(-97, None)

    # Driven through the poller's own loop shape, because the damage is in the offset arithmetic
    # rather than in one call: one tick's chunk read fails the way tailscale fails, and every byte
    # of the burst must still arrive.
    _bs_partial_state.pop(-96, None)
    _fp_log = "".join("[2026-09-18 06:22:08] MODULE: fp_%05d.lua\n" % i for i in range(3000))
    check("console poller: (setup) the fixture spans more than one capped read",
          len(_fp_log) > 65536, "only %d bytes" % len(_fp_log))
    _fp_pos, _fp_seen, _fp_tick = 0, [], 0
    while _fp_pos < len(_fp_log) and _fp_tick < 20:
        _fp_tick += 1
        _fp_diff = min(len(_fp_log) - _fp_pos, 65536)
        _fp_raw = ("" if _fp_tick == 2                     # the timed-out read: no frame, rc=-1
                   else "B" + _fp_log[_fp_pos:_fp_pos + _fp_diff] + "E")
        _fp_out = _bs_whole_lines(-96, _fp_raw)
        if _fp_out is None:
            continue                                       # the fix: do NOT advance last_pos
        if _fp_out:
            _fp_seen.extend(_fp_out.split("\n"))
        _fp_pos += _fp_diff
    _bs_partial_state.pop(-96, None)
    check("console poller: a chunk read that never ran does not advance the offset past it",
          _fp_seen == [_l for _l in _fp_log.split("\n") if _l],
          "saw %d of %d lines — a window of console output was skipped and can never be "
          "recovered" % (len(_fp_seen), 3000))
    check("console poller: ...and the poller refuses the advance on that answer",
          "if out is None:" in _bs_src
          and "out = _console_whole_lines(server_id, out) if rc == 0 else None" in _bs_src,
          "the offset still moves on a read whose result was never proven to have arrived")

    # ── The REAL tick, against a fake log that rotates the way LinuxGSM rotates it ───────────
    # Everything above drives _console_whole_lines; the offset arithmetic around it lived in the
    # poller's closure, so it could only be checked by reading its source — and a source check
    # cannot tell a rotation the poller handles from one it misses. It missed one. LinuxGSM's
    # start is `mv consolelog <dated>; touch consolelog`, and rotation was detected only by the
    # file SHRINKING. On the test VPS a Minecraft start wrote 4.5KB in under two seconds, outgrew
    # the old log's 4528-byte offset before the next tick, and the poller read the NEW log from
    # the OLD offset: the boot output was never shown and the first push began
    # 'l:joml:1.10.9) to libraries/…'. _console_tick is the extracted body; this drives it.
    import re as _ct_re
    import types as _ct_types
    import panel.routes.server_files as _ct_sf
    from panel.core.panel_state import _console_offsets as _ct_offsets

    class _CtLog:
        """A console log on a fake host, answering exactly the two reads _console_tick makes."""
        def __init__(self):
            self.ino, self.data, self.exists, self.fail_chunk = 5000, "", True, False

        def rotate(self, text=""):             # mv consolelog <dated>; touch consolelog
            self.ino, self.data = self.ino + 1, text

        def read(self, _server, _user, sh, timeout=30):
            if sh.startswith("stat -c '%i %s'"):
                return ("%d %d" % (self.ino, len(self.data)) if self.exists else "MISSING"), "", 0
            m = _ct_re.match(r"printf B; \{ tail -c \+(\d+) \S+ 2>/dev/null \| head -c (\d+); \}; "
                             r"printf E$", sh)
            if not m:
                return "", "unexpected command %r" % sh, 1
            if self.fail_chunk:
                self.fail_chunk = False
                return "", "SSH command timed out", -1      # tailscale/local: no raise, no frame
            a = int(m.group(1)) - 1
            # .strip(): what every transport does to the output before the caller sees it
            return ("B" + self.data[a:a + int(m.group(2))] + "E").strip(), "", 0

    class _CtSio:
        def __init__(self):
            self.lines = []

        def emit(self, event, payload, room=None, **_k):
            if event == "console_output":
                self.lines.extend(r["line"] for r in payload.get("rows") or [])

    _ct_log, _ct_sio = _CtLog(), _CtSio()
    _ct_gs = _ct_types.SimpleNamespace(console_log="/home/mcserver/log/console/mc-console.log",
                                       remote=object(), short_name="mcserver")
    # On _core, the defining module: the package resolves names through __getattr__, and a stub
    # set on the package itself would shadow that (the unit suite's stub-seam gate says so).
    _ct_saved = (_sm_core.read_as_game_user, _ct_sf._host_timezone_cached)
    _CT = -95

    def _ct_tick():
        _ct_sf._console_tick(app, _ct_sio, _ct_gs, _CT)

    try:
        _sm_core.read_as_game_user = _ct_log.read
        _ct_sf._host_timezone_cached = lambda *_a, **_k: ""
        _ct_offsets.pop(_CT, None)
        _bs_partial_state.pop(_CT, None)
        _ct_log.data = "".join("[03:30:%02d] old line %d\n" % (i, i) for i in range(40))
        _ct_tick()
        check("console tick: first sight reads nothing — history is /api/console's to show",
              _ct_sio.lines == [] and _ct_offsets.get(_CT, {}).get("pos") == len(_ct_log.data),
              "pushed %d lines / offset %r" % (len(_ct_sio.lines), _ct_offsets.get(_CT)))
        _ct_log.data += "list\n[03:30:35] There are 0 of a max of 20 players online: \n"
        _ct_tick()
        check("console tick: (control) new output after first sight is pushed, whitespace intact",
              _ct_sio.lines == ["list", "[03:30:35] There are 0 of a max of 20 players online: "],
              "pushed %r" % (_ct_sio.lines,))

        # THE REPORTED CASE: a start rotates the log and the new one is already LONGER than the
        # old offset by the time the poller next looks.
        _ct_sio.lines = []
        _ct_boot = ["Unpacking io/netty/netty-codec/4.2.7/netty-codec-4.2.7.jar (libraries:io.netty:"
                    "netty-codec:4.2.7) to libraries/io/netty/netty-codec/4.2.7/netty-codec.jar %03d"
                    % i for i in range(60)] + ["Starting net.minecraft.server.Main"]
        _ct_log.rotate("".join(l + "\n" for l in _ct_boot))
        check("console tick: (setup) the new log outgrew the old offset before the tick",
              len(_ct_log.data) > _ct_offsets[_CT]["pos"],
              "new %d <= old %d — the size check alone would already catch it"
              % (len(_ct_log.data), _ct_offsets[_CT]["pos"]))
        _ct_tick()
        check("console tick: a rotated log is read from its FIRST byte, not from the old offset",
              _ct_sio.lines[:1] == _ct_boot[:1],
              "first pushed line %r — the boot output before it was skipped, and it began "
              "mid-line" % (_ct_sio.lines[:1],))
        check("console tick: ...and every line of the new log arrives, in order, whole",
              _ct_sio.lines == _ct_boot, "pushed %d of %d lines" % (len(_ct_sio.lines),
                                                                  len(_ct_boot)))

        # A rotation that SHRINKS the file (the older, size-only detection) must still work, and
        # read from byte 0 rather than skipping the new log's first chunk as "first sight".
        _ct_sio.lines = []
        _ct_log.rotate("[03:40:00] Starting minecraft server version 26.3\n")
        _ct_tick()
        check("console tick: a smaller rotated log is read from byte 0, not skipped",
              _ct_sio.lines == ["[03:40:00] Starting minecraft server version 26.3"],
              "pushed %r" % (_ct_sio.lines,))

        # Between LinuxGSM's mv and its touch there is no file at all. That is not an empty log
        # and not a rotation, and it must not disturb the offset.
        _ct_before = dict(_ct_offsets[_CT])
        _ct_log.exists = False
        _ct_tick()
        _ct_log.exists = True
        check("console tick: a log that is briefly MISSING changes nothing",
              _ct_offsets[_CT] == _ct_before, "offset %r -> %r" % (_ct_before, _ct_offsets[_CT]))

        # A chunk read that does not run (the non-raising transports) must not advance: the next
        # tick re-reads the range. This is the case the loop-shaped check above simulates; here
        # it goes through the real function.
        _ct_sio.lines = []
        _ct_log.data += "[03:40:05] Done (4.2s)! For help, type \"help\"\n"
        _ct_log.fail_chunk = True
        _ct_tick()
        _ct_mid = list(_ct_sio.lines)
        _ct_tick()
        check("console tick: a chunk read that never ran is retried, not skipped",
              _ct_mid == [] and _ct_sio.lines == ['[03:40:05] Done (4.2s)! For help, type "help"'],
              "after the failed read %r, after the retry %r" % (_ct_mid, _ct_sio.lines))

        # A burst over the per-tick cap drains over several ticks with nothing lost or cut.
        _ct_sio.lines = []
        # Unstamped: a LinuxGSM "[YYYY-MM-DD HH:MM:SS] " prefix is parsed off into the row's `t`,
        # so a stamped fixture would compare unequal for a reason that has nothing to do with this.
        _ct_burst = ["MODULE: ct_%05d.lua loaded" % i for i in range(3000)]
        _ct_log.data += "".join(l + "\n" for l in _ct_burst)
        for _ in range(12):
            _ct_tick()
        check("console tick: a burst bigger than one read arrives complete, in order, unsplit",
              _ct_sio.lines == _ct_burst,
              "pushed %d of 3000; first bad %r" % (len(_ct_sio.lines),
                                                  [l for l in _ct_sio.lines if not l.endswith(" loaded")][:1]))

        # One absurd colour code must not wedge the console. int() of more than 4300 digits
        # RAISES in CPython, the renderer runs on every chunk, and a tick that raises never
        # advances — so the same chunk was re-read, and re-raised, every two seconds, forever.
        _ct_sio.lines = []
        _ct_log.data += "before \x1b[" + "9" * 5000 + "mstill here\nthe next line\n"
        try:
            _ct_tick()
            _ct_wedge = None
        except Exception as _ct_exc:        # the poller swallows this and retries forever
            _ct_wedge = "%s: %s" % (type(_ct_exc).__name__, str(_ct_exc)[:80])
        check("console tick: a colour code too long to parse does not wedge the console",
              _ct_wedge is None and _ct_sio.lines == ["before still here", "the next line"],
              "tick raised %s; pushed %r" % (_ct_wedge, [l[:40] for l in _ct_sio.lines]))

        # A line that never ends must not be held forever. It grew by a whole read every tick.
        _ct_sio.lines = []
        _ct_log.data += "x" * 70000
        for _ in range(3):
            _ct_tick()
        check("console tick: an unterminated line past the cap is shown, not held without bound",
              len(_ct_sio.lines) == 1 and _ct_sio.lines[0] == "x" * 70000
              and not _bs_partial_state.get(_CT),
              "pushed %d line(s); still holding %d chars"
              % (len(_ct_sio.lines), len(_bs_partial_state.get(_CT) or "")))
        _ct_log.data += "\n"
        _ct_tick()
        _ct_sio.lines = []
        _ct_log.data += "half a li"
        _ct_tick()
        _ct_log.data += "ne\n"
        _ct_tick()
        check("console tick: (control) a SHORT fragment is still held and completed",
              _ct_sio.lines == ["half a line"], "pushed %r" % (_ct_sio.lines,))

        # Nobody watching: the offset goes, so reopening the console starts from NOW rather than
        # replaying everything written while it was closed as if it were live.
        _ct_sf._forget_unwatched_consoles([])
        _ct_sio.lines = []
        _ct_log.data += "".join("[04:%02d:00] written while nobody watched %d\n" % (i, i)
                                for i in range(50))
        _ct_tick()
        check("console tick: a console nobody watched does not replay its backlog on reopen",
              _ct_sio.lines == [], "replayed %d lines as live" % len(_ct_sio.lines))
        _ct_log.data += "[05:00:00] after reopening\n"
        _ct_tick()
        check("console tick: ...and streams what is written after it is reopened",
              _ct_sio.lines == ["[05:00:00] after reopening"], "pushed %r" % (_ct_sio.lines,))
        _ct_sf._forget_unwatched_consoles([_CT])
        check("console tick: (control) a WATCHED console keeps its offset",
              _CT in _ct_offsets, "the offset of a console someone has open was dropped")
    finally:
        _sm_core.read_as_game_user, _ct_sf._host_timezone_cached = _ct_saved
        _ct_offsets.pop(_CT, None)
        _bs_partial_state.pop(_CT, None)

    # ...and the poller really calls those two, every tick. Read as AST, not text: the comment
    # explaining the fix names both functions.
    import ast as _ct_ast
    _ct_tree = _ct_ast.parse(_bs_src)
    _ct_poller = next((n for n in _ct_ast.walk(_ct_tree)
                       if isinstance(n, _ct_ast.FunctionDef) and n.name == "console_poller"), None)
    _ct_calls = {c.func.id for c in _ct_ast.walk(_ct_poller or _ct_ast.Module(body=[]))
                 if isinstance(c, _ct_ast.Call) and isinstance(c.func, _ct_ast.Name)}
    check("console poller: it drives _console_tick and forgets unwatched consoles",
          _ct_poller is not None and {"_console_tick", "_forget_unwatched_consoles"} <= _ct_calls,
          "console_poller calls %s" % sorted(_ct_calls))


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
    # ...and asks for the password on the way, because a token is a second credential that outlives
    # the session that minted it. A bare POST — all a stolen cookie can manage — must mint nothing.
    check("account page: the mint form asks for the password",
          'name="password"' in _acct.split("api-token/generate", 1)[1][:800],
          "the form posts with nothing but the session")
    _bare = c.post("/account/api-token/generate", follow_redirects=True)
    check("api token: a POST with no password mints nothing",
          _re_as.search(r"(lgsm_[0-9a-f]{48})", _bare.get_data(as_text=True) or "") is None,
          "status=%d" % _bare.status_code)
    # ...and the refusal is RECORDED. log_action fired on the mint alone, so the one thing this
    # gate produces that is worth watching — somebody in a borrowed session trying passwords
    # against it, now the only way past — left no trace anywhere, while the mint they were aiming
    # at left a tidy one. A gate with invisible refusals reports afterwards that nothing happened,
    # which is exactly what it looks like when something did.
    from panel.db.models import AuditLog as _at_AL
    with app.app_context():
        _at_refused = _at_AL.query.filter_by(username="smoke_admin", action="api_token_generate",
                                             success=False).count()
    check("api token: ...and that refusal is written to the audit log", _at_refused == 1,
          "%d refusals on record for smoke_admin, expected 1" % _at_refused)
    # The label has to point AT the field it labels. This card copied the 2FA row's markup, which
    # has a bare <label> and no ids, while the password-change form at the top of the same page
    # wires for/id properly — so clicking the label did nothing and the box's only accessible name
    # was a placeholder, which goes away the moment you type in it.
    _mint_form = _acct.split("api-token/generate", 1)[1].split("</form>", 1)[0]
    _mint_for = _re_as.search(r'<label[^>]*\sfor="([^"]+)"', _mint_form)
    check("account page: the mint form's label points at its password field",
          bool(_mint_for) and ('id="%s"' % _mint_for.group(1)) in _mint_form,
          "label for=%r; ids in the form: %r" % (_mint_for and _mint_for.group(1),
                                                 _re_as.findall(r'id="([^"]+)"', _mint_form)))
    _mint = c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
    _mint_body = _mint.get_data(as_text=True)
    _shown = _re_as.search(r"(lgsm_[0-9a-f]{48})", _mint_body)
    check("api token: minting one SHOWS it (once)", _shown is not None, "status=%d" % _mint.status_code)
    if _shown:
        check("api token: the token it showed actually authenticates",
              app.test_client().get("/api/servers", headers={
                  "Authorization": "Bearer %s" % _shown.group(1)}).status_code == 200)
    # ...and it is actually WRITTEN DOWN. Both checks above pass on a route whose
    # `db.session.commit()` has been deleted: the mint and the Bearer read share one scoped
    # session, so the query sees the pending write and the token authenticates for the rest of
    # the process. Proven by mutation — with the commit removed, unit and smoke both stayed
    # fully green. Drop the session first, so this reads what survived the request rather than
    # what is still sitting in it: a credential the panel shows you once and forgets is worse
    # than no credential at all.
    if _shown:
        # Read it on a SEPARATE CONNECTION, which sees only what was committed — the checks above
        # cannot, because the mint and the Bearer read share one scoped session, so a token that
        # was never written would still authenticate for the rest of the process.
        #
        # Honest about what this does and does not prove: deleting the route's own
        # `db.session.commit()` does NOT make it fail, because log_action (panel/security/auth.py)
        # commits a few lines later and carries the write with it. So the explicit commit is
        # redundant today. That is exactly why the check is worth having — it pins the PROPERTY
        # (the credential the panel shows you once is on disk) rather than the call, and it will
        # fail if the audit line that happens to be carrying it ever moves or goes conditional.
        import sqlite3 as _tok_sql
        _tok_con = _tok_sql.connect(str(DB_PATH))
        try:
            _persisted = _tok_con.execute(
                "SELECT api_token FROM user WHERE id=?", (admin_id,)).fetchone()
        finally:
            _tok_con.close()
        check("api token: ...and it SURVIVES the request that minted it",
              bool(_persisted and _persisted[0]),
              "nothing committed to the row — the token the panel showed once is already gone")
    check("account page: offers Revoke once a token exists", "api-token/revoke" in _mint_body)
    _rev = c.post("/account/api-token/revoke", follow_redirects=True)
    check("api token: revoking it works", _rev.status_code == 200)
    if _shown:
        check("api token: ...and the revoked token stops authenticating",
              app.test_client().get("/api/servers", headers={
                  "Authorization": "Bearer %s" % _shown.group(1)}).status_code != 200)

    # ── An API token is a SECOND credential, and it has to answer to the controls that take an
    # account back. It answered to none of them: it carries no auth_epoch, so a password change
    # did not touch it, and "sign out everywhere" deleted every UserSession row and left it
    # working. app.py's note that "cookie theft is also recoverable via sign out everywhere" was
    # untrue while one existed — and minting one needed only a live session (no password, no 2FA),
    # so an attacker holding a stolen cookie could leave themselves a key that survived the
    # victim's entire recovery. Minting now costs the password (and a code when 2FA is on), which
    # is why this POST carries one; the revocation reach below is what makes an already-minted
    # token recoverable.
    _tok_c = client_as(admin_id)
    _mint2 = _tok_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
    _m = _re_as.search(r"(lgsm_[0-9a-f]{48})", _mint2.get_data(as_text=True) or "")
    check("api token: minted for the revocation tests", bool(_m),
          _mint2.get_data(as_text=True)[:120])
    if _m:
        _tok = _m.group(1)
        _bearer = lambda: app.test_client().get(
            "/api/servers", headers={"Authorization": "Bearer %s" % _tok}).status_code
        check("api token: it authenticates before the revoke", _bearer() == 200)
        _tok_c.post("/account/sessions/revoke")
        check("api token: 'sign out everywhere' also revokes the API token", _bearer() != 200,
              "status=%s" % _bearer())

    # The OTHER control that takes an account back. "Sign out everywhere" is asserted above; the
    # password change was only ever claimed — in the mint's own rationale, which now rests on both
    # being true. Nothing in the token carries an auth_epoch, so neither control reaches it by the
    # sweep every session cookie gets: each route has an explicit revoke_api_token(), and deleting
    # either one is silent. Its own account, because changing smoke_admin's password would pull the
    # rug from under every later check that signs in as them.
    with app.app_context():
        _pw_u = _TU(username="api_token_pwchg", display_name="Token PW",
                    password_hash=auth.hash_password("Str0ng!passw0rd"),
                    is_superadmin=False, is_active=True)
        db.session.add(_pw_u)
        db.session.commit()
        _pw_id = _pw_u.id
    _pw_c = client_as(_pw_id)
    _pw_mint = _pw_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
    _pw_m = _re_as.search(r"(lgsm_[0-9a-f]{48})", _pw_mint.get_data(as_text=True) or "")
    check("api token: minted for the password-change test", bool(_pw_m),
          "status=%d" % _pw_mint.status_code)
    if _pw_m:
        def _pw_bearer():
            return app.test_client().get("/api/servers", headers={
                "Authorization": "Bearer %s" % _pw_m.group(1)}).status_code

        check("api token: it authenticates before the password change", _pw_bearer() == 200,
              "status=%s" % _pw_bearer())
        _pw_c.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                              "new_password": "Str0ng!passw0rd-2",
                                              "confirm_password": "Str0ng!passw0rd-2"})
        check("api token: a password change also revokes the API token", _pw_bearer() != 200,
              "status=%s — the token answers to no epoch, so only that route's explicit "
              "revoke_api_token() takes it away" % _pw_bearer())

    # ── The 2FA branch of the mint, end to end — and the writes that have to SURVIVE the request
    # Every mint above is smoke_admin's, and smoke_admin has no 2FA, so the block that burns a
    # TOTP step and spends a one-time backup code ran against a hand-built stand-in in the unit
    # suite and nothing else. What a stand-in cannot show is the half that makes either of those
    # mean anything: the step and the spent code have to reach the DATABASE. If they don't, the
    # replay guard is a per-request variable and a backup code is infinite — and the route reads
    # exactly the same either way.
    #
    # Nor did anything assert that the mint persists what it hands out: deleting
    # db.session.commit() from the route left both suites fully green, because log_action commits
    # the same session one line later. So every assertion below re-reads the row in a FRESH app
    # context — a new session, a real SELECT — after the POST has finished, instead of trusting
    # the response that request returned.
    import hashlib as _at_hashlib
    with app.app_context():
        _at2_codes = auth.generate_backup_codes()
        _at2_secret = auth.generate_totp_secret()
        _at2 = _TU(username="api_token_2fa", display_name="Token 2FA",
                   password_hash=auth.hash_password("Str0ng!passw0rd"),
                   is_superadmin=False, is_active=True,
                   totp_enabled=True, totp_secret=encrypt_secret(_at2_secret))
        _at2.set_backup_codes(_at2_codes)
        db.session.add(_at2)
        db.session.commit()
        _at2_id = _at2.id

    def _at2_row():
        """(stored token digest, last spent step, backup codes left), as the DATABASE has them.

        A fresh app context on purpose: flask-sqlalchemy scopes its session to the app context, so
        this is a new session and a real read — not the writing request's own uncommitted work
        handed back from an identity map."""
        with app.app_context():
            _row = db.session.get(_TU, _at2_id)
            return (_row.api_token, _row.last_totp_step or 0, _row.backup_codes_remaining)

    def _at2_shown_digest(body):
        """What the page showed, hashed the way the column stores it (or None if it showed none)."""
        _hit = _re_as.search(r"(lgsm_[0-9a-f]{48})", body or "")
        return _at_hashlib.sha256(_hit.group(1).encode()).hexdigest() if _hit else None

    _at2_c = client_as(_at2_id)
    _at2_page = _at2_c.get("/account").get_data(as_text=True)
    _at2_form = _at2_page.split("api-token/generate", 1)[-1].split("</form>", 1)[0]
    check("account page (2FA): the mint form asks for a code as well as the password",
          'name="totp_code"' in _at2_form, "the 2FA branch of the route can never be satisfied")
    check("account page (2FA): ...and the code box has a name a screen reader can read",
          'aria-label="Code or backup code"' in _at2_form,
          "its only accessible name is the placeholder, which disappears as soon as you type")
    # The password alone, with 2FA on — the proof account_2fa_disable refuses on the same page.
    _r = _at2_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"},
                     follow_redirects=True)
    _at2_tok, _at2_step, _at2_left = _at2_row()
    check("api token (2FA): the password alone mints nothing", _at2_tok is None,
          "a token was stored anyway: %r" % (_at2_tok,))
    check("api token (2FA): ...and nothing was written to the account either",
          _at2_step == 0 and _at2_left == len(_at2_codes),
          "last_totp_step=%r, %d of %d backup codes left" % (_at2_step, _at2_left, len(_at2_codes)))
    # A REAL backup code with the wrong password. Counted, not re-checked: use_backup_code
    # CONSUMES, so asking "is it still valid" would spend the thing being asked about.
    _r = _at2_c.post("/account/api-token/generate",
                     data={"password": "wrong-password", "totp_code": _at2_codes[1]},
                     follow_redirects=True)
    _at2_tok, _, _at2_left = _at2_row()
    check("api token (2FA): a valid code with the wrong password mints nothing",
          _at2_tok is None, "stored=%r" % (_at2_tok,))
    check("api token (2FA): ...and that backup code was NOT spent on the failed attempt",
          _at2_left == len(_at2_codes),
          "%d of %d left — a one-time code was burnt by a request that failed for another reason"
          % (_at2_left, len(_at2_codes)))
    # The real thing: password plus a live authenticator code.
    _at2_code = _pyotp.TOTP(_at2_secret).now()
    _r = _at2_c.post("/account/api-token/generate",
                     data={"password": "Str0ng!passw0rd", "totp_code": _at2_code})
    _at2_first = _at2_shown_digest(_r.get_data(as_text=True))
    check("api token (2FA): password + a live authenticator code mints one (positive control)",
          _at2_first is not None, "status=%d" % _r.status_code)
    _at2_tok, _at2_step, _ = _at2_row()
    check("api token (2FA): ...and the token it showed is IN THE ROW once the request is over",
          _at2_first is not None and _at2_tok == _at2_first,
          "shown=%r stored=%r — the plaintext was handed out and the database kept nothing"
          % (_at2_first, _at2_tok))
    check("api token (2FA): ...and the step that code spent was committed with it",
          _at2_step > 0,
          "last_totp_step=%r — the replay guard is comparing against a value that never landed"
          % (_at2_step,))
    # Which is what that step is FOR. A new request re-loads the user from the database, so the
    # replay below is refused only if the step above really got there.
    _r = _at2_c.post("/account/api-token/generate",
                     data={"password": "Str0ng!passw0rd", "totp_code": _at2_code},
                     follow_redirects=True)
    # Both halves, not just the row: "the digest did not change" is also true of a route that
    # stored nothing at all, so the response is asserted to have shown no token either.
    _at2_replay = _at2_shown_digest(_r.get_data(as_text=True))
    _at2_after, _, _ = _at2_row()
    check("api token (2FA): REPLAYING that code mints nothing",
          _at2_replay is None and _at2_after == _at2_tok,
          "shown=%r, stored digest %s" % (_at2_replay,
                                          "changed" if _at2_after != _at2_tok else "held"))
    # Somebody whose authenticator is gone is not locked out of their own token.
    _r = _at2_c.post("/account/api-token/generate",
                     data={"password": "Str0ng!passw0rd", "totp_code": _at2_codes[0]})
    _at2_second = _at2_shown_digest(_r.get_data(as_text=True))
    check("api token (2FA): a one-time backup code mints one too", _at2_second is not None,
          "status=%d" % _r.status_code)
    _at2_tok, _, _at2_left = _at2_row()
    check("api token (2FA): ...and that mint replaced the stored digest",
          _at2_second is not None and _at2_tok == _at2_second,
          "shown=%r stored=%r" % (_at2_second, _at2_tok))
    check("api token (2FA): ...and the code it spent is gone from the ROW, not just the request",
          _at2_left == len(_at2_codes) - 1, "%d of %d left" % (_at2_left, len(_at2_codes)))
    _r = _at2_c.post("/account/api-token/generate",
                     data={"password": "Str0ng!passw0rd", "totp_code": _at2_codes[0]},
                     follow_redirects=True)
    _at2_replay = _at2_shown_digest(_r.get_data(as_text=True))
    _at2_after, _, _ = _at2_row()
    check("api token (2FA): ...so replaying that backup code mints nothing",
          _at2_replay is None and _at2_after == _at2_tok,
          "shown=%r, stored digest %s" % (_at2_replay,
                                          "changed" if _at2_after != _at2_tok else "held"))
    # Four refusals above, and a gate is only as useful as its record of them.
    with app.app_context():
        _at2_refusals = _at_AL.query.filter_by(username="api_token_2fa",
                                               action="api_token_generate",
                                               success=False).count()
    check("api token (2FA): every refusal above is in the audit log", _at2_refusals == 4,
          "%d recorded, expected 4 (no code, wrong password, replayed code, spent backup code)"
          % _at2_refusals)

    # ── Deactivating an account must END its open sessions, and nothing asserted that it did.
    # It does — but through a coupling nobody would find by reading the panel: this model is
    # `User(UserMixin, db.Model)` with `is_active` as a Column, and UserMixin.is_authenticated is
    # `return self.is_active`, so declaring the column also redefines is_authenticated and
    # @login_required refuses the account. Declare an is_authenticated of your own, or drop
    # UserMixin, and every open session of every deactivated account silently works again.
    # These pin the BEHAVIOUR, so it survives whichever layer happens to provide it.
    with app.app_context():
        _victim = User(username="deactivateme", is_active=True,
                       password_hash=auth.hash_password("Str0ng!passw0rd"))
        db.session.add(_victim)
        db.session.commit()
        _vid = _victim.id
    # BOTH cookie shapes, because load_user has two branches and client_as() only exercises one.
    # A bare "<id>" is the legacy cookie; a real login carries "<id>:<auth_epoch>", and that is the
    # branch every current session actually takes — a gate that covers only the legacy form would
    # pass with the modern branch wide open.
    def _client_with_id(raw_id):
        _c = app.test_client()
        with _c.session_transaction() as _s:
            _s["_user_id"] = str(raw_id)
            _s["_fresh"] = True
        return _c

    with app.app_context():
        _modern_id = db.session.get(User, _vid).get_id()
    check("deactivation: the modern cookie form is <id>:<epoch>, not a bare id",
          ":" in _modern_id, _modern_id)
    _vc_legacy, _vc_modern = _client_with_id(_vid), _client_with_id(_modern_id)
    check("deactivation: the legacy-cookie session works while the account is active",
          _vc_legacy.get("/api/servers").status_code == 200)
    check("deactivation: the epoch-cookie session works while the account is active",
          _vc_modern.get("/api/servers").status_code == 200)
    with app.app_context():
        db.session.get(User, _vid).is_active = False
        db.session.commit()
    _after_l = _vc_legacy.get("/api/servers").status_code
    _after_m = _vc_modern.get("/api/servers").status_code
    check("deactivation: the legacy-cookie session stops working once deactivated",
          _after_l != 200, "status=%s" % _after_l)
    check("deactivation: the epoch-cookie session stops working once deactivated",
          _after_m != 200, "status=%s" % _after_m)

    # ── two more "reported success without reading the result" ────────────────────────────────
    # Both stubbed at the seam that actually fails on this codebase: run_command returns
    # ("", "...timed out", -1) rather than raising, which is why neither route's except branch
    # ever saw these.
    from panel.ops.ssh_manager import _core as _sw_core

    _sw_saved = {}

    def _sw_stub(mod, name, fn):
        _sw_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    try:
        # 1. upload-check answered "we looked, nothing conflicts" from a listing that never ran.
        #    stat_upload_targets discarded rc, so out="" meant no matches, and the route reported
        #    checked=true. The browser then uploads without asking, and the upload route's own
        #    re-check is the only thing left between that and a clobbered file.
        _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "ssh: connect to host ... timed out", -1))
        _uc = c.post("/api/server/%d/upload-check" % gs_id,
                     json={"path": "", "names": ["server.cfg"]},
                     headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        check("upload-check: a listing that never ran is not reported as 'no conflicts'",
              _uc.get("checked") is False,
              "answered checked=%r existing=%r — the browser reads that as a clear and uploads "
              "without asking" % (_uc.get("checked"), _uc.get("existing")))
        # ...and a listing that DID run still reports checked=true, so the guard is not "always
        # say we could not look".
        _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "", 0))
        _uc2 = c.post("/api/server/%d/upload-check" % gs_id,
                      json={"path": "", "names": ["server.cfg"]},
                      headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        check("upload-check: ...while a real listing still answers checked=true",
              _uc2.get("checked") is True, "%r" % (_uc2,))

        # 2. "Run now" on a scheduled task reported "Started" from a launch that never happened.
        #    The job is detached, so the rc says nothing about how the job ENDS — but it does say
        #    whether it began, and that was discarded.
        _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "sudo: a password is required", 1))
        _cr = c.post("/api/server/%d/cron/run" % gs_id, json={"raw": "0 5 * * * /home/x/x update"},
                     headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        check("cron run-now: a launch that failed is not reported as 'Started'",
              _cr.get("success") is False,
              "answered %r — Last run never changes, and the audit row says it succeeded"
              % (_cr.get("message"),))
        _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "", 0))
        _cr2 = c.post("/api/server/%d/cron/run" % gs_id, json={"raw": "0 5 * * * /home/x/x update"},
                      headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        check("cron run-now: ...while a launch that started still says so",
              _cr2.get("success") is True, "%r" % (_cr2,))
    finally:
        for (_m, _n), _v in _sw_saved.items():
            setattr(_m, _n, _v)

    # ── "the mounts could not be read" is not "this server mounts nothing" ────────────────────
    # gmod_current_mounts has three answers and its docstring calls the third the whole point:
    # a list, [] for "mounts nothing", and None for "could not be read". The status route did
    # `or []`, so a failed read painted every checkbox unticked — and Apply rewrites mount.cfg to
    # exactly the visible ticks, so applying that card unmounts everything the server had. The
    # uninstall worker in the same file already guards the identical call for the identical
    # reason.
    # Stubbed on the ROUTE module: server_files.py imports these BY NAME, so a stub on the
    # ssh_manager submodule is never seen. detect_content_user and path_disk_free are stubbed too
    # — they SSH, and against this suite's unreachable host they raise, which sends the whole
    # handler into its `except` and returns {"error": ...}. That is what the first version of
    # this test actually measured.
    import panel.routes.server_files as _gm_mod

    _gm_saved = (_gm_mod.gmod_current_mounts, _gm_mod.detect_content_user, _gm_mod.path_disk_free)
    try:
        _gm_mod.detect_content_user = lambda *a, **k: {"user": "gmodcontent", "present": {}}
        _gm_mod.path_disk_free = lambda *a, **k: (10 * 1024 ** 3, 50 * 1024 ** 3)
        with app.app_context():
            _gm_gs = db.session.get(GameServer, gs_id)
            _gm_type_before = _gm_gs.game_type
            _gm_gs.game_type = "gmod"
            db.session.commit()

        _gm_mod.gmod_current_mounts = lambda *a, **k: None       # the host did not answer
        _gm_get = c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}
        check("gmod mounts: an unreadable mount state is reported as unreadable",
              _gm_get.get("mounts_readable") is False,
              "answered %r — the card renders every box unticked, i.e. 'mounts nothing'"
              % (_gm_get.get("mounts_readable"),))
        _gm_post = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": []},
                          headers={"X-Requested-With": "XMLHttpRequest"})
        check("gmod mounts: ...and applying a selection against it is REFUSED",
              (_gm_post.get_json() or {}).get("success") is False,
              "the panel rewrote mount.cfg from a state it could not read — an empty selection "
              "unmounts everything the server had")

        # The control: a readable state still reports and still applies.
        _gm_mod.gmod_current_mounts = lambda *a, **k: ["cstrike"]
        _gm_get2 = c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}
        check("gmod mounts: a readable state says so", _gm_get2.get("mounts_readable") is True,
              "%r" % (_gm_get2.get("mounts_readable"),))
        # From here the background APPLY worker's own dependencies are stubbed too. An apply spawns
        # a thread, and left real it would SSH at this suite's unreachable host for a minute and
        # land its write in the middle of a later check.
        import time as _gm_time
        _gm_state = _gm_mod._gmod_content_apply_state
        _gm_saved2 = (_gm_mod.ensure_content_user, _gm_mod.install_gmod_content,
                      _gm_mod.gmod_mount_setup)
        _gm_mounted = []

        def _gm_mount_spy(_remote, _gmod_user, _content_user, _games):
            _gm_mounted.append(list(_games))
            return True, "Mounted: %s — restart the server to apply" % (", ".join(_games) or "(none)")

        def _gm_settle(_timeout=20):
            _dl2 = _gm_time.time() + _timeout
            while (_gm_time.time() < _dl2
                   and (_gm_state.get(gs_id) or {}).get("status") == "running"):
                _gm_time.sleep(0.02)
            return dict(_gm_state.get(gs_id) or {})

        try:
            _gm_mod.ensure_content_user = lambda *a, **k: {"user": "gmodcontent",
                                                           "group": "gmodcontent", "present": {}}
            _gm_mod.gmod_mount_setup = _gm_mount_spy
            # SteamCMD ran and put nothing on disk — the out-of-free-disk case that this card's
            # own "Host disk" readout exists to warn about. ok=True, installed=[].
            _gm_mod.install_gmod_content = lambda *a, **k: (True, [], "already present")
            _gm_state.pop(gs_id, None)
            _gm_post2 = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                               headers={"X-Requested-With": "XMLHttpRequest"})
            check("gmod mounts: ...and an apply against it still goes through",
                  (_gm_post2.get_json() or {}).get("success") is True,
                  "the control failed — the refusal above proves nothing")

            # ── content that never downloaded must not be reported as mounted ───────────────
            # install_gmod_content returns (ok, installed, msg), where `installed` is the games it
            # re-verified are on disk AFTERWARDS. The worker discarded it and wrote the mount for
            # everything the operator ticked, then stored "Mounted: Counter-Strike: Source —
            # restart the server to apply" as the job result. mount.cfg pointed at a directory
            # that is not there, and the operator restarted as instructed into purple ERROR
            # textures on every map. The uninstall worker below it already reports what it
            # actually removed rather than what was asked.
            _gm_res = _gm_settle()
            check("gmod content: a game whose content did not install is NOT mounted",
                  bool(_gm_mounted) and "cstrike" not in _gm_mounted[-1],
                  "mount.cfg was written for %r — a mount pointing at content that is not on the "
                  "host" % (_gm_mounted,))
            check("gmod content: ...and the job says that, instead of reporting a mount",
                  _gm_res.get("status") == "error"
                  and "Counter-Strike" in (_gm_res.get("msg") or ""),
                  "job=%r" % (_gm_res,))

            # The control: content that IS on the host is mounted, and the job reports done — or
            # the checks above would pass on a card that simply refuses every apply.
            _gm_mod.install_gmod_content = lambda *a, **k: (True, ["cstrike"], "installed: cstrike")
            _gm_mounted[:] = []
            _gm_state.pop(gs_id, None)
            c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                   headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_res2 = _gm_settle()
            check("gmod content: (control) content that DID install is mounted and reported done",
                  _gm_mounted and _gm_mounted[-1] == ["cstrike"]
                  and _gm_res2.get("status") == "done",
                  "mounted=%r job=%r" % (_gm_mounted, _gm_res2))

            # ── every terminal result reaches the card that polls for it ────────────────────
            # The status GET filtered to status == "running", so a job that ended in error — "No
            # content storage could be prepared on the host.", "Content setup failed — check the
            # server logs.", gmod_mount_setup's "Couldn't read <user>'s group, so the content
            # mount was not granted" — was indistinguishable from no job at all: the spinner
            # vanished, the card said nothing, and the operator restarted the server into ERROR
            # textures. Every failure mode of a job that can run for two hours behaved this way.
            _gm_state[gs_id] = {"status": "error", "ts": _gm_time.time(),
                                "msg": "No content storage could be prepared on the host."}
            _gm_j = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job") or {}
            check("gmod content: a job that ended in error reaches the card that polls for it",
                  _gm_j.get("status") == "error" and "content storage" in (_gm_j.get("msg") or ""),
                  "job=%r — the failure was recorded and then filtered out of the only endpoint "
                  "that reports it" % (_gm_j,))
            _gm_state[gs_id] = {"status": "running", "msg": "", "ts": _gm_time.time()}
            _gm_jr = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job") or {}
            check("gmod content: (control) a running job is still reported",
                  _gm_jr.get("status") == "running", "job=%r" % (_gm_jr,))
            # ...and a long-finished one expires rather than greeting every later page load, the
            # way remote_bootstrap's job poll expires its done/failed card.
            _gm_state[gs_id] = {"status": "error", "msg": "an old failure",
                                "ts": _gm_time.time() - (_gm_mod._GMOD_JOB_TTL + 60)}
            _gm_je = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job")
            check("gmod content: ...and a long-finished one expires instead of reappearing",
                  _gm_je is None and gs_id not in _gm_state,
                  "job=%r — a month-old error greets every later visit to this server"
                  % (_gm_je,))

            # ── one content job per HOST ─────────────────────────────────────────────────────
            # Content is host-wide (one content user, one ~/serverfiles), but nothing stopped a
            # second job on the same host while the first ran: two SteamCMD installs into one
            # directory, or an uninstall deleting what another server's job was mounting. The
            # first job is held mid-install here, so the second request really does overlap it.
            import threading as _gm_thr
            _gm_gate = _gm_thr.Event()

            def _gm_slow_install(*a, **k):
                _gm_gate.wait(20)
                return (True, ["cstrike"], "installed: cstrike")
            _gm_mod.install_gmod_content = _gm_slow_install
            _gm_state.pop(gs_id, None)
            _gm_first = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                               headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_second = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                                headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_third = c.post("/api/server/%d/gmod-content" % gs_id,
                               json={"action": "uninstall", "games": ["cstrike"]},
                               headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_gate.set()
            _gm_after = _gm_settle()
            check("gmod content: a second apply on the same host while one runs is refused (409)",
                  (_gm_first.get_json() or {}).get("success") is True
                  and _gm_second.status_code == 409
                  and "already running" in ((_gm_second.get_json() or {}).get("message") or ""),
                  "first %r, second %d %r" % (_gm_first.get_json(), _gm_second.status_code,
                                              _gm_second.get_json()))
            check("gmod content: ...and so is an uninstall on that host",
                  _gm_third.status_code == 409, "got %d %r" % (_gm_third.status_code, _gm_third.get_json()))
            check("gmod content: ...and the first job still finished on its own",
                  _gm_after.get("status") == "done", "job=%r" % (_gm_after,))
            # Positive control: the host is free again the moment the job reports done.
            _gm_mod.install_gmod_content = lambda *a, **k: (True, ["cstrike"], "installed: cstrike")
            _gm_again = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                               headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_settle()
            check("gmod content: (control) once it finishes, the next job on that host is accepted",
                  (_gm_again.get_json() or {}).get("success") is True,
                  "got %d %r — the host stayed held" % (_gm_again.status_code, _gm_again.get_json()))
        finally:
            (_gm_mod.ensure_content_user, _gm_mod.install_gmod_content,
             _gm_mod.gmod_mount_setup) = _gm_saved2
            _gm_settle()
            _gm_state.pop(gs_id, None)
    finally:
        (_gm_mod.gmod_current_mounts, _gm_mod.detect_content_user,
         _gm_mod.path_disk_free) = _gm_saved
        with app.app_context():
            db.session.get(GameServer, gs_id).game_type = _gm_type_before
            db.session.commit()

    # ── a game LinuxGSM caps BELOW this host's release must be refused up front ───────────────
    # The picker marks these against the newest OS in the CATALOGUE — a stand-in, because the list
    # renders before a host is chosen. At install time the host IS chosen, so the comparison can
    # be the real one: LinuxGSM caps btl and onset at 20.04 and bf1942/bfv at 22.04, and on a
    # newer host those fail every time, minutes into the download, leaving a failed row behind.
    # Reported from the panel: Battalion 1944 offered and accepted on a 24.04 host.
    #
    # The catalogue is STUBBED, not read: this suite seeds a minimal serverlist.csv with no capped
    # game in it, so reading the real list would make every check below pass on an empty set. The
    # first version of this test did exactly that and reported it.
    import panel.routes.manage_servers as _os_mod
    # The DEFINITION site, not the package: panel/ops/ssh_manager/__init__.py exposes these
    # through __getattr__ so there is one stub target, and a unit check enforces that — it caught
    # this exact line. See ssh-manager-stub-seam-scope.
    from panel.ops.ssh_manager import hosts as _os_sm

    _os_saved = _os_sm.host_os_slug
    _os_before = _appmod_ij._remote_listening_ports
    _os_real_list = _os_mod.load_game_list

    def _os_try(name, port, game="btl"):
        """POST an install and say whether a row was created.

        Under the seam for the same reason the content-capture POST is: an accepted install starts
        a background worker, and the row is deleted below while it runs. Draining it here is what
        keeps its failure off the next row to be handed that id.
        """
        with _install_seam_closed("install-OS"):
            c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": game,
                                         "server_name": name, "port": str(port)},
                   follow_redirects=True)
        with app.app_context():
            _row = GameServer.query.filter_by(short_name=name).first()
            _made = _row is not None
            if _row is not None:
                db.session.delete(_row)
                db.session.commit()
        return _made

    _os_has = _os_mod.host_account_state
    try:
        _appmod_ij._remote_listening_ports = lambda r: {22}
        _os_mod.host_account_state = lambda r, n: "absent"
        _os_mod.load_game_list = lambda: [
            {"shortname": "btl", "name": "BATTALION: Legacy", "os": "ubuntu-20.04",
             "legacy_os": "ubuntu-20.04"},
            {"shortname": "csgo", "name": "CS:GO", "os": "ubuntu-24.04", "legacy_os": ""},
        ]

        _os_sm.host_os_slug = lambda s: "ubuntu-24.04"
        check("install OS: a game capped at 20.04 is refused on a 24.04 host, before the download",
              not _os_try("osrefuse", 28850),
              "the install started and will fail minutes in, leaving a failed row to clean up")

        # The control, and the case the operator actually asked about: the SAME game on a host
        # that CAN run it. A 20.04 remote under a 24.04 panel must still install it.
        _os_sm.host_os_slug = lambda s: "ubuntu-20.04"
        check("install OS: ...while the same game on a 20.04 REMOTE is still allowed",
              _os_try("osallow", 28851),
              "the guard is refusing installs that would have worked — the panel's own OS is not "
              "the one that matters here")

        # Fails OPEN: an unreadable host OS is not evidence of a problem.
        _os_sm.host_os_slug = lambda s: None
        check("install OS: ...and a host whose OS could not be read is not refused",
              _os_try("osunknown", 28852),
              "this fails closed — an unreadable OS blocks an install that may be fine")

        # The host NEWER than the whole catalogue. Every game declares the newest release LinuxGSM
        # builds its dependency list for — 136 of 140 say ubuntu-24.04 — so a guard that compares
        # that column against the host refuses EVERYTHING on an Ubuntu 26.04 box. The first
        # version of this change did, and the 26.04 leg of CI caught it. Only the catalogue-
        # relative cap (legacy_os) may decide.
        _os_sm.host_os_slug = lambda s: "ubuntu-26.04"
        check("install OS: ...and an ordinary game is still installable on a host NEWER than the "
              "whole catalogue",
              _os_try("osnewhost", 28853, game="csgo"),
              "every game declares 24.04, so this refuses the entire catalogue on a 26.04 host")
        check("install OS: ...while a capped game on that same newer host is still refused",
              not _os_try("osnewcap", 28854),
              "the 20.04 cap is real whatever the host is, and a 26.04 box is further past it")
    finally:
        _os_mod.load_game_list = _os_real_list
        _os_mod.host_account_state = _os_has
        _os_sm.host_os_slug = _os_saved
        _appmod_ij._remote_listening_ports = _os_before

    # ── a ban the engine drops at the next map change is not a ban ────────────────────────────
    # `banid ...; writeid` persists the id to cfg/banned_user.cfg, but the engine only reloads that
    # file if the server config EXECS it — and ensure_persistent_bans is what appends that line.
    # It ran on the install path and on the two GLOBAL-ban paths, whose docstring states the rule
    # outright ("this is the one place that knows a ban is about to be applied to this server"),
    # and not on the per-server moderate route. A server IMPORTED rather than installed through
    # the panel never had the line, so every ban issued from the Players panel lasted until the
    # map changed.
    _ban_ensured, _ban_saved = [], {}
    try:
        _bn_game = _sm_game
        _ban_saved["ensure"] = _bn_game.ensure_persistent_bans
        _ban_saved["moderate"] = _bn_game.moderate
        _bn_game.ensure_persistent_bans = lambda r, u, sn=None: _ban_ensured.append(u)
        _bn_game.moderate = (lambda r, u, gt, action, target="", message="", selfname=None,
                             steamid="", num=None: (True, "ok"))
        c.post("/api/server/%d/moderate" % gs_id,
               json={"action": "ban", "steamid": "STEAM_0:1:1234"},
               headers={"X-Requested-With": "XMLHttpRequest"})
        check("ban: the server is made to reload its ban list before the ban is issued",
              bool(_ban_ensured),
              "ensure_persistent_bans was never called, so on an imported server the engine "
              "drops this ban at the next map change")
        # ...and a NON-ban action must not pay for it — this runs an SSH round trip.
        _ban_ensured.clear()
        c.post("/api/server/%d/moderate" % gs_id,
               json={"action": "kick", "target": "someone"},
               headers={"X-Requested-With": "XMLHttpRequest"})
        check("ban: ...but a kick does not, since nothing is being persisted",
              not _ban_ensured, "called on a kick: %s" % (_ban_ensured,))
    finally:
        _bn_game.ensure_persistent_bans = _ban_saved["ensure"]
        _bn_game.moderate = _ban_saved["moderate"]

    # ── a ban "on all servers" must say which servers it did NOT reach ────────────────────────
    # The fan-out counted only its successes: `applied = sum(1 for r in ex.map(...) if r)`, with
    # _ban_other collapsing every other outcome to False — its `except Exception: return False`
    # swallowed the ConnectionError a paramiko host raises, and _sm.moderate returns ok=False for a
    # host reached over Tailscale or locally, because those transports return ("", "…", -1|255)
    # instead of raising. `if applied:` then gated BOTH the audit row and the message, so a
    # fan-out that reached nothing wrote no moderate_ban_all row at all and answered with the
    # origin server's bare "Done.", while the origin's own row still said success=True. An
    # operator reading either one believed the player was banned install-wide.
    from panel.db.models import AuditLog as _fo_AL
    _fo_saved, _fo_ids = {}, []
    try:
        _fo_saved["ensure"] = _sm_game.ensure_persistent_bans
        _fo_saved["moderate"] = _sm_game.moderate
        _sm_game.ensure_persistent_bans = lambda r, u, sn=None: True
        with app.app_context():
            _fo_rid = db.session.get(GameServer, gs_id).remote_id
            for _n, _sn in (("smoke-fanout-a", "fanoutaserver"), ("smoke-fanout-b", "fanoutbserver")):
                _row = GameServer(remote_id=_fo_rid, name=_n, short_name=_sn, game_type="csgo",
                                  port=27801 + len(_fo_ids), installed=True, status="offline")
                db.session.add(_row)
                db.session.commit()
                _fo_ids.append(_row.id)

        def _fo_moderate(r, u, gt, action, target="", message="", selfname=None, steamid="",
                         num=None):
            # The ORIGIN call succeeds; a named fan-out target is the unreachable host.
            return (u != _fo_dead["name"]), "ok"

        _fo_dead = {"name": "\0none"}      # nothing fails on the positive-control pass
        _sm_game.moderate = _fo_moderate
        with app.app_context():
            _fo_before = _fo_AL.query.filter_by(action="moderate_ban_all").count()
        _fo_ok = c.post("/api/server/%d/moderate" % gs_id,
                        json={"action": "ban", "steamid": "STEAM_0:1:770001", "scope": "all"},
                        headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        with app.app_context():
            _fo_row = _fo_AL.query.filter_by(action="moderate_ban_all").order_by(
                _fo_AL.id.desc()).first()
            _fo_after = _fo_AL.query.filter_by(action="moderate_ban_all").count()
        check("ban fan-out: an all-servers ban that reached every server logs success (control)",
              _fo_after == _fo_before + 1 and _fo_row is not None and _fo_row.success is True
              and "Also banned on" in (_fo_ok.get("message") or ""),
              "rows %d->%d row=%r msg=%r" % (_fo_before, _fo_after,
                                             getattr(_fo_row, "target", None),
                                             _fo_ok.get("message")))
        check("ban fan-out: ...and there were targets to fan out to, so this is not a vacuous pass",
              _fo_row is not None and not (_fo_row.target or "").startswith("0 of 0"),
              "target=%r — with no other valve server the checks below prove nothing"
              % (getattr(_fo_row, "target", None),))
        # Now one target is unreachable. That is the case the old code was silent about.
        _fo_dead["name"] = "fanoutbserver"
        with app.app_context():
            _fo_before = _fo_AL.query.filter_by(action="moderate_ban_all").count()
        _fo_bad = c.post("/api/server/%d/moderate" % gs_id,
                         json={"action": "ban", "steamid": "STEAM_0:1:770002", "scope": "all"},
                         headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        with app.app_context():
            _fo_row2 = _fo_AL.query.filter_by(action="moderate_ban_all").order_by(
                _fo_AL.id.desc()).first()
            _fo_after = _fo_AL.query.filter_by(action="moderate_ban_all").count()
        check("ban fan-out: a server the ban did not reach is recorded, not dropped",
              _fo_after == _fo_before + 1 and _fo_row2 is not None
              and _fo_row2.success is False and "fanoutbserver" in (_fo_row2.detail or ""),
              "rows %d->%d success=%r detail=%r — the audit row used to be gated on `applied`, so "
              "a partial or total miss left nothing to read"
              % (_fo_before, _fo_after, getattr(_fo_row2, "success", None),
                 getattr(_fo_row2, "detail", None)))
        check("ban fan-out: ...and the reply says so instead of claiming the whole install",
              "could not be reached" in (_fo_bad.get("message") or ""),
              "message=%r" % (_fo_bad.get("message"),))
    finally:
        _sm_game.ensure_persistent_bans = _fo_saved["ensure"]
        _sm_game.moderate = _fo_saved["moderate"]
        with app.app_context():
            for _fid in _fo_ids:
                _row = db.session.get(GameServer, _fid)
                if _row is not None:
                    db.session.delete(_row)
            db.session.commit()

    # ── a moderate body whose VALUES are not strings is a 400, never a 500 ────────────────────
    # `scope` was read as `(data.get("scope") or "this").strip()` — raw off the body, and ABOVE the
    # handler's try:, so a truthy non-string raised AttributeError that nothing here caught and the
    # app-wide handler turned into a JSON 500 "Internal server error" with a traceback in the log.
    # _json_body guarantees the BODY is a dict and says nothing about the VALUES, which is exactly
    # why _json_str exists and was already used on the next line for `reason`.
    import panel.routes.server_detail as _ms_rt
    _ms_saved = (_sm_game.moderate, _sm_game.ensure_persistent_bans, _ms_rt._resolve_from_console)
    try:
        _sm_game.moderate = (lambda r, u, gt, action, target="", message="", selfname=None,
                             steamid="", num=None: (True, "ok"))
        # The ban branch reaches these two before the try:, and both SSH. Stubbed so this block
        # tests the TYPING and never opens a connection.
        _sm_game.ensure_persistent_bans = lambda r, u, sn=None: True
        _ms_rt._resolve_from_console = lambda *a, **k: None
        for _lbl, _mb in (("scope", {"action": "kick", "target": "bob", "scope": 1}),
                          ("target", {"action": "kick", "target": {"a": 1}}),
                          ("message", {"action": "say", "message": ["x"]}),
                          ("num", {"action": "kick", "target": "bob", "num": {"z": 2}}),
                          ("steamid", {"action": "ban", "steamid": 5, "target": "bob"})):
            _mr = c.post("/api/server/%d/moderate" % gs_id, json=_mb,
                         headers={"X-Requested-With": "XMLHttpRequest"})
            check("moderate: a non-string %s is not a 500" % _lbl,
                  _mr.status_code < 500, "%r -> %d" % (_mb, _mr.status_code))
        # Positive control: the ordinary body still works, so this is not "refuse everything".
        _mr_ok = c.post("/api/server/%d/moderate" % gs_id,
                        json={"action": "kick", "target": "bob"},
                        headers={"X-Requested-With": "XMLHttpRequest"})
        check("moderate: ...while a well-formed kick still succeeds",
              _mr_ok.status_code == 200 and (_mr_ok.get_json() or {}).get("success") is True,
              "%d %r" % (_mr_ok.status_code, _mr_ok.get_json()))
    finally:
        (_sm_game.moderate, _sm_game.ensure_persistent_bans,
         _ms_rt._resolve_from_console) = _ms_saved

    # ── a backup must prune to THIS server's retention, not the global default ────────────────
    # The per-server override is first-class: the schedule route writes it, get_game_schedule
    # resolves "its override where set, else the global default", the API and the disk projection
    # in the UI both show it. But only the scheduled ticker read it. The three other paths that
    # run a backup — "Back up now", the full backup, and the queued-when-empty sweep — passed the
    # GLOBAL keep, and pruning is an unconditional `rm` of everything past it. A server whose
    # operator had deliberately raised its retention lost those archives the next time any of
    # those three ran.
    #
    # Asserted on the number actually handed to run_game_backup, because that is the value the
    # prune uses; anything else would be testing the config layer twice.
    import panel.routes.panel_backup as _bkroute
    from panel.ops import backup as _bkmod
    from panel.core.panel_state import _full_backup_lock as _bk_lock_chk

    _keep_seen = []
    _bk_saved = {}

    def _bk_stub(mod, name, fn):
        _bk_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    # Wait for any backup worker still running before stubbing: the stub records every call by
    # the name it replaces, and a straggler's call is not this route's. See the lock held across
    # the typed-body sweep above, which is where one came from.
    for _ in range(200):
        if not _bk_lock_chk.locked():
            break
        _ijw_time.sleep(0.05)
    try:
        _bk_stub(_bkroute, "run_game_backup",
                 lambda remote, short, lgsm, keep, **k: (_keep_seen.append(keep),
                                                         (True, "", False))[1])
        _bk_global = _bkmod.get_full_settings()["keep"]
        _bk_override = int(_bk_global) + 7          # unmistakably not the global value
        _bkmod.set_game_schedule(gs_id, 1, _bk_override)
        try:
            c.post("/api/panel/backup/game/%d" % gs_id,
                   headers={"X-Requested-With": "XMLHttpRequest"})
            for _ in range(100):
                if _keep_seen:
                    break
                _ijw_time.sleep(0.05)
            check("backup keep: 'Back up now' prunes to THIS server's retention",
                  _keep_seen and _keep_seen[0] == _bk_override,
                  "handed keep=%r, but this server's override is %r (global is %r) — the extra "
                  "archives are deleted" % (_keep_seen[:1], _bk_override, _bk_global))
        finally:
            _bkmod.set_game_schedule(gs_id, None, None)
    finally:
        for (_m, _n), _v in _bk_saved.items():
            setattr(_m, _n, _v)

    # ── a failed READ must not be written down as a fact ──────────────────────────────────────
    # Two routes did it in different ways. Both are driven here with the read stubbed to fail the
    # way it actually fails on this codebase: run_command does not raise, it returns
    # ("", "...timed out", -1).
    import panel.routes.remote_vps as _rvmod
    import panel.ops.ssh_manager as _fr_pkg   # noqa: F401  (documented: stub the DEFINITION site)
    from panel.ops.ssh_manager import game as _fr_game

    # 1. close-panel-port answered "already closed" from a firewall it never managed to read.
    #    remote_ufw_status returns {"installed": False, ..., "groups": []} for a missing ufw and
    #    adds "unreachable": True when the command failed — its docstring says it does that so a
    #    down remote is not shown as an installed firewall with no rules. Reading only .get(
    #    "groups") threw that away: no rules found, so "closed", success=True, no audit row, while
    #    the panel was still listening on 0.0.0.0.
    _fr_saved = {}

    def _fr_stub(mod, name, fn):
        _fr_saved[(mod, name)] = getattr(mod, name)
        setattr(mod, name, fn)

    try:
        # The LOCAL host: this route refuses anything else with "Only applies to the panel host."
        # Picking a remote one made the check pass on that refusal instead of on the firewall
        # read — green, and measuring nothing. Flagged back afterwards.
        with app.app_context():
            _fr_remote = RemoteServer.query.filter_by(is_local=True).first() \
                or RemoteServer.query.first()
            _fr_rid = _fr_remote.id
            _fr_was_local = bool(_fr_remote.is_local)
            _fr_remote.is_local = True
            db.session.commit()
        _fr_cfg = load_config()
        _fr_cfg_saved = dict(_fr_cfg)
        _fr_cfg["tailscale_setup_done"] = True
        save_config(_fr_cfg)
        _fr_stub(_rvmod, "remote_ufw_status",
                 lambda r: {"installed": False, "enabled": False, "rules": [], "groups": [],
                            "unreachable": True})
        _fr_deleted = []
        _fr_stub(_rvmod, "remote_ufw_delete_rule",
                 lambda r, n, force=False, **k: _fr_deleted.append(n))
        _fr_r = c.post("/api/remote/%d/close-panel-port" % _fr_rid,
                       headers={"X-Requested-With": "XMLHttpRequest"})
        _fr_j = _fr_r.get_json() or {}
        check("failed read: an unreadable firewall is NOT reported as 'port already closed'",
              _fr_j.get("success") is not True,
              "answered %r — the panel is still listening on that port"
              % (_fr_j.get("message"),))
        check("failed read: ...and nothing was deleted from a firewall it could not read",
              not _fr_deleted, "deleted rule numbers %s" % (_fr_deleted,))
        # A READABLE firewall: its forced deletes by number must each name the rule they mean.
        # The numbers are read once and the auto-block inserts at 1 from another thread, so a
        # forced delete by bare number could take the rule above the panel port's.
        _fr_port = int(_fr_cfg.get("port", 5000))
        setattr(_rvmod, "remote_ufw_status",     # original already saved by _fr_stub above
                 lambda r: {"installed": True, "enabled": True, "rules": [], "groups": [
                     {"nums": [4, 9], "port_num": str(_fr_port), "action": "ALLOW",
                      "direction": "IN", "is_iface": False, "key": "k-panel-port"}]})
        _fr_keys = []
        setattr(_rvmod, "remote_ufw_delete_rule",
                 lambda r, n, force=False, expect_key=None, **k: (_fr_keys.append((n, expect_key)),
                                                                  (True, ""))[1])
        c.post("/api/remote/%d/close-panel-port" % _fr_rid,
               headers={"X-Requested-With": "XMLHttpRequest"})
        check("close panel port: each forced delete names the rule it means, not just its number",
              _fr_keys == [(9, "k-panel-port"), (4, "k-panel-port")], "deleted %r" % (_fr_keys,))
    finally:
        for (_m, _n), _v in _fr_saved.items():
            setattr(_m, _n, _v)
        save_config(_fr_cfg_saved)
        _fr_saved.clear()
        with app.app_context():
            _r = db.session.get(RemoteServer, _fr_rid)
            if _r is not None:
                _r.is_local = _fr_was_local
                db.session.commit()

    # 2. refresh-commands overwrote the stored list with whatever came back, and [] is what
    #    list_server_commands returns for a timeout, a non-zero exit or an empty pane.
    try:
        with app.app_context():
            _rc_gs = db.session.get(GameServer, gs_id)
            _rc_before = _rc_gs.commands
            _rc_gs.set_commands([{"cmd": "start", "short": "st", "desc": "Start the server."},
                                 {"cmd": "stop", "short": "sp", "desc": "Stop it."}])
            db.session.commit()
        _fr_stub(_fr_game, "list_server_commands", lambda *a, **k: [])
        c.post("/server/%d/refresh-commands" % gs_id)
        with app.app_context():
            _rc_after = db.session.get(GameServer, gs_id).get_commands()
        check("failed read: an empty command list does not wipe the stored one",
              len(_rc_after) == 2,
              "the stored list became %r — Start/Stop/Update vanish from the control bar for "
              "everyone" % (_rc_after,))
        # ...and a real answer still replaces it, so the guard is not "never update".
        _fr_stub(_fr_game, "list_server_commands",
                 lambda *a, **k: [{"cmd": "start", "short": "st", "desc": "Start."},
                                  {"cmd": "stop", "short": "sp", "desc": "Stop."},
                                  {"cmd": "update", "short": "u", "desc": "Update."}])
        c.post("/server/%d/refresh-commands" % gs_id)
        with app.app_context():
            _rc_new = db.session.get(GameServer, gs_id).get_commands()
        check("failed read: ...while a real answer still replaces it", len(_rc_new) == 3,
              "got %r" % (_rc_new,))
    finally:
        for (_m, _n), _v in _fr_saved.items():
            setattr(_m, _n, _v)
        with app.app_context():
            db.session.get(GameServer, gs_id).commands = _rc_before
            db.session.commit()

    # ── the custom-command FORM: the guard that stops a template smuggling a second command ──────
    # A custom command's template is sent to tmux as a console LINE. A newline in it is a second
    # keystroke sequence — a command the author did not write and the reviewer did not see.
    # _custom_cmd_form() refuses control characters for exactly that reason, and nothing executed
    # it: /commands/add, /edit and /delete were three of the 65 routes no suite ever entered.
    # Superadmin-only, and the url_map baseline pins that, so this is about the BODY.
    def _cc_count():
        with app.app_context():
            return CustomCommand.query.count()

    def _cc_add(name, template, **extra):
        _before = _cc_count()
        data = {"name": name, "command_template": template, "scope": "all", "enabled": "on"}
        data.update(extra)
        c.post("/commands/add", data=data)
        return _cc_count() - _before

    check("custom command form: a valid template is accepted (the control)",
          _cc_add("cc_ok", "say hello") == 1,
          "the positive control failed — every refusal below proves nothing")
    check("custom command form: a NEWLINE in the template is refused",
          _cc_add("cc_nl", "say hi\nquit") == 0,
          "a template that smuggles a second console line was stored")
    check("custom command form: ...as is a carriage return",
          _cc_add("cc_cr", "say hi\rquit") == 0)
    check("custom command form: ...and a NUL", _cc_add("cc_nul", "say hi\x00quit") == 0)
    check("custom command form: ...and an escape, which starts a terminal sequence",
          _cc_add("cc_esc", "say \x1b[2J") == 0)
    check("custom command form: two placeholders are refused",
          _cc_add("cc_two", "say {} and {}") == 0,
          "a second {} makes the argument substitution ambiguous")
    check("custom command form: an empty template is refused", _cc_add("cc_empty", "") == 0)
    check("custom command form: a scope naming a game that does not exist is refused",
          _cc_add("cc_badgame", "say hi", scope="game|nosuchgame") == 0)
    check("custom command form: ...and an engine that does not exist",
          _cc_add("cc_badengine", "say hi", scope="engine|nosuchengine") == 0)
    # ...but an EXISTING command scoped to a game the current list lacks (dropped upstream, or no
    # list could be fetched) keeps that scope. Its edit form had no matching option, the browser
    # selected "All games", and a Save to fix the label widened the command to every game.
    with app.app_context():
        _oc = CustomCommand(name="cc_orphan", command_template="say hi", scope_type="game",
                            scope_value="nosuchgame", enabled=True)
        db.session.add(_oc)
        db.session.commit()
        _oc_id = _oc.id
    try:
        check("custom command edit form: a stored game scope the list lacks is offered, and selected",
              'value="game|nosuchgame" selected' in c.get("/commands").get_data(as_text=True),
              "no option matches, so the browser submits the first one — All games")
        c.post("/commands/%d/edit" % _oc_id, data={"name": "cc_orphan", "command_template": "say hello",
                                                    "scope": "game|nosuchgame", "enabled": "on"})
        with app.app_context():
            _oc2 = db.session.get(CustomCommand, _oc_id)
            _oc_state = (_oc2.scope_type, _oc2.scope_value, _oc2.command_template)
        check("custom command edit: saving it keeps that game scope and applies the edit",
              _oc_state == ("game", "nosuchgame", "say hello"), "stored %r" % (_oc_state,))
        c.post("/commands/%d/edit" % _oc_id, data={"name": "cc_orphan", "command_template": "say bye",
                                                    "scope": "game|othernosuchgame", "enabled": "on"})
        with app.app_context():
            _oc3 = db.session.get(CustomCommand, _oc_id)
            _oc_state = (_oc3.scope_value, _oc3.command_template)
        check("custom command edit: ...while moving it to a DIFFERENT unknown game is still refused",
              _oc_state == ("nosuchgame", "say hello"), "stored %r" % (_oc_state,))
    finally:
        with app.app_context():
            db.session.delete(db.session.get(CustomCommand, _oc_id))
            db.session.commit()
    # An unparseable argument pattern must not 500 or store itself — it falls back to the default.
    _cc_re_added = _cc_add("cc_badre", "say {}", argument_pattern="([unclosed")
    check("custom command form: an invalid argument pattern does not store a broken regex",
          _cc_re_added in (0, 1), "unexpected result %s" % _cc_re_added)
    if _cc_re_added == 1:
        with app.app_context():
            _bad = CustomCommand.query.filter_by(name="cc_badre").first()
            check("custom command form: ...it falls back to a pattern that compiles",
                  _bad is not None and _bad.argument_pattern != "([unclosed",
                  "stored %r" % (getattr(_bad, "argument_pattern", None),))
    with app.app_context():
        for _n in ("cc_ok", "cc_badre"):
            _row = CustomCommand.query.filter_by(name=_n).first()
            if _row is not None:
                db.session.delete(_row)
        db.session.commit()

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

    # ── a superadmin resetting SOMEONE ELSE's 2FA ─────────────────────────────────────────────
    # rbac_test covers the refusal (a MANAGE_USERS admin must not reach a more-privileged
    # account). The path that is supposed to WORK had no test at all, and it is the one the whole
    # 2FA design leans on: /account/2fa/disable now demands a second factor, and "an admin can
    # clear it for someone who lost both" is what makes that safe to require.
    from panel.db.models import User as _R2U

    with app.app_context():
        _r2 = _R2U(username="reset2fa_target",
                   password_hash=auth.hash_password("Str0ng!passw0rd"),
                   display_name="target", is_superadmin=False, is_active=True,
                   totp_enabled=True, totp_secret=encrypt_secret(auth.generate_totp_secret()))
        _r2.set_backup_codes(auth.generate_backup_codes())
        db.session.add(_r2)
        db.session.commit()
        _r2_id = _r2.id
        _AL.query.filter_by(action="2fa_reset").delete()
        db.session.commit()

    # The control is only reachable if the page TELLS the modal this account has 2FA — the switch
    # is disabled without it. Assert the data island carries the flag, not just that the route
    # works, or the feature can be correct and unreachable at the same time.
    import json as _r2_json
    import re as _r2_re
    _r2_page = c.get("/users").get_data(as_text=True)
    _r2_m = _r2_re.search(r'id="users-data"[^>]*>(.*?)</script>', _r2_page, _r2_re.S)
    _r2_island = _r2_json.loads(_r2_m.group(1)) if _r2_m else []
    _r2_row = next((r for r in _r2_island if r.get("id") == _r2_id), None)
    check("admin 2fa reset: the users page tells the edit modal this account HAS 2FA",
          (_r2_row or {}).get("totp_enabled") is True,
          "island row %r — without this the switch renders disabled and the admin cannot use it"
          % (_r2_row,))

    c.post("/users/%d/edit" % _r2_id,
           data={"username": "reset2fa_target", "display_name": "target",
                 "is_active": "on", "reset_2fa": "on"}, follow_redirects=True)
    with app.app_context():
        _r2_after = db.session.get(_R2U, _r2_id)
        _r2_still = bool(_r2_after.totp_enabled and _r2_after.totp_secret)
        _r2_codes = _r2_after.backup_codes_remaining
        _r2_audit = _AL.query.filter_by(action="2fa_reset").count()
    check("admin 2fa reset: a superadmin clears another user's 2FA", not _r2_still,
          "2FA survived the reset, so an operator who lost their authenticator has no way back in")
    check("admin 2fa reset: ...and its backup codes go with it", _r2_codes == 0,
          "%d backup codes still accepted for a second factor that is gone" % _r2_codes)
    check("admin 2fa reset: ...and it is audited", _r2_audit == 1,
          "%d 2fa_reset rows — clearing someone's second factor must leave a trace" % _r2_audit)

    # ...and it does NOT fire when the box is left unticked, which is every other edit.
    with app.app_context():
        _r2b = db.session.get(_R2U, _r2_id)
        _r2b.totp_enabled = True
        _r2b.totp_secret = encrypt_secret(auth.generate_totp_secret())
        db.session.commit()
    c.post("/users/%d/edit" % _r2_id,
           data={"username": "reset2fa_target", "display_name": "target renamed",
                 "is_active": "on"}, follow_redirects=True)
    with app.app_context():
        check("admin 2fa reset: ...and an ordinary edit leaves 2FA alone (positive control)",
              bool(db.session.get(_R2U, _r2_id).totp_enabled),
              "every save now strips the user's second factor")
        db.session.delete(db.session.get(_R2U, _r2_id))
        db.session.commit()

    # ── the SSH-port and SSH-mode routes, which nothing entered ───────────────────────────────
    # Both change how an operator reaches a host, and a wrong outcome written down is how someone
    # believes they still have a way in. Neither route body was executed by any suite: the port
    # one validates input, then updates RemoteServer.port so the panel's own future connections
    # follow — and that update must happen only when the change actually took.
    import panel.routes.remote_vps as _shmod

    _sh_saved = (_shmod.change_ssh_port, _shmod.remote_set_public_ssh)
    _sh_calls = []

    def _al_last(action):
        """The most recent audit row for `action`, as a plain dict (the row is detached after)."""
        with app.app_context():
            _row = _AL.query.filter_by(action=action).order_by(_AL.id.desc()).first()
            return {"success": _row.success, "detail": _row.detail} if _row else None

    try:
        with app.app_context():
            _sh_before = db.session.get(RemoteServer, remote_id).port

        def _sh_port(remote, port):
            return c.post("/api/remote/%d/ssh-port" % remote_id, json={"port": port})

        def _sh_stored():
            with app.app_context():
                return db.session.get(RemoteServer, remote_id).port

        _shmod.change_ssh_port = lambda r, p, b="": (_sh_calls.append(p), (True, "moved"))[1]
        for _bad, _why in ((0, "zero"), (65536, "above the range"), ("nope", "not a number"),
                           (None, "missing")):
            _sh_calls.clear()
            _r = _sh_port(remote_id, _bad)
            check("ssh port: %r (%s) is refused before anything is changed" % (_bad, _why),
                  _r.status_code == 400 and not _sh_calls,
                  "status=%d, change_ssh_port called with %s" % (_r.status_code, _sh_calls))
        check("ssh port: ...and the stored port is untouched by all of that",
              _sh_stored() == _sh_before, "port moved to %r on a refused request" % _sh_stored())

        # A change that FAILED must not move the panel's own idea of the port: it would then
        # connect to a port sshd is not on, and the operator's next visit says the host is down.
        _shmod.change_ssh_port = lambda r, p, b="": (False, "sshd rejected the new config")
        _r = _sh_port(remote_id, 2222)
        check("ssh port: a change that FAILED does not repoint the panel at the new port",
              _sh_stored() == _sh_before,
              "stored port is now %r though the change failed — the panel will dial a port "
              "nothing is listening on" % _sh_stored())
        check("ssh port: ...and it is audited as a failure",
              (_al_last("change_ssh_port") or {}).get("success") is False,
              "audited %r" % ((_al_last("change_ssh_port") or {}).get("success"),))

        # ...and the control: one that worked DOES move it, and is audited as a success.
        _shmod.change_ssh_port = lambda r, p, b="": (True, "moved")
        _r = _sh_port(remote_id, 2223)
        check("ssh port: a change that WORKED repoints the panel (positive control)",
              _sh_stored() == 2223,
              "stored port is %r — the panel keeps dialling the old one" % _sh_stored())
        check("ssh port: ...and is audited as a success",
              (_al_last("change_ssh_port") or {}).get("success") is True,
              "audited %r" % ((_al_last("change_ssh_port") or {}).get("success"),))

        # ssh-mode: its whole job is the audit row, since the outcome is on the host.
        _shmod.remote_set_public_ssh = lambda r, m: (False, "ufw refused")
        c.post("/api/remote/%d/ssh-mode" % remote_id, json={"mode": "limit"})
        check("ssh mode: a refused change is audited as a failure",
              (_al_last("remote_ssh_mode") or {}).get("success") is False,
              "audited %r" % ((_al_last("remote_ssh_mode") or {}).get("success"),))
        _shmod.remote_set_public_ssh = lambda r, m: (True, "ok")
        c.post("/api/remote/%d/ssh-mode" % remote_id, json={"mode": "off"})
        check("ssh mode: ...and one that worked is audited as a success (positive control)",
              (_al_last("remote_ssh_mode") or {}).get("success") is True,
              "audited %r" % ((_al_last("remote_ssh_mode") or {}).get("success"),))
    finally:
        (_shmod.change_ssh_port, _shmod.remote_set_public_ssh) = _sh_saved
        with app.app_context():
            db.session.get(RemoteServer, remote_id).port = _sh_before
            db.session.commit()

    # ── close-port-22, which removed public SSH with nothing checked at all ───────────────────
    # The route ran `ufw delete allow 22/tcp` on whatever host id was posted and answered "Port 22
    # rule removed from UFW" with a success audit row. On a key-auth host reachable only over its
    # public IP that locks the panel AND the operator out, with no way back from the UI — while
    # ssh-mode above, which makes the SAME change, has always refused without a tailnet path back.
    # remote_ufw_close_port_22 checks nothing either; "safe if Tailscale SSH is active" is its
    # docstring, not a guard.
    import panel.routes.close_port22 as _cpmod
    _cp_saved = (_cpmod._tailnet_ssh_state, _cpmod.remote_ufw_close_port_22)
    _cp_closed = []
    try:
        _cpmod.remote_ufw_close_port_22 = lambda r: (_cp_closed.append(getattr(r, "id", "?")),
                                                     (True, "Port 22 rule removed from UFW"))[1]
        _cpmod._tailnet_ssh_state = lambda r: (False, False, False)      # no tailnet way back
        _cpj = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
        check("close port 22: refused when there is no Tailscale way back into the host",
              _cpj.get("success") is False and not _cp_closed,
              "answered %s and called ufw for %s" % (str(_cpj)[:120], _cp_closed))
        check("close port 22: ...and the refusal is audited as a failure, not as a change",
              (_al_last("remote_close_port_22") or {}).get("success") is False,
              "audited %r" % ((_al_last("remote_close_port_22") or {}).get("success"),))
        # Tailscale merely RUNNING is not a way in: with its SSH server off and tailscale0 not
        # allowed in UFW there is still nothing listening for you. This is the state the Tailscale
        # migrate path already refuses on, and the one the docstring's "safe if Tailscale SSH is
        # active" was being read as covering.
        _cpmod._tailnet_ssh_state = lambda r: (True, False, False)
        _cpj2 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
        check("close port 22: ...and Tailscale running with SSH OFF is not a way back either",
              _cpj2.get("success") is False and not _cp_closed,
              "answered %s and called ufw for %s" % (str(_cpj2)[:120], _cp_closed))
        # The control: a host that really can be reached over the tailnet still closes, so the two
        # checks above cannot be passing on a route that refuses everything.
        _cpmod._tailnet_ssh_state = lambda r: (True, True, False)
        _cpj3 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
        check("close port 22: a host with Tailscale SSH working still closes (positive control)",
              _cpj3.get("success") is True and _cp_closed == [remote_id],
              "answered %s and called ufw for %s" % (str(_cpj3)[:120], _cp_closed))
        # ...and so does one reachable only because tailscale0 is allowed in UFW, which is the
        # other half of the gate remote_set_public_ssh("off") applies.
        _cp_closed[:] = []
        _cpmod._tailnet_ssh_state = lambda r: (True, False, True)
        _cpj4 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
        check("close port 22: ...and an allowed tailscale0 interface counts as a way back too",
              _cpj4.get("success") is True and _cp_closed == [remote_id],
              "answered %s and called ufw for %s" % (str(_cpj4)[:120], _cp_closed))
    finally:
        (_cpmod._tailnet_ssh_state, _cpmod.remote_ufw_close_port_22) = _cp_saved

    # ── deleting a UFW rule by number, which nothing entered either ───────────────────────────
    # The route hands `num` to a helper whose whole job is refusing a delete that would lock the
    # operator out — including when the firewall could not be READ, because "I could not check"
    # is not "it is safe". The route's own contribution is the audit row, and that it never
    # passes force=True: a caller cannot reach the override through the API.
    import panel.routes.remote_vps as _fwmod

    _fw_saved = _fwmod.remote_ufw_delete_rule
    _fw_args = []
    try:
        def _fw_stub(server, num, force=False, expect_key=None):
            _fw_args.append({"num": num, "force": force, "key": expect_key})
            return (False, "refused")
        _fwmod.remote_ufw_delete_rule = _fw_stub
        c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3})
        check("ufw delete: the route never asks for the force override",
              _fw_args and _fw_args[-1]["force"] is False,
              "called with force=%r — the API would be able to delete the rule keeping SSH open"
              % (_fw_args[-1:] or None,))
        check("ufw delete: a refusal is audited as a failure",
              (_al_last("remote_ufw_delete_rule") or {}).get("success") is False,
              "audited %r" % ((_al_last("remote_ufw_delete_rule") or {}).get("success"),))
        # The number is a position; the page sends the rule's key with it, and the route has to
        # hand that on, or the helper cannot notice the number now names a different rule.
        _fw_key = '["27015", "ALLOW", "IN", "Anywhere", "", "gamea"]'
        c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3, "key": _fw_key})
        check("ufw delete: the route passes the rule's key on, so a moved number is refused",
              _fw_args and _fw_args[-1]["key"] == _fw_key, "called with %r" % (_fw_args[-1:] or None,))
        check("ufw delete: ...and a request with no key is no identity check, not an empty one",
              len(_fw_args) >= 2 and _fw_args[-2]["key"] is None, "called with %r" % (_fw_args,))
        _fwmod.remote_ufw_delete_rule = lambda s, n, force=False, expect_key=None: (True, "deleted")
        c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3})
        check("ufw delete: ...and a delete that happened is audited as a success (control)",
              (_al_last("remote_ufw_delete_rule") or {}).get("success") is True,
              "audited %r" % ((_al_last("remote_ufw_delete_rule") or {}).get("success"),))
    finally:
        _fwmod.remote_ufw_delete_rule = _fw_saved

    # ── revoking an invite must claim it, not read it and then write ─────────────────────────────
    # Redemption claims the row atomically — "UPDATE ... WHERE used_at IS NULL", with a comment
    # saying that checking is_usable and trusting it would be a race. Revocation was the
    # read-then-write half of that same race: it checked used_at, and stamped revoked_at after.
    # A link redeemed in between left a row stamped BOTH used and revoked, and told the admin the
    # link no longer works — about an invite whose account had just been created.
    #
    # Driven deterministically by opening the window by hand: utcnow() is what the route calls
    # between the two, so a stub that marks the invite used is exactly the redemption landing
    # there. The atomic version evaluates it BEFORE the UPDATE, so the WHERE clause sees the
    # claim and matches nothing.
    import panel.routes.admin_notifications as _ivmod
    from panel.db.models import Invite as _IvR
    from sqlalchemy import text as _iv_text

    _iv_saved_now = _ivmod.utcnow
    try:
        with app.app_context():
            _iv_admin = db.session.get(User, admin_id)
            _iv_row, _ = _IvR.mint(_iv_admin, hours=24)
            db.session.add(_iv_row)
            db.session.commit()
            _iv_id = _iv_row.id
            _AL.query.filter_by(action="invite_revoked").delete()
            db.session.commit()

        def _iv_redeem_mid_flight():
            """The redemption, landing in the window the route leaves open."""
            db.session.execute(_iv_text("UPDATE invite SET used_at = :t WHERE id = :i"),
                               {"t": _iv_saved_now(), "i": _iv_id})
            return _iv_saved_now()

        _ivmod.utcnow = _iv_redeem_mid_flight
        _iv_resp = c.post("/users/invite/%d/revoke" % _iv_id, follow_redirects=True)
        _ivmod.utcnow = _iv_saved_now
        _iv_body = _iv_resp.get_data(as_text=True)
        with app.app_context():
            _iv_after = db.session.get(_IvR, _iv_id)
            _iv_used = _iv_after.used_at is not None
            _iv_revoked = _iv_after.revoked_at is not None
            _iv_audit = _AL.query.filter_by(action="invite_revoked").count()
        check("invite revoke: the redemption really did land first (positive control)",
              _iv_used, "the window never opened, so the checks below prove nothing")
        check("invite revoke: a link redeemed in the same instant is not ALSO stamped revoked",
              not _iv_revoked,
              "the row is stamped used AND revoked — a read-then-write lost the race")
        check("invite revoke: ...and the admin is told it was redeemed, not that it was revoked",
              "already redeemed" in _iv_body and "no longer works" not in _iv_body,
              "the page reported a revocation of an invite that had just made an account")
        check("invite revoke: ...and nothing is audited as a revocation",
              _iv_audit == 0, "%d invite_revoked row(s) for an invite that was redeemed" % _iv_audit)

        # The ordinary path still works: an unredeemed invite is revoked and audited.
        with app.app_context():
            _iv_row2, _ = _IvR.mint(db.session.get(User, admin_id), hours=24)
            db.session.add(_iv_row2)
            db.session.commit()
            _iv_id2 = _iv_row2.id
        _iv_body2 = c.post("/users/invite/%d/revoke" % _iv_id2,
                           follow_redirects=True).get_data(as_text=True)
        with app.app_context():
            _iv_after2 = db.session.get(_IvR, _iv_id2)
            _iv_ok = _iv_after2.revoked_at is not None and not _iv_after2.is_usable
            _iv_audit2 = _AL.query.filter_by(action="invite_revoked").count()
        check("invite revoke: an unredeemed invite is still revoked (positive control)",
              _iv_ok and "no longer works" in _iv_body2,
              "revoking stopped working altogether, so the checks above would pass with the "
              "route removed")
        check("invite revoke: ...and that one IS audited", _iv_audit2 == 1,
              "%d invite_revoked rows" % _iv_audit2)
    finally:
        _ivmod.utcnow = _iv_saved_now

    # ── the invite list must be bounded over REDEEMABLE invites, not over all of them ───────────
    # /users took `Invite.query.order_by(created_at.desc()).limit(25)` — the 25 newest rows of ANY
    # state — while its own comment said the useful part of the list is what is still redeemable.
    # The Revoke button is rendered only for rows in that list, and revoke_invite is linked from
    # nowhere else, so 25 newer used/expired links pushed a live one off the page and left it
    # working and unrevokable through the UI for the rest of its TTL.
    from datetime import timedelta as _iv_td
    from panel.core.clock import utcnow as _iv_now
    _iv_made = []
    try:
        with app.app_context():
            _iv_admin3 = db.session.get(User, admin_id)
            _iv_live, _ = _IvR.mint(_iv_admin3, hours=720, note="smoke-live-invite")
            _iv_live.created_at = _iv_now() - _iv_td(days=40)
            db.session.add(_iv_live)
            db.session.flush()
            _iv_live_id = _iv_live.id
            _iv_made.append(_iv_live_id)
            # 30 NEWER rows, every one of them finished: under the old bound these alone filled
            # the page and the live one above never appeared.
            for _n in range(30):
                _iv_dead, _ = _IvR.mint(_iv_admin3, hours=720, note="smoke-dead-%02d" % _n)
                _iv_dead.created_at = _iv_now() - _iv_td(minutes=(30 - _n))
                _iv_dead.used_at = _iv_dead.created_at
                db.session.add(_iv_dead)
                db.session.flush()
                _iv_made.append(_iv_dead.id)
            db.session.commit()
            _iv_live_row = db.session.get(_IvR, _iv_live_id)
            _iv_live_usable = _iv_live_row.is_usable
            _iv_live_older = all(db.session.get(_IvR, i).created_at > _iv_live_row.created_at
                                 for i in _iv_made[1:])
        # The setup has to be the setup the bug needs, or the check below proves nothing.
        check("invite list: the fixture really is one live invite behind 30 newer dead ones",
              _iv_live_usable and _iv_live_older,
              "live=%r, all 30 newer=%r" % (_iv_live_usable, _iv_live_older))
        _iv_page = c.get("/users").get_data(as_text=True)
        check("invite list: a still-redeemable invite is not crowded out by newer finished ones",
              ("/users/invite/%d/revoke" % _iv_live_id) in _iv_page,
              "the only Revoke button a live link ever gets was pushed off the page")
        # Positive control: finished invites are still shown for context, so the fix is a
        # re-bounding of the list and not a filter that emptied it.
        check("invite list: finished invites are still listed for context",
              "smoke-dead-29" in _iv_page,
              "the page now shows nothing but live invites")
    finally:
        with app.app_context():
            if _iv_made:
                _IvR.query.filter(_IvR.id.in_(_iv_made)).delete(synchronize_session=False)
                db.session.commit()

    # ── and the ROUTE must not publish a reading nobody took ──────────────────────────────────
    # The helper now says read_ok; this is the caller that has to act on it. Driven through the
    # endpoint the page actually polls, because a flag no route reads changes nothing on screen.
    import panel.routes.ubuntu_pro as _lrmod

    _lr_saved = _lrmod.remote_live_metrics
    try:
        _lr_zeros = {"read_ok": False, "cpu_overall": 0.0, "cpu_cores": [], "core_count": 0,
                     "ram_used": 0, "ram_total": 0, "ram_percent": 0, "swap_used": 0,
                     "swap_total": 0, "swap_percent": 0, "disk_used": 0, "disk_total": 0,
                     "disk_percent": 0}
        _lrmod.remote_live_metrics = lambda r: _lr_zeros
        _lr = c.get("/api/remote/%d/live" % remote_id).get_json() or {}
        check("live route: a read that produced nothing answers an error, not zeros",
              bool(_lr.get("error")) and "cpu_overall" not in _lr,
              "published %r — the card renders CPU 0%%, 0 cores and RAM 0 of 0 for a host that "
              "never answered" % (sorted(_lr.items())[:4],))
        check("live route: ...and says the host did not answer, so the card can say so too",
              _lr.get("unreachable") is True, "no unreachable flag: %r" % (_lr,))

        _lrmod.remote_live_metrics = lambda r: dict(_lr_zeros, read_ok=True, cpu_overall=12.5,
                                                    ram_total=2048, ram_used=1024, core_count=2)
        _lr2 = c.get("/api/remote/%d/live" % remote_id).get_json() or {}
        check("live route: ...while a real reading is still published (positive control)",
              _lr2.get("cpu_overall") == 12.5 and not _lr2.get("error"),
              "the route stopped publishing readings at all: %r" % (_lr2,))
    finally:
        _lrmod.remote_live_metrics = _lr_saved

    # ── backups: the schedule clock, and an audit line that matches what happened ─────────────
    # Three accounting bugs, all the same shape: a backup path that did (or did not do) something
    # and told the rest of the panel otherwise.
    import panel.routes.panel_backup as _bkmod
    import panel.routes._shared as _bksh
    import time
    from panel.core.panel_state import _full_backup_lock as _bk_lock
    from panel.ops import backup as _bkops

    def _bk_clock(sid):
        """This server's schedule last-run, the number game_backup_due measures against."""
        return _bkops.get_game_schedule(sid)["last"]

    def _bk_wait(sid, before, secs=5.0):
        """Wait for the background worker to move the clock (or give up and let the check fail)."""
        _end = time.time() + secs
        while time.time() < _end:
            if _bk_clock(sid) != before:
                return True
            time.sleep(0.05)
        return False

    _bk_saved_pb = _bkmod.run_game_backup
    _bk_saved_sh = _bksh.run_game_backup
    _bk_saved_trig = None
    with app.app_context():
        _bk_gs = db.session.get(GameServer, gs_id)
        _bk_gs.installed = True
        db.session.commit()
    try:
        # A refused full backup must be audited as a REFUSAL. The route hardcoded success=True, so
        # "a full backup is already running" — a request that did nothing — was indistinguishable
        # in /logs from one that ran, and the failures filter (the one an operator reaches for
        # when a backup is missing) hid it. The reboot route already carries this exact fix.
        with app.app_context():
            _AL.query.filter_by(action="panel_full_backup").delete()
            db.session.commit()
        _bk_lock.acquire()          # exactly what a full backup in progress looks like
        try:
            _r = c.post("/api/panel/backup/full", json={"mode": ""})
            _busy = (_r.get_json() or {}).get("running")
        finally:
            _bk_lock.release()
        with app.app_context():
            _al = _AL.query.filter_by(action="panel_full_backup").order_by(_AL.id.desc()).first()
        check("full backup: a request refused because one is already running is audited as a "
              "FAILURE", _al is not None and _al.success is False,
              "audited success=%r — /logs filtered to failures hides this, and the history shows "
              "two full backups where one happened" % (None if _al is None else _al.success,))
        check("full backup: ...and the refusal says so in the entry",
              _al is not None and "refused" in (_al.detail or ""),
              "detail=%r" % (None if _al is None else _al.detail,))
        check("full backup: ...and the caller was told it was busy (positive control)",
              _busy is True,
              "the route did not take the refusal path at all, so the checks above prove nothing")

        # An on-demand "Back up now" must move that server's schedule clock. record_game_backup
        # was called from ONE place (the hourly ticker), so a backup taken by hand left the
        # scheduler believing none had happened and it archived the same server again within the
        # hour — twice the disk, twice the stop/start.
        _bkmod.run_game_backup = lambda *a, **k: (True, "", False)
        _bkops.record_game_backup(gs_id)        # a known starting point, not whatever ran before
        time.sleep(1.05)                        # the clock is whole seconds
        _bk_before = _bk_clock(gs_id)
        _r = c.post("/api/panel/backup/game/%d" % gs_id, json={})
        _moved = _bk_wait(gs_id, _bk_before)
        check("game backup: 'back up now' moves the server's schedule clock",
              _moved,
              "last=%r unchanged (%r) — the hourly ticker still thinks this server is overdue and "
              "will archive it again within the hour" % (_bk_clock(gs_id), _bk_before))

        # ...but only when a backup actually HAPPENED. Skipped = players online, and the ticker
        # deliberately leaves the clock alone there so the server stays due and is retried once it
        # empties. Recording a skip would silently drop that backup for a whole interval.
        _bkmod.run_game_backup = lambda *a, **k: (True, "players online", True)
        _bkops.record_game_backup(gs_id)
        time.sleep(1.05)
        _bk_before = _bk_clock(gs_id)
        c.post("/api/panel/backup/game/%d" % gs_id, json={})
        time.sleep(1.2)
        check("game backup: ...but a SKIPPED one does not (it stays due, and is retried)",
              _bk_clock(gs_id) == _bk_before,
              "a backup that never ran moved the clock, so the server waits a full interval")

        # The 'wait until empty' queue is a third path to the same archive, and it recorded
        # nothing either: a server backed up by THIS sweep still looked overdue to the ticker in
        # the same tick.
        _bksh.run_game_backup = lambda *a, **k: (True, "", False)
        with app.app_context():
            db.session.get(GameServer, gs_id).backup_pending = True
            db.session.commit()
        _bkops.record_game_backup(gs_id)
        time.sleep(1.05)
        _bk_before = _bk_clock(gs_id)
        _bksh._run_pending_backups(app)
        with app.app_context():
            _pend_after = db.session.get(GameServer, gs_id).backup_pending
        check("queued backup: the 'wait until empty' sweep moves the clock too",
              _bk_clock(gs_id) != _bk_before,
              "last=%r unchanged — the ticker backs the same server up again on the next tick"
              % (_bk_clock(gs_id),))
        check("queued backup: ...and the server leaves the queue (positive control)",
              _pend_after is False,
              "the sweep never backed this server up, so the check above proves nothing")

        def _bk_settle():
            """Wait for whatever the checks above started to let go of the backup lock."""
            if _bk_lock.acquire(timeout=8):
                _bk_lock.release()
                return True
            return False

        # ── every backup path hands run_game_backup the server's gamedig override ──────────────
        # Without query_type, player_count has no gamedig type for the games that need an override
        # (Project Zomboid, ARK, Mordhau, Killing Floor), answers None, and run_game_backup reads
        # None as "empty" and runs LinuxGSM `backup`, which STOPS the server with players on it.
        # All four callers left it out. Driven through each real path.
        _qt_seen = []
        with app.app_context():
            _qt_short = db.session.get(GameServer, gs_id).short_name

        def _qt_rgb(*a, **k):
            if a[1] == _qt_short:
                _qt_seen.append(k.get("query_type"))
            return (True, "", False)
        _qt_due_saved = _bkops.game_backup_due
        _qt_prev_sh, _qt_prev_pb = _bksh.run_game_backup, _bkmod.run_game_backup
        try:
            with app.app_context():
                _qt_gs = db.session.get(GameServer, gs_id)
                _qt_gs.query_type = "projectzomboid"
                _qt_gs.backup_pending = True
                db.session.commit()
            _bksh.run_game_backup = _bkmod.run_game_backup = _qt_rgb
            _bkops.game_backup_due = lambda sid: sid == gs_id
            _bkops.record_game_backup(gs_id)
            _bkops.set_game_schedule(gs_id, 1, 2)
            for _qt_label, _qt_run in (
                    ("the 'wait until empty' sweep", lambda: _bksh._run_pending_backups(app)),
                    ("the scheduled ticker", lambda: _bksh._run_due_game_backups(app)),
                    ("'back up now'", lambda: c.post("/api/panel/backup/game/%d" % gs_id, json={})),
                    ("the full backup", lambda: c.post("/api/panel/backup/full", json={"mode": ""}))):
                del _qt_seen[:]
                _bk_settle()
                _qt_run()
                _bk_settle()
                check("backup query_type: %s passes the server's gamedig override" % _qt_label,
                      _qt_seen == ["projectzomboid"],
                      "run_game_backup saw query_type %r ([] = never called for this server) — "
                      "player_count answers None, and None reads as empty" % (_qt_seen,))
        finally:
            _bksh.run_game_backup = _qt_prev_sh
            _bkmod.run_game_backup = _qt_prev_pb
            _bkops.game_backup_due = _qt_due_saved
            _bkops.set_game_schedule(gs_id, None, None)
            with app.app_context():
                _qt_gs = db.session.get(GameServer, gs_id)
                _qt_gs.query_type = None
                _qt_gs.backup_pending = False
                db.session.commit()

        # ── the backup runners say a backup is RUNNING, and stand aside for the Backup button ──
        # Only the manual route set _game_backup_status running, so _run_due_restarts (its own
        # 90 s thread, whose guard reads exactly that flag) could stop or restart a server a
        # scheduled backup had just stopped to archive. And the maintenance menu's Backup button
        # runs outside the backup lock with no flag at all: the hourly ticker took its live
        # backup.lock for an orphan and started a second archive of the same files.
        from panel.core.panel_state import _action_output as _rb_ao, _game_backup_status as _rb_st
        _rb_seen = []
        _rb_prev = _bksh.run_game_backup
        _rb_due_saved = _bkops.game_backup_due
        with app.app_context():
            _rb_short = db.session.get(GameServer, gs_id).short_name

        def _rb_rgb(*a, **k):
            if a[1] == _rb_short:
                _rb_seen.append((_rb_st.get(gs_id) or {}).get("running"))
            return (True, "", False)
        try:
            _bkops.game_backup_due = lambda sid: sid == gs_id
            _bkops.record_game_backup(gs_id)
            _bkops.set_game_schedule(gs_id, 1, 2)
            _bksh.run_game_backup = _rb_rgb
            for _rb_label, _rb_pend, _rb_run in (
                    ("the scheduled ticker", False, lambda: _bksh._run_due_game_backups(app)),
                    ("the 'wait until empty' sweep", True, lambda: _bksh._run_pending_backups(app))):
                del _rb_seen[:]
                _rb_st.pop(gs_id, None)
                with app.app_context():
                    db.session.get(GameServer, gs_id).backup_pending = _rb_pend
                    db.session.commit()
                _bk_settle()
                _rb_run()
                check("backup running flag: %s marks the server running while it backs up" % _rb_label,
                      _rb_seen == [True] and (_rb_st.get(gs_id) or {}).get("running") is False,
                      "running during=%r, after=%r" % (_rb_seen, _rb_st.get(gs_id)))
                # ...and stands aside while the Backup button is archiving the same server.
                del _rb_seen[:]
                with app.app_context():
                    db.session.get(GameServer, gs_id).backup_pending = _rb_pend
                    db.session.commit()
                _rb_ao[gs_id] = {"action": "backup", "path": "/dev/null", "user": _rb_short, "pos": 0}
                try:
                    _bk_settle()
                    _rb_run()
                finally:
                    _rb_ao.pop(gs_id, None)
                check("backup running flag: %s does not start a second archive over a Backup-button run"
                      % _rb_label, _rb_seen == [], "run_game_backup called %d time(s)" % len(_rb_seen))
            # The FULL run (panel_backup, its own reference to run_game_backup) set no flag either,
            # and it too must leave a server alone while the Backup button is archiving it.
            _rb_prev_pb = _bkmod.run_game_backup
            _bkmod.run_game_backup = _rb_rgb
            try:
                del _rb_seen[:]
                _rb_st.pop(gs_id, None)
                _bk_settle()
                c.post("/api/panel/backup/full", json={"mode": ""})
                _bk_settle()
                check("backup running flag: the full backup marks the server running while it backs up",
                      _rb_seen == [True] and (_rb_st.get(gs_id) or {}).get("running") is False,
                      "running during=%r, after=%r" % (_rb_seen, _rb_st.get(gs_id)))
                del _rb_seen[:]
                _rb_ao[gs_id] = {"action": "backup", "path": "/dev/null", "user": _rb_short, "pos": 0}
                try:
                    _bk_settle()
                    c.post("/api/panel/backup/full", json={"mode": ""})
                    _bk_settle()
                    _rb_now = c.post("/api/panel/backup/game/%d" % gs_id, json={})
                    _bk_settle()
                finally:
                    _rb_ao.pop(gs_id, None)
                check("backup running flag: the full backup does not start a second archive over a "
                      "Backup-button run", _rb_seen == [], "run_game_backup called %d time(s)" % len(_rb_seen))
                check("backup running flag: ...nor does 'back up now', and it says why",
                      (_rb_now.get_json() or {}).get("success") is False
                      and "already being backed up" in ((_rb_now.get_json() or {}).get("message") or ""),
                      "answered %r" % (_rb_now.get_json(),))
                # Positive control: the chain is walked, so a backup DISPLACED by a later long action
                # (an update started while it runs) still counts; an ended one does not.
                _rb_ao[gs_id] = {"action": "update", "path": "/dev/null", "user": _rb_short, "pos": 0,
                                 "prev": {"action": "backup", "path": "/dev/null", "user": _rb_short,
                                          "pos": 0}}
                try:
                    _rb_disp = _bksh._button_backup_running(gs_id)
                    _rb_ao[gs_id]["prev"]["ended"] = True
                    _rb_ended = _bksh._button_backup_running(gs_id)
                finally:
                    _rb_ao.pop(gs_id, None)
                check("backup running flag: a Backup-button run displaced by a later action still counts; "
                      "an ended one does not", _rb_disp is True and _rb_ended is False,
                      "displaced=%r ended=%r" % (_rb_disp, _rb_ended))
            finally:
                _bkmod.run_game_backup = _rb_prev_pb
            # A run that RAISES must not leave the flag set, or the restart sweep skips it for ever.

            def _rb_boom(*a, **k):
                raise RuntimeError("ssh fell over")
            _bksh.run_game_backup = _rb_boom
            _rb_st.pop(gs_id, None)
            _bk_settle()
            _bksh._run_due_game_backups(app)
            check("backup running flag: a run that raises clears the flag",
                  (_rb_st.get(gs_id) or {}).get("running") is False, "status %r" % (_rb_st.get(gs_id),))
        finally:
            _bksh.run_game_backup = _rb_prev
            _bkops.game_backup_due = _rb_due_saved
            _bkops.set_game_schedule(gs_id, None, None)
            _rb_st.pop(gs_id, None)
            with app.app_context():
                db.session.get(GameServer, gs_id).backup_pending = False
                db.session.commit()

        # ── an unreadable config.json must not prune a server past its own retention ──────────
        # get_game_schedule answers the DEFAULT keep (2) when config.json cannot be read, and
        # "Back up now" and the full run pruned to it: a server set to keep 10 lost 8 archives.
        # The sweeps skip in that state; these two now prune no lower than the largest retention
        # any setting can hold.
        #
        # The unreadable file is what the BACKUP module reads (its load_config), not the real
        # config.json: with that broken the app redirects every request before a route runs.
        from panel.core.config import UnreadableConfig as _PkUC
        _pk_seen = []
        _pk_prev_pb, _pk_load = _bkmod.run_game_backup, _bkops.load_config
        with app.app_context():
            _pk_short = db.session.get(GameServer, gs_id).short_name
        try:
            _bkops.set_game_schedule(gs_id, 1, 10)
            _bkmod.run_game_backup = lambda *a, **k: (
                _pk_seen.append(a[3]) if a[1] == _pk_short else None, (True, "", False))[1]
            for _pk_label, _pk_run in (
                    ("'back up now'", lambda: c.post("/api/panel/backup/game/%d" % gs_id, json={})),
                    ("the full backup", lambda: c.post("/api/panel/backup/full", json={"mode": ""}))):
                for _pk_bad, _pk_want in ((True, _bkops.MAX_FULL_KEEP), (False, 10)):
                    del _pk_seen[:]
                    _bk_settle()
                    if _pk_bad:
                        _bkops.load_config = lambda: _PkUC(_pk_load())
                    try:
                        _pk_r = _pk_run()
                        _bk_settle()
                    finally:
                        _bkops.load_config = _pk_load
                    check("backup keep: %s with config.json %s prunes to %d"
                          % (_pk_label, "UNREADABLE" if _pk_bad else "readable (control)", _pk_want),
                          _pk_seen == [_pk_want],
                          "run_game_backup got keep %r (status %d)" % (_pk_seen, _pk_r.status_code))
        finally:
            _bkmod.run_game_backup = _pk_prev_pb
            _bkops.load_config = _pk_load
            _bkops.set_game_schedule(gs_id, None, None)

        # ── a scheduled backup that FAILS has to say so somewhere ─────────────────────────────
        # run_game_backup does not raise for a failed backup: it returns (False, reason, False),
        # and a host that is down reaches it as rc=-1/255 from run_command on the tailscale and
        # local transports rather than as an exception. The ticker's only notify() sat in its
        # `except`, so the failure shape that actually happens took no branch at all — and the
        # ticker records the clock for a genuine failure (deliberately, so it does not retry
        # hourly), which makes the silence last a whole interval: no alert, no audit row, no
        # retry. The operator learns of it when they need a restore.
        _bk_notes = []
        _bk_notify_saved = _bksh.notifications.notify
        _bk_due_saved = _bkops.game_backup_due
        try:
            _bksh.notifications.notify = lambda k, t, b="": _bk_notes.append((k, t))
            _bkops.game_backup_due = lambda sid: sid == gs_id    # only OUR server is due
            _bkops.record_game_backup(gs_id)                     # a clock: not "never run before"
            _bkops.set_game_schedule(gs_id, 1, 2)                # ...and the schedule is ON
            with app.app_context():
                _AL.query.filter_by(action="scheduled_backup").delete()
                db.session.commit()
            _bksh.run_game_backup = lambda *a, **k: (False, "Not enough disk space to back up",
                                                     False)
            _bk_free = _bk_settle()
            _bksh._run_due_game_backups(app)
            with app.app_context():
                _bk_row = (_AL.query.filter_by(action="scheduled_backup")
                           .order_by(_AL.id.desc()).first())
            check("scheduled backup: the lock was free, so the ticker actually ran",
                  _bk_free, "a backup from an earlier check still held it — the checks below "
                            "would fail for the wrong reason")
            check("scheduled backup: a failure that RETURNS (rather than raises) is alerted",
                  any(k == "backup_failed" for k, _ in _bk_notes),
                  "notified %s — the alert lives in an except branch a returned failure never "
                  "enters, on exactly the transports the panel steers users towards" % (_bk_notes,))
            check("scheduled backup: ...and audited as a failure, so /logs' failures filter finds it",
                  _bk_row is not None and _bk_row.success is False,
                  "audit row %r — the whole record was an in-memory dict"
                  % (None if _bk_row is None else (_bk_row.action, _bk_row.success),))
            check("scheduled backup: ...with the reason, not just the fact",
                  _bk_row is not None and "disk space" in (_bk_row.detail or ""),
                  "detail=%r" % (None if _bk_row is None else _bk_row.detail,))
            # Positive control: a backup that WORKED is recorded as a success and alerts nobody.
            _bk_notes.clear()
            with app.app_context():
                _AL.query.filter_by(action="scheduled_backup").delete()
                db.session.commit()
            _bksh.run_game_backup = lambda *a, **k: (True, "", False)
            _bk_settle()
            _bksh._run_due_game_backups(app)
            with app.app_context():
                _bk_ok_row = (_AL.query.filter_by(action="scheduled_backup")
                              .order_by(_AL.id.desc()).first())
            check("scheduled backup: one that worked is recorded as a success, and alerts nobody",
                  _bk_ok_row is not None and _bk_ok_row.success is True and not _bk_notes,
                  "row success=%r, notified %s — the checks above would pass just as well with "
                  "every backup reported as a failure"
                  % (None if _bk_ok_row is None else _bk_ok_row.success, _bk_notes))
            # The 'wait until empty' sweep reported nothing at all, on any path.
            _bk_notes.clear()
            with app.app_context():
                _AL.query.filter_by(action="queued_backup").delete()
                db.session.get(GameServer, gs_id).backup_pending = True
                db.session.commit()
            _bksh.run_game_backup = lambda *a, **k: (False, "Not enough disk space to back up",
                                                     False)
            _bk_settle()
            _bksh._run_pending_backups(app)
            with app.app_context():
                _bk_q_row = (_AL.query.filter_by(action="queued_backup")
                             .order_by(_AL.id.desc()).first())
            check("queued backup: a failed one is alerted and audited too",
                  _bk_q_row is not None and _bk_q_row.success is False
                  and any(k == "backup_failed" for k, _ in _bk_notes),
                  "row=%r notified %s — this sweep clears backup_pending either way, so nothing "
                  "picks the server up again until its own schedule comes round"
                  % (None if _bk_q_row is None else (_bk_q_row.action, _bk_q_row.success),
                     _bk_notes))
        finally:
            _bksh.notifications.notify = _bk_notify_saved
            _bkops.game_backup_due = _bk_due_saved
            _bkops.set_game_schedule(gs_id, None, None)

        # ── every clock write goes through the helpers that survive an unreadable config ───────
        # record_game_backup / record_full_backup RAISE ConfigUnreadable while config.json is there
        # but unparseable. The backup paths below were moved onto _record_game_clock; the install
        # route was not, and its call sat one line after committing the new server row — so an
        # install started while the file was bad answered 500 and left a row "installing" with no
        # job behind it. Gate the class: only the two helpers may call the raising writers.
        import ast as _bkc_ast
        _bkc_direct = []
        for _bkc_py in sorted((_lgsm_pathlib.Path(_repo_root) / "panel").rglob("*.py")) + [
                _lgsm_pathlib.Path(_repo_root) / "app.py"]:
            for _bkc_fn in _bkc_ast.walk(_bkc_ast.parse(_bkc_py.read_text(encoding="utf-8"))):
                if not isinstance(_bkc_fn, _bkc_ast.FunctionDef) or _bkc_fn.name in (
                        "_record_game_clock", "_record_full_clock"):
                    continue
                for _bkc_c in _bkc_ast.walk(_bkc_fn):
                    if (isinstance(_bkc_c, _bkc_ast.Call) and isinstance(_bkc_c.func, _bkc_ast.Attribute)
                            and _bkc_c.func.attr in ("record_game_backup", "record_full_backup")):
                        _bkc_direct.append("%s:%d in %s()" % (_bkc_py.name, _bkc_c.lineno, _bkc_fn.name))
        check("backup clock: nothing but the two safe helpers calls the writers that raise on a bad "
              "config.json", not _bkc_direct,
              "direct calls: %s — each one turns a readable-later config into a 500 or a false "
              "failure" % sorted(set(_bkc_direct)))

        # ── config.json going bad under a backup that WORKED ──────────────────────────────────
        # update_config now refuses to write while config.json is there but unparseable (it used
        # to replace it with the defaults). Every backup path writes its clock AFTER the archive,
        # and that refusal reached each path's `except`: a backup that worked was audited and
        # alerted as "backup error (ConfigUnreadable)", a manual one told the user to check the
        # host's disk, and a full run alerted that it "errored before completing". And a sweep
        # that STARTS on an unreadable file works from the defaults — including the `keep` its
        # prune deletes past.
        from panel.core.config import ConfigUnreadable as _BkcCU
        from panel.core.panel_state import _game_backup_status as _bkc_status
        _bkc_good = CONFIG_FILE.read_bytes()
        _bkc_bad = b"{ not valid json"
        _bkc_notes, _bkc_ran, _bkc_refused, _bkc_full_refused, _bkc_spawned = [], [], [], [], []

        def _bkc_break_config(*a, **k):
            """A backup that works — and config.json goes bad while it runs."""
            _bkc_ran.append(1)
            CONFIG_FILE.write_bytes(_bkc_bad)
            return True, "", False

        _bkc_rec_real, _bkc_full_real = _bkops.record_game_backup, _bkops.record_full_backup
        _bkc_sched_real = _bkops.get_game_schedule

        def _bkc_rec(sid):
            try:
                return _bkc_rec_real(sid)
            except _BkcCU:
                _bkc_refused.append(sid)
                raise

        def _bkc_full(summary):
            try:
                return _bkc_full_real(summary)
            except _BkcCU:
                _bkc_full_refused.append(summary)
                raise

        def _bkc_rows(action):
            with app.app_context():
                return [(r.success, r.detail) for r in _AL.query.filter_by(action=action).all()]

        def _bkc_reset(pending=False):
            CONFIG_FILE.write_bytes(_bkc_good)
            for _l in (_bkc_notes, _bkc_ran, _bkc_refused, _bkc_full_refused):
                del _l[:]
            _bkc_status.pop(gs_id, None)
            with app.app_context():
                _AL.query.filter(_AL.action.in_(("queued_backup", "scheduled_backup"))).delete(
                    synchronize_session=False)
                db.session.get(GameServer, gs_id).backup_pending = pending
                db.session.commit()
            _bk_settle()

        class _BkcNoThread:
            class Thread:
                def __init__(self, target=None, daemon=None, **kw):
                    self.target = target

                def start(self):
                    _bkc_spawned.append(self.target)

        _bkc_saved = (_bksh.notifications.notify, _bkops.game_backup_due, _bksh.run_game_backup,
                      _bkmod.run_game_backup, _bkmod.threading)
        try:
            _bksh.notifications.notify = lambda k, t, b="": _bkc_notes.append((k, t))
            _bkops.game_backup_due = lambda sid: sid == gs_id    # only OUR server is due
            _bkops.record_game_backup, _bkops.record_full_backup = _bkc_rec, _bkc_full
            _bkc_rec_real(gs_id)                                 # a clock: not "never run before"
            _bkops.set_game_schedule(gs_id, 1, 2)                # ...and the schedule is ON
            _bksh.run_game_backup = _bkmod.run_game_backup = _bkc_break_config
            _bkc_good = CONFIG_FILE.read_bytes()                 # what each case starts from

            # The 'wait until empty' sweep.
            _bkc_reset(pending=True)
            _bksh._run_pending_backups(app)
            _bkc_left = CONFIG_FILE.read_bytes()
            _bkc_rs = _bkc_rows("queued_backup")
            check("backup + bad config: a QUEUED backup that worked is not reported as failed",
                  _bkc_rs and all(_s is True for _s, _ in _bkc_rs) and not _bkc_notes
                  and (_bkc_status.get(gs_id) or {}).get("ok") is True,
                  "audit %r, notified %s, status %r — the refused clock write reached the sweep's "
                  "except" % (_bkc_rs, _bkc_notes, _bkc_status.get(gs_id)))
            check("backup + bad config: ...it did back up, and its clock write WAS refused, "
                  "leaving the file alone (positive control)",
                  _bkc_ran and gs_id in _bkc_refused and _bkc_left == _bkc_bad,
                  "ran=%r refused=%r file=%r" % (_bkc_ran, _bkc_refused, _bkc_left[:20]))

            # The scheduled ticker, after an archive...
            _bkc_reset()
            _bksh._run_due_game_backups(app)
            _bkc_rs = _bkc_rows("scheduled_backup")
            check("backup + bad config: a SCHEDULED backup that worked is not reported as failed",
                  _bkc_rs and all(_s is True for _s, _ in _bkc_rs) and not _bkc_notes
                  and (_bkc_status.get(gs_id) or {}).get("ok") is True,
                  "audit %r, notified %s, status %r" % (_bkc_rs, _bkc_notes, _bkc_status.get(gs_id)))
            check("backup + bad config: ...it did back up, and its clock write WAS refused "
                  "(positive control)", _bkc_ran and gs_id in _bkc_refused,
                  "ran=%r refused=%r" % (_bkc_ran, _bkc_refused))

            # ...and where it only STARTS a never-run server's clock, which archives nothing.
            def _bkc_fresh(sid):
                if sid != gs_id:
                    return _bkc_sched_real(sid)
                CONFIG_FILE.write_bytes(_bkc_bad)
                return {"interval_days": 1, "keep": 2, "last": 0}
            _bkc_reset()
            _bkops.get_game_schedule = _bkc_fresh
            try:
                _bksh._run_due_game_backups(app)
            finally:
                _bkops.get_game_schedule = _bkc_sched_real
            _bkc_rs = _bkc_rows("scheduled_backup")
            check("backup + bad config: starting a new server's clock is not a failed backup",
                  not any(_s is False for _s, _ in _bkc_rs) and not _bkc_notes,
                  "audit %r, notified %s — no backup was even attempted" % (_bkc_rs, _bkc_notes))
            check("backup + bad config: ...that clock write WAS refused (positive control)",
                  gs_id in _bkc_refused and not _bkc_ran,
                  "refused=%r ran=%r" % (_bkc_refused, _bkc_ran))

            # "Back up now": the worker's own status is what the page shows.
            _bkc_reset()
            c.post("/api/panel/backup/game/%d" % gs_id, json={})
            _bk_settle()
            _bkc_st = _bkc_status.get(gs_id) or {}
            check("backup + bad config: a MANUAL backup that worked says so, not 'check the host "
                  "is reachable and has free disk space'",
                  _bkc_st.get("ok") is True and "error" not in (_bkc_st.get("msg") or ""),
                  "status %r" % (_bkc_st,))
            check("backup + bad config: ...it did back up, and its clock write WAS refused "
                  "(positive control)", _bkc_ran and gs_id in _bkc_refused,
                  "ran=%r refused=%r" % (_bkc_ran, _bkc_refused))

            # A full run: its one clock write comes after every server is archived.
            _bkc_reset()
            _bkmod.threading = _BkcNoThread
            c.post("/api/panel/backup/full", json={"mode": ""})
            _bkmod.threading = _bkc_saved[4]
            for _t in _bkc_spawned:
                _t()                                             # the worker, here, to the end
            check("backup + bad config: a FULL run that completed is not alerted as one that "
                  "'errored before completing'",
                  _bkc_spawned and not any(k == "backup_failed" for k, _ in _bkc_notes),
                  "spawned %d, notified %s" % (len(_bkc_spawned), _bkc_notes))
            check("backup + bad config: ...it did back up, and its clock write WAS refused "
                  "(positive control)", _bkc_ran and _bkc_full_refused and not _bk_lock.locked(),
                  "ran=%r refused=%r lock held=%r" % (_bkc_ran, _bkc_full_refused, _bk_lock.locked()))

            # A sweep that STARTS on an unreadable file does nothing: its schedules and its prune's
            # `keep` would all be the defaults, and nothing it did could be recorded.
            _bkc_reset(pending=True)
            _bksh.run_game_backup = lambda *a, **k: (_bkc_ran.append(a), (True, "", False))[1]
            CONFIG_FILE.write_bytes(_bkc_bad)
            _bksh._run_pending_backups(app)
            _bksh._run_due_game_backups(app)
            CONFIG_FILE.write_bytes(_bkc_good)
            with app.app_context():
                _bkc_still = db.session.get(GameServer, gs_id).backup_pending
            check("backup + bad config: a sweep that starts on an unreadable config.json backs "
                  "nothing up and writes nothing",
                  not _bkc_ran and not _bkc_refused and _bkc_still is True
                  and _bkc_rows("queued_backup") == [] and _bkc_rows("scheduled_backup") == [],
                  "ran=%r refused=%r still queued=%r — a prune to the DEFAULT keep deletes "
                  "archives a server's own retention kept" % (_bkc_ran, _bkc_refused, _bkc_still))
            _bksh._run_pending_backups(app)
            _bksh._run_due_game_backups(app)
            check("backup + bad config: ...and both sweeps run once it reads (positive control)",
                  len(_bkc_ran) >= 2, "ran %d time(s)" % len(_bkc_ran))
        finally:
            CONFIG_FILE.write_bytes(_bkc_good)
            (_bksh.notifications.notify, _bkops.game_backup_due, _bksh.run_game_backup,
             _bkmod.run_game_backup, _bkmod.threading) = _bkc_saved
            _bkops.record_game_backup, _bkops.record_full_backup = _bkc_rec_real, _bkc_full_real
            _bkops.get_game_schedule = _bkc_sched_real
            _bkops.set_game_schedule(gs_id, None, None)
            with app.app_context():
                db.session.get(GameServer, gs_id).backup_pending = False
                db.session.commit()

        # ── "Full backup started" must not be decided by a test the lock can lose ─────────────
        # _trigger_full_backup checked `_full_backup_lock.locked()` and the worker acquired it
        # later — two steps, with three other holders (the per-server backup, the hourly ticker,
        # the 'wait until empty' sweep) able to take it in between. The worker's own acquire then
        # lost and returned in total silence, while the route had already answered "Full backup
        # started" and written the audit row whose success flag exists precisely so /logs cannot
        # hide a refusal. Driven by never letting the worker run: after a started=True answer the
        # lock must ALREADY be held by the request that answered.
        class _BkNoThread:
            class Thread:
                def __init__(self, target=None, daemon=None, **kw):
                    self.target = target

                def start(self):
                    _bk_spawned.append(self.target)   # ...and never run it

        _bk_spawned = []
        _bk_thr_saved = _bkmod.threading
        _bk_held = False
        try:
            _bk_settle()
            _bkmod.threading = _BkNoThread
            _bk_full = c.post("/api/panel/backup/full", json={"mode": ""})
            _bk_full_running = (_bk_full.get_json() or {}).get("running")
            _bk_held = _bk_lock.locked()
        finally:
            _bkmod.threading = _bk_thr_saved
            if _bk_held:
                _bk_lock.release()
        check("full backup: the REQUEST takes the lock, rather than leaving it to the thread it "
              "spawns", _bk_held,
              "the lock was free after a 'started' answer — anything that takes it before the "
              "worker does makes that answer, and its success=True audit row, a record of a "
              "backup that never ran")
        check("full backup: ...and the request still reports it started (positive control)",
              _bk_full_running is True and len(_bk_spawned) == 1,
              "answered running=%r, spawned %d worker(s)" % (_bk_full_running, len(_bk_spawned)))

        # ── the two buttons on a backup ROW, against a host that did not answer ───────────────
        # list_game_backups returns None for "could not read" (#330) and _find_game_backup
        # iterated it, so both raised TypeError: the browser got a 500 whose body says the panel
        # is broken, a traceback went to the panel log, and the real cause — the host did not
        # answer — was never stated. Before #330 they answered a calm, wrong "Backup not found."
        _bk_lgb_saved = _bkmod.list_game_backups
        try:
            _bkmod.list_game_backups = lambda *a, **k: None       # the host did not answer
            _bk_delr = c.post("/api/panel/backup/game/%d/delete" % gs_id,
                              json={"name": "an-archive.tar.gz"})
            _bk_delj = _bk_delr.get_json() or {}
            _bk_dlr = c.get("/backup/game/%d/download?name=an-archive.tar.gz" % gs_id)
            check("backup row: deleting one when the listing can't be read is not a 500",
                  _bk_delr.status_code < 500 and _bk_delj.get("success") is False,
                  "status %d, body %r" % (_bk_delr.status_code, _bk_delj))
            check("backup row: ...and it says the host didn't answer, not 'Backup not found.'",
                  "didn't answer" in (_bk_delj.get("message") or ""),
                  "message %r — 'not found' is a claim about a directory nobody reached"
                  % (_bk_delj.get("message"),))
            check("backup row: downloading one is not a 500 either",
                  _bk_dlr.status_code == 502,
                  "status %d — a Werkzeug HTML error page where a file should be"
                  % _bk_dlr.status_code)
            # Positive control: a listing that WAS read still answers 404 for a name not in it.
            _bkmod.list_game_backups = lambda *a, **k: []
            _bk_delr2 = c.post("/api/panel/backup/game/%d/delete" % gs_id,
                               json={"name": "an-archive.tar.gz"})
            check("backup row: a listing that was READ still answers 'Backup not found.'",
                  _bk_delr2.status_code == 404
                  and "not found" in ((_bk_delr2.get_json() or {}).get("message") or "").lower(),
                  "status %d, body %r — the route now refuses everything, so the checks above "
                  "prove nothing" % (_bk_delr2.status_code, _bk_delr2.get_json()))
        finally:
            _bkmod.list_game_backups = _bk_lgb_saved
    finally:
        _bkmod.run_game_backup = _bk_saved_pb
        _bksh.run_game_backup = _bk_saved_sh
        with app.app_context():
            _bk_gs = db.session.get(GameServer, gs_id)
            _bk_gs.backup_pending = False
            db.session.commit()

    # ── a host reboot must not report a server it could not read as an empty one ───────────────
    # player_count returns None for BOTH "the query failed" and "this game is not queryable", and
    # the reboot check folded that into its `pc > 0` test — so an online server the panel could
    # not read was simply absent from the answer, the confirm dialog said nothing, and the reboot
    # disconnected whoever was on it. Verified on the test box before the fix: an online server
    # with a query_type override answered {"busy":[],"total":0}.
    import panel.routes.remote_vps as _rpmod

    _rp_saved = _rpmod.sm_player_count
    _rp_args = []

    def _rp_get():
        return (c.get("/api/remote/%d/players" % remote_id).get_json() or {})

    def _rp_unknown(d):
        return [u["name"] for u in (d.get("unknown") or [])]

    def _rp_busy(d):
        return [b["name"] for b in (d.get("busy") or [])]

    try:
        # Named, not counted: other checks leave their own servers on this host, so "the answer
        # has one entry" is not a fact about the server under test. The first version of these
        # checks asserted totals and failed on somebody else's rows.
        with app.app_context():
            _rp_gs = db.session.get(GameServer, gs_id)
            _rp_status_before, _rp_qt_before = _rp_gs.status, _rp_gs.query_type
            _rp_gs.status, _rp_gs.query_type = "online", "unreal3"
            db.session.commit()
            _rp_name, _rp_short = _rp_gs.name, _rp_gs.short_name

        def _rp_stub(server, short, game_type=None, port=None, query_type=None):
            _rp_args.append({"short": short, "query_type": query_type})
            return None                      # the read failed / the game cannot be queried
        _rpmod.sm_player_count = _rp_stub

        _rp = _rp_get()
        check("host reboot: a running server whose player count could not be read is reported",
              _rp_name in _rp_unknown(_rp) and _rp_name not in _rp_busy(_rp),
              "unknown=%r busy=%r — the confirm says nothing about it, and the reboot disconnects "
              "whoever was on it" % (_rp_unknown(_rp), _rp_busy(_rp)))
        _rp_mine = [a for a in _rp_args if a["short"] == _rp_short]
        check("host reboot: ...and the per-server query type override reaches the query",
              _rp_mine and _rp_mine[-1]["query_type"] == "unreal3",
              "called with %r — a game with no built-in gamedig type is queryable ONLY through "
              "the override, so dropping it makes every one of them unreadable here while the "
              "Players panel reads them fine" % (_rp_mine[-1:] or None,))

        # A STOPPED server is unreadable because nothing is running. Listing it would put a
        # warning on every reboot of a host with an idle server on it, which is how a real warning
        # gets ignored.
        with app.app_context():
            db.session.get(GameServer, gs_id).status = "offline"
            db.session.commit()
        check("host reboot: ...but a stopped server is not reported as unreadable",
              _rp_name not in _rp_unknown(_rp_get()),
              "every idle server raises a warning, so the real one stops being read")

        # ...and a server that DOES answer still counts, both ways round.
        with app.app_context():
            db.session.get(GameServer, gs_id).status = "online"
            db.session.commit()
        _rpmod.sm_player_count = lambda *a, **k: 3
        _rp = _rp_get()
        check("host reboot: a server with players is still reported as busy (positive control)",
              _rp_name in _rp_busy(_rp) and _rp_name not in _rp_unknown(_rp)
              and _rp.get("total", 0) >= 3,
              "busy=%r unknown=%r total=%r" % (_rp_busy(_rp), _rp_unknown(_rp), _rp.get("total")))
        _rpmod.sm_player_count = lambda *a, **k: 0
        check("host reboot: ...and a server that answers ZERO is empty, not unknown",
              _rp_name not in _rp_unknown(_rp_get()),
              "a confirmed-empty server is being reported as unreadable")
    finally:
        _rpmod.sm_player_count = _rp_saved
        with app.app_context():
            _rp_gs = db.session.get(GameServer, gs_id)
            _rp_gs.status, _rp_gs.query_type = _rp_status_before, _rp_qt_before
            db.session.commit()

    # ── the default group cannot be deleted by a direct POST ──────────────────────────────────
    # manage_groups.html hides the delete button behind `{% if not group.is_default %}`, and that
    # was the ONLY thing stopping it: the route never looked at the flag. The default group is
    # what every new account and every invite starts pre-ticked with, so deleting it leaves the
    # install with no default for anyone created afterwards. A guard that lives in the markup is
    # not a guard — anything that can POST bypasses it.
    # A FRESH login. s1 is long dead by this point in the suite and an unauthenticated POST
    # answers success=False all on its own — which is exactly what several of these checks are
    # looking for, so they passed against a session that had expired. Prove the client is logged
    # in before trusting anything it says.
    _lc, _lr = _real_login()
    check("late-suite client: the fresh login actually authenticated (the checks below need it)",
          _lc.get("/groups").status_code == 200,
          "GET /groups answered %s — every check below would pass for the wrong reason"
          % (_lc.get("/groups").status_code,))
    with app.app_context():
        _dflt = Group.query.filter_by(is_default=True).first()
        if _dflt is None:
            _dflt = Group(name="smoke-default-grp", description="", is_default=True)
            db.session.add(_dflt)
            db.session.commit()
        _dflt_id = _dflt.id
    _dg = _lc.post("/groups/%d/delete" % _dflt_id, follow_redirects=False)
    with app.app_context():
        _dflt_after = db.session.get(Group, _dflt_id)
    check("groups: a direct POST cannot delete the default group", _dflt_after is not None,
          "the default group was deleted by POST /groups/%d/delete (status %s)"
          % (_dflt_id, _dg.status_code))
    check("groups: ...and it is still marked default",
          _dflt_after is not None and bool(_dflt_after.is_default),
          "the flag was cleared instead")
    # Positive control: a NON-default group still deletes, so the guard above is not just a
    # broken route.
    with app.app_context():
        _ndg = Group(name="smoke-deletable-grp", description="", is_default=False)
        db.session.add(_ndg)
        db.session.commit()
        _ndg_id = _ndg.id
    _lc.post("/groups/%d/delete" % _ndg_id, follow_redirects=False)
    with app.app_context():
        check("groups: ...while an ordinary group still deletes (positive control)",
              db.session.get(Group, _ndg_id) is None,
              "the guard is refusing every delete, not just the default one")

    # ── sync-ports reports what the firewall TOOK, not what was asked for ─────────────────────
    # It discarded remote_ufw_allow_game_ports' return value and answered
    # "Ports 27015, 27016 opened." with an audit row saying success=True, whether or not a single
    # rule landed. An audit row recording an action that did not happen is worse than no row.
    import panel.routes.remote_vps as _rv_mod
    from panel.db.models import AuditLog as _SPAudit
    _rv_detect = _rv_mod.detect_game_ports
    _rv_allow = _rv_mod.remote_ufw_allow_game_ports
    try:
        _rv_mod.detect_game_ports = lambda *a, **k: {"game_port": 27015,
                                                     "open_ports": [27015, 27016],
                                                     "ports": [27015, 27016]}
        _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([], "opened 0 port(s): none")
        _sp = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
        _spj = _sp.get_json() or {}
        check("sync-ports: a firewall that opened nothing is not reported as success",
              _spj.get("success") is False,
              "answered success=%r message=%r" % (_spj.get("success"), _spj.get("message")))
        check("sync-ports: ...and the message names the ports that failed",
              "27015" in (_spj.get("message") or "") and "27016" in (_spj.get("message") or ""),
              "message=%r" % (_spj.get("message"),))
        with app.app_context():
            _spa = (_SPAudit.query.filter_by(action="sync_ports")
                    .order_by(_SPAudit.id.desc()).first())
        check("sync-ports: ...and the audit row does not claim it succeeded",
              _spa is not None and not _spa.success,
              "audit row: %r" % (getattr(_spa, "success", "no row"),))
        # Positive control: when the firewall takes them, it says so and audits success.
        _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([27015, 27016], "opened 2")
        _sp2 = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
        _spj2 = _sp2.get_json() or {}
        check("sync-ports: ...while ports that really opened are reported as success",
              _spj2.get("success") is True and _spj2.get("open_ports") == [27015, 27016],
              "answered %r" % (_spj2,))
        # A PARTIAL result is the case the old code hid completely.
        _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([27015], "opened 1")
        _sp3 = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
        _spj3 = _sp3.get_json() or {}
        check("sync-ports: ...and a PARTIAL open is reported as a failure naming the missing port",
              _spj3.get("success") is False and _spj3.get("failed_ports") == [27016]
              and "27016" in (_spj3.get("message") or ""),
              "answered %r" % (_spj3,))
    finally:
        _rv_mod.detect_game_ports = _rv_detect
        _rv_mod.remote_ufw_allow_game_ports = _rv_allow

    # ── a validation regex is not silently truncated into a DIFFERENT one ─────────────────────
    # The pattern was compiled in full and then stored as arg_pattern[:200]. A cut does not always
    # break a regex: an alternation sliced just after a `|` leaves a trailing empty branch, and an
    # empty branch matches everything — so a superadmin's whitelist became "accept anything" for
    # everyone allowed to run the command. The pattern below is built so that its first 200
    # characters are exactly that: still valid, and wide open.
    # Built by arithmetic, not by searching for a cut point: each branch below is exactly 8
    # characters, so 25 of them are exactly 200 and the 200-character prefix ends on the `|`.
    # (A search loop here spun forever — the separator never lands on index 199 for a branch
    # length that does not divide into it.)
    _branch = "^(?:x)$|"                      # 8 chars
    _wide = _branch * 25 + "^(?:y)$"          # [:200] is exactly 25 branches, ending in `|`
    import re as _spre
    _cut = _wide[:200]
    check("commands: the test's own pattern really does widen when cut (not a vacuous check)",
          len(_wide) > 200 and _cut.endswith("|")
          and _spre.match(_wide, "anything-at-all; rm -rf /") is None
          and _spre.match(_cut, "anything-at-all; rm -rf /") is not None,
          "the constructed pattern does not demonstrate the widening: full=%r cut=%r"
          % (_wide[-20:], _cut[-20:]))
    _cf = {"name": "smoke-trunc-cmd", "command_template": "say {}", "argument_label": "Map",
           "scope": "all|", "enabled": "on", "argument_pattern": _wide}
    _cr = _lc.post("/commands/add", data=_cf, follow_redirects=False)
    with app.app_context():
        _stored = CustomCommand.query.filter_by(name="smoke-trunc-cmd").first()
        _stored_pat = _stored.argument_pattern if _stored else None
    check("commands: an over-long validation pattern is refused, not truncated",
          _stored is None or _stored_pat == _wide,
          "stored a %d-char pattern from a %d-char one — %r"
          % (len(_stored_pat or ""), len(_wide), (_stored_pat or "")[-30:]))
    # Positive control: a pattern that FITS is still accepted, in full.
    _ok_pat = "^(?:de_dust2|de_inferno|de_nuke)$"
    _lc.post("/commands/add", data=dict(_cf, name="smoke-ok-cmd", argument_pattern=_ok_pat),
             follow_redirects=False)
    with app.app_context():
        _ok_cmd = CustomCommand.query.filter_by(name="smoke-ok-cmd").first()
        check("commands: ...while a pattern that fits is stored exactly as written",
              _ok_cmd is not None and _ok_cmd.argument_pattern == _ok_pat,
              "stored %r" % (getattr(_ok_cmd, "argument_pattern", None),))
        for _c in (CustomCommand.query.filter_by(name="smoke-trunc-cmd").first(),
                   CustomCommand.query.filter_by(name="smoke-ok-cmd").first()):
            if _c is not None:
                _c.groups = []
                db.session.delete(_c)
        db.session.commit()

    # ── the terminal page must name the account it is ACTUALLY running as ────────────────────
    # It carried one fixed sentence for every host — "running as the panel's own account — not as
    # root" — which was written for the panel host and printed on remotes too. On a remote the
    # session runs as whatever account that host is configured with, and for most installs that is
    # root: `whoami` in a terminal on the test VPS answers root, under a line promising it was not.
    #
    # This creates BOTH hosts itself. Two earlier versions asked about rows seeded 6000 lines up:
    # the first used an id captured back then and compared the wrong page, and the second queried
    # for is_local=True and found None — by this point in the suite no local host survives — then
    # crashed the whole run formatting that None into a URL. A test that depends on another test's
    # leftovers is testing the leftovers.
    _tp_user = "deployacct"          # distinctive, so "it names the account" cannot match by luck
    with app.app_context():
        _tp_loc = RemoteServer(name="smoke-term-local", host="127.0.0.1", port=22,
                               username="root", auth_method="key", auth_credential="",
                               is_local=True)
        _tp_rem = RemoteServer(name="smoke-term-remote", host="198.51.100.7", port=22,
                               username=_tp_user, auth_method="key", auth_credential="",
                               is_local=False)
        db.session.add_all([_tp_loc, _tp_rem])
        db.session.commit()
        _tp_loc_id, _tp_rem_id = _tp_loc.id, _tp_rem.id
    try:
        _t_local = _lc.get("/terminal/%d" % _tp_loc_id)
        _t_remote = _lc.get("/terminal/%d" % _tp_rem_id)
        check("terminal page: both hosts render (the copy checks below need them)",
              _t_local.status_code == 200 and _t_remote.status_code == 200,
              "local=%d remote=%d" % (_t_local.status_code, _t_remote.status_code))
        _tl = _t_local.get_data(as_text=True)
        _tr = _t_remote.get_data(as_text=True)
        # The local page NAMES the account now rather than promising what it is not: "running as
        # the panel's own account — not as root" is true of a root install's service account and
        # misleading on a per-user one, where that account is usually able to become root without
        # a password. Asserting the real OS account name also catches the Jinja trap — a forgotten
        # `local_user=` kwarg is silently Undefined and falsy, so the fallback would render and
        # this would look fine.
        import panel.ops.terminal_session as _tp_ts
        _tp_acct = _tp_ts.panel_account()
        # The FALLBACK phrase is the discriminator, not the account name: the name also appears in
        # the sudo hint higher up the page, so `acct in html` is satisfied whether or not the
        # footer rendered it. Checked by removing the kwarg and watching the first version of this
        # pass 977/977 — the exact Jinja trap this change could have walked into.
        check("terminal page: the local host names the account the shell runs as",
              bool(_tp_acct) and ("<code>%s</code>" % _tp_acct) in _tl
              and "the account the panel runs under" not in _tl   # the local_user-missing branch
              and "not as root" not in _tl,
              "expected the footer to name %r inside <code>; fallback-branch present=%r means the "
              "route did not pass local_user"
              % (_tp_acct, "the account the panel runs under" in _tl))
        check("terminal page: a REMOTE does not claim to be 'not as root'",
              "not as root" not in _tr,
              "a remote whose configured account is root renders a promise that it is not root")
        check("terminal page: ...it names the account the panel connects with",
              _tp_user in _tr and "the account the panel connects with" in _tr,
              "the remote's copy does not name %r as the account the session runs as" % (_tp_user,))

        # ── ...and its way back must be a page that has actually read this host ──────────────
        # "Back to host" pointed EVERY host at remote_manage, which renders remote_manage.html
        # with no `status` — and status is what the Connection & SSH card reads. Jinja's Undefined
        # is silently falsy, so on the PANEL host that page states Tailscale SSH is Disabled,
        # tailscale0 is Not allowed in UFW and that disabling public SSH would lock you out,
        # having probed nothing, with both firewall buttons disabled. server_management is the
        # only route that calls get_server_status(), and the two checks below it pin exactly that
        # gap. Read off the ANCHOR, not the page: base.html's nav links /server-management on
        # every page for a superadmin, so `in html` would be true either way.
        def _back_href(_html):
            # The rendered SPAN, not the bare words: base.html embeds window.I18N inline, and in a
            # non-English session that catalog carries "Back to host" as a key further up the page.
            _i = _html.find("<span>Back to host</span>")
            if _i < 0:
                return ""
            _a = _html.rfind('<a href="', 0, _i)
            if _a < 0:
                return ""
            _s = _a + len('<a href="')
            return _html[_s:_html.find('"', _s)]

        check("terminal page: the panel host's way back is the route that owns its card",
              _back_href(_tl).endswith("/server-management"),
              "the local terminal's back link is %r — a page rendered without status"
              % (_back_href(_tl),))
        # POSITIVE CONTROL: a real remote still goes back to its own manage page, which IS the
        # page that owns it — this must not have become "everything goes to /server-management".
        check("terminal page: ...and a remote still goes back to its own manage page",
              _back_href(_tr).endswith("/remote/%d/manage" % _tp_rem_id),
              "the remote's back link is %r" % (_back_href(_tr),))
        # The card that links here carried the same sentence, so check it the same way.
        _c_local = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
        _c_remote = _lc.get("/remote/%d/manage" % _tp_rem_id).get_data(as_text=True)
        check("host page: the Terminal card names the account on a remote",
              "as the panel's own account" in _c_local
              and "as the panel's own account" not in _c_remote
              and _tp_user in _c_remote,
              "the card says 'the panel's own account' on a host where the account is %r"
              % (_tp_user,))
        # ── ...and its Connection & SSH card must read the host, not an Undefined ────────────
        # remote_manage() rendered this template without `status`. Jinja's Undefined is silently
        # falsy, so `ts_up` and `ssh_lockdown_safe` were false on a panel host with Tailscale SSH
        # running: "Tailscale SSH: Disabled", "Not allowed", both setup buttons greyed with "Set
        # up Tailscale first", and "Disable (tailnet-only)" given data-lockdown="1" — which
        # remote_manage_host.js deliberately never re-enables, so that control could not be
        # reached on this page at all. /server-management renders the same card correctly, which
        # is what made it look like a working gate.
        import panel.ops.system_ops as _sso
        _o_gss = _sso.get_server_status
        try:
            _sso.get_server_status = lambda force=False: {
                "has_sudo": True, "ufw": {"enabled": True, "installed": True},
                "tailscale_ssh": {"running": True, "enabled": True},
                "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": True,
                "updates": {}, "uptime": "1 day"}
            _ms_up = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
            check("host page: a panel host WITH Tailscale SSH is not told to set Tailscale up",
                  "Set up Tailscale first" not in _ms_up and 'data-lockdown="1"' not in _ms_up
                  and "Disable Tailscale SSH" in _ms_up,
                  "the card still reads as if Tailscale were absent — status was not passed")
            # POSITIVE CONTROL: a host that really has no Tailscale must still be guarded, or the
            # check above would pass by the card simply never locking anything down.
            _sso.get_server_status = lambda force=False: {
                "has_sudo": True, "ufw": {"enabled": True, "installed": True},
                "tailscale_ssh": {"running": False, "enabled": False},
                "tailscale_interface": "", "tailscale_ufw_allowed": False,
                "updates": {}, "uptime": "1 day"}
            _ms_down = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
            check("host page: ...and a host without it still gets the lock-out guard",
                  "Set up Tailscale first" in _ms_down and 'data-lockdown="1"' in _ms_down,
                  "the guard no longer fires for a host with no way back in")
        finally:
            _sso.get_server_status = _o_gss
    finally:
        with app.app_context():
            for _tid in (_tp_loc_id, _tp_rem_id):
                _row = db.session.get(RemoteServer, _tid)
                if _row is not None:
                    db.session.delete(_row)
            db.session.commit()

    # ── a custom command's argument guard, driven through the real route ─────────────────────
    # The route COMPILES the stored pattern and MATCHES the value in two separate try blocks, and
    # the comment there records why: they used to be one, so `raise ValueError` for a value that
    # did not match was caught by the same `except (re.error, ValueError)` as a broken stored
    # pattern and fell through to the lenient default. A command restricted to
    # ^(easy|normal|hard)$ accepted 9999. The shell-injection half still held — the default
    # charset has no metacharacters — but the AUTHORIZATION half did nothing at all.
    #
    # That was found and fixed by hand. No suite enters this route, so nothing would catch it
    # coming back. The helpers are covered in unit; this is the CALLER.
    import panel.routes.server_detail as _cc_mod
    _cc_sent = []

    def _fake_send(remote, short, cmd, timeout=10, selfname=None):
        _cc_sent.append(cmd)
        return ("", "", 0)

    _cc_saved = _cc_mod.send_console_command
    _cc_mod.send_console_command = _fake_send
    with app.app_context():
        _cc = CustomCommand(name="smoke-difficulty", command_template="difficulty {}",
                            argument_label="Difficulty",
                            argument_pattern="^(easy|normal|hard)$",
                            scope_type="all", scope_value="", enabled=True,
                            created_by="smoke_admin")
        db.session.add(_cc)
        db.session.commit()
        _cc_id = _cc.id
    try:
        _u = "/api/server/%d/custom-command/%d" % (gs_id, _cc_id)
        _cc_sent[:] = []
        _r_ok = _lc.post(_u, json={"value": "hard"})
        check("custom command: a value the pattern allows runs, substituted into the template",
              _r_ok.status_code == 200 and _cc_sent == ["difficulty hard"],
              "status=%d sent=%r" % (_r_ok.status_code, _cc_sent))
        _cc_sent[:] = []
        _r_no = _lc.post(_u, json={"value": "9999"})
        check("custom command: a value the pattern REFUSES is rejected, not run",
              _r_no.status_code == 400 and _cc_sent == [],
              "status=%d sent=%r — the authorization half of the guard is back to doing nothing"
              % (_r_no.status_code, _cc_sent))
        # A BROKEN stored pattern must fall back to the safe default, not become a bypass.
        with app.app_context():
            db.session.get(CustomCommand, _cc_id).argument_pattern = "^(unclosed"
            db.session.commit()
        _cc_sent[:] = []
        _r_meta = _lc.post(_u, json={"value": "a;rm -rf /"})
        check("custom command: a broken stored pattern still refuses a value the default refuses",
              _r_meta.status_code == 400 and _cc_sent == [],
              "status=%d sent=%r — an uncompilable pattern became an ALLOW-ALL"
              % (_r_meta.status_code, _cc_sent))
        _cc_sent[:] = []
        _r_plain = _lc.post(_u, json={"value": "9999"})
        check("custom command: ...and it falls back to the DEFAULT, not to refusing everything",
              _r_plain.status_code == 200 and _cc_sent == ["difficulty 9999"],
              "status=%d sent=%r — 9999 matches the default charset, so this should run; "
              "refusing it would mean the fallback is 'deny all' rather than the documented default"
              % (_r_plain.status_code, _cc_sent))
    finally:
        _cc_mod.send_console_command = _cc_saved
        with app.app_context():
            _row = db.session.get(CustomCommand, _cc_id)
            if _row is not None:
                _row.groups = []
                db.session.delete(_row)
                db.session.commit()

    # ── "Is the server running?" must not be the panel's answer to every failure ──────────────
    # send_console_command documents exactly ONE failure code: rc 3 with NO_SESSION, meaning there
    # is no tmux session to send to. Both console routes branched on `rc != 0` alone and printed
    # that one sentence for all of them — including rc 255 from `ssh: connect to host … No route to
    # host`, which a Tailscale/local transport RETURNS rather than raising, so the except never
    # fired. The operator was sent to look at their game server while the panel could not reach the
    # machine, on a page still showing that server's cached status. And the form route logged only
    # on success, so the failed attempt left no audit row at all — the JSON sibling in
    # server_files.py has always logged unconditionally with success=(rc == 0).
    from panel.db.models import AuditLog as _sc_AL
    _sc_rc = {"v": ("", "", 0)}
    _sc_saved = _cc_mod.send_console_command
    try:
        _cc_mod.send_console_command = (lambda remote, short, cmd, timeout=10, selfname=None:
                                        _sc_rc["v"])

        def _sc_post(rc, err):
            """POST the detail page's command box and hand back (page html, new audit rows)."""
            _sc_rc["v"] = ("", err, rc)
            with app.app_context():
                _before = _sc_AL.query.filter_by(action="send_command").count()
            _h = _lc.post("/server/%d/command" % gs_id, data={"command": "changelevel de_dust2"},
                          follow_redirects=True).get_data(as_text=True)
            with app.app_context():
                _rows = _sc_AL.query.filter_by(action="send_command").order_by(
                    _sc_AL.id.desc()).limit(1).all()
                _added = _sc_AL.query.filter_by(action="send_command").count() - _before
            return _h, _added, (_rows[0] if _rows else None)

        _h3, _n3, _r3 = _sc_post(3, "NO_SESSION")
        check("console send: rc 3 is the one case that means 'that server isn't running'",
              "no console session to send to" in _h3,
              "the page does not say the server is stopped")
        _h255, _n255, _r255 = _sc_post(255, "ssh: connect to host gmod1 port 22: No route to host")
        check("console send: an unreachable HOST is not reported as a stopped game server",
              "Is the server running" not in _h255
              and "could not run that on the host" in _h255,
              "the page still blames the game server for a host the panel never reached")
        check("console send: ...and it surfaces what the host actually said",
              "No route to host" in _h255, "the ssh error never reaches the operator")
        check("console send: a failed attempt is audited, not silently dropped",
              _n255 == 1 and _r255 is not None and _r255.success is False,
              "rows added=%d success=%r — the form route used to log only on success"
              % (_n255, getattr(_r255, "success", None)))
        # Positive control: the ordinary send still works, and still logs a success.
        _h0, _n0, _r0 = _sc_post(0, "")
        check("console send: ...while a command that went through still reports and logs success",
              "Command sent" in _h0 and _n0 == 1 and _r0 is not None and _r0.success is True,
              "rows added=%d success=%r" % (_n0, getattr(_r0, "success", None)))
        # The JSON custom-command route answers from the same helper, so it gets the same split.
        with app.app_context():
            _sc_cmd = CustomCommand(name="smoke-sendfail", command_template="status",
                                    scope_type="all", scope_value="", enabled=True,
                                    created_by="smoke_admin")
            db.session.add(_sc_cmd)
            db.session.commit()
            _sc_cmd_id = _sc_cmd.id
        try:
            _sc_u = "/api/server/%d/custom-command/%d" % (gs_id, _sc_cmd_id)
            _sc_rc["v"] = ("", "ssh: connect to host gmod1 port 22: No route to host", 255)
            _sc_j = (_lc.post(_sc_u, json={}).get_json() or {})
            check("custom command: an unreachable host is not 'Is the server running?' either",
                  "Is the server running" not in (_sc_j.get("message") or "")
                  and "could not run that on the host" in (_sc_j.get("message") or ""),
                  "message=%r" % (_sc_j.get("message"),))
            _sc_rc["v"] = ("", "NO_SESSION", 3)
            _sc_j3 = (_lc.post(_sc_u, json={}).get_json() or {})
            check("custom command: ...and rc 3 still says the server is not running",
                  "no console session to send to" in (_sc_j3.get("message") or ""),
                  "message=%r" % (_sc_j3.get("message"),))
            _sc_rc["v"] = ("", "", 0)
            _sc_j0 = (_lc.post(_sc_u, json={}).get_json() or {})
            check("custom command: ...while a successful run is unchanged (positive control)",
                  _sc_j0.get("success") is True, "json=%r" % (_sc_j0,))
        finally:
            with app.app_context():
                _row = db.session.get(CustomCommand, _sc_cmd_id)
                if _row is not None:
                    _row.groups = []
                    db.session.delete(_row)
                    db.session.commit()
    finally:
        _cc_mod.send_console_command = _sc_saved

    # ── the terminal's two audit promises, driven through a real socket ──────────────────────
    # The feature claims "a row per session opened and closed, and NEVER what was typed", and
    # nothing checked either. Socket events are covered by neither CSRFProtect nor rbac_test's
    # url_map sweeps — host_terminal.py's own docstring says so — which makes this the code path
    # with the least watching it.
    #
    # The transport is stubbed: the question is what the ROUTE records, not whether a shell
    # spawns. The disconnect leg is the real prize — it goes through the console's disconnect
    # handler and the socket_hooks chain, which is what #323 broke and a later commit fixed.
    import panel.ops.terminal_session as _tsmod
    _TERM_SECRET = "hunter2-do-not-log-this"

    class _FakeTermSess(object):
        def __init__(self): self.writes = []
        def write(self, d): self.writes.append(d)
        def resize(self, c, r): pass

    _fake_sessions = {}
    _ts_saved = (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid)

    def _fake_open(sid, server, is_local, user_key, on_output, on_exit, cols=80, rows=24):
        _fake_sessions[sid] = _FakeTermSess()
        return _fake_sessions[sid]

    with app.app_context():
        _ta_host = RemoteServer(name="smoke-audit-host", host="127.0.0.1", port=22,
                                username="root", auth_method="key", auth_credential="",
                                is_local=True)
        db.session.add(_ta_host)
        db.session.commit()
        _ta_id, _ta_name = _ta_host.id, _ta_host.name
    _tsmod.open_session = _fake_open
    _tsmod.get = lambda sid: _fake_sessions.get(sid)
    _tsmod.close_for_sid = lambda sid, reason="": _fake_sessions.pop(sid, None)
    _ta_err = ""
    try:
        _ta_c = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
        _ta_ok = _ta_c.is_connected()
    except Exception as _e:
        _ta_c, _ta_ok, _ta_err = None, False, "%s: %s" % (type(_e).__name__, _e)
    check("terminal audit: a terminal socket client connects", _ta_ok, _ta_err)
    try:
        if _ta_ok:
            _ta_c.emit("term_open", {"remote_id": _ta_id, "cols": 80, "rows": 24})
            with app.app_context():
                _opened = _SPAudit.query.filter_by(action="terminal_open",
                                                   target=_ta_name).first()
            check("terminal audit: opening a session writes a row naming the host",
                  _opened is not None,
                  "no terminal_open row for %r — the feature claims one per session" % (_ta_name,))
            _ta_c.emit("term_input", {"data": _TERM_SECRET})
            _wrote = [w for s_ in _fake_sessions.values() for w in s_.writes]
            check("terminal audit: ...and the keystrokes really did reach the session",
                  _TERM_SECRET in _wrote,
                  "the input event did nothing, so the next check would pass vacuously: %r"
                  % (_wrote,))
            with app.app_context():
                _leaked = [r.id for r in _SPAudit.query.all()
                           if _TERM_SECRET in ((r.detail or "") + (r.target or "")
                                               + (r.action or ""))]
            check("terminal audit: ...and NOTHING typed is written to the audit log",
                  not _leaked,
                  "what was typed into the terminal appears in audit row(s) %r — people type "
                  "passwords into terminals" % (_leaked,))
            _ta_c.disconnect()
            with app.app_context():
                _closed = _SPAudit.query.filter_by(action="terminal_close",
                                                   target=_ta_name).first()
            check("terminal audit: a disconnect writes the closing row",
                  _closed is not None,
                  "no terminal_close row — the socket_hooks chain did not reach the terminal, "
                  "which is exactly what a second disconnect handler would cause")
    finally:
        (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid) = _ts_saved
        try:
            if _ta_c is not None and _ta_c.is_connected():
                _ta_c.disconnect()
        except Exception:
            pass
        with app.app_context():
            _row = db.session.get(RemoteServer, _ta_id)
            if _row is not None:
                db.session.delete(_row)
                db.session.commit()

    # ── a terminal on the PANEL'S OWN host is superadmin-only, whatever the grants say ──────────
    # A shell there runs as the account that owns panel.db, secret_key and cred_key, so it is the
    # panel itself. It was reachable with USE_TERMINAL plus any group granting the panel host —
    # two ordinary, delegable grants that together added up to superadmin. The page route, the
    # term_open event and the per-keystroke re-check all refuse it now; a REMOTE stays reachable
    # on the same grants (the positive controls), since the panel is root there by design.
    import panel.routes.host_terminal as _htmod
    _lt_sessions = {}

    def _lt_open(sid, server, is_local, user_key, on_output, on_exit, cols=80, rows=24):
        _lt_sessions[sid] = _FakeTermSess()
        _lt_sessions[sid].host = server.id
        return _lt_sessions[sid]

    with app.app_context():
        _lt_local = RemoteServer(name="smoke-lt-local", host="127.0.0.1", port=22,
                                 username="panel", auth_method="local", auth_credential="",
                                 is_local=True)
        _lt_remote = RemoteServer(name="smoke-lt-remote", host="192.0.2.77", port=22,
                                  username="root", auth_method="key", auth_credential="",
                                  is_local=False)
        db.session.add_all([_lt_local, _lt_remote])
        db.session.flush()
        _lt_grp = Group(name="smoke-term-both", description="", is_default=False)
        _lt_grp.set_permissions([auth.USE_TERMINAL, auth.MANAGE_REMOTES])
        _lt_grp.servers.append(_lt_local)
        _lt_grp.servers.append(_lt_remote)
        db.session.add(_lt_grp)
        db.session.flush()
        _lt_u = User(username="smoke-term-deleg", password_hash=auth.hash_password("Str0ng!passw0rd"),
                     is_superadmin=False, is_active=True)
        _lt_u.groups.append(_lt_grp)
        db.session.add(_lt_u)
        db.session.commit()
        _lt_lid, _lt_rid, _lt_uid, _lt_gid = _lt_local.id, _lt_remote.id, _lt_u.id, _lt_grp.id
    _tsmod.open_session = _lt_open
    _tsmod.get = lambda sid: _lt_sessions.get(sid)
    _tsmod.close_for_sid = lambda sid, reason="": _lt_sessions.pop(sid, None)
    _lt_c = _lt_c2 = None
    try:
        _lt_http = client_as(_lt_uid)
        _lt_pg = _lt_http.get("/terminal/%d" % _lt_lid, headers={"Accept": "application/json"})
        check("terminal: a non-superadmin with use_terminal and a panel-host grant is refused the "
              "panel host's terminal PAGE", _lt_pg.status_code == 403,
              "status=%d — the page offers a shell as the account that owns panel.db and the keys"
              % _lt_pg.status_code)
        _lt_pr = _lt_http.get("/terminal/%d" % _lt_rid)
        check("terminal: ...while the same grants still reach a REMOTE's terminal page "
              "(positive control)", _lt_pr.status_code == 200, "status=%d" % _lt_pr.status_code)
        # The panel records no input, but the shell is an ordinary interactive one and writes its
        # own history on the host. "Nothing typed here is recorded" was stated as absolute, on the
        # page where operators type secrets.
        _lt_prt = _lt_pr.get_data(as_text=True)
        check("terminal: the page does not promise nothing typed is kept — the shell's own "
              "history is",
              "Nothing typed here is recorded" not in _lt_prt and "command history" in _lt_prt,
              "the page still says nothing is recorded while ~/.bash_history is written")
        # xterm's DOM renderer gives each colour run its own <span>, and the catalog walker swaps
        # any text node equal to a key: a French viewer saw the host print ERREUR.
        _lt_mount = _re_ab.search(r'<div[^>]*\bid="terminal"[^>]*>', _lt_prt)
        check("terminal: the xterm mount point is exempt from the translation walker",
              _lt_mount is not None and "data-no-i18n" in _lt_mount.group(0),
              "mount tag: %r — host output gets translated" % (_lt_mount and _lt_mount.group(0)))
        import panel.ops.system_ops as _lt_so
        _lt_gss = _lt_so.get_server_status
        _lt_so.get_server_status = lambda force=False: None      # reads THIS machine; not the question
        try:
            _lt_mg = _lt_http.get("/remote/%d/manage" % _lt_lid).get_data(as_text=True)
            _lt_mr = _lt_http.get("/remote/%d/manage" % _lt_rid).get_data(as_text=True)
        finally:
            _lt_so.get_server_status = _lt_gss
        check("terminal: ...and the manage page hides the panel host's terminal card from them",
              ("/terminal/%d" % _lt_lid) not in _lt_mg and ("/terminal/%d" % _lt_rid) in _lt_mr,
              "local card shown=%s, remote card shown=%s"
              % (("/terminal/%d" % _lt_lid) in _lt_mg, ("/terminal/%d" % _lt_rid) in _lt_mr))

        _lt_c = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
        _lt_c.emit("term_open", {"remote_id": _lt_lid, "cols": 80, "rows": 24})
        _lt_err = [e for e in _lt_c.get_received() if e.get("name") == "term_error"]
        check("terminal: ...and term_open on the panel host opens NO shell for them",
              not any(getattr(v, "host", None) == _lt_lid for v in _lt_sessions.values())
              and _lt_err and _htmod.LOCAL_HOST_REFUSAL in str(_lt_err[0].get("args")),
              "sessions=%r errors=%r" % ({k: getattr(v, "host", None)
                                          for k, v in _lt_sessions.items()}, _lt_err))
        _lt_c.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
        check("terminal: ...while term_open on a granted REMOTE does (positive control)",
              any(getattr(v, "host", None) == _lt_rid for v in _lt_sessions.values()),
              "no session on the remote — the gate refuses everything")
        _lt_c.disconnect()
        _lt_sessions.clear()

        # The per-keystroke re-check asks the same question: a superadmin with a panel-host shell
        # open who is demoted keeps nothing, even though their groups still grant the host.
        with app.app_context():
            db.session.get(User, _lt_uid).is_superadmin = True
            db.session.commit()
        _lt_c2 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
        _lt_c2.emit("term_open", {"remote_id": _lt_lid, "cols": 80, "rows": 24})
        _lt_c2.emit("term_input", {"data": "before-demotion"})
        _lt_w = [w for v in _lt_sessions.values() for w in v.writes]
        check("terminal: a superadmin's panel-host shell takes keystrokes (control for the next)",
              "before-demotion" in _lt_w, "writes=%r" % (_lt_w,))
        with app.app_context():
            db.session.get(User, _lt_uid).is_superadmin = False
            db.session.commit()
        _htmod._sid_access.clear()          # the 10 s cache, not the question under test
        _lt_c2.emit("term_input", {"data": "after-demotion"})
        _lt_w = [w for v in _lt_sessions.values() for w in v.writes]
        check("terminal: ...and once they are demoted the re-check refuses the panel host, "
              "though a group still grants it",
              "after-demotion" not in _lt_w, "writes=%r" % (_lt_w,))

        # Losing the terminal ITSELF must close the shell, not only refuse the keystroke. When
        # _may_use_terminal() said no, the handlers returned: the shell stayed up and its output
        # kept streaming to the socket until the 15-minute idle sweep. Driven through the real
        # events, with use_terminal taken off the user's only group between two keystrokes.
        _lt_c2.disconnect()
        _lt_sessions.clear()
        _lt_c3 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
        _lt_c3.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
        _lt_c3.emit("term_input", {"data": "before-revoke"})
        _lt_open3 = [k for k, v in _lt_sessions.items() if getattr(v, "host", None) == _lt_rid]
        check("terminal: a delegated user's remote shell takes keystrokes (control for the next)",
              bool(_lt_open3)
              and "before-revoke" in [w for v in _lt_sessions.values() for w in v.writes],
              "sessions=%r" % (list(_lt_sessions),))
        with app.app_context():
            db.session.get(Group, _lt_gid).set_permissions([auth.MANAGE_REMOTES])
            db.session.commit()
        _lt_c3.get_received()
        _lt_c3.emit("term_input", {"data": "after-revoke"})
        _lt_err3 = [e for e in _lt_c3.get_received() if e.get("name") == "term_error"]
        check("terminal: taking use_terminal away CLOSES the open shell at its next event",
              _lt_open3 and not any(k in _lt_sessions for k in _lt_open3) and _lt_err3,
              "still open=%r, term_error=%r — the keystroke is refused but the shell and its "
              "output stay up for another fifteen minutes"
              % ([k for k in _lt_open3 if k in _lt_sessions], _lt_err3))
        with app.app_context():
            db.session.get(Group, _lt_gid).set_permissions([auth.USE_TERMINAL,
                                                            auth.MANAGE_REMOTES])
            db.session.commit()

        # ...and with NO event at all. A shell following a log is sent nothing, so a check made
        # only when a keystroke arrives never runs for it: the timer sweep has to. Signing the
        # user out everywhere (auth_epoch bumped) must close it on the sweep alone.
        _lt_c4 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
        _lt_before4 = set(_lt_sessions)
        _lt_c4.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
        _lt_open4 = [k for k in _lt_sessions if k not in _lt_before4]
        with app.app_context():
            _htmod.sweep_revoked_terminals(app, app.socketio)
        check("terminal: the revocation sweep leaves a shell whose login still holds alone "
              "(positive control)",
              bool(_lt_open4) and all(k in _lt_sessions for k in _lt_open4),
              "opened=%r, still open=%r" % (_lt_open4, [k for k in _lt_open4 if k in _lt_sessions]))

        def _lt_revoked_rows():
            return _SPAudit.query.filter_by(action="terminal_close",
                                            detail="terminal access was revoked",
                                            username="smoke-term-deleg").count()
        with app.app_context():
            _lt_aud_before4 = _lt_revoked_rows()
            _lt_u4 = db.session.get(User, _lt_uid)
            _lt_u4.auth_epoch = (_lt_u4.auth_epoch or 0) + 1
            db.session.commit()
        _lt_c4.get_received()
        with app.app_context():
            _htmod.sweep_revoked_terminals(app, app.socketio)
            _lt_aud4 = _lt_revoked_rows() - _lt_aud_before4
        _lt_err4 = [e for e in _lt_c4.get_received() if e.get("name") == "term_error"]
        check("terminal: a shell sent no input is closed by the sweep once its login is revoked",
              _lt_open4 and not any(k in _lt_sessions for k in _lt_open4) and _lt_err4,
              "still open=%r, term_error=%r — its output keeps reaching the signed-out browser"
              % ([k for k in _lt_open4 if k in _lt_sessions], _lt_err4))
        check("terminal: ...and the closing row names the user whose access went",
              _lt_aud4 >= 1, "no new terminal_close row for smoke-term-deleg with that reason")
        for _cl in (_lt_c3, _lt_c4):
            try:
                if _cl.is_connected():
                    _cl.disconnect()
            except Exception:
                pass
    finally:
        (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid) = _ts_saved
        for _cl in (_lt_c, _lt_c2):
            try:
                if _cl is not None and _cl.is_connected():
                    _cl.disconnect()
            except Exception:
                pass
        with app.app_context():
            _u = db.session.get(User, _lt_uid)
            if _u is not None:
                _u.groups = []
                db.session.delete(_u)
            _g = db.session.get(Group, _lt_gid)
            if _g is not None:
                _g.servers = []
                db.session.delete(_g)
            for _rid in (_lt_lid, _lt_rid):
                _row = db.session.get(RemoteServer, _rid)
                if _row is not None:
                    db.session.delete(_row)
            db.session.commit()

    # ── the two exemptions that rest on SameSite ─────────────────────────────────────────────
    # A WebSocket handshake is NOT subject to the same-origin policy: any page the operator visits
    # can open one to the panel, and the browser attaches cookies for the target origin. What
    # stops that page getting a console — or, since this branch, a SHELL — is that the session
    # cookie is SameSite=Lax and so is not sent cross-site, which leaves the socket's connect gate
    # seeing an anonymous client and refusing it.
    #
    # The socket's origin check is the first layer: with no site_domain and no explicit
    # socketio_cors_origins it is same-origin, port included (the 'socket origin' checks below),
    # never "*" unless the operator lists it. This cookie is the second layer under it — where the
    # check does let a cross-site page through (an operator's "*"), that page still reaches the
    # connect gate anonymously — and the CSRF Bearer exemption a few hundred lines above rests on
    # it alone. Nothing asserted it. Setting it to "None" — which is what anyone embedding the
    # panel in an iframe would reach for — silently removes the floor under both.
    check("cookie: the session cookie is SameSite-restricted",
          app.config.get("SESSION_COOKIE_SAMESITE") in ("Lax", "Strict"),
          "SESSION_COOKIE_SAMESITE is %r — the socket connect gate and the CSRF Bearer exemption "
          "both rely on this cookie not being sent cross-site"
          % (app.config.get("SESSION_COOKIE_SAMESITE"),))
    check("cookie: ...and is not readable from JavaScript",
          app.config.get("SESSION_COOKIE_HTTPONLY") is True,
          "SESSION_COOKIE_HTTPONLY is %r" % (app.config.get("SESSION_COOKIE_HTTPONLY"),))
    # ...and the socket's origin check. Driven through the engineio server the app really built, so
    # it covers the wiring too. It was a list fixed at startup — ["https://<site_domain>",
    # "http://<site_domain>"], no port, else "*" — so the default direct install (site_domain typed
    # into the wizard, browsed on :5000) had every handshake refused, a Settings change needed a
    # restart, and with no domain ANY page could complete the handshake.
    from panel.core.config import load_config as _lc_cfg, save_config as _sc_cfg
    _eio = app.socketio.server.eio

    def _sio_ok(origin, scheme="https", host="panel.example.com:5000", **extra):
        _env = dict({"wsgi.url_scheme": scheme, "HTTP_HOST": host, "HTTP_ORIGIN": origin}, **extra)
        return _eio._cors_allowed_origins(_env) in (None, [origin])

    _cfg_before = _lc_cfg()
    try:
        _sc_cfg(dict(_cfg_before, site_domain="panel.example.com", socketio_cors_origins=None))
        check("socket: a page on the host:port the panel is reached on may connect (site_domain set)",
              _sio_ok("https://panel.example.com:5000"),
              "the default direct install's own origin was refused — no console, no terminal")
        check("socket: ...and so may site_domain, reached through a proxy that rewrote Host",
              _sio_ok("https://panel.example.com", scheme="http", host="127.0.0.1:5000"))
        check("socket: ...and so may the origin a proxy forwards (X-Forwarded-Proto/Host)",
              _sio_ok("https://node.example.ts.net", scheme="http", host="127.0.0.1:5000",
                      HTTP_X_FORWARDED_PROTO="https", HTTP_X_FORWARDED_HOST="node.example.ts.net"))
        check("socket: a page on any other origin may not",
              not _sio_ok("https://evil.example"),
              "a wildcard lets any page complete the handshake, leaving the session cookie as the "
              "only thing between a visited page and a shell")
        _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=None))
        check("socket: with no domain it is same-origin, not '*' — a foreign page is refused",
              not _sio_ok("https://evil.example", scheme="http", host="203.0.113.5:5000"))
        check("socket: ...while plain IP:port access still connects",
              _sio_ok("http://203.0.113.5:5000", scheme="http", host="203.0.113.5:5000"))
        _sc_cfg(dict(_cfg_before, site_domain="later.example", socketio_cors_origins=None))
        check("socket: a site_domain saved at runtime applies without a restart",
              _sio_ok("https://later.example", scheme="http", host="127.0.0.1:5000"))
        _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=["https://only.example"]))
        check("socket: an explicit socketio_cors_origins list still wins",
              _sio_ok("https://only.example") and not _sio_ok("https://panel.example.com:5000"))
        # No domain and NO explicit list: the check above leaves socketio_cors_origins set, and an
        # explicit list wins outright — every case below would then pass or fail for that reason.
        _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=None))
        # Two review fixes changed this check two ways; one survives, and the other's cases are
        # asserted against it here. A SITE ignores the port, so a page on another port of the
        # panel's own address (a game's web map) is same-site: the Lax cookie rides along, and only
        # the port refuses it. Compared as (host, port): a Host with no port takes the ORIGIN's
        # scheme default, so a TLS proxy that forwards the host but not X-Forwarded-Proto still
        # matches — requiring the scheme too refused exactly those proxies, with no message.
        for _so_origin, _so_kw, _so_want, _so_what in (
                ("http://1.2.3.4:8123", dict(scheme="http", host="1.2.3.4:5000"), False,
                 "a page on another port of the panel's own address"),
                ("http://127.0.0.1:8123", dict(scheme="http", host="127.0.0.1:5000"), False,
                 "...on loopback too"),
                ("https://panel.example.com", dict(scheme="http", host="panel.example.com"), True,
                 "TLS proxy forwards Host without X-Forwarded-Proto"),
                ("https://panel.example.com", dict(scheme="http", host="127.0.0.1:5000",
                                                   HTTP_X_FORWARDED_HOST="panel.example.com"), True,
                 "TLS proxy forwards X-Forwarded-Host without X-Forwarded-Proto"),
                ("https://other.example.ts.net", dict(scheme="http", host="127.0.0.1:5000",
                                                      HTTP_X_FORWARDED_PROTO="https",
                                                      HTTP_X_FORWARDED_HOST="node.example.ts.net"),
                 False, "a sibling host on the same site (another tailnet node)"),
                ("https://panel.example.com:8443", dict(scheme="http", host="panel.example.com"),
                 False, "another port of a host forwarded without a port"),
                ("http://panel.lan:8123", dict(scheme="http", host="panel.lan:5000"), False,
                 "...by hostname too"),
                ("https://panel.lan:8443", dict(scheme="http", host="127.0.0.1:5000",
                                                HTTP_X_FORWARDED_PROTO="https",
                                                HTTP_X_FORWARDED_HOST="panel.lan"), False,
                 "...and against the host a proxy forwarded"),
                ("http://1.2.3.4:5000", dict(scheme="http", host="1.2.3.4:5000"), True,
                 "the panel's own page"),
                ("https://panel.lan", dict(scheme="https", host="panel.lan:443"), True,
                 "an implied default port"),
                ("https://panel.lan", dict(scheme="http", host="127.0.0.1:5000",
                                           HTTP_X_FORWARDED_PROTO="https",
                                           HTTP_X_FORWARDED_HOST="panel.lan"), True,
                 "a proxy that forwards the original host and scheme"),
                ("null", dict(scheme="http", host="1.2.3.4:5000"), False, "an opaque origin")):
            check("socket origin: %s is %s" % (_so_what, "accepted" if _so_want else "refused"),
                  _sio_ok(_so_origin, **_so_kw) is _so_want, "%r with %r" % (_so_origin, _so_kw))
        # A proxy that rewrites Host to loopback and forwards NOTHING cannot be told from a local
        # page, so with no site_domain it is refused: set site_domain (the README's nginx and
        # Caddy examples, and Tailscale Serve, all forward the host).
        check("socket origin: a proxy that hides the host is refused without a site_domain",
              not _sio_ok("https://panel.lan", scheme="http", host="127.0.0.1:5000"))
    finally:
        _sc_cfg(_cfg_before)
    # The app's REAL engine.io server, driven over HTTP: its handshake refuses the other-port page
    # and still answers the panel's own. Only meaningful when the app came up without a domain,
    # which is how this suite builds it; the first check says so if that ever changes.
    _so_eio = app.socketio.server.eio
    import app as _so_app
    check("socket origin: the running engine.io server was built with the per-request origin check",
          _so_eio.cors_allowed_origins is _so_app._socket_origin_allowed,
          "cors_allowed_origins is %r" % (_so_eio.cors_allowed_origins,))
    _so_c = app.test_client()
    _so_bad = _so_c.get("/socket.io/?EIO=4&transport=polling", base_url="http://1.2.3.4:5000",
                        headers={"Origin": "http://1.2.3.4:8123"})
    _so_ok = _so_c.get("/socket.io/?EIO=4&transport=polling", base_url="http://1.2.3.4:5000",
                       headers={"Origin": "http://1.2.3.4:5000"})
    check("socket origin: the live handshake refuses a page on another port of the same address",
          _so_bad.status_code == 400, "status %d %r" % (_so_bad.status_code, _so_bad.data[:80]))
    check("socket origin: ...and completes for the panel's own origin (control)",
          _so_ok.status_code == 200, "status %d %r" % (_so_ok.status_code, _so_ok.data[:80]))

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
            line += "   [%s]" % (detail,)   # (detail,) not detail: a multi-element TUPLE detail made
            #     THIS line raise ('not all arguments converted'), so a
            #     FAILING check printed a traceback instead of its name
        #     and killed the tally and cleanup. Lists and ints are fine
        #     here; the concat-style printer elsewhere breaks on those.
        print(line)
    print("\n%d / %d checks passed" % (passed, len(results)))
    cleanup()

sys.exit(0 if results and passed == len(results) else 1)
