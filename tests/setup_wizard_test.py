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
  2. the lock was gated on is_setup_complete(), which was then (DB row AND config flag) — and the
     config half FAILED OPEN, because load_config() swallows JSONDecodeError/OSError and returns
     DEFAULT_CONFIG, where setup_complete is False. So deleting data/config.json, or truncating it
     on a full disk, or hand-editing it into invalid JSON, reopened the wizard on a live install.

Both are now defended by reading the SetupState row alone — which is also all is_setup_complete()
reads now; config.json's setup_complete is written but no longer read. Neither had a test. They
do now: the config-corruption cases below are the ones that matter most, because nothing about
them looks like an attack — a full disk produces the same file.

Runs against a throwaway database like the other suites, and deliberately does NOT pre-complete
setup — that is the entire point.

    python tests/setup_wizard_test.py     # exits 0 if all checks pass, 1 otherwise
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panel.core.config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("SKIP: %s already exists — this only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

# The one-time setup token the installer prints (manage.py setup-token writes it). Spelled as a
# path rather than imported, so this suite names the file the operator is told about.
_TOKEN_FILE = DATA_DIR / "setup_token"

# panel.db.backup is in here, and it is the one that matters. It is not scratch: models.
# _ensure_db_healthy keeps it as the rolling KNOWN-GOOD copy and restores from it when the live
# database is corrupt. The cleanup below unlinks it, and "not in _PREEXISTING" was the only thing
# standing between a developer's data and that unlink — so it was deleted every run.
#
# The window is narrow and it is exactly the wrong one: these harnesses refuse to run at all while
# panel.db EXISTS, so the only state in which they run and the backup is present is "the live
# database is missing and this copy is the last one left". The WAL/SHM pair is here for the same
# reason — they hold committed pages the main file may not have yet.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE, _TOKEN_FILE,
                            DB_PATH.with_name("panel.db.backup"),
                            DB_PATH.with_name("panel.db-wal"),
                            DB_PATH.with_name("panel.db-shm")) if p.exists()}
_TOKEN_SNAPSHOT = _TOKEN_FILE.read_bytes() if _TOKEN_FILE in _PREEXISTING else None

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


def _restore(path, snapshot):
    """Put back the bytes a file held before the suite ran (nothing to do when it had none)."""
    if snapshot is None:
        return
    try:
        path.write_bytes(snapshot)
    except OSError:
        pass


def cleanup():
    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass
    if _CFG_BACKUP is not None:
        CONFIG_FILE.write_bytes(_CFG_BACKUP)
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE, _TOKEN_FILE,
              DB_PATH.with_name("panel.db-wal"), DB_PATH.with_name("panel.db-shm"),
              DB_PATH.with_name("panel.db.backup")):
        if p not in _PREEXISTING and p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    _restore(CONFIG_FILE, _CONFIG_SNAPSHOT)   # undo our edits to someone else's config
    _restore(_TOKEN_FILE, _TOKEN_SNAPSHOT)     # ...and to a setup token that was already there


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


# The first admin's password throughout: it passes the strength policy, so every refusal below is
# the lock or the step order refusing, never the password rules.
_ADMIN_PASSWORD = "Sufficient1!pass"  # nosec B105 - a fixture for this suite's throwaway DB  # noqa: password


def _is_token_page(resp):
    return b'name="setup_token"' in resp.data and b'name="step"' not in resp.data


def _wiz_step():
    with app.app_context():
        _st = SetupState.query.first()
        return _st.step if _st else None


def _remote_names():
    with app.app_context():
        return sorted(r.name for r in RemoteServer.query.all())


# The three Tailscale actions that change this host, and the wizard's SSH test, are recorders for
# the whole run: a broken gate then RECORDS a call instead of installing Tailscale, joining a
# tailnet, rewriting Serve or opening an SSH connection from a test run. rbac_test.py warns what
# these do unstubbed — they reconfigure the tailnet of the machine the suite runs on.
from panel.ops import tailscale_integration as _ts_mod  # noqa: E402
_so_mod = _so                                      # restart_panel is stubbed on it below
import panel.routes.route_helpers as _rh  # noqa: E402
from panel.db.models import RemoteServer  # noqa: E402
_ts_saved = (_ts_mod.install_tailscale_local, _ts_mod.tailscale_up_local,
             _ts_mod.setup_tailscale_serve, _ts_mod.get_tailscale_info)
_ssh_saved = _rh.ssh_test_connection
_restart_saved = _so_mod.restart_panel
_ts_calls, _ssh_calls, _restarts = [], [], []
_ts_mod.install_tailscale_local = lambda *a, **k: (_ts_calls.append("install") or (True, ""))
_ts_mod.tailscale_up_local = lambda *a, **k: (_ts_calls.append("up") or (True, "https://x"))
_ts_mod.setup_tailscale_serve = lambda *a, **k: (_ts_calls.append("serve") or (True, ""))
# A host on a tailnet, so the Serve step and the complete page have a tailnet name to show.
_TS_INFO = _ts_mod.TailscaleInfo(installed=True, running=True, dns_name="panel.example-tail.ts.net",
                                 tailscale_ips=["100.64.0.7"])
_ts_mod.get_tailscale_info = lambda *a, **k: _TS_INFO
_rh.ssh_test_connection = lambda *a, **k: (_ssh_calls.append(a) or (True, "ok"))
_so_mod.restart_panel = lambda *a, **k: (_restarts.append(1) or (True, "scheduled"))
_SSH_ADD = {"step": "remote_server", "action": "add", "name": "Probe box", "host": "192.0.2.44",
            "ssh_port": "22", "ssh_user": "root", "auth_method": "password", "credential": "pw"}



# The wizard's four Tailscale endpoints. /up joins this host to the CALLER's tailnet with Tailscale
# SSH on and returns them the login URL; /install runs the installer as root; /serve rewrites
# bind_host; /status reads out the host's tailnet name and addresses.
_TS_EPS = (("/api/setup/tailscale/status", "get"), ("/api/setup/tailscale/install", "post"),
           ("/api/setup/tailscale/up", "post"), ("/api/setup/tailscale/serve", "post"))
# Set by the checks below, read by the ones after them.
c = _TOKEN = _paste = _retire = None


def _check_unclaimed_wizard():
    """Before an admin exists, a browser without the setup token gets the token page, nothing more."""
    global c, _TOKEN
    # ── Before an admin exists, the wizard answers only to the setup token ────────────────────
    # It was open to anyone who reached the port until the operator submitted step 2 — and a
    # default install opens that port itself. Whoever got there first created the superadmin (root
    # on this host) and was issued the owner token; the operator's browser was then sent to a login
    # it had no account for. The installer runs in the operator's own terminal, so it can hand them
    # a secret nobody on the network has: the token file manage.py setup-token writes.
    import secrets as _secrets
    _TOKEN = _secrets.token_urlsafe(24)
    _TOKEN_FILE.write_text(_TOKEN + "\n", encoding="ascii")   # what the installer leaves behind

    c = app.test_client()
    r = c.get("/setup")
    check("token: GET /setup without the token shows the token page, not the wizard",
          r.status_code == 200 and _is_token_page(r), "got %d" % r.status_code)
    _anon = app.test_client()
    r = _anon.post("/setup", data={"step": "admin_user", "username": "attacker",
                                   "password": _ADMIN_PASSWORD, "confirm_password": _ADMIN_PASSWORD})
    check("token: an unclaimed POST step=admin_user creates no superadmin",
          superadmins() == [], str(superadmins()))
    # Not the owner-token failure path: that redirects to /login, and before an admin exists
    # check_setup sends /login straight back to /setup — an endless loop.
    check("token: ...and answers the token page, not a redirect (no /setup <-> /login loop)",
          r.status_code == 403 and _is_token_page(r),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    _anon.post("/setup", data={"step": "welcome", "site_title": "Hijacked", "port": "5099",
                               "bind_host": "0.0.0.0"})  # nosec B104 - a hostile input, not a bind
    check("token: an unclaimed POST step=welcome writes nothing",
          load_config().get("port") != 5099 and load_config().get("site_title") != "Hijacked",
          "%s %s" % (load_config().get("port"), load_config().get("site_title")))
    _anon.post("/setup", data=_SSH_ADD)
    check("token: an unclaimed POST step=remote_server makes no SSH connection and adds no host",
          _ssh_calls == [] and _remote_names() == [], "%r %r" % (_ssh_calls, _remote_names()))
    r = _anon.get("/setup?token=" + "x" * len(_TOKEN))
    check("token: a wrong ?token= is refused with the token page",
          r.status_code == 403 and _is_token_page(r), "got %d" % r.status_code)
    for _bad in ("", _TOKEN[:-1], _TOKEN + "x", "\u00e9" * 8):
        _anon.post("/setup", data={"setup_token": _bad})
    # Step 1 is the one step the wizard's order allows here, so it is what shows a claim.
    _anon.post("/setup", data={"step": "welcome", "site_title": "Hijacked", "port": "5098",
                               "bind_host": "0.0.0.0"})  # nosec B104 - a hostile input, not a bind
    check("token: ...and a wrong, empty, truncated or non-ASCII one grants nothing",
          load_config().get("port") != 5098 and superadmins() == [],
          "%s %s" % (load_config().get("port"), superadmins()))



def _check_unclaimed_tailscale():
    """...and the setup Tailscale endpoints refuse it, CSRF or no CSRF."""
    _anon = app.test_client()
    _bind_first = load_config().get("bind_host")
    for _ep, _meth in _TS_EPS:
        rr = getattr(_anon, _meth)(_ep)
        check("token: an unclaimed caller is refused %s" % _ep, rr.status_code == 403,
              "got %d" % rr.status_code)
    # ...and with CSRF ON (its production default): a cookie-less request with a Bearer header
    # skips CSRF by design, so CSRF is not what may refuse these.
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        _bearer = app.test_client(use_cookies=False)
        for _ep, _meth in _TS_EPS:
            rr = getattr(_bearer, _meth)(_ep, headers={"Authorization": "Bearer x"})
            check("token: a cookie-less Bearer request (CSRF on) is refused %s" % _ep,
                  rr.status_code == 403, "got %d" % rr.status_code)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
    check("token: ...and nothing was run on the host for any of them", _ts_calls == [],
          repr(_ts_calls))
    check("token: ...and the bind address is unchanged", load_config().get("bind_host") == _bind_first,
          repr(load_config().get("bind_host")))



def _check_claim():
    """The printed link (or the pasted token) claims the wizard; the Tailscale step still waits."""
    global _paste, _retire
    # The printed link claims the wizard for this browser, and the token leaves the URL at once
    # (history, Referer and the address bar would otherwise keep it).
    r = c.get("/setup?token=" + _TOKEN)
    _loc = r.headers.get("Location") or ""
    check("token: the printed link claims the wizard and redirects the token out of the URL",
          r.status_code in (302, 303) and _loc.endswith("/setup") and "token" not in _loc,
          "%d -> %s" % (r.status_code, _loc))
    # ── While setup is OPEN ───────────────────────────────────────────────────────────────────
    r = c.get("/setup")
    check("open: GET /setup renders the wizard once claimed (200, not a redirect)",
          r.status_code == 200 and b'name="step"' in r.data, "got %d" % r.status_code)
    # The token page's own form is the other way in (a pasted token).
    _paste = app.test_client()
    _paste.post("/setup", data={"setup_token": " %s " % _TOKEN})
    check("token: pasting the token into the page's form claims the wizard too",
          _paste.get("/setup").status_code == 200 and b'name="step"' in _paste.get("/setup").data)
    # A claimed browser still cannot reach the Tailscale endpoints before an admin exists: the
    # page that calls them is step 3, after the admin, so nothing legitimate needs them earlier.
    for _ep, _meth in _TS_EPS:
        rr = getattr(c, _meth)(_ep)
        check("token: before an admin exists even a claimed browser is refused %s" % _ep,
              rr.status_code == 403, "got %d" % rr.status_code)
    check("token: ...and nothing ran for those either", _ts_calls == [], repr(_ts_calls))
    # Boot deletes the token once it can no longer be used — and must NOT while it still can.
    import app as _app_mod  # noqa: E402
    _retire = getattr(_app_mod, "_retire_setup_token", lambda: None)
    with app.app_context():
        _retire()
    check("token: starting the panel before an admin exists keeps the token",
          _TOKEN_FILE.exists(), "the boot check deleted a token the operator still needs")


def _check_step_order():
    """At the admin step: the token still guards it, and the wizard follows its own step."""
    # The real window: the operator has done step 1 and is filling in the admin form. The step
    # order now allows admin_user, so only the token stands between a stranger and the account.
    check("token: (precondition) the wizard is at the admin step", _wiz_step() == "admin_user",
          _wiz_step())
    r = app.test_client().post("/setup", data={"step": "admin_user", "username": "attacker",
                                               "password": _ADMIN_PASSWORD,
                                               "confirm_password": _ADMIN_PASSWORD})
    check("token: while the operator is at the admin step, an unclaimed POST creates no superadmin",
          superadmins() == [] and r.status_code == 403, "%d %s" % (r.status_code, superadmins()))

    # ── The wizard follows its OWN step, not the one the form names ───────────────────────────
    # The handler dispatched on the posted `step`, so step=remote_server action=add made the panel
    # test an SSH connection to a host of the caller's choosing before any admin existed — a
    # reachability oracle from this host, known_hosts writes, and a planted host row. A posted step
    # AHEAD of the stored one is refused; an earlier one (a browser Back resubmit) still works.
    check("order: (precondition) the wizard is at the admin step", _wiz_step() == "admin_user",
          _wiz_step())
    c.post("/setup", data=_SSH_ADD)
    check("order: step=remote_server posted ahead of the wizard makes no SSH connection",
          _ssh_calls == [] and _remote_names() == [], "%r %r" % (_ssh_calls, _remote_names()))
    c.post("/setup", data={"step": "tailscale"})
    check("order: step=tailscale posted ahead does not advance the wizard",
          _wiz_step() == "admin_user", _wiz_step())
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})
    check("order: re-posting an earlier step works, and does not move the wizard backwards",
          _wiz_step() == "admin_user" and load_config().get("port") == 5052, _wiz_step())


def _check_admin_race():
    """The first admin, created while a second claimed browser races it; the token then retires."""
    # The happy path — raced by a second claimed browser. The superadmin-exists check ran BEFORE
    # hash_password, which parks the greenlet in tpool under eventlet, so two concurrent POSTs both
    # passed it and both created a superadmin (reproduced: ['attacker', 'operator']). A timing
    # race would not reproduce here, so the interleaving is forced: the racer's hash runs the
    # operator's whole POST re-entrantly, which is exactly what the hub can do between the two.
    _racer = app.test_client()
    _racer.get("/setup?token=" + _TOKEN)
    _real_hash = _rh.hash_password
    _race_fired = []

    def _racing_hash(pw):
        if not _race_fired:
            _race_fired.append(1)
            c.post("/setup", data={"step": "admin_user", "username": "firstadmin",
                                   "password": _ADMIN_PASSWORD,
                                   "confirm_password": _ADMIN_PASSWORD,
                                   "email": "admin@example.com"})
        return _real_hash(pw)
    _rh.hash_password = _racing_hash
    try:
        _racer.post("/setup", data={"step": "admin_user", "username": "racer",
                                    "password": _ADMIN_PASSWORD, "confirm_password": _ADMIN_PASSWORD})
    finally:
        _rh.hash_password = _real_hash
    check("race: (control) the operator's POST really ran inside the racer's password hash",
          _race_fired == [1], repr(_race_fired))
    check("race: two admin_user POSTs interleaved create exactly ONE superadmin",
          superadmins() == ["firstadmin"], str(superadmins()))
    check("open: a valid step=admin_user creates the first superadmin",
          superadmins() == ["firstadmin"], str(superadmins()))
    check("token: the token file is deleted once the first admin exists",
          not _TOKEN_FILE.exists(), "still on disk")
    r = app.test_client().get("/setup?token=" + _TOKEN, follow_redirects=False)
    check("token: the printed link, opened after the admin exists, does not reopen the wizard",
          r.status_code in (301, 302, 303) and "/login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    r = _paste.get("/setup", follow_redirects=False)
    check("token: a browser that claimed the token but did not create the admin is sent to sign in",
          r.status_code in (301, 302, 303) and "/login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))


def _check_remote_step():
    """Step 4's add-a-host form runs the Hosts page's checks before any connection."""
    # ── Step 4: the first remote host is checked like the Hosts page's own add form ───────────
    # The wizard stored auth_method straight from the form, and "local" is what makes
    # is_local_server() treat a row as the PANEL HOST — so "Backup box" at 203.0.113.9 became a
    # host the terminal and every panel-host refusal read as this machine. Refused before any
    # connection, like a host that is not a hostname and a name the Hosts page would refuse.
    for _label, _over in (("auth_method=local", {"name": "Backup box", "host": "203.0.113.9",
                                                 "auth_method": "local"}),
                          ("an unknown auth_method", {"name": "Odd box", "auth_method": "agent"}),
                          ("a host that is not a hostname", {"name": "Bad host",
                                                             "host": "-oProxyCommand=x"}),
                          ("a name with markup", {"name": "<b>box</b>"}),
                          ("an SSH user that is not a Linux user", {"name": "User box",
                                                                    "ssh_user": "root;id"})):
        _before_calls = len(_ssh_calls)
        c.post("/setup", data=dict(_SSH_ADD, **_over))
        check("remote step: %s is refused before any connection, and adds no host" % _label,
              len(_ssh_calls) == _before_calls and _remote_names() == [],
              "%d call(s), hosts %r" % (len(_ssh_calls) - _before_calls, _remote_names()))
    # Positive control: an ordinary host, in order, as the owner, is tested and added.
    c.post("/setup", data=dict(_SSH_ADD, name="Wizard box"))
    check("remote step: the owner's in-order add still tests the connection and adds the host",
          len(_ssh_calls) == 1 and _remote_names() == ["Wizard box"],
          "%r %r" % (_ssh_calls, _remote_names()))
    with app.app_context():
        _wb = RemoteServer.query.filter_by(name="Wizard box").first()
        check("remote step: ...as a remote, not the panel host",
              _wb is not None and _wb.auth_method == "password" and not _wb.is_local,
              repr(_wb and (_wb.auth_method, _wb.is_local)))


def _check_complete_page():
    """Finishing shows the complete page, which says where the panel still answers."""
    # ── Finishing: the complete page tells the truth about where the panel still answers ───────
    # The Serve step stores bind_host 127.0.0.1, but the bind is read only at process start, so
    # after the wizard the panel kept answering on its public bind until the next restart (and
    # then, silently, only on the tailnet). The complete page said "Private tailnet — only your
    # devices can reach it" the whole time. Nothing restarts on its own: an operator on the public
    # address, off the tailnet, would be cut off mid-setup.
    app.config["_BOOT_BIND"] = "0.0.0.0"  # nosec B104 - the bind this process "started" on
    rr = c.post("/setup", data={"step": "remote_server", "action": "skip"})
    _done_html = rr.get_data(as_text=True)
    with app.app_context():
        _done_state = SetupState.query.first()
        check("complete: the last step completes setup", bool(_done_state and _done_state.complete))
    check("complete: finishing shows the complete page", rr.status_code == 200
          and "Setup Complete!" in _done_html, "%d %s" % (rr.status_code, _done_html[:80]))
    check("complete: it says the panel still answers on its public bind until it restarts",
          'id="rebind-notice"' in _done_html and "0.0.0.0:5052" in _done_html, _done_html[-600:])
    check("complete: ...and makes no 'only your devices can reach it' claim while it does",
          "Private tailnet" not in _done_html)
    check("complete: ...and did NOT restart the panel by itself", _restarts == [], repr(_restarts))
    # "Restart now" is the owner's explicit choice, and nobody else's.
    rr = _att.post("/setup/restart")
    check("complete: another browser cannot restart the panel", _restarts == [], repr(_restarts))
    rr = c.post("/setup/restart")
    check("complete: the owner's Restart now restarts the panel once",
          _restarts == [1] and rr.status_code == 200, "%d %r" % (rr.status_code, _restarts))
    # Once the running bind is the stored one there is nothing to apply, so no restart...
    app.config["_BOOT_BIND"] = "127.0.0.1"
    c.post("/setup/restart")
    check("complete: with nothing to apply, Restart now does nothing", _restarts == [1],
          repr(_restarts))
    # ...and the private claim is back, because it is true now (positive control).
    with app.test_request_context("/setup"):
        _cp = getattr(_rh, "_complete_page", None)
        _priv_html = _cp(load_config()) if _cp else ""
    check("complete: on a loopback bind the page does say the tailnet URL is private",
          "Private tailnet" in _priv_html and 'id="rebind-notice"' not in _priv_html,
          _priv_html[-400:])
    app.config.pop("_BOOT_BIND", None)


try:
    _check_unclaimed_wizard()
    _check_unclaimed_tailscale()
    _check_claim()

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
    # 192.0.2.123 (TEST-NET-1) is well-formed and on no host: it passed the parse, and the panel
    # then failed to bind it with EADDRNOTAVAIL on the next start.
    for _bad in ("not-an-ip", "0.0.0.0; rm -rf /", "999.1.1.1",
                 "example.com", "127.0.0.1:5000", "<script>", "localhost", "192.0.2.123"):
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
          load_config().get("bind_host") == "0.0.0.0",  # nosec B104 - the expected default, not a bind
          repr(load_config().get("bind_host")))
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})
    _bind_before = load_config().get("bind_host")
    check("open: a refused bind address leaves the rest of step 1 unsaved too",
          load_config().get("site_title") == "Test Panel", load_config().get("site_title"))
    for _good in ("0.0.0.0", "::", "127.0.0.1", "::1"):  # nosec B104 - inputs posted to the wizard
        r = c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                                   "port": "5052", "bind_host": _good})
        check("open: step=welcome accepts bind_host=%r (positive control)" % _good,
              load_config().get("bind_host") == _good, repr(load_config().get("bind_host")))
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})

    _check_step_order()

    # ── Step 2 validation: none of these may create an account ────────────────────────────────
    for _name, _form, _why in (
            ("a short username", {"username": "ab", "password": _ADMIN_PASSWORD,
                                  "confirm_password": _ADMIN_PASSWORD}, "under 3 chars"),
            ("a weak password", {"username": "admin1", "password": "short",  # nosec B105 - fixture
                                 "confirm_password": "short"}, "password_problem"),  # nosec B105
            ("a mismatched confirmation", {"username": "admin1", "password": _ADMIN_PASSWORD,
                                           "confirm_password": "Different1!pass"},  # nosec B105
             "mismatch")):
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

    _check_admin_race()

    with app.app_context():
        _u = User.query.filter_by(username="firstadmin").first()
        check("open: the first admin is active and a superadmin",
              _u is not None and _u.is_superadmin and _u.is_active)
        check("open: their password is HASHED, never stored in the clear",
              _u is not None and _ADMIN_PASSWORD not in (_u.password_hash or ""))
        check("open: their email is encrypted at rest, not stored in the clear",
              _u is not None and "admin@example.com" not in (_u.email or ""))

    # ── From here the wizard belongs to the browser that created the admin ────────────────────
    # It stayed open to ANY caller until the last step, and the steps after the admin are the
    # dangerous ones: /api/setup/tailscale/up joined this host to the caller's tailnet with
    # Tailscale SSH on and handed them the auth URL, and step=welcome rewrote the bind.
    _att = app.test_client()
    r = _att.get("/setup", follow_redirects=False)
    check("owner: another browser's GET /setup is sent to sign in, not shown the wizard",
          r.status_code in (301, 302, 303) and "/login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    for _ep, _meth in (("/api/setup/tailscale/up", "post"),
                       ("/api/setup/tailscale/install", "post"),
                       ("/api/setup/tailscale/serve", "post"),
                       ("/api/setup/tailscale/status", "get")):
        rr = getattr(_att, _meth)(_ep, json={}) if _meth == "post" else _att.get(_ep)
        check("owner: another browser is refused %s" % _ep, rr.status_code == 403,
              "got %d" % rr.status_code)
    check("owner: ...and nothing was run on the host for it", _ts_calls == [], repr(_ts_calls))
    _bind_owner = load_config().get("bind_host")
    _att.post("/setup", data={"step": "welcome", "site_title": "Hijacked", "port": "5099",
                              "bind_host": "0.0.0.0"})  # nosec B104 - a hostile input, not a bind
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
    # A Back-button resubmit of step 1 is harmless, and must not move the wizard back to the admin
    # step: that page's POST now refuses (an admin exists), so the owner would be stuck on it.
    c.post("/setup", data={"step": "welcome", "site_title": "Test Panel",
                           "port": "5052", "bind_host": "127.0.0.1"})
    check("order: the owner re-posting step 1 does not send the wizard back to the admin step",
          _wiz_step() == "tailscale", _wiz_step())
    # ...and the way back in from any other browser is to sign in as the admin.
    r = _att.get("/login", follow_redirects=False)
    check("owner: /login is reachable once an admin exists (not bounced into the wizard)",
          r.status_code == 200, "got %d -> %s" % (r.status_code, r.headers.get("Location")))
    _rec = app.test_client()
    _rec.post("/login?next=/setup", data={"username": "firstadmin",
                                          "password": _ADMIN_PASSWORD})
    r = _rec.get("/setup", follow_redirects=False)
    check("owner: a browser signed in as the superadmin may finish the wizard",
          r.status_code == 200, "got %d -> %s" % (r.status_code, r.headers.get("Location")))

    # ── Step 3: Tailscale Serve, as the owner (positive control for the 403s above) ───────────
    rr = c.post("/api/setup/tailscale/serve")
    check("owner: the creating browser can run the Serve step",
          rr.status_code == 200 and (rr.get_json() or {}).get("success") is True
          and _ts_calls == ["serve"], "%d %r" % (rr.status_code, _ts_calls))
    check("owner: ...which stores a loopback bind for the next start",
          load_config().get("bind_host") == "127.0.0.1", repr(load_config().get("bind_host")))
    c.post("/setup", data={"step": "tailscale"})
    check("owner: the creating browser advances the wizard", _wiz_step() == "remote_server",
          _wiz_step())

    # A second admin_user POST must be refused even while the wizard is still open — the wizard
    # creates the FIRST admin only (defence in depth behind the completion lock).
    c.post("/setup", data={"step": "admin_user", "username": "sneak",
                           "password": _ADMIN_PASSWORD, "confirm_password": _ADMIN_PASSWORD})
    check("open: step=admin_user refuses once a superadmin exists",
          superadmins() == ["firstadmin"], str(superadmins()))

    _check_remote_step()

    _check_complete_page()

    # ── Once setup is COMPLETE, the wizard is permanently locked ──────────────────────────────
    mark_setup_complete()
    c = app.test_client()

    r = c.get("/setup", follow_redirects=False)
    check("locked: GET /setup redirects to login",
          r.status_code in (301, 302, 303) and "login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    # An install that finished before the token existed is unaffected: a token file left behind
    # (an interrupted update, a hand copy) opens nothing, and the next start deletes it.
    _TOKEN_FILE.write_text(_TOKEN, encoding="ascii")
    r = c.get("/setup?token=" + _TOKEN, follow_redirects=False)
    check("locked: a completed install ignores ?token= and stays locked",
          r.status_code in (301, 302, 303) and "login" in (r.headers.get("Location") or ""),
          "%d -> %s" % (r.status_code, r.headers.get("Location")))
    with app.app_context():
        _retire()
    check("locked: starting a finished install deletes a leftover setup token",
          not _TOKEN_FILE.exists(), "still on disk")

    # REGRESSION 1: POST used to be unguarded while GET was blocked.
    r = c.post("/setup", data={"step": "admin_user", "username": "backdoor",
                               "password": _ADMIN_PASSWORD, "confirm_password": _ADMIN_PASSWORD},
               follow_redirects=False)
    check("locked: POST step=admin_user cannot create a superadmin",
          "backdoor" not in superadmins(), str(superadmins()))

    _before = load_config()
    c.post("/setup", data={"step": "welcome", "site_title": "Hijacked",
                           "port": "1234", "bind_host": "0.0.0.0"}, follow_redirects=False)  # nosec B104 - hostile input
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
            ("deleted", CONFIG_FILE.unlink),
            ("truncated to empty", lambda: CONFIG_FILE.write_text("", encoding="utf-8")),
            ("invalid JSON", lambda: CONFIG_FILE.write_text("{not json", encoding="utf-8"))):
        _writer()
        c2 = app.test_client()
        r = c2.get("/setup", follow_redirects=False)
        check("locked: with config.json %s, GET /setup STAYS locked" % _label,
              r.status_code in (301, 302, 303) and "login" in (r.headers.get("Location") or ""),
              "%d -> %s" % (r.status_code, r.headers.get("Location")))
        c2.post("/setup", data={"step": "admin_user", "username": "cfgbreak-%s" % _label[:4],
                                "password": _ADMIN_PASSWORD,
                                "confirm_password": _ADMIN_PASSWORD}, follow_redirects=False)
        check("locked: with config.json %s, POST still creates NO superadmin" % _label,
              not any(u.startswith("cfgbreak") for u in superadmins()), str(superadmins()))

        # THE ACTUAL EXPLOIT from regression #2, and the reason the two above are not enough:
        # step=admin_user is additionally guarded by "a superadmin already exists", so it stays
        # shut even when the outer lock is broken. step=welcome has no such inner guard — it just
        # writes. On a live install that turns a loopback-only panel into 0.0.0.0 at the next
        # restart, from an unauthenticated request, with no credential involved.
        c2.post("/setup", data={"step": "welcome", "site_title": "Hijacked-%s" % _label[:4],
                                "port": "1234", "bind_host": "0.0.0.0"}, follow_redirects=False)  # nosec B104 - hostile input
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
    (_ts_mod.install_tailscale_local, _ts_mod.tailscale_up_local,
     _ts_mod.setup_tailscale_serve, _ts_mod.get_tailscale_info) = _ts_saved
    _rh.ssh_test_connection = _ssh_saved
    _so_mod.restart_panel = _restart_saved
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
