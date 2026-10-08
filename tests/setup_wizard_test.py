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
# nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled -- the test client posts forms without a browser-issued token
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
        pass  # cleanup only: a config it cannot restore must not hide the result


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
            except OSError as e:
                # Said, not swallowed: a panel.db left behind makes the NEXT run of every
                # DB-owning suite print SKIP and exit 0, with nothing to say why.
                print("cleanup: could not remove %s (%s)" % (p, e), file=sys.stderr)
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


def _audit(action):
    """(username, target, detail, success, remote_id) of each audit row with `action`, in order."""
    with app.app_context():
        return [(a.username, a.target, a.detail, a.success, a.remote_id)
                for a in AuditLog.query.filter_by(action=action).order_by(AuditLog.id).all()]


# The three Tailscale actions that change this host, and the wizard's SSH test, are recorders for
# the whole run: a broken gate then RECORDS a call instead of installing Tailscale, joining a
# tailnet, rewriting Serve or opening an SSH connection from a test run. rbac_test.py warns what
# these do unstubbed — they reconfigure the tailnet of the machine the suite runs on.
from panel.ops import tailscale_integration as _ts_mod  # noqa: E402
_so_mod = _so                                      # restart_panel is stubbed on it below
import panel.routes.route_helpers as _rh  # noqa: E402
from panel.db.models import AuditLog, RemoteServer  # noqa: E402
_ts_saved = (_ts_mod.install_tailscale_local, _ts_mod.tailscale_up_local,
             _ts_mod.setup_tailscale_serve, _ts_mod.get_tailscale_info)
_ssh_saved = _rh.ssh_test_connection
_restart_saved = _so_mod.restart_panel
_ts_calls, _ssh_calls, _restarts = [], [], []
_ts_mod.install_tailscale_local = lambda *a, **k: (_ts_calls.append("install") or (True, ""))
_ts_mod.tailscale_up_local = lambda *a, **k: (_ts_calls.append("up") or (True, "https://x"))
# A host on a tailnet, so the Serve step and the complete page have a tailnet name to show.
_TS_INFO = _ts_mod.TailscaleInfo(installed=True, running=True, dns_name="panel.example-tail.ts.net",
                                 tailscale_ips=["100.64.0.7"])


def _ts_publish(port=5000, mount="/", funnel=False, backend_scheme="http"):
    """What a Serve write leaves on the host: the panel's route, in the reading the stub answers.

    The complete page names the panel's Tailscale address only when the host reports a route to
    the panel at its mount, on the scheme it serves, so the recorder has to leave one behind.
    """
    _TS_INFO.serve_config = {"services": [{"url": "https://panel.example-tail.ts.net",
                                           "funnel": bool(funnel), "routes": [
        {"mount": mount or "/", "target": "%s://127.0.0.1:%s" % (backend_scheme, port)}]}]}


_ts_mod.setup_tailscale_serve = lambda *a, **k: (_ts_calls.append("serve") or _ts_publish(**k)
                                                 or (True, ""))
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
        # nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled -- the test client posts forms without a browser-issued token
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
    # sys.modules, not `import app as`: this file already has `from app import`, and a module
    # imported both ways is what CodeQL's py/import-and-import-from flags (tests/ is out of its
    # scope, so part37 holds the rule here instead).
    _app_mod = sys.modules["app"]
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


def _lock_probe(real_hash):
    """A third claimed browser whose admin POST arrives while the operator's is INSIDE the lock.

    _check_admin_race forces its interleave inside hash_password, which runs BEFORE
    _ADMIN_CREATE_LOCK, so it proves the re-check under the lock and not the lock: `with
    _ADMIN_CREATE_LOCK:` replaced by `if True:` passed the whole suite. This forces the other window.
    Once the operator's own password is hashed, its next superadmin check is the re-check it makes
    holding the lock; there it lets a third POST run for two seconds before going on to insert and
    commit. With the lock, the third waits at it the whole time and then finds the admin. Without
    it, the third creates a second superadmin in that window. Nothing in the current code yields
    there under eventlet, but anything added between the re-check and the commit that does (a log
    line to a slow disk, a tpool call) is exactly this.
    """
    import threading as _thr
    _third = app.test_client()
    _third.get("/setup?token=" + _TOKEN)
    _instant = real_hash(_ADMIN_PASSWORD)     # the third's hash costs nothing, so it reaches the lock
    # Waited on with an Event, never Thread.join(timeout): under eventlet on Python 3.13+ that join
    # raises eventlet's Timeout (a BaseException) instead of returning, which ended this suite early
    # with a passing tally (see panel/ops/terminal_session.py for the same trap).
    _done = _thr.Event()
    st = {"armed": False, "fired": False, "waited": None, "resp": None, "thread": None,
          "real_exists": _rh._superadmin_exists}

    def _post():
        try:
            st["resp"] = _third.post("/setup", data={"step": "admin_user", "username": "third",
                                                     "password": _ADMIN_PASSWORD,
                                                     "confirm_password": _ADMIN_PASSWORD})
        finally:
            _done.set()

    def _hash(pw):
        if st["armed"]:
            return _instant
        out = real_hash(pw)      # the operator's: from here its next check is the one under the lock
        st["armed"] = True
        return out

    def _exists():
        found = st["real_exists"]()
        if st["armed"] and not st["fired"]:
            st["fired"] = True
            st["thread"] = _thr.Thread(target=_post, daemon=True)
            st["thread"].start()
            st["waited"] = not _done.wait(2.0)    # True: still waiting after two seconds
        return found

    def _finish():
        if st["thread"] is not None:
            _done.wait(30)

    st.update(hash=_hash, exists=_exists, finish=_finish)
    return st


def _check_lock_held(st):
    """What _lock_probe's third POST did while the operator's POST held the lock."""
    _resp = st["resp"]
    check("lock: (control) a third admin POST was started while the first sat between its re-check "
          "and its commit", st["fired"] and st["thread"] is not None, repr(st["fired"]))
    check("lock: ...and it waited at _ADMIN_CREATE_LOCK until the first had committed",
          st["waited"] is True, "it %s inside the two seconds"
          % ("finished" if st["waited"] is False else "never ran"))
    check("lock: ...then found the admin and created nothing (sent to sign in)",
          _resp is not None and _resp.status_code in (301, 302, 303)
          and "/login" in (_resp.headers.get("Location") or "") and "third" not in superadmins(),
          "%s %s" % (_resp and _resp.status_code, superadmins()))


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
    _lock = _lock_probe(_real_hash)

    def _racing_hash(pw):
        if not _race_fired:
            _race_fired.append(1)
            c.post("/setup", data={"step": "admin_user", "username": "firstadmin",
                                   "password": _ADMIN_PASSWORD,
                                   "confirm_password": _ADMIN_PASSWORD,
                                   "email": "admin@example.com"})
            return _real_hash(pw)
        return _lock["hash"](pw)
    _rh.hash_password = _racing_hash
    _rh._superadmin_exists = _lock["exists"]
    try:
        _racer.post("/setup", data={"step": "admin_user", "username": "racer",
                                    "password": _ADMIN_PASSWORD, "confirm_password": _ADMIN_PASSWORD})
    finally:
        _rh.hash_password = _real_hash
        _rh._superadmin_exists = _lock["real_exists"]
        _lock["finish"]()
    check("race: (control) the operator's POST really ran inside the racer's password hash",
          _race_fired == [1], repr(_race_fired))
    check("race: two admin_user POSTs interleaved create exactly ONE superadmin",
          superadmins() == ["firstadmin"], str(superadmins()))
    _check_lock_held(_lock)
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
        _wb_id = _wb.id if _wb is not None else None
    # Filed under the host's id (remote=), which is what lets its delegated viewers read it; the
    # refused adds above wrote nothing.
    check("audit: the host the wizard added is one row, about that host",
          [(r[0], r[1], r[2], r[4]) for r in _audit("add_remote")]
          == [("setup wizard", "Wizard box", "root@192.0.2.44", _wb_id)] and _wb_id is not None,
          repr(_audit("add_remote")))


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
    check("audit: finishing setup is on record, by the setup wizard",
          [r[:2] + r[3:4] for r in _audit("setup_finished")]
          == [("setup wizard", "Panel Server", True)], repr(_audit("setup_finished")))
    # The Serve step already published the panel, so the finish publishes nothing more. It used to
    # publish it AGAIN — it read the step's own "/" route as another app's, and added /lgsm beside
    # it — and this check pinned that second write ("...and so is the Serve it set up on the way
    # out"). part32 drives both paths against a fake tailscale CLI.
    _serve_end = [r for r in _audit("setup_tailscale_serve") if r[2].startswith("at the end")]
    check("audit: ...and the finish publishes no second Serve route once the Serve step has",
          _serve_end == [] and _ts_calls.count("serve") == 1,
          repr((_audit("setup_tailscale_serve"), _ts_calls)))


def _check_restart_now():
    """The complete page's Restart now: the owner's alone, and only when there is a bind to apply."""
    # "Restart now" is the owner's explicit choice, and nobody else's.
    rr = _att.post("/setup/restart")
    check("complete: another browser cannot restart the panel", _restarts == [],
          "%d %r" % (rr.status_code, _restarts))
    rr = c.post("/setup/restart")
    check("complete: the owner's Restart now restarts the panel once",
          _restarts == [1] and rr.status_code == 200, "%d %r" % (rr.status_code, _restarts))
    check("audit: the owner's restart is one row, with the bind it applies; the refused one none",
          [(r[0], r[3]) for r in _audit("panel_restart")] == [("setup wizard", True)]
          and "127.0.0.1" in _audit("panel_restart")[0][2], repr(_audit("panel_restart")))
    # Once the running bind is the stored one there is nothing to apply, so no restart...
    app.config["_BOOT_BIND"] = "127.0.0.1"
    c.post("/setup/restart")
    check("complete: with nothing to apply, Restart now does nothing", _restarts == [1],
          repr(_restarts))
    check("audit: ...and writes no row", len(_audit("panel_restart")) == 1,
          repr(_audit("panel_restart")))
    # ...and the private claim is back, because it is true now (positive control). This is the
    # panel after its restart: on loopback it serves plain HTTP (BOOT_TLS False), and the boot
    # re-point has moved the Serve route to http, which is what the page names.
    app.config["BOOT_TLS"] = False
    _cfg_now = load_config()
    _ts_publish(port=_cfg_now.get("port", 5000), mount=_cfg_now.get("tailscale_mount") or "/",
                backend_scheme="http")
    with app.test_request_context("/setup"):
        _cp = getattr(_rh, "_complete_page", None)
        _priv_html = _cp(load_config()) if _cp else ""
    check("complete: on a loopback bind the page does say the tailnet URL is private",
          "Private tailnet" in _priv_html and 'id="rebind-notice"' not in _priv_html,
          _priv_html[-400:])
    check("complete: ...and names the panel's own Serve address, with its mount",
          'href="https://panel.example-tail.ts.net"' in _priv_html, _priv_html[-400:])
    app.config.pop("_BOOT_BIND", None)
    app.config.pop("BOOT_TLS", None)


def _check_auto_serve_failure():
    """A Serve that fails at the end of setup is on record as failed, and not stored as done."""
    # Its result was dropped: tailscale_setup_done went True whatever Serve answered, and that flag
    # is what tells the firewall page the panel is reachable over the tailnet, so the public web
    # port's rule stopped being protected on a host where Serve never took.
    _cfg = dict(load_config(), tailscale_setup_done=False, tailscale_mount="/keep")
    _on_disk = load_config()
    _recorder = _ts_mod.setup_tailscale_serve
    _ts_mod.setup_tailscale_serve = lambda *a, **k: (False, "serve refused")
    try:
        with app.test_request_context("/setup"):
            _rh._auto_tailscale_serve(_cfg)
    finally:
        _ts_mod.setup_tailscale_serve = _recorder
    check("auto-serve: a Serve that failed is not recorded as set up",
          _cfg.get("tailscale_setup_done") is False and _cfg.get("tailscale_mount") == "/keep"
          and load_config() == _on_disk, repr((_cfg.get("tailscale_setup_done"),
                                               _cfg.get("tailscale_mount"))))
    _last = (_audit("setup_tailscale_serve") or [("", "", "", None, None)])[-1]
    check("auto-serve: ...and its row says it failed, and why",
          _last[3] is False and "serve refused" in _last[2], repr(_last))


def _check_setup_rows_by_account():
    """Restart now writes its row before the restart is armed; a signed-in superadmin is named."""
    # restart_panel arms a detached two-second timer that stops the unit, and a row queued behind a
    # SQLite lock for longer than that died with the process: remote_security's binding change
    # writes its row BEFORE the restart for that reason, and Restart now wrote its row after. So the
    # stub below counts the rows already there when it is called, and refuses, as systemd-run can.
    # And once the admin exists a signed-in superadmin may drive the wizard (_rec here), yet every
    # row said "setup wizard" with no account: a restart, or a host added with root SSH, on record
    # as nobody's.
    app.config["_BOOT_BIND"] = "0.0.0.0"  # nosec B104 - the bind this process "started" on
    _n_before = len(_audit("panel_restart"))
    _at_call, _recorder = [], _so_mod.restart_panel

    def _refusing_restart(*a, **k):
        _at_call.append(len(_audit("panel_restart")))
        return False, "systemd-run: refused"
    _so_mod.restart_panel = _refusing_restart
    try:
        _rec.post("/setup/restart")
    finally:
        _so_mod.restart_panel = _recorder
        app.config.pop("_BOOT_BIND", None)
    with app.app_context():
        _admin_id = User.query.filter_by(username="firstadmin").one().id
        _rows = [(a.username, a.user_id, a.success, a.detail) for a in
                 AuditLog.query.filter_by(action="panel_restart").order_by(AuditLog.id).all()]
    _rows = _rows[_n_before:]
    check("audit: Restart now's row is written BEFORE the restart is armed, which can stop the "
          "process before a later write lands", _at_call == [_n_before + 1],
          "rows when restart_panel ran: %r (before: %d)" % (_at_call, _n_before))
    check("audit: ...and a restart that could not be scheduled is a row of its own, saying why",
          [r[2] for r in _rows] == [True, False] and "systemd-run: refused" in _rows[-1][3],
          repr(_rows))
    check("audit: a signed-in superadmin's rows name that account, not 'setup wizard'",
          {r[:2] for r in _rows} == {("firstadmin", _admin_id)}, repr(_rows))


def _check_setup_rows_one_writer():
    """Every row the wizard writes goes through _setup_log, so no step can write one by nobody."""
    # A log_action call anywhere else in route_helpers.py is one that can.
    import ast as _ast
    import inspect as _inspect
    _others = [f for f in _ast.parse(_inspect.getsource(_rh)).body
               if getattr(f, "name", None) != "_setup_log"]
    _outside = [n.lineno for f in _others for n in _ast.walk(f)
                if getattr(getattr(n, "func", None), "id", None) == "log_action"]
    check("audit: every row the wizard writes goes through _setup_log, which names the account",
          _outside == [] and hasattr(_rh, "_setup_log"),
          "log_action called directly at route_helpers.py lines %r" % (_outside,))


def _check_claim_follows_current_token():
    """A claim holds only for the token on disk NOW: replacing or deleting the token revokes it.

    The operator's way to shut out a token that leaked (pasted install output, a shared screen) is
    to delete data/setup_token and print a new one. _setup_claimed compares the session's claim
    with the CURRENT file for exactly that reason; a claim kept as a bare flag would survive it,
    and nothing held that: `return bool(claim)` there passed the whole suite.
    """
    import secrets as _secrets
    _held = app.test_client()
    _held.get("/setup?token=" + _TOKEN)
    _was = _held.get("/setup")
    _claimed = _was.status_code == 200 and b'name="step"' in _was.data
    _saved = _TOKEN_FILE.read_text(encoding="ascii")
    try:
        _TOKEN_FILE.write_text(_secrets.token_urlsafe(24) + "\n", encoding="ascii")   # rotated
        _rot = _held.get("/setup")
        _held.post("/setup", data={"step": "welcome", "site_title": "Stale claim", "port": "5097",
                                   "bind_host": "0.0.0.0"})  # nosec B104 - a hostile input
        _TOKEN_FILE.unlink()                                                     # deleted
        _gone = _held.get("/setup")
    finally:
        _TOKEN_FILE.write_text(_saved, encoding="ascii")
    check("token: (control) the browser below had claimed the wizard", _claimed,
          "got %d" % _was.status_code)
    check("token: a claim made with a token that has since been replaced opens nothing",
          _rot.status_code == 200 and _is_token_page(_rot) and load_config().get("port") != 5097,
          "%d %s" % (_rot.status_code, load_config().get("port")))
    check("token: ...nor once the token file is deleted",
          _is_token_page(_gone), "got %d" % _gone.status_code)
    _back = _held.get("/setup")
    check("token: ...and the same claim works again once that token is back (control)",
          _back.status_code == 200 and b'name="step"' in _back.data, "got %d" % _back.status_code)


class _NoStartThread:
    """A Thread for a second create_app(): records nothing and starts nothing.

    The boot path is run once more near the end to see what it does to the token file. Its
    supervised workers (pollers, sweepers) are the first boot's business, and a second copy of each
    running against this database for the rest of the run would be a leak, not a test.
    """

    def __init__(self, target=None, **_kw):
        self.target = target

    def start(self):
        """Never run the target."""

    def join(self, timeout=None):
        """Nothing was started."""

    def is_alive(self):
        """Nothing was started."""
        return False


def _boot_again():
    """Run the panel's real start-up path (create_app) once more, with no worker started."""
    import threading as _thr
    import types as _types
    _app_mod_boot = sys.modules["app"]   # imported above by `from app import`; the module itself
    _saved_thr = _app_mod_boot.threading
    _app_mod_boot.threading = _types.SimpleNamespace(
        Thread=_NoStartThread, Lock=_thr.Lock, RLock=_thr.RLock, Event=_thr.Event,
        local=_thr.local, current_thread=_thr.current_thread, enumerate=_thr.enumerate)
    try:
        _app2 = _app_mod_boot.create_app()
    finally:
        _app_mod_boot.threading = _saved_thr
    with _app2.app_context():
        db.engine.dispose()     # its engine's connection, not the suite's
    return _app2


try:
    _check_unclaimed_wizard()
    _check_unclaimed_tailscale()
    _check_claim()
    _check_claim_follows_current_token()

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
    # The wizard's rows. It wrote none: the bind it set, the first superadmin, a host it added and
    # a restart were on record nowhere. Exactly one row, so the refused step=welcome POSTs above
    # (unclaimed, wrong token) are shown to have written none.
    check("audit: step=welcome is on record, by the setup wizard, with the bind it saved",
          [r[:4] for r in _audit("setup_site_settings")]
          == [("setup wizard", "Panel Server", "bind 127.0.0.1, port 5051", True)],
          repr(_audit("setup_site_settings")))

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
    # Read HERE, straight after the refusals. It used to be read after the next good post had saved
    # "Test Panel" again, so it held whatever the refused posts did.
    check("open: a refused bind address leaves the rest of step 1 unsaved too",
          load_config().get("site_title") == "Test Panel", load_config().get("site_title"))
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
    c.post("/setup", data={"step": "remote_server", "action": "skip"})
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
    check("audit: the first superadmin's creation is one row naming it, the racer's none",
          [r[:2] for r in _audit("add_user")] == [("setup wizard", "firstadmin")],
          repr(_audit("add_user")))

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
    _check_restart_now()
    _check_auto_serve_failure()
    _check_setup_rows_by_account()
    _check_setup_rows_one_writer()

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
    # ...and the start-up path itself does it. The check above calls the helper directly, so
    # `pass` in place of create_app's call to it passed the whole suite. Run the real boot.
    _TOKEN_FILE.write_text(_TOKEN, encoding="ascii")
    _present = _TOKEN_FILE.exists()
    _boot_again()
    check("locked: the panel's real start-up (create_app) deletes a leftover setup token",
          _present and not _TOKEN_FILE.exists(),
          "still on disk after create_app()" if _present else "the token was never written")

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

except BaseException:
    # BaseException, not Exception: the finally below ends in sys.exit(), which REPLACES an
    # exception still in flight. An eventlet Timeout (a BaseException) raised mid-suite
    # therefore ended the run early with "N / N checks passed" and exit 0. Recorded here,
    # it is a failure with its traceback, like any other crash.
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
