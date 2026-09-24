"""Hostile-value tests: every numeric form field, driven with the values a browser never sends.

WHY THIS SUITE EXISTS, AND WHAT IT IS NOT A DUPLICATE OF.
    The suites around it assert SHAPE. url_map_test proves every route still has its endpoint,
    methods and guard chain; rbac_test proves the guards are structurally present; perf_budget
    proves no page's query count scales with the server count. All three are good at catching a
    regression in something that already works.

    None of them ever sends a handler a BAD VALUE. That is not a small gap: the install route
    took `int(port)` straight from a form with no bounds at all, so a port of 0, -5 or 99999 was
    stored on the row, opened in the firewall and written into a LinuxGSM config — while three
    OTHER port fields in the same codebase each had their own inline range check, two of them with
    their own test. The rule was known. The endpoint that actually writes a server row was the one
    nobody drove with a bad value, because driving handlers with bad values was not something any
    suite did.

    So this one does exactly that, and it is table-driven: a new numeric field costs one line.

EVERY CASE HAS A POSITIVE CONTROL. A validation test that only asserts refusal passes just as well
against an endpoint that is broken outright and refuses everything — so each field is also driven
with a GOOD value, and the good value must be accepted and stored. Refusing bad input is only
interesting if accepting good input still works.

SAFETY: refuses to run when a real database exists, and removes what it created. The fixture's
remote host is unreachable by design. The positive controls run against a LOCAL host record, so
they do reach this machine — but only for read-only probes (its listening ports, `id <name>`). The
install job an accepted /servers/add starts, and the Tailscale Serve change an accepted mount
makes, are captured and never run: both used to run for real on whatever machine ran the suite.

    python tests/input_validation_test.py     # exits 0 if all checks pass, 1 otherwise
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panel.core.config import DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE

if DB_PATH.exists():
    print("SKIP: %s already exists — this suite only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

# panel.db.backup is in here, and it is the one that matters. It is not scratch: models.
# _ensure_db_healthy keeps it as the rolling KNOWN-GOOD copy and restores from it when the live
# database is corrupt. The cleanup below unlinks it, and "not in _PREEXISTING" was the only thing
# standing between a developer's data and that unlink — so it was deleted every run.
#
# The window is narrow and it is exactly the wrong one: these harnesses refuse to run at all while
# panel.db EXISTS, so the only state in which they run and the backup is present is "the live
# database is missing and this copy is the last one left". The WAL/SHM pair is here for the same
# reason — they hold committed pages the main file may not have yet.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE,
                            DB_PATH.with_name("panel.db.backup"),
                            DB_PATH.with_name("panel.db-wal"),
                            DB_PATH.with_name("panel.db-shm")) if p.exists()}
# A config that was already there is RESTORED BYTE-FOR-BYTE at the end, not just left in place.
# This suite has to edit config.json to boot the app (setup_complete, ssh_timeout), and on a
# developer's tree that file is theirs. Deleting it only when we created it is not enough — the
# edits stay behind otherwise, and the next suite reads them as the real configuration. That is
# not hypothetical: leaving ssh_timeout=1 behind makes the unit suite's "no override -> the
# documented default" check fail, in a different suite, for no visible reason.
_CONFIG_SNAPSHOT = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

from panel.core.config import load_config, save_config
_cfg = load_config()
_cfg["setup_complete"] = True
_cfg["ssh_timeout"] = 1          # the fixture host is unreachable BY DESIGN — see smoke_test
save_config(_cfg)

# The install route validates game_type against LinuxGSM's serverlist, which is fetched at runtime.
# Seed the cache so a rejected port is rejected for being a port, not for an unknown game.
from panel.services import lgsm_data as _lgsm_data
import pathlib as _pl
import tempfile as _tf
_lgsm_data._CACHE_DIR = _pl.Path(_tf.mkdtemp())
(_lgsm_data._CACHE_DIR / _lgsm_data.SERVERLIST).write_text(
    "shortname,gameservername,gamename,os\n"
    "cod,codserver,Call of Duty,ubuntu-24.04\n"
    "gmod,gmodserver,Garry's Mod,ubuntu-24.04\n", encoding="utf-8")
(_lgsm_data._CACHE_DIR / _lgsm_data.DEPS).write_text("all,bc,curl\n", encoding="utf-8")
_lgsm_data._mem.clear()

from app import create_app
from panel.db.models import db, User, RemoteServer, GameServer, SetupState
from panel.security import auth

app = create_app()
app.config["WTF_CSRF_ENABLED"] = False
app.config["SESSION_PROTECTION"] = None
app.config["SESSION_COOKIE_SECURE"] = False
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
    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass
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


# The values a port field must never accept. Not a random fuzz list — each one is a real shape:
#   "0"/"65536"/"-1"/"99999"  the boundaries and just past them (0 is not bindable; 65536 does not
#                             exist). These are what int() accepts happily and a range check does not.
#   ""/" "/"abc"              a blank or non-numeric field, which int() raises on
#   "27015.5"/"1e4"/"0x69"    numeric-LOOKING strings int() still refuses — they must not 500
#   "+27015"                  int() ACCEPTS this one; it must be treated as the port it names
#   "9"*40                    a value far past any integer column, to prove nothing overflows
#   "27015\n80"               a newline, because ports are interpolated into config files
_BAD_PORTS = ["0", "-1", "65536", "99999", "abc", "", " ", "27015.5", "1e4", "0x69",
              "9" * 40, "27015\n80", "27015; id", "١٢٣"]
# int() accepts these and they name a port in range, so they are NOT failures — listed separately
# so a change that starts rejecting them is visible rather than silent.
_ODD_BUT_VALID = ["+2302", " 2302 "]

# ── nothing here may INSTALL a game server on the machine running the suite ─────────────────────
# Every accepted /servers/add commits a row and starts the install job's worker thread. The
# positive controls post to the LOCAL host, and nothing was stubbed past the port allocator — so
# each one ran the real job here: useradd, fetch and run linuxgsm.sh as the new account, apt-get as
# root, auto-install. Five accounts per run on every CI runner; and on a host that already runs a
# LinuxGSM `codserver` (the default name of the auto-named controls), the installer ran inside the
# live server's home. The worker is captured here instead, and never started. Its target is the only
# thing that identifies it (a bare `threading.Thread(target=_run)`), so the check below asserts one
# was captured per row — a job that stops going through this seam fails that, not silently.
import threading as _iv_thr  # noqa: E402
import panel.routes.manage_servers as _ms_mod  # noqa: E402
_iv_workers = []


class _IvCapturedThread:
    def __init__(self, target=None, **kw):
        self.target = target
        _iv_workers.append(self)

    def start(self):
        """Captured: never run."""


class _IvThreadingShim:
    Thread = _IvCapturedThread

    def __getattr__(self, name):
        return getattr(_iv_thr, name)


_iv_o_threading = _ms_mod.threading
_ms_mod.threading = _IvThreadingShim()
# Saved here so the outer finally can put it back whatever happens (see the Tailscale block).
from panel.ops import tailscale_integration as _ts_mod  # noqa: E402
_o_ts_setup = _ts_mod.setup_tailscale_serve

try:
    with app.app_context():
        db.session.add(SetupState(step="complete", complete=True))
        admin = User(username="iv_admin", password_hash=auth.hash_password("Str0ng!passw0rd"),
                     display_name="IV Admin", is_superadmin=True, is_active=True)
        db.session.add(admin)
        remote = RemoteServer(name="iv-host", host="192.0.2.10", port=22, username="root",
                              auth_method="key", auth_credential="", is_local=False)
        # A LOCAL host too. Every port decision reads the host's listening ports, which for a
        # remote is an SSH round trip this suite deliberately cannot make (192.0.2.0/24 is
        # TEST-NET-1 and egress is refused). The positive controls — the half that proves the
        # route still ACCEPTS good input — therefore run against the panel's own machine, where
        # the scan is a local command and no network is involved.
        local = RemoteServer(name="iv-local", host="127.0.0.1", port=22, username="root",
                             auth_method="local", auth_credential="", is_local=True)
        db.session.add_all([remote, local])
        db.session.commit()
        admin_id, remote_id, local_id = admin.id, remote.id, local.id

    c = client_as(admin_id)

    def servers_count():
        with app.app_context():
            return GameServer.query.count()

    def remotes_count():
        with app.app_context():
            return RemoteServer.query.count()

    def stored_remote_port():
        with app.app_context():
            return db.session.get(RemoteServer, remote_id).port

    # ── /servers/add — the endpoint that had no bounds at all ────────────────────────────────
    # A refusal here must leave NO row. That is the assertion that matters: the route used to
    # commit the GameServer first and only fail later, on the host, as the game's own error.
    #
    # Driven at the LOCAL host with the port allocator and the account probe stubbed to succeed,
    # each with its own name, so the range check is the only thing left that can refuse. This
    # posted to the unreachable host, which refuses every add by itself ("on an unreachable host
    # writes no server row" below, with a VALID port): the loop passed with the range check
    # deleted. A blank port is not in it — on this form blank means "the game's default port".
    import panel.routes.manage_servers as _ms_mod
    _o_rfp_bad, _o_has_bad = _ms_mod.resolve_free_port, _ms_mod.host_account_state
    try:
        _ms_mod.resolve_free_port = lambda remote, remote_id, desired, game_type: (desired, False)
        _ms_mod.host_account_state = lambda remote, n: "absent"
        for _bad_i, bad in enumerate(b for b in _BAD_PORTS if b.strip()):
            before = servers_count()
            r = c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                             "server_name": "ivbad%d" % _bad_i, "port": bad},
                       follow_redirects=False)
            label = repr(bad)[:22]
            check("/servers/add port=%s does not 5xx" % label, r.status_code < 500,
                  "got %d" % r.status_code)
            check("/servers/add port=%s writes no server row" % label, servers_count() == before,
                  "row count went %d -> %d" % (before, servers_count()))
    finally:
        _ms_mod.resolve_free_port, _ms_mod.host_account_state = _o_rfp_bad, _o_has_bad

    # Positive control: a valid port IS accepted and IS what gets stored. Without this the block
    # above would pass against a route that refuses everything.
    #
    # resolve_free_port is stubbed, because it SCANS THE HOST'S LISTENING PORTS. Unstubbed, this
    # check asserts a property of the machine rather than of the route: it passed on a dev box with
    # nothing on 28960 and failed on the test VPS, which runs a real CoD server there — the route
    # correctly reassigned to 28961 and the check called that a bug. The route's contract is
    # "stores what it was given WHEN THAT PORT IS FREE", so the allocator has to be the free one.
    import panel.routes.manage_servers as _ms_mod
    _o_rfp = _ms_mod.resolve_free_port
    before = servers_count()
    try:
        _ms_mod.resolve_free_port = lambda remote, remote_id, desired, game_type: (desired, False)
        r = c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                         "server_name": "ivgood", "port": "28960"},
                   follow_redirects=False)
        check("/servers/add accepts a valid port (positive control)",
              servers_count() == before + 1,
              "row count went %d -> %d, status %d" % (before, servers_count(), r.status_code))
        with app.app_context():
            _gs = GameServer.query.filter_by(short_name="ivgood").first()
            check("/servers/add stores the port it was given",
                  _gs is not None and _gs.port == 28960,
                  "stored %s" % (getattr(_gs, "port", None),))

        # ...and the OTHER half of the contract, which nothing asserted: a TAKEN port is
        # reassigned rather than stored. That is what the host-dependent version was accidentally
        # observing on the VPS, so pin it deliberately instead.
        _ms_mod.resolve_free_port = lambda remote, remote_id, desired, game_type: (desired + 1, True)
        c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "ivtaken", "port": "28960"},
               follow_redirects=False)
        with app.app_context():
            _gs2 = GameServer.query.filter_by(short_name="ivtaken").first()
            check("/servers/add stores the REASSIGNED port when the one asked for is taken",
                  _gs2 is not None and _gs2.port == 28961,
                  "stored %s" % (getattr(_gs2, "port", None),))
    finally:
        _ms_mod.resolve_free_port = _o_rfp

    # ── a server name that is ALREADY an account on the host ─────────────────────────────────
    # The name becomes the Linux account the install creates and acts as. INSTANCE_NAME_RE is a
    # username grammar, not an ownership check, so "root" or "ubuntu" passed it; the job then
    # deleted such an account as a "half-finished leftover" (userdel -r, rm -rf of the home) and
    # bound the row to it. The route now asks the HOST first. "root" exists on every host, so this
    # needs no stub: the real probe runs on the local transport.
    before = servers_count()
    r = c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "root", "port": "28960"},
               follow_redirects=False)
    check("/servers/add refuses a name that is already an account on the host (root)",
          servers_count() == before and r.status_code < 500,
          "row count went %d -> %d, status %d" % (before, servers_count(), r.status_code))
    # A typed name the host has no account for still installs: the ivgood/ivtaken rows above are
    # the positive control. The DEFAULT name skips past an existing account instead of refusing,
    # the courtesy it already gets for a panel row of the same name.
    _o_has = _ms_mod.host_account_state
    _o_rfp2 = _ms_mod.resolve_free_port
    try:
        _ms_mod.resolve_free_port = lambda remote, remote_id, desired, game_type: (desired, False)
        _ms_mod.host_account_state = lambda remote, n: ("exists" if n in ("gmodserver", "gmodserver2")
                                                        else "absent")
        c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "gmod",
                                     "server_name": "", "port": "27015"},
               follow_redirects=False)
        with app.app_context():
            _gm_rows = sorted(g.short_name for g in GameServer.query.filter_by(game_type="gmod").all())
        check("/servers/add's default name skips accounts the host already has",
              _gm_rows == ["gmodserver3"], "gmod rows: %r" % (_gm_rows,))
        # ...and a host that does not answer is refused, not read as "no such account".
        _ms_mod.host_account_state = lambda remote, n: None
        before = servers_count()
        c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "ivnoanswer", "port": "28960"},
               follow_redirects=False)
        check("/servers/add refuses when the host cannot say whether the account exists",
              servers_count() == before, "row count went %d -> %d" % (before, servers_count()))
    finally:
        _ms_mod.host_account_state = _o_has
        _ms_mod.resolve_free_port = _o_rfp2

    # int() accepts these and they name a real port, so they must still work.
    # Typed throwaway names: an auto-named row is `codserver`, a real account on a host that runs
    # CoD, which is where this suite gets run.
    for _odd_i, ok_val in enumerate(_ODD_BUT_VALID):
        before = servers_count()
        c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "ivodd%d" % _odd_i, "port": ok_val},
               follow_redirects=False)
        check("/servers/add accepts %r (int() does)" % ok_val, servers_count() == before + 1,
              "row count went %d -> %d" % (before, servers_count()))

    with app.app_context():
        _iv_local_rows = GameServer.query.filter_by(remote_id=local_id).count()
    check("/servers/add on this machine: every install job was captured, none ran",
          _iv_local_rows >= 1 and len(_iv_workers) == _iv_local_rows
          and all(getattr(w.target, "__qualname__", "").endswith("._run") for w in _iv_workers),
          "%d local rows, %d install workers captured" % (_iv_local_rows, len(_iv_workers)))

    # An unreachable host is a NORMAL condition for this panel, not a fault in it. Picking a free
    # port scans the host over SSH, so this route raised straight through as a 500 — the exact
    # shape _unreachable() was written for, on a form endpoint that needed the form version of it.
    before = servers_count()
    r = c.post("/servers/add", data={"remote_id": str(remote_id), "game_type": "cod",
                                     "server_name": "ivdown", "port": "28960"},
               follow_redirects=False)
    check("/servers/add on an unreachable host does not 5xx", r.status_code < 500,
          "got %d" % r.status_code)
    check("/servers/add on an unreachable host writes no server row", servers_count() == before,
          "row count went %d -> %d" % (before, servers_count()))

    # ── /remotes/add and /remotes/<id>/edit — the SSH port ───────────────────────────────────
    # The connection test is stubbed SUCCESSFUL, as the auth_method block below does and for its
    # reason: left real, the unreachable 192.0.2.11 refused every add on its own, and this loop
    # passed with the port's range check deleted. The positive control is "accepts
    # auth_method=key" below — the same POST with the same stub, a valid port, and a new row.
    import panel.routes.remotes as _rr
    _saved_test_bad = _rr.ssh_test_connection
    try:
        _rr.ssh_test_connection = lambda *a, **k: (True, "stubbed OK")
        for _bad_i, bad in enumerate(_BAD_PORTS):
            before = remotes_count()
            r = c.post("/remotes/add", data={"name": "iv-bad-%d" % _bad_i, "host": "192.0.2.11",
                                             "ssh_user": "root", "ssh_port": bad,
                                             "auth_method": "key", "credential": "",
                                             "setup_type": "existing"},
                       follow_redirects=False)
            label = repr(bad)[:22]
            check("/remotes/add ssh_port=%s does not 5xx" % label, r.status_code < 500,
                  "got %d" % r.status_code)
            check("/remotes/add ssh_port=%s writes no host row" % label, remotes_count() == before,
                  "row count went %d -> %d" % (before, remotes_count()))
    finally:
        _rr.ssh_test_connection = _saved_test_bad

    for bad in _BAD_PORTS:
        r = c.post("/remotes/%d/edit" % remote_id,
                   data={"name": "iv-host", "host": "192.0.2.10", "ssh_user": "root",
                         "ssh_port": bad, "auth_method": "key"}, follow_redirects=False)
        label = repr(bad)[:22]
        check("/remotes/edit ssh_port=%s does not 5xx" % label, r.status_code < 500,
              "got %d" % r.status_code)
        check("/remotes/edit ssh_port=%s leaves the stored port alone" % label,
              stored_remote_port() == 22, "stored port is now %s" % stored_remote_port())

    r = c.post("/remotes/%d/edit" % remote_id,
               data={"name": "iv-host", "host": "192.0.2.10", "ssh_user": "root",
                     "ssh_port": "2222", "auth_method": "key"}, follow_redirects=False)
    check("/remotes/edit accepts a valid ssh_port (positive control)", stored_remote_port() == 2222,
          "stored port is %s" % stored_remote_port())

    # ── /remotes/<id>/edit — auth_method PICKS THE TRANSPORT ─────────────────────────────────
    # Every other field on this form was validated; this one was stored raw. It is not a label:
    # _core.is_local_server() answers True for auth_method == "local", so that one value moves
    # every command the panel runs "on that host" onto the PANEL HOST — the machine holding the
    # database, the credential key and the panel's own sudoers grant. The form's select offers
    # exactly key/password/tailscale (templates/manage_remotes.html), so anything else is forged.
    def stored_remote_auth():
        with app.app_context():
            return db.session.get(RemoteServer, remote_id).auth_method

    def stored_remote_fields():
        with app.app_context():
            _r = db.session.get(RemoteServer, remote_id)
            return _r.name, _r.host, _r.username

    for bad in ("local", "LOCAL", "banana", "", "key\nlocal"):
        r = c.post("/remotes/%d/edit" % remote_id,
                   data={"name": "iv-host", "host": "192.0.2.10", "ssh_user": "root",
                         "ssh_port": "2222", "auth_method": bad}, follow_redirects=False)
        label = repr(bad)[:22]
        check("/remotes/edit auth_method=%s does not 5xx" % label, r.status_code < 500,
              "got %d" % r.status_code)
        check("/remotes/edit auth_method=%s never becomes local execution" % label,
              stored_remote_auth() == "key", "stored auth_method is now %r" % stored_remote_auth())
    for good in ("password", "tailscale", "key"):
        c.post("/remotes/%d/edit" % remote_id,
               data={"name": "iv-host", "host": "192.0.2.10", "ssh_user": "root",
                     "ssh_port": "2222", "auth_method": good}, follow_redirects=False)
        check("/remotes/edit accepts auth_method=%s (positive control)" % good,
              stored_remote_auth() == good, "stored auth_method is %r" % stored_remote_auth())

    # ...and /remotes/add refuses the same value, so the hole is closed on both sides.
    #
    # The connection test has to be stubbed SUCCESSFUL for this to mean anything. Left real, the
    # unreachable 192.0.2.x host refuses the add by itself and the check passes whether the
    # allowlist is there or not — a gate that certifies the bug. With the test passing, the only
    # thing standing between this POST and a stored auth_method="local" is the allowlist, which
    # runs before it.
    import panel.routes.remotes as _rr
    _saved_test = _rr.ssh_test_connection
    try:
        _rr.ssh_test_connection = lambda *a, **k: (True, "stubbed OK")
        before = remotes_count()
        r = c.post("/remotes/add", data={"name": "iv-local-sneak", "host": "192.0.2.12",
                                         "ssh_user": "root", "ssh_port": "22",
                                         "auth_method": "local", "credential": ""},
                   follow_redirects=False)
        check("/remotes/add auth_method=local writes no host row",
              r.status_code < 500 and remotes_count() == before,
              "status %d, rows %d -> %d" % (r.status_code, before, remotes_count()))
        # positive control: the same POST with a real method DOES add, so the check above is
        # measuring the allowlist and not a route that refuses everything.
        before = remotes_count()
        c.post("/remotes/add", data={"name": "iv-add-ok", "host": "192.0.2.13",
                                     "ssh_user": "root", "ssh_port": "22",
                                     "auth_method": "key", "credential": "",
                                     "setup_type": "existing"},
               follow_redirects=False)
        check("/remotes/add accepts auth_method=key (positive control)",
              remotes_count() == before + 1, "rows %d -> %d" % (before, remotes_count()))
    finally:
        _rr.ssh_test_connection = _saved_test

    # ── /remotes/<id>/edit — a BLANK field is not an edit ────────────────────────────────────
    # `.get(key, default)` only falls back when the key is ABSENT, and this form posts all three
    # every time, without `required` (the add form above it has it). So clearing a box and saving
    # stored "" over the real value — and the guards were all `if new_x and ...`, which an empty
    # string skips. A remote whose host is "" is unreachable and its game servers unmanageable.
    _was = stored_remote_fields()
    r = c.post("/remotes/%d/edit" % remote_id,
               data={"name": "", "host": "", "ssh_user": "", "ssh_port": "2222",
                     "auth_method": "key"}, follow_redirects=False)
    check("/remotes/edit blank fields do not 5xx", r.status_code < 500, "got %d" % r.status_code)
    check("/remotes/edit blank name/host/ssh_user leave the stored values alone",
          stored_remote_fields() == _was,
          "%r -> %r" % (_was, stored_remote_fields()))

    # ── /api/panel/change-port — JSON body, and the panel's OWN port ─────────────────────────
    # Side-effect-free for every value below: all are refused before any save or restart. A VALID
    # port is deliberately not exercised — that one restarts the panel.
    for bad in _BAD_PORTS + ["80", "443", "1023"]:      # <1024 needs root; the panel is not root
        r = c.post("/api/panel/change-port", json={"port": bad})
        label = repr(bad)[:22]
        check("change-port port=%s is refused, not 5xx" % label,
              r.status_code == 400 and not (r.get_json() or {}).get("success"),
              "got %d" % r.status_code)

    # ── /api/free-port — the read-only suggestion the install form uses ──────────────────────
    # At the LOCAL host with the allocator stubbed to hand back whatever it is asked for, so the
    # route's own range check is what answers None. Aimed at the unreachable host, the allocator
    # raised and the route's `except` answered None for every value, range check or not.
    import panel.routes.api as _api_mod
    _o_rfp_api = _api_mod.resolve_free_port
    try:
        _api_mod.resolve_free_port = lambda remote, remote_id, desired, game: (desired, False)
        for bad in ("0", "-1", "65536", "abc", ""):
            r = c.get("/api/free-port?remote_id=%d&game=cod&desired=%s" % (local_id, bad))
            check("free-port desired=%r suggests nothing" % bad,
                  r.status_code == 200 and (r.get_json() or {}).get("port") is None,
                  "got %d %s" % (r.status_code, r.get_data(as_text=True)[:60]))
        r = c.get("/api/free-port?remote_id=%d&game=cod&desired=28960" % local_id)
        check("free-port: ...while the same stubbed request with a valid port suggests it "
              "(control)", (r.get_json() or {}).get("port") == 28960,
              r.get_data(as_text=True)[:80])
    finally:
        _api_mod.resolve_free_port = _o_rfp_api
    r = c.get("/api/free-port?remote_id=%d&game=cod&desired=28960" % local_id)
    _fp = (r.get_json() or {}).get("port")
    check("free-port suggests a real port for a valid request (positive control)",
          isinstance(_fp, int) and 1 <= _fp <= 65535, "got %r" % (_fp,))

    # ── The data layer refuses what a route might not ────────────────────────────────────────
    # The route checks above are the first line; this is the one that cannot be forgotten by the
    # NEXT route to assign a port. Same reasoning as the shell-identifier validator beside it.
    with app.app_context():
        for bad in (0, -1, 65536, 99999):
            for model, field in ((GameServer, "port"), (GameServer, "query_port"),
                                 (RemoteServer, "port")):
                raised = False
                try:
                    model(**{field: bad})
                except ValueError:
                    raised = True
                check("%s.%s = %d is refused at the data layer" % (model.__name__, field, bad),
                      raised, "it was accepted")
        check("GameServer.query_port = None is still allowed (optional column)",
              GameServer(query_port=None).query_port is None)

    # ── A hostile Tailscale mount point is a refusal, not a 500 ─────────────────────────────
    # The mount is request JSON and it is strictly validated — privileged._ts_mount rebuilds it
    # character by character out of a literal alphabet, so nothing outside that set survives. But
    # it signals a bad value by RAISING (VerbError, a ValueError), and the chain from the route
    # down to it — api_tailscale_serve -> setup_tailscale_serve -> _ts_serve_args ->
    # ts_serve_argv -> _ts_mount — catches nothing. So a typo in the mount box answered 500 with
    # no message saying what was wrong, which is the shape api_tags_create already catches
    # ValueError specifically to avoid.
    #
    # Nothing is stored either way (the route only writes tailscale_mount when Serve succeeded),
    # so this is about the ANSWER, not about a bad value reaching the config.
    from panel.core.config import load_config as _tsl
    # setup_tailscale_serve is a RECORDER here. The real one makes the current user the Tailscale
    # operator, adds a UFW allow on tailscale0, and runs `tailscale serve --bg` UNPRIVILEGED first —
    # which nosudo_runner cannot refuse, since it names no sudo. So the positive control below left
    # a persistent Serve route publishing this machine's 127.0.0.1:5000 at <node>.ts.net/lgsm to
    # every tailnet peer, on every developer box where the user is the operator. The recorder
    # answers "not done" so nothing is stored, and what it received is asserted instead.
    _ts_calls = []
    _ts_mod.setup_tailscale_serve = lambda **kw: (_ts_calls.append(kw), (False, "stub: not run"))[1]
    _mount_before = _tsl().get("tailscale_mount")
    for _bad in ("../etc", "/a/../../b", "not-a-path", "/" + "x" * 40, "/a;b", "//host"):
        r = c.post("/api/tailscale/serve", json={"action": "enable", "mount": _bad})
        check("tailscale serve mount=%r is refused, not a 500" % _bad,
              r.status_code < 500,
              "got %d %s" % (r.status_code, r.get_data(as_text=True)[:80]))
        check("tailscale serve mount=%r says it was refused" % _bad,
              (r.get_json() or {}).get("success") is False,
              "body was %s" % r.get_data(as_text=True)[:80])
    check("tailscale serve: a refused mount is never stored",
          _tsl().get("tailscale_mount") == _mount_before,
          "config moved to %r" % (_tsl().get("tailscale_mount"),))
    # Positive control: a VALID mount must get PAST the validation above and reach the real work,
    # so the gate cannot pass by refusing everything.
    #
    # It asserts the REFUSAL is absent, not that the request succeeded. What happens after the
    # mount is accepted depends on the machine: with no `tailscale` binary the command fails and
    # the route answers 500 ("command not found"), which is the pre-existing behaviour of every
    # failure branch here and not what this change is about. An earlier version of this control
    # asserted `status_code < 500` and passed locally — where the no-sudo test runner fails the
    # command differently — then failed in CI on all three matrix jobs. The status was never the
    # thing being tested; the 400-with-"mount point" is.
    check("tailscale serve: a refused mount never reaches the host",
          not _ts_calls, "setup_tailscale_serve was called with %r" % (_ts_calls,))
    try:
        r = c.post("/api/tailscale/serve", json={"action": "enable", "mount": "/lgsm"})
    finally:
        _ts_mod.setup_tailscale_serve = _o_ts_setup
    check("tailscale serve: a valid mount is not rejected as invalid (positive control)",
          r.status_code != 400
          and "mount point" not in ((r.get_json() or {}).get("message") or "").lower(),
          "got %d %s" % (r.status_code, r.get_data(as_text=True)[:100]))
    check("tailscale serve: ...and it reaches Serve with that mount, recorded and not run",
          [k.get("mount") for k in _ts_calls] == ["/lgsm"], repr(_ts_calls))

    # ── Structural: a port field must go through the bounded parser ──────────────────────────
    # This is the check that generalises. _int_or guarantees "an int" and carries no range; every
    # place that took a port through it is where a bad port got in. Naming the parser is what stops
    # the next port field repeating it, so assert it rather than trusting the convention.
    import ast
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    _int_or_sites = 0
    for py in sorted((_root / "panel").rglob("*.py")) + [_root / "app.py"]:
        for node in ast.walk(ast.parse(py.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_int_or"):
                continue
            _int_or_sites += 1
            # The assignment target's name is what says whether this is a port.
            src = ast.get_source_segment(py.read_text(encoding="utf-8"), node) or ""
            if "port" in src.lower():
                offenders.append("%s:%d  %s" % (py.relative_to(_root), node.lineno, src[:70]))
    # ...and a positive control, because the scan matches a hardcoded NAME. Rename _int_or and
    # every `node.func.id == "_int_or"` stops matching: the loop runs zero times and the gate
    # reports clean. Proven by renaming it to _intOr across 13 call sites in 4 files — 142/142,
    # all passing. Counting the call sites makes the rename a failure instead.
    # >= 1, deliberately: the failure being guarded is ZERO, and a higher floor would just be a
    # number to maintain every time a call site is legitimately added or removed. (Measured at 4
    # when this was written.)
    check("the _int_or scan found call sites at all", _int_or_sites >= 1,
          "%d call sites — the check below would pass vacuously (was _int_or renamed?)"
          % _int_or_sites)
    check("no port is parsed with _int_or (the parser without a range)", not offenders,
          "; ".join(offenders))

except Exception as exc:                      # a crash in the harness is a failure, not a pass
    import traceback
    traceback.print_exc()
    results.append((False, "suite ran to completion", "%s: %s" % (type(exc).__name__, exc)))
finally:
    _ms_mod.threading = _iv_o_threading
    _ts_mod.setup_tailscale_serve = _o_ts_setup
    cleanup()

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
sys.exit(0 if results and passed == len(results) else 1)
