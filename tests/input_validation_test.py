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

SAFETY: refuses to run when a real database exists, and removes what it created. Like the smoke
suite, it needs no network — the fixture host is unreachable by design and every assertion here is
about what the ROUTE did before anything reached it.

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
    for bad in _BAD_PORTS:
        before = servers_count()
        r = c.post("/servers/add", data={"remote_id": str(remote_id), "game_type": "cod",
                                         "server_name": "", "port": bad},
                   follow_redirects=False)
        label = repr(bad)[:22]
        check("/servers/add port=%s does not 5xx" % label, r.status_code < 500,
              "got %d" % r.status_code)
        check("/servers/add port=%s writes no server row" % label, servers_count() == before,
              "row count went %d -> %d" % (before, servers_count()))

    # Positive control: a valid port IS accepted and IS what gets stored. Without this the block
    # above would pass against a route that refuses everything.
    before = servers_count()
    r = c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "ivgood", "port": "28960"},
               follow_redirects=False)
    check("/servers/add accepts a valid port (positive control)", servers_count() == before + 1,
          "row count went %d -> %d, status %d" % (before, servers_count(), r.status_code))
    with app.app_context():
        _gs = GameServer.query.filter_by(short_name="ivgood").first()
        check("/servers/add stores the port it was given", _gs is not None and _gs.port == 28960,
              "stored %s" % (getattr(_gs, "port", None),))

    # int() accepts these and they name a real port, so they must still work.
    for ok_val in _ODD_BUT_VALID:
        before = servers_count()
        c.post("/servers/add", data={"remote_id": str(local_id), "game_type": "cod",
                                     "server_name": "", "port": ok_val}, follow_redirects=False)
        check("/servers/add accepts %r (int() does)" % ok_val, servers_count() == before + 1,
              "row count went %d -> %d" % (before, servers_count()))

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
    for bad in _BAD_PORTS:
        before = remotes_count()
        r = c.post("/remotes/add", data={"name": "iv-bad", "host": "192.0.2.11",
                                         "ssh_user": "root", "ssh_port": bad,
                                         "auth_method": "key", "credential": ""},
                   follow_redirects=False)
        label = repr(bad)[:22]
        check("/remotes/add ssh_port=%s does not 5xx" % label, r.status_code < 500,
              "got %d" % r.status_code)
        check("/remotes/add ssh_port=%s writes no host row" % label, remotes_count() == before,
              "row count went %d -> %d" % (before, remotes_count()))

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
    for bad in ("0", "-1", "65536", "abc", ""):
        r = c.get("/api/free-port?remote_id=%d&game=cod&desired=%s" % (remote_id, bad))
        check("free-port desired=%r suggests nothing" % bad,
              r.status_code == 200 and (r.get_json() or {}).get("port") is None,
              "got %d %s" % (r.status_code, r.get_data(as_text=True)[:60]))
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
    r = c.post("/api/tailscale/serve", json={"action": "enable", "mount": "/lgsm"})
    check("tailscale serve: a valid mount is not rejected as invalid (positive control)",
          r.status_code != 400
          and "mount point" not in ((r.get_json() or {}).get("message") or "").lower(),
          "got %d %s" % (r.status_code, r.get_data(as_text=True)[:100]))

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
    cleanup()

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
