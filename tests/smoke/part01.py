"""Part 1 of the smoke suite: the setup every later part imports from.

It is the single-file suite's preamble, as it was: the refusal to run over a real database, the
config the app boots with, the throwaway app and its test client settings, and the helpers the
checks share (`check`, `results`, `client_as`, `cleanup`, ...). It runs OUTSIDE the runner's
try, as it did before, so a failure here is a traceback rather than a recorded check.
"""
import os
import sys

# Where the checks that locate the repository from __file__ were written: tests/smoke_test.py, the
# runner. They still resolve from it, so each such path is what it was before the suite was split,
# whichever part the check now lives in.
_SUITE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "smoke_test.py")
from panel.ops.ssh_manager import _core as _sm_core  # noqa: F401 - a later part imports it
from panel.ops.ssh_manager import cron as _sm_cron  # noqa: F401 - a later part imports it
from panel.ops.ssh_manager import game as _sm_game  # noqa: F401 - a later part imports it
from panel.ops.ssh_manager import hosts as _sm_hosts   # the stub seam: stubbed by MODULE,  # noqa: F401
# because every caller now reaches these through the module rather than binding them.

from panel.core.config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: F401  # pylint: disable=unused-import
from panel.core.validation import password_problem as auth_password_problem  # noqa: F401  # pylint: disable=unused-import

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
from panel.db.models import db, User, Group, RemoteServer, GameServer, SetupState, CustomCommand  # noqa: F401  # pylint: disable=unused-import
from panel.security import auth  # noqa: F401  # pylint: disable=unused-import
from panel.ops import backup as bk  # noqa: F401  # pylint: disable=unused-import

app = create_app()
# nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled -- the test client posts forms without a browser-issued token
app.config["WTF_CSRF_ENABLED"] = False   # test client posts without a browser-issued token
# The Funnel ban gate refreshes its set in a background thread after a failed login (where proxied
# traffic can arrive) and after Block / Unban / Whitelist. Left live, those threads outlive the
# check that started them and read whatever firewall stub a LATER check installed into the set.
# The refresh itself is driven directly, with its own stub, where it is tested.
from panel.security import banlist as _smoke_banlist
_smoke_banlist.refresh_soon = lambda *a, **k: None
# An uninstall asks the HOST whether the account it is about to `userdel` is root-capable there
# (privileged_accounts) and refuses when the host cannot answer. This suite's hosts are blackholed,
# so every uninstall would stop at "couldn't check"; the probe is answered "a plain game account"
# suite-wide, and the real one is driven — with the host's reply scripted — where it is tested.
import panel.routes.manage_servers as _smoke_ms  # noqa: E402
_smoke_priv_real = _smoke_ms.privileged_accounts
_smoke_ms.privileged_accounts = lambda _remote, _users: {}
# The file-manager and cron WRITE routes ask the same question for the rows imported before import
# asked it (_shared.game_account_write_refusal, which looks privileged_accounts up in _shared).
# Answered the same way suite-wide; the gate itself is driven below with the host's reply scripted.
import panel.routes._shared as _smoke_shared  # noqa: E402
_smoke_shared.privileged_accounts = lambda _remote, _users: {}
app.config["SESSION_PROTECTION"] = None  # tests inject the session directly (no IP/UA fingerprint)
app.config["SESSION_COOKIE_SECURE"] = False  # test client talks http://; Secure cookies wouldn't round-trip
app.config["REMEMBER_COOKIE_SECURE"] = False
results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def join_for(thread, seconds):
    """thread.join(seconds) that RETURNS when the time runs out, on every Python.

    Under eventlet on Python 3.13+ a green join that times out raises eventlet.timeout.Timeout, a
    BaseException, instead of returning: a worker that hung ended the whole suite at the join
    instead of failing the check after it by name. is_alive() and a short sleep behave the same
    patched or not, so this waits the same way everywhere.
    """
    import time as _jf_time
    deadline = _jf_time.monotonic() + seconds
    while thread.is_alive() and _jf_time.monotonic() < deadline:
        _jf_time.sleep(0.02)


# Every url_for('endpoint') referenced in a template must resolve to a real route — otherwise the
# page 500s the moment it renders. Catches a nav link / redirect pointing at a renamed or removed
# endpoint (the template-side companion to the data-action button-wiring test).
def _check_template_url_for():
    import re
    endpoints = {r.endpoint for r in app.url_map.iter_rules()}
    bad = []
    _tpls = sorted(_lgsm_pathlib.Path("templates").glob("*.html"))
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
    (unframed) read. Any other command gets the bare text, as these stubs always gave it.
    """
    def _run(*a, **k):
        cmd = a[1] if len(a) > 1 else k.get("command", "")
        if "printf B;" in cmd:
            return ("B" + text + "\nE").strip(), "", 0
        return text.strip(), "", 0
    return _run


def client_as(user_id):
    # "<id>:<current auth_epoch>", read at the moment the client is made. It was a bare "<id>" —
    # the pre-epoch legacy cookie — which auth._load_legacy_user used to accept whatever the
    # account's epoch; it now accepts one only while the epoch is still 0 (a bare id predates
    # epochs, so any bump revoked it). This suite bumps epochs along the way (sign out everywhere,
    # logout's fallback), and a bare id would then stop working for every later client_as. The
    # epoch form keeps this helper meaning what it always meant: a client signed in NOW, with no
    # per-device row. Checks that need the legacy form build it themselves.
    c = app.test_client()
    with app.app_context():
        _u = db.session.get(User, user_id)
        _login_id = "%d:%d" % (user_id, _u.auth_epoch or 0) if _u is not None else str(user_id)
    with c.session_transaction() as s:
        s["_user_id"] = _login_id
        s["_fresh"] = True
    return c


def page_with_assets(client, path):
    """The page's HTML plus the text of every non-vendor static .js/.css it pulls in.

    base.html serves its own CSS and JS as cacheable static files rather than inlining them, so a
    check that greps a page for a handler or a rule has to follow the reference. That is a STRONGER
    assertion than the old inline grep, not a weaker one: it only passes if the asset is really
    linked from this page and really served.
    """
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
            except OSError as e:
                # Said, not swallowed: a panel.db left behind makes the NEXT run of every
                # DB-owning suite print SKIP and exit 0, with nothing to say why.
                print("cleanup: could not remove %s (%s)" % (p, e), file=sys.stderr)
    if _CONFIG_SNAPSHOT is not None:
        try:
            CONFIG_FILE.write_bytes(_CONFIG_SNAPSHOT)   # undo our edits to someone else's config
        except OSError:
            pass


# ── audit IPs: an older version's IPv6 zone text goes at startup, whatever the row's age ────────
# anonymise_audit_ips rewrites a zoned audit IP only once its row is past the retention window, and
# never with ageing off (audit_ip_retention_days 0), so the text stayed on every younger row. The
# update path (_run_light_migrations -> _unzone_audit_ips) now rewrites every row holding a '%'.
# Replayed as the update runs it, with an audit_log index dropped so the index build has to take
# SQLite's write lock: a rewrite left uncommitted there waits out the 15 s busy timeout, and the
# upgrade dies at startup on every install that holds such a row. Called from the audit-ip section.
_AZ_ZONED = {   # stored -> what the startup leaves
    "fe80::1c2d:3e4f:5a6b:7c8d%eth0": "fe80::1c2d:3e4f:5a6b:7c8d",               # an address
    "2001:db8::1%x $(id)": "2001:db8::1",                                        # ...free text
    "2001:db8:77::%x panel login failed from 203.0.113.9/64": "2001:db8:77::/64",  # reduced
    "%not an address": "",                                                       # no address
    "203.0.113.9%x": "",                                                         # IPv4: no zones
}
# Rows without a '%' are not this cleanup's, however they read: non-canonical and junk included.
_AZ_CLEAN = ("198.51.100.43", "2001:0DB8::0001", "198.51.100.0/24", "2001:db8:1:2::/64",
             "not-an-ip", "")


def _az_ips():
    """{id: ip_address} for the whole audit_log as stored (raw SQL, so no identity map is stale)."""
    from sqlalchemy import text as _t
    return dict(db.session.execute(_t("SELECT id, ip_address FROM audit_log")).all())


def _az_add_young_rows(values):
    """One audit row a day old per value in `values`; {id: stored ip}."""
    from datetime import timedelta as _td
    from panel.core.clock import utcnow as _now
    from panel.db.models import AuditLog as _AL
    rows = [_AL(username="zone_young", action="smoke_audit_zone", ip_address=v,
                timestamp=_now() - _td(days=1)) for v in values]
    db.session.add_all(rows)
    db.session.commit()
    return {r.id: r.ip_address for r in rows}


def _az_ts_index():
    """audit_log's declared timestamp index, and whether the database has it now."""
    from sqlalchemy import inspect as _insp
    from panel.db.models import AuditLog as _AL
    ix = next(i for i in _AL.__table__.indexes if list(i.columns.keys()) == ["timestamp"])
    return ix, ix.name in {i["name"] for i in _insp(db.engine).get_indexes("audit_log")}


def _az_replay_upgrade(drop=True):
    """The update's migrations, the timestamp index dropped first: (it was gone, error or None)."""
    from panel.db.models import _run_light_migrations
    ix = _az_ts_index()[0]
    if drop:
        ix.drop(db.engine, checkfirst=True)
    gone = not _az_ts_index()[1]
    try:
        _run_light_migrations()                             # <- the update path
        return gone, None
    except Exception as e:   # a locked or failed upgrade is this check's finding, not a crash
        db.session.rollback()
        ix.create(db.engine, checkfirst=True)
        return gone, "%s: %s" % (type(e).__name__, str(e)[:160])


def _az_run_cleanup():
    """Young zoned and clean rows, the upgrade replayed, then a second start: each read, by name."""
    from panel.db.models import anonymise_audit_ips, _unzone_audit_ips
    with app.app_context():
        r = {"added": _az_add_young_rows(list(_AZ_ZONED) + list(_AZ_CLEAN))}
        r["zoned"] = {i: v for i, v in r["added"].items() if "%" in v}
        r["before"] = _az_ips()
        r["aged_off"] = (anonymise_audit_ips(0), _az_ips())
        r["gone"], r["err"] = _az_replay_upgrade()
        r["after"], r["has_ix"] = _az_ips(), _az_ts_index()[1]
        r["err_again"] = _az_replay_upgrade(drop=False)[1]      # a second start
        r["again"], r["n_again"] = _az_ips(), _unzone_audit_ips()
    return r


def _az_others(ips, zoned):
    """An {id: ip} read without the zoned fixture rows."""
    return {i: v for i, v in ips.items() if i not in zoned}


def _check_audit_zone_cleanup_on_upgrade():
    """A young zoned audit IP loses its zone at startup, with ageing off; nothing else changes."""
    r = _az_run_cleanup()
    check("audit-ip zone: (premise) with ageing off, the ageing leaves the young zoned rows be",
          r["aged_off"] == (0, r["before"]) and len(r["zoned"]) == len(_AZ_ZONED), repr(r["zoned"]))
    check("audit-ip zone: the upgrade runs, its rewrite committed before the index build",
          r["gone"] and r["err"] is None,
          r["err"] or "the index was not dropped, so nothing had to be built")
    check("audit-ip zone: ...and it builds the audit_log index it found missing", r["has_ix"])
    got = {v: r["after"].get(i) for i, v in r["zoned"].items()}
    check("audit-ip zone: a YOUNG zoned row loses the zone at startup: an address keeps the "
          "address, a reduced row its /64, and one that is no address is blanked",
          got == _AZ_ZONED, repr(got))
    _check_audit_zone_rest_and_rerun(r)


def _check_audit_zone_rest_and_rerun(r):
    """...every other row is as it was, the clean fixtures included; a second start does nothing."""
    rest, rest_before = _az_others(r["after"], r["zoned"]), _az_others(r["before"], r["zoned"])
    clean = _az_others(r["added"], r["zoned"])
    check("audit-ip zone: ...and every other row is untouched, clean ones in any spelling included",
          rest == rest_before and {i: rest.get(i) for i in clean} == clean,
          repr(sorted(set(rest.items()) ^ set(rest_before.items()))))
    check("audit-ip zone: a second start changes nothing",
          (r["err_again"], r["n_again"]) == (None, 0) and r["again"] == r["after"],
          r["err_again"] or "%d rewritten again" % r["n_again"])


def _check_audit_zone_failure_is_logged():
    """A rewrite that fails is rolled back and logged, the startup goes on, the next one cleans."""
    import logging as _logging
    from panel.db import models as _m
    seen = []
    handler = _logging.Handler()
    handler.emit = lambda r: seen.append(r.getMessage())
    log = _logging.getLogger("panel.models")
    saved = (_m.unzoned_ip_or_network, log.propagate)

    def _boom(value):
        raise RuntimeError("stand-in parse failure")
    with app.app_context():
        rid = next(iter(_az_add_young_rows(["fe80::99%eth0"])))
        _m.unzoned_ip_or_network, log.propagate = _boom, False     # quiet: no traceback on stderr
        log.addHandler(handler)
        try:
            _m._run_light_migrations()
            err = None
        except Exception as e:   # the finding, not a crash
            db.session.rollback()
            err = "%s: %s" % (type(e).__name__, e)
        finally:
            _m.unzoned_ip_or_network, log.propagate = saved
            log.removeHandler(handler)
        stuck = _az_ips().get(rid)
        _m._run_light_migrations()
        fixed = _az_ips().get(rid)
    check("audit-ip zone: a rewrite that fails does not stop the startup, is undone, and says so",
          err is None and stuck == "fe80::99%eth0" and any("zone text" in s for s in seen),
          repr((err, stuck, seen)))
    check("audit-ip zone: ...and the next start cleans that row", fixed == "fe80::99", repr(fixed))
