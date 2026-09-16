#!/usr/bin/env python3
"""Every page's query count must be bounded by HOSTS, never by the number of game servers.

The repo already budgets two hot paths inside smoke_test (the dashboard and /api/servers). That
caught the regression it was written for and nothing else: it names two endpoints, so an N+1 on
any of the other eighty-odd pages is invisible. One was — /api/panel/backups issued 644 queries
at 300 servers, roughly two per server, and no gate said a word.

This asserts the SHAPE instead of a number. It renders every GET page twice: once with a small
set of game servers, once with five times as many spread over the SAME hosts. A query count that
is host-bounded does not move. A per-server one grows with the data, which is the definition of
the bug, and it shows up whatever the absolute numbers are — so nobody has to keep a budget
per endpoint up to date, and a new page is covered the day it is added.

Deliberately NOT a wall-clock benchmark: timings on a CI runner are too noisy to gate on, and the
query count is the thing that actually explains why a page gets slow as an install grows.
tools/perf_bench.py is the one that walks the timing curve.

No SSH and no sudo: the exec primitives are stubbed at the definition site, which is the one target
that reaches both the route modules and ssh_manager's own internals.

    python tests/perf_budget_test.py     # exits 0 if all pages stay host-bounded
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panel.core.config import DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("SKIP: %s already exists — this only runs against a throwaway DB." % DB_PATH)
    sys.exit(0)

# Record what was here BEFORE, and put it back in cleanup(). The suites all write into the repo's
# data/ dir; the ones that do it safely note the pre-existing files and restore the config they
# edited. A probe that skipped this step rewrote a real config.json and the loss was not
# recoverable from the checkout — hence the care here.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}

# A config that was already on disk is RESTORED BYTE-FOR-BYTE at the end. Every DB-owning suite
# has to edit config.json to boot the app, and deleting it only when the suite CREATED it is not
# enough: on a developer's tree the file is theirs and the edits stay behind. That is not
# hypothetical — a leftover ssh_timeout=1 makes the UNIT suite's "no override -> the documented
# default" check fail, in a different suite, pointing at config rather than at whoever wrote it.
# tools/smoke-local.sh sidesteps this by copying to a throwaway tree; running a suite in-tree
# (which CI does, where no config pre-exists) should not behave differently.
_CONFIG_SNAPSHOT = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None
_CFG_BACKUP = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

from panel.core.config import load_config, save_config  # noqa: E402
_cfg = load_config()
_cfg["setup_complete"] = True
_cfg["ssh_timeout"] = 1
save_config(_cfg)

from panel.ops import system_ops as _so  # noqa: E402
_so._check_sudo = lambda force=False: False

from panel.services import lgsm_data as _lgsm  # noqa: E402
import tempfile as _tf  # noqa: E402
import pathlib as _pl  # noqa: E402
_lgsm._CACHE_DIR = _pl.Path(_tf.mkdtemp())
_lgsm._CACHE_DIR.mkdir(parents=True, exist_ok=True)
(_lgsm._CACHE_DIR / _lgsm.SERVERLIST).write_text(
    "shortname,gameservername,gamename,os\ncsgo,csgoserver,CS,ubuntu-24.04\n", encoding="utf-8")
(_lgsm._CACHE_DIR / _lgsm.DEPS).write_text("all,bc\n", encoding="utf-8")
_lgsm._mem.clear()

from app import create_app  # noqa: E402
from panel.db.models import db, User, Group, RemoteServer, GameServer, SetupState  # noqa: E402
from panel.security import auth  # noqa: E402
from panel.ops.ssh_manager import _core as _sm_core  # noqa: E402

app = create_app()
app.config.update(WTF_CSRF_ENABLED=False, SESSION_PROTECTION=None, SESSION_COOKIE_SECURE=False)

# Stub at the DEFINITION site: panel.ops.ssh_manager resolves names through __getattr__, so this one
# target is seen by the route modules AND by ssh_manager's own internal call sites.
for _name in ("run_command", "run_privileged", "run_as_game_user"):
    setattr(_sm_core, _name, lambda *a, **k: ("", "", 0))

HOSTS = 4
SERVERS_SMALL = 20
SERVERS_LARGE = 100      # same hosts, 5x the servers

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def cleanup():
    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass
    if _CFG_BACKUP is not None:
        CONFIG_FILE.write_bytes(_CFG_BACKUP)
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE,
              DB_PATH.with_name("panel.db-wal"), DB_PATH.with_name("panel.db-shm"),
              DB_PATH.with_name("panel.db.backup")):
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
def seed_servers(first, count):
    with app.app_context():
        remotes = RemoteServer.query.all()
        for i in range(first, first + count):
            db.session.add(GameServer(name="srv%03d" % i, short_name="srv%03d" % i,
                                      game_type="csgo", port=27015 + i,
                                      remote_id=remotes[i % len(remotes)].id, installed=True))
        db.session.commit()


GROUPS_SMALL = 3
GROUPS_LARGE = 24        # same servers, 8x the groups


def seed_groups(user_id, first, count):
    """Put `user_id` in `count` more groups, each granting one whole host."""
    with app.app_context():
        u = db.session.get(User, user_id)
        remotes = RemoteServer.query.all()
        for i in range(first, first + count):
            g = Group(name="perfgrp%03d" % i, description="", is_default=False)
            g.set_permissions([auth.VIEW_SERVERS, auth.VIEW_CONSOLE])
            g.servers.append(remotes[i % len(remotes)])
            db.session.add(g)
            u.groups.append(g)
        db.session.commit()


def probe(client, paths):
    """{path: query_count} for one pass over every page."""
    from sqlalchemy import event as sa_event
    counter = {"n": 0}

    def _count(conn, cur, stmt, params, ctx, many):
        counter["n"] += 1

    with app.app_context():
        engine = db.engine
    sa_event.listen(engine, "before_cursor_execute", _count)
    try:
        out = {}
        for path in paths:
            counter["n"] = 0
            try:
                client.get(path)
            except Exception:
                continue          # a page that raises is smoke_test's business, not this gate's
            out[path] = counter["n"]
        return out
    finally:
        sa_event.remove(engine, "before_cursor_execute", _count)


try:
    with app.app_context():
        db.create_all()
        st = SetupState.query.first() or SetupState(step="done", data="{}")
        st.complete = True
        db.session.add(st)
        if not Group.query.filter_by(name="Everyone").first():
            db.session.add(Group(name="Everyone"))
        admin = User(username="perf", password_hash=auth.hash_password("Sufficient1!pass"),
                     display_name="Perf", is_superadmin=True, is_active=True)
        db.session.add(admin)
        db.session.commit()
        for h in range(HOSTS):
            db.session.add(RemoteServer(name="host%d" % h, host="192.0.2.%d" % h,
                                        username="u", is_local=(h == 0)))
        db.session.commit()
        admin_id = admin.id

    seed_servers(0, SERVERS_SMALL)
    with app.app_context():
        one_server = GameServer.query.first().id
        one_remote = RemoteServer.query.first().id

    subs = {"<int:server_id>": str(one_server), "<int:remote_id>": str(one_remote),
            "<int:user_id>": str(admin_id), "<int:group_id>": "1", "<int:tag_id>": "1",
            "<int:cmd_id>": "1", "<int:ban_id>": "1"}
    with app.app_context():
        paths = []
        for rule in app.url_map.iter_rules():
            if "GET" not in (rule.methods or set()):
                continue
            p = str(rule)
            if p.startswith("/static"):
                continue
            for k, v in subs.items():
                p = p.replace(k, v)
            if "<" not in p:
                paths.append(p)
    paths.sort()

    c = app.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = str(admin_id)
        s["_fresh"] = True

    t0 = time.perf_counter()
    small = probe(c, paths)
    seed_servers(SERVERS_SMALL, SERVERS_LARGE - SERVERS_SMALL)
    large = probe(c, paths)
    elapsed = time.perf_counter() - t0

    check("perf: the probe actually rendered pages (a run that measures nothing proves nothing)",
          len(small) >= 40 and len(large) >= 40, "%d / %d pages" % (len(small), len(large)))

    # Host-bounded pages do not move at all. Allow a couple of queries of slack for pagination and
    # the like; a real per-server N+1 adds ~80 here (4x the servers added), not 2.
    SLACK = 2
    grew = []
    for p in sorted(small):
        if p not in large:
            continue
        delta = large[p] - small[p]
        if delta > SLACK:
            grew.append("%s %d->%d (+%d)" % (p, small[p], large[p], delta))
    check("perf: no page's query count grows with the number of game servers (N+1)",
          not grew, "; ".join(grew[:4]))

    # ── Second axis: GROUPS ───────────────────────────────────────────────────────────────────
    # The sweep above varies servers and holds groups fixed, which is a blind spot rather than a
    # choice — and something was hiding in it. Group.servers / Group.game_servers are lazy, so
    # get_user_servers and accessible_remote_ids fired two queries PER GROUP: a user in 60 groups
    # cost /api/dashboard/metrics — which the dashboard POLLS — 125 queries instead of 9, and
    # /groups cost 190. Neither moved by a single query as the servers grew, so this file said
    # nothing. Probed as a NON-superadmin, because is_superadmin short-circuits both functions
    # and an admin never walks the path that had the bug.
    with app.app_context():
        _ru = User(username="perf_restricted",
                   password_hash=auth.hash_password("Sufficient1!pass"),
                   display_name="Perf restricted", is_superadmin=False, is_active=True)
        db.session.add(_ru)
        db.session.commit()
        restricted_id = _ru.id
    seed_groups(restricted_id, 0, GROUPS_SMALL)

    cu = app.test_client()
    with cu.session_transaction() as s2:
        s2["_user_id"] = str(restricted_id)
        s2["_fresh"] = True
    few = probe(cu, paths)
    seed_groups(restricted_id, GROUPS_SMALL, GROUPS_LARGE - GROUPS_SMALL)
    many = probe(cu, paths)

    check("perf: the group probe rendered pages too", len(few) >= 10 and len(many) >= 10,
          "%d / %d pages" % (len(few), len(many)))
    grew_g = []
    for p in sorted(few):
        if p not in many:
            continue
        delta = many[p] - few[p]
        if delta > SLACK:
            grew_g.append("%s %d->%d (+%d)" % (p, few[p], many[p], delta))
    check("perf: no page's query count grows with the number of GROUPS a user is in",
          not grew_g, "; ".join(grew_g[:4]))

    # ── /api/servers must scan the HOSTS concurrently, not one after another ──────────────────
    # Query counts cannot see this one: the cost is SSH round trips, and they were serial. The
    # dashboard polls this every 8 seconds, so with an 80ms link it cost hosts x 80ms — 404ms at
    # 5 hosts and 1.61s at 20, measured. /api/dashboard/metrics already ran its per-host pass in a
    # pool; this endpoint did not.
    #
    # Asserted as OVERLAP rather than wall-clock, so it states the property instead of a timing a
    # loaded CI runner could fail on: each stubbed scan holds a counter up while it sleeps, and
    # serial code can never drive that counter above 1.
    import threading
    from panel.routes import api as _apimod
    _inflight, _peak, _lk = [0], [0], threading.Lock()

    def _counting_scan(remote):
        with _lk:
            _inflight[0] += 1
            _peak[0] = max(_peak[0], _inflight[0])
        try:
            time.sleep(0.05)      # long enough that genuine concurrency overlaps; eventlet-friendly
            return set()
        finally:
            with _lk:
                _inflight[0] -= 1

    _saved_scan = _apimod._remote_listening_ports
    try:
        _apimod._remote_listening_ports = _counting_scan
        c.get("/api/servers")
    finally:
        _apimod._remote_listening_ports = _saved_scan
    check("perf: /api/servers scans the hosts concurrently (peak %d of %d in flight)"
          % (_peak[0], HOSTS),
          _peak[0] > 1,
          "every host scanned in sequence — this endpoint costs hosts x SSH latency")

    worst = sorted(large.items(), key=lambda kv: -kv[1])[:5]
    print("busiest pages at %d hosts / %d servers: %s"
          % (HOSTS, SERVERS_LARGE, ", ".join("%s=%d" % (p, n) for p, n in worst)))
    print("probed %d pages twice in %.1fs" % (len(paths), elapsed))

except Exception:
    import traceback
    traceback.print_exc()
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
