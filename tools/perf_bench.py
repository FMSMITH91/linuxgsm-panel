"""Performance benchmark — boots the panel on a THROWAWAY database, seeds it at several
sizes, and reports wall-clock time, SQL query count and response bytes per endpoint.

The point is to see how the panel SCALES. A query count that grows with the number of game
servers is an N+1; one that stays flat (or grows with hosts only) is fine. tests/smoke_test.py
already gates two endpoints at 50 servers; this walks the curve so a regression that only shows
up on a big install is visible before a user finds it.

Nothing here touches the network or sudo: SSH and the sudo probe are stubbed at the boundary,
so what is measured is the panel's own CPU + template + database cost, which is what the panel
controls. Network latency to a game host is not the panel's to optimise.

    python tools/perf_bench.py                  # default sizes
    python tools/perf_bench.py --sizes 10,50,200,500 --iterations 15
    python tools/perf_bench.py --json out.json  # machine-readable, for comparing two runs

SAFETY: refuses to run if a real database already exists, and removes what it created.
"""
import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATA_DIR, DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE  # noqa: E402

if DB_PATH.exists():
    print("REFUSING: %s exists — the benchmark only runs against a throwaway DB." % DB_PATH)
    sys.exit(2)

_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}
# The benchmark has to flip setup_complete to boot past the wizard, which rewrites config.json.
# Keep a verbatim copy of a pre-existing one and put it back on the way out.
_CFG_BACKUP = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None

from config import load_config, save_config  # noqa: E402
_cfg = load_config()
_cfg["setup_complete"] = True
save_config(_cfg)

import system_ops as so                                    # noqa: E402
so._check_sudo = lambda force=False: False                 # never probe real sudo (pam_faillock)

import app as appmod                                       # noqa: E402
from app import create_app                                 # noqa: E402
from models import db, User, Group, RemoteServer, GameServer, ServerTag, SetupState  # noqa: E402
import auth                                                # noqa: E402

# The I/O boundary the panel does not own: every remote call is stubbed to return promptly, so the
# numbers below are panel CPU + DB only. _host_reachable/_remote_listening_ports keep the monitor
# and the status poll on their "everything is fine" path, which is the common case in production.
appmod.run_command = lambda *a, **k: ("", "", 0)
appmod._host_reachable = lambda r: True
appmod._host_disk_pct = lambda r: 40
appmod._host_load_mem = lambda r: (10, 10)
appmod._remote_listening_ports = lambda r: set()
appmod._lgsm_maintenance_running = lambda remote, gs: False
appmod.server_live_metrics = lambda *a, **k: {}
appmod.get_server_status = lambda *a, **k: "offline"
appmod.player_list = lambda *a, **k: []
appmod.game_map = lambda *a, **k: ""
appmod.list_server_commands = lambda *a, **k: []
appmod.remote_public_ip = lambda *a, **k: ""


def build_app():
    """An in-process app for the benchmark only — it is never served or bound to a port.

    The four settings below are what a Werkzeug test client needs to talk to it: no browser means
    no CSRF token, no session fingerprint and no https. This is the same reason .codacy.yaml
    excludes tests/** ("test fixtures legitimately ... disable CSRF ... not shipped app code");
    this file is a harness that happens to live in tools/, so it says so at the line instead.
    """
    a = create_app()
    a.config["WTF_CSRF_ENABLED"] = False   # nosemgrep - benchmark harness, never served
    a.config["SESSION_PROTECTION"] = None
    a.config["SESSION_COOKIE_SECURE"] = False
    a.config["REMEMBER_COOKIE_SECURE"] = False
    return a


# A panel that has been up for a while is not an empty database. The audit log and the metrics
# history are the two tables that grow on their own — the sampler writes ~1/min per server and
# prunes at 14 days, so one server's slice is ~20k rows. Seed both so the pages that read them are
# measured against a realistic table, not a toy one.
AUDIT_ROWS = 20000
METRIC_ROWS = 14 * 24 * 60


def seed_history(app, gs_id):
    from datetime import datetime, timedelta
    from models import AuditLog, MetricSample
    now = datetime.utcnow()
    with app.app_context():
        db.session.bulk_save_objects([
            AuditLog(user_id=None, username="bench%d" % (i % 20), action="server_start",
                     target="bench-0-0", detail="seeded", ip_address="10.0.0.%d" % (i % 255),
                     timestamp=now - timedelta(minutes=i), success=True)
            for i in range(AUDIT_ROWS)])
        db.session.bulk_save_objects([
            MetricSample(server_id=gs_id, ts=now - timedelta(minutes=i),
                         cpu=float(i % 90), ram_mb=1024 + (i % 512), players=i % 24)
            for i in range(METRIC_ROWS)])
        db.session.commit()


def seed(app, hosts, per_host, tags=3, groups=5, users=100):
    """Seed `hosts` remotes with `per_host` game servers each, plus a NON-superadmin in `groups`
    groups and a population of `users` plain accounts.

    The restricted user matters: is_superadmin short-circuits get_user_servers, so a benchmark that
    only logs in as an admin never executes the permission-resolution path that every other account
    goes through. Returns (admin_id, server_id, restricted_id)."""
    with app.app_context():
        db.session.add(SetupState(step="complete", complete=True))
        admin = User(username="bench_admin", password_hash=auth.hash_password("Str0ng!passw0rd"),
                     display_name="Bench Admin", is_superadmin=True, is_active=True)
        db.session.add(admin)
        tag_rows = []
        for t in range(tags):
            tag_rows.append(ServerTag(name="tag%d" % t, color="#3ba55d", notify=True))
        db.session.add_all(tag_rows)
        db.session.flush()
        first_gs = None
        for h in range(hosts):
            rem = RemoteServer(name="bench-host%d" % h, host="10.30.%d.1" % (h % 255), port=22,
                               username="root", auth_method="key", auth_credential="",
                               public_ip="203.0.113.%d" % (h % 255))
            db.session.add(rem)
            db.session.flush()
            for g in range(per_host):
                gs = GameServer(remote_id=rem.id, name="bench-%d-%d" % (h, g),
                                short_name="bench%d_%d" % (h, g), game_type="gmod",
                                port=27000 + g, installed=True, status="offline")
                # Every third server carries a tag, so the tag join has real work to do.
                if g % 3 == 0:
                    gs.tags.append(tag_rows[g % tags])
                db.session.add(gs)
                if first_gs is None:
                    db.session.flush()
                    first_gs = gs.id
        # A normal user: member of `groups` groups, each granting one whole host.
        restricted = User(username="bench_user", password_hash=auth.hash_password("Str0ng!passw0rd"),
                          display_name="Bench User", is_superadmin=False, is_active=True)
        all_remotes = RemoteServer.query.all()
        for gi in range(groups):
            grp = Group(name="bench_grp%d" % gi, description="", is_default=False)
            grp.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER, auth.STOP_SERVER])
            grp.servers.append(all_remotes[gi % len(all_remotes)])
            db.session.add(grp)
            restricted.groups.append(grp)
        db.session.add(restricted)
        # ...and a crowd of plain accounts, so the user-management page has rows to render.
        db.session.add_all([
            User(username="filler%d" % i, password_hash="x", display_name="Filler %d" % i,
                 is_superadmin=False, is_active=True) for i in range(users)])
        db.session.commit()
        return admin.id, first_gs, restricted.id


def client_as(app, user_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = str(user_id)
        s["_fresh"] = True
    return c


class QueryCounter:
    """Counts statements on the real engine, and keeps the slowest one for attribution."""

    def __init__(self, engine):
        from sqlalchemy import event
        self.n = 0
        self.slowest = (0.0, "")
        self._t0 = 0.0
        self._engine = engine
        event.listen(engine, "before_cursor_execute", self._before)
        event.listen(engine, "after_cursor_execute", self._after)

    def _before(self, conn, cursor, statement, params, context, executemany):
        self._t0 = time.perf_counter()

    def _after(self, conn, cursor, statement, params, context, executemany):
        dt = time.perf_counter() - self._t0
        self.n += 1
        if dt > self.slowest[0]:
            self.slowest = (dt, " ".join(statement.split())[:110])

    def reset(self):
        self.n = 0
        self.slowest = (0.0, "")


# A browser always asks for gzip, and the panel compresses text responses in an after_request hook.
# Timing without this header measures a response no real client ever receives — and hides the CPU
# the compression itself costs on a big page.
GZIP = {"Accept-Encoding": "gzip"}


def measure(c, counter, path, iterations):
    """Hit `path` `iterations` times. Returns a dict of timings, query count and payload size."""
    appmod._port_scan_cache.clear()
    r = c.get(path, headers=GZIP)         # warm: fills one-time caches so the numbers are steady
    if r.status_code >= 400:
        return {"path": path, "status": r.status_code, "error": True}
    wire = len(r.data)
    raw = len(c.get(path).data)           # same page uncompressed, for the compression ratio
    times = []
    counter.reset()
    first_q = None
    for _ in range(iterations):
        appmod._port_scan_cache.clear()
        counter.reset()
        t0 = time.perf_counter()
        r = c.get(path, headers=GZIP)
        times.append((time.perf_counter() - t0) * 1000.0)
        if first_q is None:
            first_q = counter.n
    times.sort()
    return {
        "path": path,
        "status": r.status_code,
        "queries": first_q,
        "p50_ms": round(statistics.median(times), 1),
        "p95_ms": round(times[min(len(times) - 1, int(len(times) * 0.95))], 1),
        "min_ms": round(times[0], 1),
        "max_ms": round(times[-1], 1),
        "kb": round(raw / 1024.0, 1),
        "wire_kb": round(wire / 1024.0, 1),
        "slowest_sql_ms": round(counter.slowest[0] * 1000, 2),
        "slowest_sql": counter.slowest[1],
    }


def run_size(total_servers, hosts, iterations, paths):
    per_host = max(1, total_servers // hosts)
    app = build_app()
    admin_id, gs_id, restricted_id = seed(app, hosts, per_host)
    seed_history(app, gs_id)
    with app.app_context():
        actual = GameServer.query.count()
        counter = QueryCounter(db.engine)
    c = client_as(app, admin_id)
    rows = [measure(c, counter, p.replace("{gs}", str(gs_id)), iterations) for p in paths]
    # The same hot paths as a NON-superadmin, whose permission resolution the admin path skips.
    cu = client_as(app, restricted_id)
    urows = [measure(cu, counter, p, iterations) for p in RESTRICTED_PATHS]

    # The monitor sweep is a background cost, not a request: time it separately.
    t0 = time.perf_counter()
    with app.app_context():
        appmod._monitor_state = {"remotes": {}, "servers": {}, "disk": {}, "load": {}}
        appmod._monitor_pass()
    mon = (time.perf_counter() - t0) * 1000.0

    try:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110
        pass
    return {"servers": actual, "hosts": hosts, "rows": rows, "restricted": urows,
            "monitor_ms": round(mon, 1)}


def cleanup():
    if _CFG_BACKUP is not None:
        CONFIG_FILE.write_bytes(_CFG_BACKUP)
    for p in (DB_PATH, SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE):
        if p not in _PREEXISTING and p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    # create_app() also drops a startup backup next to the DB.
    for extra in (DATA_DIR / "panel.db-wal", DATA_DIR / "panel.db-shm", DATA_DIR / "panel.db.backup"):
        if extra.exists():
            try:
                extra.unlink()
            except OSError:
                pass


PATHS = [
    "/",                            # dashboard: every host + every server
    "/servers/manage",
    "/server-management",
    "/server/{gs}",                 # the heaviest single page
    "/server/{gs}/files",
    "/remotes",
    "/users",
    "/groups",
    "/logs",                        # reads the audit table
    "/notifications",
    "/settings",
    "/api/servers",                 # the status poll every open tab fires on a timer
    "/api/tags",
    "/api/server-management",
    "/api/server/{gs}",
    "/api/server/{gs}/history",     # reads the metrics table (24h window)
    "/api/server/{gs}/history?range=7d",   # ...and the 7-day window the chart toggle asks for
    "/api/panel/db-stats",
    "/api/dashboard/metrics",       # the dashboard polls this every 10s
]

# Hit as a normal (non-superadmin) account: these run auth.get_user_servers' permission branch.
RESTRICTED_PATHS = ["/", "/api/servers", "/api/dashboard/metrics"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10,50,200,500",
                    help="total game servers per run (comma separated)")
    ap.add_argument("--hosts", type=int, default=5, help="hosts to spread them over")
    ap.add_argument("--iterations", type=int, default=11)
    ap.add_argument("--json", default="", help="write the full result set here")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    runs = []
    for n in sizes:
        cleanup()                        # each size gets a virgin database
        print("seeding %d servers across %d hosts…" % (n, args.hosts), flush=True)
        runs.append(run_size(n, args.hosts, args.iterations, PATHS))

    print("\n%-22s %7s %7s %7s %7s %8s %8s"
          % ("endpoint", "servers", "queries", "p50 ms", "p95 ms", "HTML KB", "wire KB"))
    print("-" * 76)
    for run in runs:
        for row in run["rows"]:
            if row.get("error"):
                print("%-22s %8d   HTTP %d" % (row["path"], run["servers"], row["status"]))
                continue
            print("%-22s %7d %7d %7.1f %7.1f %8.1f %8.1f"
                  % (row["path"], run["servers"], row["queries"], row["p50_ms"], row["p95_ms"],
                     row["kb"], row["wire_kb"]))
        for row in run.get("restricted", []):
            if row.get("error"):
                print("%-22s %7d   HTTP %d" % ("(user) " + row["path"], run["servers"],
                                               row["status"]))
                continue
            print("%-22s %7d %7d %7.1f %7.1f %8.1f %8.1f"
                  % ("(user) " + row["path"], run["servers"], row["queries"], row["p50_ms"],
                     row["p95_ms"], row["kb"], row["wire_kb"]))
        print("%-22s %7d %7s %7.1f" % ("[monitor sweep]", run["servers"], "-", run["monitor_ms"]))
        print("-" * 76)

    # Scaling: the number that matters. Queries should be flat in server count; ms may grow, but
    # only linearly with the payload. Anything superlinear is the bug this harness exists to find.
    if len(runs) > 1:
        first, last = runs[0], runs[-1]
        growth = last["servers"] / float(first["servers"])
        print("\nscaling %d -> %d servers (%.0fx more data)"
              % (first["servers"], last["servers"], growth))
        for a, b in zip(first["rows"], last["rows"]):
            if a.get("error") or b.get("error"):
                continue
            dq = b["queries"] - a["queries"]
            dt = (b["p50_ms"] / a["p50_ms"]) if a["p50_ms"] else 0
            flag = "  <-- QUERIES GROW WITH SERVER COUNT" if dq > 2 else ""
            print("  %-22s queries %3d -> %3d (%+d)   time x%.1f   wire %.0f -> %.0f KB%s"
                  % (a["path"], a["queries"], b["queries"], dq, dt, a["wire_kb"], b["wire_kb"],
                     flag))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(runs, f, indent=2)
        print("\nwrote %s" % args.json)


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
