"""The polling API the pages refresh themselves from.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from datetime import (timedelta)
from flask import (jsonify, request)
from flask_login import (current_user, login_required)
from panel.core.clock import (utcnow)
from panel.core.panel_state import (_install_jobs, _install_lock)
from panel.db.models import (GameServer, HostSample, MetricSample, db)
from panel.db.prefs import (_apply_user_server_order, _effective_prefs)
from panel.ops.ssh_manager import (_remote_listening_ports, get_server_status)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (INSTALL_SERVER, MANAGE_SERVERS, _perm_for_action, get_game,
    get_remote, get_user_servers, has_permission, permission_required, server_access_required)

# The only actions the command palette will offer. Deliberately the three you do without thinking
# — a search box is the wrong place to reach uninstall or a branch switch, both of which have a
# confirmation flow on the page that owns them.
PALETTE_ACTIONS = ("start", "restart", "stop")
from panel.services.monitoring import (_PLAYER_POLL_WORKERS, _cached_player_count,
    _host_metrics_work, _query_host_metrics)
import concurrent.futures
import itertools
import re
import time
from panel.core.http import (_log_and_generic)
from app import (_cached_player_max, _cached_player_name, _log, resolve_free_port)
from panel.routes._shared import (_looks_installed, _maybe_resolve_public_ip,
    _notify_servers_changed)


def register(app):
    @app.route("/api/dashboard/metrics")
    @login_required
    def api_dashboard_metrics():
        """Live resource metrics for the dashboard / manage pages: per-server game CPU%/RAM/uptime,
        and per-host whole-VPS CPU%/RAM%/disk%/uptime. Each server is one cached SSH sample, taken in
        parallel; polled on a slower cadence than the status feed so it stays cheap."""
        servers = get_user_servers(current_user)
        # One pass over the rows already in hand: the hosts are joinedloaded, so naming them and
        # answering "is this host local?" below costs no further queries.
        remote_by_id = {gs.remote_id: gs.remote for gs in servers if gs.remote_id and gs.remote}
        # One sample per HOST, not per game. Each sample already describes the whole machine, so
        # asking once per game fetched the same host figures N times; the pool now spreads over
        # hosts, which is what the SSH round trips actually cost.
        work = _host_metrics_work(servers)
        out_servers, hosts = {}, {}
        if work:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
                for sid, m, rid, mp in itertools.chain.from_iterable(ex.map(_query_host_metrics, work)):
                    if not m:
                        continue
                    out_servers[str(sid)] = {
                        "cpu": round(m.get("game_cpu_percent") or 0, 1),
                        "ram_mb": int(m.get("game_ram_mb") or 0),
                        "uptime": int(m.get("game_uptime_secs") or 0),
                        "up": bool(m.get("game_procs")),   # a live game process, not just a listening port
                        "map": mp or "",
                    }
                    if rid is not None and str(rid) not in hosts:
                        rt, dt = m.get("ram_total") or 0, m.get("disk_total") or 0
                        _rem = remote_by_id.get(rid)
                        hosts[str(rid)] = {
                            "name": getattr(_rem, "display_name", "") or "",
                            "local": bool(getattr(_rem, "is_local", False)),
                            "cpu": round(m.get("cpu_percent") or 0, 1),
                            "ram_pct": round(100.0 * (m.get("ram_used") or 0) / rt, 1) if rt else 0,
                            "disk_pct": round(100.0 * (m.get("disk_used") or 0) / dt, 1) if dt else 0,
                            "uptime": int(m.get("uptime_secs") or 0),
                            "cores": int(m.get("cores") or 1),
                        }
        return jsonify({"servers": out_servers, "hosts": hosts})

    @app.route("/api/server/<int:server_id>/history")
    @login_required
    @server_access_required
    def api_server_history(server_id):
        """Down-sampled CPU/RAM/player time series for the history charts (range=24h|7d), plus the
        host's CPU/RAM/disk over the same window. Capped to ~240 points so the chart stays light."""
        gs = get_game(server_id)
        rng = "7d" if request.args.get("range") == "7d" else "24h"
        since = utcnow() - timedelta(hours=(168 if rng == "7d" else 24))
        # with_entities, not the mapped class: the 7-day window is ~10k samples, of which at most
        # 240 survive down-sampling. Building a full ORM instance (and an identity-map entry) for
        # every discarded row was ~80% of this endpoint's time. Rows are plain named tuples.
        srows = (db.session.query(MetricSample.ts, MetricSample.cpu, MetricSample.ram_mb,
                                  MetricSample.players)
                 .filter(MetricSample.server_id == server_id, MetricSample.ts >= since)
                 .order_by(MetricSample.ts.asc()).all())
        sstep = max(1, len(srows) // 240)
        # Players is a spiky, low-integer metric: plain decimation (every sstep-th sample) silently
        # drops peaks that land on discarded samples — and 24h vs 7d use different steps, so they drop
        # DIFFERENT sessions and disagree. Take the MAX players over each point's window so no peak or
        # session is lost. CPU/RAM stay point-sampled (a level metric reads fine decimated).
        server = []
        for i in range(0, len(srows), sstep):
            r = srows[i]
            pv = [w.players for w in srows[i:i + sstep] if w.players is not None]
            server.append({"t": r.ts.isoformat() + "Z", "cpu": r.cpu, "ram": r.ram_mb,
                           "players": max(pv) if pv else None})
        host = []
        if gs.remote_id:
            hrows = (db.session.query(HostSample.ts, HostSample.cpu, HostSample.ram_pct,
                                      HostSample.disk_pct)
                     .filter(HostSample.remote_id == gs.remote_id, HostSample.ts >= since)
                     .order_by(HostSample.ts.asc()).all())
            hstep = max(1, len(hrows) // 240)
            host = [{"t": r.ts.isoformat() + "Z", "cpu": r.cpu, "ram": r.ram_pct, "disk": r.disk_pct}
                    for r in hrows[::hstep]]
        return jsonify({"server": server, "host": host, "range": rng})

    @app.route("/api/free-port")
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def api_free_port():
        """Suggest a non-colliding port for installing <game> on <remote_id> near <desired>, so the
        install form can show a free port up front (the install resolves one anyway). Read-only."""
        try:
            remote_id = int(request.args.get("remote_id") or 0)
            desired = int(request.args.get("desired") or 0)
        except (TypeError, ValueError):
            return jsonify({"port": None})
        game = re.sub(r"[^a-z0-9]", "", (request.args.get("game") or "").lower())[:40]
        # get_remote(), not a bare lookup: this scans listening ports on the host, so it must be
        # a host the caller may see (see get_remote's "every remote-scoped route" contract).
        remote = get_remote(remote_id) if remote_id else None
        if not remote or not game or not (1 <= desired <= 65535):
            return jsonify({"port": None})
        try:
            port, changed = resolve_free_port(remote, remote_id, desired, game)
        except Exception:
            return jsonify({"port": None})
        # port is None when nothing near `desired` is free. The form reads this as "no suggestion"
        # and leaves the field alone, which is the same shape as the failure branches above.
        return jsonify({"port": port, "changed": bool(changed)})

    @app.route("/api/palette")
    @login_required
    def api_palette():
        """The game servers the command palette can jump to — names only, and no probing.

        DELIBERATELY not /api/servers. That endpoint refreshes live status, which costs one
        listening-port scan per remote over SSH; opening a search box must not reach out to every
        host the user owns. Everything here comes from rows already in hand: get_user_servers()
        joinedloads the remote, so naming each server's host adds no query, and the palette fetches
        this once per page load and keeps it.

        Access is get_user_servers(), the same filter the dashboard uses, so the palette can never
        surface a server the user cannot already see.
        """
        # Which of these the user may RUN, not just reach. Computed here rather than in the
        # browser for the same reason the palette scrapes the sidebar instead of hardcoding a nav:
        # the answer is the server's to give, and a palette that offered an action the user cannot
        # perform would be a menu of 403s. Mirrors the check api_server_action itself makes, so the
        # two cannot disagree about what is allowed.
        #
        # Only ever these three. The palette is for the things you do without thinking; uninstall,
        # branch switches and mod changes are not those, and each carries its own confirmation
        # flow on the page that owns it.
        _allowed = [a for a in PALETTE_ACTIONS
                    if current_user.is_superadmin
                    or has_permission(current_user, _perm_for_action(a))]
        return jsonify([{
            "id": gs.id,
            "name": gs.name,
            "game": gs.game_type or "",
            "host": gs.remote.name if gs.remote else "",
            "installed": bool(gs.installed),
            # An un-installed server has nothing to start, so it gets no verbs even for an admin.
            "actions": _allowed if gs.installed else [],
        } for gs in get_user_servers(current_user)])

    @app.route("/api/servers")
    @login_required
    def api_servers():
        # Same per-user order as the dashboard. This payload is keyed by id client-side, so order
        # is not load-bearing here — but any future consumer that iterates it should see the user's
        # order rather than a second, different one.
        servers = _apply_user_server_order(get_user_servers(current_user),
                                           _effective_prefs(current_user))
        # Refresh live status efficiently: one listening-port scan per remote,
        # then match each game server's port (instead of an SSH call per server).
        by_remote = {}
        for gs in servers:
            if gs.remote_id:
                by_remote.setdefault(gs.remote_id, []).append(gs)
        # Scan the hosts CONCURRENTLY, then apply what came back. Each scan is one SSH round trip
        # and they do not depend on each other, so doing them in sequence made this endpoint cost
        # hosts x latency: measured against an 80ms link, 404ms at 5 hosts and 1.61s at 20 — re-paid
        # every 8 seconds by the dashboard's status poll, on top of /api/dashboard/metrics doing its
        # own (already parallel) pass. Same shape as _query_host_metrics.
        #
        # `remote` is resolved HERE, not in the worker: get_user_servers joinedloads it, and reading
        # a lazy relationship from a pool thread would emit a query on a session this greenthread
        # owns. Only the scan runs in the pool for the same reason — the status writes below stay
        # on this greenthread.
        work = [(gslist[0].remote, gslist) for gslist in by_remote.values() if gslist[0].remote]

        def _scan(item):
            remote, gslist = item
            try:
                # `or set()`: the scanner answers None for a failed read. Here that is the
                # same as 'nothing listening' — this endpoint reports per-server status and a
                # blip already shows as offline; it is the MONITOR that must not alert on it.
                return gslist, remote, (_remote_listening_ports(remote) or set())
            except Exception:
                _log.debug("api_servers: port scan failed", exc_info=True)
                return gslist, remote, None

        scanned = []
        if work:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
                scanned = list(ex.map(_scan, work))

        # Status writes are collected and applied as TWO statements, not one UPDATE per server.
        # Per-object assignment made this endpoint's query count scale with the number of game
        # servers — 49 -> 206 at 100 servers — which tests/perf_budget_test.py gates against.
        #
        # It only surfaced once the stats endpoint stopped persisting a status it could not read:
        # while that endpoint wrote "offline" for every server on a failed sample, the scan below
        # agreed with it and had nothing to write, so the N+1 never fired. The budget was being met
        # by a bug, not by the loop being cheap.
        flip = {"online": [], "offline": []}
        flipped = {}
        for gslist, remote, ports in scanned:
            if ports is None:
                continue                      # this host's scan failed; leave its statuses alone
            for gs in gslist:
                # NEVER overwrite an in-progress install's status. This poller only reflects
                # running/stopped, and a not-yet-running install would otherwise get flipped
                # "installing" -> "offline" (it isn't listening on its port yet) — which made the
                # progress row vanish and show "Not installed" the moment you navigated back.
                if not gs.installed or gs.status in ("installing", "configuring"):
                    continue
                st = "online" if gs.port in ports else "offline"
                if gs.status != st:
                    # Deliberately NOT `gs.status = st`. Assigning marks the object dirty, and the
                    # commit then flushes one UPDATE per server no matter what bulk statement runs
                    # beside it — which is the N+1 this endpoint is gated against. The response
                    # below reads the new value out of `flipped` instead.
                    flip[st].append(gs.id)
                    flipped[gs.id] = st
            # Resolve+cache the remote's public IP for the connect address in the background
            # (non-blocking) — the connect address falls back to remote.host until it's cached,
            # so a slow/unreachable remote never stalls this polled endpoint.
            if not remote.public_ip:
                _maybe_resolve_public_ip(app, remote.id)
        data = []
        for gs in servers:
            r = gs.remote
            host = (r.public_ip if r else "") or (r.host if (r and not r.is_local) else "")
            data.append({
                "id": gs.id,
                "name": gs.name,
                "short_name": gs.short_name,
                "game_type": gs.game_type,
                "port": gs.port,
                "status": flipped.get(gs.id, gs.status),
                "installed": gs.installed,
                "remote_name": r.name if r else "",
                "connect": f"{host}:{gs.port}" if host else "",
                "connect_url": gs.connect_uri(host),
                "players": _cached_player_count(gs.id),
                "max_players": _cached_player_max(gs.id),
                "game_name": _cached_player_name(gs.id),
            })
        # The status writes land HERE, after the response is built. Two statements, not one per
        # server — and, more importantly, AFTER every attribute the loop above reads.
        #
        # db.session.commit() expires every loaded object (expire_on_commit), so committing before
        # that loop made it re-SELECT all of them: measured at 100 servers, 101 game_server SELECTs
        # plus 100 lazy server_tag loads, taking /api/servers from 8 queries to 206. This endpoint
        # is POLLED by the dashboard.
        #
        # It was invisible until the stats endpoint stopped persisting a status it could not read:
        # while that wrote "offline" for every server on a failed sample, the scan above agreed and
        # nothing was ever dirty, so the commit never fired. The perf budget was being met by a bug.
        if flip["online"] or flip["offline"]:
            for _st, _ids in flip.items():
                if _ids:
                    # synchronize_session=False: nothing in the session needs reconciling — the
                    # response has already been built, from `flipped`.
                    GameServer.query.filter(GameServer.id.in_(_ids)).update(
                        {GameServer.status: _st}, synchronize_session=False)
            db.session.commit()

        return jsonify(data)

    @app.route("/api/server/<int:server_id>")
    @login_required
    @server_access_required
    def api_server_status(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        try:
            status = get_server_status(remote, gs)
            # Don't clobber an in-progress install's status (see /api/servers) — only persist
            # running/stopped for a server that's actually installed and not mid-install/config.
            if gs.installed and gs.status not in ("installing", "configuring"):
                gs.status = status
                db.session.commit()
        except Exception:
            status = "error"

        # The player counts come from the SAME cache /api/servers reads, kept fresh by the
        # background poller (gamedig, with the console and LinuxGSM-query fallbacks).
        #
        # This used to run `cat <console_log> | grep -c '...'` over SSH and then scan the result for
        # a line containing both "players" and "has". `grep -c` prints a bare number, so that loop
        # could never match: the endpoint reported 0/0 for every server, always — while paying for a
        # round trip that `cat`s the whole console log across the network on each call. None (not 0)
        # is what "we could not read it" means everywhere else in the API, so it is what this
        # answers now too.
        player_count = _cached_player_count(gs.id)
        max_players = _cached_player_max(gs.id)

        return jsonify({
            "id": gs.id,
            "name": gs.name,
            "short_name": gs.short_name,
            "game_type": gs.game_type,
            "port": gs.port,
            "status": status,
            "installed": gs.installed,
            "player_count": player_count,
            "max_players": max_players,
            "remote": gs.remote.name if gs.remote else "",
        })

    @app.route("/api/server/<int:server_id>/stats")
    @login_required
    @server_access_required
    def api_server_stats(server_id):
        """Fast live metrics for polling: VPS CPU/RAM/disk/uptime + the game's RAM
        and a port-based online check + the public connect address."""
        gs = get_game(server_id)
        remote = gs.remote
        try:
            m = _sm.server_live_metrics(remote, gs.short_name, gs.port)
        except Exception:
            # An unreachable host is an expected condition, not a server error — return
            # 200 with an error field (the poller handles it) so it doesn't log a console
            # 500 on every poll of an offline server.
            return jsonify({"error": _log_and_generic("server stats failed")}), 200

        # ram_total is the sentinel, the same one _live_run_state and _record_metric_samples use.
        # server_live_metrics builds its dict UP FRONT and returns it all-zero when the read
        # produced no output, so port_open=False / game_procs=0 is indistinguishable from a real
        # stopped server — and this endpoint COMMITS that as gs.status. `free -b` never fails on a
        # reachable host, so a zero there means the sample did not happen.
        #
        # app.py's _live_run_state says it is "deliberately the SAME predicate /api/server/<id>/stats
        # uses to set gs.status", and it guards on ram_total; this did not, so the two disagreed in
        # exactly the case the sentinel exists for. A wrongly persisted "offline" is not cosmetic:
        # _query_server_slots short-circuits on it and returns 0 players WITHOUT querying, which
        # satisfies the one-shot notify_when_empty ("now has 0 players — safe to make changes") and
        # clears the flag, while players are still connected.
        #
        # `port_open`, NOT `port_open or game_procs`. game_procs is `ps -u <game user> | wc -l` —
        # EVERY process that user owns, which includes the tmux server, a cron `update`, and the
        # steamcmd of an install in progress. So it answered "online" for a server that had never
        # started, for one whose game had crashed inside a surviving srcds_run, and for one still
        # downloading; and it persisted that. A listening port is what a player means by online,
        # it is what /api/servers and the monitor already report, and get_server_status now
        # confirms LinuxGSM's STARTED against it too — four answers, one definition.
        #
        # game_procs stays in the payload (the page shows the process count) and stays in
        # _live_run_state, which asks a different question: "is ANY trace of this server alive",
        # the right test for refusing a redundant start/stop. A crashed server reads offline here
        # and still has processes there, so the Stop that clears its tmux session is not refused.
        _readable = bool(m and m.get("ram_total"))
        status = "online" if m.get("port_open") else "offline"
        changed = False
        # Never overwrite an in-progress install, exactly as /api/servers refuses to: this endpoint
        # is polled by the very page that shows the install progress, and "installing" -> "online"
        # (steamcmd is a process; with the old predicate it was also 'online') ends the progress
        # row mid-download.
        if _readable and gs.installed and gs.status not in ("installing", "configuring") \
                and gs.status != status:
            gs.status = status
            changed = True
        elif not _readable:
            status = gs.status or "unknown"     # report what we last knew, do not persist a guess
        # Resolve + cache the remote's public IP (for the connect address) in the background —
        # non-blocking, so this polled endpoint never stalls on a slow/unreachable remote.
        if not remote.public_ip:
            _maybe_resolve_public_ip(app, remote.id)
        if changed:
            db.session.commit()

        host = remote.public_ip or (remote.host if not remote.is_local else "")
        return jsonify({
            "status": status,
            "connect": f"{host}:{gs.port}" if host else f":{gs.port}",
            "connect_url": gs.connect_uri(host),
            "public_ip": remote.public_ip,
            "port": gs.port,
            "metrics": m,
        })


    @app.route("/api/server/<int:server_id>/version")
    @login_required
    @server_access_required
    def api_server_version(server_id):
        """Which build of the game is installed on this server.

        Its OWN endpoint rather than a field on /stats: that one polls every few seconds and this
        costs an SSH read plus a game query, where the answer only changes when an update runs.
        The detail page fetches this once after it has drawn, and ssh_manager caches it, so a
        second tab or a reload is free.

        A host that can't be reached is an expected condition here too (see api_server_stats), so
        it answers 200 with an empty label rather than a 500 on a page that is otherwise fine."""
        gs = get_game(server_id)
        try:
            info = _sm.game_version(gs.remote, gs.short_name, game_type=gs.game_type,
                                    port=gs.port, query_type=gs.query_type,
                                    selfname=gs.lgsm_name)
        except Exception:
            # gs.id, not the route's own server_id — the same number, taken off the row rather
            # than off the URL. `<int:server_id>` already makes CR/LF impossible, so nothing can
            # be injected into the log either way, but no other route handler here logs its raw
            # path parameter and CodeQL's py/log-injection does not model Werkzeug's converters:
            # this is the only one that flowed request text straight to a log sink. A gate that
            # cries wolf is how a real alert gets waved through, so break the flow rather than
            # dismiss the alert.
            _log.debug("game version read failed for server %s", gs.id, exc_info=True)
            info = {"reported": "", "build": "", "appid": "", "updated": None, "label": ""}
        return jsonify({"supports_update": gs.supports_update, **info})

    @app.route("/api/server/<int:server_id>/install-status")
    @login_required
    @server_access_required
    def api_server_install_status(server_id):
        """Live step-by-step progress of a game-server install (mirrors bootstrap)."""
        gs = db.session.get(GameServer, server_id)
        installed_flag = bool(gs and gs.installed)
        with _install_lock:
            j = _install_jobs.get(server_id)
        if not j:
            # No live job. If the DB still says "installing", the in-memory progress was lost —
            # almost always because the panel restarted mid-install (e.g. a deploy). Reconcile
            # against the real server so the user gets a definite answer instead of a vanished row.
            # Covers both "installing" (steps 1-4) and "configuring" (steps 5-8, installed=True): a
            # restart in either phase strands a status the poller skips forever, so both reconcile.
            if gs and gs.status in ("installing", "configuring"):
                verdict = _looks_installed(app, gs.remote, gs.short_name, gs.lgsm_name)
                if verdict is True:
                    gs.installed = True
                    gs.status = "offline"   # live metrics will flip it to online if it's running
                    db.session.commit()
                    _notify_servers_changed(app)
                    return jsonify({"status": "done", "step": 8, "total": 8, "percent": 100,
                                    "step_name": "Complete",
                                    "message": "Install finished — verified after the panel restarted.",
                                    "log": [], "elapsed": 0})
                if verdict is False:
                    gs.status = "failed"
                    db.session.commit()
                    _notify_servers_changed(app)
                    return jsonify({"status": "failed", "step": 0, "total": 8, "percent": 0,
                                    "step_name": "Interrupted",
                                    "message": "The panel restarted before this install finished, so it "
                                               "didn't complete. Uninstall it, then install again.",
                                    "log": [], "elapsed": 0})
                # Couldn't reach the host to check — report an interrupted-but-unknown state.
                return jsonify({"status": "interrupted", "step": 0, "total": 8, "percent": 0,
                                "step_name": "Unknown", "log": [], "elapsed": 0,
                                "message": "Install progress was lost (the panel may have restarted) and "
                                           "the server couldn't be reached to confirm. Try refreshing."})
            return jsonify({"status": "none"})
        with _install_lock:
            j = _install_jobs.get(server_id)
            if not j:
                return jsonify({"status": "none"})
            if j["status"] in ("done", "failed") and (time.time() - j.get("updated", j["started"])) > 900:
                _install_jobs.pop(server_id, None)
                return jsonify({"status": "none"})
            pct = int(j["step"] / j["total"] * 100) if j.get("total") else 0
            return jsonify({
                "status": j["status"], "step": j["step"], "total": j["total"], "percent": pct,
                "step_name": j["step_name"], "message": j.get("message", ""),
                "warn": bool(j.get("warn")),   # done, but with a caveat (installed yet didn't start)
                "log": j["log"][-100:], "elapsed": int(time.time() - j["started"]),
                # installed flips True after the game files download (step 4), several steps before
                # the job's final "done" (config → ports → autostart → start). Surface it so the live
                # view can show "Finishing setup…" during those steps (server is installed but not yet
                # fully up) instead of a premature "Installed".
                "installed": installed_flag,
            })

    @app.route("/api/server/<int:server_id>/install-dismiss", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_install_dismiss(server_id):
        """Clear a finished install job so its progress card goes away.

        The same permission that owns installs, because _install_jobs is SHARED: popping the job
        clears the progress (or failure) card for every session watching that install, not just
        the caller's. @server_access_required alone let anyone who could see the server do it."""
        if not (current_user.is_superadmin
                or has_permission(current_user, INSTALL_SERVER)
                or has_permission(current_user, MANAGE_SERVERS)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        with _install_lock:
            j = _install_jobs.get(server_id)
            if j and j["status"] in ("done", "failed"):
                _install_jobs.pop(server_id, None)
        return jsonify({"success": True})
