"""Part 4 of the smoke suite. Imported for its side effects: see tests/smoke_test.py.

Two markers here are about the split, not the checks. `# pylint: disable=reimported`: each section
imports what it uses under an alias of its own, as it did in the single-file suite, whose one try
hid those imports from Pylint's reimport rule. `# noqa: MC0001` (mccabe): a block whose branches
mccabe counted, until the split, as part of that one try, already reported as too complex.
"""
from smoke.part01 import (_sm_core, _sm_cron, _sm_game, _sm_hosts, _SUITE_FILE, app, auth, check,
                          client_as, db, GameServer, Group, join_for, os, page_with_assets,
                          RemoteServer, sys, User)
from smoke.part02 import (admin_id, gs_id, mru_id, remote2_id, remote_id)
from smoke.part03 import (c, MetricSample)

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
                    # "created" ties an entry to the row holding its id now; one without
                    # it reads as not-checked-yet, and would skip every host below.
                    _appmod._os_update_seen[_r.id] = {
                        "name": _r.name, "count": 3, "security": 1,
                        "packages": [{"name": "openssl", "suite": "noble-security"}],
                        "at": 1.0, "created": _r.created_at}
            _sum_q, _sum_code = _qcount("/api/os-updates/summary")
            check("perf: the OS-updates banner endpoint renders", _sum_code == 200,
                  "got %d" % _sum_code)
            # 5 and 8, not 10 and 15: it really costs 3 and 7 (measured 2026-09-29, with 9
            # hosts in the snapshot — the same with the row-identity check the entries now
            # carry, whose query also answers which host is the panel's), so a per-host query
            # would add 9. A looser budget would leave the N+1 this guards against comfortably
            # inside it — a gate with too much headroom passes exactly when it matters.
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
_tpl_dir = _pl_esc.Path(_SUITE_FILE).resolve().parent.parent / "templates"
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
    import re as _re_l  # pylint: disable=reimported
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
    import re as _re_r  # pylint: disable=reimported
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
    import re as _re_t  # pylint: disable=reimported
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
    import re as _re_h  # pylint: disable=reimported
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
# Whitespace-tolerant: panel.css writes one declaration per line (Stylelint), so a rule is
# "selector {\n  prop: value;" there. A literal "{ .panel-tools" would never match the
# stylesheet's own spelling and the negative check below would pass on anything.
check("layout: nothing makes them visible again on touch",
      _re_d.search(r"@media \(hover: none\)\s*\{\s*\.panel-tools", _drag_html) is None)
check("layout: in edit mode they sit IN FLOW, so they cannot overlay the content",
      _re_d.search(r"body\.layout-edit \.panel-tools \{\s*position: static;", _drag_html) is not None)
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
    import re as _re_mig  # pylint: disable=reimported
    import pathlib as _pl_mig  # pylint: disable=reimported
    import sqlite3 as _sqlite_mig
    from sqlalchemy import inspect as _sa_inspect, text as _sa_text
    from panel.db.models import _run_light_migrations as _rlm
    _models_src = (_pl_mig.Path(_SUITE_FILE).resolve().parent.parent
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
from panel.db.models import (db as _hs_db, GameServer as _HSGame,                  # noqa: E402  # pylint: disable=reimported
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
    _saved_stop = dict(_ps._expected_stop)
    _saved_full = dict(_ps._server_full_alerted)
    _saved_peak = dict(_ps._server_peak_notified)
    _saved_pc = dict(_ps._player_counts)
    try:  # noqa: MC0001
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

        # A server that was up and is no longer listening -> server_down, once CONFIRMED: one
        # sweep with the port shut used to alert, and a scan that missed it once paged
        # "offline" then "back online" a minute later. It takes _DOWN_CONFIRM_SWEEPS in a row.
        _monmod._remote_listening_ports = lambda r: set()
        _rec.clear(); _monmod._monitor_pass()
        check("monitor: one sweep with the port shut does not alert yet", "server_down" not in _rec,
              "fired: %s" % _rec)
        for _ in range(_monmod._DOWN_CONFIRM_SWEEPS - 1):
            _monmod._monitor_pass()
        check("monitor: server_down fires on a confirmed up->down transition", "server_down" in _rec)

        # ...but a panel-issued stop (inside the expected-offline window) suppresses it.
        _reset_mon()
        _ps._monitor_state["servers"][_mon_id] = True
        _monmod._mark_expected_offline(_mon_id, "stop")      # what the Stop button marks
        _monmod._remote_listening_ports = lambda r: set()
        _rec.clear(); _monmod._monitor_pass()
        check("monitor: a panel-issued stop suppresses server_down", "server_down" not in _rec)
        # ...and it is recorded DOWN at once, marked as the panel's own. It used to stay recorded
        # UP for the whole window (so its return would not page "Server back online" for an
        # outage nobody was told about), and when a Stop's window ended with the server still
        # down, as a Stop intends, the sweeps after it paged "went offline unexpectedly". The
        # mark is what keeps the return quiet now (next check), however late it comes.
        check("monitor: ...records it down at once, marked as the panel's own, so neither the end "
              "of its window nor its return pages",
              (_ps._monitor_state["servers"].get(_mon_id),
               _ps._monitor_state["server_unannounced"].get(_mon_id)) == (False, True),
              "recorded %r / %r" % (_ps._monitor_state["servers"].get(_mon_id),
                                    _ps._monitor_state["server_unannounced"].get(_mon_id)))
        # Drive the next sweep for real: _rec holds only event KEYS and other fixture servers
        # transition too, so record the BODIES and look for this server by name.
        _exp_bodies = []
        _am.notifications.notify = lambda k, t, b="": (_rec.append(k), _exp_bodies.append((k, b)))[0]
        _monmod._remote_listening_ports = lambda r: {27100}
        _rec.clear(); _monmod._monitor_pass()
        check("monitor: ...so coming back from a panel-issued stop is silent",
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

        # ── A server a reboot plan holds is not "went offline unexpectedly" ──────────────────
        # A clean reboot (panel/services/host_reboot.py) marks every server its plan stops as
        # expected-offline for as long as the plan runs — not for a fixed eight minutes, which
        # a big host's stop phase alone could outlast. Driven through a real sweep seven
        # minutes later with the port still shut; the control without the mark alerts.
        _rw_real_time = _monmod.time
        _rw_saved_ports = _monmod._remote_listening_ports
        _rw_bodies = []

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
                _rw_bodies.clear()
                for _ in range(_monmod._DOWN_CONFIRM_SWEEPS):
                    _monmod._monitor_pass()
            finally:
                _monmod.time = _rw_real_time
            return [b for k, t, b in _rw_bodies if k == "server_down" and "mon-srv" in b]

        try:
            _am.notifications.notify = \
                lambda k, t, b="": (_rec.append(k), _rw_bodies.append((k, t, b)))[0]
            _ps._expected_offline[_mon_id] = float("inf")
            _rw_down = _rw_sweep_later(420)
            check("monitor: a server a reboot plan holds does not report 'offline unexpectedly'",
                  not _rw_down, str(_rw_down)[:160])
            _ps._expected_offline.pop(_mon_id, None)
            _rw_down = _rw_sweep_later(420)
            check("monitor: ...while one no plan holds does (control)", len(_rw_down) == 1,
                  str(_rw_down)[:160])
            # Reboot now, through the real route, on a host the panel cannot reach: refused,
            # and nothing marked — a reboot is never sent on a guess.
            _rw_c = app.test_client()
            _rw_c.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
            _rw_resp = _rw_c.post("/api/remote/%d/reboot" % _r1_id, json={"mode": "now"})
            # This fixture host answers nothing real: whichever refusal the census reaches first
            # (unreachable, a preflight that cannot escalate, an install row left by an earlier
            # block), the answer is a 409 and nothing is marked or started.
            check("reboot now: a host the panel cannot really reach is not rebooted, and nothing is marked",
                  _rw_resp.status_code == 409
                  and (_rw_resp.get_json() or {}).get("error") in ("unreachable", "preflight", "blocked")
                  and _mon_id not in _ps._expected_offline,
                  "%s %r" % (_rw_resp.status_code, _rw_resp.get_json()))
            _rw_c.get("/logout")
        finally:
            _monmod.time = _rw_real_time
            _monmod._remote_listening_ports = _rw_saved_ports
            _ps._expected_offline.pop(_mon_id, None)
            _am.notifications.notify = lambda key, title, body="": _rec.append(key)

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
        # One failed `echo ok` is a blip, not an outage: it used to page "Host unreachable"
        # and then "Host back online" a minute later.
        check("monitor: a single failed probe does not yet declare the host unreachable",
              "remote_unreachable" not in _rec, "fired: %s" % _rec)
        for _ in range(_monmod._DOWN_CONFIRM_SWEEPS - 1):
            _monmod._monitor_pass()
        check("monitor: remote_unreachable fires when a host stops responding (confirmed)",
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
        import panel.services.host_reboot as _idle_hr
        _idle_hr_saved = (_idle_hr._probe_rows, _idle_hr._host_blockers, _monmod._host_reachable,
                          _monmod._batched_slots)
        # The census reads each server's tmux session on the host; this host is a fixture, so
        # every installed server reads as running, and the host as reachable with nothing of
        # its own in flight (dpkg, apt). What is under test is the rows and the counts.
        _idle_hr._probe_rows = lambda remote, rows: {g.id: {"ok": True, "session": 1, "maint": 0}
                                                     for g in rows}
        _idle_hr._host_blockers = lambda remote: []
        _monmod._host_reachable = lambda remote: True
        _monmod._batched_slots = lambda servers: {}
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
            _monmod._server_slots = lambda gs, **k: (0, 16, None)   # every server: a confident 0
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
            _monmod._server_slots = lambda gs, **k: (3, 16, None)
            check("idle state: a host with players connected is busy",
                  _monmod._host_idle_state(_r1) == "busy", _monmod._host_idle_state(_r1))
            # ...and a count the panel could not read is 'unknown', never 'idle'.
            _monmod._server_slots = lambda gs, **k: (None, 16, None)
            check("idle state: an unreadable count is unknown, not idle",
                  _monmod._host_idle_state(_r1) == "unknown", _monmod._host_idle_state(_r1))
        finally:
            _monmod._server_slots = _sv_slots_idle
            (_idle_hr._probe_rows, _idle_hr._host_blockers, _monmod._host_reachable,
             _monmod._batched_slots) = _idle_hr_saved
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
            # Every host due for its (gated) read: when each was last read is the gate's
            # business, tested in unit part34; this is about what a read records.
            _monmod._restart_flags_read_at.clear()
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
            # Enough sweeps to CONFIRM the down, so the maintenance probe is what is tested —
            # a single sweep is silent now whatever maintenance says.
            _rec.clear()
            for _ in range(_monmod._DOWN_CONFIRM_SWEEPS):
                _monmod._monitor_pass()
            check("maintenance: a scheduled update does not alert as a crash",
                  "server_down" not in _rec and _mon_id in _probes, "%s probed=%s" % (_rec, _probes))
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
            _monmod._mark_expected_offline(_mon_id, "stop")
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
            _rec.clear()
            for _ in range(_monmod._DOWN_CONFIRM_SWEEPS):
                _monmod._monitor_pass()
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
        _rec.clear()
        for _ in range(_monmod._DOWN_CONFIRM_SWEEPS):      # a CONFIRMED down, or this is vacuous
            _monmod._monitor_pass()
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
        _rec.clear()
        for _ in range(_monmod._DOWN_CONFIRM_SWEEPS):
            _monmod._monitor_pass()
        check("mute: removing the tag restores server_down", "server_down" in _rec, str(_rec))
        db.session.delete(_mute_tag); db.session.commit()
    finally:
        _am.notifications.notify = _saved_notify
        for _n, _v in _saved.items():
            setattr(_monmod, _n, _v)
        for _k, _v in _saved_mstate.items():
            _ps._monitor_state[_k].clear(); _ps._monitor_state[_k].update(_v)
        _ps._expected_offline.clear(); _ps._expected_offline.update(_saved_exp)
        _ps._expected_stop.clear(); _ps._expected_stop.update(_saved_stop)
        _ps._server_full_alerted.clear(); _ps._server_full_alerted.update(_saved_full)
        _ps._server_peak_notified.clear(); _ps._server_peak_notified.update(_saved_peak)
        _ps._player_counts.clear(); _ps._player_counts.update(_saved_pc)
        db.session.delete(_mon); db.session.commit()

# ── reboot-when-empty: the POP is the commit point ────────────────────────────────────────────
# The wait (host_reboot.wait_pass) snapshots the pending hosts, then spends tens of seconds of
# SSH on the census before popping the entry. An operator who clicks Cancel inside that window
# is told "Auto-reboot canceled." — and the pop must come back empty, so nothing reboots.
with app.app_context():
    _rw_hr = sys.modules["panel.services.host_reboot"]
    _rw_mon = sys.modules["panel.services.monitoring"]
    _rw_ps = sys.modules["panel.core.panel_state"]
    _rw_hosts = sys.modules["panel.ops.ssh_manager.hosts"]
    _rw_rid = RemoteServer.query.filter_by(name="smoke-host").first().id
    # The REAL start_clean_reboot: the hand-over from the wait to the job is the commit point
    # under test. Only the job's thread is stubbed (_spawn), so nothing runs on the host.
    _rw_saved = [(_rw_hr, n, getattr(_rw_hr, n)) for n in
                 ("host_player_state", "_spawn", "log_action")]
    _rw_saved += [(_rw_mon, "_host_reachable", _rw_mon._host_reachable),
                  (_rw_hosts, "host_boot_identity", _rw_hosts.host_boot_identity)]
    _rw_saved_notify = _rw_hr.notifications.notify
    _rw_saved_reg = dict(_rw_ps._reboot_when_empty)
    _rw_reboots = []

    def _rw_run(state, cancel=False):
        """ONE pass of the real wait with the census answering `state`; what it started."""
        _rw_reboots.clear()

        def _census(remote, probes=None):
            if cancel:
                with _rw_ps._rwe_lock:
                    _rw_ps._reboot_when_empty.pop(remote.id, None)
            return {"state": state, "busy": [], "unknown": [], "blockers": [], "total": 0}
        _rw_hr.host_player_state = _census
        _rw_hr._spawn = lambda target: _rw_reboots.append(target.__self__.remote_id)
        _rw_hr.log_action = lambda *a, **k: None
        _rw_mon._host_reachable = lambda r: True
        _rw_hosts.host_boot_identity = lambda r: None
        _rw_hr.notifications.notify = lambda *a, **k: None
        try:
            _rw_hr.wait_pass(app)
        finally:
            with _rw_ps._hr_lock:
                _rw_ps._host_reboots.pop(_rw_rid, None)    # the job that never ran
        return list(_rw_reboots)

    def _rw_arm():
        with _rw_ps._rwe_lock:
            _rw_ps._reboot_when_empty.clear()
            _rw_ps._reboot_when_empty[_rw_rid] = {"by": "smoke", "since": _time_mon.time()}

    try:
        _rw_arm()
        check("reboot-when-empty: a reboot cancelled while the census ran does not fire",
              _rw_run("idle", cancel=True) == [],
              "rebooted %s after the operator was told it was cancelled" % _rw_reboots)
        _rw_arm()
        check("reboot-when-empty: ...while a queued, idle host still reboots",
              _rw_run("idle") == [_rw_rid], str(_rw_reboots))
        check("reboot-when-empty: ...and firing removes it from the registry",
              _rw_rid not in _rw_ps._reboot_when_empty)
        _rw_arm()
        check("reboot-when-empty: a busy host is not rebooted and stays queued",
              _rw_run("busy") == [] and _rw_rid in _rw_ps._reboot_when_empty, str(_rw_reboots))
    finally:
        for _m, _n, _v in _rw_saved:
            setattr(_m, _n, _v)
        _rw_hr.notifications.notify = _rw_saved_notify
        with _rw_ps._rwe_lock:
            _rw_ps._reboot_when_empty.clear()
            _rw_ps._reboot_when_empty.update(_rw_saved_reg)

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
        check("autoblock: an IP at/above the 7-day attempt threshold is blocked",
              "203.0.113.10" in _denied and _added == 1, "added=%r denied=%r" % (_added, _denied))
        check("autoblock: an IP below the threshold is NOT blocked", "203.0.113.11" not in _denied)
        check("autoblock: a whitelisted IP is never blocked even far over threshold", "10.9.9.9" not in _denied)
        check("autoblock: a stale auto-block that no longer qualifies is released",
              "203.0.113.99" in _undenied and _removed == 1,
              "removed=%r undenied=%r" % (_removed, _undenied))
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
import re as _re_as  # pylint: disable=reimported
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
import time as _rd_time  # pylint: disable=reimported
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
import re as _re_ab  # pylint: disable=reimported


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

# ...and a host (or game server) deleted WHILE a pass is running is not written to again.
# Deleting a host touches nothing on it by design, and the pass reads only database rows, but
# it read each list once, at the start, and one host's gamedig install can take ten minutes:
# a host deleted in that window was still in the list, and got its gamedig and cron put back.
# The delete here happens as a request's would: another thread, its own app context and so its
# own session, committed. Of each pair, the first reached deletes the other, so the order the
# rows come back in does not matter; the survivor is the positive control.
import threading as _ntd_thr
with app.app_context():
    _ntd_rows = [RemoteServer(name="ntd-%s" % _n, host="198.51.100.%d" % _i, port=22,
                              username="root", auth_method="key", auth_credential="")
                 for _i, _n in ((31, "games"), (32, "a"), (33, "b"))]
    db.session.add_all(_ntd_rows)
    db.session.flush()
    _ntd_gs = [GameServer(remote_id=_ntd_rows[0].id, name="ntd-%s" % _n, short_name=_n,
                          game_type="csgo", port=_p, installed=True, status="offline")
               for _n, _p in (("ntdserverone", 27131), ("ntdservertwo", 27132))]
    db.session.add_all(_ntd_gs)
    db.session.commit()
    _ntd_hids = [_r.id for _r in _ntd_rows]
    _ntd_gids = {_g.short_name: _g.id for _g in _ntd_gs}


def _ntd_delete_elsewhere(model, row_id):
    def _run():
        with app.app_context():
            db.session.delete(db.session.get(model, row_id))
            db.session.commit()
    _t = _ntd_thr.Thread(target=_run)
    _t.start()
    join_for(_t, 30)


_ntd_hosts, _ntd_up, _ntd_gone = [], [], {}


def _ntd_ensure(r):
    _ntd_hosts.append(r.id)
    if r.id in _ntd_hids[1:] and "host" not in _ntd_gone:
        _ntd_gone["host"] = _ntd_hids[2] if r.id == _ntd_hids[1] else _ntd_hids[1]
        _ntd_delete_elsewhere(RemoteServer, _ntd_gone["host"])
    return True


def _ntd_upgrade(remote, user, selfname=None, game_type=None, port=None):
    _ntd_up.append(str(user))
    if user in _ntd_gids and "game" not in _ntd_gone:
        _ntd_gone["game"] = [_n for _n in _ntd_gids if _n != user][0]
        _ntd_delete_elsewhere(GameServer, _ntd_gids[_ntd_gone["game"]])
    return False


_sv_ntd = (_sm_cron.upgrade_managed_cron_tracking, _ntp_app.ensure_node_tools_cron)
try:
    _sm_cron.upgrade_managed_cron_tracking = _ntd_upgrade
    _ntp_app.ensure_node_tools_cron = _ntd_ensure
    _ntd_err = None
    try:
        _ntp_app._node_tools_cron_pass(app)
    except Exception as _e:
        _ntd_err = _e
    with app.app_context():
        _ntd_really = (db.session.get(RemoteServer, _ntd_gone.get("host", -1)) is None
                       and db.session.get(GameServer, _ntd_gids.get(
                           _ntd_gone.get("game"), -1)) is None)
    _ntd_kept_h = [_h for _h in _ntd_hids[1:] if _h != _ntd_gone.get("host")]
    _ntd_kept_g = [_n for _n in _ntd_gids if _n != _ntd_gone.get("game")]
    check("daily cron pass: a host deleted while the pass runs is not acted on again, and one "
          "that was not is (control)",
          _ntd_err is None and _ntd_really and len(_ntd_kept_h) == 1
          and "host" in _ntd_gone and _ntd_gone.get("host") not in _ntd_hosts
          and _ntd_kept_h[0] in _ntd_hosts,
          "raised %r; gone %r; ensured %r" % (_ntd_err, _ntd_gone, _ntd_hosts[-4:]))
    check("daily cron pass: ...and the same for a game server deleted mid-pass",
          _ntd_err is None and _ntd_really and len(_ntd_kept_g) == 1
          and "game" in _ntd_gone and _ntd_gone.get("game") not in _ntd_up
          and _ntd_kept_g[0] in _ntd_up,
          "gone %r; upgraded %r" % (_ntd_gone, _ntd_up[-4:]))
finally:
    _sm_cron.upgrade_managed_cron_tracking, _ntp_app.ensure_node_tools_cron = _sv_ntd
    with app.app_context():
        for _gid in _ntd_gids.values():
            _g = db.session.get(GameServer, _gid)
            if _g is not None:
                db.session.delete(_g)
        for _hid in _ntd_hids:
            _h = db.session.get(RemoteServer, _hid)
            if _h is not None:
                db.session.delete(_h)
        db.session.commit()

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
    # Put the port back: the route saved the bumped one to config.json. Not in a try: a restore
    # that fails leaves every later check on the wrong port, so it must stop the suite, loudly.
    _am.update_config(lambda cfg: cfg.update({"port": _cp_port}))

# ── change-port: a panel bound to the host's own public/LAN address keeps its port OPEN ──
# Only the wildcard counted as public, so binding to the host's public IP deleted the allow
# rule for the port the panel was about to listen on — UFW's default-deny then shut it — and
# the answer said "kept tailnet-only". Its own seeded is_local row: none survives to here.
from panel.routes import remote_security as _rs_bind  # pylint: disable=reimported
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
    _am.update_config(_bind_restore)   # a restore that fails must stop the suite, not pass
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
    for _ in range(_auth_mod.TOKEN_MAX_FAILS):
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
from panel.services.bots import discord as _dcmod  # noqa: F401 - a later part imports it
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
        """Start with nothing submitted."""
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
        _tgmod._telegram_do_update = lambda a, tok, chat, sender=None: _tg_upd.append("panel")
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
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE)))
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


# What later parts import from this one (`from smoke.part04 import ...`). The parts are
# one suite, run in order by tests/smoke_test.py; listing these here says so to a reader,
# and to CodeQL, which does not follow those imports and reads the names as unused.
__all__ = [
    '_dc_src',
    '_dcmod',
    '_InlineWorker',
    '_notif',
    '_re_ab',
    '_re_as',
    '_repo_root',
    '_tg_handler',
    '_tgmod',
]
