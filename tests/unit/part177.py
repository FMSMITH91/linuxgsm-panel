r"""Part 177 of the unit suite: network traffic in the host history, and the host page's History card.

Held here (panel/ops/ssh_manager/_core.py, panel/services/monitoring.py, panel/routes/api.py and the
two pages):
* The host read's /proc/net/dev line, run under bash on sample files: every interface's received and
  sent bytes, a name glued to a large counter included.
* Which interfaces count: physical ones; never lo, container and VM links (veth, docker, br-, virbr)
  or tunnels (tailscale, wg), whose bytes the physical interface carries too.
* The rate: kbit/s from two readings of the same host; None on the first reading, after a counter
  went down, after a gap of more than ten minutes, and for a read with no counters; a deleted host's
  last reading forgotten.
* The sampler itself (monitoring._record_metric_samples on part12's app, host read replaced): the
  first HostSample after a start has no rate, the next one has it.
* The two new columns' migration entries, run on an old host_sample table.
* The routes on part12's app: the server history's host points carry rx/tx; the host history answers
  24h and 7d, refuses any other range, needs MANAGE_REMOTES and the host in the caller's reach, and
  is down-sampled like the server history.
* The pages: the host page's History card and its scripts in order, the server page's network chart;
  the shared chart script and the host card's script in node.

HOW IT RUNS. No host is reached: host_live_metrics and run_command are replaced, part12's transport
tripwire is armed, the /proc/net/dev line runs on files in a temporary directory, and the page
scripts run in node through part75's runner.
"""
import os as _os177
import sqlite3 as _sqlite177
import subprocess as _subprocess177  # nosec B404 - runs bash on a fixed command over a temp file
import tempfile as _tempfile177
from datetime import timedelta as _td177

from unit.part01 import _root, check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, P9_HOST2, P9_VIEWER, _p9, _p9_arm, _p9_client,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from panel.core.clock import utcnow as _now177
from panel.db import models as _m177
from panel.db.models import (Group as _Group177, HostSample as _HS177, MetricSample as _MS177, User as _User177,
                             db as _db177)
from panel.ops.ssh_manager import _core as _core177
from panel.security import auth as _auth177
from panel.services import monitoring as _mon177

# ── 1. the /proc/net/dev line, run for real on sample files ─────────────────────────────────────
proc_net_dev_sample = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls "
    "carrier compressed\n"
    "    lo: 93303860 1679630    0    0    0     0          0         0 93303860 1679630    0    0    0     0"
    "       0          0\n"
    "  ens3: 2128801739 3838650    0    0    0     0          0         0 918891908 4170652    0    0    0     0"
    "       0          0\n"
    "eth1:12345678901 99 0 0 0 0 0 0 2222 7 0 0 0 0 0 0\n"
    "tailscale0: 29338673  102316    0    0    0     0          0         0  7145994  137573    0    0    0     0"
    "       0          0\n"
    "docker0: 500 5 0 0 0 0 0 0 600 6 0 0 0 0 0 0\n"
    "vethab12: 700 7 0 0 0 0 0 0 800 8 0 0 0 0 0 0\n"
    "br-1f2e: 900 9 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n")


def _netif_cmd177():
    """The host read's /proc/net/dev part, exactly as _host_sample_cmd builds it."""
    parts = [p.strip() for p in _core177._host_sample_cmd().split(" ; ")]
    return [p for p in parts if "/proc/net/dev" in p]


def _run_netif177(text):
    """The NETIF lines that command prints for /proc/net/dev holding `text`."""
    cmd = _netif_cmd177()
    if len(cmd) != 1:
        return None
    with _tempfile177.TemporaryDirectory(prefix="lgsm-unit-p177-") as d:
        path = _os177.path.join(d, "dev")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        out = _subprocess177.run(["bash", "-c", cmd[0].replace("/proc/net/dev", path)],  # nosec B603 B607
                                 capture_output=True, text=True, timeout=10, check=False)
    return out.stdout.splitlines()


_lines177 = _run_netif177(proc_net_dev_sample)
eq("host read: the /proc/net/dev line prints every interface's received and sent bytes, a name glued to a "
   "large counter (eth1:12345678901) split from it",
   _lines177,
   ["NETIF lo 93303860 93303860", "NETIF ens3 2128801739 918891908", "NETIF eth1 12345678901 2222",
    "NETIF tailscale0 29338673 7145994", "NETIF docker0 500 600", "NETIF vethab12 700 800",
    "NETIF br-1f2e 900 1000"])

# ── 2. which interfaces count ───────────────────────────────────────────────────────────────────
eq("host traffic: physical interfaces count; lo, veth, docker, br-, virbr, tailscale and wg do not",
   [_core177._hch_net_counted(n) for n in ("ens3", "eth0", "enp0s3", "lo", "lowpan0", "veth1a", "docker0",
                                            "br-1f2e", "virbr0", "tailscale0", "wg0")],
   [True, True, True, False, True, False, False, False, False, False, False])
_host177, _acc177 = _core177._parse_host_sample("\n".join(_lines177 or []) + "\nNETIF eth2 x 5\nNETIF eth3\n")
eq("host traffic: the parsed read sums received and sent bytes over the counted interfaces only, and skips a "
   "line that is not two counters",
   (_host177.get("net_rx_bytes"), _host177.get("net_tx_bytes")), (2128801739 + 12345678901, 918891908 + 2222))
_none177, _ = _core177._parse_host_sample("MEM 100 50\nNETIF lo 5 5\n")
eq("host traffic: a read with no counted interface has no counters (None), not a host that moved 0 bytes",
   (_none177.get("net_rx_bytes"), _none177.get("net_tx_bytes")), (None, None))


def _hlm177(out):
    """host_live_metrics' host figures for a read printing `out` (run_command replaced, cache bypassed)."""
    saved = _core177.run_command
    _core177.run_command = lambda server, cmd, **kw: (out, "", 0)
    try:
        return _core177.host_live_metrics(type("R177", (), {"id": -177})(), force=True)["host"]
    finally:
        _core177.run_command = saved
        _core177._host_metrics_cache.pop(-177, None)


_withnet177 = _hlm177("MEM 100 50\nNETIF ens3 10 20\n")
_nonet177 = _hlm177("MEM 100 50\n")
check("host read: host_live_metrics stamps when the counters were read, and only when there are counters",
      isinstance(_withnet177.get("net_read_at"), float) and _withnet177.get("net_rx_bytes") == 10
      and _nonet177.get("net_read_at") is None and _nonet177.get("net_rx_bytes") is None,
      repr((_withnet177, _nonet177)))

# ── 3. the rate ─────────────────────────────────────────────────────────────────────────────────
_rid177 = 917701


def _rate177(at, rx, tx):
    return _mon177._hch_net_rates(_rid177, {"net_read_at": at, "net_rx_bytes": rx, "net_tx_bytes": tx})


_mon177._hch_net_last.pop(_rid177, None)
_seq177 = [_rate177(1000.0, 1000, 5000),                  # first reading: no rate
           _rate177(1060.0, 1000 + 7500000, 5000 + 75000),  # 60 s later: 1000 and 10 kbit/s
           _rate177(1120.0, 500, 6000),                    # received went down: a reboot
           _rate177(1180.0, 500 + 750, 6000 + 750),        # the reading after it has a rate again
           _rate177(1781.0, 900, 7000),                    # 601 s gap: no rate
           _rate177(2381.0, 900 + 75000, 7000)]            # exactly 600 s: a rate
eq("host traffic: the rate is kbit/s since the host's previous reading; None on the first, after a counter "
   "went down, and after more than ten minutes; exactly ten minutes still counts",
   _seq177, [(None, None), (1000.0, 10.0), (None, None), (0.1, 0.1), (None, None), (1.0, 0.0)])
_kept177 = _mon177._hch_net_last.get(_rid177)
_miss177 = [_rate177(None, 5, 5), _rate177(2441.0, None, 5)]
eq("host traffic: a read with no counters has no rate and leaves the previous reading in place",
   (_miss177, _mon177._hch_net_last.get(_rid177) == _kept177), ([(None, None), (None, None)], True))
_core177.forget_remote_caches(_rid177)
check("host traffic: a deleted host's last reading is forgotten (the memo is registered per host id), so a "
      "new host given the same id starts without a rate",
      _rid177 not in _mon177._hch_net_last and _rate177(3000.0, 1, 1) == (None, None),
      repr(_mon177._hch_net_last.get(_rid177)))
_mon177._hch_net_last.pop(_rid177, None)

# ── 4. the migration entries ────────────────────────────────────────────────────────────────────
_mig177 = [_m177._LIGHT_MIGRATIONS.get(("host_sample", c)) for c in ("net_rx_kbps", "net_tx_kbps")]
_con177 = _sqlite177.connect(":memory:")
try:
    _con177.execute("CREATE TABLE host_sample (id INTEGER PRIMARY KEY, remote_id INTEGER NOT NULL, ts DATETIME, "
                    "cpu FLOAT, ram_pct FLOAT, disk_pct FLOAT)")
    _con177.execute("INSERT INTO host_sample (remote_id, cpu) VALUES (1, 5)")
    for _ddl177 in _mig177:
        if _ddl177:
            _con177.execute(_ddl177)
    _cols177 = [r[1] for r in _con177.execute("PRAGMA table_info(host_sample)")]
    _old177 = _con177.execute("SELECT net_rx_kbps, net_tx_kbps FROM host_sample").fetchall() \
        if "net_tx_kbps" in _cols177 and "net_rx_kbps" in _cols177 else None
finally:
    _con177.close()
check("migration: both network columns have an ALTER entry, and on an older host_sample table they add the "
      "columns with existing rows reading None (no rate)",
      all(_mig177) and _old177 == [(None, None)], repr((_mig177, _old177)))

# ── 5. the sampler, on part12's app ─────────────────────────────────────────────────────────────
_clock177 = {"at": 5000.0, "rx": 1000, "tx": 2000}
with _p9.app_context():
    _ms_floor177 = _db177.session.query(_db177.func.max(_MS177.id)).scalar() or 0


def _sample177(remote, force=False):
    host = {"cpu_percent": 10.0, "ram_used": 50, "ram_total": 100, "disk_used": 1, "disk_total": 4,
            "net_rx_bytes": _clock177["rx"], "net_tx_bytes": _clock177["tx"], "net_read_at": _clock177["at"]}
    return {"host": host, "users": {}, "ports": set()}


def _clear177():
    """Drop this part's samples: P9_HOST's and P9_HOST2's HostSamples, and the MetricSamples it wrote."""
    _HS177.query.filter(_HS177.remote_id.in_((P9_HOST, P9_HOST2))).delete(synchronize_session=False)
    _MS177.query.filter(_MS177.id > _ms_floor177).delete(synchronize_session=False)
    _db177.session.commit()


def _host_rows177():
    with _p9.app_context():
        return [(r.net_rx_kbps, r.net_tx_kbps) for r in
                _HS177.query.filter_by(remote_id=P9_HOST).order_by(_HS177.id.asc()).all()]


_r177 = {}
try:
    _p9_arm(who="part177")
    _trips177 = len(_P9_TRIPPED)
    _p9_patch(_mon177, "host_live_metrics", _sample177)
    for _k177 in (P9_HOST, P9_HOST2):
        _mon177._hch_net_last.pop(_k177, None)
    with _p9.app_context():
        _clear177()
    _mon177._record_metric_samples(_p9)
    _clock177.update(at=5060.0, rx=1000 + 750000, tx=2000 + 7500)
    _mon177._record_metric_samples(_p9)
    _r177["rows"] = _host_rows177()
    _r177["trips"] = _P9_TRIPPED[_trips177:]
finally:
    _p9_restore_all()
    for _k177 in (P9_HOST, P9_HOST2):
        _mon177._hch_net_last.pop(_k177, None)
eq("sampler: the first HostSample after a start has no network rate and the next one has it, from the host "
   "read's counters (100 and 1 kbit/s over 60 s)",
   _r177.get("rows"), [(None, None), (100.0, 1.0)])

# ── 6. the routes ───────────────────────────────────────────────────────────────────────────────


def _seed177(remote_id, n, minutes=1, rx=800.0, tx=None):
    """`n` HostSamples for `remote_id`, one every `minutes`, the newest a minute ago."""
    with _p9.app_context():
        now = _now177()
        _db177.session.add_all([_HS177(remote_id=remote_id, ts=now - _td177(minutes=minutes * (n - i)),
                                       cpu=1.0, ram_pct=2.0, disk_pct=3.0, net_rx_kbps=rx, net_tx_kbps=tx)
                                for i in range(n)])
        _db177.session.commit()


def _scoped_user177():
    """A MANAGE_REMOTES user whose group covers P9_HOST only: (user id, group id)."""
    with _p9.app_context():
        grp = _Group177(name="p177_hosts", description="", is_default=False)
        grp.set_permissions([_auth177.MANAGE_REMOTES])
        grp.servers.append(_db177.session.get(_m177.RemoteServer, P9_HOST))
        _db177.session.add(grp)
        _db177.session.flush()
        u = _User177(username="p177_hosts", password_hash="x", display_name="Hosts",  # nosec B106
                     is_superadmin=False, is_active=True)
        u.groups.append(grp)
        _db177.session.add(u)
        _db177.session.commit()
        return u.id, grp.id


def _drop_user177(uid, gid):
    with _p9.app_context():
        for model, rid in ((_User177, uid), (_Group177, gid)):
            row = _db177.session.get(model, rid)
            if row is not None:
                _db177.session.delete(row)
        _db177.session.commit()


def _j177(r):
    return r.get_json(silent=True) or {}


_g177 = {}
_uid177 = _gid177 = None
try:
    _p9_arm(who="part177")
    _trips177 = len(_P9_TRIPPED)
    _p9_patch_sm("run_command", lambda *a, **k: ("", "", 0))
    with _p9.app_context():
        _clear177()
        from panel.db.models import GameServer as _GS177
        _gs177 = _GS177.query.filter_by(remote_id=P9_HOST).first().id
    _seed177(P9_HOST, 3, rx=800.0, tx=None)
    _uid177, _gid177 = _scoped_user177()
    _A177, _V177, _S177 = _p9_client(P9_ADMIN), _p9_client(P9_VIEWER), _p9_client(_uid177)
    _g177["server"] = _A177.get("/api/server/%d/history" % _gs177)
    _g177["host24"] = _A177.get("/api/remote/%d/history?range=24h" % P9_HOST)
    _g177["hostdef"] = _A177.get("/api/remote/%d/history" % P9_HOST)
    _g177["bad"] = [_A177.get("/api/remote/%d/history?range=%s" % (P9_HOST, r)).status_code
                    for r in ("1h", "30d", "24H", "7d%20")]
    _g177["viewer"] = _V177.get("/api/remote/%d/history" % P9_HOST).status_code
    _g177["scoped"] = _S177.get("/api/remote/%d/history" % P9_HOST).status_code
    _g177["scoped_other"] = _S177.get("/api/remote/%d/history" % P9_HOST2).status_code
    _g177["empty"] = _A177.get("/api/remote/%d/history" % P9_HOST2)
    # A week at one sample a minute: the cap holds, and 24h keeps only the last day.
    _seed177(P9_HOST2, 7 * 24 * 60 - 10, rx=None, tx=None)
    _g177["week"] = _A177.get("/api/remote/%d/history?range=7d" % P9_HOST2)
    _g177["day"] = _A177.get("/api/remote/%d/history?range=24h" % P9_HOST2)
    _g177["page"] = _A177.get("/remote/%d/manage" % P9_HOST)
    _g177["spage"] = _A177.get("/server/%d" % _gs177)
    _g177["trips"] = _P9_TRIPPED[_trips177:]
finally:
    _p9_restore_all()
    if _uid177 is not None:
        _drop_user177(_uid177, _gid177)
    with _p9.app_context():
        _clear177()

_sh177 = _j177(_g177["server"]).get("host") or []
check("server history: each host point carries the network rates rx/tx (None where there is no rate)",
      len(_sh177) == 3 and all(p.get("rx") == 800.0 and "tx" in p and p["tx"] is None for p in _sh177),
      repr(_sh177)[:300])
_hh177 = _j177(_g177["host24"])
check("host history: one host's CPU, RAM, disk and network series, oldest first, for 24h by default",
      _hh177.get("range") == "24h" and [sorted(p) for p in _hh177.get("host") or []] ==
      [["cpu", "disk", "ram", "rx", "t", "tx"]] * 3 and _hh177["host"][0]["t"] < _hh177["host"][2]["t"]
      and (_hh177["host"][0]["cpu"], _hh177["host"][0]["ram"], _hh177["host"][0]["disk"]) == (1.0, 2.0, 3.0)
      and _j177(_g177["hostdef"]) == _hh177, repr(_hh177)[:300])
eq("host history: any range but 24h and 7d is refused (400), not answered as another window",
   _g177["bad"], [400, 400, 400, 400])
eq("host history: the host page's access: refused without MANAGE_REMOTES, allowed with it for a host in the "
   "caller's groups, refused for a host outside them",
   (_g177["viewer"], _g177["scoped"], _g177["scoped_other"] in (403, 404)), (403, 200, True))
eq("host history: a host with no samples answers an empty series (the card then says No history yet)",
   _j177(_g177["empty"]).get("host"), [])
_wk177, _dy177 = _j177(_g177["week"]).get("host") or [], _j177(_g177["day"]).get("host") or []
check("host history: a week of samples is down-sampled like the server history (every len // 240-th "
      "sample, so 240 to 479 points), and 24h keeps only the last day's",
      240 <= len(_wk177) < 480 and 240 <= len(_dy177) < 480 and _j177(_g177["week"]).get("range") == "7d"
      and _dy177[0]["t"] > _wk177[0]["t"], repr((len(_wk177), len(_dy177))))
check("sampler and routes: nothing reached a host transport", not _r177.get("trips") and not _g177.get("trips"),
      repr((_r177.get("trips"), _g177.get("trips"))))

_page177 = _g177["page"].get_data(as_text=True) if _g177["page"].status_code == 200 else ""
_ix177 = [_page177.find(s) for s in ('id="hh-card"', 'id="hh-cpu"', 'id="hh-ram"', 'id="hh-disk"', 'id="hh-net"',
                                     'data-hh-range="24h"', 'data-hh-range="7d"', 'id="hh-empty"')]
_sx177 = [_page177.find(s) for s in ("vendor/chartjs/chart.umd.min.js", "js/history_charts.js",
                                     "js/remote_history.js")]
_card177 = _page177[_page177.find('id="hh-card"') - 60:_page177.find('id="hh-card"')]
check("host page: the History card is on the Overview tab with CPU, RAM, disk and network charts, a 24h/7d "
      "toggle and an empty state",
      all(i > 0 for i in _ix177) and 'data-mtab="overview"' in _card177, repr((_ix177, _card177)))
check("host page: Chart.js, then the shared chart script, then the card's own script",
      all(i > 0 for i in _sx177) and _sx177 == sorted(_sx177), repr(_sx177))
_sp177 = _g177["spage"].get_data(as_text=True) if _g177["spage"].status_code == 200 else ""
_ss177 = [_sp177.find(s) for s in ("js/history_charts.js", "js/server_detail.js")]
check("server page: a host network chart beside the host chart, and the shared chart script loaded before "
      "server_detail.js",
      'id="hist-net"' in _sp177 and _sp177.find('id="hist-host"') < _sp177.find('id="hist-net"')
      and all(i > 0 for i in _ss177) and _ss177 == sorted(_ss177), repr((_g177["spage"].status_code, _ss177)))

# ── 7. the page scripts in node ─────────────────────────────────────────────────────────────────


def _read177(*parts):
    with open(_os177.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


hist_js = _read177("panel", "static", "js", "history_charts.js")
host_js = _read177("panel", "static", "js", "remote_history.js")
sd_js = _read177("panel", "static", "js", "server_detail.js")
_sd_cut177 = sd_js[sd_js.find("function _r25c_histUnread("):sd_js.find("document.addEventListener('click'",
                                                                        sd_js.find("window.loadHistory = "))]

js_stage = r"""
global.window = global;
const els = {}, built = {}, urls = [];
let replyWith, clickFn = null;
const canvas = id => ({id, getContext: () => ({id})});
['hh-cpu', 'hh-ram', 'hh-disk', 'hh-net', 'hist-players', 'hist-server', 'hist-host', 'hist-net']
  .forEach(id => { els[id] = canvas(id); });
els['hh-card'] = {offsetParent: {}};
els['hh-empty'] = {style: {display: 'none'}};
els['hh-charts'] = {style: {}};
els['hist-empty'] = {style: {display: 'none'}};
els['hist-charts'] = {style: {}};
global.document = {getElementById: id => (id in els ? els[id] : null),
                   addEventListener: (t, fn) => { if (t === 'click') clickFn = fn; }};
global.MOUNT = ''; global.REMOTE_ID = 7; global.serverId = 3; global._histRange = '24h';
global.fetch = u => { urls.push(u); return Promise.resolve({json: () => Promise.resolve(replyWith)}); };
global.Chart = class {
  constructor(ctx, cfg){ this.data = cfg.data; this.options = cfg.options; built[ctx.id] = this; }
  update(){} destroy(){ this.destroyed = true; } };
const settle = () => new Promise(r => setTimeout(r, 0)).then(() => new Promise(r => setTimeout(r, 0)));
"""

_prog177 = js_stage + hist_js + "\n" + host_js + "\n" + r"""
(async () => {
  const out = {};
  out.fmt = [_hch_rate(999.4), _hch_rate(1000), _hch_rate(1530), _hch_rate(null), _hch_rate(undefined)];
  replyWith = {host: []}; window.loadHostHistory(); await settle();
  out.empty = [els['hh-empty'].style.display, els['hh-charts'].style.visibility, Object.keys(built).length];
  replyWith = {host: [{t: '2026-11-12T10:00:00Z', cpu: 5, ram: 6, disk: 7, rx: 500, tx: 1500},
                      {t: '2026-11-12T10:01:00Z', cpu: 8, ram: 9, disk: 10, rx: null, tx: null}]};
  window.loadHostHistory(); await settle();
  out.shown = [els['hh-empty'].style.display, els['hh-charts'].style.visibility];
  out.ids = Object.keys(built).sort();
  const net = built['hh-net'];
  out.net = net && net.data.datasets.map(d => [d.data, d.spanGaps]);
  out.tick = net && net.options.scales.y.ticks.callback(1500);
  out.tip = net && net.options.plugins.tooltip.callbacks.label({dataset: {label: 'Sent'}, parsed: {y: 1500}});
  out.cpu = built['hh-cpu'].data.datasets[0].data;
  els['hh-empty'].style.display = 'KEPT';
  replyWith = {error: 'boom'}; window.loadHostHistory(); await settle();
  out.err = els['hh-empty'].style.display;
  const btn = {getAttribute: () => '7d', parentNode: {querySelectorAll: () => []}};
  clickFn({target: {closest: () => btn}}); await settle();
  out.range = [urls[urls.length - 1], net.destroyed === true];
  console.log(JSON.stringify(out));
})();
"""
_out177 = _run_js75("host page History card: empty state, charts, error replies, range toggle", _prog177)
if _out177 is not None:
    eq("history charts: a rate reads kbit/s up to 1000 and Mbit/s above it; no rate is blank",
       _out177.get("fmt"), ["999 kbit/s", "1.0 Mbit/s", "1.5 Mbit/s", "", ""])
    eq("host page History card: no samples says No history yet over the chart area, which keeps its height "
       "(hidden, not removed), and builds no chart",
       _out177.get("empty"), ["", "hidden", 0])
    check("host page History card: samples show the CPU, RAM, disk and network charts; network has received "
          "and sent with gaps where there is no rate, Mbit/s on the axis and in the tooltip",
          _out177.get("shown") == ["none", ""] and _out177.get("ids") == ["hh-cpu", "hh-disk", "hh-net", "hh-ram"]
          and _out177.get("net") == [[[500, None], False], [[1500, None], False]]
          and _out177.get("tick") == "1.5 Mbit/s" and _out177.get("tip") == "Sent: 1.5 Mbit/s"
          and _out177.get("cpu") == [5, 8], repr(_out177))
    eq("host page History card: an error reply keeps what is on screen (it is not No history yet)",
       _out177.get("err"), "KEPT")
    eq("host page History card: the 7d button asks for range=7d and rebuilds the charts",
       _out177.get("range"), ["/api/remote/7/history?range=7d", True])

_prog177s = js_stage + hist_js + "\n" + _sd_cut177 + "\n" + r"""
(async () => {
  replyWith = {server: [{t: '2026-11-12T10:00:00Z', cpu: 1, ram: 2, players: 0}],
               host: [{t: '2026-11-12T10:00:00Z', cpu: 5, ram: 6, disk: 7, rx: 2500, tx: 40}]};
  window.loadHistory(); await settle();
  const net = built['hist-net'];
  console.log(JSON.stringify({ids: Object.keys(built).sort(), net: net && net.data.datasets.map(d => d.data),
                              url: urls[urls.length - 1]}));
})();
"""
_out177s = _run_js75("server page history: the host network chart", _prog177s)
if _out177s is not None:
    eq("server page history: the host network chart is drawn beside the host chart from the same reply's rx/tx",
       _out177s, {"ids": ["hist-host", "hist-net", "hist-players", "hist-server"], "net": [[2500], [40]],
                  "url": "/api/server/3/history?range=24h"})
