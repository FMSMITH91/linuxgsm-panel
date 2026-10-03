"""Debug-report section(s): hosts_brief, hosts.

Owner: builder B4. hosts_brief: the compact public block (R6, R53 conflicts). hosts: per-host
transport/address class/flags, reachability, last probe error, tailscale peer, cached OS/specs, SSH
internals (R46-R51).

WHAT THIS MAY PRINT: DB ids, transport classes, address CLASSES (never the address), counts, ages,
percentages and fixed tokens. Never a host, address, account name, display name, key path, pool
key (user@host:port) or tailscale peer name. Every value read from a host or a row passes through a
classifier or a fixed-shape check (_tok) before it is printed.

WHAT THIS NEVER DOES: probe, scan, poll players, SSH or fetch. Everything below is a database read
of plain columns, or a read of a cache something else already filled. Decrypting columns (address,
login, host key) happens only when data/cred_key exists: decrypting without it would CREATE a new
key (config._cred_fernet), on exactly the install this report is trying to diagnose (R10's rule).
"""
import datetime
import importlib
import ipaddress
import os
import re
import stat as _stat
import time
from collections import Counter

from sqlalchemy import func

from panel.ops import system_ops as _so
from panel.ops.debug_report._base import Result, ago, unread_line

AREA = "Hosts"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}\Z")
_GAME_RE = re.compile(r"^[a-z0-9]{1,24}\Z")
_STATUS_RE = re.compile(r"^[a-z_]{1,20}\Z")
_OS_RE = re.compile(r"^[a-z0-9]{1,16}\Z")
_SLUG_RE = re.compile(r"^[a-z0-9.-]{3,24}\Z")
_TRANSPORTS = ("local", "tailscale", "key", "password")
_T_LABEL = dict(zip(_TRANSPORTS, ("panel host", "tailscale", "key", "password")))
_T_WORD = dict(zip(_TRANSPORTS, ("local (panel host)", None, "key (paramiko, pooled)",
                                 "password (paramiko, pooled)")))
# Tailscale's fixed ranges, from their one definition (system_ops._TAILNET_RANGES).
_TAILNET_V4, _TAILNET_V6 = (ipaddress.ip_network(n) for n in _so._TAILNET_RANGES)
_DOWN_SHOWN = 3        # down hosts named in the public block; the rest are counted
_CONFLICTS_SHOWN = 3   # port conflicts named in the public block; the rest are counted


def tok(value, pattern=_TOKEN_RE, other="other"):
    """`value` when it is a short fixed-shape token, else `other` -- never free text."""
    return value if isinstance(value, str) and pattern.match(value) else other


def game_tok(value):
    """A game_type as printed: LinuxGSM shortnames are [a-z0-9]; anything else is 'other'."""
    return tok(value, _GAME_RE)


def mod(name):
    """A panel module, looked up at call time (so the suites' stubs on it are what is read)."""
    return importlib.import_module(name)


def snap(mapping):
    """dict(mapping), the copy every read of a live map goes through (R6: copy before iterating)."""
    return dict(mapping)


# ── shared reads, once per report ─────────────────────────────────────────────────────────────

def transport_of(is_local, auth_method):
    """The transport run_command would use, by its own predicates (ssh_manager._core.run_command)."""
    if is_local or auth_method == "local":
        return "local"
    if auth_method == "tailscale":
        return "tailscale"
    return "password" if auth_method == "password" else "key"


def _read_host_cols():
    """[{id, transport, port, sudo, is_online}], plain columns only: nothing here decrypts."""
    models = mod("panel.db.models")
    rs = models.RemoteServer
    q = models.db.session.query(rs.id, rs.is_local, rs.auth_method, rs.port, rs.sudo_enabled,
                                rs.is_online).order_by(rs.id)
    return [{"id": rid, "transport": transport_of(loc, am), "port": port or 22,
             "sudo": bool(sudo), "is_online": online}
            for rid, loc, am, port, sudo, online in q.all()]


def host_cols(ctx):
    """Every host's plain columns (memoised for the report)."""
    return ctx.memo("b4.host_cols", _read_host_cols)


def _read_gs_cols():
    """[{id, remote_id, game_type, port, query_port, status, installed}] for every game server."""
    models = mod("panel.db.models")
    gs = models.GameServer
    q = models.db.session.query(gs.id, gs.remote_id, gs.game_type, gs.port, gs.query_port,
                                gs.status, gs.installed).order_by(gs.id)
    return [{"id": i, "remote_id": rid, "game_type": game_tok(gt), "port": port,
             "query_port": qp, "status": tok(st, _STATUS_RE),
             "installed": bool(inst)}
            for i, rid, gt, port, qp, st, inst in q.all()]


def gs_cols(ctx):
    """Every game server's plain columns (memoised for the report)."""
    return ctx.memo("b4.gs_cols", _read_gs_cols)


class LockBusy(Exception):
    """The install-jobs lock was not free within a second: the jobs were not read."""


_JOB_FIELDS = ("status", "step", "total", "step_name", "started", "updated")


def install_jobs():
    """{server id: the job's ALLOWLISTED fields}, copied under _install_lock (1 s at most).

    Never 'name', 'message', 'log' or 'born': free text and identities (R54).
    """
    ps = mod("panel.core.panel_state")
    if not ps._install_lock.acquire(timeout=1):
        raise LockBusy()
    try:
        return {k: {f: v.get(f) for f in _JOB_FIELDS}
                for k, v in list(ps._install_jobs.items()) if isinstance(v, dict)}
    finally:
        ps._install_lock.release()


def stranded_ids(rows, jobs):
    """Ids whose row says installing/configuring with no RUNNING job behind it."""
    return sorted(r["id"] for r in rows if r["status"] in ("installing", "configuring")
                  and (jobs.get(r["id"]) or {}).get("status") != "running")


def _panel_port():
    """The panel's own port, from config (read once per report)."""
    return mod("panel.core.config").load_config().get("port", 5000)


def _claims_by_host(gs_rows):
    """{remote_id: {port: {gs id: game_type}}} over every game port and query port."""
    claims = {}
    for r in gs_rows:
        for p in {r["port"], r["query_port"]}:
            if isinstance(p, int):
                claims.setdefault(r["remote_id"], {}).setdefault(p, {})[r["id"]] = r["game_type"]
    return claims


def _reserved_ports(host_rows, panel_port):
    """{remote_id: (port, what)}: a remote's SSH port, and the panel's own port on the panel host."""
    out = {}
    for h in host_rows:
        if h["transport"] == "local":
            out[h["id"]] = (panel_port, "the panel's own port")
        else:
            out[h["id"]] = (h["port"], "the host's SSH port")
    return out


def port_conflicts(ctx):
    """[(remote_id, port, what, {gs id: game_type})], computed from the DB (R53).

    `what` is None for two servers sharing a port (a game or query port), else the reserved port
    a server claims. Online is 'gs.port in the host's listening ports', so a collision makes a
    crashed server look healthy (#291).
    """
    def _compute():
        hosts = host_cols(ctx)
        reserved = _reserved_ports(hosts, _panel_port())
        out = []
        for rid, ports in sorted(_claims_by_host(gs_cols(ctx)).items()):
            for port, owners in sorted(ports.items()):
                if len(owners) > 1:
                    out.append((rid, port, None, owners))
                if reserved.get(rid, (None,))[0] == port:
                    out.append((rid, port, reserved[rid][1], owners))
        return out
    return ctx.memo("b4.port_conflicts", _compute)


def fmt_conflict(c):
    """'host 3: port 27015 → gs 12 (gmod), gs 14 (cs)' -- ids, game types and ports only."""
    rid, port, what, owners = c
    who = ", ".join("gs %d (%s)" % (i, gt) for i, gt in sorted(owners.items()))
    if what:
        return "host %s: port %d is %s → %s" % (rid, port, what, who)
    return "host %s: port %d → %s" % (rid, port, who)


def probe_records():
    """A copy of the monitor's last-probe record per host (monitoring._probe_record, R48)."""
    return snap(mod("panel.services.monitoring")._probe_record)


def monitor_map(name):
    """A copy of one of panel_state._monitor_state's maps."""
    return snap(mod("panel.core.panel_state")._monitor_state[name])


# ── hosts_brief: the public block (R6) ────────────────────────────────────────────────────────

def _down_detail(down, probes, now):
    """'host 3: timeout, 3 h 12 m' for each down host (the first few), from R48's record."""
    parts = []
    for rid in down[:_DOWN_SHOWN]:
        rec = probes.get(rid)
        if isinstance(rec, dict) and not rec.get("ok"):
            since = rec.get("fail_since")
            parts.append("host %d: %s, %s" % (rid, tok(rec.get("token")),
                                              ago(now - since) if since else "?"))
        else:
            parts.append("host %d: no failed probe recorded" % rid)
    if len(down) > _DOWN_SHOWN:
        parts.append("+%d more" % (len(down) - _DOWN_SHOWN))
    return " (%s)" % "; ".join(parts) if parts else ""


def _kinds(rows):
    """'panel host 1 · tailscale 1 · key 1'."""
    by_t = Counter(r["transport"] for r in rows)
    return " · ".join("%s %d" % (_T_LABEL[t], by_t[t]) for t in _TRANSPORTS if by_t.get(t))


def _probe_token(rec):
    return tok(rec.get("token")) if isinstance(rec, dict) else "no probe recorded"


def _brief_hosts(ctx, res):
    rows = host_cols(ctx)
    mon = monitor_map("remotes")
    states = [mon.get(r["id"]) for r in rows]
    down = [r["id"] for r, st in zip(rows, states) if st is False]
    up = states.count(True)
    probes = probe_records() if down else {}
    res.add("- **Hosts**: %d (%s). Monitor: %d up, %d DOWN%s, %d not yet probed" % (
        len(rows), _kinds(rows) or "none in the database", up, len(down),
        _down_detail(down, probes, time.time()), len(rows) - up - len(down)))
    for rid in down:
        res.find("warn", AREA, "host %d is down (%s)" % (rid, _probe_token(probes.get(rid))))


_STATUS_ORDER = ("online", "offline", "failed")


def _stranded_text(rows):
    """'stranded N', or why it could not be counted."""
    try:
        n = len(stranded_ids(rows, install_jobs()))
    except LockBusy:
        return "stranded: not checked (install lock busy)", None
    return "stranded %d" % n, n


def _brief_servers(ctx, res):
    rows = gs_cols(ctx)
    by_s = Counter(r["status"] for r in rows)
    parts = ["%s %d" % (s.capitalize() if i == 0 else s, by_s.get(s, 0))
             for i, s in enumerate(_STATUS_ORDER)]
    installing = by_s.get("installing", 0) + by_s.get("configuring", 0)
    other = len(rows) - sum(by_s.get(s, 0) for s in _STATUS_ORDER) - installing
    stranded, n = _stranded_text(rows)
    parts.append("installing %d (%s)" % (installing, stranded))
    if other:
        parts.append("other %d" % other)
    res.add("- **Game servers**: %d. %s" % (len(rows), " · ".join(parts)))
    if n:
        res.find("warn", "Game servers", "%d install(s) stranded: status installing with no "
                                         "live job" % n)


def _brief_conflicts(ctx, res):
    conf = port_conflicts(ctx)
    if not conf:
        res.add("- **Port conflicts**: none")
        return
    shown = "; ".join(fmt_conflict(c) for c in conf[:_CONFLICTS_SHOWN])
    more = " (+%d more)" % (len(conf) - _CONFLICTS_SHOWN) if len(conf) > _CONFLICTS_SHOWN else ""
    res.add("- **Port conflicts**: %d. %s%s" % (len(conf), shown, more))
    res.find("warn", "Game servers", "%d port conflict(s): a shared port makes a crashed server "
                                     "read online" % len(conf))


_BRIEF = (("Hosts", _brief_hosts), ("Game servers", _brief_servers),
          ("Port conflicts", _brief_conflicts))


def section_hosts_brief(ctx):
    """The public Hosts & game servers block: three lines, each read on its own (R6, R53)."""
    res = Result()
    for what, fn in _BRIEF:
        try:
            fn(ctx, res)
        except Exception as exc:  # noqa: BLE001 - one line unread is printed as exactly that
            res.add(unread_line(what, exc))
            res.find("unread", AREA, "%s could not be read" % what)
    res.summary_lines = list(res.lines)
    return res


# ── hosts: the full per-host block (R46-R51) ──────────────────────────────────────────────────

def _ip_class(ip):
    """The class of an IP address: never the address."""
    if ip.is_loopback:
        return "loopback"
    if ip in (_TAILNET_V4 if ip.version == 4 else _TAILNET_V6):
        return "tailnet IPv%d" % ip.version
    if ip.is_link_local:
        return "link-local IPv%d" % ip.version
    return ("private IPv%d" if ip.is_private else "public IPv%d") % ip.version


def addr_class(host):
    """The class of a stored host value, by ipaddress and name SHAPE only -- never resolved."""
    if isinstance(host, mod("panel.db.models").UnreadableSecret):
        return "unreadable"
    h = (host or "").strip().strip("[]")
    if not h:
        return "empty"
    try:
        return _ip_class(ipaddress.ip_address(h))
    except ValueError:
        pass
    low = h.lower().rstrip(".")
    if low == "localhost":
        return "loopback name"
    if low.endswith(".ts.net"):
        return "MagicDNS name"
    return "bare name (no dot)" if "." not in low else "DNS name"


def _login_class(user):
    if isinstance(user, mod("panel.db.models").UnreadableSecret):
        return "unreadable"
    return "empty" if not user else ("root" if user == "root" else "non-root")


def _hostkey_state(key, transport):
    if transport == "tailscale":
        return "n/a (tailnet)"
    if isinstance(key, mod("panel.db.models").UnreadableSecret):
        return "UNREADABLE (connections refused)"
    return "pinned" if key else "not pinned yet"


def _cred_state(raw, transport):
    """'UNREADABLE under this cred_key' / 'none stored' / None. Never the value."""
    cfg = mod("panel.core.config")
    if raw and cfg.is_encrypted(raw) and cfg.decrypt_secret(raw) == "":
        return "UNREADABLE under this cred_key"
    if not raw and transport == "password":
        return "none stored"
    return None


def _read_host_details():
    """{id: {addr, login, hostkey, cred}} as CLASSES -- only called when cred_key exists."""
    models = mod("panel.db.models")
    rs = models.RemoteServer
    out = {}
    for rid, host, user, key, cred, loc, am in models.db.session.query(
            rs.id, rs.host, rs.username, rs.host_key, rs.auth_credential, rs.is_local,
            rs.auth_method).all():
        t = transport_of(loc, am)
        out[rid] = {"addr": addr_class(host), "login": _login_class(user),
                    "hostkey": _hostkey_state(key, t), "cred": _cred_state(cred, t)}
    return out


def key_present():
    """Whether data/cred_key exists.

    Every decrypting read here is gated on it: without the key, decrypting CREATES a new one
    (config._cred_fernet), on exactly the install this report is diagnosing.
    """
    return bool(mod("panel.core.config").CRED_KEY_FILE.exists())


def host_details(ctx):
    """The classes above (memoised). Callers check key_present() first."""
    return ctx.memo("b4.host_details", _read_host_details)


def mux_state():
    """(True/False/None, reason) for the tailscale transport's ssh multiplexing.

    lstat as _cm_dir_is_ours does, WITHOUT calling it: it logs a warning each time (R51).
    """
    path = mod("panel.ops.ssh_manager._core")._SSH_CM_DIR
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, "control dir not created yet (made on the first tailscale command)"
    if not _stat.S_ISDIR(st.st_mode):
        return False, "OFF: control dir is not a directory"
    if st.st_uid != os.getuid():
        return False, "OFF: control dir not owned by this account"
    if st.st_mode & 0o077:
        return False, "OFF: control dir is open to group/other"
    return True, "on"


def _is_active(client):
    """Whether a pooled client's transport is up: is_active() only, no transport I/O."""
    try:
        t = client.get_transport()
        return bool(t is not None and t.is_active())
    except Exception:  # noqa: BLE001 - a torn-down client counts as inactive
        return False


def _pool_counts():
    """(clients, active) in the paramiko pool."""
    clients = list(mod("panel.ops.ssh_manager._core")._connections.values())
    return len(clients), sum(1 for c in clients if _is_active(c))


def _transport_word(row, mux):
    t = row["transport"]
    if t == "tailscale":
        return "tailscale (system ssh, multiplexing %s)" % (
            "on" if mux[0] else "off" if mux[0] is False else "not set up yet")
    return _T_WORD[t]


def _host_head(row, det, mux):
    """'- host 3 · tailscale (…) · port 22 · sudo yes · address MagicDNS name · login root · …'.

    `det` is the classes per host id, or a fixed string saying why they were not read.
    """
    parts = ["- host %d" % row["id"], _transport_word(row, mux)]
    if row["transport"] != "local":
        parts.append("port %s" % ("22" if row["port"] == 22 else "custom"))
        parts.append("sudo %s" % ("yes" if row["sudo"] else "no"))
        d = det.get(row["id"]) if isinstance(det, dict) else None
        parts += _detail_parts(row, d) if d else [det if isinstance(det, str) else
                                                   "address/login: row not read"]
    return " · ".join(parts)


def _detail_parts(row, d):
    parts = ["address %s" % d["addr"], "login %s" % d["login"], "host key %s" % d["hostkey"]]
    if d["cred"]:
        parts.append("credential %s" % d["cred"])
    if d["addr"] == "bare name (no dot)" and row["transport"] in ("key", "password"):
        parts.append("FLAG: a bare name on a %s host (only the tailscale path qualifies bare "
                     "names)" % row["transport"])
    return parts


def _cache_age(cache, rid, ttl, now):
    """(age seconds, value) of a cache entry stored as (expiry, value); (None, None) if absent."""
    hit = cache.get(rid)
    if not (isinstance(hit, tuple) and len(hit) == 2):
        return None, None
    return now - (hit[0] - ttl), hit[1]


def _metrics_part(rid, now):
    core = mod("panel.ops.ssh_manager._core")
    age, val = _cache_age(snap(core._host_metrics_cache), rid, core._LIVE_METRICS_TTL, now)
    if age is None:
        return "last good metrics read: none since panel start"
    host = (val or {}).get("host") or {}
    pct = " · disk %s%% ram %s%%" % (host.get("disk_percent", "?"), host.get("ram_percent", "?"))
    return "last good metrics read %s ago%s" % (ago(age), pct)


def _scan_part(rid, now):
    ps_mod = mod("panel.ops.ssh_manager.portscan")
    age, ports = _cache_age(snap(ps_mod._port_scan_cache), rid, ps_mod._PORT_SCAN_TTL, now)
    if age is None:
        return "port scan: none since panel start"
    return "port scan %s ago (%d listening)" % (ago(age), len(ports or ()))


def _read_samples_24h():
    """{remote_id: (newest ts, rows in 24 h)} from HostSample: sentinel-checked rows only."""
    models = mod("panel.db.models")
    hs = models.HostSample
    cutoff = mod("panel.core.clock").utcnow() - datetime.timedelta(hours=24)
    q = (models.db.session.query(hs.remote_id, func.max(hs.ts), func.count(hs.id))
         .filter(hs.ts >= cutoff).group_by(hs.remote_id))
    return {rid: (ts, n) for rid, ts, n in q.all()}


def _samples_part(ctx, row, installed):
    if installed == 0:
        return "no installed games, so never sampled (absence is not downtime)"
    samples = ctx.memo("b4.samples24", _read_samples_24h)
    got = samples.get(row["id"])
    if not got:
        return "samples: none in 24 h"
    ts, n = got
    age = (mod("panel.core.clock").utcnow() - ts).total_seconds()
    per_day = 86400 // mod("panel.services.monitoring")._METRIC_SAMPLE_SECONDS
    return "newest sample %s ago · 24 h: %d/%d" % (ago(age), n, per_day)


def _monitor_part(rid):
    mon, misses = monitor_map("remotes"), monitor_map("remote_misses")
    state = mon.get(rid)
    word = "up" if state is True else "DOWN (declared)" if state is False else "not probed yet"
    if misses.get(rid):
        word += ", %s/%d misses pending" % (misses[rid],
                                            mod("panel.services.monitoring")._DOWN_CONFIRM_SWEEPS)
    return "monitor " + word


def _rwe_part(rid, now):
    entry = snap(mod("panel.core.panel_state")._reboot_when_empty).get(rid)
    if not isinstance(entry, dict):
        return None
    since = entry.get("since")
    return "reboot-when-empty queued %s ago" % (ago(now - since) if since else "?")


def _reach_line(ctx, row, installed, now):
    """R47: the monitor's view, the DB column and the last good reads, side by side."""
    rid = row["id"]
    parts = [_monitor_part(rid), "DB is_online %s" % ("yes" if row["is_online"] else "no"),
             _metrics_part(rid, now), _scan_part(rid, now), _samples_part(ctx, row, installed)]
    rwe = _rwe_part(rid, now)
    if rwe:
        parts.append(rwe)
    return "  - reachability: " + " · ".join(parts)


def _probe_line(rid, probes, now):
    """R48: the last probe's outcome as a fixed token and rc, never a message."""
    if probes is None:
        return "  - last probe: could not be read"
    rec = probes.get(rid)
    if not isinstance(rec, dict):
        return "  - last probe: none recorded since panel start"
    ok_at = rec.get("ok_at")
    last_ok = "last OK %s ago" % ago(now - ok_at) if ok_at else "no OK since panel start"
    if rec.get("ok"):
        return "  - last probe: OK %s ago" % ago(now - (rec.get("at") or now))
    rc = rec.get("rc")
    return "  - last probe: FAILED %s ago: %s%s · %s · streak %d" % (
        ago(now - (rec.get("at") or now)), tok(rec.get("token")),
        " (rc %d)" % rc if isinstance(rc, int) else "", last_ok, int(rec.get("streak") or 0))


_SPEC_RE = re.compile(r"^[A-Za-z0-9 .,_()/+:@#-]{1,60}\Z")
_SPEC_FIELDS = ("os", "kernel", "arch", "cpu", "cores", "ram", "disk", "virt")   # never "hostname"


def _specs_line(rid):
    """R50: what host_specs and host_os_slug already cached -- an ALLOWLIST of fields."""
    specs = snap(mod("panel.ops.ssh_manager.firewall")._specs_cache).get(rid)
    slug = snap(mod("panel.ops.ssh_manager.hosts")._OS_SLUG_CACHE).get(rid)
    if not isinstance(specs, dict):
        text = "(specs not read since panel start)"
    else:
        text = " · ".join(tok(specs.get(f), _SPEC_RE, "unrecognised")
                          for f in _SPEC_FIELDS if specs.get(f))
    if slug:
        text += " · deps list %s" % tok(slug, _SLUG_RE)
    return "  - specs: " + text


def _host_block(ctx, row, det, mux, extra):
    """Every line for one host; a part that cannot be read says so, the rest still print."""
    now = time.time()
    lines = [_host_head(row, det, mux)]
    inst = extra["installed"]
    for fn in (lambda: _reach_line(ctx, row, None if inst is None else inst.get(row["id"], 0),
                                   now),
               lambda: _probe_line(row["id"], extra["probes"], now),
               lambda: _specs_line(row["id"])):
        try:
            lines.append(fn())
        except Exception as exc:  # noqa: BLE001
            lines.append("  " + unread_line("part of this host's block", exc))
    peer = (extra["peers"] or {}).get(row["id"])
    if peer:
        lines.append("  - tailscale peer: " + peer)
    return lines


def _installed_by_host(ctx):
    out = Counter()
    for r in gs_cols(ctx):
        if r["installed"]:
            out[r["remote_id"]] += 1
    return out


def _safe(fn, what, res):
    """fn(), or None with an unread line in `res` when it raised."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        res.add(unread_line(what, exc))
        return None


def _details_or_reason(ctx, res):
    """The per-host classes, or the fixed reason they were not read."""
    if not key_present():
        res.add("- **Address classes**: not read: the credential key file is missing, and "
                "decrypting without it would create a new one")
        return "address/login: not read (credential key missing)"
    det = _safe(lambda: host_details(ctx), "host address classes", res)
    return det if det is not None else "address/login: could not be read"


def section_hosts(ctx):
    """The full Hosts section: one block per host, then the SSH transport line.

    Per host: transport and address class (R46), reachability (R47), last probe (R48), tailscale
    peer (R49) and cached specs (R50). Then the paramiko pool and ssh multiplexing (R51).
    """
    res = Result()
    rows = host_cols(ctx)
    if not rows:
        return res.add("- no hosts in the database")
    mux = _safe(mux_state, "ssh multiplexing", res) or (None, "could not be read")
    det = _details_or_reason(ctx, res)
    extra = {"installed": _safe(lambda: _installed_by_host(ctx), "game servers per host", res),
             "probes": _safe(probe_records, "probe records", res),
             "peers": _safe(lambda: peers_by_host(ctx, res), "tailscale peers", res)}
    for row in rows:
        res.lines += _host_block(ctx, row, det, mux, extra)
    _transport_summary(res, mux, rows)
    return res


def _transport_summary(res, mux, rows):
    """R51, one line: the paramiko pool size and whether tailscale multiplexing is on, and why."""
    try:
        clients, active = _pool_counts()
        pool = "paramiko pool %d client(s), %d active" % (clients, active)
    except Exception as exc:  # noqa: BLE001
        pool = "paramiko pool: could not be read (%s)" % type(exc).__name__
    if any(r["transport"] == "tailscale" for r in rows):
        mx = "tailscale ssh multiplexing %s" % mux[1]
        if mux[0] is False:
            res.find("warn", AREA, "tailscale ssh multiplexing is off: every command "
                                   "re-handshakes")
    else:
        mx = "no tailscale hosts"
    res.add("- **SSH transport**: %s · %s" % (pool, mx))


# ── R49: tailscale peers for tailscale-transport hosts ────────────────────────────────────────

def _tsf(info, *names):
    """A field of the tailscale info, whether it is B3's dict or a TailscaleInfo object."""
    for n in names:
        v = info.get(n) if isinstance(info, dict) else getattr(info, n, None)
        if v is not None:
            return v
    return None


def ts_info(ctx):
    """The tailscale status, read without a new CLI call when one is recent.

    The integration's own cache when it is under 5 min old, else the report's single shared read
    (_src_tailscale.shared_info, the reading the Network section and the privacy pass share). No
    ping.
    """
    tsi = mod("panel.ops.tailscale_integration")
    cache = snap(getattr(tsi, "_cache", None) or {})
    if cache.get("info") is not None and time.time() - (cache.get("ts") or 0) <= 300:
        return cache["info"]
    src = mod("panel.ops.debug_report._src_tailscale")
    return src.shared_info(ctx)


# Kept back from the report's deadline when waiting for the Tailscale read: what is left prints
# every host's own lines, so a hung tailscaled costs the Tailscale words and nothing else.
_TS_RESERVE_S = 1.5


def _ts_unanswered(res, status, why):
    """{host id: why} for every tailscale host, when the Tailscale read did not answer."""
    timed_out = status == "timeout"
    res.add("- **Tailscale (this node)**: %s" % ("timed out (not shown)" if timed_out
                                                else "could not be read (%s)" % why))
    res.find("unread", AREA, "Tailscale status could not be read")
    return {rid: "tailscale status %s" % ("timed out" if timed_out else "not readable")
            for rid in _ts_hosts()}


def _ts_info_bounded(ctx):
    """ts_info(ctx) in a thread, waited on until the deadline less _TS_RESERVE_S.

    ("ok", info) | ("error", class name) | ("timeout", None). A late read is left to finish.
    """
    network = mod("panel.ops.debug_report.network")
    return network.bounded(ctx, (("tailscale", lambda: ts_info(ctx)),),
                           reserve=_TS_RESERVE_S)["tailscale"]


def _peer_names(peer):
    names = set()
    for key in ("dns_name", "DNSName", "hostname", "HostName"):
        v = (peer.get(key) or "").lower().rstrip(".")
        if v:
            names.add(v)
            names.add(v.split(".", 1)[0])
    return names


def _peer_keys(peer):
    """Every name and address a peer answers to, lower-cased (for matching only)."""
    ips = {str(i) for i in (peer.get("ips") or peer.get("TailscaleIPs") or ())}
    return ips | _peer_names(peer)


def match_peer(host, peers):
    """The peer a stored tailscale host names, matched IN MEMORY (name, MagicDNS or IP)."""
    h = (host or "").strip().lower().rstrip(".")
    found = [p for p in (peers or ()) if isinstance(p, dict) and h and h in _peer_keys(p)]
    return found[0] if found else None


def _last_seen_age(value):
    """Seconds since a tailscale LastSeen timestamp, or None."""
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return time.time() - dt.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def peer_online(peer):
    """Tailscale's own Online flag (authoritative: never second-guessed from LastSeen)."""
    return bool(peer.get("online", peer.get("Online")))


def _path_word(peer):
    """'direct' / 'DERP-relayed' from a boolean only: CurAddr is the peer's public IP:port."""
    direct = peer.get("direct")
    if direct is None and ("cur_addr" in peer or "CurAddr" in peer):
        direct = bool(peer.get("cur_addr") or peer.get("CurAddr"))
    if direct is None:
        return "path unknown"
    return "direct" if direct else "DERP-relayed (expect slow polls and console lag)"


def _offline_words(peer):
    age = _last_seen_age(peer.get("last_seen") or peer.get("LastSeen"))
    seen = "last seen %s ago" % ago(age) if age is not None and age < 10 ** 9 else \
        "last seen unknown"
    return [seen, "the host or its tailscaled is down; not an SSH problem"]


def peer_text(peer):
    """'online yes · direct · linux' -- Online, last-seen age, path and OS only (R49)."""
    if peer is None:
        return "no tailnet peer matches its stored address"
    online = peer_online(peer)
    parts = ["online %s" % ("yes" if online else "NO")]
    parts += [_path_word(peer)] if online else _offline_words(peer)
    parts.append(tok(peer.get("os") or peer.get("OS"), _OS_RE, "os unknown"))
    return " · ".join(parts)


def _ts_hosts():
    """{id: stored host} for the tailscale-transport rows (decrypted in memory, never printed)."""
    models = mod("panel.db.models")
    rs = models.RemoteServer
    return {rid: host for rid, host in models.db.session.query(rs.id, rs.host)
            .filter(rs.auth_method == "tailscale", rs.is_local.isnot(True)).all()}


def _node_line(info):
    if info is None:
        return "- **Tailscale (this node)**: not installed, or its status could not be read"
    if _tsf(info, "installed") is False:
        return "- **Tailscale (this node)**: not installed"
    state = tok(_tsf(info, "backend_state", "BackendState"), other="unknown")
    magic = _tsf(info, "magic_dns_enabled", "magic_dns")
    return "- **Tailscale (this node)**: BackendState %s · MagicDNS %s%s" % (
        state, "on" if magic else "off" if magic is False else "unknown",
        "" if state in ("Running", "unknown") else " · every tailscale host will fail")


def peers_by_host(ctx, res):
    """{host id: peer text} for each tailscale host; adds the node line to `res`."""
    if not any(r["transport"] == "tailscale" for r in host_cols(ctx)):
        return {}
    if not key_present():
        res.add("- **Tailscale peers**: not matched (credential key missing)")
        return {}
    status, info = _ts_info_bounded(ctx)
    if status != "ok":
        return _ts_unanswered(res, status, info)
    res.add(_node_line(info))
    peers = _tsf(info, "peers") if info is not None else None
    if not isinstance(peers, (list, tuple)):
        return {rid: "tailscale status not readable" for rid in _ts_hosts()}
    return _matched_peers(res, peers)


def _matched_peers(res, peers):
    """{host id: peer text}, each tailscale host matched against the node's peers."""
    out = {}
    for rid, host in _ts_hosts().items():
        p = match_peer(host, peers)
        out[rid] = peer_text(p)
        if p is not None and not peer_online(p):
            res.find("warn", AREA, "host %d: its tailnet peer is offline" % rid)
    return out
