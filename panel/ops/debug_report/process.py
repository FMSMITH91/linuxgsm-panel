"""Debug-report section(s): process.

Owner: builder B3. systemd state/restarts/memory (R15), resources/fds/cgroup (R18), eventlet hub (R17),
listening vs config (R19), boot transport record (R20), unit drift (R21).

Also the hub-lag watch (R17): one greenlet, started once by app.create_app() under eventlet's
thread patching, that times a one-second sleep and records how late it woke into runtime_stats.
Its body is a clock read, a sleep and a few dict stores, and it can never raise.
"""
import os
import re
import sys
import time

from panel.core import runtime_stats
from panel.ops import system_ops as so
from panel.ops.debug_report import _src_net, _src_systemd
from panel.ops.debug_report._base import Result, ago, unread_line

AREA = "Panel process"

# ── the hub-lag watch (R17) ──────────────────────────────────────────────────────────────────────
_HUB_LAG = {"started": False}
_LAG_TICK = 1.0
_LAG_BUCKETS = 10          # per-minute maxima kept, keyed by minute modulo this (fixed keys)
_SPAWN = [None]            # a test's stand-in for eventlet.spawn_n; None means the real one


def lag_tick(state, lag):
    """Record one tick of the watch: `lag` seconds late. Never raises."""
    try:
        lag = max(0.0, float(lag))
        state["ticks"] += 1
        runtime_stats.put("hub", "ticks", state["ticks"])
        if lag > state["max"]:
            state["max"] = lag
            runtime_stats.put("hub", "lag_max", round(lag, 3))
        minute = int(time.time() // 60)
        if minute != state["minute"]:
            state["minute"], state["minute_max"] = minute, -1.0
        if lag > state["minute_max"]:
            state["minute_max"] = lag
            runtime_stats.put("hub_lag", "m%d" % (minute % _LAG_BUCKETS), (minute, round(lag, 3)))
    except Exception:  # noqa: BLE001 - instrumentation never raises into its loop
        return


def hub_lag_loop(sleep, clock):
    """Time `sleep(1)` forever and record how late each wake-up was."""
    state = {"ticks": 0, "max": -1.0, "minute": None, "minute_max": -1.0}
    while True:
        t0 = clock()
        sleep(_LAG_TICK)
        lag_tick(state, clock() - t0 - _LAG_TICK)


def start_hub_lag_watch():
    """Start the watch once per process, only under eventlet's thread patching. True if started now.

    Idempotent: unit parts share one process and a second create_app() must start nothing.
    """
    if _HUB_LAG["started"]:
        return False
    try:
        import eventlet
        from eventlet import patcher
        if not patcher.is_monkey_patched("thread"):
            return False
        _HUB_LAG["started"] = True
        (_SPAWN[0] or eventlet.spawn_n)(hub_lag_loop, eventlet.sleep, time.monotonic)
        return True
    except Exception:  # noqa: BLE001 - a watch that cannot start is reported as not measured
        return False


# ── Serve's boot outcome as a fixed reason (R20) ─────────────────────────────────────────────────
_SERVE_REASONS = (
    ("serve-not-enabled-on-tailnet", ("not enabled on your tailnet", "serve is not enabled",
                                      "funnel is not enabled", "enable serve", "enable funnel")),
    ("permission", ("access denied", "permission", "denied", "sudo:", "not permitted")),
    ("not-running", ("not running", "needslogin", "needs login", "failed to connect",
                     "tailscaled", "stopped", "not found")),
    ("bad-mount", ("mount point",)),
)


def serve_reason(msg):
    """A fixed reason class for a failed Serve re-point: the message itself is never kept."""
    low = str(msg or "").lower()
    for token, needles in _SERVE_REASONS:
        if any(n in low for n in needles):
            return token
    return "other"


# ── small readers ────────────────────────────────────────────────────────────────────────────────
_TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{1,32}\Z")


def _tok(value, default="n/a"):
    """A systemd or eventlet word as printed: only a short fixed-alphabet token, else 'other'."""
    if value is None or value == "":
        return default
    return value if _TOKEN_RE.match(str(value)) else "other"


def _mb(value):
    """Bytes (systemd's integer, or 'infinity'/unset) as 'N MB', or 'n/a'."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "n/a"
    if n < 0 or n >= 2 ** 63:
        return "n/a"
    return "%d MB" % (n // (1024 * 1024))


def _yn(flag):
    return "yes" if flag else "no"


def _app_config(ctx):
    """The running app's config mapping, or {} outside an app."""
    return getattr(ctx.app, "config", None) or {}


def _load_cfg():
    """(config dict, readable?) through the config module, so a test's redirect applies."""
    from panel.core import config as _cfg
    cfg = _cfg.load_config()
    return cfg, not _cfg.is_unreadable(cfg)


def _app_module():
    """The `app` module the routes import (not __main__), or None when it is not loaded."""
    return sys.modules.get("app")


# ── R15: the unit's state ────────────────────────────────────────────────────────────────────────
def _account_name():
    """The account name of the process, for the linger lookup only. Never printed."""
    import pwd
    return pwd.getpwuid(os.geteuid()).pw_name


def _linger(scope):
    """' · linger: on/off' for a user unit; '' for a system one. The account name stays local."""
    if scope != "user":
        return ""
    try:
        on = os.path.exists("/var/lib/systemd/linger/" + _account_name())
    except (KeyError, OSError) as exc:
        return " · linger: could not be read (%s)" % type(exc).__name__
    return " · linger: %s" % ("on" if on else "OFF (the panel stops at logout, not started at boot)")


def _active_for(props):
    """' for 3 h 10 m' from ActiveEnterTimestampMonotonic, or ''."""
    try:
        since = int(props.get("ActiveEnterTimestampMonotonic", "0")) / 1e6
    except ValueError:
        return ""
    return " for %s" % ago(time.monotonic() - since) if since > 0 else ""


def _service_findings(res, props, facts):
    if props.get("ActiveState") != "active":
        res.find("warn", AREA, "the panel's unit is not active (this process was started another way)")
    if not facts["mainpid_is_me"]:
        res.find("warn", AREA, "this process is not the unit's MainPID (started by hand, or a second copy)")
    if facts["restarts"]:
        res.find("warn", AREA, "systemd restarted the panel automatically since the unit was last started")
    if props.get("NeedDaemonReload") == "yes":
        res.find("warn", AREA, "the unit file changed on disk and systemd has not reloaded it")


def _service_lines(ctx, res, facts):
    """R15: one `systemctl show`, shared with R8 and R21 through the memo."""
    unit = ctx.memo("systemd_unit", _src_systemd.unit_show)
    facts["unit"] = unit
    if unit.get("error"):
        rc = unit.get("rc")
        res.add("- **Service**: systemd state could not be read (%s%s)"
                % (_tok(unit.get("why"), "unreadable"), "" if rc is None else ", rc=%d" % rc))
        res.find("unread", AREA, "the panel's systemd state could not be read")
        return
    props, scope = unit["props"], unit.get("scope")
    facts["mainpid_is_me"] = props.get("MainPID") == str(os.getpid())
    try:
        facts["restarts"] = int(props.get("NRestarts", "0"))
    except ValueError:
        facts["restarts"] = None
    res.add("- **Service**: %s unit · %s (%s)%s · MainPID is this process: %s · enabled: %s%s"
            % (scope, _tok(props.get("ActiveState")), _tok(props.get("SubState")),
               _active_for(props), _yn(facts["mainpid_is_me"]), _tok(props.get("UnitFileState")),
               _linger(scope)))
    res.add("- **Automatic restarts (systemd's NRestarts)**: %s · last Result: %s · "
            "NeedDaemonReload: %s · KillMode: %s"
            % ("n/a" if facts["restarts"] is None else facts["restarts"],
               _tok(props.get("Result")), _tok(props.get("NeedDaemonReload")),
               _tok(props.get("KillMode"))))
    res.add("- **Unit cgroup memory**: %s now, peak %s · tasks %s"
            % (_mb(props.get("MemoryCurrent")), _mb(props.get("MemoryPeak")),
               _tok(props.get("TasksCurrent"))))
    wd = props.get("WorkingDirectory")
    res.add("- **Unit's WorkingDirectory is this checkout**: %s"
            % ("not set" if not wd else _yn(os.path.realpath(wd) == os.path.realpath(so.PANEL_DIR))))
    _service_findings(res, props, facts)


# ── R18: resources, descriptors, the cgroup's other processes ────────────────────────────────────
PROC = "/proc"
_COMM_ALLOW = frozenset(("python3", "python", "ssh", "bash", "sh", "sudo", "tmux: server", "tmux",
                         "systemd-run", "journalctl", "git", "ufw", "fail2ban-client", "tailscale",
                         "timeout", "node", "gamedig"))
MAX_PIDS = 200


def _proc_status():
    """{VmRSS, VmHWM (kB ints), Threads} from /proc/self/status."""
    out = {}
    with open(os.path.join(PROC, "self", "status"), encoding="ascii", errors="replace") as fh:
        for line in fh:
            key, _, val = line.partition(":")
            if key in ("VmRSS", "VmHWM", "Threads"):
                out[key] = int(val.split()[0])
    return out


def _fd_kind(target):
    for prefix, kind in (("socket:", "sockets"), ("pipe:", "pipes"), ("/dev/pts/", "ptys"),
                         ("/dev/ptmx", "ptys"), ("anon_inode:", "anon")):
        if target.startswith(prefix):
            return kind
    return "files"


def _fd_counts(limit):
    """{kind: count} of this process's descriptors, readlinks capped at `limit`. Never the targets."""
    counts = {}
    fd_dir = os.path.join(PROC, "self", "fd")
    for i, name in enumerate(os.listdir(fd_dir)):
        if i >= limit:
            break
        try:
            kind = _fd_kind(os.readlink(os.path.join(fd_dir, name)))
        except OSError:
            continue
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _nofile():
    import resource
    soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    return soft if 0 < soft < 1 << 20 else 1 << 20


def _cgroup_path():
    """The cgroup v2 path of the process, or None on cgroup v1 / outside one."""
    with open(os.path.join(PROC, "self", "cgroup"), encoding="ascii", errors="replace") as fh:
        for line in fh:
            if line.startswith("0::"):
                return line[3:].strip() or None
    return None


def _uptime():
    with open(os.path.join(PROC, "uptime"), encoding="ascii") as fh:
        return float(fh.read().split()[0])


def _pid_info(pid, uptime, hz, me):
    """{comm, state, age, cpu, owner} of one pid from /proc/<pid>/stat: comm only, never cmdline."""
    base = os.path.join(PROC, str(pid))
    with open(os.path.join(base, "stat"), encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    comm = raw[raw.index("(") + 1:raw.rindex(")")]
    rest = raw[raw.rindex(")") + 2:].split()
    age = max(uptime - int(rest[19]) / hz, 0.001)
    cpu = (int(rest[11]) + int(rest[12])) / hz
    uid = os.stat(base).st_uid
    return {"comm": comm if comm in _COMM_ALLOW else "other", "state": rest[0], "age": age,
            "cpu_pct": 100.0 * cpu / age,
            "owner": "panel" if uid == me else "root" if uid == 0 else "other"}


def _cgroup_others(path):
    """The OTHER processes in this cgroup, at most MAX_PIDS; a pid that vanished is skipped."""
    with open("/sys/fs/cgroup" + path + "/cgroup.procs", encoding="ascii") as fh:
        pids = [int(p) for p in fh.read().split()[:MAX_PIDS + 1]]
    me, hz, up = os.geteuid(), os.sysconf("SC_CLK_TCK"), _uptime()
    out = []
    for pid in pids:
        if pid == os.getpid():
            continue
        try:
            out.append(_pid_info(pid, up, hz, me))
        except (OSError, ValueError, IndexError):
            continue
    return out[:MAX_PIDS]


def _group_procs(procs):
    """'ssh ×2 (up 4 s), other ×1 (up 3 h, R, 98% CPU, root)': comm from the allowlist only."""
    groups = {}
    for p in procs:
        groups.setdefault((p["comm"], p["owner"]), []).append(p)
    parts = []
    for (comm, owner), ps in sorted(groups.items()):
        oldest = max(ps, key=lambda q: q["age"])
        extra = [] if owner == "panel" else [owner]
        if oldest["state"] in ("R", "D", "Z"):
            extra.append(oldest["state"])
        if oldest["cpu_pct"] >= 50:
            extra.append("%d%% CPU" % oldest["cpu_pct"])
        parts.append("%s ×%d (up %s%s)" % (comm, len(ps), ago(oldest["age"]),
                                          "".join(", " + e for e in extra)))
    return ", ".join(parts)


def _cgroup_line(res):
    try:
        path = _cgroup_path()
        if not path or not path.endswith("/" + _src_systemd.UNIT):
            res.add("- **Other processes in the panel's cgroup**: unavailable (cgroup v1, or not "
                    "running under the panel's unit)")
            return
        procs = _cgroup_others(path)
    except (OSError, ValueError) as exc:
        res.add(unread_line("Other processes in the panel's cgroup", exc))
        return
    res.add("- **Other processes in the panel's cgroup**: %d%s"
            % (len(procs), (": " + _group_procs(procs)) if procs else ""))
    zombies = sum(1 for p in procs if p["state"] == "Z")
    res.add("- **Zombie processes in the cgroup**: %d" % zombies)
    if zombies:
        res.find("warn", AREA, "zombie processes in the panel's cgroup (children not reaped)")


def _resource_lines(ctx, res, facts):
    """R18: RSS and peak, threads, nice, CPU, descriptors by kind, the cgroup's other processes."""
    st, t = _proc_status(), os.times()
    res.add("- **Process**: RSS %d MB (VmHWM %d MB) · threads %d · nice %d · CPU %s user / %s sys"
            % (st.get("VmRSS", 0) // 1024, st.get("VmHWM", 0) // 1024, st.get("Threads", 0),
               os.getpriority(os.PRIO_PROCESS, 0), ago(t.user), ago(t.system)))
    limit = _nofile()
    try:
        fds = _fd_counts(limit)
        res.add("- **File descriptors**: %d of %d (%s)" % (
            sum(fds.values()), limit,
            ", ".join("%s %d" % (k, fds[k]) for k in sorted(fds)) or "none"))
    except OSError as exc:
        res.add(unread_line("File descriptors", exc))
    _cgroup_line(res)


# ── R17: the eventlet runtime ────────────────────────────────────────────────────────────────────
_PATCHABLE = ("os", "select", "socket", "thread", "time")


def _eventlet_server(ctx):
    """(text, hub) for the Server line, or None when eventlet is not patching this process.

    The text reads 'Flask-SocketIO async_mode=eventlet · eventlet 0.41.2 · hub epolls ·
    monkey-patched 5/5'. The hub is read from eventlet's thread-local, never get_hub(), which would
    create one in a thread that has none.
    """
    ev = sys.modules.get("eventlet")
    patcher = sys.modules.get("eventlet.patcher")
    if ev is None or patcher is None or not patcher.is_monkey_patched("thread"):
        return None
    sio = getattr(ctx.app, "socketio", None) if ctx.app is not None else None
    mode = getattr(getattr(sio, "server", None), "async_mode", None) or getattr(sio, "async_mode", None)
    hub = getattr(getattr(sys.modules.get("eventlet.hubs"), "_threadlocal", None), "hub", None)
    hub_name = type(hub).__module__.rsplit(".", 1)[-1] if hub is not None else "none yet"
    patched = sum(1 for m in _PATCHABLE if patcher.is_monkey_patched(m))
    return ("Flask-SocketIO async_mode=%s · eventlet %s · hub %s · monkey-patched %d/%d"
            % (_tok(mode, "unknown"), _tok(getattr(ev, "__version__", None), "unknown"),
               _tok(hub_name), patched, len(_PATCHABLE)), hub)


def _hub_counts(hub):
    """'listeners read 14 / write 0 · timers 52 · tpool 20 threads, 0 queued'.

    The internals are private: every read is a getattr with a default and a len().
    """
    try:
        listeners = getattr(hub, "listeners", {}) or {}
        timers = len(getattr(hub, "timers", ()) or ()) + len(getattr(hub, "next_timers", ()) or ())
        text = "listeners read %d / write %d · timers %d" % (
            len(listeners.get("read", {})), len(listeners.get("write", {})), timers)
    except (AttributeError, TypeError):
        text = "listeners/timers unavailable (eventlet API changed)"
    tp = sys.modules.get("eventlet.tpool")
    try:
        reqq = getattr(tp, "_reqq", None)
        text += " · tpool %d threads, %s queued" % (
            len(getattr(tp, "_threads", ()) or ()), reqq.qsize() if reqq is not None else "0")
    except (AttributeError, TypeError):
        text += " · tpool internals unavailable (eventlet API changed)"
    return text


def recent_lag(now):
    """The worst lag recorded in the current minute and the four before it (0.0 when none)."""
    cur = int(now // 60)
    recent = [v[1][1] for v in runtime_stats.snapshot("hub_lag").values()
              if isinstance(v, tuple) and isinstance(v[1], tuple) and v[1][0] >= cur - 4]
    return max(recent) if recent else 0.0


def _lag_text(res, now=None):
    """'max 2.4 s at 13:02:11Z since start; max 0.01 s in the last 5 min' from runtime_stats."""
    now = time.time() if now is None else now
    hub = runtime_stats.snapshot("hub")
    if "ticks" not in hub:
        return "not measured (the lag watch runs only in a process app.py started under eventlet)"
    at, worst = hub.get("lag_max") or (None, 0.0)
    last_5 = recent_lag(now)
    text = "max %.2f s%s since start; max %.2f s in the last 5 min" % (
        worst, (" at %s" % time.strftime("%H:%M:%SZ", time.gmtime(at))) if at else "", last_5)
    if now - hub["ticks"][0] > 10:
        text += " · the watch has not ticked for %s" % ago(now - hub["ticks"][0])
        res.find("warn", AREA, "the hub-lag watch stopped ticking")
    if last_5 >= _LAG_TICK:
        res.find("warn", AREA, "the eventlet hub was blocked for a full second or more in the "
                               "last 5 minutes")
    return text


def _socket_counts():
    """'3 (console viewers on 2 servers) · terminal sessions 1 of 12': counts only, no ids."""
    sf = sys.modules.get("panel.routes.server_files")
    term = sys.modules.get("panel.ops.terminal_session")
    parts = []
    if sf is not None:
        viewers = dict(getattr(sf, "_console_viewers", {}) or {})
        parts.append("%d (console viewers on %d servers)" % (
            len(getattr(sf, "_socket_addrs", {}) or {}), sum(1 for v in viewers.values() if v)))
    else:
        parts.append("socket registry not loaded")
    if term is not None:
        parts.append("terminal sessions %d of %d" % (len(getattr(term, "_sessions", {}) or {}),
                                                     getattr(term, "_MAX_SESSIONS_TOTAL", 0)))
    return " · ".join(parts)


def _hub_lines(ctx, res, facts):
    """R17: async mode, eventlet version, patching, hub/tpool counts, lag, live sockets."""
    server = _eventlet_server(ctx)
    if server is None:
        res.add("- **Server**: eventlet not active (process not started by app.py)")
        return
    text, hub = server
    res.add("- **Server**: " + text)
    res.add("- **Hub**: " + (_hub_counts(hub) if hub is not None else "no hub in this thread"))
    lag = _lag_text(res)
    facts["lag"] = lag
    res.add("- **Hub lag**: " + lag)
    res.add("- **Live sockets**: " + _socket_counts())


# ── R19: where the process listens, against the config ───────────────────────────────────────────
def _bindv6only():
    try:
        with open(os.path.join(PROC, "sys", "net", "ipv6", "bindv6only"), encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def _listen_text(rows, scheme):
    shown = []
    for r in sorted(rows, key=lambda r: (r["family"], r["port"])):
        cls = _src_net.addr_class(r["addr"])
        addr = r["addr"] if cls in ("loopback", "wildcard") else "[%s]" % cls
        addr = "[%s]" % addr if r["family"] == 6 and not addr.startswith("[") else addr
        note = cls
        if r["family"] == 6 and cls == "wildcard":
            note += ", bindv6only=%s" % _bindv6only()
        shown.append("%s:%d (%s)" % (addr, r["port"], note))
    return "%s, held by this process · %s" % (", ".join(shown) or "nothing", scheme)


def _listen_lines(ctx, res, facts):
    """R19: this process's LISTEN sockets against the configured and the boot bind and port."""
    conf = _app_config(ctx)
    cfg, readable = _load_cfg()
    boot_bind, boot_port = conf.get("BOOT_BIND", conf.get("_BOOT_BIND")), conf.get("BOOT_PORT")
    tls = conf.get("BOOT_TLS")
    scheme = "HTTPS" if tls else "plain HTTP" if tls is False else "scheme unknown (no boot record)"
    try:
        rows = ctx.memo("net_listening", _src_net.listening)
        res.add("- **Listening**: " + _listen_text(rows, scheme))
    except OSError as exc:
        res.add("- **Listening**: unknown (/proc/net/tcp unreadable: %s)" % type(exc).__name__)
    if not readable:
        res.add("- **Bind**: config.json could not be read · bound at boot %s"
                % (_src_net.shown(boot_bind) if boot_bind else "unknown (no boot record)"))
        return
    stored = (cfg.get("bind_host") or "").strip()
    res.add("- **Bind**: config %s · bound at boot %s · port: config %s / boot %s" % (
        _src_net.shown(stored) if stored else "auto", _src_net.shown(boot_bind) if boot_bind
        else "unknown (no boot record)", cfg.get("port", 5000), boot_port or "unknown"))
    _restart_pending(res, facts, stored, boot_bind, (cfg.get("port", 5000), boot_port))


def _restart_pending(res, facts, stored, boot_bind, ports):
    loop_now = _src_net.addr_class(boot_bind) == "loopback" if boot_bind else None
    if boot_bind and stored and _src_net.addr_class(stored) == "loopback" and not loop_now:
        res.add("- **RESTART PENDING**: listening beyond loopback, but config.json now says "
                "loopback (the panel still answers on its other addresses)")
        res.find("warn", AREA, "restart pending: still listening beyond loopback")
        facts["pending"] = True
    if ports[1] is not None and str(ports[0]) != str(ports[1]):
        res.add("- **RESTART PENDING**: config.json's port differs from the port bound at boot")
        res.find("warn", AREA, "restart pending: the configured port is not the one bound")
        facts["pending"] = True


# ── R20: the boot transport record ───────────────────────────────────────────────────────────────
def _serving_line(conf):
    if "BOOT_TLS" not in conf:
        return "unknown (no boot record)"
    if conf.get("BOOT_TLS"):
        return "HTTPS (self-signed, terminated by the panel) since boot"
    err = conf.get("BOOT_TLS_ERROR")
    if err:
        return ("HTTP. Self-signed HTTPS was configured but FAILED to start (%s). Serve and the "
                "Secure cookie flag may still assume HTTPS" % _tok(err, "error"))
    return "HTTP since boot"


def _scheme_line(conf, cfg):
    """'process serves http · routes point Serve at http ✓ · cookies Secure: yes'."""
    serves = "https" if conf.get("BOOT_TLS") else "http"
    mod = _app_module()
    try:
        backend = mod._ts_backend_scheme(cfg) if mod is not None else None
    except Exception:  # noqa: BLE001 - a scheme that cannot be worked out is said to be unknown
        backend = None
    want = "https+insecure" if serves == "https" else "http"
    mark = "" if backend is None else (" ✓" if backend == want else " ✗ MISMATCH")
    return "process serves %s · routes would point Serve at %s%s · session cookie Secure: %s" % (
        serves, backend or "unknown", mark, _yn(conf.get("SESSION_COOKIE_SECURE"))), mark


def _boot_lines(ctx, res, facts):
    """R20: whether TLS really started, the boot Serve re-point, and scheme agreement."""
    conf = _app_config(ctx)
    res.add("- **Serving**: " + _serving_line(conf))
    serve = conf.get("BOOT_SERVE")
    res.add("- **Serve re-point at boot**: %s" % (
        "unknown (no boot record)" if serve is None else re.sub(r"[^A-Za-z0-9:_ .+-]", "", serve)[:60]))
    if conf.get("BOOT_TLS_ERROR") and not conf.get("BOOT_TLS"):
        res.find("fail", AREA, "HTTPS was configured but failed to start at boot")
    if isinstance(serve, str) and serve.startswith("failed"):
        res.find("warn", AREA, "the boot-time Tailscale Serve re-point failed")
    if "BOOT_TLS" not in conf:
        return
    cfg, readable = _load_cfg()
    if not readable:
        res.add("- **Scheme agreement**: config.json could not be read")
        return
    text, mark = _scheme_line(conf, cfg)
    res.add("- **Scheme agreement**: " + text)
    if "MISMATCH" in mark and cfg.get("tailscale_setup_done"):
        res.find("warn", AREA, "Serve's backend scheme does not match what the process serves")


# ── R21: the unit file and drop-ins against install.sh ───────────────────────────────────────────
# install.sh's render_service_unit and ensure_service_tuning, mirrored WITH their shell placeholders
# so tests/unit (part22) can hold them byte-equal to install.sh's heredocs. Never sourced or run.
UNIT_TEMPLATES = {
    "system": """[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target
# Keep auto-restarting no matter how many times it has crashed — a self-healing
# appliance should keep trying to recover rather than give up and stay down.
StartLimitIntervalSec=0

[Service]
Type=simple
User=${PANEL_USER}
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
""",
    "user": """[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target
# Keep auto-restarting no matter how many times it has crashed — a self-healing
# appliance should keep trying to recover rather than give up and stay down.
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
""",
}
PRIORITY_CONF = """[Service]
Nice=10
CPUWeight=30
IOSchedulingClass=best-effort
IOSchedulingPriority=6
"""
_DROPIN_NAME_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}\.conf\Z")


def render_unit(scope, user, panel_dir):
    """install.sh's unit text for `scope`, rendered in Python."""
    return (UNIT_TEMPLATES[scope].replace("${PANEL_USER}", user)
            .replace("${PANEL_DIR}", panel_dir))


def directives(text):
    """{(section, Name): [values]} of a unit file's text; comments and blank lines ignored."""
    out, section = {}, ""
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s
            continue
        name, sep, value = s.partition("=")
        if sep:
            out.setdefault((section, name.strip()), []).append(value.strip())
    return out


def differing(actual, expected):
    """The directive NAMES whose values differ between two unit texts (never the values)."""
    a, e = directives(actual), directives(expected)
    return sorted({k[1] for k in set(a) | set(e) if a.get(k) != e.get(k)})


def _unit_file(scope):
    return (_src_systemd.SYSTEM_UNIT_FILE if scope == "system"
            else os.path.expanduser(_src_systemd.USER_UNIT_FILE))


def _unit_line(scope):
    try:
        with open(_unit_file(scope), encoding="utf-8") as fh:
            actual = fh.read()
    except FileNotFoundError:
        return "none at the expected path", False
    except OSError as exc:
        return "could not be read (%s)" % type(exc).__name__, False
    want = render_unit(scope, _account_name() if scope == "system" else "", so.PANEL_DIR)
    if actual == want:
        return "byte-identical to install.sh's render", True
    names = differing(actual, want)
    if not names:
        return "differs from install.sh's render in comments or spacing only", True
    return "DIFFERS from install.sh's render (an update rewrites it): %s" % ", ".join(names), False


def _dropin_text(path):
    name = os.path.basename(path)
    shown = name if _DROPIN_NAME_RE.match(name) else "a drop-in"
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return "%s (could not be read: %s)" % (shown, type(exc).__name__)
    if name == "priority.conf":
        diff = differing(text, PRIORITY_CONF)
        return "priority.conf (%s)" % ("matches" if not diff else "differs: " + ", ".join(diff))
    names = sorted({k[1] for k in directives(text)})
    return "%s (sets: %s; values not shown)" % (shown, ", ".join(_tok(n, "?") for n in names)
                                                 or "nothing")


def _drift_lines(ctx, res, facts):
    """R21: the unit file against install.sh's render, and every drop-in by name."""
    unit = facts.get("unit") or {}
    scope = unit.get("scope")
    if scope is None:
        res.add("- **Unit file**: none at either path")
        return
    text, ok = _unit_line(scope)
    res.add("- **Unit file**: " + text)
    if not ok:
        res.find("warn", AREA, "the unit file is not what install.sh writes")
    paths = (unit.get("props") or {}).get("DropInPaths", "").split()
    res.add("- **Drop-ins**: %s" % ("; ".join(_dropin_text(p) for p in paths) if paths else
                                    "none" if not unit.get("error") else "unknown (systemd unread)"))


# ── the section ──────────────────────────────────────────────────────────────────────────────────
_PARTS = (("Service", _service_lines), ("Process resources", _resource_lines),
          ("Server", _hub_lines), ("Listening", _listen_lines), ("Boot transport", _boot_lines),
          ("Unit file", _drift_lines))


def _verdict(facts):
    bits = []
    unit = facts.get("unit") or {}
    if unit.get("error"):
        bits.append("systemd state unread")
    else:
        bits.append("the unit's MainPID" if facts.get("mainpid_is_me") else "NOT the unit's MainPID")
        bits.append("%s automatic restarts" % ("?" if facts.get("restarts") is None
                                               else facts.get("restarts")))
    if facts.get("pending"):
        bits.append("restart pending")
    return "Panel process: " + ", ".join(bits)


def section_process(ctx):
    """R15, R18, R17, R19, R20, R21: one part's failure is printed as unread, never fatal."""
    res, facts = Result(), {"mainpid_is_me": False, "restarts": None}
    for title, part in _PARTS:
        try:
            part(ctx, res, facts)
        except Exception as exc:  # noqa: BLE001 - reported by class, the rest still prints
            res.add(unread_line(title, exc))
            res.find("unread", AREA, "%s could not be read" % title.lower())
    res.verdict = _verdict(facts)
    return res
