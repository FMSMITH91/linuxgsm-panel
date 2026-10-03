"""Part 24 of the unit suite: the debug report's cross-builder contracts, run as real pairs.

Four builders wrote the report's sections against stubs of each other's sources. This part feeds
each consumer the PRODUCER's real output, built by the producer's own code from a faked command or
a throwaway file, so a shape that one side changed and the other did not fails here by name:

  1. `systemctl show` (_src_systemd.unit_show)  -> Diagnostics' Service check, Panel process
  2. Tailscale (tailscale_integration -> _src_tailscale)  -> Network, Hosts' peers, the privacy pass
  3. SQLite (_src_db.run_ro / integrity)  -> Sign-ins, the Database section, Diagnostics
  4. app.config's boot record (app.py)  -> Config, Diagnostics' TLS check, Panel process, header
  5. runtime_stats groups: every group a section reads is written somewhere, and the reverse
  6. the panel jail's health: ONE test, shared by the self-heal and the report

HOW IT RUNS. No command runs and nothing leaves the process: every CLI is a fake on the module that
calls it, the databases are temp files, and every patched attribute and cache is restored in the
finally at the bottom.
"""
import ast as _ast24
import glob as _glob24
import json as _json24
import os
import re as _re24
import sqlite3 as _sql24
import subprocess as _sp24  # nosec B404 - for TimeoutExpired only; nothing is run
import tempfile as _tf24
import time as _time24

from flask import Flask as _Flask24

from unit.part01 import check, eq
import app as _app24
from panel.ops import system_ops as _so24
from panel.ops import tailscale_integration as _ts24
from panel.ops.debug_report import _src_db as _db24
from panel.ops.debug_report import _src_systemd as _sd24
from panel.ops.debug_report import _src_tailscale as _st24
from panel.ops.debug_report import config_section as _cs24
from panel.ops.debug_report import data as _data24
from panel.ops.debug_report import diagnostics as _diag24
from panel.ops.debug_report import header as _hd24
from panel.ops.debug_report import hosts as _h24
from panel.ops.debug_report import network as _nw24
from panel.ops.debug_report import privacy as _pv24
from panel.ops.debug_report import process as _proc24
from panel.ops.debug_report._base import Ctx as _Ctx24
from panel.ops.debug_report._base import Result as _Result24

_TMP24 = _tf24.mkdtemp(prefix="lgsm-unit-p24-")
_REPO24 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SAVED24 = []
_TS_CACHE24 = dict(_ts24._cache)
_DB_CACHE24 = dict(_db24._cache)


def _p24(owner, name, value):
    """owner.name = value until the finally at the bottom."""
    _SAVED24.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _text24(res):
    return "\n".join(res.lines)


# ══ 1. `systemctl show` -> Diagnostics' Service check and Panel process ═════════════════════════
_SHOW24 = "\n".join((
    "ActiveState=active", "SubState=running", "UnitFileState=enabled", "MainPID=%d" % os.getpid(),
    "NRestarts=0", "Result=success", "NeedDaemonReload=no", "WorkingDirectory=" + _so24.PANEL_DIR,
    "LoadState=loaded", "FragmentPath=/etc/systemd/system/linuxgsm-panel.service", "DropInPaths=",
    "MemoryPeak=[not set]", "KillMode=mixed", "MemoryCurrent=123456", "TasksCurrent=9",
    "ActiveEnterTimestamp=Thu 2026-10-01 12:00:00 UTC")) + "\n"


def _systemd_pair():
    runs = []

    def _run(cmd, timeout):
        runs.append(list(cmd))
        return _SHOW24, "", 0

    def _timeout(cmd, timeout):
        raise _sp24.TimeoutExpired(cmd, timeout)
    _p24(_so24, "_is_system_service", lambda: True)
    _p24(_so24, "_USER_UNIT", os.path.join(_TMP24, "no-user.service"))
    _p24(_so24, "_SYSTEM_UNIT", os.path.join(_TMP24, "no-system.service"))
    _p24(_sd24, "run", _run)
    ctx = _Ctx24()
    diag = _so24._diag_service(_diag24.shared_unit(ctx))
    res, facts = _Result24(), {"mainpid_is_me": False, "restarts": None}
    _proc24._service_lines(ctx, res, facts)
    check("contract systemd -> Diagnostics: unit_show's real answer reads as an enabled, running "
          "system unit that is this process",
          diag[0] == "ok" and "system unit · enabled · active (running) · MainPID is this process: "
          "yes" in diag[1], repr(diag))
    check("contract systemd -> Panel process: the same answer, and ONE `systemctl show` for both",
          len(runs) == 1 and facts["mainpid_is_me"] is True and facts["restarts"] == 0
          and "system unit · active (running)" in _text24(res), repr((runs, facts, res.lines)))
    _p24(_sd24, "run", _timeout)
    failed = _so24._diag_service(_sd24.unit_show())
    check("contract systemd -> Diagnostics: a failed read names WHY (unit_show's `why`), not its "
          "constant `error` word", failed[0] == "warn"
          and "systemd state unreadable (timeout)" in failed[1], repr(failed))


# ══ 2. Tailscale -> Network (R36), Hosts' peers (R49), the privacy pass (R72) ═══════════════════
def _me24():
    import pwd
    return pwd.getpwuid(os.geteuid()).pw_name


_STATUS24 = {
    "BackendState": "Running", "TailscaleIPs": ["100.77.0.31"],
    "MagicDNSSuffix": "tail7731ab.ts.net",
    "CurrentTailnet": {"Name": "canarytailnet7731"}, "Health": ["canary health text 7731"],
    "Self": {"HostName": "canarynode", "DNSName": "canarynode.tail7731ab.ts.net.",
             "KeyExpiry": "2099-01-01T00:00:00Z"},
    "User": {"1": {"LoginName": "canarylogin7731@example.com", "DisplayName": "Canaryperson7731"}},
    "Peer": {"k1": {"HostName": "canarypeer7731", "DNSName": "canarypeer7731.tail7731ab.ts.net.",
                    "TailscaleIPs": ["100.77.0.32"], "OS": "linux", "Online": True,
                    "CurAddr": "198.51.100.77:41641"},
             "k2": {"HostName": "canaryrelay7731", "DNSName": "canaryrelay7731.tail7731ab.ts.net.",
                    "TailscaleIPs": ["100.77.0.33"], "OS": "linux", "Online": True, "CurAddr": "",
                    "Relay": "fra"}}}


def _fake_ts(calls):
    prefs = {"RouteAll": False, "OperatorUser": _me24(), "RunSSH": False}

    def _run_ts(args, timeout=5):
        calls.append(" ".join(args))
        if args[:1] in (["version"], ["--version"]):
            return "1.76.1\n  tailscale commit: abc", "", 0
        if args == ["status", "--json"]:
            return _json24.dumps(_STATUS24), "", 0
        if args == ["debug", "prefs"]:
            return _json24.dumps(prefs), "", 0
        if args == ["serve", "status"]:
            return ("https://canarynode.tail7731ab.ts.net (tailnet only)\n"
                    "|-- / proxy http://127.0.0.1:5000"), "", 0
        return "", "unexpected", 1
    return _run_ts


def _ts_network(state, v):
    head = _nw24._ts_head(v) if state == "ok" else ""
    wanted = ("panel account is the operator: yes", "health warnings 1")
    check("contract tailscale -> Network: the status/prefs JSON is kept, so key expiry, health and "
          "the operator are read, not 'not recorded'",
          v["extras_recorded"] is True and "not recorded" not in head
          and all(w in head for w in wanted), repr((state, head)))


def _ts_hosts(hosts_view):
    peers = (hosts_view or {}).get("peers") or []
    texts = [_h24.peer_text(_h24.match_peer(n, peers))
             for n in ("canarypeer7731", "canaryrelay7731")]
    kept = repr(peers)
    check("contract tailscale -> Hosts: a peer's direct/relayed path is read from the peer dict "
          "('direct' from CurAddr), never 'path unknown', and CurAddr itself is not kept",
          texts[0].startswith("online yes · direct") and "DERP-relayed" in texts[1]
          and "CurAddr" not in kept and "198.51.100.77" not in kept, repr(texts))


_TS_NAMES24 = ("canarynode", "canarypeer7731", "canaryrelay7731", "canarytailnet7731",
               "canarylogin7731", "Canaryperson7731", "tail7731ab")


def _ts_privacy(ctx, st):
    ctx._memo["privacy"] = (True, st)
    probe = ("node canarynode, peers canarypeer7731 and canaryrelay7731 in canarytailnet7731, user "
             "canarylogin7731@example.com (Canaryperson7731), suffix tail7731ab.ts.net")
    out = _pv24.scrub(ctx, probe).lower()
    check("contract tailscale -> privacy: every name in the real reading (node, peers, tailnet, "
          "logins, display names, MagicDNS suffix) is pseudonymised",
          not [c for c in _TS_NAMES24 if c.lower() in out], out)


def _tailscale_pair():
    calls, reads = [], []
    real_read = _st24.read
    _p24(_ts24, "_run_ts", _fake_ts(calls))
    _p24(_st24, "read", lambda: reads.append(1) or real_read())
    _ts24._cache.update(info=None, ts=0)
    ctx = _Ctx24()
    hosts_view = _h24.ts_info(ctx)             # a stale cache: the report's one shared read
    state, v = _st24.shared_read(ctx)          # what Network reads
    st = _pv24._State()
    _pv24._tailscale_names(ctx, st, 5.0)       # what the privacy pass reads
    eq("contract tailscale: Hosts, Network and the privacy pass share ONE reading (one read(), one "
       "`tailscale status`)", (len(reads), calls.count("status --json")), (1, 1))
    _ts_network(state, v or {"extras_recorded": None})
    _ts_hosts(hosts_view)
    _ts_privacy(ctx, st)


# ══ 3. SQLite -> Sign-ins (R43), the Database section (R57/R58), Diagnostics (R12) ══════════════
def _schema24(name):
    from sqlalchemy import create_engine
    from panel.db.models import db as _mdb
    path = os.path.join(_TMP24, name)
    engine = create_engine("sqlite:///" + path)
    _mdb.metadata.create_all(engine)
    engine.dispose()
    return path


def _db_signins():
    path = _schema24("counts.db")
    now = _time24.strftime("%Y-%m-%d %H:%M:%S", _time24.gmtime())
    with _sql24.connect(path) as cx:
        for ip in ("203.0.113.5", "100.100.1.1", "10.1.2.3"):
            cx.execute("INSERT INTO audit_log (username, action, ip_address, timestamp, success) "
                       "VALUES ('u', 'login_failed', ?, ?, 0)", (ip, now))
        cx.execute("INSERT INTO audit_log (username, action, ip_address, timestamp, success) "
                   "VALUES ('u', 'login', '1.1.1.1', ?, 1)", (now,))
    cx.close()
    _p24(_db24, "_db_path", lambda: path)
    res, facts = _Result24(), {}
    _nw24._signin_lines(res, _db24.run_ro(_nw24.signin_queries(), timeout=10), facts)
    text = _text24(res)
    check("contract _src_db.run_ro -> Sign-ins: the real rows are counted, sources classified",
          "ok 1/1 · failed 3/3" in text and "3 distinct (public 1 · tailnet 1 · private 1" in text
          and facts.get("audit_fail_24h") == 3 and not res.findings, text)
    return path


def _integrity_pair(path):
    """(Database section lines, Diagnostics' verdict) from ONE real integrity check of `path`."""
    _p24(_db24, "_db_path", lambda: path)
    _db24._cache.update(key=None, res=None)
    ctx, res = _Ctx24(), _Result24()
    _data24._health_lines(ctx, res)
    return res.lines, _so24._diag_db_integrity(_diag24.shared_integrity(ctx), path)


def _db_pair():
    lines, verdict = _integrity_pair(_db_signins())
    check("contract _src_db.integrity -> Database section and Diagnostics: a healthy file reads ok "
          "in both, from one check", lines[:1] and lines[0].startswith("- **health**: ok")
          and verdict == ("ok", "No corruption detected."), repr((lines, verdict)))
    bad = os.path.join(_TMP24, "bad.db")
    with open(bad, "wb") as fh:
        fh.write(b"SQLite format 3\x00" + b"\x13" * 4096)
    lines, verdict = _integrity_pair(bad)
    check("contract _src_db.integrity -> Database section and Diagnostics: a damaged file with no "
          "backup is DAMAGED in one and 'starts EMPTY' in the other",
          "DAMAGED" in "\n".join(lines) and verdict[0] == "fail" and "starts EMPTY" in verdict[1],
          repr((lines, verdict)))
    _p24(_db24, "_db_path", lambda: os.path.join(_TMP24, "missing.db"))
    mres = _Result24()
    _nw24._signin_lines(mres, _db24.run_ro(_nw24.signin_queries()), {})
    check("contract _src_db.run_ro -> Sign-ins: a database that cannot be opened is 'not queryable "
          "(Class)', never 0", "audit log not queryable (FileNotFoundError)" in _text24(mres)
          and [f["level"] for f in mres.findings] == ["unread"], _text24(mres))


# ══ 4. app.py's boot record -> Config, Diagnostics' TLS, Panel process, the header ══════════════
def _boot(fail):
    fake = _Flask24("p24boot")

    def _cert(cert, key, domain):
        if fail:
            # its message carries a path, which the report must never print
            raise PermissionError("cannot write /home/canarypanelacct/secret/cert.pem")
    _p24(_app24, "_effective_https", lambda cfg: True)
    _p24(_app24, "_ensure_self_signed_cert", _cert)
    _app24._boot_ssl_args(fake, {}, "0.0.0.0", 5000)    # nosec B104 - a bind string, not a socket
    with fake.app_context():
        diag_tls = _so24._diag_tls(os.path.join(_TMP24, "no-data"))
        boot = _so24._boot_tls()
    return fake, diag_tls, boot


def _boot_pair():
    fake, diag_tls, boot = _boot(fail=True)
    ctx = _Ctx24(app=fake)
    texts = (_cs24._tls_text(ctx), _proc24._serving_line(fake.config))
    check("contract BOOT_TLS/BOOT_TLS_ERROR -> Config, Diagnostics, Panel process: a TLS start "
          "that failed is named by its CLASS in all three, and no path",
          boot == (False, "PermissionError")
          and texts[0] == "no (configured, but it failed to start: PermissionError)"
          and "FAILED to start (PermissionError)" in texts[1] and diag_tls[0] == "fail"
          and "PermissionError" in diag_tls[1]
          and "canarypanelacct" not in repr((texts, diag_tls)), repr((boot, texts, diag_tls)))
    fake, _diag_ok, boot = _boot(fail=False)
    ctx = _Ctx24(app=fake)
    check("contract BOOT_TLS -> Config and Panel process: TLS that started reads as yes",
          boot == (True, None) and _cs24._tls_text(ctx) == "yes"
          and _proc24._serving_line(fake.config).startswith("HTTPS"), repr(boot))
    _p24(_so24, "_is_git_checkout", lambda: True)
    _p24(_so24, "_git", lambda args, timeout=45: ("abc1234\n", "", 0) if args[0] == "rev-parse"
         else (" M app.py\n", "", 0))
    fake.config["PANEL_COMMIT"] = _so24.panel_commit()
    eq("contract PANEL_COMMIT -> header: panel_commit()'s dirty form is read as the running commit",
       _hd24._running_commit(_Ctx24(app=fake)), "abc1234+")


def _config_keys_read():
    """Every PANEL_COMMIT / BOOT_* name the report's modules read."""
    found = set()
    for path in _glob24.glob(os.path.join(_REPO24, "panel", "ops", "debug_report", "*.py")) + \
            [os.path.join(_REPO24, "panel", "ops", "system_ops.py")]:
        with open(path, encoding="utf-8") as fh:
            found |= set(_re24.findall(r"[\"'](PANEL_COMMIT|BOOT_[A-Z_]+)[\"']", fh.read()))
    return found


def _boot_keys_written():
    with open(os.path.join(_REPO24, "app.py"), encoding="utf-8") as fh:
        tree = _ast24.parse(fh.read())
    out = set()
    for node in _ast24.walk(tree):
        if isinstance(node, _ast24.Assign):
            for t in node.targets:
                if (isinstance(t, _ast24.Subscript) and isinstance(t.slice, _ast24.Constant)
                        and _ast24.unparse(t.value) == "app.config"):
                    out.add(t.slice.value)
    return out


# ══ 5. runtime_stats: what is read is written, and what is written is read ═════════════════════
_RS_NAMES = {"runtime_stats", "rs", "_rs"}
_RS_OWN_GROUP = {"beat": "heartbeat", "loop_started": "loop_start"}


def _is_rs(node):
    """Whether `node` is the runtime_stats module: an alias, or mod("panel.core.runtime_stats")."""
    if isinstance(node, _ast24.Name):
        return node.id in _RS_NAMES
    return (isinstance(node, _ast24.Call) and isinstance(node.func, _ast24.Name)
            and node.func.id == "mod" and len(node.args) == 1
            and isinstance(node.args[0], _ast24.Constant)
            and node.args[0].value == "panel.core.runtime_stats")


def _rs_group(node):
    """("read"|"written", group) for one runtime_stats call node, or None."""
    if not (isinstance(node, _ast24.Call) and isinstance(node.func, _ast24.Attribute)
            and _is_rs(node.func.value)):
        return None
    verb = node.func.attr
    if verb in _RS_OWN_GROUP:              # a writer with its own fixed group
        return "written", _RS_OWN_GROUP[verb]
    first = node.args[0] if node.args else None
    if verb in ("bump", "put", "snapshot") and isinstance(first, _ast24.Constant):
        return ("read" if verb == "snapshot" else "written"), first.value
    return None


def _rs_calls():
    """{"read": {group}, "written": {group}} over panel/ and app.py, by the AST."""
    out = {"read": set(), "written": set()}
    paths = _glob24.glob(os.path.join(_REPO24, "panel", "**", "*.py"), recursive=True)
    for path in paths + [os.path.join(_REPO24, "app.py")]:
        if path.endswith(os.path.join("core", "runtime_stats.py")):
            continue
        with open(path, encoding="utf-8") as fh:
            tree = _ast24.parse(fh.read())
        for got in filter(None, map(_rs_group, _ast24.walk(tree))):
            out[got[0]].add(got[1])
    return out


def _contract_gates():
    keys_read, keys_written = _config_keys_read(), _boot_keys_written()
    check("contract app.config: every PANEL_COMMIT/BOOT_* key a report module reads is assigned by "
          "app.py", keys_read and keys_read <= keys_written, repr(sorted(keys_read - keys_written)))
    rs = _rs_calls()
    gaps = (sorted(rs["read"] - rs["written"]), sorted(rs["written"] - rs["read"]))
    eq("contract runtime_stats: every group a section snapshots is written by some loop or hook, "
       "and every group written is read by a section", gaps, ([], []))
    from panel.ops.debug_report import _base
    undocumented = sorted(g for g in rs["written"] if not _re24.search(
        r"\n    %s +" % _re24.escape(g), _base.__doc__))
    eq("contract runtime_stats: every group written is listed in _base.py's CROSS-MODULE CONTRACTS",
       undocumented, [])


# ══ 6. the panel jail: ONE health test for the self-heal and the report ═════════════════════════
def _jail_pair():
    configured = []
    health = {k: True for k in ("port", "banaction", "logpath", "backend", "ignoreip", "filter")}
    health["allports"] = False
    _p24(_so24, "panel_fail2ban_status", lambda: {"installed": True, "enabled": True})
    _p24(_so24, "configure_panel_fail2ban",
         lambda auth_log, port, ignore=None: configured.append(port) or (True, "rewritten"))
    _p24(_so24, "panel_jail_health", lambda auth_log, port, ignore=None: dict(health))
    first = _so24.ensure_panel_fail2ban("/x/auth.log", 5000)
    health["filter"] = False
    second = _so24.ensure_panel_fail2ban("/x/auth.log", 5000)
    check("contract jail health: ensure_panel_fail2ban decides by panel_jail_health -- healthy is "
          "left alone, one stale check rewrites it",
          first[0] is True and "already active" in first[1] and configured == [5000]
          and second == (True, "rewritten"), repr((first, second, configured)))
    health["probe24"] = "the stub's own answer"
    eq("contract jail health: the report's Network section asks the same function",
       _nw24.panel_jail_health("/x/auth.log", 5000).get("probe24"), "the stub's own answer")


def _modes():
    import panel.ops.debug_report as _dr
    modes = {key: mode for key, _t, _m, mode, _p in _dr.SECTIONS}
    eq("contract runner: both Hosts sections run as workers -- on a stale cache they make the "
       "report's one Tailscale read (~20 s cold), which only a worker's deadline bounds",
       (modes.get("hosts_brief"), modes.get("hosts")), ("worker", "worker"))


try:
    for _fn24 in (_systemd_pair, _tailscale_pair, _db_pair, _boot_pair, _contract_gates,
                  _jail_pair, _modes):
        try:
            _fn24()
        except Exception as _e24:  # noqa: BLE001 - a crash fails by name, the next pair still runs
            check("contract checks: %s ran without raising" % _fn24.__name__, False, repr(_e24))
finally:
    while _SAVED24:
        _o24, _n24, _v24 = _SAVED24.pop()
        setattr(_o24, _n24, _v24)
    _ts24._cache.clear()
    _ts24._cache.update(_TS_CACHE24)
    _db24._cache.clear()
    _db24._cache.update(_DB_CACHE24)
