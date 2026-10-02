"""Part 22 of the unit suite: the debug report's process, install, network and notification sections.

Builder B3's: those sections and the errors one, their shared sources (systemd, tailscale, /proc/net),
and the runtime hooks app.py attaches for them: the log handlers and error counter, the hub-lag
watch, the boot record.

What is held here, besides each reader's answer: a section that cannot read something SAYS so
(never "none", 0 or "inactive"), and nothing identifying is printed (no host, address, account,
path, header value, chat id or topic). Every privileged read is shown not to run without the
helper or root.

Runs before part15, which must stay last. Nothing here reaches a host or the machine's own config:
every reader is stubbed on the module it is called through and restored in a `finally`, and the
only files read are fixtures in a temporary directory.
"""
import ast as _ast22
import contextlib as _ctx22
import io as _io22
import ipaddress as _ip22
import logging as _log22
import os
import queue as _q22
import shutil as _sh22
import sqlite3 as _sql22
import subprocess as _sp22  # nosec B404 - only its exception classes and constants are used here
import sys
import tempfile as _tf22
import threading as _thr22
import time as _time22
import urllib.error as _ue22

from flask import Flask as _Flask22

import app as _app22
from panel import REPO_ROOT as _ROOT22
from panel.core import runtime_stats as _rs22
from panel.core import middleware as _mw22
from panel.ops import system_ops as _so22
from panel.ops import tailscale_integration as _ts22
from panel.ops.debug_report import _base as _b22
from panel.ops.debug_report import _src_db as _db22
from panel.ops.debug_report import _src_net as _net22
from panel.ops.debug_report import _src_systemd as _sd22
from panel.ops.debug_report import _src_tailscale as _tsrc22
from panel.ops.debug_report import errors as _err22
from panel.ops.debug_report import install as _inst22
from panel.ops.debug_report import network as _nw22
from panel.ops.debug_report import notifications as _nsec22
from panel.ops.debug_report import process as _proc22
from panel.security import auth as _auth22
from panel.security import banlist as _bl22
from panel.security import privileged as _priv22
from panel.services import notifications as _notif22
from unit.part01 import check, eq

_TMP22 = _tf22.mkdtemp(prefix="lgsm-p22-")
_APP22 = _Flask22("p22")
_APP22.config.update(_TRUST_PROXY=False, BOOT_TLS=False)
_ABSENT22 = object()


@_ctx22.contextmanager
def _patched(owner, **attrs):
    """Set attributes on `owner` for the block, and put every one back after it."""
    saved = {k: owner.__dict__.get(k, _ABSENT22) if isinstance(owner, type(os)) else
             getattr(owner, k, _ABSENT22) for k in attrs}
    for k, v in attrs.items():
        setattr(owner, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is _ABSENT22:
                delattr(owner, k)
            else:
                setattr(owner, k, v)


def _ctx(deadline=20.0, app=_APP22):
    return _b22.Ctx(app=app, deadline_s=deadline)


def _text(res):
    return "\n".join(res.lines) + "\n" + repr(res.findings) + "\n" + str(res.verdict)


def _levels(res):
    return [f["level"] for f in res.findings]


def _w(name, content, mode="w"):
    path = os.path.join(_TMP22, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as fh:
        fh.write(content)
    return path


def _clear_groups(*names):
    for n in names:
        _rs22._GROUPS.pop(n, None)


# ══ _src_net: this process's LISTEN sockets, and an address only as its class ═══════════════════
eq("src_net: a /proc/net/tcp address decodes from host-order words (127.0.0.1:5000)",
   _net22._decode("0100007F:1388", 4), ("127.0.0.1", 5000))
eq("src_net: ...and a tcp6 one (::1:5000)",
   _net22._decode("00000000000000000000000001000000:1388", 6), ("::1", 5000))

_NETDIR22 = os.path.join(_TMP22, "fd")
os.makedirs(_NETDIR22)
os.symlink("socket:[4242]", os.path.join(_NETDIR22, "7"))
os.symlink("pipe:[17]", os.path.join(_NETDIR22, "8"))
_TCP_HEAD22 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
_TCP22 = _w("tcp", _TCP_HEAD22 +
            "   0: 0100007F:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 4242 1\n"
            "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0 0 999 1\n"
            "   2: 0100007F:1388 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000 0 4242 1\n")
_TCP6_22 = _w("tcp6", _TCP_HEAD22)
with _patched(_net22, PROC_NET_TCP={4: _TCP22, 6: _TCP6_22}, PROC_SELF_FD=_NETDIR22):
    _l22 = _net22.listening()
    with _patched(_net22, MAX_ROWS=0):
        _l22_capped = _net22.listening()
eq("src_net: only THIS process's LISTEN rows are kept (another owner's and an ESTABLISHED row are not)",
   [(r["addr"], r["port"], r["inode"]) for r in _l22], [("127.0.0.1", 5000, 4242)])
eq("src_net: the read stops at MAX_ROWS rows (a host with huge socket tables)", _l22_capped, [])
eq("src_net: an address is printed only as its class",
   [_net22.addr_class(a) for a in ("127.0.0.1", "::ffff:127.0.0.1", "0.0.0.0", "::",  # nosec B104
                                     "100.101.1.2", "fd7a:115c:a1e0::5", "10.1.2.3", "fe80::1%eth0",
                                     "8.8.4.4", "nonsense")],
   ["loopback", "loopback", "wildcard", "wildcard", "tailnet", "tailnet", "private", "private",
    "public", "not an address"])
eq("src_net: shown() keeps loopback literal and turns anything else into its class",
   (_net22.shown("127.0.0.1"), _net22.shown("8.8.4.4"), _net22.shown("100.64.0.9")),
   ("127.0.0.1", "[public]", "[tailnet]"))


# ══ _src_systemd: the ONE `systemctl show` ══════════════════════════════════════════════════════
class _FakeSp22:
    DEVNULL = _sp22.DEVNULL
    TimeoutExpired = _sp22.TimeoutExpired

    def __init__(self, stdout="", stderr="", rc=0, exc=None):
        self.calls, self.result, self.exc = [], (stdout, stderr, rc), exc

    def run(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.exc is not None:
            raise self.exc
        return type("R", (), {"stdout": self.result[0], "stderr": self.result[1],
                              "returncode": self.result[2]})()


_SHOW22 = ("ActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=%d\nNRestarts=2\n"
           "Result=success\nNeedDaemonReload=no\nMemoryCurrent=190840832\nMemoryPeak=[not set]\n"
           "TasksCurrent=31\nDropInPaths=\nFragmentPath=/etc/systemd/system/linuxgsm-panel.service\n"
           "WorkingDirectory=%s\nKillMode=control-group\nLoadState=loaded\nUnknownProp=x\n"
           % (os.getpid(), _so22.PANEL_DIR))
_fsp22 = _FakeSp22(stdout=_SHOW22)
with _patched(_sd22, subprocess=_fsp22), _patched(_so22, _is_system_service=lambda: True):
    _us22 = _sd22.unit_show(timeout=30)
_c22 = _fsp22.calls[0] if _fsp22.calls else ([], {})
check("src_systemd: one argv `systemctl show` (no shell, --no-pager, no --user for a system unit), "
      "stdin /dev/null, the timeout capped at 5 s",
      isinstance(_c22[0], list) and _c22[0][:2] == ["systemctl", "show"] and "--no-pager" in _c22[0]
      and "--user" not in _c22[0] and _c22[1].get("stdin") == _sp22.DEVNULL
      and _c22[1].get("timeout") == 5 and not _c22[1].get("shell"), repr(_c22))
check("src_systemd: props parsed; an unknown name, an empty value and '[not set]' are left out",
      _us22["scope"] == "system" and _us22["error"] is None and _us22["props"]["NRestarts"] == "2"
      and "MemoryPeak" not in _us22["props"] and "DropInPaths" not in _us22["props"]
      and "UnknownProp" not in _us22["props"], repr(_us22))
check("src_systemd: a user unit asks the user manager",
      "--user" in _sd22.argv("user") and "--user" not in _sd22.argv("system"))


def _show_fail(fake):
    with _patched(_sd22, subprocess=fake), _patched(_so22, _is_system_service=lambda: True):
        r = _sd22.unit_show()
    return (r["error"], r["why"], r["rc"], r["props"])


eq("src_systemd: a timeout is 'unreadable (timeout)', never an empty reading taken as fact",
   _show_fail(_FakeSp22(exc=_sp22.TimeoutExpired("systemctl", 5))), ("unreadable", "timeout", None, {}))
eq("src_systemd: no systemctl is 'unreadable (no-systemctl)'",
   _show_fail(_FakeSp22(exc=FileNotFoundError("systemctl"))), ("unreadable", "no-systemctl", None, {}))
eq("src_systemd: a missing user bus is 'no-bus' with its rc, and the stderr text is not kept",
   _show_fail(_FakeSp22(stderr="Failed to connect to bus: No medium found", rc=1)),
   ("unreadable", "no-bus", 1, {}))
with _patched(_so22, _is_system_service=lambda: False), \
        _patched(_sd22, USER_UNIT_FILE=os.path.join(_TMP22, "no-such.service")):
    eq("src_systemd: no unit file at either path is said, not probed", _sd22.unit_show()["why"],
       "no-unit-file")


# ══ _src_tailscale: the one cached reading ══════════════════════════════════════════════════════
def _ti(**kw):
    base = dict(installed=True, running=True, backend_state="Running", version="1.90.1",
                hostname="secret-node", dns_name="secret-node.tail9999.ts.net",
                tailscale_ips=["100.101.102.103"])
    base.update(kw)
    return _ts22.TailscaleInfo(**base)


_tsd22 = _tsrc22.as_dict(_ti())
check("src_tailscale: fields the panel's tailscale_integration does not keep read as None "
      "('not recorded'), never as False or empty",
      _tsd22["key_expiry"] is None and _tsd22["health"] is None and _tsd22["operator_user"] is None
      and _tsd22["extras_recorded"] is False, repr(_tsd22))
_ti_x22 = _ti()
_ti_x22.status_json = {"Self": {"KeyExpiry": "2030-01-01T00:00:00Z"}, "Health": ["a", "b"],
                       "MagicDNSSuffix": "tail9999.ts.net", "CurrentTailnet": {"Name": "me@github"},
                       "User": {"1": {"LoginName": "me@github", "DisplayName": "Me"}}}
_ti_x22.prefs_json = {"OperatorUser": "panel", "RunSSH": True}
_tsx22 = _tsrc22.as_dict(_ti_x22)
check("src_tailscale: ...and from the kept status/prefs JSON when it is there",
      _tsx22["key_expiry"] == "2030-01-01T00:00:00Z" and _tsx22["health"] == ["a", "b"]
      and _tsx22["operator_user"] == "panel" and _tsx22["run_ssh"] is True
      and _tsx22["tailnet_name"] == "me@github" and _tsx22["user_logins"] == ["me@github", "Me"],
      repr(_tsx22))
_tsk22 = []


def _gti22(force_refresh=False):
    _tsk22.append(force_refresh)
    return _ti()


with _patched(_ts22, get_tailscale_info=_gti22):
    _tsr22 = _tsrc22.read()
with _patched(_ts22, get_tailscale_info=lambda force_refresh=False: _ti(installed=False)):
    _tsa22 = (_tsrc22.read(), _tsrc22.info())


def _ts_boom(force_refresh=False):
    raise RuntimeError("tailscaled said something with secret-node in it")


with _patched(_ts22, get_tailscale_info=_ts_boom):
    _tse22 = (_tsrc22.read(), _tsrc22.info())
check("src_tailscale: read() reuses the 15 s cache (never force_refresh)",
      _tsr22[0] == "ok" and _tsk22 == [False], repr(_tsk22))
eq("src_tailscale: absent and unreadable are told apart by read(), and both are None to info()",
   (_tsa22, _tse22), ((("absent", None), None), (("error", "RuntimeError"), None)))


# ══ process: the hub-lag watch ══════════════════════════════════════════════════════════════════
_clear_groups("hub", "hub_lag")
_lst22 = {"ticks": 0, "max": -1.0, "minute": None, "minute_max": -1.0}
_proc22.lag_tick(_lst22, 2.5)
_proc22.lag_tick(_lst22, 0.25)
_hub22, _hl22 = _rs22.snapshot("hub"), _rs22.snapshot("hub_lag")
check("hub lag: each tick counts, the worst since start is kept, and the minute's worst is bucketed",
      _hub22.get("ticks", (0, 0))[1] == 2 and _hub22.get("lag_max", (0, 0))[1] == 2.5
      and any(v[1][1] == 2.5 for v in _hl22.values()), repr((_hub22, _hl22)))
check("hub lag: the last-5-minutes reader sees the bucket", _proc22.recent_lag(_time22.time()) == 2.5)


def _raise(*_a, **_k):
    raise RuntimeError("stats store broken")


with _patched(_rs22, put=_raise):
    try:
        _proc22.lag_tick(_lst22, 9.0)
        _lt_err22 = None
    except Exception as _e22:   # the finding
        _lt_err22 = repr(_e22)
eq("hub lag: a tick never raises into its loop, even when recording fails", _lt_err22, None)


class _Stop22(BaseException):
    pass


def _loop_run22():
    clock = iter([0.0, 1.5, 10.0, 11.0, 20.0, 20.0, 30.0])
    slept = []

    def sleep(s):
        slept.append(s)
        if len(slept) > 3:
            raise _Stop22()
    st = []
    with _patched(_proc22, lag_tick=lambda state, lag: st.append(round(lag, 3))):
        try:
            _proc22.hub_lag_loop(sleep, lambda: next(clock))
        except _Stop22:
            pass
    return slept[:3], st


eq("hub lag: the loop times a one-second sleep and records how late it woke",
   _loop_run22(), ([1.0, 1.0, 1.0], [0.5, 0.0, -1.0]))

_spawned22 = []
with _patched(_proc22, _HUB_LAG={"started": False}, _SPAWN=[lambda *a: _spawned22.append(a)]):
    _hs22 = (_proc22.start_hub_lag_watch(), _proc22.start_hub_lag_watch())
check("hub lag: started once under eventlet's thread patching; a second create_app starts nothing",
      _hs22 == (True, False) and len(_spawned22) == 1, repr((_hs22, _spawned22)))
import eventlet.patcher as _evp22  # noqa: E402
_spawned22 = []
with _patched(_proc22, _HUB_LAG={"started": False}, _SPAWN=[lambda *a: _spawned22.append(a)]), \
        _patched(_evp22, is_monkey_patched=lambda name: False):
    _hs22b = _proc22.start_hub_lag_watch()
check("hub lag: ...and never without thread patching (a CLI or test process)",
      _hs22b is False and not _spawned22)
class _RecThreading22:
    """Stands in for app.py's `threading`: records each Thread's target instead of starting it."""

    started = []

    class Thread:
        def __init__(self, target=None, args=(), daemon=None, name=None):
            self.target, self.args, self.daemon = target, args, daemon

        def start(self):
            _RecThreading22.started.append((self.target, self.daemon))


with _patched(_proc22, _HUB_LAG={"started": False}, _SPAWN=[None]), \
        _patched(_app22, _dr_process=_proc22, threading=_RecThreading22):
    _app22._start_hub_lag_watch()
check("hub lag: app.py's create_app hook starts it on a daemon thread from app.py's own `threading` "
      "(so a suite recording app.py's threads records this one, and never runs it)",
      _RecThreading22.started == [(_proc22.hub_lag_loop, True)], repr(_RecThreading22.started))
_clear_groups("hub", "hub_lag")

# ══ process: Serve's boot outcome as a fixed reason ═════════════════════════════════════════════
eq("serve reason: tailscale's failure text becomes a fixed class, the message is never kept",
   [_proc22.serve_reason(m) for m in (
       "Failed to configure Tailscale Serve: Serve is not enabled on your tailnet. To enable, "
       "visit: https://login.tailscale.com/f/serve?node=nXYZ",
       "Failed to configure Tailscale Serve: Access denied: serve config denied",
       "Failed to configure Tailscale Serve: failed to connect to local tailscaled; it doesn't "
       "appear to be running",
       "That isn't a usable mount point. Use \"/\" or a short path like \"/lgsm\".",
       "Failed to configure Tailscale Serve: something else at secret-node.tail9999.ts.net", None)],
   ["serve-not-enabled-on-tailnet", "permission", "not-running", "bad-mount", "other", "other"])


# ══ process: the unit's state (R15) ═════════════════════════════════════════════════════════════
def _svc(unit):
    res, facts = _b22.Result(), {"mainpid_is_me": False, "restarts": None}
    ctx = _ctx()
    ctx._memo["systemd_unit"] = (True, unit)
    _proc22._service_lines(ctx, res, facts)
    return res, facts


_props22 = _sd22.parse(_SHOW22)
_r22, _f22 = _svc({"scope": "system", "props": _props22, "error": None, "rc": 0, "why": None})
check("R15: the service line says whose MainPID, the restarts, memory n/a on an old systemd, and "
      "whether WorkingDirectory is this checkout, never the directory itself",
      "MainPID is this process: yes" in _text(_r22) and "Automatic restarts (systemd's NRestarts)**: 2"
      in _text(_r22) and "182 MB now, peak n/a" in _text(_r22) and "is this checkout**: yes"
      in _text(_r22) and _so22.PANEL_DIR not in _text(_r22) and "/etc/systemd" not in _text(_r22),
      _text(_r22))
check("R15: automatic restarts are a finding", any("restarted the panel automatically" in f["text"]
                                                   for f in _r22.findings), repr(_r22.findings))
with _patched(_proc22, _account_name=lambda: "zz-acct-p22"):
    _r22b, _ = _svc({"scope": "user", "props": dict(_props22, MainPID="1", NeedDaemonReload="yes"),
                     "error": None, "rc": 0, "why": None})
check("R15: another MainPID and a pending daemon-reload are findings; linger is looked up for a user "
      "unit and the account name is never printed",
      "MainPID is this process: no" in _text(_r22b) and "linger:" in _text(_r22b)
      and sum(1 for f in _r22b.findings if f["level"] == "warn") >= 3
      and "zz-acct" not in _text(_r22b), _text(_r22b))
_r22c, _ = _svc({"scope": "user", "props": {}, "error": "unreadable", "rc": 1, "why": "no-bus"})
check("R15: systemd that could not be read says so with the reason class and rc, as an unread finding",
      "could not be read (no-bus, rc=1)" in _text(_r22c) and _levels(_r22c) == ["unread"],
      _text(_r22c))
eq("R15: memory values systemd prints for 'no accounting' read n/a",
   [_proc22._mb(v) for v in ("infinity", "18446744073709551615", None, "1048576")],
   ["n/a", "n/a", "n/a", "1 MB"])


# ══ process: resources and the cgroup (R18) ═════════════════════════════════════════════════════
_PROC22 = os.path.join(_TMP22, "proc")
os.makedirs(os.path.join(_PROC22, "self", "fd"))
for _n22, _t22 in (("3", "socket:[1]"), ("4", "pipe:[2]"), ("5", "/dev/pts/3"), ("6", "/srv/me/x.log"),
                   ("7", "anon_inode:[eventpoll]")):
    os.symlink(_t22, os.path.join(_PROC22, "self", "fd", _n22))
with _patched(_proc22, PROC=_PROC22):
    _fd22 = _proc22._fd_counts(1000)
    _fd22c = sum(_proc22._fd_counts(2).values())
eq("R18: descriptors are counted by kind, never by target", _fd22,
   {"sockets": 1, "pipes": 1, "ptys": 1, "files": 1, "anon": 1})
eq("R18: ...and the readlinks are capped", _fd22c, 2)
os.makedirs(os.path.join(_PROC22, "4242"))
_w("proc/4242/stat", "4242 (my secret srv) S 1 1 1 0 -1 0 0 0 0 0 500 100 0 0 20 0 1 0 1000 0 0\n")
_w("proc/uptime", "100.0 50.0\n")
with _patched(_proc22, PROC=_PROC22):
    _pi22 = _proc22._pid_info(4242, 100.0, 100, os.geteuid())
check("R18: a process's comm outside the allowlist is 'other' (a LinuxGSM script's comm is the "
      "server's name), with its state, age and CPU", _pi22["comm"] == "other" and _pi22["state"] == "S"
      and abs(_pi22["age"] - 90.0) < 0.01 and abs(_pi22["cpu_pct"] - 6.67) < 0.1, repr(_pi22))
_gp22 = _proc22._group_procs([
    {"comm": "ssh", "owner": "panel", "state": "S", "age": 4.0, "cpu_pct": 0.0},
    {"comm": "other", "owner": "other", "state": "R", "age": 11520.0, "cpu_pct": 98.0}])
eq("R18: the cgroup's other processes are grouped by allowlisted comm and owner role",
   _gp22, "other ×1 (up 3 h 12 m, other, R, 98% CPU), ssh ×1 (up 4 s)")


# ══ process: listening, boot record, unit drift (R19, R20, R21) ═════════════════════════════════
_lt22 = _proc22._listen_text([{"addr": "8.8.4.4", "port": 5000, "family": 4, "inode": 1},
                              {"addr": "::", "port": 5000, "family": 6, "inode": 2}], "plain HTTP")
check("R19: a specific address is printed as its class; the wildcard literally, with bindv6only",
      "[public]:5000" in _lt22 and "8.8.4.4" not in _lt22 and "[::]:5000 (wildcard, bindv6only="
      in _lt22, _lt22)


def _pending(stored, boot, ports):
    res, facts = _b22.Result(), {}
    _proc22._restart_pending(res, facts, stored, boot, ports)
    return bool(facts.get("pending")), _levels(res)


eq("R19: config says loopback while the boot bind was the wildcard: RESTART PENDING",
   _pending("127.0.0.1", "0.0.0.0", (5000, 5000)), (True, ["warn"]))  # nosec B104
eq("R19: ...not when the boot bind is loopback too", _pending("127.0.0.1", "127.0.0.1", (5000, 5000)),
   (False, []))
eq("R19: ...and a port changed since boot is pending as well",
   _pending("", "127.0.0.1", (5001, 5000)), (True, ["warn"]))
eq("R20: TLS that was configured and failed is said, with its class only",
   _proc22._serving_line({"BOOT_TLS": False, "BOOT_TLS_ERROR": "OSError"}).split(".")[1].strip(),
   "Self-signed HTTPS was configured but FAILED to start (OSError)")
eq("R20: no boot record is 'unknown', never 'HTTP'", _proc22._serving_line({}),
   "unknown (no boot record)")
_br22 = _b22.Result()
_proc22._boot_lines(_ctx(app=type("A", (), {"config": {"BOOT_TLS": False, "BOOT_TLS_ERROR": "OSError",
                                                       "BOOT_SERVE": "failed:permission"}})()),
                    _br22, {})
check("R20: a failed TLS start is a fail and a failed Serve re-point a warn",
      _levels(_br22)[:2] == ["fail", "warn"] and "failed:permission" in _text(_br22), _text(_br22))


def _heredocs(text):
    """Every `cat <<SERVICEEOF` body in install.sh, verbatim."""
    out, cur = [], None
    for line in text.splitlines(keepends=True):
        if cur is None and line.strip().startswith("cat <<SERVICEEOF"):
            cur = []
        elif cur is not None and line.strip() == "SERVICEEOF":
            out.append("".join(cur))
            cur = None
        elif cur is not None:
            cur.append(line)
    return out


with open(os.path.join(str(_ROOT22), "install.sh"), encoding="utf-8") as _fh22:
    _install22 = _fh22.read()
eq("R21: the Python mirror of render_service_unit is byte-equal to install.sh's two heredocs",
   _heredocs(_install22), [_proc22.UNIT_TEMPLATES["system"], _proc22.UNIT_TEMPLATES["user"]])
_prio22 = _install22.split("<<'PRIOEOF'\n", 1)[1].split("PRIOEOF\n", 1)[0] \
    if "<<'PRIOEOF'\n" in _install22 else None
eq("R21: ...and PRIORITY_CONF is ensure_service_tuning's heredoc", _prio22, _proc22.PRIORITY_CONF)
_want22 = _proc22.render_unit("system", "svcacct", "/srv/panel")
_drift22 = _want22.replace("User=svcacct", "User=someoneelse").replace("RestartSec=5", "RestartSec=9")
eq("R21: a differing unit names its directives, never their values",
   _proc22.differing(_drift22, _want22), ["RestartSec", "User"])
_dpath22 = _w("override.conf", "[Service]\nEnvironment=TOKEN=hunter2secret\nMemoryMax=1G\n")
_dt22 = _proc22._dropin_text(_dpath22)
check("R21: an extra drop-in is listed by name with its directive names, never a value",
      _dt22 == "override.conf (sets: Environment, MemoryMax; values not shown)"
      and "hunter2" not in _dt22, _dt22)
_ppath22 = _w("d/priority.conf", _proc22.PRIORITY_CONF.replace("Nice=10", "Nice=0"))
eq("R21: priority.conf is compared with install.sh's", _proc22._dropin_text(_ppath22),
   "priority.conf (differs: Nice)")


def _part_boom(ctx, res, facts):
    raise PermissionError("/home/someone/secret")


with _patched(_proc22, _PARTS=(("Service", _part_boom), ("Listening", _proc22._listen_lines))):
    _sp22r = _proc22.section_process(_ctx())
check("process: a part that raises is 'could not be read (Class)', its message is not printed, and "
      "the next part still runs", "could not be read (PermissionError)" in _text(_sp22r)
      and "/home/someone" not in _text(_sp22r) and "**Listening**" in _text(_sp22r), _text(_sp22r))


# ══ install: the model and the privilege verdict (R16), which sudo (R26) ════════════════════════
eq("R16: the privilege verdict for each install shape",
   [_inst22.verdict_text(*a)[:30] for a in ((0, False, None), (1000, True, True), (1000, True, False),
                                             (1000, True, None), (1000, False, None),
                                             (1000, False, False))],
   ["the panel runs as root, so not", "passwordless sudo works for th",
    "narrow grant in force, so root", "helper installed; whether gene",
    "no helper installed; passwordl", "no helper and no passwordless "])


_sudo_probes22 = []


def _no_check_sudo(*_a, **_k):
    _sudo_probes22.append(_a)
    return False


_pl22 = _b22.Result()
with _patched(_so22, _check_sudo=_no_check_sudo, _SUDO_PROBE={"at": 0.0, "ok": None},
              _helper_present=lambda: True):
    _inst22._privilege_lines(_pl22, {})
check("R16: an empty sudo probe cache prints 'not probed in this process', and _check_sudo is never "
      "called (each failed probe counts toward faillock)",
      "`sudo -n true`**: not probed in this process" in _text(_pl22) and not _sudo_probes22,
      repr((_text(_pl22), _sudo_probes22)))
_pl22b = _b22.Result()
with _patched(_so22, _check_sudo=_no_check_sudo,
              _SUDO_PROBE={"at": _time22.time() - 180, "ok": False}, _helper_present=lambda: False):
    _inst22._privilege_lines(_pl22b, {})
check("R16: a cached refusal is printed with its age; no helper and no sudo is a fail",
      "refused (cached, probed 3 m ago)" in _text(_pl22b) and "fail" in _levels(_pl22b)
      or os.geteuid() == 0, _text(_pl22b))

_pc22 = _w("panel.conf", "panel_dir=%s\ndata_dir=/elsewhere/data\n# db_path=x\n" % _so22.PANEL_DIR)
_pct22 = _inst22.panel_conf_text(_pc22)
check("R16: panel.conf fields are compared, printed as yes / NO / not set, never as paths",
      _pct22 == "points at this checkout: yes · data dir: NO · database: not set"
      and "/elsewhere" not in _pct22, _pct22)
eq("R16: an absent panel.conf says the helper is not installed",
   _inst22.panel_conf_text(os.path.join(_TMP22, "none.conf")), "absent (helper not installed)")
eq("R16: one that cannot be read says so, never 'no'", _inst22.panel_conf_text(_TMP22),
   "unreadable (IsADirectoryError)")
_grp22 = _w("group", "root:x:0:\n%s:x:%d:a,b\nsudo:x:65000:\nsecret-team:x:%d:\n" % (
    _priv22.GAME_GROUP, os.getegid(), os.getegid()))
with _patched(_inst22, ETC_GROUP=_grp22):
    eq("R16: groups come only from the fixed list (the panel's own group, sudo, admin, wheel), "
       "matched by gid", _inst22._groups(), [_priv22.GAME_GROUP])
check("R16: the fixed group name is install.sh's GAME_GROUP (lgsmpanel-games)",
      _priv22.GAME_GROUP == "lgsmpanel-games"
      and 'GAME_GROUP="%s"' % _priv22.GAME_GROUP in _install22)
# Path prefixes that may carry an account name; none may appear in the printed line.
_ABS_DIRS22 = tuple("/%s/" % d for d in ("home", "tmp", "usr", "opt", "srv", "root"))
_interp22 = []
for _exe22 in ("/srv/someacct/py/bin/python3", os.path.join(_so22.PANEL_DIR, "venv", "bin", "python3"),
               "/usr/bin/python3"):
    with _patched(sys, executable=_exe22):
        _interp22.append(_inst22._interpreter())
check("R16: the interpreter is '<panel>/venv/bin/...', 'system python' or 'other path', never an "
      "absolute path (an account name can be in one)",
      [i.split(",")[0] for i in _interp22] == ["other path", "<panel>/venv/bin/python3", "system python"]
      and not any(d in i for i in _interp22 for d in _ABS_DIRS22 + (_so22.PANEL_DIR,)), repr(_interp22))

_vfake22 = _FakeSp22(stdout="Sudo version 1.9.15p5\nSudoers policy plugin\nLocal IP address and "
                            "netmask pairs:\n\t203.0.113.9/255.255.255.0\n")
with _patched(_inst22, subprocess=_vfake22):
    _rv22 = _inst22.run_version("/usr/bin/sudo")
_vc22 = _vfake22.calls[0] if _vfake22.calls else ([], {})
check("R26: `sudo --version` is an argv with stdin /dev/null and a 5 s timeout, and ONLY its first "
      "line is kept (classic sudo run as root goes on to print the host's addresses)",
      _rv22 == "Sudo version 1.9.15p5" and _vc22[0] == ["/usr/bin/sudo", "--version"]
      and _vc22[1].get("stdin") == _sp22.DEVNULL and _vc22[1].get("timeout") == 5, repr(_vc22))
with _patched(_inst22, run_version=lambda path, timeout=5: "sudo-rs 0.2.13"):
    _rs_v22 = _inst22._sudo_version("/usr/bin/sudo")
with _patched(_inst22, run_version=lambda path, timeout=5: "Sudo version 1.9.17p2"):
    _cl_v22 = _inst22._sudo_version("/usr/bin/sudo")
eq("R26: the flavour and version are read from that first line", (_rs_v22, _cl_v22),
   ("sudo-rs 0.2.13", "sudo 1.9.17p2"))
_nss22 = _w("nsswitch.conf", "passwd: files\nsudoers:  files sss ldapx # comment sss\n")
with _patched(_inst22, NSSWITCH=_nss22):
    eq("R26: nsswitch's sudoers sources are fixed tokens only", _inst22.nss_sudoers(),
       ["files", "sss", "other"])

_sudo_rs22 = _w("cargo/bin/sudo", "")
_sudo_cl22 = _w("plain/sudo", "")


def _sudo_line22(path):
    res = _b22.Result()
    with _patched(_inst22, shutil=type("Sh", (), {"which": staticmethod(lambda name: path)}),
                  run_version=lambda p, timeout=5: "sudo 1.0", NSSWITCH=_nss22,
                  SUDO_WS=os.path.join(_TMP22, "no-sudo.ws")):
        _inst22._sudo_line(res)
    return _text(res)


_sl22rs, _sl22cl = _sudo_line22(_sudo_rs22), _sudo_line22(_sudo_cl22)
check("R26: nsswitch's sudoers sources are printed when sudo-rs answers, and only then",
      "sudo-rs" in _sl22rs and "nsswitch sudoers: files sss other (sudo-rs ignores the sss rules)"
      in _sl22rs and "classic sudo" in _sl22cl and "nsswitch" not in _sl22cl, repr((_sl22rs, _sl22cl)))


# ══ network: UFW (R40) ══════════════════════════════════════════════════════════════════════════
_UFW22 = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
Anywhere on tailscale0     ALLOW IN    Anywhere
27015/udp                  ALLOW IN    Anywhere
Anywhere                   DENY IN     203.0.113.7                # panel-autoblock
Anywhere                   DENY IN     198.51.100.8               # panel-block
Anywhere                   DENY IN     192.0.2.99                 # my-secret-comment
22/tcp (v6)                LIMIT IN    Anywhere (v6)
"""
_uc22 = _nw22.ufw_classify(_UFW22, "", 0)
check("R40: one verbose read gives state, rules, default policy and the deny-all rules by tag",
      _uc22["state"] == "ok" and _uc22["active"] and _uc22["default_in"] == "deny"
      and len(_uc22["rules"]) == 7 and _uc22["shadowed"] == 1
      and sorted(_uc22["blocks"].values()) == ["panel-autoblock", "panel-block"],
      repr(_uc22))
eq("R40: rc 127, sudo refused, a timeout and any other failure are four states, never 'inactive'",
   [_nw22.ufw_classify(*a)["state"] for a in (
       ("", "", 127), ("", "sudo: a password is required", 1), ("", "Command timed out", -1),
       ("", "boom", 2), ("", "", 0), ("", "Command not found", -1))],
   ["not-installed", "refused", "timeout", "unreadable", "unreadable", "not-installed"])
_uv22 = []


def _verb22(verb, args=(), timeout=30, merge_stderr=True):
    _uv22.append((verb, list(args), timeout, merge_stderr))
    return _UFW22, "", 0


with _patched(_so22, _run_verb=_verb22, _helper_present=lambda: False,
              _SUDO_PROBE={"at": 0.0, "ok": None}), \
        _patched(_nw22.os, geteuid=lambda: 1000):
    _ur22a = _nw22.ufw_read()
with _patched(_so22, _run_verb=_verb22, _helper_present=lambda: True):
    _ur22b = _nw22.ufw_read()
check("R40: without the helper (or root) UFW is not read at all (the pre-helper form is a sudo "
      "without -n); with it, one ufw-status verbose, 10 s at most, stderr apart",
      _ur22a == {"state": "not-read"} and _uv22 == [("ufw-status", ["verbose"], 10, False)]
      and _ur22b["state"] == "ok", repr((_ur22a, _uv22)))


def _ufw_text(got, cfg=None):
    res, facts = _b22.Result(), {}
    _nw22._ufw_lines(res, facts, got, cfg or {"port": 5000, "tailscale_setup_done": True})
    return res, facts


_ut22, _ = _ufw_text(("ok", _uc22))
check("R40: the posture prints counts, actions, ports and 'Anywhere' only: no rule source, no comment",
      "SSH LIMIT from Anywhere" in _text(_ut22) and "tailscale0 allow-in: yes" in _text(_ut22)
      and "panel port 5000: not allowed (tailnet-only, Serve up)" in _text(_ut22)
      and "panel-autoblock 1 · panel-block 1 (+1 operator rule below an allow, so it blocks "
      "nothing)" in _text(_ut22)
      and not any(s in _text(_ut22) for s in ("203.0.113", "198.51.100", "192.0.2.99", "secret")),
      _text(_ut22))
_ut22s, _ = _ufw_text(("ok", _nw22.ufw_classify(_UFW22.replace(
    "27015/udp                  ALLOW IN    Anywhere",
    "5000/tcp                   ALLOW IN    192.0.2.44                 # alice-laptop"), "", 0)))
check("R40: a panel-port rule from one address says 'a specific source', never the address or its "
      "comment", "panel port 5000: allowed from a specific source" in _text(_ut22s)
      and "192.0.2.44" not in _text(_ut22s) and "alice" not in _text(_ut22s), _text(_ut22s))
_ut22r, _uf22r = _ufw_text(("ok", {"state": "refused"}))
check("R40: a refused read is UNREADABLE, sudo refused, and a fail", "UNREADABLE, sudo refused"
      in _text(_ut22r) and _levels(_ut22r) == ["fail"] and "inactive" not in _text(_ut22r),
      _text(_ut22r))
_ut22n, _ = _ufw_text(("ok", {"state": "not-read"}))
check("R40: not read without the helper says why", "not read (no helper, and passwordless sudo not "
      "confirmed; it would need sudo)" in _text(_ut22n), _text(_ut22n))


class _FakePopen22:
    """subprocess for network.sudo_n_verb: records the argv and keywords; answers as told."""

    DEVNULL, PIPE, TimeoutExpired = _sp22.DEVNULL, _sp22.PIPE, _sp22.TimeoutExpired

    def __init__(self, answer):
        self.calls, self.answer = [], answer

    def Popen(self, argv, **kw):  # noqa: N802 - stands in for subprocess.Popen
        self.calls.append((list(argv), kw))
        return self


def _sudo_n22(answer, fn):
    """Run fn() with no helper, not root, and a CACHED passwordless-sudo probe."""
    fake, verbs = _FakePopen22(answer), []
    with _patched(_so22, _helper_present=lambda: False, _SUDO_PROBE={"at": 1.0, "ok": True},
                  _run_verb=lambda *a, **k: verbs.append(a) or ("", "", 1),
                  _collect_verb_output=lambda p, argv, timeout, *a, **k: fake.answer), \
            _patched(_nw22, subprocess=fake), _patched(_nw22.os, geteuid=lambda: 1000):
        return fn(), fake.calls, verbs


_sn22, _snc22, _snv22 = _sudo_n22((_UFW22, "", 0), _nw22.ufw_read)
check("R40: no helper but a CACHED passwordless sudo: one `sudo -n ufw status verbose` argv, stdin "
      "/dev/null, never _run_verb's shell form (a sudo with no -n)",
      _sn22["state"] == "ok" and len(_snc22) == 1 and _snc22[0][0][:2] == ["sudo", "-n"]
      and _snc22[0][0][2:] == _priv22.tool_argv("ufw-status", ["verbose"])
      and _snc22[0][1].get("stdin") == _sp22.DEVNULL and _snc22[0][1].get("shell") is False
      and _snv22 == [], repr((_sn22, _snc22, _snv22)))
_sn22r, _, _ = _sudo_n22(("", "sudo: a password is required", 1), _nw22.ufw_read)
_sn22m, _, _ = _sudo_n22(("", "sudo: ufw: command not found", 1), _nw22.ufw_read)
eq("R40: through `sudo -n`, a refusal is 'refused' and a missing tool 'not installed'",
   (_sn22r["state"], _sn22m["state"]), ("refused", "not-installed"))
_sf22, _sfc22, _sfv22 = _sudo_n22(("`- Jail list:\tsshd", "", 0), _nw22.f2b_runtime)
check("R41: ...and fail2ban the same way: three `sudo -n fail2ban-client` argvs, no shell form",
      len(_sfc22) == 3 and all(c[0][:2] == ["sudo", "-n"] for c in _sfc22) and _sfv22 == []
      and _sf22["status"] == (0, "`- Jail list:\tsshd"), repr((_sf22, _sfc22)))
with _patched(_so22, _helper_present=lambda: False, _SUDO_PROBE={"at": 1.0, "ok": False}), \
        _patched(_nw22.os, geteuid=lambda: 1000):
    eq("R40/R41: a cached REFUSAL (or no probe) reads nothing: no new sudo is tried",
       (_nw22.may_read_privileged(), _nw22.priv_read("ufw-status", ["verbose"], 10)), (False, None))


# ══ network: fail2ban (R41) ═════════════════════════════════════════════════════════════════════
def _f2b_with(answers):
    calls = []

    def verb(v, args=(), timeout=30, merge_stderr=True):
        calls.append((v, list(args), timeout))
        return answers.pop(0) if answers else ("", "", 1)
    with _patched(_so22, _run_verb=verb, _helper_present=lambda: True):
        out = _nw22.f2b_runtime()
    return out, calls


_fr22, _fc22 = _f2b_with([("", "Command timed out", -1)])
check("R41: after the first fail2ban-client timeout, nothing more is asked (1+N jails at 10 s each "
      "would take minutes)", _fr22 == {"status": "timeout", "panel": "not-read", "sshd": "not-read"}
      and len(_fc22) == 1 and _fc22[0][2] == 5, repr((_fr22, _fc22)))
_fr22b, _fc22b = _f2b_with([("Status\n`- Jail list:\tsshd", "", 0), ("x", "", 0), ("y", "", 0)])
check("R41: at most three helper calls, 5 s each", len(_fc22b) == 3 and all(c[2] == 5 for c in _fc22b)
      and [c[0] for c in _fc22b] == ["f2b-status", "f2b-status-jail", "f2b-status-jail"], repr(_fc22b))
_f2b_calls22 = []
with _patched(_so22, _helper_present=lambda: False, _SUDO_PROBE={"at": 0.0, "ok": None},
              _run_verb=lambda *a, **k: _f2b_calls22.append(a) or ("", "", 1)), \
        _patched(_nw22.os, geteuid=lambda: 1000):
    eq("R41: without the helper or root fail2ban is not read", (_nw22.f2b_runtime(), _f2b_calls22),
       (None, []))
eq("R41: a status with no 'Jail list:' line is unreadable (None), not 'no jails'",
   (_nw22.jail_list("ERROR  Failed to access socket path"), _nw22.jail_list("`- Jail list:\t")),
   (None, []))
_alog22 = _nw22.auth_log_path()
_JAIL22 = ("Status for the jail: linuxgsm-panel\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total "
           "failed:\t41\n|  `- %s\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t3\n"
           "   `- Banned IP list:\t203.0.113.50\n")


def _f2b_text(rt):
    res, facts = _b22.Result(), {}
    _nw22._f2b_runtime_lines(res, facts, rt)
    return res


_ft22 = _f2b_text({"status": (0, "Status\n|- Number of jail:\t3\n`- Jail list:\tlinuxgsm-panel, sshd, "
                                 "my-secret-game"),
                   "panel": (0, _JAIL22 % ("File list:\t" + _alog22)),
                   "sshd": (0, _JAIL22 % "Journal matches:\t_SYSTEMD_UNIT=sshd.service")})
check("R41: jail names only when standard, the others counted; the panel jail watching auth.log; "
      "counts only, no banned IP",
      "jails: linuxgsm-panel, sshd + 1 other jail" in _text(_ft22) and "my-secret-game"
      not in _text(_ft22) and "watching the panel's auth.log ✓" in _text(_ft22)
      and "banned now 1 · total banned 3 · failed 41" in _text(_ft22) and "203.0.113.50"
      not in _text(_ft22) and _alog22 not in _text(_ft22), _text(_ft22))
_ft22j = _f2b_text({"status": (0, "`- Jail list:\tlinuxgsm-panel"),
                    "panel": (0, _JAIL22 % "Journal matches:\t_SYSTEMD_UNIT=x"), "sshd": "not-read"})
check("R41: a panel jail on the journal backend is ACTIVE BUT NOT WATCHING, a fail",
      "ACTIVE BUT NOT WATCHING" in _text(_ft22j) and "fail" in _levels(_ft22j), _text(_ft22j))
_ft22u = _f2b_text({"status": (1, "ERROR  Failed to access socket"), "panel": "not-read",
                    "sshd": "not-read"})
check("R41: an unreadable status is UNREADABLE (rc 1), not the same as no jails, and unread",
      "status UNREADABLE (rc 1), not the same as no jails" in _text(_ft22u)
      and _levels(_ft22u) == ["unread"], _text(_ft22u))
_jfile22 = os.path.join(_TMP22, "jail.conf")
_ffile22 = os.path.join(_TMP22, "filter.conf")
with _patched(_so22, _F2B_PANEL_JAIL=_jfile22, _F2B_PANEL_FILTER=_ffile22,
              _panel_login_proxied=lambda: True):
    with open(_jfile22, "w") as _fh22:
        _fh22.write(_so22._panel_f2b_jail_body("/x/auth.log", 5000, ["198.51.100.0/24"], True))
    with open(_ffile22, "w") as _fh22:
        _fh22.write(_so22._panel_f2b_filter_body())
    _jh22 = _nw22.panel_jail_health("/x/auth.log", 5000, ["198.51.100.0/24"])
    _jh22b = _nw22.panel_jail_health("/y/auth.log", 5001, [])
check("R41: the jail-file checks answer True on the jail ensure_panel_fail2ban itself writes",
      all(_jh22[k] for k in ("port", "banaction", "logpath", "backend", "ignoreip", "filter")),
      repr(_jh22))
check("R41: ...and False on a moved logpath, another port and another whitelist",
      not _jh22b["logpath"] and not _jh22b["port"] and not _jh22b["ignoreip"] and _jh22b["filter"],
      repr(_jh22b))


# ══ network: Tailscale (R36), the slow reads under the deadline ═════════════════════════════════
eq("R36: the node key's expiry as days, EXPIRED, disabled or not recorded",
   [_nw22._key_text(e, now=1_900_000_000) for e in ("2030-04-01T00:00:00Z", "2020-01-01T00:00:00Z",
                                                     "0001-01-01T00:00:00Z", None)],
   ["node key expires in 14 days", "node key EXPIRED", "node key expiry disabled",
    "node key expiry not recorded"])


def _ts_lines(v, cfg):
    res, facts = _b22.Result(), {}
    with _patched(_nw22, _load_cfg=lambda: (cfg, True)):
        _nw22._tailscale_lines(_ctx(), res, facts, ("ok", ("ok", v)))
    return res, facts


_tsv22 = dict(_tsx22, funnel_enabled=True, serve_services=[
    {"url": "https://secret-node.tail9999.ts.net", "funnel": True,
     "routes": [{"mount": "/lgsm", "target": "http://127.0.0.1:5000"},
                {"mount": "/", "target": "http://127.0.0.1:8096"}]}],
    peers=[{"hostname": "peer-secret", "dns_name": "peer-secret.ts.net", "ips": ["100.99.1.1"]}])
_tl22, _tf22f = _ts_lines(_tsv22, {"port": 5000, "tailscale_setup_done": True,
                                   "tailscale_use_funnel": False, "tailscale_mount": "/lgsm"})
check("R36: state, Serve and Funnel print without any node name, tailnet, IP, URL, login or health "
      "text", "1 route to the panel at /lgsm → http to loopback:5000" in _text(_tl22)
      and "1 other app route" in _text(_tl22) and "health warnings 2" in _text(_tl22)
      and not any(s in _text(_tl22) for s in ("secret-node", "tail9999", "100.10", "peer-secret",
                                               "me@github", "https://")), _text(_tl22))
check("R36: Funnel on in Serve but off in the config is a fail (switched on outside the panel)",
      any("Funnel is ON" in f["text"] and f["level"] == "fail" for f in _tl22.findings),
      repr(_tl22.findings))
_tl22u, _ = _ts_lines(dict(_tsd22, serve_unreadable=True), {"port": 5000})
check("R36: an unreadable Serve status is UNREADABLE, never 'no routes'",
      "Serve**: UNREADABLE" in _text(_tl22u) and "0 routes" not in _text(_tl22u), _text(_tl22u))
eq("R36: a mount outside a plain path shape prints as 'custom'",
   (_nw22._mount("/lgsm"), _nw22._mount("/a b/../x"), _nw22._mount("/" + "x" * 40)),
   ("/lgsm", "custom", "custom"))

_hold22 = _thr22.Event()


def _stuck22():
    _hold22.wait(10)
    return "late"


def _broken22():
    raise ValueError("secret detail")


_bd22 = _nw22.bounded(_ctx(deadline=1.0), (("slow", _stuck22), ("bad", _broken22),
                                           ("fine", lambda: 7)), reserve=0.5)
_hold22.set()
eq("network: each slow read runs under the deadline: a stuck one is 'timeout', a raising one its "
   "class, the rest answer", _bd22, {"slow": ("timeout", None), "bad": ("error", "ValueError"),
                                     "fine": ("ok", 7)})


# ══ access: this request (R38) ══════════════════════════════════════════════════════════════════
def _req_lines(**environ):
    res = _b22.Result()
    with _APP22.test_request_context("/api/panel/debug-report", environ_base=environ,
                                     headers={"X-Forwarded-For": "198.51.100.77",
                                              "Tailscale-User-Login": "alice@github",
                                              "Tailscale-User-Name": "Alice Example"}):
        _nw22._request_lines(res, {"BOOT_TLS": False})
    return res


_rq22 = _req_lines(REMOTE_ADDR="8.8.4.4")
check("R38: this request as categories and booleans: no address, no header value, no Tailscale "
      "identity", "from a public peer" in _text(_rq22) and "X-Forwarded-For present: yes"
      in _text(_rq22) and not any(s in _text(_rq22) for s in ("8.8.4.4", "198.51.100", "alice",
                                                                "Alice")), _text(_rq22))
eq("R38: HSTS as app.py's after_request decides it: a proxy's https, or TLS that is not the panel's "
   "own self-signed", [_nw22.hsts_expected(*a) for a in (("https", False, True), ("", True, False),
                                                          ("", True, True), ("http", False, False))],
   [True, True, False, False])
with _patched(_nw22, _load_cfg=lambda: ({"x": 1}, True)), \
        _patched(_app22, _effective_https=lambda cfg: cfg == {"x": 1}):
    eq("R38: whether the panel serves its own TLS is asked of app.py's _effective_https, as the "
       "header is", (_nw22._self_tls({"BOOT_TLS": False}),), (True,))
_rq22n = _b22.Result()
_nw22._request_lines(_rq22n, {})
eq("R38: outside a request it says so", _rq22n.lines,
   ["- **This request**: not generated from a browser request (CLI or test)"])
with _patched(_auth22, client_ip=lambda: "127.0.0.1", _loopback_peer_uid_memo=lambda: 0):
    _rq22l = _req_lines(REMOTE_ADDR="127.0.0.1")
check("R38: a proxied request keyed as loopback is a warn (one throttle bucket for every client)",
      "loopback peer, owned by root" in _text(_rq22l) and _levels(_rq22l) == ["warn"], _text(_rq22l))


# ══ access: sign-ins and auth.log (R43), accounts (R45): SQL against the real schema ════════════
def _schema_db():
    from sqlalchemy import create_engine
    from panel.db.models import db as _mdb
    path = os.path.join(_TMP22, "counts.db")
    engine = create_engine("sqlite:///" + path)
    _mdb.metadata.create_all(engine)
    engine.dispose()
    return path


_dbp22 = _schema_db()
_now22 = _time22.strftime("%Y-%m-%d %H:%M:%S", _time22.gmtime())
_old22 = _time22.strftime("%Y-%m-%d %H:%M:%S", _time22.gmtime(_time22.time() - 3 * 86400))
_ips22 = ("203.0.113.5", "203.0.113.5", "100.100.1.1", "100.200.1.1", "10.1.2.3", "172.20.0.1",
          "172.40.0.1", "127.0.0.1", "", "fd7a:115c:a1e0::5", "unknown")
with _sql22.connect(_dbp22) as _cx22:
    for _i22, _ip in enumerate(_ips22):
        _cx22.execute("INSERT INTO audit_log (username, action, target, detail, ip_address, timestamp, "
                      "success) VALUES ('u', 'login_failed', '', '', ?, ?, 0)",
                      (_ip, _now22 if _i22 % 2 else _old22))
    _cx22.execute("INSERT INTO audit_log (username, action, ip_address, timestamp, success) VALUES "
                  "('u', 'login', '1.1.1.1', ?, 1)", (_now22,))
    _cx22.execute("INSERT INTO \"user\" (username, password_hash, is_superadmin, is_active, "
                  "totp_enabled, must_change_password, api_token, auth_epoch, last_totp_step, "
                  "otp_nag_dismissed) VALUES ('a', 'x', 1, 1, 0, 1, 'tok', 0, 0, 0)")
    _cx22.execute("INSERT INTO setup_state (step, complete, data) VALUES ('complete', 1, '{}')")
    _q22r = {}
    for _name22, (_sql22q, _params22) in _nw22.signin_queries().items():
        try:
            _q22r[_name22] = _cx22.execute(_sql22q, _params22).fetchall()
        except _sql22.Error as _e22:
            _q22r[_name22] = "error:" + type(_e22).__name__
eq("R43: the failed-login sources are classified IN SQL (no address leaves the database)",
   dict(_q22r["sources"]) if isinstance(_q22r["sources"], list) else _q22r["sources"],
   {"public": 3, "tailnet": 2, "private": 2, "loopback": 1, "unknown": 2})
eq("R43: sign-ins counted per action over 24 h and 7 d",
   sorted(tuple(r) for r in _q22r["signins"]) if isinstance(_q22r["signins"], list) else
   _q22r["signins"], [("login", 1, 1), ("login_failed", 5, 11)])
check("R45: every account query runs on the real schema", all(
    isinstance(_q22r[k], list) for k in ("users", "invites", "sessions", "setup")), repr(_q22r))
try:
    _acc22 = _nw22.account_counts(_q22r)
except LookupError as _e22:     # the finding, named below rather than ending the part
    _acc22 = {"error": repr(_e22)}
eq("R45: the account numbers", tuple(_acc22.get(k) for k in ("active", "supers", "s2fa", "mcp_tok",
                                                             "setup_done")), (1, 1, 0, 1, True))


def _access(counts, funnel):
    res = _b22.Result()
    with _patched(_nw22, _funnel_on=lambda: funnel):
        _nw22._account_lines(res, counts)
        _nw22._signin_lines(res, counts, {})
    return res


_al22 = _b22.Result()
with _patched(_nw22, _funnel_on=lambda: False):
    _nw22._account_lines(_al22, _q22r)
check("R45: the accounts are TWO lines (active and superadmins with the census; must-change-password "
      "with a token and the setup token)", len(_al22.lines) == 2
      and "1 holding an API token" in _al22.lines[1] and "1 active (1 superadmin" in _al22.lines[0],
      repr(_al22.lines))
_ac22 = _access(_q22r, True)
check("R45: with Funnel on, the ONE aggregated posture finding; no username anywhere",
      [f["text"] for f in _ac22.findings] == ["Funnel is on and not every superadmin has 2FA"]
      and "'a'" not in _text(_ac22), _text(_ac22))
check("R45: ...and with Funnel off, posture stays out of At a glance", _access(_q22r, False).findings
      == [])
_ac22e = _access({k: "error:OperationalError" for k in _nw22.signin_queries()}, False)
check("R43/R45: a count that could not be read says so with its class, never 0",
      "audit log not queryable (OperationalError)" in _text(_ac22e)
      and "DB not queryable (OperationalError)" in _text(_ac22e) and " 0/" not in _text(_ac22e)
      and _levels(_ac22e) == ["unread"], _text(_ac22e))
_seen_ro22 = []


def _run_ro22(queries, timeout=10):
    _seen_ro22.append(sorted(queries))
    return {k: "error:NotImplementedError" for k in queries}


with _patched(_db22, run_ro=_run_ro22), \
        _patched(_nw22, auth_log_path=lambda: os.path.join(_TMP22, "no-auth.log")):
    _sa22 = _nw22.section_access(_ctx())
check("access: the counts go through _src_db.run_ro (off the hub), once per report",
      _seen_ro22 == [sorted(_nw22.signin_queries())], repr(_seen_ro22))


def _authlog_fixture():
    lines = []
    t = _time22.time()
    for age, ip, what in ((600, "203.0.113.1", "login failed"), (7200, "unknown", "login failed"),
                          (200000, "203.0.113.2", "login failed"), (300, "203.0.113.1", "login blocked"),
                          (310, "203.0.113.1", "login blocked"), (320, "8.8.4.4", "api token blocked")):
        stamp = _time22.strftime("%Y-%m-%d %H:%M:%S", _time22.localtime(t - age))
        lines.append("%s panel %s from %s" % (stamp, what, ip))
    # A failure 100 s old BEFORE the 512 KB of filler: a reader that does not stop at the last
    # AUTHLOG_MAX bytes counts it.
    early = "%s panel login failed from 203.0.113.3" % _time22.strftime(
        "%Y-%m-%d %H:%M:%S", _time22.localtime(t - 100))
    return _w("auth.log", early + "\n" + "x" * (_nw22.AUTHLOG_MAX + 10) + "\n" + "\n".join(lines)
              + "\n")


_as22 = _nw22.authlog_scan(_authlog_fixture())
check("R43: auth.log is read from its last 512 KB: failed sign-ins in 24 h apart from refusals, the "
      "last line's age, 'unknown'", _as22["lines_24h"] == 2 and _as22["blocked_24h"] == 3
      and _as22["unknown"] == 1 and 290 < _as22["last_age"] < 400, repr(_as22))
_sg22f = {}
_nw22._signin_lines(_b22.Result(), {"signins": [("login_failed", 2, 3), ("login_blocked", 4, 4),
                                                ("api_token_blocked", 5, 5)], "sources": []}, _sg22f)
_at22 = _nw22._authlog_text(_as22, True, _sg22f.get("audit_fail_24h"))
check("R43: auth.log is held against login_failed ONLY (a refusal writes a line per request but one "
      "audit row per window), so these agree", _sg22f == {"audit_fail_24h": 2}
      and "2 failed-login lines in 24 h (audit log says 2 ✓) · 3 refusal lines" in _at22,
      repr((_sg22f, _at22)))


# ══ access: throttles and the ban gate (R44) ════════════════════════════════════════════════════
_tnow22 = _time22.time()
eq("R44: throttle keys are counted, and the blocked ones only by class",
   _nw22.throttle_summary({"127.0.0.1": [_tnow22] * 8, "8.8.4.4": [_tnow22] * 3,
                           "2a00:1450::/64": [_tnow22] * 9}, 8, 300, _tnow22),
   (3, {"loopback": 1, "public": 1}))
_held22 = _thr22.Lock()
_held22.acquire()
eq("R44: a lock held past a second is 'busy', not an empty throttle", _nw22._copy_locked(_held22, {}),
   None)
_held22.release()
with _app22._LOGIN_FAILS_LOCK:
    _app22._LOGIN_FAILS["127.0.0.1"] = [_tnow22] * _app22.LOGIN_MAX_FAILS
try:
    _tl22r = _b22.Result()
    _nw22._throttle_line(_tl22r)
finally:
    with _app22._LOGIN_FAILS_LOCK:
        _app22._LOGIN_FAILS.pop("127.0.0.1", None)
check("R44: the login route's own throttle (the `app` module copy) is read; a blocked loopback key "
      "is a fail", "1 blocked (loopback 1)" in _text(_tl22r) and _levels(_tl22r) == ["fail"]
      and "127.0.0.1" not in _text(_tl22r), _text(_tl22r))

_saved_bl22 = (_bl22._by_len, dict(_bl22._taken))
_clear_groups("bangate")
_bl22._by_len = {(4, 32): frozenset({_ip22.ip_network("203.0.113.9/32")})}
try:
    def _inner22(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]
    _gate22 = _mw22.ProxiedBanGate(_inner22)
    _st22 = []
    _body22a = _gate22({"HTTP_X_FORWARDED_FOR": "203.0.113.9"}, lambda s, h: _st22.append(s))
    _n22a = _rs22.snapshot("bangate").get("refused")
    _body22b = _gate22({"HTTP_X_FORWARDED_FOR": "198.51.100.1"}, lambda s, h: _st22.append(s))
    _n22b = _rs22.snapshot("bangate").get("refused")
finally:
    _bl22._by_len = _saved_bl22[0]
check("R44: ProxiedBanGate counts a refusal, and a request it lets through is not counted",
      _st22 == ["403 Forbidden", "200 OK"] and _n22a == 1 and _n22b == 1, repr((_st22, _n22a, _n22b)))
_bg22 = _b22.Result()
with _patched(_bl22, _taken={"f2b": float("-inf"), "ufw": _time22.monotonic() - 41}):
    _nw22._bangate_line(_bg22)
check("R44: the ban gate prints counts and ages; a fail2ban set never read since boot is a warn",
      "refusals since boot 1 (last" in _text(_bg22) and "fail2ban set 0 networks, never read since "
      "boot" in _text(_bg22) and "UFW set 0, read 41 s ago" in _text(_bg22)
      and _levels(_bg22) == ["warn"], _text(_bg22))
_clear_groups("bangate")


# ══ notifications (R63) ═════════════════════════════════════════════════════════════════════════
eq("R63: a sender's detail text becomes a fixed outcome word",
   [_notif22.delivery_outcome(*a) for a in (
       (True, ""), (False, "couldn't reach api.telegram.org — check the host's outbound network"),
       (False, "Discord rejected it — the webhook URL is wrong or was deleted."),
       (False, "the chat ID is missing"), (False, "something new"))],
   ["sent", "unreachable", "rejected", "not-configured", "failed"])
_clear_groups("notify")


def _boom_send():
    raise RuntimeError("x")


with _patched(_notif22, _cfg=lambda: {}, _channel_senders=lambda tg, dc, nt, text: (
        ("telegram", True, lambda: (False, "Telegram rejected it")), ("discord", True, _boom_send),
        ("ntfy", False, lambda: (True, "")))):
    _notif22._deliver_alerts([("server_down", "t", "b")])
_nd22 = _rs22.snapshot("notify")
eq("R63: delivery is counted per channel and outcome (a raising sender as 'error'; a channel that "
   "is off not at all)", {k: v for k, v in _nd22.items()}, {"telegram|rejected": 1, "discord|error": 1})



class _BadStr22:
    """A sender's detail whose str() raises: the counter must still not raise into the loop."""

    def __str__(self):
        raise RuntimeError("detail")


_saved_notify22 = dict(_rs22._GROUPS.get("notify") or {})     # the counts the checks below read
try:
    _notif22._count_delivery("telegram", False, _BadStr22())
    _cd22 = "no raise"
except Exception as _e22:  # noqa: BLE001 - the finding, named below
    _cd22 = repr(_e22)
finally:
    _rs22._GROUPS["notify"] = _saved_notify22
eq("R63: counting a delivery never raises into the sender loop, whatever the detail is", _cd22,
   "no raise")


class _Opener22:
    def __init__(self, exc):
        self.exc = exc

    def open(self, req, timeout=None):
        raise self.exc


with _patched(_notif22, _OPENER=_Opener22(_ue22.HTTPError("https://api.telegram.org/x", 401, "no",
                                                           {}, None))):
    _notif22._post("https://api.telegram.org/botX/sendMessage", b"", {}, provider="telegram")
    _notif22.telegram_get_updates("123456:" + "A" * 35)
with _patched(_notif22, _OPENER=_Opener22(_ue22.HTTPError("https://api.telegram.org/x", 409, "no",
                                                           {}, None))):
    _notif22.telegram_get_updates("123456:" + "A" * 35)
_np22 = _rs22.snapshot("notify")
check("R63: _post keeps the provider's int HTTP status; polling counts failures and the last status",
      _np22.get("telegram|last_http", (0, 0))[1] == 401 and _np22.get("telegram_poll|failed") == 2
      and _np22.get("telegram_poll|last_http", (0, 0))[1] == 409, repr(_np22))


class _FullQ22:
    def put_nowait(self, item):
        raise _q22.Full()


with _patched(_notif22, _alert_queue=_FullQ22()):
    _notif22._queue_alert(("k", "t", "b"))
eq("R63: an alert dropped on a full queue is counted", _rs22.snapshot("notify").get("queue|dropped"), 1)
_FORM22 = {"telegram": {"enabled": True, "chat_id": "987654321",
                        "has_token": True,  # nosec B105 - a boolean the form returns, not a secret
                        "accept_commands": True, "command_users": "111, 222"},
           "discord": {"enabled": True, "has_webhook": True,
                       "has_bot_token": True,  # nosec B105 - a boolean the form returns, not a secret
                       "channel_id": "123456789012345678", "accept_commands": False,
                       "command_users": "", "gateway_problem": "Discord rejected the bot token "
                                                               "(close code 4004). Paste ..."},
           "ntfy": {"enabled": True, "server": "https://ntfy.secret.example", "topic": "my-topic-x9",
                    "has_token": False},  # nosec B105 - a boolean the form returns, not a secret
           "events": {"a": True, "b": False}, "thresholds": {"disk_pct": 90, "load_pct": 200,
                                                           "mem_pct": 90, "load_mins": 5}}
with _patched(_notif22, settings_for_form=lambda: _FORM22):
    _ns22 = _nsec22.section_notifications(_ctx())
check("R63: channels print as booleans and counts; no chat id, channel id, topic, server or user id",
      "chat set · commands on · command users 2" in _text(_ns22) and "server custom · topic set"
      in _text(_ns22) and "gateway problem: close code 4004" in _text(_ns22)
      and "telegram 0 sent / 1 rejected / last rejection HTTP 401" in _text(_ns22)
      and "2 failed polls since start, last HTTP 409 (another poller uses this token)"
      in _text(_ns22) and not any(s in _text(_ns22) for s in (
          "987654321", "123456789012", "my-topic", "ntfy.secret", "111", "222")), _text(_ns22))
check("R63: a rejection, a dropped alert and a 409 poller are findings",
      len([f for f in _ns22.findings if f["level"] == "warn"]) == 3, repr(_ns22.findings))
_clear_groups("notify")


# ══ errors: the log handlers and the counter (R23, R24) ═════════════════════════════════════════
_eapp22 = _Flask22("p22err")
_flask_default22 = list(_eapp22.logger.handlers)
_auth_before22 = (list(_log22.getLogger("panel.auth").handlers), _log22.getLogger("panel.auth").propagate)
_root_before22 = list(_log22.getLogger().handlers)
_lvls22 = {n: _log22.getLogger(n).level for n in ("panel", "notifications")}
# An earlier part's create_app (part13) may have attached them already: set those aside, so this
# block starts from a process that has none, and put them back after.
_pre22 = {n: [h for h in _log22.getLogger(n).handlers if getattr(h, _err22._MARK, None)]
          for n in ("panel", "notifications")}
for _n22, _hs22l in _pre22.items():
    for _h22 in _hs22l:
        _log22.getLogger(_n22).removeHandler(_h22)
_clear_groups("errors", "errors_last")
try:
    _added22 = _err22.attach_log_handlers(_eapp22.logger)
    _again22 = _err22.attach_log_handlers(_eapp22.logger)
    _pl22h = _log22.getLogger("panel").handlers
    check("R23: attached once: one stderr handler and one counter on 'panel' and 'notifications', "
          "one counter at WARNING on Flask's logger; a second call adds nothing",
          len(_added22) == 5 and _again22 == [] and all(
              sum(1 for h in _log22.getLogger(n).handlers if getattr(h, _err22._MARK, None) == k) == 1
              for n in ("panel", "notifications") for k in ("stderr", "counter"))
          and [h.level for h in _eapp22.logger.handlers if getattr(h, _err22._MARK, None)]
          == [_log22.WARNING], repr((_added22, _again22)))
    check("R24: Flask's own default handler is still there (a 500's traceback still prints), and its "
          "logger's level is not changed", all(h in _eapp22.logger.handlers for h in _flask_default22)
          and bool(_flask_default22) and _eapp22.logger.level == _log22.NOTSET,
          repr(_eapp22.logger.handlers))
    check("R23: panel.auth's file handler and its propagate=False are untouched, and nothing is "
          "added to the root logger",
          (list(_log22.getLogger("panel.auth").handlers), _log22.getLogger("panel.auth").propagate)
          == _auth_before22 and list(_log22.getLogger().handlers) == _root_before22)
    _stderr_h22 = [h for h in _pl22h if getattr(h, _err22._MARK, None) == "stderr"][0]
    _native22 = type(_evp22.original("threading").RLock())
    check("R23: the stderr handler's lock is a NATIVE RLock (a tpool thread can wait on it)",
          type(_stderr_h22.lock) is _native22, repr(type(_stderr_h22.lock)))
    _buf22 = _io22.StringIO()
    with _patched(_stderr_h22, stream=_buf22):
        _log22.getLogger("panel.p22").warning("p22 host %s unreachable", "secret-host-9")
        _log22.getLogger("panel.p22").debug("p22 quiet debug")
        _log22.getLogger("panel.p22").debug("p22 swallowed", exc_info=(OSError, OSError("x"), None))
        _log22.getLogger("panel.p22").info(ValueError("secret-host-9 in an exception object"))
    eq("R23: one WARNING line, '<LEVEL> <logger>: <message>', and no DEBUG in the journal",
       _buf22.getvalue(), "WARNING panel.p22: p22 host secret-host-9 unreachable\n")
    _ec22, _el22 = _rs22.snapshot("errors"), _rs22.snapshot("errors_last")
    check("R24: the counter keys by the TEMPLATE (never the formatted message), counts a DEBUG that "
          "carries exc_info with its class, and skips a plain DEBUG and INFO",
          _ec22 == {"WARNING|panel.p22|p22 host %s unreachable": 1, "DEBUG|panel.p22|p22 swallowed": 1}
          and _el22.get("DEBUG|panel.p22|p22 swallowed", (0, None))[1] == "OSError"
          and "secret-host-9" not in repr((_ec22, _el22)), repr((_ec22, _el22)))
    _ctr22 = [h for h in _pl22h if getattr(h, _err22._MARK, None) == "counter"][0]
    eq("R24: a msg that is not text is keyed by its type's name only",
       _err22.error_key(_log22.LogRecord("panel.x", 30, "f", 1, RuntimeError("secret-host-9"), (), None)),
       "WARNING|panel.x|RuntimeError")
    with _patched(_rs22, bump=_raise, put=_raise):
        try:
            _log22.getLogger("panel.p22").error("p22 while the store is broken")
            _cnt_err22 = None
        except Exception as _e22:   # the finding
            _cnt_err22 = repr(_e22)
    check("R24: the counter takes no lock and never raises into the code that logged",
          _cnt_err22 is None and _ctr22.lock is None, repr(_cnt_err22))
    _se22 = _err22.section_errors_since_start(_ctx())
    check("R24: the section prints a table of templates, counts and exception classes",
          "| DEBUG | panel.p22 | p22 swallowed | OSError | 1 |" in _text(_se22)
          and "secret-host-9" not in _text(_se22), _text(_se22))
    eq("R24: a template is one line with no pipes, cut to 120 characters",
       _err22._cell("a|b\n" + "c" * 200)[:6] + str(len(_err22._cell("c" * 300))), "a/b cc120")
finally:
    _err22.detach_log_handlers(_eapp22.logger)
    for _n22, _lv22 in _lvls22.items():
        _log22.getLogger(_n22).setLevel(_lv22)
_se22n = _err22.section_errors_since_start(_ctx())
check("R24: with no counter attached the section says there is no capture (unread), never 'none'",
      "no error capture" in _text(_se22n) and _levels(_se22n) == ["unread"], _text(_se22n))
for _n22, _hs22l in _pre22.items():       # what an earlier part had attached, put back
    for _h22 in _hs22l:
        _log22.getLogger(_n22).addHandler(_h22)
_clear_groups("errors", "errors_last")
_ll22 = []
with _patched(_err22, attach_log_handlers=lambda lg=None: _ll22.append(lg)), \
        _patched(_app22, _dr_errors=_err22):
    _app22._attach_debug_logging(_eapp22)
check("R23: app.py's create_app hook attaches through the module, with Flask's logger",
      _ll22 == [_eapp22.logger], repr(_ll22))


def _preformatted_log_calls():
    """Logging calls in app.py and panel/ whose message is built before the call.

    An f-string, a % or + expression, a .format(): its arguments would then be in the counter's key.
    """
    bad = []
    methods = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
    root = str(_ROOT22)
    files = [os.path.join(root, "app.py")]
    for dp, _dn, fn in os.walk(os.path.join(root, "panel")):
        files += [os.path.join(dp, f) for f in fn if f.endswith(".py")]
    for path in files:
        with open(path, encoding="utf-8") as fh:
            tree = _ast22.parse(fh.read())
        for n in _ast22.walk(tree):
            if _is_prebuilt_log(n, methods):
                bad.append("%s:%d" % (os.path.relpath(path, root), n.lineno))
    return bad


def _log_message_arg(n, methods):
    """The message argument of a call on a logger-named receiver, or None for any other node."""
    if not (isinstance(n, _ast22.Call) and isinstance(n.func, _ast22.Attribute)
            and n.func.attr in methods):
        return None
    recv = n.func.value
    name = getattr(recv, "id", None) or getattr(recv, "attr", None) or ""
    args = n.args[1:] if n.func.attr == "log" else n.args
    return args[0] if "log" in name.lower() and args else None


def _is_prebuilt_log(n, methods):
    a = _log_message_arg(n, methods)
    if isinstance(a, _ast22.BinOp):
        return isinstance(a.op, (_ast22.Mod, _ast22.Add))
    if isinstance(a, _ast22.Call):
        return isinstance(a.func, _ast22.Attribute) and a.func.attr == "format"
    return isinstance(a, _ast22.JoinedStr)


_pf22 = _preformatted_log_calls()
check("R24: no logging call in app.py or panel/ pre-formats its message (the counter keys by "
      "template, so a value formatted in first would be stored)", not _pf22, repr(_pf22[:10]))
check("R24: ...the gate recognises one (positive control)", _is_prebuilt_log(
    _ast22.parse('_log.warning(f"host {h} down")').body[0].value, {"warning"}))


# ══ app.py: the boot record (R4, R19, R20) ══════════════════════════════════════════════════════
def _create_app_assigns(key):
    with open(os.path.join(str(_ROOT22), "app.py"), encoding="utf-8") as fh:
        tree = _ast22.parse(fh.read())
    fn = next(n for n in tree.body if isinstance(n, _ast22.FunctionDef) and n.name == "create_app")
    src = _ast22.unparse(fn)
    return ("app.config['%s']" % key) in src, src


_ca22 = _create_app_assigns("PANEL_COMMIT")
check("R4: create_app puts PANEL_COMMIT into app.config, and calls the debug-report hooks",
      _ca22[0] and "app.config['PANEL_COMMIT'] = PANEL_COMMIT" in _ca22[1]
      and "_attach_debug_logging(app)" in _ca22[1] and "_start_hub_lag_watch()" in _ca22[1])
with open(os.path.join(str(_ROOT22), "app.py"), encoding="utf-8") as _fh22:
    _main22 = _fh22.read().split('if __name__ == "__main__":', 1)[1]
check("R19/R20: the __main__ block records the bind and port, and goes through the recording helpers",
      "app.config[\"BOOT_BIND\"] = host" in _main22 and "app.config[\"BOOT_PORT\"] = port" in _main22
      and "ssl_args = _boot_ssl_args(app, cfg, host, port)" in _main22
      and "_boot_serve(app, cfg, port)" in _main22 and "setup_tailscale_serve(" not in _main22)


def _boot_tls(https, cert_exc=None):
    fake = type("A", (), {"config": {}})()

    def cert(*_a):
        if cert_exc is not None:
            raise cert_exc
    with _patched(_app22, _effective_https=lambda cfg: https, _ensure_self_signed_cert=cert), \
            _ctx22.redirect_stdout(_io22.StringIO()):
        args = _app22._boot_ssl_args(fake, {}, "127.0.0.1", 5000)
    return bool(args), fake.config.get("BOOT_TLS"), fake.config.get("BOOT_TLS_ERROR")


eq("R20: TLS that started, TLS that failed (class only), and TLS not configured",
   [_boot_tls(True), _boot_tls(True, PermissionError("/srv/data/ssl/key.pem")), _boot_tls(False)],
   [(True, True, None), (False, False, "PermissionError"), (False, False, None)])


def _boot_serve(cfg, answer):
    fake = type("A", (), {"config": {}})()
    calls = []

    def setup(**kw):
        calls.append(kw)
        if isinstance(answer, Exception):
            raise answer
        return answer
    with _patched(_ts22, setup_tailscale_serve=setup), \
            _patched(_app22, _ts_backend_scheme=lambda c: "http"):
        _app22._boot_serve(fake, cfg, 5000)
    return fake.config.get("BOOT_SERVE"), len(calls)


eq("R20: Serve's boot re-point is recorded as ok / failed:<reason class> / not attempted",
   [_boot_serve({}, (True, "")), _boot_serve({"tailscale_setup_done": True}, (True, "ok")),
    _boot_serve({"tailscale_setup_done": True},
                (False, "Failed to configure Tailscale Serve: Access denied: serve config denied "
                        "https://secret-node.tail9999.ts.net")),
    _boot_serve({"tailscale_setup_done": True}, RuntimeError("secret"))],
   [("not attempted", 0), ("ok", 1), ("failed:permission", 1), ("failed:RuntimeError", 1)])

_sh22.rmtree(_TMP22, ignore_errors=True)
