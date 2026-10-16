"""Part 96 of the unit suite: the fourteenth review's integration fix (review 1016b).

Tailscale Serve and Funnel publish only the panel's own port. The helper's `tailscale-serve` used
to publish any loopback port the caller named, so the panel's account could put another local
service on the tailnet, or with Funnel on the internet. Held here:

* the helper publishes only panel.conf's `panel_port`, and only while no other account's process
  listens on it (nothing listening is allowed: the boot re-points Serve before the panel binds);
* `panel-port-record` moves that record, keeps the rest of panel.conf, and refuses a port another
  account listens on;
* install.sh records the port (a fresh install's chosen one; on an update config.json's only when it
  is the recorded one or no other account holds it);
* the panel records a new port before anything is saved, from /api/panel/change-port and from the
  setup wizard, and a refused record changes nothing.

HOW IT RUNS. The helper's main() with stand-ins for subprocess and the kernel's socket tables (files
in a throwaway dir), install.sh's own functions under bash, and part12's app for the route. Nothing
reaches this machine's tailscale, sudo, panel.conf or the checkout's data/.
"""
import atexit as _atexit96
import io as _io96
import json as _json96
import os
import shutil as _shutil96
import socket as _socket96
import subprocess as _sp96  # nosec B404 - bash over the repo's own install.sh, in a throwaway dir
import sys
import tempfile as _tf96
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper96, _root
from unit.part12 import P9_ADMIN, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
import app as _app96
from panel.core import config as _cfg96
from panel.db.models import User as _U96, db as _db96
from panel.ops import system_ops as _so96
from panel.ops import tailscale_integration as _ts96
from panel.routes import remote_security as _rs96
from panel.routes import route_helpers as _rh96
from panel.security import privileged as _priv96

_TMP96 = _tf96.mkdtemp(prefix="p96-")
_atexit96.register(_shutil96.rmtree, _TMP96, True)
_ME96 = os.getuid()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The helper publishes only the recorded panel port
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HDR96 = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout "
          "inode\n")


def _row96(port, uid, state="0A", v6=False):
    """One /proc/net/tcp{,6} row: a socket on `port` in `state`, owned by `uid`."""
    local = ("0" * 32 if v6 else "00000000") + ":%04X" % port
    remote = ("0" * 32 if v6 else "00000000") + ":0000"
    return ("   0: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 4242 1 0 100 0 0 10 0\n"
            % (local, remote, state, uid))


def _tables96(v4=(), v6=(), missing=()):
    """Two socket tables in a fresh dir, as the helper's R25J_PROC_NET_TCP; `missing` are absent."""
    d = _tf96.mkdtemp(dir=_TMP96)
    paths = []
    for name, rows, v6flag in (("tcp", v4, False), ("tcp6", v6, True)):
        p = os.path.join(d, name)
        paths.append(p)
        if name in missing:
            continue
        with open(p, "w", encoding="ascii") as fh:
            fh.write(_HDR96 + "".join(_row96(*r, v6=v6flag) for r in rows))
    return tuple(paths)


class _Run96:
    """subprocess for the helper: every command is recorded and succeeds."""

    TimeoutExpired = _sp96.TimeoutExpired
    DEVNULL = _sp96.DEVNULL
    STDOUT = _sp96.STDOUT
    PIPE = _sp96.PIPE

    def __init__(self, serve_json="null", run_ssh=None):
        self.ran, self.reads, self.serve_json, self.run_ssh = [], [], serve_json, run_ssh

    def run(self, argv, **_kw):
        if list(argv[1:]) == ["debug", "prefs"]:
            # The Tailscale SSH pref, read for an unrecorded choice (None: tailscale did not answer).
            self.reads.append(list(argv[1:]))
            if self.run_ssh is None:
                return _sp96.CompletedProcess(argv, 1, "", "failed")
            return _sp96.CompletedProcess(argv, 0, _json96.dumps({"RunSSH": self.run_ssh}), "")
        if list(argv[1:]) == ["serve", "status", "--json"]:
            # The Funnel check's read of the Serve config (None: tailscale did not answer).
            self.reads.append(list(argv[1:]))
            if self.serve_json is None:
                return _sp96.CompletedProcess(argv, 1, "", "failed")
            return _sp96.CompletedProcess(argv, 0, self.serve_json, "")
        self.ran.append(list(argv[1:]))
        return _sp96.CompletedProcess(argv, 0, "", "")

    def Popen(self, argv, **_kw):  # noqa: N802 - subprocess's own name
        self.ran.append(list(argv[1:]))
        return NS(pid=1, wait=lambda *a, **k: 0, communicate=lambda *a, **k: ("", ""), returncode=0)


def _helper_run96(argv, conf=None, tables=None, sudo_uid=_ME96, conf_path=None, serve_json="null",
                  run_ssh=None):
    """(rc, what ran, stdout, stderr) of the helper's main(argv).

    `serve_json` is what `tailscale serve status --json` prints (None: it fails), `run_ssh` the
    RunSSH pref `tailscale debug prefs` reports (None: it fails).
    """
    fake = _Run96(serve_json, run_ssh)
    saved = (_helper96.subprocess, _helper96.resolve, _helper96.panel_conf, _helper96.R25J_PROC_NET_TCP,
             _helper96.PANEL_CONF, os.environ.get("SUDO_UID"), sys.stdin, sys.stdout, sys.stderr)
    _helper96.subprocess, _helper96.resolve = fake, (lambda n: "/usr/bin/" + n)
    if conf is not None:
        _helper96.panel_conf = lambda: dict(conf)
    if conf_path is not None:
        _helper96.PANEL_CONF = conf_path
    _helper96.R25J_PROC_NET_TCP = tables if tables is not None else _tables96()
    if sudo_uid is None:
        os.environ.pop("SUDO_UID", None)
    else:
        os.environ["SUDO_UID"] = str(sudo_uid)
    sys.stdin, sys.stdout, sys.stderr = _io96.StringIO(""), _io96.StringIO(), _io96.StringIO()
    try:
        rc = _helper96.main(["panel-helper"] + list(argv))
        return rc, fake.ran, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        (_helper96.subprocess, _helper96.resolve, _helper96.panel_conf, _helper96.R25J_PROC_NET_TCP,
         _helper96.PANEL_CONF, _sudo_was96, sys.stdin, sys.stdout, sys.stderr) = saved
        if _sudo_was96 is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = _sudo_was96


def _serve96(verb, port, **kw):
    rc, ran, _out, err = _helper_run96(["tailscale-serve", verb, "modern", "/", "http", str(port)], **kw)
    return rc, [c[:1] for c in ran], err


_REC96 = {"panel_port": "5000"}
_OTHER96 = _ME96 + 4242      # an account that is not the helper's caller
_serve_rows96 = {
    "serve, recorded port, nothing listening (boot)": _serve96("serve", 5000, conf=_REC96),
    "funnel, recorded port, nothing listening": _serve96("funnel", 5000, conf=_REC96),
    "serve, recorded port, the caller listening": _serve96(
        "serve", 5000, conf=_REC96, tables=_tables96(v4=[(5000, _ME96)])),
    "serve, recorded port, another account only ESTABLISHED": _serve96(
        "serve", 5000, conf=_REC96, tables=_tables96(v4=[(5000, _OTHER96, "01")])),
    "serve, recorded port, IPv6 off (no tcp6)": _serve96(
        "serve", 5000, conf=_REC96, tables=_tables96(missing=("tcp6",))),
    "serve, no record yet (the old installer's panel.conf), the running panel's port": _serve96(
        "serve", 5000, conf={}, tables=_tables96(v4=[(5000, _ME96)])),
}
_refused_rows96 = {
    "serve, another port": _serve96("serve", 8080, conf=_REC96),
    "funnel, another port": _serve96("funnel", 8080, conf=_REC96),
    "funnel, no recorded port (an older panel.conf), nothing listening": _serve96("funnel", 5000, conf={}),
    "funnel, no recorded port, another account listening beside the caller": _serve96(
        "funnel", 5000, conf={}, tables=_tables96(v4=[(5000, _ME96)], v6=[(5000, _OTHER96)])),
    "funnel, no recorded port, only another account listening": _serve96(
        "funnel", 5000, conf={}, tables=_tables96(v4=[(5000, _OTHER96)])),
    "funnel, recorded port below 1024": _serve96("funnel", 80, conf={"panel_port": "80"}),
    "funnel, recorded port, another account listening (v4)": _serve96(
        "funnel", 5000, conf=_REC96, tables=_tables96(v4=[(5000, _OTHER96)])),
    "funnel, recorded port, root listening on IPv6 only": _serve96(
        "funnel", 5000, conf=_REC96, tables=_tables96(v6=[(5000, 0)])),
    "funnel, recorded port, socket tables unreadable": _serve96(
        "funnel", 5000, conf=_REC96, tables=_tables96(missing=("tcp", "tcp6"))),
}
check("panel-helper: `tailscale-serve` publishes panel.conf's recorded panel port, Serve or Funnel, "
      "while nothing listens on it (the boot re-points Serve before the panel binds), while the "
      "caller's own account does, and when another account's socket on it is not a listener; with no "
      "record yet (the self-update runs the previous installer once), the port the caller alone is "
      "listening on (controls)",
      all(v == (0, [["serve"]] if "serve," in k else [["funnel"]], "") for k, v in _serve_rows96.items()),
      repr(_serve_rows96))
check("panel-helper: ...and refuses, running nothing, any other port, a panel.conf with no (or no "
      "usable) record, the recorded port while another account (IPv4 or IPv6) listens on it, and "
      "socket tables it cannot read: the panel's account cannot put another local service on the "
      "tailnet or, with Funnel, the internet",
      all(v[0] == 1 and v[1] == [] and "tailscale-serve refused" in v[2] for v in _refused_rows96.values()),
      repr(_refused_rows96))
check("panel-helper: the serve refusal is a PRECHECK on the verb (it runs before any tailscale call)",
      _helper96.PRECHECKS.get("tailscale-serve") is _helper96._r25j_serve_port_refusal,
      repr(_helper96.PRECHECKS.get("tailscale-serve")))


# ── Funnel is per listener: a `funnel` write must not put another app on the internet (R2) ──────
_HP96 = "node.example-tailnet.ts.net:443"


def _sc96(handlers=None, funnel=False, extra=None):
    """`tailscale serve status --json` text: the node's :443 listener with `handlers` {mount: handler}."""
    conf = {"TCP": {"443": {"HTTPS": True}}, "Web": {_HP96: {"Handlers": handlers or {}}}}
    if funnel:
        conf["AllowFunnel"] = {_HP96: True}
    conf.update(extra or {})
    return _json96.dumps(conf)


_PANEL_H96 = {"/lgsm": {"Proxy": "http://127.0.0.1:5000"}}
_OTHER_H96 = dict(_PANEL_H96, **{"/": {"Proxy": "http://127.0.0.1:8080"}})


def _funnel96(serve_json, verb="funnel"):
    return _serve96(verb, 5000, conf=_REC96, serve_json=serve_json)


_funnel_ok96 = {
    "no Serve config at all (null)": _funnel96("null"),
    "only the panel's routes on :443 (either scheme, any loopback name)": _funnel96(_sc96(
        {"/lgsm": {"Proxy": "https+insecure://localhost:5000"}, "/x": {"Proxy": "http://[::1]:5000/"}})),
    "another app on :443, but Funnel is already on there": _funnel96(_sc96(_OTHER_H96, funnel=True)),
    "another app on another listener (:8443)": _funnel96(_json96.dumps(
        {"Web": {"node.example-tailnet.ts.net:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}},
                 _HP96: {"Handlers": _PANEL_H96}}})),
    "another app in a Tailscale Service (its own listener)": _funnel96(_sc96(_PANEL_H96, extra={
        "Services": {"svc:other": {"Web": {"other.example-tailnet.ts.net:443": {
            "Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}}}}})),
    "serve (not funnel) beside another app": _funnel96(_sc96(_OTHER_H96), verb="serve"),
}
_funnel_no96 = {
    "another app on :443, Funnel off": _funnel96(_sc96(_OTHER_H96)),
    "the panel's OLD port on :443": _funnel96(_sc96({"/": {"Proxy": "http://127.0.0.1:5055"}})),
    "a file share on :443": _funnel96(_sc96({"/files": {"Path": "/srv/share"}})),
    "a fixed reply on :443": _funnel96(_sc96({"/hi": {"Text": "hello"}})),
    "a redirect on :443": _funnel96(_sc96({"/r": {"Redirect": "https://example.com/"}})),
    "a proxy to another host's port 5000": _funnel96(_sc96({"/": {"Proxy": "http://other.example:5000"}})),
    "a raw TCP forward on 443": _funnel96(_json96.dumps({"TCP": {"443": {"TCPForward": "127.0.0.1:8443"}}})),
    "another app in a foreground session on :443": _funnel96(_sc96(_PANEL_H96, extra={
        "Foreground": {"sess1": {"Web": {_HP96: {"Handlers": {"/fg": {"Proxy": "http://127.0.0.1:9000"}}}}}}})),
    "Serve config unreadable": _funnel96(None),
}
check("panel-helper: a `funnel` write for the panel's port runs where the node's :443 listener holds "
      "only the panel's routes, where Funnel is already on there, and where other apps are on other "
      "listeners or in a Tailscale Service; a `serve` write never asks (controls)",
      all(v[0] == 0 and v[1] in ([["funnel"]], [["serve"]]) for v in _funnel_ok96.values()),
      repr(_funnel_ok96))
check("panel-helper: ...and is refused, running nothing, while that listener has any route that is not "
      "loopback on the panel's port with Funnel off (another app, the panel's old port, a file share, "
      "a fixed reply, a redirect, another host, a raw TCP forward, a foreground session's app), or "
      "when the Serve config cannot be read: Funnel is per listener, so it would put that app on the "
      "internet",
      all(v[0] == 1 and v[1] == [] and "tailscale-serve refused" in v[2] for v in _funnel_no96.values())
      and "the app at /" in _funnel_no96["another app on :443, Funnel off"][2], repr(_funnel_no96))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. panel-port-record
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _conf_file96(text):
    d = _tf96.mkdtemp(dir=_TMP96)
    p = os.path.join(d, "panel.conf")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def _read96(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


_BASE96 = "db_path=/x/data/panel.db\ndata_dir=/x/data\npanel_dir=/x\ntailscale_ssh=no\npanel_port=5000\n"
_p1 = _conf_file96(_BASE96)
_mode_before96 = os.stat(_p1).st_mode
_rec_ok96 = _helper_run96(["panel-port-record", "5055"], conf_path=_p1)
check("panel-helper: panel-port-record moves panel.conf's panel_port and keeps every other line and "
      "the file's mode",
      _rec_ok96[0] == 0 and _rec_ok96[1] == []
      and _read96(_p1) == _BASE96.replace("panel_port=5000", "panel_port=5055")
      and os.stat(_p1).st_mode == _mode_before96 and len(os.listdir(os.path.dirname(_p1))) == 1,
      repr((_rec_ok96, _read96(_p1))))
_p2 = _conf_file96(_BASE96)
_rec_refused96 = {
    "another account listening": _helper_run96(["panel-port-record", "5055"], conf_path=_p2,
                                               tables=_tables96(v4=[(5055, _OTHER96)])),
    "root listening on IPv6": _helper_run96(["panel-port-record", "5055"], conf_path=_p2,
                                            tables=_tables96(v6=[(5055, 0)])),
    "socket tables unreadable": _helper_run96(["panel-port-record", "5055"], conf_path=_p2,
                                              tables=_tables96(missing=("tcp", "tcp6"))),
    "a port below 1024": _helper_run96(["panel-port-record", "443"], conf_path=_p2),
    "not a port": _helper_run96(["panel-port-record", "5055; id"], conf_path=_p2),
}
check("panel-helper: ...and refuses a port another account listens on (either family), socket "
      "tables it cannot read, and a port the panel may not use, leaving panel.conf as it was",
      all(v[0] in (1, 2) for v in _rec_refused96.values()) and _read96(_p2) == _BASE96,
      repr((_rec_refused96, _read96(_p2))))
_p3 = os.path.join(_tf96.mkdtemp(dir=_TMP96), "panel.conf")
_rec_missing96 = _helper_run96(["panel-port-record", "5055"], conf_path=_p3)
check("panel-helper: ...and with no panel.conf it creates none (the installer writes that file)",
      _rec_missing96[0] == 1 and not os.path.exists(_p3), repr(_rec_missing96))
_p4 = _conf_file96(_BASE96)
_rec_mine96 = _helper_run96(["panel-port-record", "5055"], conf_path=_p4,
                            tables=_tables96(v4=[(5055, _ME96)]))
check("panel-helper: ...while a port only the caller's own account listens on is recorded (control)",
      _rec_mine96[0] == 0 and "panel_port=5055" in _read96(_p4), repr(_rec_mine96))
check("panel-helper: panel-port-record is an action the helper performs, in both verb tables, and "
      "local-only in the panel's",
      _helper96.ACTIONS.get("panel-port-record") is _helper96.do_r25j_panel_port_record
      and "panel-port-record" in _priv96._ARGV and "panel-port-record" in _priv96.LOCAL_ONLY_VERBS
      and _priv96.helper_argv("panel-port-record", ["5055"])[-2:] == ["panel-port-record", "5055"],
      repr(_helper96.ACTIONS.get("panel-port-record")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. install.sh records the port
# ════════════════════════════════════════════════════════════════════════════════════════════════
_INSTALL96 = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()


def _fn96(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash96(script, env=None):
    p = _sp96.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                  env=dict(os.environ, LC_ALL="C.UTF-8", **(env or {})))
    return p.returncode, p.stdout.strip(), p.stderr.strip()


_FNS96 = "".join(_fn96(_INSTALL96, n) for n in ("_r25j_panel_port_to_record", "_r25j_is_panel_port"))
_PDIR96 = _tf96.mkdtemp(dir=_TMP96)


def _to_record96(chosen, recorded, cfg_port, held):
    """What install.sh records: `held` is whether another account listens on config.json's port."""
    conf = _conf_file96("" if recorded is None else "panel_port=%s\n" % recorded)
    script = (_FNS96 + "panel_port() { echo %s; }\n" % cfg_port
              + "_r25j_port_held_by_other() { return %d; }\n" % (0 if held else 1)
              + "PANEL_DIR=%s\n_R25J_CHOSEN_PORT=%s\n" % (_PDIR96, chosen)
              + "_r25j_panel_port_to_record %s\n" % conf)
    return _bash96(script)[1]


_install_rows96 = {
    "fresh install: the port it chose": (_to_record96("5003", "5000", "5000", True), "5003"),
    "update: config.json's port is the recorded one": (_to_record96("", "5000", "5000", True), "5000"),
    "update: config.json moved to a port no other account holds": (_to_record96("", "5000", "5055", False),
                                                                   "5055"),
    "update: config.json names a port another account holds": (_to_record96("", "5000", "8080", True),
                                                               "5000"),
    "update from an older panel.conf, the panel's own port": (_to_record96("", None, "5000", False),
                                                              "5000"),
    "update from an older panel.conf, a port another account holds": (_to_record96("", None, "8080", True),
                                                                      ""),
    "update: config.json's port is below 1024": (_to_record96("", "5000", "80", False), "5000"),
    "update: a recorded value that is not a port": (_to_record96("", "x; id", "8080", True), ""),
    # The helper reads a port below 1024 as no record (v_r25j_panel_port), so none is written.
    "update: config.json's port is 1023": (_to_record96("", "5000", "1023", False), "5000"),
    "update: the recorded port is 1000": (_to_record96("", "1000", "8080", True), ""),
}
check("install.sh: panel.conf's panel_port is a fresh install's chosen port; on an update "
      "config.json's port (the panel's account can edit it) only when it is the recorded one or no "
      "other account listens on it, else the recorded one is kept",
      all(got == want for got, want in _install_rows96.values()), repr(_install_rows96))
# The two "is this the panel's port" definitions agree, on both sides of 1024 (R7).
_edge96 = {p: _bash96(_fn96(_INSTALL96, "_r25j_is_panel_port") + "_r25j_is_panel_port %s" % p)[0] == 0
           for p in ("1000", "1023", "1024", "5000", "65535", "65536")}
_edge_helper96 = {}
for _ep96 in _edge96:
    try:
        _edge_helper96[_ep96] = bool(_helper96.v_r25j_panel_port(_ep96))
    except ValueError:
        _edge_helper96[_ep96] = False
check("install.sh: _r25j_is_panel_port accepts exactly the ports the helper's v_r25j_panel_port "
      "does (1024..65535): a record of 1000..1023 was written and then read by the helper as none",
      _edge96 == _edge_helper96 and _edge96["1023"] is False and _edge96["1024"] is True,
      repr((_edge96, _edge_helper96)))

# The real listener read, against a socket this check holds.
_lsock96 = _socket96.socket(_socket96.AF_INET, _socket96.SOCK_STREAM)
try:
    _lsock96.bind(("127.0.0.1", 0))
    _lsock96.listen(1)
    _lport96 = _lsock96.getsockname()[1]
    _held_fn96 = _fn96(_INSTALL96, "_r25j_port_held_by_other")
    _held96 = {
        "a port the owner itself listens on": _bash96(_held_fn96 + "_r25j_port_held_by_other %d %d"
                                                      % (_lport96, _ME96))[0],
        "the same port, judged for another owner": _bash96(_held_fn96 + "_r25j_port_held_by_other %d %d"
                                                           % (_lport96, _OTHER96))[0],
    }
finally:
    _lsock96.close()
check("install.sh: _r25j_port_held_by_other reads the kernel's socket tables: a listener of the "
      "panel directory's owner is not another account's, and the same socket is when judged for "
      "someone else",
      _held96 == {"a port the owner itself listens on": 1, "the same port, judged for another owner": 0},
      repr(_held96))
_irt96 = _fn96(_INSTALL96, "install_root_tools")
_fresh96 = _INSTALL96[_INSTALL96.find('PANEL_PORT="$(choose_and_record_port'):]
check("install.sh: install_root_tools reads the port to record before it rewrites panel.conf, and "
      "writes it as panel_port; the fresh path hands it the port it chose before calling it",
      -1 < _irt96.find("_r25j_panel_port_to_record") < _irt96.find('tee "${PANEL_CONF}"')
      and "panel_port=%s" in _irt96
      and -1 < _fresh96.find('_R25J_CHOSEN_PORT="${PANEL_PORT}"') < _fresh96.find("\ninstall_root_tools\n"),
      repr(_irt96[:200]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The panel records a new port before it saves anything
# ════════════════════════════════════════════════════════════════════════════════════════════════
_verb96 = []
try:
    _p9_arm(_p9_patch, who="part96")
    _p9_patch(_so96, "_run_verb", lambda verb, args=(), **kw: (
        _verb96.append((verb, list(args))), _verb96_answer[0])[1])
    _verb96_answer = [("recorded", "", 0)]
    _helper_on96 = [False]
    _p9_patch(_so96, "_helper_present", lambda: _helper_on96[0])
    _rp96 = {"no helper": _so96.record_panel_port(5055), "no helper, verbs": list(_verb96)}
    _helper_on96[0] = True
    _rp96["recorded"] = _so96.record_panel_port(5055)
    _verb96_answer[0] = ("", "panel-port-record refused: another account's process is listening on "
                             "port 5055\n", 1)
    _rp96["refused"] = _so96.record_panel_port(5055)
    _rp96["verbs"] = list(_verb96)
    # A helper too old for the verb, and one sudo will not run (R5).
    _verb96_answer[0] = ("", "panel-helper: unknown verb 'panel-port-record'\n", 2)
    _rp96["old helper"] = _so96.record_panel_port(5055)
    _verb96_answer[0] = ("", "sudo: a password is required\n", 1)
    _rp96["sudo refuses"] = _so96.record_panel_port(5055)
    _verb96_answer[0] = ("", "panel-helper: bad argument\n", 2)
    _rp96["bad argument"] = _so96.record_panel_port(5055)
finally:
    _p9_restore_all()
check("system_ops.record_panel_port: through the helper's panel-port-record, and its refusal is "
      "the answer; with no helper there is nothing to record (that host has no narrow grant)",
      _rp96["no helper"] == (True, "") and _rp96["no helper, verbs"] == []
      and _rp96["recorded"] == (True, "")
      and _rp96["refused"] == (False, "panel-port-record refused: another account's process is "
                                      "listening on port 5055")
      and _rp96["verbs"] == [("panel-port-record", ["5055"])] * 2, repr(_rp96))
check("system_ops.record_panel_port: a helper older than panel-port-record (\"unknown verb\") or one "
      "sudo will not run does not block the port change (neither publishes by the record), while "
      "any other failure still does",
      _rp96["old helper"] == (True, "") and _rp96["sudo refuses"] == (True, "")
      and _rp96["bad argument"][0] is False, repr(_rp96))

_cp96 = {"answer": (False, "another account's process is listening on port 5055"), "calls": [],
         "steps": []}
_cfg_was96 = None
try:
    _p9_arm(_p9_patch, who="part96")
    with _p9.app_context():
        _cfg_was96 = _cfg96.load_config()
        _cfg96.save_config(dict(_cfg_was96, port=5000, bind_host="0.0.0.0"))  # nosec B104 - a stored value

    def _record96(port):
        _cp96["calls"].append((port, _cfg96.load_config().get("port")))
        return _cp96["answer"]

    _p9_patch(_so96, "record_panel_port", _record96)
    _p9_patch(_so96, "port_in_use", lambda port: False)
    _p9_patch(_so96, "restart_panel", lambda: (_cp96["steps"].append("restart"), (True, "scheduled"))[1])
    _p9_patch(_so96, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
    _p9_patch(_rs96, "remote_ufw_open_port", lambda *a, **k: (_cp96["steps"].append("fw"), (True, "ok"))[1])
    _p9_patch(_rs96, "remote_ufw_close_port", lambda *a, **k: (_cp96["steps"].append("fw"), (True, "ok"))[1])
    _A96 = _p9_client(P9_ADMIN)
    _r96 = _A96.post("/api/panel/change-port", json={"port": 5055, "bind_host": "0.0.0.0"})  # nosec B104
    with _p9.app_context():
        _after96 = _cfg96.load_config().get("port")
    _cp96["refused"] = (_r96.status_code, _p9_json(_r96).get("success"), _p9_json(_r96).get("message", ""),
                        _after96, list(_cp96["steps"]), list(_cp96["calls"]))
    _cp96["answer"], _cp96["steps"], _cp96["calls"] = (True, ""), [], []
    _r96 = _A96.post("/api/panel/change-port", json={"port": 5055, "bind_host": "0.0.0.0"})  # nosec B104
    with _p9.app_context():
        _after96 = _cfg96.load_config().get("port")
    _cp96["moved"] = (_r96.status_code, _p9_json(_r96).get("success"), _after96, list(_cp96["steps"]),
                      list(_cp96["calls"]))
    _cp96["calls"] = []
    _r96 = _A96.post("/api/panel/change-port", json={"port": 5055, "bind_host": "::"})  # nosec B104
    _cp96["bind only"] = (_r96.status_code, list(_cp96["calls"]))
finally:
    _p9_restore_all()
    if _cfg_was96 is not None:
        with _p9.app_context():
            _cfg96.save_config(_cfg_was96)
check("change-port: a port the helper will not record as the panel's is refused before anything is "
      "saved: config.json keeps the old port, and no firewall step or restart runs",
      _cp96["refused"][:2] == (400, False) and "5055" in _cp96["refused"][2]
      and "another account" in _cp96["refused"][2] and _cp96["refused"][3:] == (5000, [], [(5055, 5000)]),
      repr(_cp96["refused"]))
check("change-port: ...while a port the helper records moves the panel, recorded while config.json "
      "still held the old port (control); a bind-only change records nothing",
      _cp96["moved"][:3] == (200, True, 5055) and "restart" in _cp96["moved"][3]
      and _cp96["moved"][4] == [(5055, 5000)] and _cp96["bind only"] == (200, []), repr(_cp96))

_wz96 = {"answer": (False, "another account's process is listening on port 5055"), "calls": [],
         "saved": []}
try:
    _p9_patch(_so96, "record_panel_port", lambda port: (_wz96["calls"].append(port), _wz96["answer"])[1])
    _p9_patch(_rh96, "set_config_keys", lambda cfg, **kw: _wz96["saved"].append(kw.get("port")))
    _p9_patch(_rh96, "bind_host_error", lambda *a, **k: None)
    _p9_patch(_rh96, "_setup_log", lambda *a, **k: None)
    for _wl96, _wp96 in (("refused", "5055"), ("same port", "5000"), ("recorded", "5055")):
        if _wl96 == "recorded":
            _wz96["answer"] = (True, "")
        with _p9.test_request_context("/setup", method="POST",
                                      data={"port": _wp96, "bind_host": "0.0.0.0"}):  # nosec B104
            _rh96._setup_welcome(NS(step="welcome", data="{}"), {}, {"port": 5000})
        _wz96[_wl96] = (list(_wz96["calls"]), list(_wz96["saved"]))
        _wz96["calls"], _wz96["saved"] = [], []
finally:
    _p9_restore_all()
check("setup wizard: a new port the helper will not record is refused and nothing is saved; the "
      "port it already has records nothing, and a recorded one is saved (control)",
      _wz96["refused"] == ([5055], []) and _wz96["same port"] == ([], [5000])
      and _wz96["recorded"] == ([5055], [5055]), repr(_wz96))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The boot repairs a record that drifted from config.json (pre-merge review R1)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A restored backup, the self-update window (the previous installer writes no panel_port) or a
# change-port whose save failed left panel.conf naming another port, and nothing put it back: the
# boot's Serve re-point, the Tailscale page's Enable and the wizard were all refused.
_rc_conf96 = os.path.join(_tf96.mkdtemp(dir=_TMP96), "panel.conf")
_rc96 = {}
_rc_calls96 = []
try:
    _p9_patch(_so96, "_R25A_PANEL_CONF", _rc_conf96)
    _p9_patch(_so96, "_helper_present", lambda: True)
    _rc_answer96 = [(True, "")]
    _p9_patch(_so96, "record_panel_port", lambda port: (_rc_calls96.append(port), _rc_answer96[0])[1])
    # Each with a recorded Tailscale SSH choice: an unrecorded one calls the verb too (section 6).
    for _rl96, _rt96 in (("recorded, the same port", "tailscale_ssh=no\npanel_port=5055\n"),
                         ("recorded, another port (a restored backup)", "tailscale_ssh=no\npanel_port=5000\n"),
                         ("no record (the previous installer's panel.conf)", "db_path=/x\ntailscale_ssh=no\n"),
                         ("an empty record", "tailscale_ssh=no\npanel_port=\n"),
                         ("no panel.conf", None)):
        if _rt96 is None:
            if os.path.exists(_rc_conf96):
                os.unlink(_rc_conf96)
        else:
            with open(_rc_conf96, "w", encoding="utf-8") as _fh96:
                _fh96.write(_rt96)
        del _rc_calls96[:]
        _rc96[_rl96] = (_so96.reconcile_panel_port(5055), list(_rc_calls96))
    _rc_answer96[0] = (False, "panel-port-record refused: another account's process is listening on "
                              "port 5055")
    with open(_rc_conf96, "w", encoding="utf-8") as _fh96:
        _fh96.write("tailscale_ssh=no\npanel_port=5000\n")
    del _rc_calls96[:]
    _rc96["refused"] = (_so96.reconcile_panel_port(5055), list(_rc_calls96))
    _p9_patch(_so96, "_helper_present", lambda: False)
    del _rc_calls96[:]
    _rc96["no helper"] = (_so96.reconcile_panel_port(5055), list(_rc_calls96))
finally:
    _p9_restore_all()
check("system_ops.reconcile_panel_port: records the port the panel is about to bind when panel.conf "
      "records another, none, or there is no panel.conf; records nothing when it already matches or "
      "there is no helper; a refusal is reported, not hidden",
      _rc96 == {"recorded, the same port": ("ok", []),
                "recorded, another port (a restored backup)": ("recorded", [5055]),
                "no record (the previous installer's panel.conf)": ("recorded", [5055]),
                "an empty record": ("recorded", [5055]),
                "no panel.conf": ("recorded", [5055]),
                "refused": ("failed: panel-port-record refused: another account's process is "
                            "listening on port 5055", [5055]),
                "no helper": ("ok", [])}, repr(_rc96))

_boot96 = {}
for _bl96, _bcfg96 in (("Serve set up", {"tailscale_setup_done": True}), ("no Serve", {})):
    _order96 = []
    try:
        _p9_patch(_ts96, "release_operator", lambda: (_order96.append("release"), "not-operator")[1])
        _p9_patch(_so96, "reconcile_panel_port", lambda port: (_order96.append(("record", port)), "ok")[1])
        _p9_patch(_ts96, "setup_tailscale_serve",
                  lambda **kw: (_order96.append(("serve", kw.get("port"))), (False, "refused"))[1])
        _p9_patch(_app96, "_serve_scheme_now", lambda cfg, conf: "http")
        _app96._boot_serve(NS(config={}), _bcfg96, 5055)
    finally:
        _p9_restore_all()
    _boot96[_bl96] = _order96
check("boot: _boot_serve records the port it is about to bind before the Serve re-point (which the "
      "helper refuses for any other port), after the operator release, and with Serve not set up too",
      _boot96 == {"Serve set up": ["release", ("record", 5055), ("serve", 5055)],
                  "no Serve": ["release", ("record", 5055)]}, repr(_boot96))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Tailscale SSH already on, with no choice recorded, is recorded yes (pre-merge review R3)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The panel's self-update runs the PREVIOUS installer once, which writes no tailscale_ssh at all, so
# a host running Tailscale SSH stayed unrecorded: Disable then made Enable refused ("not chosen").
_NOKEY96 = "db_path=/x/data/panel.db\ndata_dir=/x/data\npanel_dir=/x\n"
_ssh96 = {}
for _sl96, _sargv96, _sconf96, _son96 in (
        ("off, unrecorded, SSH on", ["tailscale-ssh", "off"], _NOKEY96, True),
        ("on, unrecorded, SSH on", ["tailscale-ssh", "on"], _NOKEY96, True),
        ("on, unrecorded, SSH off", ["tailscale-ssh", "on"], _NOKEY96, False),
        ("on, unrecorded, prefs unreadable", ["tailscale-ssh", "on"], _NOKEY96, None),
        ("on, recorded no, SSH on", ["tailscale-ssh", "on"], _NOKEY96 + "tailscale_ssh=no\n", True),
        ("port record, unrecorded, SSH on", ["panel-port-record", "5055"], _NOKEY96, True),
        ("port record, unrecorded, SSH off", ["panel-port-record", "5055"], _NOKEY96, False)):
    _sp_conf96 = _conf_file96(_sconf96)
    _sres96 = _helper_run96(_sargv96, conf_path=_sp_conf96, run_ssh=_son96)
    _ssh96[_sl96] = (_sres96[0], _sres96[1], _read96(_sp_conf96))
check("panel-helper: with no Tailscale SSH choice recorded (the previous installer's panel.conf) and "
      "Tailscale SSH on now, `tailscale-ssh off`, `tailscale-ssh on` and the boot's panel-port-record "
      "record tailscale_ssh=yes (as install.sh records a host already running it) before they run",
      _ssh96["off, unrecorded, SSH on"] == (0, [["set", "--ssh=false"]], _NOKEY96 + "tailscale_ssh=yes\n")
      and _ssh96["on, unrecorded, SSH on"] == (0, [["set", "--ssh=true"]], _NOKEY96 + "tailscale_ssh=yes\n")
      and _ssh96["port record, unrecorded, SSH on"][:2] == (0, [])
      and _ssh96["port record, unrecorded, SSH on"][2] == _NOKEY96 + "panel_port=5055\ntailscale_ssh=yes\n",
      repr(_ssh96))
check("panel-helper: ...while SSH off now, an unreadable pref, or a recorded \"no\" records nothing and "
      "`on` stays refused",
      _ssh96["on, unrecorded, SSH off"] == (1, [], _NOKEY96)
      and _ssh96["on, unrecorded, prefs unreadable"] == (1, [], _NOKEY96)
      and _ssh96["on, recorded no, SSH on"] == (1, [], _NOKEY96 + "tailscale_ssh=no\n")
      and _ssh96["port record, unrecorded, SSH off"][2] == _NOKEY96 + "panel_port=5055\n", repr(_ssh96))

_choice96 = {}
try:
    _p9_patch(_so96, "_R25A_PANEL_CONF", _rc_conf96)
    _p9_patch(_so96, "_helper_present", lambda: True)
    _ssh_on96 = [False]
    _p9_patch(_so96, "tailscale_ssh_status", lambda: {"enabled": _ssh_on96[0], "running": True})
    for _cl96, _ct96, _con96 in (("unrecorded, SSH on", _NOKEY96, True), ("unrecorded, SSH off", _NOKEY96, False),
                                 ("yes", "tailscale_ssh=yes\n", False), ("no, SSH on", "tailscale_ssh=no\n", True)):
        with open(_rc_conf96, "w", encoding="utf-8") as _fh96:
            _fh96.write(_ct96)
        _ssh_on96[0] = _con96
        _en96 = _so96.tailscale_ssh_enable() if not _con96 and _ct96 == _NOKEY96 else None
        _choice96[_cl96] = (_so96.tailscale_ssh_choice(), _so96.tailscale_ssh_allowed(),
                            _en96 and (_en96[0], _en96[1] is _so96.TS_SSH_NOT_RECORDED))
    # The boot: the verb recorded the running choice, so the record names it and the boot says so.
    with open(_rc_conf96, "w", encoding="utf-8") as _fh96:
        _fh96.write(_NOKEY96 + "panel_port=5055\n")

    def _rec_ssh96(port):
        with open(_rc_conf96, "a", encoding="utf-8") as fh:
            fh.write("tailscale_ssh=yes\n")
        return True, ""
    _p9_patch(_so96, "record_panel_port", _rec_ssh96)
    _choice96["reconcile, same port, unrecorded"] = _so96.reconcile_panel_port(5055)
    _choice96["reconcile, then recorded"] = _so96.reconcile_panel_port(5055)
finally:
    _p9_restore_all()
check("system_ops: an unrecorded Tailscale SSH choice is its own state; with SSH on it is allowed (the "
      "helper records it yes), with SSH off Enable is refused with copy saying no choice is recorded "
      "yet, not that it \"was not chosen\"",
      _choice96["unrecorded, SSH on"] == ("unrecorded", True, None)
      and _choice96["unrecorded, SSH off"] == ("unrecorded", False, (False, True))
      and _choice96["yes"] == ("yes", True, None) and _choice96["no, SSH on"] == ("no", False, None),
      repr(_choice96))
check("system_ops.reconcile_panel_port: an unrecorded Tailscale SSH choice calls the verb even when the "
      "port already matches, and reports the running choice it recorded; once recorded, nothing",
      _choice96["reconcile, same port, unrecorded"] == "recorded, tailscale ssh"
      and _choice96["reconcile, then recorded"] == "ok", repr(_choice96))

_boot_ssh96 = []
try:
    _p9_patch(_ts96, "release_operator", lambda: "not-operator")
    _p9_patch(_so96, "reconcile_panel_port", lambda port: "recorded, tailscale ssh")
    _p9_patch(_app96, "_boot_audit", lambda app, detail, ok, action=None: _boot_ssh96.append((action, ok)))
    _app96._boot_serve(NS(config={}), {}, 5055)
finally:
    _p9_restore_all()
check("boot: a Tailscale SSH choice the helper recorded because SSH was on is said in the audit log",
      _boot_ssh96 == [("tailscale_ssh_choice_recorded", True)], repr(_boot_ssh96))

# The route answers the stable code for the unrecorded copy too, in the viewer's language.
_ES96 = _json96.loads(open(os.path.join(_root, "translations", "es", "r25j.json"), encoding="utf-8").read())
try:
    _p9_arm(_p9_patch, who="part96")
    _p9_patch(_so96, "tailscale_ssh_enable", lambda: (False, _so96.TS_SSH_NOT_RECORDED))
    with _p9.app_context():
        _lang_was96 = _db96.session.get(_U96, P9_ADMIN).language
        _db96.session.get(_U96, P9_ADMIN).language = "es"
        _db96.session.commit()
    try:
        _resp96 = _p9_client(P9_ADMIN).post("/api/server-management/ts-ssh-enable")
        _route96 = (_resp96.status_code, _p9_json(_resp96).get("code"), _p9_json(_resp96).get("message"))
    finally:
        with _p9.app_context():
            _db96.session.get(_U96, P9_ADMIN).language = _lang_was96
            _db96.session.commit()
finally:
    _p9_restore_all()
check("ts-ssh-enable: the unrecorded refusal answers 403 with code tailscale_ssh_not_chosen, in es",
      _route96 == (403, "tailscale_ssh_not_chosen", _ES96[str(_so96.TS_SSH_NOT_RECORDED)]), repr(_route96))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. How to allow it, for both install models (R4), and the Public SSH card (R6)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TPL96 = open(os.path.join(_root, "templates", "remote_manage.html"), encoding="utf-8").read()
_refusal96 = _helper_run96(["tailscale-ssh", "on"], conf={"tailscale_ssh": "no"})[3]
_howto96 = {"helper": _refusal96, "system_ops": str(_so96.TS_SSH_NOT_CHOSEN),
            "system_ops, unrecorded": str(_so96.TS_SSH_NOT_RECORDED),
            "page": _TPL96[_TPL96.find('id="ts-ssh-not-chosen"'):
                           _TPL96.find("</div>", _TPL96.find('id="ts-ssh-not-chosen"'))]}
check("Tailscale SSH copy (helper, panel, page): names `sudo PANEL_TAILSCALE_SSH=1 bash install.sh` "
      "(sudo drops a variable set before it) and the per-user install's run without sudo, and no "
      "longer says \"as root\" (a per-user install refuses a root run)",
      all("sudo PANEL_TAILSCALE_SSH=1 bash install.sh" in v and "per-user install" in v
          and "without" in v and "as root with" not in v for v in _howto96.values()), repr(_howto96))


def _public_ssh96(allowed, enabled=False, ufw_allowed=False):
    """The panel host's Public SSH card, rendered, for a connected host."""
    status = {"has_sudo": True, "ufw": {"enabled": True, "rules": []},
              "tailscale_ssh": {"enabled": enabled, "running": True},
              "tailscale_ssh_allowed": allowed, "tailscale_interface": "tailscale0",
              "tailscale_ufw_allowed": ufw_allowed, "updates": {}, "uptime": ""}
    try:
        _p9_arm(_p9_patch, who="part96")
        _p9_patch(_so96, "get_server_status", lambda force=False: status)
        _p9_patch(_ts96, "panel_funnel_facts", lambda cfg: {})
        resp = _p9_client(P9_ADMIN).get("/server-management")
        body = resp.get_data(as_text=True)
    finally:
        _p9_restore_all()
    i = body.find("Public SSH (port 22 from the internet)")
    return resp.status_code, body[i:body.find('id="ssh-msg"', i)] if i >= 0 else ""


_pub_no96, _pub_yes96, _pub_on96 = _public_ssh96(False), _public_ssh96(True), _public_ssh96(False, True, True)
check("System page, Public SSH: where Tailscale SSH was not chosen (and is off), the card names only "
      "the tailscale0 allow as the way back in, and does not say Tailscale SSH keeps working",
      _pub_no96[0] == 200 and "Tailscale SSH keeps working" not in _pub_no96[1]
      and "enable tailscale ssh" not in _pub_no96[1].lower()
      and "Allow the tailscale0 interface (SSH to this host" in _pub_no96[1]
      and "allow the tailscale0 interface first" in _pub_no96[1], repr(_pub_no96))
check("System page, Public SSH: ...where it may be enabled, the card offers both ways (control); with "
      "Tailscale SSH on, it says it keeps working",
      "Enable Tailscale SSH, or allow the tailscale0 interface" in _pub_yes96[1]
      and "enable Tailscale SSH or allow the tailscale0 interface first" in _pub_yes96[1]
      and "Tailscale SSH keeps working regardless" in _pub_on96[1], repr((_pub_yes96, _pub_on96)))
