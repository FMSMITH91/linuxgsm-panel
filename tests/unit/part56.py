"""Part 56 of the unit suite: the 2026-10-11 second review's routes, tools and page fixes (builder C).

Held here, each against the code path the finding named:

* routes: with Tailscale Serve set up the panel binds only where Serve reaches it (::1 locked it
  out); a JSON switch is a boolean or a 400 (the string "false" turned Tailscale SSH on, rebooted a
  bootstrapped host, muted nothing, enabled autostart and backups); the backup passphrase is judged
  before any default and before the other settings are saved; repair `paths` holds text only.
* pages and scripts (node, against stubs, as part47 and part53 do).

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import contextlib as _ctx56
import importlib.util as _ilu56
import io as _io56
import json as _json56
import os
import re as _re56
import shutil as _shutil56
import subprocess as _sp56  # nosec B404 - runs bash on install.sh's own block
import sys as _sys56
import tempfile as _tf56
from types import SimpleNamespace as _NS56

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (_p9_arm, P9_ADMIN, P9_GS, P9_HOST, _P9_CFG_PATH, _P9_TRIPPED, _p9_cfg, _p9_client,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_so)
from unit.part47 import _cut47, _node47
from panel.ops import backup as _bk56
from panel.routes import remote_bootstrap as _rb56
from panel.routes import remote_security as _rs56
from panel.routes import remote_tailscale as _rt56

_JS56 = os.path.join(_root, "static", "js")
_TPL56 = os.path.join(_root, "templates")
_CFG56_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _read56(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node56(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


_A56 = _p9_client(P9_ADMIN)
# part12 disarmed its transport tripwire when it ended, and every check below stubs only the leaf
# it names: a route that reached one more host call ran it for real (paramiko to the fixture host,
# or a local shell — as root on CI's root leg) and this part still passed. Re-armed, as part53
# does, and closed with a check below.
_TRIP56_START = len(_P9_TRIPPED)
try:
    _p9_arm(who="part56")
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. routes
    # ════════════════════════════════════════════════════════════════════════════════════════════

    # ── with Serve, the panel binds only where Serve reaches it ──────────────────────────────────
    _p9_patch(_p9_so, "host_has_ip", lambda ip: True)
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "restart_panel", lambda: (True, "scheduled"))
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
    _p9_patch(_rs56, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_rs56, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
    _served56 = {b: _rs56._bind_refusal(True, _rs56._r11c_canonical_bind(b))
                 for b in ("::1", "0:0:0:0:0:0:0:1", "127.0.0.1", "0.0.0.0", "::")}  # nosec B104
    check("change-port: with Tailscale Serve, ::1 (any spelling) is refused — Serve proxies to "
          "127.0.0.1, which an IPv6 loopback socket refuses, so the panel was locked out",
          all(_served56[b] and "Tailscale Serve" in _served56[b] for b in ("::1", "0:0:0:0:0:0:0:1")),
          repr(_served56))
    check("change-port: ...while 127.0.0.1 and the wildcards are still allowed with Serve (control)",
          [_served56[b] for b in ("127.0.0.1", "0.0.0.0", "::")] == [None] * 3, repr(_served56))  # nosec B104
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, bind_host="127.0.0.1",
                             tailscale_setup_done=True))
    _r56 = _A56.post("/api/panel/change-port", json={"port": 5000, "bind_host": "::1"})
    check("change-port: the route refuses ::1 behind Serve with a 400 and saves nothing",
          _r56.status_code == 400 and _p9_cfg.load_config().get("bind_host") == "127.0.0.1",
          repr((_r56.status_code, _p9_json(_r56), _p9_cfg.load_config().get("bind_host"))))

    # ── a JSON switch is a boolean, or a 400 ─────────────────────────────────────────────────────
    _up56, _tsb56, _boot56 = [], [], []
    _p9_patch(_rt56, "remote_tailscale_up_url",
              lambda remote, enable_ssh, advertise_routes: (_up56.append(enable_ssh) or (True, "https://x")))
    _p9_patch(_rt56, "remote_bootstrap_tailscale",
              lambda remote, auth_key, enable_ssh, advertise_routes: (_tsb56.append(enable_ssh)
                                                                      or (True, "ok", "")))
    _p9_patch(_rb56, "_begin_bootstrap", lambda app, rid, opts, uid: (_boot56.append(opts) or (False, "busy")))
    _up_url56 = "/api/remote/%d/tailscale-up" % P9_HOST
    _tsb_url56 = "/api/remote/%d/tailscale-bootstrap" % P9_HOST
    _bad56 = ([_A56.post(_up_url56, json={"enable_ssh": _v}).status_code for _v in ("false", "no", 0, None)]
              + [_A56.post(_tsb_url56, json={"auth_key": "tskey-x", "enable_ssh": "false"}).status_code])
    check("tailscale join: enable_ssh that is not a JSON boolean is a 400 and Tailscale is not asked "
          "(the string \"false\" ran `tailscale up --ssh`)",
          _bad56 == [400] * 5 and _up56 == [] and _tsb56 == [], repr((_bad56, _up56, _tsb56)))
    _A56.post(_up_url56, json={"enable_ssh": False})
    _A56.post(_up_url56, json={})
    _A56.post(_tsb_url56, json={"auth_key": "tskey-x", "enable_ssh": False})
    check("tailscale join: ...a real false turns SSH off and an absent key keeps the default on (control)",
          _up56 == [False, True] and _tsb56 == [False], repr((_up56, _tsb56)))
    _boot_url56 = "/api/remote/%d/bootstrap" % P9_HOST
    _bad56 = [_A56.post(_boot_url56, json={_k: "false"}).status_code
              for _k in ("reboot", "enable_ufw", "install_lgsm_deps", "install_fail2ban")]
    check("bootstrap: a switch that is not a JSON boolean is a 400 and nothing starts (\"false\" rebooted "
          "the host)", _bad56 == [400] * 4 and _boot56 == [], repr((_bad56, _boot56)))
    _A56.post(_boot_url56, json={"reboot": False})
    check("bootstrap: ...a real false is passed through as off, the rest default on (control)",
          len(_boot56) == 1 and _boot56[0]["do_reboot"] is False and _boot56[0]["enable_ufw"] is True,
          repr(_boot56))
    _r56 = _A56.post("/api/tags", json={"name": "p56tag", "notify": "false"})
    check("tags: a notify that is not a JSON boolean is a 400, not a tag that alerts",
          _r56.status_code == 400, repr((_r56.status_code, _p9_json(_r56))))
    _r56 = _A56.post("/api/server/%d/autostart" % P9_GS, json={"enabled": "false"})
    check("autostart: an enabled that is not a JSON boolean is a 400 (\"false\" turned autostart ON)",
          _r56.status_code == 400, repr((_r56.status_code, _p9_json(_r56))))

    # ── the backup passphrase: judged first, and before any default ──────────────────────────────
    _pp56, _set56 = [], []
    _p9_patch(_bk56, "set_passphrase", _pp56.append)
    _p9_patch(_bk56, "set_settings", lambda **k: (_set56.append(k) or {}))
    _p9_patch(_bk56, "set_full_settings", lambda **k: (_set56.append(k) or {}))
    _bad56 = [_A56.post("/api/panel/backup/settings", json={"enabled": True, "passphrase": _p}).status_code
              for _p in (None, False, 0, [])]
    check("backup settings: a falsy passphrase that is not text (null, false, 0, []) is a 400, not "
          "\"turn encryption off\"", _bad56 == [400] * 4 and _pp56 == [], repr((_bad56, _pp56)))
    _A56.post("/api/panel/backup/settings", json={"enabled": False, "passphrase": "short"})  # nosec B105 - a test value
    _A56.post("/api/panel/backup/settings", json={"enabled": "false"})
    check("backup settings: ...a refused request saves none of the other settings either (a short "
          "passphrase left enabled=false saved while the page said it failed), and enabled is a boolean",
          _set56 == [] and _pp56 == [], repr((_set56, _pp56)))
    _A56.post("/api/panel/backup/settings", json={"enabled": True, "passphrase": ""})  # nosec B105 - turns it off
    check("backup settings: ...while \"\" still turns encryption off on purpose (control)",
          _pp56 == [""] and len(_set56) == 2, repr((_pp56, _set56)))

    # ── repair: each path is text ────────────────────────────────────────────────────────────────
    _rep56 = []
    _p9_patch(_p9_so, "panel_repair", lambda paths: (_rep56.append(paths) or (True, "ok", [])))
    _bad56 = [_A56.post("/api/panel/repair", json={"paths": _p}).status_code for _p in ([{}], ["a", 1])]
    check("panel repair: a `paths` list holding something other than text is a 400, not a 500",
          _bad56 == [400, 400] and _rep56 == [], repr((_bad56, _rep56)))
finally:
    _p9_restore_all()
    if _CFG56_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG56_SNAPSHOT)
check("part56: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP56_START, repr(_P9_TRIPPED[_TRIP56_START:][:6]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. scripts, in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RMB56 = _read56(_JS56, "remote_manage_backups.js")

# ── a game's Keep box with text it cannot parse is not "clear the override" ─────────────────────
_name56 = "backup schedule: an unparseable Keep box is refused on the page"
_out56 = _node56(_name56, (
    "global.window = global; global.MOUNT = ''; const sent = [], msgs = [];\n"
    "global.bkMsg = (m) => msgs.push(m); global.t = s => s;\n"
    "global.fetch = (u, o) => { sent.push(o.body); return new Promise(() => {}); };\n"
    "let bad = true;\n"
    "global.document = {getElementById: id => id.startsWith('gsk-')\n"
    "  ? {value: '', validity: {badInput: bad}} : {value: ''}};\n"
    "window._bkSched = {7: {keep_set: true, keep: 5, interval_set: false}};\n"
    + _cut47(_RMB56, "function setGameSchedule(") + "\n"
    "setGameSchedule(7); const out = {bad: [sent.splice(0), msgs.splice(0)]};\n"
    "bad = false; setGameSchedule(7); out.empty = sent.splice(0);\n"
    "console.log(JSON.stringify(out));\n"))
if _out56 is not None:
    check("backup schedule: a Keep box holding text it cannot parse (\"7d\") sends nothing and says so — "
          "it sent \"\", which cleared the override and said \"Schedule saved\"",
          _out56.get("bad", [None])[0] == [] and len(_out56.get("bad", [[], []])[1]) == 1, repr(_out56))
    check("backup schedule: ...a box the user emptied still clears it (control)",
          _out56.get("empty") == ['{"keep":""}'], repr(_out56))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. tools
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _bash56(script, env=None):
    return _sp56.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607 - fixture script
                     timeout=60, env=dict(os.environ, **(env or {})), check=False)


# ── install.sh: a port range and an outbound rule, read for what they are ───────────────────────
_INS56 = _read56(_root, "install.sh")
_blk56 = _INS56[_INS56.index("UFW_ACTIVE=0; TS_UFW=0; PORT_OPEN=0; UFW_READ=0"):
                _INS56.index("\n# While the wizard has no administrator")]
_fw56 = {}
for _k56, _st56 in (("range deny", "5000:5010/tcp   DENY   Anywhere\n"),
                    ("list deny", "80,5000/tcp   DENY   Anywhere\n"),
                    ("range allow", "4990:5005/tcp   ALLOW   Anywhere\n"),
                    ("udp range", "5000:5010/udp   DENY   Anywhere\n"),
                    ("range elsewhere", "6000:6010/tcp   DENY   Anywhere\n"),
                    ("allow out", "5000/tcp   ALLOW OUT   Anywhere\n")):
    _r56 = _bash56("set -euo pipefail\nPORT=5000 SUDO= TS_ADDR=\nok() { echo \"OK $*\"; }\n"
                   "command() { [ \"$1\" = -v ] && [ \"$2\" = ufw ] && return 0; builtin command \"$@\"; }\n"
                   "ufw() { case \"$1\" in status) printf 'Status: active\\n\\nTo   Action  From\\n%%s' \"$ST\";;\n"
                   "  allow) echo \"ALLOWED $2\";; esac; }\n%s\necho \"OPEN=${PORT_OPEN} RULED=${PORT_RULED}\"\n"
                   % _blk56, env={"ST": _st56})
    _fw56[_k56] = ("OK Opened 5000/tcp" in _r56.stdout, (_r56.stdout.strip().splitlines() or [""])[-1])
check("install.sh: a port RANGE or list covering the panel port is the operator's rule — no `ufw allow` "
      "behind `5000:5010/tcp DENY` (it appended one and printed \"Opened\"), and a range ALLOW is open",
      _fw56["range deny"] == (False, "OPEN=0 RULED=1") and _fw56["list deny"] == (False, "OPEN=0 RULED=1")
      and _fw56["range allow"] == (False, "OPEN=1 RULED=1"), repr(_fw56))
check("install.sh: an OUTBOUND rule on the port is not a rule for reaching the panel — the port is still "
      "opened (it was left closed, the banner saying a rule \"limits\" it)",
      _fw56["allow out"] == (True, "OPEN=1 RULED=0"), repr(_fw56))
check("install.sh: ...a udp range, or a range that misses the port, is still no rule for it (control)",
      _fw56["udp range"] == (True, "OPEN=1 RULED=0") and _fw56["range elsewhere"] == (True, "OPEN=1 RULED=0"),
      repr(_fw56))
_pub56 = _INS56[_INS56.index('PUBLIC_IP="$('):_INS56.index("host_addr_fallback)", _INS56.index('PUBLIC_IP="$('))]
check("install.sh: the public address printed beside the IPv4 firewall verdict is fetched over IPv4 "
      "(ifconfig.me answers IPv6 to an IPv6 connection)",
      _pub56.count("curl ") == 2 and _pub56.count("curl -4 ") == 2, _pub56)

# ── gamedig's osv-scanner ignores describe the tree they ignore ──────────────────────────────────
# Each reason names the dependency path it reviewed ("got 13.0.0 -> ... -> http-cache-semantics
# 4.2.0"). #417 moved the lockfile to 4.3.0 and left the reason naming 4.2.0, so the reviewed text
# no longer described what is installed. Every "-> name version" in a reason must be the locked one.
# Read as text: the 3.10 CI leg has no tomllib. A reason is a """...""" string with "\" line joins.
# A one-line "..." reason too: only the triple-quoted form was read, so a reason written the short
# way read as no reason at all. And as many reasons as the file declares (comments aside).
_osv56_txt = _read56(_root, "tools", "gamedig", "osv-scanner.toml")
_osv56 = [(_a or _b).replace("\\\n", "") for _a, _b in
          _re56.findall(r'^\s*reason\s*=\s*(?:"""(.*?)"""|"([^"\n]*)")', _osv56_txt, _re56.S | _re56.M)]
_osv56_declared = sum(1 for _l in _osv56_txt.splitlines()
                      if _re56.match(r"\s*reason\s*=", _l.split("#", 1)[0]))
check("gamedig osv-scanner: every reason the file declares is read (either string form)",
      _osv56_declared == len(_osv56), "%d declared, %d read" % (_osv56_declared, len(_osv56)))
_lock56 = _json56.loads(_read56(_root, "tools", "gamedig", "package-lock.json"))["packages"]


def _stale_versions56(reasons):
    """Each "-> name version" a reason names that the lockfile does not install, as (name, named, locked)."""
    out = []
    for _e in reasons:
        for _pkg, _ver in _re56.findall(r"->\s+([@a-z0-9._/-]+)\s+(\d+\.\d+\.\d+)", _e):
            _have = (_lock56.get("node_modules/" + _pkg) or {}).get("version")
            if _have != _ver:
                out.append((_pkg, _ver, _have))
    return out


# The file may hold no ignores at all (the GHSA-ch52 one was removed once 4.3.0 left its range), so
# the real read can be empty; the control below keeps the reader honest whether or not it is.
_stale56 = _stale_versions56(_osv56)
check("gamedig osv-scanner: every package version an ignore's reason names is the one the lockfile "
      "installs (the reason still named http-cache-semantics 4.2.0 after the lock moved to 4.3.0)",
      not _stale56, repr((len(_osv56), _stale56)))
_ctl56 = _stale_versions56(["here only as got 13.0.0 -> cacheable-request 10.2.14 -> "
                            "http-cache-semantics 4.2.0 (reviewed)"])
check("gamedig osv-scanner: ...a reason naming a version the lock does not install IS caught (control: "
      "the #417 text naming http-cache-semantics 4.2.0 against the locked 4.3.0)",
      ("http-cache-semantics", "4.2.0", "4.3.0") in _ctl56, repr(_ctl56))


# ── js_coverage: the 375px rename flow's cleanup cannot swallow its own failed check ─────────────
# run.py puts tools/js_coverage at sys.path[0] and imports its siblings as TOP-LEVEL modules; left
# there, any later `import flows`/`walk`/`driver`/`cdp`/`run` got the harness's file (part14 and
# part53 put both back, and check it). Taken by name here, then sys.path and the table are restored.
_jc56_path0, _jc56_mods0 = list(_sys56.path), set(_sys56.modules)
try:
    _spec56 = _ilu56.spec_from_file_location("jscov56_run",
                                             os.path.join(_root, "tools", "js_coverage", "run.py"))
    _run56 = _ilu56.module_from_spec(_spec56)
    with _ctx56.redirect_stdout(_io56.StringIO()):
        _spec56.loader.exec_module(_run56)
    _flows56, _drv56 = _sys56.modules.get("flows"), _sys56.modules.get("driver")
finally:
    _sys56.path[:] = _jc56_path0
    for _jc56_m in set(_sys56.modules) - _jc56_mods0:
        del _sys56.modules[_jc56_m]
check("part56: loading run.py leaves sys.path and the top-level module names as they were",
      _sys56.path == _jc56_path0 and not ({"walk", "driver", "flows", "cdp", "v8_lcov"}
                                          & set(_sys56.modules))
      and None not in (_flows56, _drv56), repr(_sys56.path[:2]))


class _PhoneDrv56:
    """Every step answers nothing (so the fit check fails); a second goto has lost its session."""

    def __init__(self):
        self.gotos, self.cdp = [], _NS56(call=lambda *a, **k: None)

    def goto(self, path):
        self.gotos.append(path)
        if len(self.gotos) > 1:
            raise _drv56.LoginFailed("the session was lost")

    def run(self, js):
        return {}

    def keys(self, text):
        return None


try:
    _flows56._rename_phone(_PhoneDrv56())
    _ph56 = "no exception"
except Exception as _e56:  # noqa: BLE001 - which class arrives IS the check
    _ph56 = type(_e56).__name__
check("js coverage: the 375px rename flow's failed fit check reaches the run as a FlowAssertion even when "
      "its cleanup's page load cannot log in (the cleanup's LoginFailed replaced it, and only warned)",
      _ph56 == "FlowAssertion", _ph56)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. the console's catch-up against a rebuild (server_detail.js, in node)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SD56 = _read56(_JS56, "server_detail.js")
_CONSOLE56 = (
    "global.window = global; var _lastPanelT = 0, _resync = null, _logAt = null, _consoleLines = [],\n"
    "  _awayRead = false, _shownOnReturn = {}, shown = [], _rebuildPushes = [], _rebuildSeq = 0,\n"
    "  _REBUILD_KEEP = 2000;\n"
    "function appendConsole(text, ts){ shown.push(text); }\n"
    "function _r13c_notePanelPush(){}\n"
    "function _showReturnGap(){ shown.push('GAP'); }\n"
    "function _appendConsoleRows(rows, ts, at){ if (!rows.length) return;\n"
    "  _consoleLines = _consoleLines.concat(rows.map(r => r.line)); _logAt = Array.isArray(at) ? at : null; }\n"
    + "\n".join(_cut47(_SD56, h) for h in (
        "function _panelShownAt(", "function _endResync(", "function _showPanelPush(",
        "function _r11c_resyncFrom(", "function _resyncRelease(", "function _pushAfter(", "function _resyncRows(",
        "function _rebuildNotePush(", "function _rebuildMark(", "function _rebuildHasRun(",
        "function _rebuildRestore(", "function _sameLine(", "function _eqRange(", "function _newConsoleLines(",
        "function _resyncShowAway(", "function _returnOverlap(", "function _appendReturnRows("))
    + "\nfunction _startResync(prime){ _endResync(); }\n")

_name56 = "console: held panel pushes and a rebuild"
_out56 = _node56(_name56, _CONSOLE56 + (
    "const out = {};\n"
    # Load older rendered the backlog up to t=110; the catch-up held pushes at 100 and 110 (in that
    # backlog) and one at 120 (after it).
    "_resync = {held: [{panel: true, ts: 100, data: 'p100'}, {panel: true, ts: 110, data: 'p110'},\n"
    "  {panel: true, ts: 120, data: 'p120'}], prime: false};\n"
    "_lastPanelT = 110; _r11c_resyncFrom([0, 1, 50]); out.older = shown.splice(0);\n"
    # The answer path releases what is held the same way.
    "_lastPanelT = 0; _resyncRelease({held: [{panel: true, ts: 5, data: 'p5'}]}, null);\n"
    "out.release = shown.splice(0);\n"
    # Load older asks at T; a catch-up answers before it, appending c..e from the page's place; the
    # read's answer then rebuilds the console from a window ending at c, and restores what was noted.
    "_consoleLines = ['a', 'b']; const mark = _rebuildMark();\n"
    "_resyncShowAway([{line: 'c'}, {line: 'd'}, {line: 'e'}],\n"
    "  {since: [0, 1, 5], at: [0, 1, 9], now: 1}, false);\n"
    "_consoleLines = []; _appendConsoleRows([{line: 'a'}, {line: 'b'}, {line: 'c'}], null, [0, 1, 6]);\n"
    "_rebuildRestore(mark); out.race = _consoleLines.slice();\n"
    # A held log push released by the answer is noted as well.
    "_consoleLines = ['a']; const mark2 = _rebuildMark();\n"
    "_resyncRelease({held: [{rows: [{line: 'f'}], ts: 2, at: [0, 1, 12]}]}, [0, 1, 10]);\n"
    "_consoleLines = ['a']; _rebuildRestore(mark2); out.released = _consoleLines.slice();\n"
    "console.log(JSON.stringify(out));\n"))
if _out56 is not None:
    check("console: Load older during a catch-up does not show the held panel lines its backlog already "
          "rendered a second time — only the newer one",
          _out56.get("older") == ["p120"], repr(_out56))
    check("console: ...and a held panel line nothing has shown is still shown when released (control)",
          _out56.get("release") == ["p5"], repr(_out56))
    check("console: a catch-up answered while Load older is in flight is put back after the rebuilt window "
          "(the lines between the window's end and the catch-up's were silently missing)",
          _out56.get("race") == ["a", "b", "c", "d", "e"], repr(_out56))
    check("console: ...and a held log push the catch-up releases is put back the same way",
          _out56.get("released") == ["a", "f"], repr(_out56))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. pages a Spanish or French viewer reads (node, on a small DOM of this part's own)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _catalog56(lang):
    out = {}
    tdir = os.path.join(_root, "translations", lang)
    for fname in sorted(os.listdir(tdir)):
        if fname.endswith(".json"):
            out.update(_json56.loads(_read56(tdir, fname)))
    return out


_ES56 = _catalog56("es")


def _es_for56(*sources):
    """Return the Spanish catalog cut to the keys `sources` contain.

    Node takes the program as ONE argument, and the whole catalog is past the kernel's limit for one.
    """
    text = "".join(sources)
    return {_k: _v for _k, _v in _ES56.items() if _k in text}


# Elements with children, text nodes, attributes, and a walk that lists every visible text node the
# page's translator would reach (none under data-no-i18n): enough to build a dialog and read it.
_DOM56 = r"""
class Node56 { constructor(tag){ this.tagName = tag; this.children = []; this.attrs = {}; this.style = {};
    this.className = ''; this.listeners = {}; this.parentNode = null; this.hidden = false; this.disabled = false; }
  appendChild(c){ c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref){ c.parentNode = this; const i = this.children.indexOf(ref);
    if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  get firstChild(){ return this.children[0] || null; }
  setAttribute(k, v){ this.attrs[k] = String(v); } getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k){ return k in this.attrs; }
  set textContent(v){ this.children = []; if (v !== '' && v != null) this.appendChild(new Text56(String(v))); }
  get textContent(){ return this.children.map(c => c.textContent).join(''); }
  addEventListener(ev, fn){ this.listeners[ev] = fn; } remove(){ this.removed = true; }
  querySelector(){ return new Node56('STUB'); } }
class Text56 { constructor(v){ this.nodeValue = v; this.parentNode = null; }
  get textContent(){ return this.nodeValue; } }
global.document = { body: new Node56('BODY'), createElement: t => new Node56(t.toUpperCase()),
  createTextNode: v => new Text56(v), createDocumentFragment: () => new Node56('FRAG'),
  getElementById: id => (global.__ids || {})[id] || null, querySelector: s => (global.__qs || {})[s] || null,
  querySelectorAll: () => [] };
function visibleTexts(n, out){ out = out || [];
  if (n instanceof Text56){ const v = n.nodeValue.replace(/\s+/g, ' ').trim(); if (v) out.push(v); return out; }
  if (n.hasAttribute && n.hasAttribute('data-no-i18n')) return out;
  // markup a script assigned: each text run between tags is a text node of its own
  if (typeof n.innerHTML === 'string')
    n.innerHTML.split(/<[^>]*>/).forEach(v => { v = v.replace(/\s+/g, ' ').trim(); if (v) out.push(v); });
  n.children.forEach(c => visibleTexts(c, out)); return out; }
"""

# ── the players dialogs: every word reaches the translator, as a whole catalog key ──────────────
_SA56 = _read56(_JS56, "server_actions.js")
_name56 = "players dialog: every sentence translatable"
_out56 = _node56(_name56, _DOM56 + (
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.SERVER_NAME = 'Test';\n"
    "const ES = %s; global.t = s => (Object.prototype.hasOwnProperty.call(ES, s) ? ES[s] : s);\n"
    "global._discT = global.t; global.toast = () => 0; global.bkMsg = () => 0; global.fbStart = () => 0;\n"
    "global._doServerAction = () => 0; global.showPendingBanner = () => 0;\n"
    "global._esc = s => String(s);\n" % _json56.dumps(_es_for56(_SA56, _RMB56))
    + (_cut47(_SA56, "function _r12c_el(") if "function _r12c_el(" in _SA56 else "") + "\n"
    + _cut47(_SA56, "function actionPlayersDialog(") + "\n"
    + _cut47(_RMB56, "function fbPlayersDialog(") + "\n"
    # A sentence with its count and name in it is one translated template, cut at its {slots}
    # (i18n.js tfNodes): its text nodes are the pieces of a translated VALUE between the slots.
    + _cut47(_read56(_JS56, "i18n.js"), "window.tfNodes = function(") + "\n"
    "const vals = new Set(Object.values(ES)); const out = {english: [], names: []};\n"
    "for (const v of Object.values(ES)) v.split(/\\{\\w+\\}/).forEach(p => {\n"
    "  p = p.replace(/\\s+/g, ' ').trim(); if (p) vals.add(p); });\n"
    "for (const [kind, n] of [['stop', 1], ['stop', 3], ['restart', 1], ['restart', 3],\n"
    "                         ['backup', 1], ['backup', 4]]) {\n"
    "  document.body.children = [];\n"
    "  try {\n"
    "    if (kind === 'backup') fbPlayersDialog([{name: 'Server', players: n}, {name: 'Game', players: 1}]);\n"
    "    else actionPlayersDialog(kind, n, {});\n"
    "  } catch (e) { out.english.push(kind + ': ' + e.message); continue; }\n"
    "  for (const v of visibleTexts(document.body))\n"
    "    if (/[A-Za-z]{2}/.test(v) && !vals.has(v)) out.english.push(kind + n + ': ' + v);\n"
    "  // the server's name and the counts are shown, kept from the translator\n"
    "  const all = JSON.stringify(document.body, (k, v) => k === 'parentNode' ? undefined : v);\n"
    "  if (all.indexOf(kind === 'backup' ? 'Server (' : '\"Test\"') < 0) out.names.push(kind + n);\n"
    "}\n"
    "console.log(JSON.stringify(out));\n"))
if _out56 is not None:
    check("players dialog (restart/stop, and the backup one): with Spanish selected every sentence in it is "
          "translated — it was one innerHTML string with the count and name spliced in, all English but "
          "\"Cancel\"", _out56.get("english") == [] and "error" not in _out56, repr(_out56))
    check("players dialog: ...and it still names the server and the count, kept from the translator (control)",
          _out56.get("names") == [], repr(_out56))

# ── the i18n gate reads text built inside markup, and what is handed to t() ─────────────────────
# tools/ on sys.path only for this import (part53 does the same, and says why).
_i18n56_path0, _i18n56_mods0 = list(_sys56.path), set(_sys56.modules)
_sys56.path.insert(0, os.path.join(_root, "tools"))
try:
    import i18n_scan as _i18n56  # noqa: E402
finally:
    _sys56.path[:] = _i18n56_path0
    for _i18n56_m in set(_sys56.modules) - _i18n56_mods0:
        del _sys56.modules[_i18n56_m]
check("part56: importing tools/i18n_scan leaves sys.path and the module table as they were",
      _sys56.path == _i18n56_path0 and "i18n_scan" not in _sys56.modules, repr(_sys56.path[:2]))
_tdir56 = os.path.realpath(_tf56.mkdtemp(prefix="lgsm-unit-p56-i18n-"))
try:
    with open(os.path.join(_tdir56, "a.js"), "w", encoding="utf-8") as _fh56:
        _fh56.write("el.innerHTML = '<thead><tr><th>Widgetry</th><th title=\"x\">Gadgets galore</th>"
                    "</tr></thead>';\n"
                    "out.innerHTML = '<span class=\"s\"><i class=\"bi bi-x\"></i> Scan went sideways.</span>';\n"
                    "p.innerHTML = '<strong>' + n + '</strong> players are connected to <strong>';\n"
                    "head.textContent = t(one ? 'player is wired to' : 'players are wired to');\n"
                    "x.title = t(action === 'halt' ? 'Halt server' : 'Resume server');\n")
    _js56 = set(_i18n56.scan_js(_tdir56))
finally:
    _shutil56.rmtree(_tdir56, ignore_errors=True)
check("i18n scan: an element's whole text inside an innerHTML-built literal is asked for (the players "
      "dialog and 117 more strings were invisible to the gate: a literal with `<` was dropped whole)",
      {"Widgetry", "Gadgets galore", "Scan went sideways."} <= _js56, repr(sorted(_js56)))
check("i18n scan: ...and so is every literal handed to t(), lower-case or one word",
      {"player is wired to", "players are wired to", "Halt server", "Resume server"} <= _js56,
      repr(sorted(_js56)))
check("i18n scan: ...but not prose spliced to a value at a literal's edge, nor the value t() chooses by "
      "(control)", "players are connected to" not in _js56 and "halt" not in _js56, repr(sorted(_js56)))

# ── the discovery card (#disc-result is data-no-i18n): built translated ──────────────────────────
_name56 = "discovery card: built translated"
_out56 = _node56(_name56, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.REMOTE_ID = 2;\n"
    "const ES = %s; global.t = s => (Object.prototype.hasOwnProperty.call(ES, s) ? ES[s] : s);\n"
    "global.escapeHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')\n"
    "  .replace(/>/g, '&gt;').replace(/\"/g, '&quot;');\n"
    "global._da = () => ''; const out = {innerHTML: '', insertBefore(){}, firstChild: null};\n"
    "global.document = {getElementById: id => id === 'disc-result' ? out : null,\n"
    "  createDocumentFragment: () => ({appendChild(){}})};\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve({servers: [\n"
    "  {user: 'mc', game_type: 'mc', game_name: 'Minecraft', port: 25565, autostart: true}]})});\n"
    % _json56.dumps(_es_for56(_RMB56))
    + _cut47(_RMB56, "function _discT(") + "\n" + _cut47(_RMB56, "function prependContentNotes(") + "\n"
    + _cut47(_RMB56, "function scanExisting(") + "\n"
    "(async () => { scanExisting(); await settle(); console.log(JSON.stringify({html: out.innerHTML})); })();\n"))
if _out56 is not None:
    _h56 = _out56.get("html", "")
    _want56 = [_ES56.get(_k) for _k in ("Import selected", "Mods", "User", "autostart", "Installed mods")]
    check("discovery card: with Spanish selected its headers, badge and Import button are translated (the "
          "container is data-no-i18n, so they stayed English)",
          all(_w and _w in _h56 for _w in _want56) and ">Import selected<" not in _h56, _h56[:600])


# ── names are guarded one by one; the containers around them are not ───────────────────────────
# Any variable spelling, and any filters after it (`{{ u.username|e }}`): lower-case names with no
# filter only was the narrowing part53's _bare_names53 was widened from (review 1011b).
_NAME56 = _re56.compile(r"\{\{\s*[A-Za-z_]\w*(?:\.\w+)*\.(?:name|username|display_name|hostname|comment|"
                        r"created_by|player_name|reason)(?:\s+or\s+'[^']*')?"
                        r"(?:\s*\|\s*\w+(?:\([^)]*\))?)*\s*\}\}")
_VOID56 = {"input", "br", "img", "hr", "meta", "link", "source", "wbr", "col", "area", "base", "embed"}


def _guarded_stack56(src, pos):
    """Whether an element open at `pos` carries data-no-i18n, or is one the translator skips."""
    stack = []
    head = _re56.sub(r"\{#.*?#\}", "", src[:pos], flags=_re56.S)
    for m in _re56.finditer(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>", head):
        close, tag, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if close:
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == tag:
                    del stack[k:]
                    break
        elif tag not in _VOID56 and not attrs.rstrip().endswith("/"):
            stack.append((tag, "data-no-i18n" in attrs))
    return any(g or t in ("code", "pre", "script", "style", "textarea") for t, g in stack)


def _bare_user_text56():
    bad = []
    strip = lambda t: _re56.sub(r"\{%.*?%\}|\{#.*?#\}", "", t, flags=_re56.S).strip()  # noqa: E731
    for fname in sorted(os.listdir(_TPL56)):
        if not fname.endswith(".html"):
            continue
        src = _read56(_TPL56, fname)
        for m in _NAME56.finditer(src):
            before, after = src[:m.start()], src[m.end():]
            lt, gt = before.rfind("<"), before.rfind(">")
            if lt > gt or strip(before[gt + 1:]) or strip(after[:after.find("<")]):
                continue                  # an attribute value, or part of a longer text node
            if not _guarded_stack56(src, m.start()):
                bad.append("%s:%d" % (fname, src.count("\n", 0, m.start()) + 1))
    return bad


_bare56 = _bare_user_text56()
check("templates: no user-authored text (a username, a group, command or tag name, a rule comment, a ban's "
      "player, reason or author) is a bare text node the translator can swap — \"Admin\" read "
      "\"Administrador\" on its own Account page", not _bare56, repr(_bare56))
_dash56, _rmh56 = _read56(_TPL56, "dashboard.html"), _read56(_TPL56, "remote_manage.html")
check("templates: the tag list and the Panel Server's game-backup list are not data-no-i18n as a whole "
      "(\"Delete\", \"Back up now\" and the empty states stayed English)",
      # The whole opening tag, wherever the attribute sits in it — and the tag must be THERE: a
      # renamed id read as "not guarded" too.
      all(_tags and not any("data-no-i18n" in _t for _t in _tags)
          for _tags in (_re56.findall(r'<[^>]*\bid="tag-list"[^>]*>', _dash56),
                        _re56.findall(r'<[^>]*\bid="fb-games"[^>]*>', _rmh56))),
      "a container is still guarded, or is gone")
_logs56 = _read56(_TPL56, "logs.html")
check("templates: the audit log's User filter lists each user under data-no-i18n",
      _re56.search(r"<option [^>]*data-no-i18n>\{\{ u \}\}</option>", _logs56) is not None, "unguarded")

# nags.js: a remote's name is guarded; the panel host's fixed label is not (review 1015c, part87).
_JSNAMES56 = (("nags.js", r'class="alert-link"[^\']*\'\s*\+\s*\(h\.local \? \'\' : \' data-no-i18n\'\)\s*\+\s*'
                          r'\' href="\'\s*\+\s*escapeHtml\(h\.url\)'),
              ("remote_manage.js", r"<td class=\"small\" data-no-i18n>'\+escapeHtml\(e\.user"),
              ("remote_firewall.js", r"data-no-i18n>' \+ esc\(g\.comment"),
              ("remote_firewall.js", r'badge bg-dark" data-no-i18n>\' \+ esc\(c\)'),
              ("remote_manage_backups.js", r"<strong data-no-i18n>'\+escapeHtml\(g\.name\)"),
              ("remote_manage_backups.js", r"<span data-no-i18n>'\+escapeHtml\(g\.host\)"))
_jsbad56 = [f for f, rx in _JSNAMES56 if _re56.search(rx, _read56(_JS56, f)) is None]
check("scripts: a host name, a username, a rule comment and a game or host name in the backup list are "
      "each written under data-no-i18n", not _jsbad56, repr(_jsbad56))

# ── the tag list: the count is a node, each phrase another ───────────────────────────────────────
_ST56 = _read56(_JS56, "server_tags.js")
_name56 = "tag list: phrases the translator can match"
_out56 = _node56(_name56, _DOM56 + (
    "global.window = global; const box = new Node56('DIV'); global.__ids = {'tag-list': box};\n"
    "var TAGS = [{id: 1, name: 'Admin', color: '', server_count: 3, notify: false}];\n"
    "function deleteTag(){}\n"
    + _cut47(_ST56, "function tagMuted(") + "\n" + _cut47(_ST56, "function chip(") + "\n"
    + _cut47(_ST56, "function renderTagList(") + "\n"
    "renderTagList(); console.log(JSON.stringify(visibleTexts(box)));\n"))
if _out56 is not None:
    check("tag list: each row's words are whole nodes the catalog has (\"3 server(s) · alerts muted\" was one "
          "node no key matched), and the tag's own name is kept from the translator",
          isinstance(_out56, list) and "Admin" not in _out56
          and all(_v in _ES56 or not _re56.search(r"[A-Za-z]{2}", _v) for _v in _out56), repr(_out56))

# ── the host page's Maintenance tab and its loaders, for a delegated host admin ──────────────────
_mli56 = _rmh56.index('data-mtab-btn="maintenance"')
_mif56 = _rmh56.rfind("{% if _host_ctl %}", 0, _mli56)
check("host page: the Maintenance tab is offered only where its cards render (_host_ctl) — a delegated host "
      "admin on the panel host opened it onto a blank page",
      _mif56 > 0 and "{% endif %}" not in _rmh56[_mif56:_mli56], _rmh56[max(0, _mli56 - 300):_mli56])
_RMHJ56 = _read56(_JS56, "remote_manage_host.js")
_name56 = "host page: panel-only loaders"
_out56 = _node56(_name56, (
    "global.window = global; global.MOUNT = ''; const asked = [];\n"
    "global.fetch = u => { asked.push(u); return new Promise(() => {}); };\n"
    "global.document = {getElementById: () => null};\n"
    + "\n".join(_cut47(_RMHJ56, h)
                for h in ("function loadIntegrity(", "function loadDbStats(", "function loadAutoUpd(")) + "\n"
    + _cut47(_RMB56, "function loadBackups(") + "\n"
    "loadIntegrity(); loadDbStats(); loadAutoUpd(); loadBackups(); console.log(JSON.stringify(asked));\n"))
if _out56 is not None:
    check("host page: with the panel-only cards not rendered (a delegate's page) their four loaders ask "
          "nothing — each was a superadmin-only request answered 403 on every load",
          _out56 == [], repr(_out56))

# ── the account page's layout card follows its own buttons ───────────────────────────────────────
_AS56 = _read56(_JS56, "account_sessions.js")
_name56 = "account: layout card after publish and reset"
_out56 = _node56(_name56, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.toast = () => 0; global.t = s => s;\n"
    "global.confirmDialog = o => o.onConfirm(); function mp(){ return ''; }\n"
    "const clear = {disabled: true}, pub = {disabled: false}, reset = {disabled: false};\n"
    "const own = {hidden: false}, dflt = {hidden: true};\n"
    "global.document = {getElementById: id => ({'acct-layout-own': own, 'acct-layout-default': dflt})[id] || null,\n"
    "  querySelector: s => s.indexOf('clearDashDefault') >= 0 ? clear\n"
    "                   : s.indexOf('publishDashLayout') >= 0 ? pub : null};\n"
    "global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve({success: true})});\n"
    + _AS56[_AS56.index("// Publish this superadmin"):_AS56.rindex("})();")] + "\n"
    "(async () => { publishDashLayout(pub); await settle(); const out = {clear: clear.disabled};\n"
    "  resetDashLayout(reset); await settle();\n"
    "  Object.assign(out, {reset: reset.disabled, pub: pub.disabled, own: own.hidden, dflt: dflt.hidden});\n"
    "  console.log(JSON.stringify(out)); })();\n"))
if _out56 is not None:
    check("account: after Publish, \"Remove the panel default\" is enabled; after Reset, Publish is disabled "
          "and the card says the default order is in use (both waited for a reload)",
          _out56 == {"clear": False, "reset": True, "pub": True, "own": True, "dflt": False}, repr(_out56))
_acct56 = _read56(_TPL56, "account.html")
check("account: both layout sentences are in the page, one hidden, so the swap stays translated",
      'id="acct-layout-own"' in _acct56 and 'id="acct-layout-default"' in _acct56, "a sentence is missing")

# ── the install page: Refresh list comes back; the GMod option follows the game ──────────────────
_MS56 = _read56(_JS56, "manage_servers.js")
_name56 = "install page: Refresh list after a failed swap"
_out56 = _node56(_name56, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.toast = () => 0;\n"
    "global.refreshSection = () => Promise.resolve();   // its page fetch failed: nothing swapped\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve({success: true, games: 141})});\n"
    "const opt = {style: {display: ''}}, sel = {value: '', options: []};\n"
    "global.document = {getElementById: id => ({'gmod-content-opt': opt, 'game-type-select': sel})[id] || null};\n"
    + _cut47(_MS56, "function refreshGameList(") + "\n" + _cut47(_MS56, "function filterGamesForHost(") + "\n"
    "(async () => { const btn = {innerHTML: 'Refresh list', getAttribute: () => null, disabled: false};\n"
    "  refreshGameList(btn); await settle(); filterGamesForHost();\n"
    "  console.log(JSON.stringify({disabled: btn.disabled, label: btn.innerHTML, gmod: opt.style.display})); })();\n"))
if _out56 is not None:
    check("install page: Refresh list is usable again after a refresh whose page fetch failed (it stayed "
          "disabled on \"Refreshing…\")", _out56.get("disabled") is False and _out56.get("label") == "Refresh list",
          repr(_out56))
    check("install page: ...and the GMod content option hides when no game is selected (a refreshed list "
          "left it showing beside an empty select)", _out56.get("gmod") == "none", repr(_out56))

# ── the 2FA reminder with site data blocked ─────────────────────────────────────────────────────
_name56 = "2fa reminder: blocked storage"
_out56 = _node56(_name56, (
    "global.window = global; const nag = {removed: false, remove(){ this.removed = true; }};\n"
    "global.document = {getElementById: () => nag};\n"
    "Object.defineProperty(global, 'sessionStorage', {get(){ throw new Error('SecurityError'); }});\n"
    "let threw = null;\n"
    "try { eval(" + _json56.dumps(_read56(_JS56, "otp_nag.js")) + "); } catch (e) { threw = e.message; }\n"
    "console.log(JSON.stringify({threw, removed: nag.removed}));\n"))
if _out56 is not None:
    check("2fa reminder: where sessionStorage throws (site data blocked) the script does not throw on load, "
          "and the banner stays", _out56 == {"threw": None, "removed": False}, repr(_out56))

# ── the file editor: the highlighted row is the file it holds ────────────────────────────────────
_SF56 = _read56(_JS56, "server_files.js")
_name56 = "file editor: highlight follows the open file"
_out56 = _node56(_name56, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "global.CSS = {escape: s => s}; var curFile = 'a.cfg';\n"
    "const mk = p => ({p, on: false, classList: {add(){ this.o.on = true; }, remove(){ this.o.on = false; }}});\n"
    "const rows = [mk('a.cfg'), mk('big.bin')]; rows.forEach(r => r.classList.o = r); rows[1].on = true;\n"
    "global.document = {getElementById: () => ({textContent: '', style: {}}),\n"
    "  querySelectorAll: () => rows.filter(r => r.on),\n"
    "  querySelector: s => rows.find(r => s.indexOf('\"' + r.p + '\"') >= 0) || null};\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve({error: 'File too large'})});\n"
    + ("var _openSeq = 0;\n" + _cut47(_SF56, "function _r12c_markOpenFile(") + "\n"
       if "function _r12c_markOpenFile(" in _SF56 else "var _openSeq = 0;\n")
    + _cut47(_SF56, "function openFile(") + "\n"
    "(async () => { openFile('big.bin'); await settle();\n"
    "  console.log(JSON.stringify({cur: curFile, lit: rows.filter(r => r.on).map(r => r.p)})); })();\n"))
if _out56 is not None:
    check("file editor: a file that cannot be opened leaves the highlight on the file the editor still holds "
          "(the refused row stayed lit over the other file's text)",
          _out56 == {"cur": "a.cfg", "lit": ["a.cfg"]}, repr(_out56))

# ── the dashboard's failed-install resync is bounded ─────────────────────────────────────────────
_DJ56 = _read56(_JS56, "dashboard.js")
_name56 = "dashboard: failed-banner resync bounded"
_out56 = _node56(_name56, (
    "global.window = global; let swaps = 0; global.refreshSection = () => { swaps++; };\n"
    "let shown = [];\n"
    "global.document = {getElementById: () => ({}),\n"
    "  querySelectorAll: () => shown.map(id => ({getAttribute: () => id}))};\n"
    + (_DJ56[_DJ56.index("var _r12c_failedAsked"):_DJ56.index("\n", _DJ56.index("var _r12c_failedAsked"))] + "\n"
       if "var _r12c_failedAsked" in _DJ56 else "")
    + _cut47(_DJ56, "function _dashResyncFailedBanners(") + "\n"
    "const failed = [{id: 7, status: 'failed'}]; const out = {};\n"
    "for (let i = 0; i < 6; i++) _dashResyncFailedBanners(failed);   // a banner the page never renders\n"
    "out.stuck = swaps; shown = ['7']; _dashResyncFailedBanners(failed); shown = [];\n"
    "_dashResyncFailedBanners(failed); out.again = swaps;\n"
    "console.log(JSON.stringify(out));\n"))
if _out56 is not None:
    check("dashboard: a failed set the page never shows a banner for is re-rendered for a few times, not on "
          "every 8 s poll forever", _out56.get("stuck") == 3, repr(_out56))
    check("dashboard: ...and once the two agree, a new disagreement re-renders again (control)",
          _out56.get("again") == 4, repr(_out56))

# ── the host page's Console button while a server installs ───────────────────────────────────────
_con56 = _re56.search(r'<a href="\{\{ url_for\(\'server_detail\', server_id=gs\.id\) \}\}"[^>]*>', _rmh56)
check("host page: a server still installing has its Console button disabled, as on the dashboard (it "
      "bounced with \"still installing\")",
      _con56 is not None and "{% if busy %} disabled{% endif %}" in _con56.group(0)
      and "{% set busy = (not gs.installed) or gs.status in ('installing', 'configuring') %}"
      in _rmh56[:_con56.start()], _con56.group(0) if _con56 else "no Console link")
