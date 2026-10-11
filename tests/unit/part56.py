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
import subprocess as _sp56  # nosec B404 - runs bash on install.sh's own block
import sys as _sys56
from types import SimpleNamespace as _NS56

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_CFG_PATH, _p9_cfg, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_so)
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
try:
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
    _A56.post("/api/panel/backup/settings", json={"enabled": False, "passphrase": "short"})
    _A56.post("/api/panel/backup/settings", json={"enabled": "false"})
    check("backup settings: ...a refused request saves none of the other settings either (a short "
          "passphrase left enabled=false saved while the page said it failed), and enabled is a boolean",
          _set56 == [] and _pp56 == [], repr((_set56, _pp56)))
    _A56.post("/api/panel/backup/settings", json={"enabled": True, "passphrase": ""})
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
_pub56 = _INS56[_INS56.index('PUBLIC_IP="$('):_INS56.index("hostname -I", _INS56.index('PUBLIC_IP="$('))]
check("install.sh: the public address printed beside the IPv4 firewall verdict is fetched over IPv4 "
      "(ifconfig.me answers IPv6 to an IPv6 connection)",
      _pub56.count("curl ") == 2 and _pub56.count("curl -4 ") == 2, _pub56)

# ── gamedig's osv-scanner ignores describe the tree they ignore ──────────────────────────────────
# Each reason names the dependency path it reviewed ("got 13.0.0 -> ... -> http-cache-semantics
# 4.2.0"). #417 moved the lockfile to 4.3.0 and left the reason naming 4.2.0, so the reviewed text
# no longer described what is installed. Every "-> name version" in a reason must be the locked one.
# Read as text: the 3.10 CI leg has no tomllib. A reason is a """...""" string with "\" line joins.
_osv56 = [_r.replace("\\\n", "") for _r in
          _re56.findall(r'^reason\s*=\s*"""(.*?)"""', _read56(_root, "tools", "gamedig", "osv-scanner.toml"),
                        _re56.S | _re56.M)]
_lock56 = _json56.loads(_read56(_root, "tools", "gamedig", "package-lock.json"))["packages"]
_stale56 = []
for _e56 in _osv56:
    for _pkg56, _ver56 in _re56.findall(r"->\s+([@a-z0-9._/-]+)\s+(\d+\.\d+\.\d+)", _e56):
        _have56 = (_lock56.get("node_modules/" + _pkg56) or {}).get("version")
        if _have56 != _ver56:
            _stale56.append((_pkg56, _ver56, _have56))
_named56 = sum(len(_re56.findall(r"->\s+[@a-z0-9._/-]+\s+\d", _e)) for _e in _osv56)
check("gamedig osv-scanner: every package version an ignore's reason names is the one the lockfile "
      "installs (the reason still named http-cache-semantics 4.2.0 after the lock moved to 4.3.0)",
      _named56 >= 2 and not _stale56, repr((_named56, _stale56)))


# ── js_coverage: the 375px rename flow's cleanup cannot swallow its own failed check ─────────────
_spec56 = _ilu56.spec_from_file_location("jscov56_run", os.path.join(_root, "tools", "js_coverage", "run.py"))
_run56 = _ilu56.module_from_spec(_spec56)
with _ctx56.redirect_stdout(_io56.StringIO()):
    _spec56.loader.exec_module(_run56)
_flows56, _drv56 = _sys56.modules["flows"], _sys56.modules["driver"]


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
