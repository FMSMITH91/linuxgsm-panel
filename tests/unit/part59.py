"""Part 59 of the unit suite: the 2026-10-11 third review's routes, tools and page fixes (builder C).

Held here, each against the code path the finding named:

* routes: every JSON switch is a boolean or a 400, in every route file (the string "false" skipped
  the pre-restore safety copy, added the allow rule it asked to remove, applied a limit, unblocked,
  turned auto-block on, dropped a whitelist entry, kicked players for a backup); a Serve that could
  not be read is not "tailnet-only"; a panel-host security log nobody answered is not "(log is
  empty)"; a retention number that cannot be read is a 400; a status read does not write onto a
  row deleted or replaced while it ran.
* pages and scripts (node, against stubs, as part47 and part56 do), and the i18n gate's blind spots.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import os
from types import SimpleNamespace as _NS59

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (_p9, P9_ADMIN, P9_GS, P9_HOST, P9_LOCAL, _P9_CFG_PATH, _p9_cfg, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_so)
from unit.part47 import _cut47, _node47
from panel.db.models import GameServer as _GS59, db as _db59
from panel.ops import backup as _bk59
from panel.ops import system_ops as _so59
from panel.ops import tailscale_integration as _ts59
from panel.routes import _shared as _sh59
from panel.routes import api as _api59
from panel.routes import host_local as _hl59
from panel.routes import panel_backup as _pb59
from panel.routes import remote_bootstrap as _rb59
from panel.routes import remote_security as _rs59
from panel.routes import remote_vps as _rv59
from panel.routes import tailscale as _tsr59

_JS59 = os.path.join(_root, "static", "js")
_TPL59 = os.path.join(_root, "templates")
_CFG59_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _read59(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node59(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _rec59(log, name, result):
    """A stub that records (name, args, kwargs) into `log` and answers `result`."""
    return lambda *a, **k: (log.append((name, a, k)) or result)


_A59 = _p9_client(P9_ADMIN)
try:
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. routes
    # ════════════════════════════════════════════════════════════════════════════════════════════

    # ── every JSON switch is a boolean, or a 400 ─────────────────────────────────────────────────
    _calls59 = []
    # The panel backup restore: "false" skipped the safety copy before overwriting panel.db.
    _p9_patch(_bk59, "restore_backup", _rec59(_calls59, "restore", (True, "restored")))
    _r59 = _A59.post("/api/panel/backup/restore", json={"name": "b.tar.gz", "skip_safety_backup": "false"})
    check("backup restore: a skip_safety_backup that is not a JSON boolean is a 400 and nothing is restored "
          "(\"false\" overwrote the panel's data with no safety copy)",
          _r59.status_code == 400 and _calls59 == [], repr((_r59.status_code, _calls59)))
    _A59.post("/api/panel/backup/restore", json={"name": "b.tar.gz", "skip_safety_backup": False})
    _A59.post("/api/panel/backup/restore", json={"name": "b.tar.gz"})
    check("backup restore: ...a real false, or no key, restores with the safety copy (control)",
          [c[2].get("skip_safety_backup") for c in _calls59] == [False, False], repr(_calls59))

    # The game backup: "false" forced a backup that stops the server and kicks its players.
    _calls59.clear()
    _p9_patch(_pb59, "_button_backup_running", _rec59(_calls59, "running?", True))
    _r59 = _A59.post("/api/panel/backup/game/%d" % P9_GS, json={"force": "false"})
    check("game backup: a force that is not a JSON boolean is a 400 before anything starts (\"false\" "
          "stopped the server and disconnected its players)",
          _r59.status_code == 400 and _calls59 == [], repr((_r59.status_code, _p9_json(_r59), _calls59)))
    _r59 = _A59.post("/api/panel/backup/game/%d" % P9_GS, json={"force": False})
    check("game backup: ...a real false goes on to the backup checks (control)",
          _r59.status_code == 200 and len(_calls59) == 1, repr((_r59.status_code, _calls59)))

    # The remote firewall's allow-from and limit: `is not False` read "false" as on.
    _calls59.clear()
    _p9_patch(_rv59, "remote_ufw_allow_from", _rec59(_calls59, "allow_from", (True, "ok")))
    _p9_patch(_rv59, "remote_ufw_limit_port", _rec59(_calls59, "limit", (True, "ok")))
    _fw59 = "/api/remote/%d/firewall/" % P9_HOST
    _bad59 = [_A59.post(_fw59 + "allow-from", json={"source": "198.51.100.4", "port": "27015",
                                                    "allow": "false"}).status_code,
              _A59.post(_fw59 + "limit", json={"port": "27015", "limit": "false"}).status_code]
    check("firewall: allow-from's allow and limit's limit that are not JSON booleans are 400s (\"false\" "
          "ADDED the rule asked to be removed, and applied the limit asked to be lifted)",
          _bad59 == [400, 400] and _calls59 == [], repr((_bad59, _calls59)))
    _A59.post(_fw59 + "allow-from", json={"source": "198.51.100.4", "port": "27015", "allow": False})
    _A59.post(_fw59 + "limit", json={"port": "27015", "limit": False})
    _A59.post(_fw59 + "limit", json={"port": "27015"})
    check("firewall: ...a real false removes or lifts, and no key keeps the default on (control)",
          [(c[0], c[2].get("allow", c[2].get("limit"))) for c in _calls59]
          == [("allow_from", False), ("limit", False), ("limit", True)], repr(_calls59))

    # Block / unblock and the auto-block switch, on a remote and on the panel host.
    _calls59.clear()
    for _mod59 in (_rs59, _hl59):
        _p9_patch(_mod59, "tailnet_exempt_ips", lambda remote, ips: set())
        _p9_patch(_mod59, "_whitelisted", lambda ip: False)
        _p9_patch(_mod59, "_set_autoblock_host", _rec59(_calls59, "set_autoblock", None))
        _p9_patch(_mod59, "_run_autoblock_now", _rec59(_calls59, "run_autoblock", None))
    _p9_patch(_rs59, "remote_ufw_deny_ip", _rec59(_calls59, "deny", (True, "ok")))
    _p9_patch(_rs59, "remote_ufw_undeny_ip", _rec59(_calls59, "undeny", (True, "ok")))
    _p9_patch(_rs59, "_follow_in_panel_gate", lambda remote, ok: None)
    _p9_patch(_p9_so, "ufw_deny_ip", _rec59(_calls59, "deny", (True, "ok")))
    _p9_patch(_p9_so, "ufw_undeny_ip", _rec59(_calls59, "undeny", (True, "ok")))
    _p9_patch(_hl59._banlist, "refresh_soon", lambda *a, **k: None)
    _sec59 = ("/api/remote/%d/security/" % P9_HOST, "/api/panel/security/")
    _bad59 = [_A59.post(b + "block", json={"ip": "198.51.100.9", "unblock": "false"}).status_code
              for b in _sec59] + [_A59.post(b + "autoblock", json={"enabled": "false"}).status_code
                                  for b in _sec59]
    check("security: block's unblock and autoblock's enabled that are not JSON booleans are 400s on both "
          "hosts (\"false\" lifted the block, and turned auto-block on and ran it)",
          _bad59 == [400] * 4 and _calls59 == [], repr((_bad59, _calls59)))
    for _b59 in _sec59:
        _A59.post(_b59 + "block", json={"ip": "198.51.100.9", "unblock": False})
        _A59.post(_b59 + "autoblock", json={"enabled": False})
    check("security: ...a real false blocks and switches auto-block off, running no pass (control)",
          [(c[0], c[1][-1] if c[0] == "set_autoblock" else None) for c in _calls59]
          == [("deny", None), ("set_autoblock", False)] * 2, repr(_calls59))

    # The security whitelist (_shared._whitelist_mutate): "false" REMOVED the entry.
    _calls59.clear()
    _p9_patch(_sh59, "_security_whitelist_remove", _rec59(_calls59, "wl_remove", None))
    _p9_patch(_sh59, "_security_whitelist_add", _rec59(_calls59, "wl_add", None))
    _r59 = _A59.post("/api/panel/security/whitelist", json={"ip": "198.51.100.23", "remove": "false"})
    check("whitelist: a remove that is not a JSON boolean is a 400 and the entry stays (\"false\" dropped it, "
          "so a whitelisted admin could be blocked again)",
          _r59.status_code == 400 and _calls59 == [], repr((_r59.status_code, _calls59)))
    _A59.post("/api/remote/%d/security/whitelist" % P9_HOST, json={"ip": "198.51.100.23", "remove": False})
    check("whitelist: ...a real false is an add (control)", [c[0] for c in _calls59] == ["wl_add"],
          repr(_calls59))

    # Tailscale Serve's Funnel: `is True` published {"funnel": "true"} WITHOUT Funnel, as a success.
    _calls59.clear()
    _p9_patch(_tsr59, "_serve_enable", lambda port, mount, funnel, page: (
        _calls59.append(funnel) or _tsr59.jsonify({"success": True})))
    _r59 = _A59.post("/api/tailscale/serve", json={"action": "enable", "mount": "/", "funnel": "true"})
    check("tailscale serve: a funnel that is not a JSON boolean is a 400, not a publish without Funnel that "
          "reports success", _r59.status_code == 400 and _calls59 == [], repr((_r59.status_code, _calls59)))
    _A59.post("/api/tailscale/serve", json={"action": "enable", "mount": "/", "funnel": True})
    _A59.post("/api/tailscale/serve", json={"action": "enable", "mount": "/"})
    check("tailscale serve: ...a real true asks for Funnel and no key means no Funnel (control)",
          _calls59 == [True, False], repr(_calls59))

    # The bootstrap's 400 names the field the request sent, not the panel's own key.
    _p9_patch(_rb59, "_begin_bootstrap", lambda app, rid, opts, uid: (False, "busy"))
    _r59 = _A59.post("/api/remote/%d/bootstrap" % P9_HOST, json={"reboot": "no"})
    _m59 = _p9_json(_r59).get("message", "")
    check("bootstrap: the 400 for {\"reboot\": \"no\"} names `reboot`, the field sent, not `do_reboot`",
          _r59.status_code == 400 and "reboot" in _m59 and "do_reboot" not in _m59, repr((_r59.status_code, _m59)))

    # ── a Serve that could not be read is not "tailnet-only" ────────────────────────────────────
    _p9_patch(_ts59, "get_tailscale_info", lambda *a, **k: _NS59(serve_unreadable=True, serve_config={}))
    _facts59 = [_ts59.panel_funnel_facts({"tailscale_setup_done": True, "port": 5000, "tailscale_use_funnel": f})
                for f in (True, False)]
    check("funnel facts: when Serve cannot be read, `unread` says so and `funnelled` follows the panel's own "
          "record of choosing Funnel (it read as \"not on Funnel\")",
          [(f.get("funnelled"), f.get("unread")) for f in _facts59] == [(True, True), (False, True)],
          repr(_facts59))
    _ufw59 = []

    def _ufw_status59(remote):
        _ufw59.append(1)
        groups = [{"port_num": 5000, "nums": [3], "key": "k3", "action": "ALLOW"}] if len(_ufw59) % 2 else []
        return {"installed": True, "groups": groups}
    _p9_patch(_rv59, "remote_ufw_status", _ufw_status59)
    _p9_patch(_rv59, "remote_ufw_delete_rule", lambda *a, **k: (True, "deleted"))
    _closed59 = []
    for _uf59 in (False, True):
        _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, tailscale_setup_done=True,
                                 tailscale_use_funnel=_uf59))
        _closed59.append(_p9_json(_A59.post("/api/remote/%d/close-panel-port" % P9_LOCAL)))
    check("close panel port: with Serve unreadable it does not claim \"reachable only over your tailnet\" "
          "(Funnel may still publish the panel); it says Serve could not be read",
          _closed59[0].get("success") is True and "only over your tailnet" not in _closed59[0].get("message", "")
          and "could not be read" in _closed59[0].get("message", ""), repr(_closed59))
    check("close panel port: ...and with the panel's Funnel on record, it says Funnel still publishes it",
          "Funnel is on" in _closed59[1].get("message", ""), repr(_closed59))
    _p9_patch(_ts59, "get_tailscale_info", lambda *a, **k: _NS59(serve_unreadable=False, serve_config={}))
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), tailscale_use_funnel=False))
    _ok59 = _p9_json(_A59.post("/api/remote/%d/close-panel-port" % P9_LOCAL))
    check("close panel port: ...while a Serve read showing no Funnel is still tailnet-only (control)",
          "only over your tailnet" in _ok59.get("message", ""), repr(_ok59))

    # ── the panel host's security log: no answer is not an empty log ────────────────────────────
    _saved_verb59 = _so59._run_verb
    try:
        _so59._run_verb = lambda verb, args, **k: ("", "Command timed out", -1)
        _none59 = (_so59.security_log_tail("fail2ban"), _so59.security_log_tail("ssh"))
        _so59._run_verb = lambda verb, args, **k: ("", "", 0)
        _empty59 = (_so59.security_log_tail("fail2ban"), _so59.security_log_tail("ssh"))
    finally:
        _so59._run_verb = _saved_verb59
    check("security_log_tail: when no helper read answers, fail2ban and ssh are None, not \"\" (shown as "
          "\"(log is empty)\", i.e. no attacks)", _none59 == (None, None), repr(_none59))
    check("security_log_tail: ...while a read that answered with nothing is a real empty log (control)",
          _empty59 == ("", ""), repr(_empty59))
    _p9_patch(_p9_so, "security_log_tail", lambda which, lines, jail=None: None)
    _d59 = _p9_json(_A59.get("/api/panel/security/log?which=fail2ban"))
    check("panel security log: the route answers an error for an unanswered read, as the remote twin does",
          _d59.get("text") == "" and _d59.get("error"), repr(_d59))

    # ── the global retention numbers: unreadable is a 400, not a "saved" that kept the old value ──
    _set59 = []
    _p9_patch(_bk59, "set_settings", lambda **k: (_set59.append(k) or {}))
    _p9_patch(_bk59, "set_full_settings", lambda **k: (_set59.append(k) or {}))
    _bad59 = [_A59.post("/api/panel/backup/settings", json={_k: _v}).status_code
              for _k, _v in (("keep_days", "7d"), ("full_keep", [3]), ("full_interval_days", True),
                             ("keep_days", 1e400))]
    check("backup settings: a retention value that is not a whole number is a 400 and nothing is saved "
          "(it was skipped while the answer said success)", _bad59 == [400] * 4 and _set59 == [],
          repr((_bad59, _set59)))
    _ok59 = [_A59.post("/api/panel/backup/settings", json=_b).status_code
             for _b in ({"keep_days": 7, "full_keep": "3"}, {"keep_days": None, "full_interval_days": 0})]
    check("backup settings: ...a number, a numeric string and null (leave it) still save (control)",
          _ok59 == [200, 200] and len(_set59) == 4, repr((_ok59, _set59)))

    # ── a status read does not write onto a row deleted or replaced while it ran ────────────────
    def _status_of59():
        with _p9.app_context():
            return _db59.session.get(_GS59, P9_GS).status

    def _set_row59(status, installed):
        with _p9.app_context():
            _g = _db59.session.get(_GS59, P9_GS)
            _was = (_g.status, _g.installed)
            _g.status, _g.installed = status, installed
            _db59.session.commit()
            return _was

    _before59 = _set_row59("offline", True)
    try:
        _p9_patch(_api59, "get_server_status", lambda remote, gs: "online")
        _p9_patch(_api59, "still_held", lambda obj: False)
        _A59.get("/api/server/%d" % P9_GS)
        _kept59 = _status_of59()
        _p9_patch(_api59, "still_held", lambda obj: True)
        _A59.get("/api/server/%d" % P9_GS)
        _moved59 = _status_of59()
    finally:
        _set_row59(*_before59)
    check("server status: a status read whose row was deleted or replaced meanwhile writes nothing (it raised "
          "StaleDataError, or set the successor's status from the old server)",
          _kept59 == "offline", repr(_kept59))
    check("server status: ...while a row still held takes the new status (control)", _moved59 == "online",
          repr(_moved59))
    _gsn59 = _NS59(installed=True, status="offline")
    _p9_patch(_api59, "still_held", lambda obj: False)
    _st59 = _api59._persisted_stats_status(_gsn59, {"port_open": True}, True)
    check("server stats: the same for the polled stats read — a row no longer held is reported, not "
          "persisted", _st59 == ("online", False) and _gsn59.status == "offline", repr((_st59, _gsn59)))
finally:
    _p9_restore_all()
    if _CFG59_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG59_SNAPSHOT)
