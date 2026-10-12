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
import ast as _ast59
import json as _json59
import os
import re as _re59
import shutil as _shutil59
import sys as _sys59
import tempfile as _tf59
from types import SimpleNamespace as _NS59

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (_p9, P9_ADMIN, P9_GS, P9_HOST, P9_LOCAL, _P9_CFG_PATH, _P9_TRIPPED, _p9_cfg, _p9_client,
                         _p9_core, _p9_json, _p9_patch, _p9_restore_all, _p9_so, _p9_trip)
from unit.part47 import _cut47, _node47
from unit.part56 import _flows56
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


def _r14d_arm59():
    """part12's transport tripwire, as part53 and part56 arm it (review 1011d).

    part12 disarmed its own when it ended, and every check below stubs only the leaf it names: a
    route that reached one more host call ran it for real — paramiko to the fixture host, or a local
    shell on P9_LOCAL, as root on CI's root leg — and this part still passed.
    """
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part59's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_so, "_git", _p9_trip("system_ops._git"))


_TRIP59_START = len(_P9_TRIPPED)
_A59 = _p9_client(P9_ADMIN)
try:
    _r14d_arm59()
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
        return {"installed": True, "enabled": True, "groups": groups}
    _p9_patch(_rv59, "remote_ufw_status", _ufw_status59)
    _p9_patch(_rv59._fw_rules, "remote_ufw_default_allows_in", lambda remote: False)
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


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. templates and pages
# ════════════════════════════════════════════════════════════════════════════════════════════════
_A59 = _p9_client(P9_ADMIN)
try:
    _r14d_arm59()
    # ── /tailscale: another app's Serve mount is shown to superadmins only ──────────────────────
    _p9_patch(_ts59, "get_tailscale_info",
              lambda *a, **k: _ts59.TailscaleInfo(installed=True, running=True, funnel_enabled=True))
    _p9_patch(_ts59, "shared_funnel_apps", lambda *a, **k: ["/r13c-other-app"])
    _tsp59 = {}
    for _who59 in (False, True):
        _p9_patch(_tsr59, "_sees_panel_host_tailnet", lambda user, _w=_who59: _w)
        _r59 = _A59.get("/tailscale")
        _tsp59[_who59] = (_r59.status_code, "/r13c-other-app" in _r59.get_data(as_text=True))
    check("tailscale page: a viewer who is not a superadmin is not shown the host's other Serve mounts in "
          "the shared-Funnel note (the page reserves Serve mappings for superadmins)",
          _tsp59[False] == (200, False), repr(_tsp59))
    check("tailscale page: ...while a superadmin still reads which app shares the Funnel (control)",
          _tsp59[True] == (200, True), repr(_tsp59))
finally:
    _p9_restore_all()
check("part59: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP59_START, repr(_P9_TRIPPED[_TRIP59_START:][:6]))

_RM59 = _read59(_TPL59, "remote_manage.html")
_ctl59 = _RM59.index('data-mtab-btn="controls"')
check("host page: the Host Controls pill renders only when one of its cards can (a delegated host admin "
      "on the panel host without manage_servers opened it onto a blank page)",
      "{% if _host_ctl or has_permission('manage_servers') %}" in _RM59[_RM59.rfind("{%", 0, _ctl59) - 3:_ctl59],
      _RM59[max(0, _ctl59 - 300):_ctl59])
_unk59 = _RM59.find('data-funnel="unknown"')
_unr59 = _RM59.find("{% elif funnel_facts and funnel_facts.unread %}")
# The marker AFTER the branch it closes: one found earlier in the file made the slice empty, and
# "tailnet-only not in ''" passed (review 1011d).
check("host page: with Serve unread, the Panel Server card has its own branch — no \"tailnet-only\" "
      "button text, and the close button marked unknown",
      0 < _unr59 < _unk59
      and "tailnet-only" not in _re59.sub(r"\{#.*?#\}", "", _RM59[_unr59:_unk59], flags=_re59.S),
      "branch at %d, unknown marker at %d" % (_unr59, _unk59))
_ACC59 = _read59(_TPL59, "account.html")
_SDT59 = _read59(_TPL59, "server_detail.html")
_ccarg59 = _SDT59[_SDT59.index('class="form-control cc-arg"'):]
check("templates: user-authored text in a translated attribute is guarded — the display-name "
      "placeholder (a user named Admin read \"Administrador\") and a custom command's argument box",
      'placeholder="{{ current_user.username }}" data-no-i18n>' in _ACC59
      and "data-no-i18n" in _ccarg59[:_ccarg59.index(">")]
      and "t('value')" in _ccarg59[:_ccarg59.index(">")], _ccarg59[:200])
check("notifications page: the in-game alerts hint names the Files & Config page, not an \"Alerts tab\" "
      "no server page has", "Alerts tab" not in _read59(_TPL59, "notifications.html")
      and "Files &amp; Config page (Alerts &amp; Notifications)" in _read59(_TPL59, "notifications.html"))
_IS59 = _read59(_TPL59, "install_server.html")
check("install page: the game list's names are LinuxGSM's, kept from the translator as manage_commands "
      "keeps them, and the greyed-out note is no longer guarded (its words are the panel's)",
      '{% endif %} data-no-i18n>{{ g.name }}' in _IS59 and 'id="game-os-note"></div>' in _IS59,
      "option or note")

# ── scripts: names kept from the translator, words given to it ──────────────────────────────────
_unguarded59 = []
for _f59 in sorted(os.listdir(_JS59)):
    if _f59.endswith(".js"):
        _src59 = _read59(_JS59, _f59)
        _unguarded59 += ["%s: %s" % (_f59, _m.group(0)) for _m in _re59.finditer(
            r"<strong>'\s*\+\s*(?:_esc|escapeHtml)\(\s*(?:SERVER_NAME|name)\s*\)", _src59)]
check("scripts: no confirm names a server or host in a bare <strong> (one called \"Backup\" read \"Copia "
      "de seguridad\"; the players dialog beside it was already guarded)", not _unguarded59,
      repr(_unguarded59))
_PAL59 = _read59(_JS59, "palette.js")
check("palette: an action row's verb goes through t() (the label span is data-no-i18n for the name, so "
      "\"Restart MyServer\" stayed English)", "label: _tr(ACTION_LABEL[act]) + ' ' + s.name," in _PAL59
      and "label: ACTION_LABEL[act] + ' ' + s.name," not in _PAL59, "label line")
# The stop/restart confirm's shape (one translated question, the name guarded inside it, the warning
# whole) is held in part66, run in Spanish: built as verb, name and "?" nodes it lost Spanish's "¿".

_RMJ59, _NAG59, _MSJ59 = (_read59(_JS59, "remote_manage.js"), _read59(_JS59, "nags.js"),
                          _read59(_JS59, "manage_servers.js"))
_name59 = "host page: the OS updates card's counts"
_out59 = _node59(_name59, (
    "const el = {innerHTML: ''}; global.document = {getElementById: () => el};\n"
    "function escapeHtml(s){ return String(s); } function isSecurityPkg(p){ return !!p.sec; }\n"
    "function setInstallUpdatesState(){}\n"
    + _cut47(_RMJ59, "function renderUpdates(") + "\n"
    "renderUpdates({count: 12, packages: [{name: 'a', version: '1', sec: true}]});\n"
    "console.log(JSON.stringify(el.innerHTML));\n"))
if _out59 is not None:
    check("host page: OS updates puts each count apart from its words (\"12 updates available\" as one "
          "node matched no catalog key)", isinstance(_out59, str)
          and "12 <span>updates available</span>" in _out59 and "1 <span>security</span>" in _out59,
          repr(_out59)[:300])
check("scripts: the update banner, the ban counts, the jail counters, the cores label and the greyed-out "
      "note no longer splice a count into a phrase",
      "' update' + (n===1?'':'s')" not in _NAG59 and "<span>' + (n===1?'update':'updates') + '</span>'" in _NAG59
      and "' ban'+(bans===1?'':'s')" not in _RMJ59 and "' <span>total</span> · '" in _RMJ59
      and "+' cores';" not in _RMJ59 and "t('cores')" in _RMJ59
      and "hidden + ' game(s) are greyed out" not in _MSJ59, "a spliced count is back")
_cat59 = {"es": {}, "fr": {}}
for _L59 in ("es", "fr"):
    for _f59 in os.listdir(os.path.join(_root, "translations", _L59)):
        _cat59[_L59].update(_json59.loads(_read59(_root, "translations", _L59, _f59)))
_words59 = ["update", "updates", "update available", "updates available", "security", "ban", "bans",
            "banned", "total", "failed", "cores", "value"]
check("catalogs: every word the split counts and the argument box's fallback hand the walker is in es and fr",
      all(_w in _cat59[_L] for _w in _words59 for _L in ("es", "fr")),
      repr([(_L, _w) for _L in ("es", "fr") for _w in _words59 if _w not in _cat59[_L]]))

# ── the console: a panel push the rebuild's backlog lacks comes back ────────────────────────────
_SD59 = _read59(_JS59, "server_detail.js")
_CON59 = (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "var shown = [], _consoleLines = [], _consolePrimed = false, _consoleSig = null, _lastPanelT = 0;\n"
    "var _returnOwed = false, _panelBacklogShown = false, _r13c_panelPushes = [], _R13C_PANEL_KEEP = 200;\n"
    "var _r15c_clearedAt = null;\n"
    "var consoleEl = {set innerHTML(v){ shown.length = 0; }};\n"
    "var socket = {connected: true};\n"
    "function _rebuildMark(){ return 0; } function _rebuildRestore(){} function _r11c_resyncFrom(){}\n"
    "function _primeAt(){} function updateTsNotice(){} function _showTsOffNote(){} function stickConsole(){}\n"
    "function consoleAtBottom(){ return true; } function _notePanelMarker(){}\n"
    "function _appendConsoleRows(rows){ (rows || []).forEach(r => shown.push(r.line)); }\n"
    "function appendConsole(text){ shown.push(text); }\n"
    "function _panelShownAt(t){ if (Number(t) > _lastPanelT) _lastPanelT = Number(t); }\n"
    "function _renderPanelLines(rows){ rows.forEach(r => { shown.push(r.line); _panelShownAt(r.t); }); }\n"
    + "".join(_cut47(_SD59, h) + "\n" for h in (
        "function _loadOlderRows(", "function _r13c_notePanelPush(", "function _r13c_reshowPanelPushes(",
        "function loadMoreConsole(", "function refreshConsole(", "function showPanelBacklog(",
        "function _newerPanelRows(", "function _panelLinesWiped(", "function _r13c_primeWipesPushes("))
    + "global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve({lines: [{line: 'log1'}],\n"
    "  panel_lines: [{t: 100, line: '[panel] a'}], at: null})});\n"
    "function push(ts, data){ const d = {panel: true, ts: ts, data: data}; appendConsole(d.data);\n"
    "  _panelShownAt(d.ts); _r13c_notePanelPush(d); }\n")
_name59 = "console: a panel push after the backlog read survives Load older"
_out59 = _node59(_name59, _CON59 + (
    "(async () => { push(100, '[panel] a'); push(105, '[panel] b'); _consolePrimed = true;\n"
    "  loadMoreConsole(null); await settle(); const older = shown.slice();\n"
    "  shown.length = 0; _lastPanelT = 0; _consolePrimed = false; _r13c_panelPushes = [];\n"
    "  push(100, '[panel] a'); push(105, '[panel] b'); refreshConsole(true); await settle();\n"
    "  console.log(JSON.stringify({older: older, primed: shown.slice()})); })();\n"))
if _out59 is not None:
    check("console: Load older keeps a panel push sent after the server read its backlog (it was wiped by "
          "the rebuild and never came back)",
          _out59.get("older") == ["log1", "[panel] a", "[panel] b"], repr(_out59))
    check("console: ...and so does the first (priming) window", _out59.get("primed") == ["log1", "[panel] a",
                                                                                           "[panel] b"],
          repr(_out59))

# ── the dashboard filter takes a failed install's banner with its row ───────────────────────────
_DJ59 = _read59(_JS59, "dashboard.js")
_name59 = "dashboard: filter hides the failed banner"
_out59 = _node59(_name59, (
    "var _tagFilter = [];\n"
    "function row(id, text){ return {style: {}, textContent: text, querySelectorAll: () => [],\n"
    "  hasAttribute: () => false, getAttribute: () => id}; }\n"
    "const rows = [row('7', 'rust1'), row('8', 'ark1')], banner = {style: {}};\n"
    "const card = {style: {}, querySelectorAll: () => rows,\n"
    "  querySelector: s => s === '.install-failed[data-server-id=\"7\"]' ? banner : null};\n"
    "const search = {value: 'ark'};\n"
    "global.document = {getElementById: id => id === 'srv-search' ? search : null,\n"
    "  querySelectorAll: () => [card]};\n"
    + _cut47(_DJ59, "function rowHasEveryTag(") + "\n" + _cut47(_DJ59, "function filterServers(") + "\n"
    "filterServers(); const hidden = banner.style.display; search.value = 'rust'; filterServers();\n"
    "console.log(JSON.stringify({hidden: hidden, shown: banner.style.display}));\n"))
if _out59 is not None:
    check("dashboard: a search that hides a failed install's row hides its banner (Retry/Remove showed "
          "beside the one matching server)", _out59 == {"hidden": "none", "shown": ""}, repr(_out59))

# ── small page guards ───────────────────────────────────────────────────────────────────────────
_name59 = "panel.js: the after-add path"
_out59 = _node59(_name59, _cut47(_read59(_JS59, "panel.js"), "function _r11c_goPath(") + "\n"
                 "console.log(JSON.stringify(['/\\t/evil.example', '/\\n/x', '//x', '/remote/3/discover']"
                 ".map(_r11c_goPath)));\n")
if _out59 is not None:
    check("panel.js: a `go` path is tested as the URL parser reads it — \"/<tab>/evil.example\" passed and "
          "location.assign read it as //evil.example", _out59 == [None, None, None, "/remote/3/discover"],
          repr(_out59))
_name59 = "files: Alerts save"
_out59 = _node59(_name59, (
    "global.MOUNT = ''; global.serverId = 1; const posted = [], msgs = [];\n"
    "function alertsMsg(m){ msgs.push(m); }\n"
    "const key = {value: 'tok ', getAttribute: k => k === 'data-orig' ? 'tok' : 'discord_webhook'};\n"
    "global.document = {querySelectorAll: s => s.indexOf('data-alert-key') >= 0 && s.indexOf('toggle') < 0 ? [key] : []};\n"
    "global.fetch = (u, o) => { posted.push(o.body); return new Promise(() => {}); };\n"
    + _cut47(_read59(_JS59, "server_files.js"), "function saveAlerts(") + "\n"
    "saveAlerts(null); key.value = 'tok2'; saveAlerts(null);\n"
    "console.log(JSON.stringify({posted: posted, msgs: msgs}));\n"))
if _out59 is not None:
    check("files: an Alerts field changed only by a trailing space is not a change (it copied a secrets "
          "file's value into the plaintext instance cfg)",
          _out59.get("posted", [None])[:1] == ['{"values":{"discord_webhook":"tok2"}}']
          and len(_out59.get("posted")) == 1, repr(_out59))
_name59 = "host page: closing the panel port with Serve unread"
_out59 = _node59(_name59, (
    "let asked; global.confirmDialog = o => { asked = o.bodyText; };\n"
    "let funnel = 'unknown'; global.document = {getElementById: () => ({getAttribute: () => funnel,\n"
    "  hasAttribute: () => funnel !== null})};\n"
    + _cut47(_read59(_JS59, "remote_manage_host.js"), "function closePanelPort(") + "\n"
    "const out = []; for (const f of ['unknown', '1', null]) { funnel = f; closePanelPort(); out.push(asked); }\n"
    "console.log(JSON.stringify(out));\n"))
if _out59 is not None:
    check("host page: with Serve unread, Close public port asks without promising \"ONLY over your "
          "tailnet\", and says Funnel is unknown",
          isinstance(_out59, list) and "could not be read" in _out59[0] and "ONLY" not in _out59[0]
          and "Funnel is on" in _out59[1] and "ONLY over your tailnet" in _out59[2], repr(_out59))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. tools
# ════════════════════════════════════════════════════════════════════════════════════════════════

# ── the i18n gate reads a confirm body however it is written ────────────────────────────────────
# Loaded from its file, not by putting tools/ on sys.path: the runner fails any part that leaves
# sys.path changed for the parts after it.
import importlib.util as _ilu59  # noqa: E402
_i18n_spec59 = _ilu59.spec_from_file_location("i18n_scan_p59", os.path.join(_root, "tools", "i18n_scan.py"))
_i18n59 = _ilu59.module_from_spec(_i18n_spec59)
_i18n_spec59.loader.exec_module(_i18n59)
_tdir59 = os.path.realpath(_tf59.mkdtemp(prefix="lgsm-unit-p59-i18n-"))
try:
    with open(os.path.join(_tdir59, "a.js"), "w", encoding="utf-8") as _fh59:
        _fh59.write(
            "toast('Split over two literals for line length, '\n"
            "  + 'and judged whole.', 'info');\n"
            "confirmDialog({requireLabel: 'Type your code to confirm:', bodyText: 'Use the IP/DNS name.'});\n"
            "var body = on ? 'Close the thing?\\n\\nIt stays reachable from elsewhere.' : 'Plain other branch.';\n"
            "confirmDialog({bodyText: 'Firewall-block ' + ip + ' on every port of the host?'});\n"
            "confirmDialog({bodyText: 'Delete this widget?\\n\\n' + name});\n")
    _js59 = set(_i18n59.scan_js(_tdir59))
finally:
    _shutil59.rmtree(_tdir59, ignore_errors=True)
check("i18n scan: a sentence split over `'…' + '…'` literals is asked for whole (the six confirm bodies "
      "were never asked: each half was a fragment)",
      "Split over two literals for line length, and judged whole." in _js59, repr(sorted(_js59)))
check("i18n scan: a confirm's requireLabel / bodyText is asked for whatever its last character or a "
      "slash (\"…to confirm:\" and \"…IP/DNS name.\" were dropped)",
      {"Type your code to confirm:", "Use the IP/DNS name."} <= _js59, repr(sorted(_js59)))
check("i18n scan: a whole confirm body with a paragraph break is asked for, whitespace-collapsed as "
      "i18n.js looks it up", "Close the thing? It stays reachable from elsewhere." in _js59,
      repr(sorted(_js59)))
check("i18n scan: ...while a body with per-request text spliced in is not claimed, whole or in part "
      "(no catalog key could match it) (control)",
      not [_s for _s in _js59 if "Firewall-block" in _s or "Delete this widget" in _s
           or _s.startswith("on every port")], repr(sorted(_js59)))

# ── install.sh: a gamedig command left alone is not "could not be installed" ────────────────────
_ig_run59 = getattr(_sys59.modules.get("unit.part06"), "_ig_run", None)
if _ig_run59 is None:
    skip("install.sh: gamedig installed with a link left alone", "part06's install_gamedig driver is not loaded")
else:
    # part06's sandbox root is gone once part06 ends; this run gets its own.
    _p06_59 = _sys59.modules["unit.part06"]
    _sb_was59, _p06_59._su_sb = _p06_59._su_sb, _tf59.mkdtemp(prefix="lgsm-unit-p59-ig-")
    try:
        _o59, _p59, _l59 = _ig_run59(script_rc=2)
    finally:
        _shutil59.rmtree(_p06_59._su_sb, ignore_errors=True)
        _p06_59._su_sb = _sb_was59
    check("install.sh: gamedig installed with a foreign command left alone (exit 2) says it was installed, "
          "not \"could not be installed … uses the gamedig this host already had\"",
          "WARN gamedig was installed from its lockfile" in _o59 and "could not be installed" not in _o59
          and "RC=0" in _o59, repr(_o59[-300:]))

# ── perf_bench: its leftovers include auth.log, and a failed boot puts config.json back ──────────
_pbf59 = os.path.join(_root, "tools", "perf_bench.py")
_pbt59 = _ast59.parse(_read59(_pbf59))
_pbdefs59 = [_n for _n in _pbt59.body if isinstance(_n, _ast59.FunctionDef) and _n.name == "cleanup"]
_pbdir59 = _tf59.mkdtemp(prefix="lgsm-unit-p59-perf-")
try:
    import pathlib as _pl59
    _d59 = _pl59.Path(_pbdir59)
    (_d59 / "auth.log").write_text("x\n")
    _pbns59 = {"_CFG_BACKUP": None, "DATA_DIR": _d59, "DB_PATH": _d59 / "panel.db", "SECRET_FILE": _d59 / "s",
               "CRED_KEY_FILE": _d59 / "k", "CONFIG_FILE": _d59 / "config.json", "AUTH_LOG": _d59 / "auth.log",
               "_PREEXISTING": set(), "sys": _sys59, "print": print,
               # Its backups directory, which this run did not create (part63 holds that branch).
               "BACKUP_DIR": _d59 / "backups", "_BACKUPS_PREEXISTED": True, "shutil": _shutil59}
    # nosemgrep: python.lang.security.audit.exec-detected.exec-detected -- this repo's own tool's cleanup, on a temp dir
    exec(compile(_ast59.Module(body=_pbdefs59, type_ignores=[]), _pbf59, "exec"), _pbns59)  # nosec B102 - this repo's own tool  # pylint: disable=exec-used
    _pbns59["cleanup"]()
    _gone59 = not (_d59 / "auth.log").exists()
finally:
    _shutil59.rmtree(_pbdir59, ignore_errors=True)
check("perf_bench: cleanup removes the auth.log create_app opened (lhci_serve already did; a run left one)",
      len(_pbdefs59) == 1 and _gone59, repr(_gone59))
_pbtry59 = [_n for _n in _pbt59.body if isinstance(_n, _ast59.Try)
            and any(isinstance(_s, _ast59.Import) and any(_a.name == "app" for _a in _s.names) for _s in _n.body)]
check("perf_bench: the imports after the setup_complete flip restore config.json when they fail (it was "
      "left flipped: main's cleanup is not reached yet)",
      len(_pbtry59) == 1 and "_r13c_restore_config" in _ast59.dump(_pbtry59[0].handlers[0]), "no guarded import")

# ── js_coverage: the 375px flow's metrics reset cannot replace its own failed check ─────────────
# The flows module part56 loaded and kept — not sys.modules["flows"], which part56 deletes (and
# checks it did), so reading it there skipped this on every run, CI included (review 1011d).
# flows.CDPError is cdp's class (`from cdp import CDPError`), the one _rename_phone catches.
_flows59 = _flows56
_cdp59 = _NS59(CDPError=getattr(_flows59, "CDPError", None))
check("js coverage: (setup) part56's flows module, and the CDPError class it catches, are in hand",
      _flows59 is not None and isinstance(_cdp59.CDPError, type), repr(_flows59))
if _flows59 is not None and isinstance(_cdp59.CDPError, type):
    class _PhoneDrv59:
        """The fit answer is `fit`; clearing the metrics override raises a CDPError."""

        def __init__(self, fit):
            self.fit = fit
            self.cdp = _NS59(call=self._call)

        def _call(self, method, *a, **k):
            if method == "Emulation.clearDeviceMetricsOverride":
                raise _cdp59.CDPError("target closed")

        def goto(self, path):
            return None

        def run(self, js):
            return self.fit if js == _flows59.RENAME_FIT else {}

        def keys(self, text):
            return None

        def settle(self, **k):
            return None

    _ph59 = []
    for _fit59 in ({}, dict({_k: True for _k in _flows59._FITS}, vw=375)):
        try:
            _flows59._rename_phone(_PhoneDrv59(_fit59))
            _ph59.append("no exception")
        except Exception as _e59:  # noqa: BLE001 - which class arrives IS the check
            _ph59.append(type(_e59).__name__)
    check("js coverage: a failed 375px fit check reaches the run as a FlowAssertion even when resetting the "
          "device metrics then fails (the CDPError replaced it, and only warned)",
          _ph59[:1] == ["FlowAssertion"], repr(_ph59))
    check("js coverage: ...while that reset failing on a passing flow is still reported (control)",
          _ph59[1:] == ["CDPError"], repr(_ph59))

# ── the closed public port's tooltip on the Panel Server card ───────────────────────────────────
_name59 = "host page: the closed-port tooltip"
_out59 = _node59(_name59, _cut47(_read59(_JS59, "remote_manage_host.js"), "function _r13c_closedPortTitle(") + "\n"
                 "console.log(JSON.stringify(['unknown', '1', null].map(_r13c_closedPortTitle)));\n")
if _out59 is not None:
    check("host page: with Serve unread, the closed-port tooltip says Funnel is not known — not \"the panel "
          "is tailnet-only\" (control: Funnel on, and a read with no Funnel, keep their own)",
          isinstance(_out59, list) and "not known" in _out59[0] and "tailnet-only" not in _out59[0]
          and "Funnel is on" in _out59[1] and "tailnet-only" in _out59[2], repr(_out59))

# ── /users at 375px: the header's buttons wrap instead of widening the page ─────────────────────
_MU59 = _read59(_TPL59, "manage_users.html")
check("users page: the header row wraps (measured at 375px it pushed Add User to 417px, so the whole "
      "page laid out 423px wide and scrolled sideways)",
      '<div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">' in
      _MU59[:_MU59.index("User Management</h1>")], _MU59[:300])
