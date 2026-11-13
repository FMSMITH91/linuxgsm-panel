"""Part 188 of the unit suite: review pass 29's fixes (builder r).

Held here:
* A port saved during a Start or Restart: the stored port moves to the port the start was issued on
  (saved before it), and the later save waits for the next start.
* A change that has reached the host (a Minecraft list line, a Workshop save, a plugin install or
  rename, a game config form save, the Project Zomboid admin password) whose audit row cannot be
  written answers what the host did, with audit_unwritten and the sentence saying so.
* The charts' legends: the server page's live chart draws translated ones, a History refresh repaints
  them in the language now chosen, and statsChart, read bare by history_charts.js, is declared.
* No field that takes a backup code or a port range asks a phone for its digits-only keypad, and every
  status word a server row can show (Installing, Configuring...) has a French and a Spanish entry.

HOW IT RUNS. No host is reached: routes run on part12's app with its transport tripwire armed and
every host call stubbed; the background power action's thread is queued and drained. Scripts run in
node through part47's runner.
"""
import json as _json188
import os as _os188
import re as _re188

from sqlalchemy.exc import OperationalError as _OpErr188

from unit.part01 import _root, check, eq, skip
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _P9Thread, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row,
                         _p9_set, _p9_threading)
from unit.part47 import _cut47, _node47
from panel.core import i18n as _i18n188
from panel.routes import _shared as _sh188, server_detail as _sd188, server_files as _sf188
from panel.routes import game_config_form as _gcfr188, mc_lists as _mcl188, modrinth_plugins as _mdr188
from panel.routes import pz_admin as _pza188, workshop as _wsc188
from panel.services import game_config_form as _gcf188, lgsm_players as _lgp188, modrinth as _mr188

_r188 = {}

# ── 1. a port saved during a Start or Restart ───────────────────────────────────────────────────
_pp188 = _p9_new_server(P9_HOST, "p188pp", "csgo", 43150, name="p188-pp", status="online")
_pp_during188 = []


def _pp_run188(*_a, **_k):
    """The stand-in power command: the Settings tab saves 43170 while it runs, then it exits 0."""
    for port in _pp_during188:
        _p9_set(_pp188, pending_port=port)
    return "Restarting csgoserver: OK", "", 0


def _pp_press188(client, pending, action="restart"):
    """Press `action` with `pending` saved before it; the worker drained. -> (port, pending_port)."""
    _p9_set(_pp188, port=43150, pending_port=pending, status="online" if action == "restart" else "offline")
    client.post("/api/server/%d/action" % _pp188, json={"action": action})
    _p9_drain()
    return _p9_row(_pp188).port, _p9_row(_pp188).pending_port


try:
    _p9_arm(who="part188")
    _n_trips188 = len(_P9_TRIPPED)
    _p9_patch(_sd188, "threading", _p9_threading(_P9Thread))
    _p9_patch_sm("run_as_game_user", _pp_run188)
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_lgp188, "allowance_seconds", lambda *a, **k: 0)
    _p9_patch_sm("_remote_listening_ports", lambda remote: set())
    _p9_patch_sm("protected_host_ports", lambda remote: {22})
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: True)
    _p9_patch_sm("remote_ufw_close_game_port", lambda *a, **k: (1, ""))
    _p9_patch(_sh188, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd188, "_live_run_state", lambda gs, remote: None)
    _A188 = _p9_client(P9_ADMIN)
    _pp_during188.append(43170)
    _r188["pp_restart"] = _pp_press188(_A188, 43160)
    _r188["pp_start"] = _pp_press188(_A188, 43160, action="start")
    _r188["pp_none_before"] = _pp_press188(_A188, None)
    _pp_during188[0] = 43160
    _r188["pp_back_to_bound"] = _pp_press188(_A188, 43160)
    _pp_during188.clear()
    _r188["pp_trips"] = _P9_TRIPPED[_n_trips188:]
finally:
    _p9_restore_all()
    _p9_delete_server(_pp188)
eq("pending port r42r: a port saved during a Restart or a Start leaves the stored port on the one the start "
   "was issued on (saved before it) and waits; with none saved before, the stored port stays; a save during "
   "the run of the same port settles it; nothing reaches a host",
   ([_r188[k] for k in ("pp_restart", "pp_start", "pp_none_before", "pp_back_to_bound")], _r188["pp_trips"]),
   ([(43160, 43170), (43160, 43170), (43150, 43170), (43160, None)], []))

# ── 2. a change the host has made, whose audit row cannot be written ────────────────────────────
_AUDIT188 = "The audit log entry for this could not be written. The panel's log has the details."
_props188 = "motd=p188\nmax-players=20\n"
_sv188 = {k: _p9_new_server(P9_HOST, "p188" + k, k, port, name="p188-" + k, status="online")
          for k, port in (("mc", 43250), ("pmc", 43260), ("arma3", 43270), ("pz", 43280))}
_send_rc188 = {"rc": 0}


def _locked188(*_a, **_k):
    raise _OpErr188("INSERT INTO audit_log", {}, Exception("database is locked"))


def _read188(_s, _u, rel, max_bytes=0):
    """The stand-in file read: the Project Zomboid ini, server.properties, and nothing else."""
    if rel.endswith(".ini"):
        return "WorkshopItems=\nMods=\n", None
    return (_props188, None) if rel.endswith("server.properties") else (None, "File not found")


def _posts188(client):
    """Every change route once, each to a server it serves. -> {name: (status, its JSON)}."""
    url = "/api/server/%d/"
    calls = {"mc_list": ("mc", "mc-lists/ops", {"action": "add", "value": "Steve"}),
             "workshop_mods": ("arma3", "workshop", {"ids": ["123456789"]}),
             "workshop_pz": ("pz", "workshop", {"items": ["123456789"], "mods": ["P188Mod"]}),
             "plugin_install": ("pmc", "plugins/install", {"project_id": "AABBCC12"}),
             "plugin_change": ("pmc", "plugins/change", {"action": "disable", "name": "Perm-1.0.jar"}),
             "game_config": ("mc", "game-config/form", {"path": "serverfiles/server.properties",
                                                        "changes": {"1": "8"},
                                                        "hash": _gcf188.content_hash(_props188)}),
             "pz_admin": ("pz", "pz-admin-password", {})}
    out = {}
    for name, (game, tail, body) in calls.items():
        r = client.post(url % _sv188[game] + tail, json=body)
        out[name] = (r.status_code, _p9_json(r))
    return out


try:
    _p9_arm(who="part188")
    _n_trips188 = len(_P9_TRIPPED)
    _p9_patch_sm("send_console_command", lambda *a, **k: ("", "", _send_rc188["rc"]))
    _p9_patch_sm("read_file", _read188)
    _p9_patch_sm("write_file", lambda *a, **k: (True, ""))
    _p9_patch_sm("lgsm_get_values", lambda *a, **k: {"workshopmods": ""})
    _p9_patch_sm("lgsm_write_config", lambda *a, **k: (True, ""))
    _p9_patch_sm("upload_file", lambda *a, **k: (True, "Uploaded"))
    _p9_patch_sm("rename_path", lambda *a, **k: (True, ""))
    _p9_patch_sm("lgc_pz_set_admin_password", lambda *a, **k: (True, ""))
    _p9_patch(_sf188, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf188, "_read_refused", lambda *a, **k: None)
    _plan188 = {"title": "Perm", "version_number": "1.0", "version_id": "VVVVVV01",
                "plan": {"filename": "Perm-1.0.jar"}}
    _p9_patch(_mr188, "resolve", lambda *a, **k: (_plan188, None))
    _p9_patch(_mr188, "download", lambda *a, **k: (b"jar", None))
    _A188 = _p9_client(P9_ADMIN)
    _r188["au_written"] = _posts188(_A188)
    for _mod188 in (_mcl188, _wsc188, _mdr188, _gcfr188, _pza188):
        _p9_patch(_mod188, "log_action", _locked188)
    _r188["au_locked"] = _posts188(_A188)
    _send_rc188["rc"] = 1
    _r188["au_locked_failed"] = _posts188(_A188)["mc_list"]
    _r188["au_trips"] = _P9_TRIPPED[_n_trips188:]
finally:
    _p9_restore_all()
    for _sid188 in _sv188.values():
        _p9_delete_server(_sid188)
check("audit after a change r42r: with the audit row written, every change route answers success with no "
      "audit_unwritten (control)",
      all(st == 200 and j.get("success") is True and "audit_unwritten" not in j
          for st, j in _r188["au_written"].values()), repr(_r188["au_written"]))
check("audit after a change r42r: a Minecraft list line, a Workshop save (cfg and Project Zomboid ini), a "
      "plugin install and rename, a game config form save and the Project Zomboid admin password whose "
      "audit row cannot be written still answer success, with audit_unwritten and the sentence",
      sorted(_r188["au_locked"]) == sorted(_r188["au_written"])
      and all(st == 200 and j.get("success") is True and j.get("audit_unwritten") is True
              and j.get("message", "").endswith(_AUDIT188) for st, j in _r188["au_locked"].values()),
      repr(_r188["au_locked"]))
check("audit after a change r42r: a console line the server refused, whose row cannot be written either, "
      "says both; nothing reached a host",
      _r188["au_locked_failed"][0] == 200 and _r188["au_locked_failed"][1].get("success") is False
      and _r188["au_locked_failed"][1].get("audit_unwritten") is True and _r188["au_trips"] == [],
      repr((_r188["au_locked_failed"], _r188["au_trips"])))


# ── 3. the charts' legends ──────────────────────────────────────────────────────────────────────
def _js188(name):
    with open(_os188.path.join(_root, "panel", "static", "js", name), encoding="utf-8") as fh:
        return fh.read()


_SD188, _HC188 = _js188("server_detail.js"), _js188("history_charts.js")
_leg188 = _node47(
    "global.window = global;\n"
    "global.document = {getElementById: () => ({getContext: () => ({})})};\n"
    "global.Chart = function(ctx, cfg){ this.data = cfg.data; this.options = cfg.options; this.update = () => {}; };\n"
    "global._cmpbInk = () => ({tick: '#000', grid: '#000', legend: '#000'});\n"
    "let lang = {'Game CPU %': 'CPU del juego %', 'Server CPU %': 'CPU del servidor %', 'CPU %': 'CPU (es)'};\n"
    "global.t = s => lang[s] || s;\n"
    "var statsChart = null, _histCharts = {}, _histTimes = {};\n"
    + _cut47(_SD188, "function initChart(") + "\n" + _cut47(_HC188, "function _histChart(") + "\n"
    "initChart();\n"
    "_histChart('h', [1], [{label: t('CPU %'), data: [1]}], {}, {});\n"
    "lang = {};\n"
    "_histChart('h', [1, 2], [{label: t('CPU %'), data: [1, 2]}], {}, {});\n"
    "console.log(JSON.stringify({live: statsChart.data.datasets.map(d => d.label),\n"
    "                            hist: _histCharts.h.data.datasets.map(d => [d.label, d.data])}));\n")
if _leg188 is None:
    skip("chart legends r42r: the live chart's legend is translated, and a History refresh repaints it",
         "node is not installed here")
else:
    eq("chart legends r42r: the live chart's legend is translated, and a History refresh after a switch to "
       "English repaints the legend in English with the new data",
       _leg188, {"live": ["CPU del juego %", "CPU del servidor %"], "hist": [["CPU %", [1, 2]]]})
_esl188 = _json188.loads(_js188(".eslintrc.json"))["globals"]
eq("eslint r42r: statsChart, read bare by history_charts.js and defined by server_detail.js, is declared",
   ("_r37d_inkChart(statsChart)" in _HC188, "var statsChart" in _SD188, _esl188.get("statsChart")),
   (True, True, "writable"))


# ── 4. the templates: keypads and status words ──────────────────────────────────────────────────
def _tpl188(name):
    with open(_os188.path.join(_root, "panel", "templates", name), encoding="utf-8") as fh:
        return fh.read()


_inputs188 = [(f, m.group(0)) for f in sorted(_os188.listdir(_os188.path.join(_root, "panel", "templates")))
              if f.endswith(".html") for m in _re188.finditer(r"<input\b[^>]*>", _tpl188(f))]
_mixed188 = [(f, tag) for f, tag in _inputs188 if _re188.search(r"backup code|range", tag, _re188.I)]
check("templates r42r: no input that takes a backup code (letters, digits, a dash) or a port range (a colon) "
      "sets inputmode=numeric, whose phone keypad cannot type them",
      len(_mixed188) >= 4 and not [t for _f, t in _mixed188 if 'inputmode="numeric"' in t],
      repr([(f, t[:120]) for f, t in _mixed188 if 'inputmode="numeric"' in t] or len(_mixed188)))
_panel_py188 = [_os188.path.join(d, f) for d, _s, fs in _os188.walk(_os188.path.join(_root, "panel"))
                for f in fs if f.endswith(".py")]
_states188 = set()
for _f188 in _panel_py188:
    with open(_f188, encoding="utf-8") as _fh188:
        _states188.update(_re188.findall(r'\.status\s*=\s*"([a-z]+)"', _fh188.read()))
_untr188 = sorted((lang, w.title()) for w in _states188 | {"unknown"} for lang in ("fr", "es")
                  if _i18n188.translate(lang, w.title()) == w.title())
check("i18n r42r: every status a server row is set to, as its row shows it (Installing, Configuring, "
      "Online, ...), has a French and a Spanish entry",
      {"installing", "configuring", "online"} <= _states188 and not _untr188, repr((sorted(_states188), _untr188)))
