"""Part 180 of the unit suite: review pass 28's fixes (builder w).

Held here:
* Project Zomboid Mod IDs: only what breaks the ini's Mods= line is refused, so a real Mod ID with
  brackets, parentheses, quotes or plus signs is saved, found in mod.info and added on the card.
* The game config form: its cfg line and XML comment readers answer as the regexes they replaced on
  random lines and run in linear time; a file that did not decode as UTF-8 gets no form; a field that
  merely holds digits takes text (only a JSON number is a number).
* A port saved while a server ran moves only after a Start or Restart that ran and exited 0, never
  after a postponed or failed one; and it is reserved for that server against new installs.
* A server LinuxGSM's own stop took down (its monitoring lock gone) is not paged as offline.
* The palette's Start anyway, the Remove-plugin dialog's icon, the history charts' legends and the
  shared chart helpers declared in .eslintrc.json.

HOW IT RUNS. No host is reached: routes run on part12's app with its transport tripwire armed and
every host call stubbed; the background power action's thread is queued and drained; scripts run
in node through part47's and part173's runners.
"""
import json as _json180
import os as _os180
import random as _random180
import re as _re180
import sys as _sys180
import time as _time180
from types import SimpleNamespace as NS

from app import resolve_free_port as _rfp180
from unit.part01 import _root, check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _P9Thread, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row, _p9_set,
                         _p9_threading)
from unit.part47 import _cut47, _node47
from unit.part173 import _node173
from panel.core import panel_state as _ps180
from panel.routes import _shared as _sh180, server_detail as _sd180
from panel.routes import server_files as _sf180, workshop as _wk180
from panel.routes.manage_servers import sibling_port_blocks as _spb180
from panel.services import game_config_form as _g180, lgsm_players as _lgp180, monitoring as _mon180
from panel.services import notifications as _nt180


def _read180(*parts):
    with open(_os180.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _j180(r):
    return r.get_json(silent=True) or {}


# ── 1. Project Zomboid Mod IDs ──────────────────────────────────────────────────────────────────
_gun180 = "Arsenal(26)GunFighter[MAIN MOD 2.0]"
eq("workshop r41w: a real Mod ID with brackets, parentheses, a quote or a plus is valid; ; = a line break, a "
   "control or line-separator character, a backslash past the first, an edge blank or over 100 still are not",
   [_wk180.check_mod_ids(v)[0] is not None for v in (
       [_gun180], ["Bob's+Mod"], ["\\" + _gun180], ["x" * 100], ["a;b"], ["a=b"], ["a\nb"], ["a\x85b"],
       ["a\u2028b"], ["a\x07b"], ["a\\b"], [" a"], ["x" * 101])],
   [True] * 4 + [False] * 9)
eq("workshop r41w: a downloaded mod.info whose id has brackets is found",
   _wk180._wsc_mod_info("name=GunFighter\nid=%s\n" % _gun180), (_gun180, "GunFighter"))

_ini180 = "PVP=true\nWorkshopItems=2297098490\nMods=%s;tsarslib\nMaxPlayers=8\n" % _gun180
_pzfiles180 = {"Zomboid/Server/pzserver.ini": (_ini180, None)}
_pzwrites180 = []
_pz180 = _p9_new_server(P9_HOST, "p180pz", "pz", 16271, name="p180-pz", status="online")
_r180 = {}
try:
    _p9_arm(who="part180")
    _p9_patch_sm("read_file", lambda s, u, rel, max_bytes=0: _pzfiles180.get(rel, (None, "File not found")))
    _p9_patch_sm("write_file", lambda s, u, rel, content, selfname=None: _pzwrites180.append(content) or (True, ""))
    _p9_patch(_sf180, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf180, "_read_refused", lambda *a, **k: None)
    _A180 = _p9_client(P9_ADMIN)
    _r180["pz_read"] = _A180.get("/api/server/%d/workshop" % _pz180)
    _r180["pz_save"] = _A180.post("/api/server/%d/workshop" % _pz180,
                                  json={"items": ["2297098490", "1"], "mods": [_gun180, "tsarslib", "NewMod"]})
finally:
    _p9_restore_all()
    _p9_delete_server(_pz180)
check("workshop r41w: a Project Zomboid server already loading a Mod ID with brackets reads it and saves its "
      "list with it kept, byte for byte",
      _j180(_r180["pz_read"]).get("mods") == [_gun180, "tsarslib"] and _j180(_r180["pz_save"]).get("success") is True
      and _pzwrites180 == [_ini180.replace("WorkshopItems=2297098490", "WorkshopItems=2297098490;1")
                           .replace("Mods=%s;tsarslib" % _gun180, "Mods=%s;tsarslib;NewMod" % _gun180)],
      repr((_j180(_r180["pz_save"]), _pzwrites180)))
_pzjs180 = _node173("workshop card r41w: a Mod ID with brackets is added and posted",
                    {"success": True, "kind": "pz", "items": ["111"], "mods": [_gun180], "missing": False},
                    "  mk('wsc-mods-add').value = 'Bob\\x27s (B42)+[x]'; window.wscAdd('mods', ev);\n"
                    "  out.msg = els['wsc-msg'].textContent; window.wscSave(); await settle();\n")
if _pzjs180 is not None:
    check("workshop card r41w: the card adds a Mod ID with brackets, a quote and a plus, and posts it beside the "
          "one already in the ini",
          _pzjs180.get("posts") == [{"items": ["111"], "mods": [_gun180, "Bob's (B42)+[x]"]}],
          repr(_pzjs180))

# ── 2. the game config form ─────────────────────────────────────────────────────────────────────
# The regexes the readers replaced, kept here as the reference the string code must answer like.
_old_cfg180 = _re180.compile(r'[ \t]*(?:(?:set|seta|sets|setu|setb)[ \t]+)?([A-Za-z_][\w.\-+]*)[ \t]+'
                             r'(?:"([^"]*)"|([^"\s;][^";]*?))[ \t]*(?://.*)?\Z')
_old_xml180 = _re180.compile(r"<!--(.*?)-->", _re180.S)


def _old_cfg_line180(body):
    m = _old_cfg180.match(body)
    if not m:
        return None
    return (m.group(1), m.span(2), "q") if m.group(2) is not None else (m.group(1), m.span(3), "u")


_abc180 = ["set", "seta", "sets", "setu", "setb", "setx", " ", " ", "\t", '"', ";", "/", "//", "a", "Z", "_", ".",
           "-", "+", "1", "\n", "\r", "\x0b", "\xa0", "\u00e9", "\u0663", "\u212a", "\u0130", "k", "\u3000", "#", "="]
_xabc180 = ["<!--", "-->", "<!-", "--", "-", ">", "<", "!", "a", "\n", " ", "<!-->", "<property"]
_rng180 = _random180.Random(180)
_cfg_bad180 = [b for b in ("".join(_rng180.choice(_abc180) for _ in range(_rng180.randint(0, 14)))
                           for _ in range(40000)) if _old_cfg_line180(b) != _g180._gcf_cfg_line(b)]
_xml_bad180 = [t for t in ("".join(_rng180.choice(_xabc180) for _ in range(_rng180.randint(0, 14)))
                           for _ in range(15000))
               if [(m.start(), m.end(), _g180._gcf_collapse(m.group(1))) for m in _old_xml180.finditer(t)]
               != _g180._gcf_xml_comments(t)]
check("game config form r41w: the cfg line reader answers as the regex it replaced on 40000 random lines "
      "(set words, quotes, ; //, blanks, line breaks, Unicode letters and spaces)", not _cfg_bad180,
      repr(_cfg_bad180[:3]))
check("game config form r41w: the XML comment reader answers as <!--(.*?)--> on 15000 random texts",
      not _xml_bad180, repr(_xml_bad180[:3]))
# Measured on this machine: the replaced regexes took 0.8 s at 10000 blanks / `<!--`s and 3.3 s at
# 20000, growing with the square of the length (so ~13 s each at 40000); the string code takes
# milliseconds at a megabyte.
_cfgs180 = 'hostname "x"\nsv_password "y"\n'
_t0_180 = _time180.monotonic()
_slow_cfg180 = _g180.build("server.cfg", _cfgs180 + "a b" + " " * 40000 + 'x"\n')
_slow_xml180 = _g180.build("s.xml", '<property name="A" value="1"/>\n' + "<!--" * 40000)
_took180 = _time180.monotonic() - _t0_180
check("game config form r41w: a cfg line of 40000 blanks inside an unquoted value and an XML file of 40000 "
      "unclosed comments are read in linear time (well under 2 s for both)",
      _took180 < 2.0 and _slow_cfg180 is not None, "%.2fs" % _took180)

_latin180 = 'hostname "Caf\ufffd Gaming"\nsv_maxplayers 16\nsv_lan 0\n'
eq("game config form r41w: a file read with bytes that were not UTF-8 (U+FFFD) has no form and its save is "
   "refused; the same file in UTF-8 has one",
   (_g180.build("server.cfg", _latin180), _g180.apply("server.cfg", _latin180, _g180.content_hash(_latin180),
                                                      {"1": "8"})[2],
    _g180.build("server.cfg", _latin180.replace("\ufffd", "\u00e9")) is not None),
   (None, _g180.NO_FORM, True))
_json8_180 = '{"max_players": 8}'
_props180 = "level-seed=12345\nrcon.password=12345\nmax-players=20\nwhite-list=false\n"
_pf180 = {f["key"]: f for g in _g180.build("server.properties", _props180)["groups"] for f in g["fields"]}
_ps_new180 = _g180.apply("server.properties", _props180, _g180.content_hash(_props180), {
    _pf180["level-seed"]["id"]: "myworld", _pf180["rcon.password"]["id"]: "abc123"})
eq("game config form r41w: a field holding digits is text (a seed, a password); text saves into it; a JSON "
   "number is still a number",
   ([_pf180[k]["kind"] for k in ("level-seed", "rcon.password", "max-players")], _pf180["rcon.password"]["secret"],
    _ps_new180[0], _ps_new180[2],
    _g180.apply("s.json", _json8_180, _g180.content_hash(_json8_180), {"0": "lots"})[2] is not None),
   (["text", "text", "text"], True, _props180.replace("level-seed=12345", "level-seed=myworld")
    .replace("rcon.password=12345", "rcon.password=abc123"), None, True))
_gcf_sid180 = _p9_new_server(P9_HOST, "p180mc", "mc", 25575, name="p180-mc", status="online")
_gcf_files180 = {"serverfiles/server.properties": ("motd=Caf\ufffd\nmax-players=20\n", None)}
_gcf_writes180 = []
try:
    _p9_arm(who="part180")
    _p9_patch_sm("read_file", lambda s, u, rel, max_bytes=0: _gcf_files180.get(rel, (None, "File not found")))
    _p9_patch_sm("write_file", lambda *a, **k: _gcf_writes180.append(a) or (True, ""))
    _p9_patch(_sf180, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf180, "_read_refused", lambda *a, **k: None)
    _A180 = _p9_client(P9_ADMIN)
    _u180 = "/api/server/%d/game-config/form" % _gcf_sid180
    _r180["gcf_get"] = _A180.get(_u180 + "?path=serverfiles/server.properties")
    _r180["gcf_post"] = _A180.post(_u180, json={"path": "serverfiles/server.properties", "changes": {"1": "8"},
                                                "hash": _g180.content_hash("motd=Caf\ufffd\nmax-players=20\n")})
finally:
    _p9_restore_all()
    _p9_delete_server(_gcf_sid180)
check("game config form r41w: through the routes, a non-UTF-8 file is read with no form and a form save of it "
      "is a 400 that writes nothing",
      _j180(_r180["gcf_get"]).get("success") is True and _j180(_r180["gcf_get"]).get("form") is None
      and _r180["gcf_post"].status_code == 400 and _gcf_writes180 == [],
      repr((_j180(_r180["gcf_get"]), _r180["gcf_post"].status_code, _gcf_writes180)))

# ── 3. the pending port ─────────────────────────────────────────────────────────────────────────
_pp180 = _p9_new_server(P9_HOST, "p180pp", "csgo", 41850, name="p180-pp", status="online")
_pp_side180 = {"run": ("", "", 0), "ufw": []}
_POSTPONED180 = "[ INFO ] Restarting csgoserver: 2 players are on the server: restart postponed"


def _pp_restart180(client, run, status="online", action="restart"):
    """Press Restart (or Start) with a port pending; the worker drained. -> (port, pending_port)."""
    _p9_set(_pp180, port=41850, pending_port=41860, status=status)
    _pp_side180["run"] = run
    client.post("/api/server/%d/action" % _pp180, json={"action": action})
    _p9_drain()
    return _p9_row(_pp180).port, _p9_row(_pp180).pending_port


try:
    _p9_arm(who="part180")
    _n_trips180 = len(_P9_TRIPPED)
    _p9_patch(_sd180, "threading", _p9_threading(_P9Thread))
    _p9_patch_sm("run_as_game_user", lambda *a, **k: _pp_side180["run"])
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_lgp180, "allowance_seconds", lambda *a, **k: 0)
    _p9_patch_sm("_remote_listening_ports", lambda remote: set())
    _p9_patch_sm("protected_host_ports", lambda remote: {22})
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: True)
    _p9_patch_sm("remote_ufw_close_game_port", lambda remote, port, user: _pp_side180["ufw"].append(port) or (1, ""))
    _p9_patch(_sh180, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd180, "_live_run_state", lambda gs, remote: None)
    _A180 = _p9_client(P9_ADMIN)
    _r180["pp_postponed"] = _pp_restart180(_A180, (_POSTPONED180, "", 0))
    _r180["pp_failed"] = _pp_restart180(_A180, ("Restarting csgoserver: FAIL", "", 1))
    _r180["pp_clean"] = _pp_restart180(_A180, ("Restarting csgoserver: OK", "", 0))
    _r180["pp_start"] = _pp_restart180(_A180, ("Starting csgoserver: OK", "", 0), status="offline", action="start")
    _r180["pp_trips"] = _P9_TRIPPED[_n_trips180:]
finally:
    _p9_restore_all()
eq("pending port r41w: a Restart LinuxGSM postponed or one that failed keeps the stored port and the saved one "
   "waiting; a clean Restart, or a Start, moves to it",
   [_r180[k] for k in ("pp_postponed", "pp_failed", "pp_clean", "pp_start")],
   [(41850, 41860), (41850, 41860), (41860, None), (41860, None)])
check("pending port r41w: ...and nothing reached a host", _r180["pp_trips"] == [], repr(_r180["pp_trips"]))

_sib180 = NS(id=1, name="a", port=27015, pending_port=27030, game_type="csgo")
_new180 = NS(id=2, name="b", port=27040, pending_port=None, game_type="csgo")
eq("pending port r41w: a sibling's port saved while it ran is held by it (sibling_port_blocks), as its stored "
   "port is; its own pending port is no sibling's",
   (_spb180([_sib180, _new180], _new180), _spb180([_sib180], _sib180)), ({27015: "a", 27030: "a"}, {}))
_app180 = _sys180.modules["app"]   # loaded by the from-import above; its names are what resolve_free_port reads
_app_saved180 = {k: getattr(_app180, k) for k in ("_remote_listening_ports", "GameServer", "sm_game_engine")}


class _Rows180:
    def __init__(self, rows):
        self._rows = rows

    def filter_by(self, **kw):
        return self

    def all(self):
        return list(self._rows)


try:
    _app180._remote_listening_ports = lambda remote: set()
    _app180.GameServer = NS(query=_Rows180([NS(game_type="pz", port=16261, pending_port=16263,
                                                       short_name="pz1", lgsm_name="pzserver")]))
    _app180.sm_game_engine = lambda gt: "other"
    _r180["free"] = _rfp180(None, 1, 16263, "pz")
finally:
    for _k180, _v180 in _app_saved180.items():
        setattr(_app180, _k180, _v180)
check("pending port r41w: a new install is not handed the port a running sibling will move to at its next "
      "restart (resolve_free_port)", _r180["free"][0] not in (16263, None), repr(_r180["free"]))

# ── 4. a stop LinuxGSM made is not "went offline" ───────────────────────────────────────────────
_mgs180 = NS(id=918180, name="p180-mon", short_name="p180m", lgsm_name="csgoserver", game_type="csgo")
_mremote180 = NS(id=918, display_name="box", name="box")
_mon_said180 = []


def _mon_down180(lock_word):
    """Two confirmed-down sweeps with the lock probe answering `lock_word`. -> (recorded, pages, unannounced)."""
    del _mon_said180[:]
    _ps180._expected_offline.pop(_mgs180.id, None)
    _mon180._monitor_state["server_misses"].pop(_mgs180.id, None)
    _mon180._monitor_state["server_unannounced"].pop(_mgs180.id, None)

    def _run(remote, cmd, timeout=None, sudo=True):
        return ("IDLE" if "pgrep" in cmd else lock_word), "", 0

    _p9_patch(_mon180, "run_command", _run)
    _p9_patch(_nt180, "notify", lambda kind, *a, **k: _mon_said180.append(kind))
    try:
        prev = True
        for _ in range(_mon180._DOWN_CONFIRM_SWEEPS):
            prev = _mon180._server_transition(_mremote180, _mgs180, False, prev, False)
    finally:
        _p9_restore_all()
    return prev, list(_mon_said180), _mon180._monitor_state["server_unannounced"].pop(_mgs180.id, False)


eq("monitor r41w: a server down with LinuxGSM's monitoring lock gone (its own stop: a scheduled Stop with "
   "warnings, a cron line) is recorded down without a page; a lock still there, or one that could not be "
   "read, pages as before",
   [_mon_down180(w) for w in ("LGSM_LOCK_none", "LGSM_LOCK_held", "LGSM_LOCK_unread", "")],
   [(False, [], True), (False, ["server_down"], False), (False, ["server_down"], False),
    (False, ["server_down"], False)])

# ── 5. the scripts ──────────────────────────────────────────────────────────────────────────────
_PAL180 = _read180("panel", "static", "js", "palette.js")
_palprog180 = (
    "global.window = global; window.MOUNT = ''; const posts = [], toasts = [], dialogs = [];\n"
    "function _tr(s){ return s; } var ACTION_LABEL = {start: 'Start', restart: 'Restart', stop: 'Stop'};\n"
    "window.tf = (s, v) => s; window.toast = (m, c) => toasts.push([m, c]);\n"
    "window.confirmDialog = o => dialogs.push(o);\n"
    "global.fetch = (u, o) => { const b = JSON.parse(o.body); posts.push(b);\n"
    "  const d = b.force ? {success: true, message: 'started'} : {success: false, port_in_use: true,\n"
    "    message: 'Port 27015 is already in use on this host. Start anyway?'};\n"
    "  return Promise.resolve({json: () => Promise.resolve(d)}); };\n"
    "function _actionBody(){ return null; }\n"
    + _cut47(_PAL180, "function runAction(") + "\n"
    "const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };\n"
    "(async () => {\n"
    "  runAction('start', 7, 'srv'); await settle(); const d = dialogs[0] || {};\n"
    "  const first = {title: d.title, label: d.confirmLabel, body: d.bodyText, toasts: toasts.slice()};\n"
    "  if (d.onConfirm) d.onConfirm('x'); await settle();\n"
    "  console.log(JSON.stringify({first, posts, toasts, dialogs: dialogs.length})); })();\n")
_pal180 = _node47(_palprog180)
if _pal180 is not None:
    check("palette r41w: a Start refused for a busy port asks 'Start anyway' (no error toast) and the answer sends "
          "the start again with force",
          _pal180.get("first") == {"title": "Port in use", "label": "Start anyway",
                                   "body": "Port 27015 is already in use on this host. Start anyway?", "toasts": []}
          and _pal180.get("posts") == [{"action": "start"}, {"action": "start", "force": True}]
          and _pal180.get("toasts") == [["started", "success"]] and _pal180.get("dialogs") == 1, repr(_pal180))

_icons180 = [(f, m.group(1)) for f in sorted(_os180.listdir(_os180.path.join(_root, "panel", "static", "js")))
             if f.endswith(".js")
             for m in _re180.finditer(r"\bicon\s*:\s*'(bi-[^']*)'", _read180("panel", "static", "js", f))]
check("confirm dialogs r41w: no script passes an icon with the bi- prefix confirmDialog adds itself (the Remove "
      "plugin dialog drew no icon)", not _icons180, repr(_icons180))
_raw_ds180 = [(f, m.group(0)) for f in ("remote_history.js", "server_detail.js")
              for m in _re180.finditer(r"\b_ds\(\s*['\"][^'\"]*['\"]", _read180("panel", "static", "js", f))]
check("history charts r41w: every legend (CPU %, RAM %, Disk %, RAM MB, Players) goes through the translator: "
      "Chart.js paints it on the canvas, where the page's translation cannot reach", not _raw_ds180,
      repr(_raw_ds180))
_HC180 = _read180("panel", "static", "js", "history_charts.js")
_hc_names180 = set(_re180.findall(r"^(?:function\s+|var\s+)([A-Za-z_$][\w$]*)", _HC180, _re180.M))
_esl180 = _json180.loads(_read180("panel", "static", "js", ".eslintrc.json"))["globals"]
_hc_used180 = sorted(n for n in _hc_names180 for f in ("remote_history.js", "server_detail.js")
                     if _re180.search(r"(?<![\w$.])%s\b" % _re180.escape(n), _read180("panel", "static", "js", f)))
check("eslint r41w: every history_charts.js helper another script reads bare is declared in .eslintrc.json",
      _hc_used180 and all(n in _esl180 for n in _hc_used180),
      repr([n for n in _hc_used180 if n not in _esl180] or _hc_used180))
