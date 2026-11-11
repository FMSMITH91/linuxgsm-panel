r"""Part 175 of the unit suite: the port check before a panel Start, and a port saved on the Settings tab.

Held here (panel/services/port_check.py, game_ports.move_stored_port and the two routes):
* Which actions are checked: Start, and Restart of a server not online. Never Stop, never a running
  server's Restart, never a caller that does not ask (the chat bots, the bulk worker).
* The page's action endpoint refuses a Start when another server on the host that reads online is
  set to the same port (named), or when the host's listening ports show the game port (anything
  else); the reply carries port_in_use, and `force` (a JSON boolean) skips the check, audited as a
  forced start.
* Fail open: a listening-port read that is None, empty or raises starts the server; a port of 0 is
  not checked.
* The saved port: a Settings-tab save of `port` while the server is stopped moves the stored port
  at once with game_ports' side effects (cron check, own firewall rule, port_resync audit); while it
  runs (or when that is unknown) it waits in pending_port, which the next Start checks and moves to.
  A port the re-read's rules refuse (SSH's, another server's block) is neither stored nor pending,
  and the save still succeeds. SA-MP and the raw editor are not followed.
* The page scripts in node: a port refusal offers "Start anyway", which sends the action again with
  force; the Settings tab shows the save's port note.

HOW IT RUNS. No host is reached: the listening-port read, protected_host_ports, the cron rewrite, the
firewall close and the config write are replaced, the background power action is a recorder, and
part12's transport tripwire is armed.
"""
import os as _os175

from unit.part01 import _root, check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row,
                         _p9_set)
from unit.part75 import _run_js75
from panel.db.models import GameServer as _GS175, db as _db175
from panel.routes import _shared as _sh175, server_detail as _sd175, server_files as _sf175
from panel.services import port_check as _pc175

# ── 1. the helpers ──────────────────────────────────────────────────────────────────────────────


class _G175:
    """A stand-in row for the pure helpers."""

    def __init__(self, status="offline", port=27015, pending_port=None, game_type="csgo"):
        self.status, self.port, self.pending_port, self.game_type = status, port, pending_port, game_type


eq("port check: Start and a not-online Restart are checked; a running server's Restart and Stop are not",
   [_pc175.wants_check(_G175(s), a) for s, a in (("offline", "start"), ("online", "start"),
                                                ("offline", "restart"), ("starting", "restart"),
                                                ("online", "restart"), ("offline", "stop"), ("online", "stop"))],
   [True, True, True, True, False, False, False])
eq("port check: a start binds the pending port when one waits, else the stored one; 0, None, a bool or out of "
   "range is no port",
   [_pc175.start_port(_G175(port=p, pending_port=q)) for p, q in (
       (27015, None), (27015, 27016), (27015, 0), (0, None), (None, None), (True, None), (70000, None))],
   [27015, 27016, 27015, None, None, None, None])
eq("saved port: the Settings map's port as a number; blank, 0, past 65535, text, a JSON number, no key, a list, "
   "or SA-MP (its cfg port= is unused) follow nothing",
   [_pc175.saved_port(_G175(game_type=g), s) for g, s in (
       ("csgo", {"port": "27016"}), ("csgo", {"port": " 27017 "}), ("csgo", {"port": ""}),
       ("csgo", {"port": "0"}), ("csgo", {"port": "65536"}), ("csgo", {"port": "27o16"}),
       ("csgo", {"port": 27016}), ("csgo", {"maxplayers": "8"}), ("csgo", ["port"]),
       ("samp", {"port": "7777"}), ("csgo", {"port": "٢٧٠١٥"}))],
   [27016, 27017, None, None, None, None, None, None, None, None, None])

# ── 2. the routes ───────────────────────────────────────────────────────────────────────────────
_r175 = {}
_live175 = {"v": None, "calls": 0}
_bg175, _crons175, _ufw175 = [], [], []


def _listening175(remote):
    _live175["calls"] += 1
    v = _live175["v"]
    if isinstance(v, Exception):
        raise v
    return v


def _act175(client, sid, action, **extra):
    """POST the page's action endpoint; -> (status, json, background actions started, ss reads)."""
    n_bg, n_ss = len(_bg175), _live175["calls"]
    r = client.post("/api/server/%d/action" % sid, json=dict({"action": action}, **extra))
    return r.status_code, (r.get_json(silent=True) or {}), len(_bg175) - n_bg, _live175["calls"] - n_ss


def _save175(client, sid, body):
    r = client.post("/api/server/%d/config" % sid, json=body)
    return r.status_code, (r.get_json(silent=True) or {})


_t175 = _p9_new_server(P9_HOST, "p175t", "csgo", 41750, name="p175-target")
_o175 = _p9_new_server(P9_HOST, "p175o", "csgo", 41760, name="p175-other", status="online")
_q175 = _p9_new_server(P9_HOST, "p175q", "csgo", 41790, name="p175-query", query_port=41795)
try:
    _p9_arm(who="part175")
    _trips175 = len(_P9_TRIPPED)
    _p9_patch_sm("_remote_listening_ports", _listening175)
    _p9_patch_sm("protected_host_ports", lambda remote: {22})
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda remote, user, lgsm, **k: _crons175.append((user, k)) or True)
    _p9_patch_sm("remote_ufw_close_game_port", lambda remote, port, user: _ufw175.append((port, user)) or (1, ""))
    _p9_patch(_sh175, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd175, "_bg_power_action", lambda app, gs, remote, action, actor, **k: _bg175.append((gs.id, action)))
    _p9_patch(_sd175, "_live_run_state", lambda gs, remote: None)    # the no-op guard reads nothing
    _p9_patch(_sf175, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf175, "write_file", lambda *a, **k: (True, ""))
    _p9_patch(_sf175, "lgsm_write_config", lambda remote, user, selfname, settings: (True, ""))
    _A175 = _p9_client(P9_ADMIN)

    # 1. another panel server that reads online, set to the same port
    _p9_set(_o175, port=41750)
    _live175["v"] = {41750}
    _r175["claim"] = _act175(_A175, _t175, "start")
    _p9_set(_o175, port=41795, status="online")     # the query port of the target's neighbour
    _p9_set(_q175, port=41800)
    _p9_set(_t175, query_port=41795)
    _live175["v"] = set()
    _r175["claim_query"] = _act175(_A175, _t175, "start")
    _p9_set(_t175, query_port=None)
    _p9_set(_o175, port=41760, status="offline")    # same port, but stopped: not this rule
    _p9_set(_o175, port=41750)
    _r175["claim_stopped"] = _act175(_A175, _t175, "start")
    _p9_set(_o175, port=41760, status="online")
    # 2. something else listens on the game port
    _live175["v"] = {41750, 22}
    _r175["listener"] = _act175(_A175, _t175, "start")
    _r175["restart_offline"] = _act175(_A175, _t175, "restart")
    _n_forced175 = _p9_audit_count("force_start_server")
    # 3. start anyway
    _r175["force"] = _act175(_A175, _t175, "start", force=True)
    _r175["force_audit"] = (_p9_audit_count("force_start_server") - _n_forced175, _p9_audit("force_start_server"))
    _r175["force_text"] = _act175(_A175, _t175, "start", force="yes")
    # never checked: a running server's restart, stop
    _p9_set(_t175, status="online")
    _r175["restart_online"] = _act175(_A175, _t175, "restart")
    _p9_set(_t175, status="offline")
    _r175["stop"] = _act175(_A175, _t175, "stop")
    # free, and the fail-open reads
    _live175["v"] = {22, 41751}
    _r175["free"] = _act175(_A175, _t175, "start")
    _live175["v"] = None
    _r175["none"] = _act175(_A175, _t175, "start")
    _live175["v"] = set()
    _r175["empty"] = _act175(_A175, _t175, "start")
    _live175["v"] = ConnectionError("unit: the host did not answer")
    _r175["raises"] = _act175(_A175, _t175, "start")
    # a port of 0 cannot be stored (models refuse it), so the check is asked of a stand-in row
    _live175["v"] = {41750}
    _n_ss175 = _live175["calls"]
    _r175["no_port"] = (_pc175.start_refusal(_G175(port=0), None), _live175["calls"] - _n_ss175)
    # the callers that never ask
    with _p9.app_context():
        _gs175 = _db175.session.get(_GS175, _t175)
        _live175["v"] = {41750}
        _r175["no_gate"] = _sd175._pck_gate(_gs175, _gs175.remote, "start", None, None)

    # the saved port: stopped -> stored now
    _p9_patch(_sd175, "_live_run_state", lambda gs, remote: False)
    _live175["v"] = set()
    _n_resync175 = _p9_audit_count("port_resync")
    _r175["save_stopped"] = _save175(_A175, _t175, {"settings": {"port": "41770"}})
    _r175["save_stopped_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    _r175["save_stopped_audit"] = (_p9_audit_count("port_resync") - _n_resync175, _p9_audit("port_resync"))
    _r175["save_stopped_side"] = (list(_crons175), list(_ufw175))
    # running -> pending, stored port kept
    _p9_patch(_sd175, "_live_run_state", lambda gs, remote: True)
    _r175["save_running"] = _save175(_A175, _t175, {"settings": {"port": "41780", "maxplayers": "8"}})
    _r175["save_running_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    # the pending port is what the next start checks...
    _live175["v"] = {41780}
    _r175["pending_busy"] = _act175(_A175, _t175, "start")
    _r175["pending_busy_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    # ...and moves to when it goes ahead
    _live175["v"] = {22}
    del _crons175[:], _ufw175[:]
    _r175["pending_go"] = _act175(_A175, _t175, "start")
    _r175["pending_go_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    _r175["pending_go_audit"] = _p9_audit("port_resync")
    _r175["pending_go_side"] = (list(_crons175), list(_ufw175))
    # unknown run state -> pending; then saving the stored port back clears it
    _p9_patch(_sd175, "_live_run_state", lambda gs, remote: None)
    _r175["save_unknown"] = _save175(_A175, _t175, {"settings": {"port": "41785"}})
    _r175["save_unknown_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    _r175["save_back"] = _save175(_A175, _t175, {"settings": {"port": "41780"}})
    _r175["save_back_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    # refused by the re-read's rules: SSH's port, another server's block; not followed, the save stands
    _p9_patch(_sd175, "_live_run_state", lambda gs, remote: False)
    _r175["save_ssh"] = _save175(_A175, _t175, {"settings": {"port": "22"}})
    _r175["save_block"] = _save175(_A175, _t175, {"settings": {"port": "41760"}})
    _r175["save_raw"] = _save175(_A175, _t175, {"raw": "port=\"41799\"\n", "settings": {"port": "41799"}})
    _r175["save_refused_row"] = (_p9_row(_t175).port, _p9_row(_t175).pending_port)
    _p9_set(_q175, game_type="samp")
    _r175["save_samp"] = _save175(_A175, _q175, {"settings": {"port": "41810"}})
    _r175["save_samp_row"] = (_p9_row(_q175).port, _p9_row(_q175).pending_port)
    _r175["trips"] = _P9_TRIPPED[_trips175:]
finally:
    _p9_restore_all()
    for _sid175 in (_t175, _o175, _q175):
        _p9_delete_server(_sid175)

eq("port check routes: nothing they drove reached a real transport (part12's tripwire, armed)",
   _r175.get("trips"), [])
_c175 = _r175.get("claim") or (0, {}, 1, 1)
check("port check: a Start is refused when another server on the host that reads online is set to its port, "
      "naming it; nothing starts, and the host is not asked",
      _c175[0] == 200 and _c175[1].get("success") is False and _c175[1].get("port_in_use") is True
      and _c175[1].get("message") == "Port 41750 is in use by p175-other, which is running. Stop it first, "
      "or start anyway." and _c175[2:] == (0, 0), repr(_c175))
check("port check: ...and when that server's game port is this one's query port",
      (_r175.get("claim_query") or (0, {}))[1].get("message", "").startswith("Port 41795 is in use by p175-other")
      and _r175["claim_query"][2] == 0, repr(_r175.get("claim_query")))
check("port check: a server set to the same port that is stopped does not refuse (two may be configured on one "
      "port as long as only one runs)",
      (_r175.get("claim_stopped") or (0, {}))[1].get("success") is True and _r175["claim_stopped"][2] == 1,
      repr(_r175.get("claim_stopped")))
_l175 = _r175.get("listener") or (0, {}, 1, 0)
check("port check: a Start is refused when the host's listening ports show its game port, from ONE read",
      _l175[1].get("success") is False and _l175[1].get("port_in_use") is True
      and _l175[1].get("message") == "Port 41750 is already in use on this host (not by a server the panel knows). "
      "Start anyway?" and _l175[2:] == (0, 1), repr(_l175))
check("port check: a Restart of a server that is not online is checked the same way",
      (_r175.get("restart_offline") or (0, {}))[1].get("port_in_use") is True and _r175["restart_offline"][2] == 0,
      repr(_r175.get("restart_offline")))
_f175 = _r175.get("force") or (0, {}, 0, 1)
_fa175 = _r175.get("force_audit") or (0, None)
check("port check: Start anyway (force) starts without reading the host, and is audited as a forced start",
      _f175[1].get("success") is True and "port_in_use" not in _f175[1] and _f175[2:] == (1, 0)
      and _fa175[0] == 1 and _fa175[1].target == "p175-target"
      and _fa175[1].detail == "started with the port check skipped", repr((_f175, _fa175)))
eq("port check: a force that is not a JSON boolean is refused with a 400 and starts nothing",
   (_r175.get("force_text") or (0, {}, 1))[0::2], (400, 0))
check("port check: a running server's Restart and a Stop are never checked",
      [(r or (0, {}, 0, 1))[1].get("success") for r in (_r175.get("restart_online"), _r175.get("stop"))] == [True, True]
      and [(r or (0, {}, 0, 1))[2:] for r in (_r175.get("restart_online"), _r175.get("stop"))] == [(1, 0), (1, 0)],
      repr((_r175.get("restart_online"), _r175.get("stop"))))
eq("port check: a free port starts after one read",
   [(_r175.get("free") or (0, {}))[1].get("success")] + list((_r175.get("free") or (0, {}, 0, 0))[2:]), [True, 1, 1])
eq("port check fails open: a read that comes back None, empty or raises starts the server as before",
   [((_r175.get(k) or (0, {}))[1].get("success"), (_r175.get(k) or (0, {}, 0))[2]) for k in ("none", "empty", "raises")],
   [(True, 1)] * 3)
eq("port check: a server whose port is unknown (0) is not checked, and the host is not read",
   _r175.get("no_port"), (None, 0))
eq("port check: a caller that does not ask (the chat bots, the bulk worker) is not checked", _r175.get("no_gate"),
   None)

_ss175 = _r175.get("save_stopped") or (0, {})
_sa175 = _r175.get("save_stopped_audit") or (0, None)
check("saved port: saved while the server is stopped, the stored port moves now, and the reply says so",
      _ss175[1].get("success") is True and _r175.get("save_stopped_row") == (41770, None)
      and _ss175[1].get("port_note") == "The panel now watches port 41770 for this server.", repr((_ss175, _r175)))
check("saved port: the move is game_ports' own, audited as port_resync: the cron check repointed and this "
      "server's firewall rule on the old port closed",
      _sa175[0] == 1 and (_sa175[1].detail or "").startswith("41750 -> 41770 (saved on the Settings tab;")
      and _r175.get("save_stopped_side") == ([("p175t", {"game_type": "csgo", "port": 41770, "query_type": None})],
                                             [(41750, "p175t")]), repr((_sa175, _r175.get("save_stopped_side"))))
check("saved port: saved while it runs, the stored port stays and the new one waits; the reply says when it "
      "takes effect",
      _r175.get("save_running_row") == (41770, 41780) and (_r175.get("save_running") or (0, {}))[1].get(
          "port_note") == "Port 41780 takes effect at the next restart. Until then the panel keeps watching port "
      "41770, which the running server still uses.", repr((_r175.get("save_running"), _r175.get("save_running_row"))))
check("saved port: the next Start checks the PENDING port (refused while something listens on it), and moves "
      "nothing when refused",
      (_r175.get("pending_busy") or (0, {}))[1].get("message", "").startswith("Port 41780 is already in use")
      and _r175.get("pending_busy_row") == (41770, 41780), repr((_r175.get("pending_busy"), _r175)))
check("saved port: a Start that goes ahead moves the stored port to the pending one, with the re-read's side "
      "effects and a port_resync audit",
      (_r175.get("pending_go") or (0, {}, 0))[2] == 1 and _r175.get("pending_go_row") == (41780, None)
      and (_r175.get("pending_go_audit").detail or "").startswith(
          "41770 -> 41780 (saved on the Settings tab while it ran; moved at a panel start;")
      and _r175.get("pending_go_side") == ([("p175t", {"game_type": "csgo", "port": 41780, "query_type": None})],
                                           [(41770, "p175t")]),
      repr((_r175.get("pending_go"), _r175.get("pending_go_row"), _r175.get("pending_go_side"))))
eq("saved port: an unknown run state waits as pending, and saving the stored port back clears it",
   (_r175.get("save_unknown_row"), _r175.get("save_back_row"), (_r175.get("save_back") or (0, {}))[1].get("port_note")),
   ((41780, 41785), (41780, None), None))
eq("saved port: SSH's port, a port in another server's block, and the raw editor are not followed; each save "
   "still succeeds",
   ([((_r175.get(k) or (0, {}))[1].get("success"), "port_note" in (_r175.get(k) or (0, {}))[1])
     for k in ("save_ssh", "save_block", "save_raw")], _r175.get("save_refused_row")),
   ([(True, False)] * 3, (41780, None)))
eq("saved port: SA-MP (its cfg port= is never passed to the game) is not followed",
   _r175.get("save_samp_row"), (41800, None))

# ── 3. the page scripts, in node ────────────────────────────────────────────────────────────────


def _js175(name):
    with open(_os175.path.join(_root, "panel", "static", "js", name), encoding="utf-8") as fh:
        return fh.read()


_stub175 = (
    "global.window = global; global.t = s => s; global.tf = (s, v) => s; global.MOUNT = ''; global.serverId = 7;\n"
    "window.escapeHtml = s => s; const sent = [], dialogs = [], toasts = [];\n"
    "global.document = {getElementById: () => null};\n"
    "global.toast = (m, k) => toasts.push([m, k]); global.confirmDialog = o => dialogs.push(o);\n"
    "let answers = [{success: false, port_in_use: true, message: 'Port 1 busy'}, {success: true, message: 'ok'}];\n"
    "global.fetch = (u, o) => { sent.push([u, JSON.parse(o.body)]); const a = answers.shift();\n"
    "  return Promise.resolve({json: () => a}); };\n"
    "const btn = {innerHTML: 'Start', disabled: false};\n")
_out175 = _run_js75("server page: a port refusal offers Start anyway, which sends the action again with force", (
    _stub175 + _js175("server_actions.js") + "\n"
    "_doServerAction('start', btn);\n"
    "setTimeout(() => { const d = dialogs[0] || {}; const before = toasts.length; if (d.onConfirm) d.onConfirm();\n"
    "  setTimeout(() => console.log(JSON.stringify({sent, title: d.title, label: d.confirmLabel, body: d.bodyText,\n"
    "    before, toasts})), 20); }, 20);\n"))
if _out175 is not None:
    check("server page: a port refusal opens a Start anyway confirm with the reply's message, and no toast",
          _out175.get("title") == "Port in use" and _out175.get("label") == "Start anyway"
          and _out175.get("body") == "Port 1 busy" and _out175.get("before") == 0, repr(_out175))
    check("server page: Start anyway sends the same action again with force: true, and its outcome is toasted",
          _out175.get("sent") == [["/api/server/7/action", {"action": "start"}],
                                  ["/api/server/7/action", {"action": "start", "force": True}]]
          and _out175.get("toasts") == [["ok", "success"]], repr(_out175))
_dash175 = _js175("dashboard.js")
_cut175 = _dash175[_dash175.index("function _offerStartAnyway("):_dash175.index("// ── Bulk actions")]
_outd175 = _run_js75("dashboard: a port refusal offers Start anyway, which sends the action again with force", (
    _stub175 + "global.refreshStatus = () => 0;\n" + _cut175 + "\n"
    "_runAction(3, 'start', btn);\n"
    "setTimeout(() => { const d = dialogs[0] || {}; if (d.onConfirm) d.onConfirm();\n"
    "  setTimeout(() => console.log(JSON.stringify({sent, label: d.confirmLabel, toasts})), 20); }, 20);\n"))
if _outd175 is not None:
    check("dashboard: a port refusal offers Start anyway, which sends the action again with force: true",
          _outd175.get("label") == "Start anyway" and _outd175.get("sent") == [
              ["/api/server/3/action", {"action": "start"}], ["/api/server/3/action", {"action": "start", "force": True}]]
          and _outd175.get("toasts") == [["ok", "success"]], repr(_outd175))
_sfjs175 = _js175("server_files.js")
check("settings tab: a save's port note is shown after Saved",
      "if (d.success && d.port_note) msg.textContent += ' ' + d.port_note;" in _sfjs175)
