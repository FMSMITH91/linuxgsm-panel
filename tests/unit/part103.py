"""Part 103 of the unit suite: the sixteenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* the console's send box: a command whose audit row could not be written (the database locked)
  says so, as the command form and a custom command do; it read only `error`, so the send looked
  audited. A custom command that FAILED with its row unwritten says so too (its toast carried only
  why the send failed).
* the SSH port card: on the panel host and on every remote it shows the ports sshd serves, read by
  ssh-status (`sshd_ports`), and "unknown" when they could not be read. The panel host's card
  printed its row's 22 (created with 22, never read from sshd), and a key host's went stale after a
  move. The script that fills the card runs here; no suite ran it before.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on part87's DOM, fed the routes' own answers.
"""
import json as _json103
import os
import re

from sqlalchemy.exc import OperationalError as _OpErr103

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part87 import _DOM87
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_sf)
from panel.db.models import CustomCommand as _CC103, db as _db103
from panel.ops import system_ops as _so103
from panel.ops import tailscale_integration as _ts103
from panel.ops.ssh_manager import _core as _smc103

_TRIP103_START = len(_P9_TRIPPED)


def _read103(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _js103(name, setup, src, cuts, body):
    """Run part87's DOM + `setup` + the cut statements of `src` + `body` in node; its JSON, or None.

    A statement that is missing becomes a comment naming it, so the check that runs it fails BY NAME.
    """
    prog = (_DOM87 + _SETTLE47 + setup
            + "".join((_cut47(src, h) if h in src else "/* MISSING %s */" % h) + "\n" for h in cuts)
            + "(async () => {\n" + body + "})();\n")
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An audit row that could not be written is said on every console sender
# ════════════════════════════════════════════════════════════════════════════════════════════════
_AUDIT103 = "The audit log entry for this could not be written. The panel's log has the details."


def _locked103(*a, **k):
    raise _OpErr103("INSERT INTO audit_log", {}, Exception("database is locked"))


_R103 = {}
_cid103 = None
try:
    with _p9.app_context():
        _cc103 = _CC103(name="p103say", command_template="say p103", scope_type="all", enabled=True)
        _db103.session.add(_cc103)
        _db103.session.commit()
        _cid103 = _cc103.id
    _p9_arm(who="part103")
    _p9_patch(_p9_sf, "send_console_command", lambda *a, **k: ("", "", 0))
    _p9_patch(_p9_sd, "send_console_command", lambda *a, **k: ("", "", 0))
    _c103 = _p9_client(P9_ADMIN)
    _R103["sent"] = _p9_json(_c103.post("/api/command/%d" % P9_GS, json={"command": "say p103"}))
    _p9_patch(_p9_sd, "log_action", _locked103)
    _R103["unwritten"] = _p9_json(_c103.post("/api/command/%d" % P9_GS, json={"command": "say p103"}))
    _R103["custom_ok"] = _p9_json(_c103.post("/api/server/%d/custom-command/%d" % (P9_GS, _cid103), json={}))
    _p9_patch(_p9_sd, "send_console_command", lambda *a, **k: ("", "tmux: no server running", 1))
    _p9_patch(_p9_sf, "send_console_command", lambda *a, **k: ("", "tmux: no server running", 1))
    _R103["custom_fail"] = _p9_json(_c103.post("/api/server/%d/custom-command/%d" % (P9_GS, _cid103),
                                               json={}))
    _R103["failed_unwritten"] = _p9_json(_c103.post("/api/command/%d" % P9_GS, json={"command": "say p103"}))
finally:
    _p9_restore_all()
    with _p9.app_context():
        _row103 = _db103.session.get(_CC103, _cid103) if _cid103 else None
        if _row103 is not None:
            _db103.session.delete(_row103)
            _db103.session.commit()

check("console send box: the route flags a send whose audit row could not be written, and only that "
      "one (the bodies fed below)",
      _R103.get("unwritten", {}).get("audit_unwritten") is True and _R103["unwritten"].get("success")
      and "audit_unwritten" not in _R103.get("sent", {})
      and _R103.get("failed_unwritten", {}).get("audit_unwritten") is True, repr(_R103))
check("custom command: a send that FAILED and whose audit row could not be written says both in its "
      "toast's message (it said only why the send failed); a success still says it (control)",
      _R103.get("custom_fail", {}).get("success") is False
      and _R103["custom_fail"].get("audit_unwritten") is True
      and _AUDIT103 in _R103["custom_fail"].get("message", "")
      and len(_R103["custom_fail"]["message"]) > len(_AUDIT103) + 1
      and _AUDIT103 in _R103.get("custom_ok", {}).get("message", ""), repr(_R103))

_SD103 = _read103("static", "js", "server_detail.js")
_name103 = "console send box: an unwritten audit row"
_out103 = _js103(_name103, (
    "var serverId = 1; let toasts = [];\n"
    "global.toast = (m, k) => toasts.push([m, k]);\n"
    "var consoleEl = document.getElementById('console');\n"
    "const inp = document.getElementById('command-input'); inp.focus = () => {};\n"), _SD103,
    ("function sendCommand(",), (
    "  const out = {};\n"
    "  for (const [k, d] of [['unwritten', " + _json103.dumps(_R103.get("unwritten", {})) + "],\n"
    "                        ['failed', " + _json103.dumps(_R103.get("failed_unwritten", {})) + "],\n"
    "                        ['sent', " + _json103.dumps(_R103.get("sent", {})) + "]]) {\n"
    "    toasts = []; consoleEl.children = []; inp.value = 'say p103';\n"
    "    global.fetch = () => Promise.resolve({json: () => Promise.resolve(d)});\n"
    "    sendCommand({preventDefault(){}}); await settle();\n"
    "    out[k] = {toasts, echo: consoleEl.children.map(c => c.textContent)}; }\n"
    "  console.log(JSON.stringify(out));\n"))
if _out103 is not None:
    check("console send box: a command whose audit row could not be written is said in a warning (the "
          "page read only `error`, so the send looked audited); a failed send says both",
          _out103.get("unwritten", {}).get("toasts") == [[_AUDIT103, "warning"]]
          and _out103["unwritten"].get("echo") == ["> say p103"]
          and _out103.get("failed", {}).get("toasts") == [[_AUDIT103, "warning"]]
          and len(_out103["failed"].get("echo", [""])[0]) > len("> say p103"), repr(_out103))
    check("console send box: ...and a send whose row was written raises no warning (control)",
          _out103.get("sent") == {"toasts": [], "echo": ["> say p103"]}, repr(_out103))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The SSH port card shows sshd's ports on every host, never the row's
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STATUS103 = {"has_sudo": True, "ufw": {"enabled": True, "rules": []},
              "tailscale_ssh": {"enabled": False, "running": True}, "tailscale_ssh_allowed": False,
              "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": False, "updates": {},
              "uptime": ""}


def _card103(page):
    """The SSH port card's "Currently:" line of a rendered host page."""
    i = page.find("(the port sshd listens on)")
    return page[i:page.find("</div>", i)] if i >= 0 else ""


_pages103 = {}
try:
    _p9_arm(who="part103")
    _p9_patch(_so103, "get_server_status", lambda *a, **k: _STATUS103)
    _p9_patch(_ts103, "panel_funnel_facts", lambda cfg: {})
    _p9_patch(_smc103, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_smc103, "run_command", lambda *a, **k: ("", "", 1))
    for _k103, _url103 in (("panel host", "/server-management"), ("key host", "/remote/%d/manage" % P9_HOST)):
        _r103 = _p9_client(P9_ADMIN).get(_url103)
        _pages103[_k103] = (_r103.status_code, _card103(_r103.get_data(as_text=True)))
finally:
    _p9_restore_all()
check("SSH port card: the panel host's card and a key host's are filled from sshd's ports (the "
      "panel host's printed its row's 22, created with 22 and never read from sshd; a key host's "
      "went stale after a move), not the row's port",
      all(st == 200 and 'Currently: <code id="ssh-port-now" data-live="1">' in card
          and "Currently: <code>" not in card for st, card in _pages103.values())
      and len(_pages103) == 2, repr(_pages103))

_RMH103 = _read103("static", "js", "remote_manage_host.js")
_m103 = re.search(r"^var SSH_LABELS=.*$", _RMH103, re.M)
_name103 = "SSH port card: the script that fills it"
_out103 = _js103(_name103, (
    "var REMOTE_ID = 1; let sent = [];\n"
    "E87.prototype.hasAttribute = function(k){ return k in this.attrs; };\n"
    "E87.prototype.removeAttribute = function(k){ delete this.attrs[k]; };\n"
    "document.querySelectorAll = () => [];\n"
    "global.confirmDialog = o => o.onConfirm();\n"
    "function _r13c_closedPortTitle(){ return ''; }\n"
    + (_m103.group(0) if _m103 else "/* MISSING var SSH_LABELS */") + "\n"
    "const reply = d => { global.fetch = u => { sent.push(u);\n"
    "  if (d === undefined) return Promise.reject(new Error('x'));\n"
    "  return Promise.resolve({json: () => Promise.resolve(d)}); }; };\n"), _RMH103,
    ("function sshModeLabel(", "function loadSshStatus(", "function _r26bSshPortNow(", "var _r32bSshPorts",
     "function _r32bPublicPorts(", "function changeSshPort("), (
    "  const out = {}, pn = document.getElementById('ssh-port-now'); document.getElementById('ssh-mode');\n"
    "  const run = async d => { pn.setAttribute('data-live', '1'); pn.textContent = '\u2026';\n"
    "    reply(d); loadSshStatus(); await settle();\n"
    "    return {text: pn.textContent, key: pn.getAttribute('data-i18n-text')}; };\n"
    "  out.ports = await run({mode: 'limit', active: true, sshd_ports: [2222, 22]});\n"
    "  out.empty = await run({mode: 'limit', active: true, sshd_ports: []});\n"
    "  out.absent = await run({mode: 'limit', active: true});\n"
    "  out.error = await run({error: 'x'});\n"
    "  out.rejected = await run(undefined);\n"
    "  out.back = await run({mode: 'limit', active: true, sshd_ports: [2022]});\n"
    "  pn.attrs = {}; pn.textContent = 'kept'; reply({sshd_ports: [9]}); loadSshStatus(); await settle();\n"
    "  out.notlive = pn.textContent;\n"
    "  pn.setAttribute('data-live', '1'); pn.textContent = '22';\n"
    "  document.getElementById('ssh-port-input').value = '2222';\n"
    "  document.getElementById('ssh-bind-input').value = '';\n"
    "  sent = []; global.fetch = u => { sent.push(u); return Promise.resolve({json: () => Promise.resolve(\n"
    "    u.endsWith('/ssh-port') ? {success: true, message: 'ok'} : {sshd_ports: [2222, 22]})}); };\n"
    "  changeSshPort(); await settle();\n"
    "  out.moved = {text: pn.textContent, sent};\n"
    "  console.log(JSON.stringify(out));\n"))
if _out103 is not None:
    _unk103 = {"text": "unknown", "key": "unknown"}
    check("SSH port card: ssh-status's sshd_ports are what the card shows (\"2222, 22\"), and a read "
          "that answered none, no field, an error or no answer at all shows \"unknown\" (re-rendered "
          "on a language switch), never a number",
          _out103.get("ports") == {"text": "2222, 22", "key": None}
          and all(_out103.get(k) == _unk103 for k in ("empty", "absent", "error", "rejected"))
          and _out103.get("back") == {"text": "2022", "key": None}, repr(_out103))
    check("SSH port card: ...a move that worked re-reads it, so the card names the new port without a "
          "reload; an element that is not the live card is left alone (control)",
          _out103.get("moved") == {"text": "2222, 22", "sent": ["/api/remote/1/ssh-port",
                                                                "/api/remote/1/ssh-status"]}
          and _out103.get("notlive") == "kept", repr(_out103))

check("part103: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP103_START, repr(_P9_TRIPPED[_TRIP103_START:][:6]))
