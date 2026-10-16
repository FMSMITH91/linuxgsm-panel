"""Part 87 of the unit suite: the twelfth review's page, script and i18n-tool fixes (builder C).

Held here, each against the code path the finding named:

* the OS-updates banner's audience: a host admin scoped to remotes (no panel host) gets it.
* the remote Firewall page: a changed host key named as such on first load, and its status card
  repainted by Refresh.
* the panel host's label in the viewer's language on the terminal's status line, in the OS-updates
  banner after a live switch, and in the command palette.
* a stored backup interval with no listed option re-rendered by a live language switch.
* the i18n gate's guarded-write pattern reads `x.title = window.t ? window.t('…') : '…'`.
* the remote page's reachability badge names a changed host key in its tooltip.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import html as _html87
import importlib.util as _ilu87
import os
import re as _re87
import shutil as _shutil87
import tempfile as _tf87
import time as _time87

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_restore_all)
from panel.core import panel_state as _ps87
from panel.db.models import (Group as _G87, RemoteServer as _RS87, User as _U87, db as _db87)
from panel.ops import terminal_session as _ts87
from panel.ops.ssh_manager._core import HostKeyMismatch as _HKM87
from panel.routes import remote_vps as _rv87
from panel.security import auth as _auth87

_TRIP87_START = len(_P9_TRIPPED)
_spec87 = _ilu87.spec_from_file_location("i18n_scan_p87", os.path.join(_root, "tools", "i18n_scan.py"))
_scan87 = _ilu87.module_from_spec(_spec87)
_spec87.loader.exec_module(_scan87)
_ES87, _FR87 = _scan87.load_catalog("es"), _scan87.load_catalog("fr")
_HOSTKEY87 = ("The panel refused to connect: this host's SSH key is not the one it trusts. If you "
              "reinstalled the host, use Re-trust host key on its page.")


def _read87(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node87(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or87(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _lang87(uid, lang):
    with _p9.app_context():
        _db87.session.get(_U87, uid).language = lang
        _db87.session.commit()


with _p9.app_context():
    _LANG87_WAS = _db87.session.get(_U87, P9_ADMIN).language

# A small DOM for the scripts here: elements by id (made on first use), with text, children,
# attributes and a classList that does nothing.
_DOM87 = (
    "class E87 { constructor(tag){ this.tagName = tag; this.children = []; this.attrs = {};\n"
    "    this.className = ''; this.style = {}; this._t = ''; this.classList = {toggle(){}}; }\n"
    "  appendChild(c){ this.children.push(c); return c; }\n"
    "  set textContent(v){ this.children = []; this._t = String(v); }\n"
    "  get textContent(){ return this._t + this.children.map(c => c.textContent).join(''); }\n"
    "  setAttribute(k, v){ this.attrs[k] = String(v); }\n"
    "  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; } }\n"
    "const els = {};\n"
    "global.window = global; global.MOUNT = '';\n"
    "global.document = { getElementById: id => els[id] || (els[id] = new E87('div')),\n"
    "  createElement: tag => new E87(tag), createTextNode: v => ({textContent: String(v)}) };\n"
    "global.t = s => s; global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g, '&amp;')\n"
    "  .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"
    "global.tf = (k, v) => k.replace(/\\{(\\w+)\\}/g, (m, n) => String(v[n]));\n"
    "global._da = () => ''; global.toast = () => {};\n"
    "const answer = d => { global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(d)}); };\n")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The OS-updates banner reaches a host admin scoped to remotes
# ════════════════════════════════════════════════════════════════════════════════════════════════
# It was gated on LOCAL_HOST_ID, which is set only when the viewer's grants include the panel host,
# and since #430 the summary never shows a delegate the panel host: a delegate scoped to remotes
# never saw it, one whose grant also covered the panel host did, for nothing extra.
_mine87 = {"users": [], "groups": []}
_pg87 = {}
_seen_was87 = dict(_ps87._os_update_seen)
try:
    with _p9.app_context():
        for _k87, _hosts87 in (("remote", (P9_HOST,)), ("local", (P9_LOCAL,))):
            _g87 = _G87(name="p87_%s" % _k87, description="", is_default=False)
            _g87.set_permissions([_auth87.MANAGE_REMOTES])
            _g87.servers.extend([_db87.session.get(_RS87, h) for h in _hosts87])
            _u87 = _U87(username="p87_%s" % _k87, password_hash=_auth87.hash_password("Str0ng!passw0rd-p87"),
                        display_name="p87 %s" % _k87, is_superadmin=False, is_active=True)
            _u87.groups.append(_g87)
            _db87.session.add_all([_g87, _u87])
            _db87.session.commit()
            _mine87["users"].append((_k87, _u87.id))
            _mine87["groups"].append(_g87.id)
        _born87 = {rid: _db87.session.get(_RS87, rid).created_at for rid in (P9_LOCAL, P9_HOST)}
    for _rid87 in (P9_LOCAL, P9_HOST):
        _ps87._os_update_seen[_rid87] = {"name": "p9-host", "count": 3, "security": 1, "packages": ["a"],
                                         "at": _time87.time(), "created": _born87[_rid87]}
    _p9_arm(who="part87")
    for _k87, _uid87 in _mine87["users"] + [("admin", P9_ADMIN)]:
        _c87 = _p9_client(_uid87)
        _page87 = _c87.get("/account").get_data(as_text=True)
        _nag87 = _re87.search(r"window\.OS_NAG = (\w+);", _page87)
        _loc87 = _re87.search(r"window\.LOCAL_HOST_ID = (\S+);", _page87)
        _sum87 = _p9_json(_c87.get("/api/os-updates/summary"))["hosts"]
        _pg87[_k87] = (_nag87.group(1) if _nag87 else None, _loc87.group(1) if _loc87 else None,
                       sorted((h["id"], h.get("local")) for h in _sum87))
finally:
    _p9_restore_all()
    _ps87._os_update_seen.clear()
    _ps87._os_update_seen.update(_seen_was87)
    with _p9.app_context():
        for _k87, _uid87 in _mine87["users"]:
            _db87.session.delete(_db87.session.get(_U87, _uid87))
        for _gid87 in _mine87["groups"]:
            _db87.session.delete(_db87.session.get(_G87, _gid87))
        _db87.session.commit()
check("OS updates banner: a host admin granted a remote only (no panel host, so LOCAL_HOST_ID is null) "
      "is its audience (OS_NAG true), and the summary has their remote to show",
      _pg87.get("remote") == ("true", "null", [(P9_HOST, False)]), repr(_pg87))
check("OS updates banner: ...one granted only the panel host is not (the summary never shows them "
      "it), and a superadmin is, with the panel host flagged local",
      _pg87.get("local") == ("false", "%d" % P9_LOCAL, [])
      and _pg87.get("admin") == ("true", "%d" % P9_LOCAL, sorted([(P9_LOCAL, True), (P9_HOST, False)])),
      repr(_pg87))

# ...and nags.js starts the banner on OS_NAG, whatever LOCAL_HOST_ID says.
_NAGS87 = _read87("static", "js", "nags.js")
_at87 = _NAGS87.find("window.pollWhenVisible(window.osUpdatesNagCheck")
_iife87 = (_NAGS87[_NAGS87.rfind("(function(){", 0, _at87):_NAGS87.index("})();", _at87) + 5]
           if _at87 >= 0 else "/* the OS-updates banner's start-up block was not found */")
_name87 = "OS updates banner: started for its audience"
_out87 = _node87(_name87, (
    "global.window = global; let asked = 0;\n"
    "window.osUpdatesNagCheck = () => { asked++; };\n"
    "const run = (nag, local) => { asked = 0; window.OS_NAG = nag; window.LOCAL_HOST_ID = local;\n"
    + _iife87 + "\n return asked; };\n"
    "console.log(JSON.stringify({delegate: run(true, null), panelOnly: run(false, 5), admin: run(true, 5)}));\n"))
if _out87 is not None:
    check("OS updates banner: nags.js asks for it for a delegate whose page has no LOCAL_HOST_ID, and "
          "not for one with only the panel host (it waited on LOCAL_HOST_ID)",
          _out87 == {"delegate": 1, "panelOnly": 0, "admin": 1}, repr(_out87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The banner's panel-host link follows a live language switch
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The server's translation went inside a data-no-i18n link, so an es -> fr switch kept "Servidor
# del panel" beside "mises à jour". The panel host's label is left to the translator now.
_name87 = "OS updates banner: the panel host's link is translatable, a remote's is guarded"
_out87 = _node87(_name87, _DOM87 + _SETTLE47 + (
    "global.sessionStorage = {getItem: () => null, setItem(){}};\n"
    + _cut_or87(_NAGS87, "function _osNagClear(") + "\n"
    + _cut_or87(_NAGS87, "window.osUpdatesNagCheck = function(){") + "\n"
    "(async () => {\n"
    "  answer({hosts: [{id: 1, name: 'Servidor del panel', local: true, count: 2, security: 0, url: '/sm'},\n"
    "                  {id: 2, name: 'Server', local: false, count: 1, security: 0, url: '/r/2'}]});\n"
    "  window.osUpdatesNagCheck(); await settle();\n"
    "  console.log(JSON.stringify({html: document.getElementById('os-updates-nag').innerHTML}));\n"
    "})();\n"))
if _out87 is not None:
    _links87 = _re87.findall(r"<a ([^>]*)>([^<]*)</a>", _out87.get("html") or "")
    check("OS updates banner: the panel host's link says \"Panel Server\" for the page's translator (no "
          "data-no-i18n: the server's translation behind the guard kept the old language after a "
          "switch); a remote's name stays guarded",
          [("data-no-i18n" in a, txt) for a, txt in _links87] == [(False, "Panel Server"), (True, "Server")],
          repr(_out87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The Firewall page names a changed host key on first load, and Refresh repaints its card
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _fw_page87(fn):
    _p9_patch(_rv87, "remote_ufw_status", fn)
    r = _p9_client(P9_ADMIN).get("/remote/%d/firewall" % P9_HOST)
    return r.status_code, _html87.unescape(r.get_data(as_text=True))


def _key87(*_a, **_k):
    raise _HKM87("unit p87: the SSH host key for h has CHANGED")


def _down87(*_a, **_k):
    raise ConnectionError("timed out")


_fwp87 = {}
try:
    _p9_arm(who="part87")
    _lang87(P9_ADMIN, "fr")
    _fwp87["key"] = _fw_page87(_key87)
    _fwp87["down"] = _fw_page87(_down87)
finally:
    _lang87(P9_ADMIN, _LANG87_WAS)
    _p9_restore_all()
_CANT87 = "The panel can't reach this host right now"
_UNREAD87 = "Rules can't be read while this host is unreachable."
_kpage87 = _fwp87.get("key", (0, ""))
check("firewall page: a host whose key changed is said as that on first load, in the viewer's language, "
      "in the status card and both rule lists (it blamed the network until Refresh)",
      _kpage87[0] == 200 and bool(_FR87.get(_HOSTKEY87))
      and _kpage87[1].count(_FR87.get(_HOSTKEY87) or "\0") == 3
      and _CANT87 not in _kpage87[1] and _UNREAD87 not in _kpage87[1],
      repr((_kpage87[0], _kpage87[1].count(_FR87.get(_HOSTKEY87) or "\0"), _CANT87 in _kpage87[1])))
_dpage87 = _fwp87.get("down", (0, ""))
check("firewall page: ...while a host that did not answer still says it cannot be reached",
      _dpage87[0] == 200 and _CANT87 in _dpage87[1] and _dpage87[1].count(_UNREAD87) == 2
      and (_FR87.get(_HOSTKEY87) or "\0") not in _dpage87[1], repr(_dpage87[0]))

# Refresh repaints the card from the same read as the badge and the lists.
_FWJS87 = _read87("static", "js", "remote_firewall.js")
_name87 = "firewall refresh: the UFW Status card follows the read"
_out87 = _node87(_name87, _DOM87 + _SETTLE47 + (
    "global.remoteId = 7; let unlisted = null;\n"
    "global._fwUnlisted = m => { unlisted = m; };\n"
    "global._fwRenderRules = () => {}; global._fwRenderBlocks = () => {};\n"
    + "".join(_cut_or87(_FWJS87, h) + "\n" for h in (
        "function refreshFirewall(", "function _fwUnreadWhy(", "function _fwHostSaid(", "function _fwStatusNote("))
    + "(async () => {\n"
    "  const card = document.getElementById('ufw-status-note'), out = {};\n"
    "  card.textContent = 'server-rendered';\n"
    "  const steps = [['key', {unreachable: true, code: 'host_key_mismatch', message: 'MSG-KEY'}],\n"
    "    ['down', {unreachable: true, code: 'host_unreachable', message: 'Host unreachable'}],\n"
    "    ['sudo', {unreachable: true, permission_denied: true}],\n"
    "    ['good', {installed: true, enabled: true, groups: []}],\n"
    "    ['none', {installed: false, enabled: false}],\n"
    "    ['off', {installed: true, enabled: false}]];\n"
    "  for (const [k, d] of steps) {\n"
    "    answer(d); unlisted = null; refreshFirewall(); await settle();\n"
    "    const p = card.children[0];\n"
    "    out[k] = [card.textContent.trim(), p ? p.className : null, unlisted];\n"
    "  }\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n"))
if _out87 is not None:
    _o87 = _out87
    check("firewall refresh: the status card names a changed host key (the route's sentence), a host "
          "that did not answer, and a sudo refusal — it kept the first load's text whatever Refresh read",
          (_o87.get("key") or [None])[0] == "MSG-KEY" and (_o87.get("key") or [None, None, None])[2] == "MSG-KEY"
          and (_o87.get("down") or [""])[0].startswith(_CANT87)
          and "sudo refused the firewall read" in (_o87.get("sudo") or [""])[0], repr(_o87))
    check("firewall refresh: ...a good read clears it, and not installed / inactive say so",
          _o87.get("good") == ["", None, None]
          and (_o87.get("none") or [""])[0] == "UFW is not installed on this remote."
          and (_o87.get("off") or [""])[0].startswith("UFW is installed but inactive"), repr(_o87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The terminal's status line names the panel host in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
# term_ready sent display_name, an i18n.Sentence, which serialized as "Panel Server": the page said
# "Conectado a Panel Server." under a heading reading "Servidor del panel".
_term87 = {}
_sio87 = None
try:
    _p9_arm(who="part87")
    _p9_patch(_ts87, "open_session", lambda *a, **k: None)
    _lang87(P9_ADMIN, "es")
    _sio87 = _p9.socketio.test_client(_p9, flask_test_client=_p9_client(P9_ADMIN))
    for _rid87 in (P9_LOCAL, P9_HOST):
        _sio87.get_received()
        _sio87.emit("term_open", {"remote_id": _rid87})
        _term87[_rid87] = [(m.get("name"), (m.get("args") or [{}])[0]) for m in _sio87.get_received()
                           if m.get("name") in ("term_ready", "term_error")]
finally:
    if _sio87 is not None:
        _sio87.disconnect()
    _lang87(P9_ADMIN, _LANG87_WAS)
    _p9_restore_all()
check("terminal: term_ready names the panel host \"Servidor del panel\" to an es viewer (it sent the "
      "English \"Panel Server\"); a remote's name is sent as typed",
      _term87.get(P9_LOCAL) == [("term_ready", {"host": _ES87["Panel Server"]})]
      and _term87.get(P9_HOST) == [("term_ready", {"host": "p9-host"})], repr(_term87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A stored backup interval with no listed option names its template for a live switch
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Files & Config and the Backups page's per-server row added "Cada 5 días" as a filled template,
# which a switch to English cannot map back to a key: it stayed Spanish until a reload.
_SF87 = _read87("static", "js", "server_files.js")
_name87 = "Files & Config: an interval with no listed option"
_out87 = _node87(_name87, _DOM87 + (
    "var _bkShown = {interval: null, keep: null}, _bkDefault = {};\n"
    "function sel(values){ const s = new E87('select'); s.options = values.map(v => ({value: v}));\n"
    "  s.appendChild = function(o){ this.options.push(o); this.children.push(o); return o; }; return s; }\n"
    "els['bk-interval'] = sel(['default', '0', '1', '3', '7', '14', '30']); els['bk-keep'] = sel(['default', '2']);\n"
    "els['bk-loading'] = null; els['bk-wrap'] = null; els['bk-now'] = null;\n"
    "global._bkRenderDisk = () => {}; global._bkRenderStatus = () => {}; global._bkRenderRows = () => {};\n"
    "global._bkPollWhileRunning = () => {};\n"
    + _cut_or87(_SF87, "function _bkShow(") + "\n" + _cut_or87(_SF87, "function renderBackups(") + "\n"
    "renderBackups({schedule: {interval_days: 5, keep: 2, interval_set: true, keep_set: false}});\n"
    "const o = els['bk-interval'].options.slice(-1)[0];\n"
    "const at = k => (o.getAttribute ? o.getAttribute(k) : null);\n"
    "console.log(JSON.stringify({value: o.value, text: o.textContent, key: at('data-i18n-text'),\n"
    "  vars: at('data-i18n-vars'), sel: els['bk-interval'].value}));\n"))
if _out87 is not None:
    check("Files & Config: a stored 5-day interval's added option names \"Every {n} days\" and {n: 5} for "
          "setLang (the filled label stayed in the old language after a switch)",
          _out87 == {"value": "5", "text": "Every 5 days", "key": "Every {n} days", "vars": '{"n":5}', "sel": "5"},
          repr(_out87))

_RMB87 = _read87("static", "js", "remote_manage_backups.js")
_name87 = "Backups page: a server row's interval with no listed option"
_out87 = _node87(_name87, _DOM87 + (
    "global.tfHtml = (k, v) => tf(k, v); global.schedNote = () => '';\n"
    + _cut_or87(_RMB87, "function gameSchedule(") + "\n"
    "console.log(JSON.stringify({html: gameSchedule({id: 4, schedule: {interval_days: 5, keep: 2,\n"
    "  interval_set: true, keep_set: false}})}));\n"))
if _out87 is not None:
    _opt87 = _re87.search(r'<option value="5"([^>]*)>([^<]*)</option>', _out87.get("html") or "")
    _attrs87 = dict(_re87.findall(r'(data-i18n-\w+)="([^"]*)"', _opt87.group(1))) if _opt87 else {}
    check("Backups page: a server row's 5-day interval option names \"Every {n} days\" and {n: 5} for "
          "setLang, selected, and the listed choices carry no such names",
          _opt87 is not None and "selected" in _opt87.group(1) and _opt87.group(2) == "Every 5 days"
          and {k: _html87.unescape(v) for k, v in _attrs87.items()}
          == {"data-i18n-text": "Every {n} days", "data-i18n-vars": '{"n":5}'}
          and (_out87.get("html") or "").count("data-i18n-text") == 1, repr(_out87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The i18n gate reads `x.title = window.t ? window.t('…') : '…'`
# ════════════════════════════════════════════════════════════════════════════════════════════════
# guarded_tcall_writes matched a right-hand side starting with t( or tf( only, so the codebase's own
# idiom for this write passed with its data-i18n-title marker removed.
_td87 = os.path.realpath(_tf87.mkdtemp(prefix="lgsm-unit-p87-"))
try:
    os.makedirs(os.path.join(_td87, "tpl"))
    os.makedirs(os.path.join(_td87, "js"))
    with open(os.path.join(_td87, "tpl", "a.html"), "w") as _fh87:
        _fh87.write('<span id="chip" data-no-i18n></span>\n')
    with open(os.path.join(_td87, "js", "a.js"), "w") as _fh87:
        _fh87.write(
            "function a(){ var el = document.getElementById('chip');\n"
            "  el.title = window.t ? window.t('Alerts are muted for this tag') : 'Alerts are muted for this tag'; }\n"
            "function b(){ var ch = document.getElementById('chip');\n"
            "  ch.title = window.t ? window.t('Alerts are muted for this tag') : 'Alerts are muted for this tag';\n"
            "  ch.setAttribute('data-i18n-title', 'Alerts are muted for this tag'); }\n"
            "function c(){ var tg = document.getElementById('chip');\n"
            "  tg.title = tag.name; var z = t('x'); }\n")
    _gw87 = _scan87.guarded_tcall_writes(js_dir=os.path.join(_td87, "js"), template_dir=os.path.join(_td87, "tpl"))
    # The real server_tags.js with its marker removed: the gate names that write. Written fresh, not
    # copied (a copy keeps a read-only checkout's mode); the guard is the script's own
    # setAttribute('data-no-i18n'), so no template is needed.
    _mut87 = os.path.join(_td87, "mut")
    os.makedirs(os.path.join(_mut87, "js"))
    os.makedirs(os.path.join(_mut87, "tpl"))
    _st87 = _read87("static", "js", "server_tags.js")
    _marker87 = "el.setAttribute('data-i18n-title', 'Alerts are muted for this tag');"
    with open(os.path.join(_mut87, "js", "server_tags.js"), "w", encoding="utf-8") as _fh87:
        _fh87.write(_st87.replace(_marker87, ""))
    _gwm87 = _scan87.guarded_tcall_writes(js_dir=os.path.join(_mut87, "js"),
                                          template_dir=os.path.join(_mut87, "tpl"))
finally:
    _shutil87.rmtree(_td87, ignore_errors=True)
check("i18n gate: a guarded field written `window.t ? window.t('…') : '…'` with no data-i18n-title is "
      "reported (the pattern read a bare t( / tf( start only); with the marker, or with no t() in the "
      "write, it is not",
      [(f, ln) for f, ln, _w in _gw87] == [("a.js", 2)], repr(_gw87))
check("i18n gate: ...and server_tags.js's muted-tag tooltip, its marker removed, is named (the tree "
      "as it is has none)",
      _marker87 in _st87 and [f for f, _ln, _w in _gwm87] == ["server_tags.js"]
      and _scan87.guarded_tcall_writes() == [], repr(_gwm87))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The command palette names the panel host by its label, in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
# /api/palette sent the panel host's row name (whatever was typed when it was added), and the meta
# line is guarded for a remote's name, so it read that, in English, beside "Servidor del panel".
_pal87 = None
_lgs87 = None
with _p9.app_context():
    _name_was87 = _db87.session.get(_RS87, P9_LOCAL).name
try:
    with _p9.app_context():
        _db87.session.get(_RS87, P9_LOCAL).name = "my box"
        _db87.session.commit()
    _lgs87 = _p9_new_server(P9_LOCAL, "p87local", "csgo", 27987)
    _p9_arm(who="part87")
    _pal87 = sorted((s["host"], s.get("host_local")) for s in _p9_json(_p9_client(P9_ADMIN).get("/api/palette"))
                    if s["name"] in ("p87local", "p9-cs"))
finally:
    _p9_restore_all()
    if _lgs87 is not None:
        _p9_delete_server(_lgs87)
    with _p9.app_context():
        _db87.session.get(_RS87, P9_LOCAL).name = _name_was87
        _db87.session.commit()
check("palette: a panel-host server's host is the label \"Panel Server\", flagged host_local (it was "
      "the typed row name \"my box\"); a remote's is its name",
      _pal87 == [("Panel Server", True), ("p9-host", False)], repr(_pal87))
_PALJS87 = _read87("static", "js", "palette.js")
_srv87 = _PALJS87[_PALJS87.find("(servers || []).forEach("):_PALJS87.find("out.sort(")]
check("palette: ...and the page shows it through its own catalog, t('Panel Server'), in the server and "
      "action rows (the meta line is guarded)",
      "var host = s.host_local ? t('Panel Server') : s.host;" in _srv87
      and _srv87.count("meta: [s.game, host]") == 2 and "s.host]" not in _srv87, _srv87[:200])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. The remote page's badge names a changed host key in its tooltip
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM87 = _read87("static", "js", "remote_manage.js")
_name87 = "remote page: the reachability badge's tooltip on a changed host key"
_out87 = _node87(_name87, _DOM87 + _SETTLE47 + (
    "global.REMOTE_ID = 7; global.IS_LOCAL = false;\n"
    + _cut_or87(_RM87, "function pollLive(") + "\n" + _cut_or87(_RM87, "function _r18cPaintHostBadge(") + "\n"
    "(async () => {\n"
    "  const out = {}, b = document.getElementById('remote-status');\n"
    "  for (const [k, d] of [['key', {error: 'x', unreachable: true, code: 'host_key_mismatch', message: 'MSG-KEY'}],\n"
    "      ['down', {error: 'x', unreachable: true, code: 'host_unreachable', message: 'Host unreachable'}]]) {\n"
    "    answer(d); pollLive(); await settle(); out[k] = [b.textContent, b.getAttribute('title')];\n"
    "  }\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n"))
if _out87 is not None:
    check("remote page: a changed host key paints the badge Unreachable with the route's reason as its "
          "tooltip (it said \"cannot reach this host over SSH\"); a host that did not answer keeps that",
          _out87 == {"key": ["Unreachable", "MSG-KEY"],
                     "down": ["Unreachable", "The panel cannot reach this host over SSH"]}, repr(_out87))

check("part87: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP87_START, repr(_P9_TRIPPED[_TRIP87_START:][:6]))
