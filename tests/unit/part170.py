"""Part 170 of the unit suite: a Java Minecraft server's operators, whitelist and bans (panel/routes/mc_lists.py).

Held here:
* Which games have the card: mcserver and pmcserver, not Bedrock (mcbserver) or the proxies.
* Everything that reaches the console is built from checked values: Mojang player names, IPv4
  addresses only (ban-ip takes one single word, so IPv6 and ranges are refused), a one-line printable
  reason of at most 100 characters. Each refusal sends nothing.
* A list file that is not there is an empty list; a read that failed, or a file that is not a JSON
  list, is "could not be read", never empty.
* The routes: the read needs the file manager's permission and asks its root-account refusal; a
  change needs the console's send permission, goes through ssh_manager.send_console_command (the
  command box's sender) only while the server runs, and is audited against the server.
* The page: the card for those games and those permissions only, its form only for senders, and its
  script, run in node, refusing a bad value without posting and drawing names as text.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed;
the card's script in node through part75's runner. Nothing reaches a host or data/.
"""
import json as _json170
import os as _os170

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_FILES, P9_HOST, P9_VIEWER, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from panel.ops.ssh_manager import _core as _smc170
from panel.routes import mc_lists as _mcl170, server_detail as _sd170, server_files as _sf170
from panel.security import auth as _auth170

# ── 1. which games ──────────────────────────────────────────────────────────────────────────────
eq("mc lists: the Java servers (mcserver, pmcserver) have the card; Bedrock, the proxies and other games do not",
   [_mcl170.mcl_supported(g) for g in ("mc", "pmc", "MC", "mcb", "vpmc", "wmc", "csgo", "", None)],
   [True, True, True, False, False, False, False, False, False])

# ── 2. the console line, and every refusal ──────────────────────────────────────────────────────
eq("mc lists: each change is the vanilla console command for it",
   [_mcl170.mcl_command(*a)[0] for a in (
       ("ops", "add", "Steve"), ("ops", "remove", "Alex_99"), ("whitelist", "add", "abc"),
       ("whitelist", "remove", "A1234567890123_5"), ("whitelist", "on"), ("whitelist", "off"),
       ("bans", "add", "Griefer", "griefing the spawn"), ("bans", "add", "Griefer"), ("bans", "remove", "Griefer"),
       ("ipbans", "add", "203.0.113.7", "bot farm"), ("ipbans", "remove", "198.51.100.20"))],
   ["op Steve", "deop Alex_99", "whitelist add abc", "whitelist remove A1234567890123_5", "whitelist on",
    "whitelist off", "ban Griefer griefing the spawn", "ban Griefer", "pardon Griefer",
    "ban-ip 203.0.113.7 bot farm", "pardon-ip 198.51.100.20"])
eq("mc lists: a reason goes only on a ban, never after a pardon or an op",
   [_mcl170.mcl_command("bans", "remove", "Griefer", "x")[0], _mcl170.mcl_command("ops", "add", "Steve", "x")[0],
    _mcl170.mcl_command("ipbans", "remove", "203.0.113.7", "x")[0]],
   ["pardon Griefer", "op Steve", "pardon-ip 203.0.113.7"])
_BAD_NAMES170 = ["ab", "A" * 17, "Steve stop", "Steve\nstop", "Steve\rstop", "Steve;op x", "@a", "@p", "Ste-ve",
                 "St\u00e9ve", "Steve\u202e", "\uff33teve", "Steve\x00", "", "Steve\t", "Ste\u0663ve"]
_bad_name_out170 = {n: _mcl170.mcl_command("ops", "add", n) for n in _BAD_NAMES170}
check("mc lists: a name that is not 3-16 ASCII letters, digits or underscores is refused with the name rule "
      "(spaces, line breaks, selectors, other alphabets and digits, control and direction characters)",
      all(v == (None, _mcl170._MCL_BAD_NAME) for v in _bad_name_out170.values()), repr(_bad_name_out170))
_BAD_IPS170 = ["10.0.0.0/8", "010.1.1.1", "1.2.3.256", "1.2.3", "1.2.3.4 stop", "1.2.3.4\nstop", "Steve",
               "", "0x7f.0.0.1", "1.2.3.4/32"]
_bad_ip_out170 = {i: _mcl170.mcl_command("ipbans", "add", i) for i in _BAD_IPS170}
check("mc lists: ban-ip takes an IPv4 address only: a range, a leading zero, a name or a trailing word is refused",
      all(v == (None, _mcl170._MCL_BAD_IP) for v in _bad_ip_out170.values()), repr(_bad_ip_out170))
eq("mc lists: an IPv6 address is refused with its own reason (Java's ban-ip cannot take one)",
   [_mcl170.mcl_command("ipbans", w, a) for w, a in (("add", "2001:db8::5"), ("remove", "::1"),
                                                       ("add", "::ffff:203.0.113.7"))],
   [(None, _mcl170._MCL_IPV6)] * 3)
_BAD_REASONS170 = ["line\nbreak", "car\rriage", "esc\x1b[2J", "nul\x00", "tab\there", "bidi\u202eevil",
                   "x" * 101, "del\x7f", "sep\u2028"]
_bad_reason_out170 = {r: _mcl170.mcl_command("bans", "add", "Griefer", r) for r in _BAD_REASONS170}
check("mc lists: a reason with a line break or any control, format or separator character, or over 100 "
      "characters, is refused",
      all(v == (None, _mcl170._MCL_BAD_REASON) for v in _bad_reason_out170.values()), repr(_bad_reason_out170))
eq("mc lists: a reason of exactly 100 printable characters is kept (control)",
   _mcl170.mcl_command("ipbans", "add", "203.0.113.7", "r" * 100), ("ban-ip 203.0.113.7 " + "r" * 100, None))
eq("mc lists: an unknown list or action, and on/off for a list that is not the whitelist, are refused",
   [_mcl170.mcl_command(*a) for a in (("ops", "on"), ("bans", "off"), ("ops", "delete", "Steve"),
                                     ("nope", "add", "Steve"), ("ops", "", "Steve"))],
   [(None, _mcl170._MCL_BAD_ACTION)] * 5)

# ── 3. reading a list file ──────────────────────────────────────────────────────────────────────
_ops_text170 = _json170.dumps([{"uuid": "u-1", "name": "Steve", "level": 4, "bypassesPlayerLimit": False},
                               "not an object", {"name": ["x"], "uuid": "u-2", "level": True}])
eq("mc lists: a list file's entries become rows; a non-object entry is dropped; a non-text field is blank",
   _mcl170.mcl_parse(_ops_text170),
   ([{"name": "Steve", "ip": "", "uuid": "u-1", "level": "4", "reason": "", "source": "", "created": "",
      "expires": ""},
     {"name": "", "ip": "", "uuid": "u-2", "level": "", "reason": "", "source": "", "created": "", "expires": ""}],
    False))
eq("mc lists: an empty file is an empty list; text that is not JSON, or JSON that is not a list, is unreadable",
   [_mcl170.mcl_parse(t) for t in ("", "  \n", "[]", "not json", "{}", '"x"', "[")],
   [([], False), ([], False), ([], False), None, None, None, None])
_many170 = _mcl170.mcl_parse(_json170.dumps([{"name": "p%d" % i} for i in range(1005)]))
check("mc lists: a list over 1000 entries is cut to 1000 and says so; a long field is capped",
      len(_many170[0]) == 1000 and _many170[1] is True
      and len(_mcl170.mcl_parse(_json170.dumps([{"reason": "r" * 500}]))[0][0]["reason"]) == 120,
      repr((len(_many170[0]), _many170[1])))
eq("mc lists: server.properties' white-list reads as on, off, or unknown (missing or commented out)",
   [_mcl170.mcl_whitelist_on(p) for p in ("motd=x\nwhite-list=true\n", "white-list = FALSE", "#white-list=true",
                                          "enforce-whitelist=true", "", None)],
   [True, False, None, None, None, None])

# ── 4. the routes ───────────────────────────────────────────────────────────────────────────────
with _p9.app_context():
    from panel.db.models import Group as _G170, RemoteServer as _RS170, User as _U170, db as _db170
    _sg170 = _G170(name="p170_send", description="", is_default=False)
    _sg170.set_permissions([_auth170.SEND_COMMAND])
    _sg170.servers.append(_db170.session.get(_RS170, P9_HOST))
    _db170.session.add(_sg170)
    _db170.session.flush()
    _su170 = _U170(username="p170_send", password_hash="x", display_name="Sender", is_superadmin=False,
                   is_active=True)
    _su170.groups.append(_sg170)
    _db170.session.add(_su170)
    _db170.session.commit()
    P170_SEND, _P170_GROUP = _su170.id, _sg170.id

_mc170 = _p9_new_server(P9_HOST, "mcserver", "mc", 25565, name="p170-mc", status="online")
_cs170 = _p9_new_server(P9_HOST, "p170cs", "css", 27115, name="p170-css", status="online")
_files170 = {}
_reads170, _sent170, _send_rc170 = [], [], {"rc": 0, "raise": None}
_read_refusal170 = {"on": False}


def _read170(server, user, relpath, max_bytes=1048576):
    _reads170.append((user, relpath))
    return _files170.get(relpath, (None, "File not found"))


def _send170(server, user, command, timeout=20, selfname=None, mark=False):
    if _send_rc170["raise"] is not None:
        raise _send_rc170["raise"]
    _sent170.append((user, command, selfname))
    return ("", "no tmux session" if _send_rc170["rc"] else "", _send_rc170["rc"])


def _refuse170(gs, action, detail=""):
    if not _read_refusal170["on"]:
        return None
    _refused170.append((action, detail))
    from flask import jsonify
    return jsonify({"success": False, "error": "refused", "message": "refused"}), 409


_refused170 = []
_g170, _p170 = {}, {}
_url170 = "/api/server/%d/mc-lists/" % _mc170
try:
    _p9_arm(who="part170")
    _p9_patch_sm("read_file", _read170)
    _p9_patch_sm("send_console_command", _send170)
    _p9_patch(_sf170, "_read_refused", _refuse170)
    _A170, _F170 = _p9_client(P9_ADMIN), _p9_client(P9_FILES)
    _V170, _S170 = _p9_client(P9_VIEWER), _p9_client(P170_SEND)

    _files170["serverfiles/ops.json"] = (_ops_text170, None)
    _files170["serverfiles/whitelist.json"] = ('[{"uuid": "u-3", "name": "Alex"}]', None)
    _files170["serverfiles/server.properties"] = ("white-list=true\n", None)
    _files170["serverfiles/banned-ips.json"] = (None, "Could not read that file — the host did not answer.")
    _files170["serverfiles/banned-players.json"] = ("{broken", None)
    _g170["ops"] = _A170.get(_url170 + "ops")
    _g170["whitelist"] = _A170.get(_url170 + "whitelist")
    _g170["ipbans"] = _A170.get(_url170 + "ipbans")
    _g170["bans"] = _A170.get(_url170 + "bans")
    del _files170["serverfiles/banned-players.json"]
    _g170["bans_missing"] = _A170.get(_url170 + "bans")
    _g170["files_user"] = _F170.get(_url170 + "ops")
    _g170["viewer"] = _V170.get(_url170 + "ops")
    _g170["sender"] = _S170.get(_url170 + "ops")
    _g170["css"] = _A170.get("/api/server/%d/mc-lists/ops" % _cs170)
    _g170["unknown_list"] = _A170.get(_url170 + "secrets")
    _reads_before_refusal170 = len(_reads170)
    _read_refusal170["on"] = True
    _g170["refused"] = _A170.get(_url170 + "ops")
    _read_refusal170["on"] = False
    _g170["reads_on_refusal"] = len(_reads170) - _reads_before_refusal170
    with _p9.app_context():
        from panel.db.models import GameServer as _GS170
        _db170.session.get(_GS170, _mc170).status = "offline"
        _db170.session.commit()
    _g170["stopped"] = _A170.get(_url170 + "ops")

    # changes, server stopped first
    _p170["stopped"] = _A170.post(_url170 + "ops", json={"action": "add", "value": "Steve"})
    _p170["stopped_audit"] = _p9_audit("mc_list_change")
    _p170["stopped_sent"] = len(_sent170)
    with _p9.app_context():
        _db170.session.get(_GS170, _mc170).status = "online"
        _db170.session.commit()
    _p170["op"] = _A170.post(_url170 + "ops", json={"action": "add", "value": "Steve"})
    _p170["op_audit"] = _p9_audit("mc_list_change")
    _p170["ban"] = _A170.post(_url170 + "bans", json={"action": "add", "value": "Griefer", "reason": "spawn grief"})
    _p170["wl_off"] = _S170.post(_url170 + "whitelist", json={"action": "off"})
    _sent_ok170 = list(_sent170)
    _p170["inject"] = [_A170.post(_url170 + w, json=b).status_code for w, b in (
        ("ops", {"action": "add", "value": "Steve\nstop"}),
        ("ops", {"action": "add", "value": "Steve stop"}),
        ("whitelist", {"action": "add", "value": "@a"}),
        ("bans", {"action": "add", "value": "Griefer", "reason": "x\nstop"}),
        ("bans", {"action": "add", "value": "Griefer", "reason": "x\x1b[2J"}),
        ("ipbans", {"action": "add", "value": "2001:db8::5"}),
        ("ipbans", {"action": "add", "value": "10.0.0.0/8"}),
        ("ops", {"action": "on"}),
        ("ops", {"action": "add", "value": ["Steve"]}),
        ("ops", {"action": "add\nstop", "value": "Steve"}))]
    _p170["inject_audit"] = _p9_audit("mc_list_change")
    _p170["files_user"] = _F170.post(_url170 + "ops", json={"action": "add", "value": "Steve"})
    _p170["viewer"] = _V170.post(_url170 + "ops", json={"action": "add", "value": "Steve"})
    _p170["css"] = _A170.post("/api/server/%d/mc-lists/ops" % _cs170, json={"action": "add", "value": "Steve"})
    _sent_after_refusals170 = list(_sent170)
    _send_rc170["rc"] = 3
    _p170["rc3"] = _A170.post(_url170 + "ops", json={"action": "remove", "value": "Steve"})
    _p170["rc3_audit"] = _p9_audit("mc_list_change")
    _send_rc170["rc"], _send_rc170["raise"] = 0, ConnectionError("timed out")
    _p170["raised"] = _A170.post(_url170 + "ops", json={"action": "remove", "value": "Steve"})
    _p170["raised_audit"] = _p9_audit("mc_list_change")
    _send_rc170["raise"] = None
finally:
    _p9_restore_all()
    _p9_delete_server(_mc170)
    _p9_delete_server(_cs170)


def _j170(r):
    return r.get_json(silent=True) or {}


_go170, _gw170 = _j170(_g170["ops"]), _j170(_g170["whitelist"])
check("mc list read: the file's rows, through the file reader at serverfiles/<file> as the game account",
      _g170["ops"].status_code == 200 and _go170.get("success") is True
      and [r["name"] for r in _go170.get("entries", [])] == ["Steve", ""] and _go170.get("running") is True
      and _go170.get("can_change") is True and ("mcserver", "serverfiles/ops.json") in _reads170,
      repr((_g170["ops"].status_code, _go170)))
check("mc list read: the whitelist carries server.properties' white-list state",
      _gw170.get("success") is True and _gw170.get("whitelist_on") is True
      and ("mcserver", "serverfiles/server.properties") in _reads170, repr(_gw170))
_gi170, _gb170, _gm170 = _j170(_g170["ipbans"]), _j170(_g170["bans"]), _j170(_g170["bans_missing"])
check("mc list read: a read that failed, and a file that is not a JSON list, are 'could not be read', never "
      "an empty list",
      _gi170.get("success") is False and _gi170.get("error") == _mcl170.MCL_UNREADABLE and "entries" not in _gi170
      and _gb170.get("success") is False and "entries" not in _gb170, repr((_gi170, _gb170)))
check("mc list read: a file that is not there is an empty list (the server writes it when it has an entry)",
      _gm170.get("success") is True and _gm170.get("entries") == [], repr(_gm170))
check("mc list read: the file manager's permission reads it (and may not change it); console viewers and "
      "senders without it are refused",
      _g170["files_user"].status_code == 200 and _j170(_g170["files_user"]).get("can_change") is False
      and _g170["viewer"].status_code == 403 and _g170["sender"].status_code == 403,
      repr([_g170[k].status_code for k in ("files_user", "viewer", "sender")]))
check("mc list read: a server that is not Java Minecraft is refused, and an unknown list has no route",
      _g170["css"].status_code == 400 and _g170["unknown_list"].status_code == 404,
      repr((_g170["css"].status_code, _g170["unknown_list"].status_code)))
check("mc list read: the file browser's root-account refusal is asked, with its own audit action, and a "
      "refused read reads nothing",
      _g170["refused"].status_code == 409 and _refused170 == [("mc_list_read", "serverfiles/ops.json")]
      and _g170["reads_on_refusal"] == 0, repr((_g170["refused"].status_code, _refused170)))
check("mc list read: a stopped server's list still reads, marked not running",
      _j170(_g170["stopped"]).get("success") is True and _j170(_g170["stopped"]).get("running") is False,
      repr(_j170(_g170["stopped"])))

check("mc list change: a stopped server is refused (409), nothing is sent, and the refusal is audited",
      _p170["stopped"].status_code == 409 and _j170(_p170["stopped"]).get("message") == _mcl170.MCL_STOPPED
      and _p170["stopped_audit"].success is False and _p170["stopped_audit"].target == "p170-mc"
      and _p170["stopped_audit"].detail.startswith("op Steve (refused:") and _p170["stopped_sent"] == 0,
      repr((_p170["stopped"].status_code, _p170["stopped_audit"])))
check("mc list change: op, ban with its reason and whitelist off go through send_console_command as the game "
      "account with the instance's selfname, and are audited against the server",
      _sent_ok170 == [("mcserver", "op Steve", "mcserver"), ("mcserver", "ban Griefer spawn grief", "mcserver"),
                      ("mcserver", "whitelist off", "mcserver")]
      and _j170(_p170["op"]).get("success") is True and _p170["op_audit"].detail == "op Steve"
      and _p170["op_audit"].success is True and _p170["op_audit"].target == "p170-mc",
      repr((_sent_ok170, _p170["op_audit"])))
check("mc list change: line breaks, spaces, selectors, control characters in a reason, an IPv6 address, a "
      "range, on/off for ops, a list value and a broken action are each a 400 and send nothing",
      _p170["inject"] == [400] * 10 and _sent_after_refusals170 == _sent_ok170
      and _p170["inject_audit"].success is False and _p170["inject_audit"].detail.startswith("ops ? (refused:"),
      repr((_p170["inject"], _sent_after_refusals170, _p170["inject_audit"])))
check("mc list change: the console's send permission is needed (a file manager and a console viewer are "
      "refused) and only a Java Minecraft server takes it",
      _p170["files_user"].status_code == 403 and _p170["viewer"].status_code == 403
      and _p170["css"].status_code == 400 and _j170(_p170["wl_off"]).get("success") is True,
      repr([_p170[k].status_code for k in ("files_user", "viewer", "css", "wl_off")]))
check("mc list change: a send the console refused says why and is audited as failed",
      _j170(_p170["rc3"]).get("success") is False and _j170(_p170["rc3"]).get("message")
      and _p170["rc3_audit"].detail == "deop Steve" and _p170["rc3_audit"].success is False,
      repr((_j170(_p170["rc3"]), _p170["rc3_audit"])))
check("mc list change: a send that raised (host down) answers 'unreachable' and is audited as failed",
      _p170["raised"].status_code == 200 and _j170(_p170["raised"]).get("error")
      and _p170["raised_audit"].detail.startswith("deop Steve") and _p170["raised_audit"].success is False
      and _p170["raised_audit"].id != _p170["rc3_audit"].id, repr((_j170(_p170["raised"]), _p170["raised_audit"])))

# ── 5. the server page ──────────────────────────────────────────────────────────────────────────
_pmc170 = _p9_new_server(P9_HOST, "pmcserver", "pmc", 25566, name="p170-pmc", status="online")
_pmb170 = _p9_new_server(P9_HOST, "mcbserver", "mcb", 19132, name="p170-mcb", status="online")
_pages170 = {}
try:
    _p9_arm(who="part170")
    _p9_patch(_sd170, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd170, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc170, "run_command", lambda *a, **k: ("", "", 1))
    for _k170, _uid170, _sid170 in (("admin", P9_ADMIN, _pmc170), ("files", P9_FILES, _pmc170),
                                    ("viewer", P9_VIEWER, _pmc170), ("bedrock", P9_ADMIN, _pmb170)):
        _r170 = _p9_client(_uid170).get("/server/%d" % _sid170)
        _pages170[_k170] = (_r170.status_code, _r170.get_data(as_text=True))
finally:
    _p9_restore_all()
    _p9_delete_server(_pmc170)
    _p9_delete_server(_pmb170)
    with _p9.app_context():
        _u170 = _db170.session.get(_U170, P170_SEND)
        if _u170 is not None:
            _db170.session.delete(_u170)
        _gr170 = _db170.session.get(_G170, _P170_GROUP)
        if _gr170 is not None:
            _db170.session.delete(_gr170)
        _db170.session.commit()
_pa170, _pf170, _pv170, _pb170 = (_pages170.get(k, (0, ""))[1] for k in ("admin", "files", "viewer", "bedrock"))
check("server page: a PaperMC server shows the Player Lists card with its form and script to a superadmin",
      _pages170.get("admin", (0,))[0] == 200 and 'id="mcl-card"' in _pa170 and 'data-can-change="1"' in _pa170
      and 'id="mcl-form"' in _pa170 and "js/server_mclists.js" in _pa170, _pa170[:200])
check("server page: a file manager sees the lists without the form; a console viewer and a Bedrock server get "
      "no card and no script",
      'id="mcl-card"' in _pf170 and 'data-can-change="0"' in _pf170 and 'id="mcl-form"' not in _pf170
      and 'id="mcl-card"' not in _pv170 and "server_mclists.js" not in _pv170
      and 'id="mcl-card"' not in _pb170 and "server_mclists.js" not in _pb170,
      repr([_pages170.get(k, (0,))[0] for k in ("files", "viewer", "bedrock")]))

# ── 6. the card's script, in node ───────────────────────────────────────────────────────────────
with open(_os170.path.join(_root, "panel", "static", "js", "server_mclists.js"), encoding="utf-8") as _fh170:
    _js170 = _fh170.read()
_name_js170 = "mc lists card: refuses a bad value without posting, draws names as text, posts a good one"
_out170 = _run_js75(_name_js170, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 9; global.t = s => s;\n"
    "global.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v[k]);\n"
    "function node(tag) { const n = {tag, children: [], attrs: {}, hidden: false, disabled: false, value: '',\n"
    "  textContent: '', className: '', style: {}, classList: {toggle: () => 0},\n"
    "  appendChild(c) { this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = String(v); },\n"
    "  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }};\n"
    "  Object.defineProperty(n, 'innerHTML', {set() { throw new Error('innerHTML used'); }}); return n; }\n"
    "const els = {}; const mk = id => (els[id] = els[id] || node('div'));\n"
    "mk('mcl-card').attrs['data-can-change'] = '1';\n"
    "global.document = {getElementById: mk, readyState: 'complete', addEventListener: () => 0,\n"
    "  querySelectorAll: () => [], createElement: node};\n"
    "const posts = [];\n"
    "const reply = {success: true, running: true, can_change: true,\n"
    "  entries: [{name: '<img src=x onerror=alert(1)>', level: '4'}, {name: 'Steve', level: '3'}]};\n"
    "global.fetch = (u, o) => { if (o && o.method === 'POST') posts.push([u, JSON.parse(o.body)]);\n"
    "  return Promise.resolve({json: () => Promise.resolve(o ? {success: true, message: 'ok'} : reply)}); };\n"
    "global.setTimeout = () => 0;\n"
    + _js170 + "\n"
    "(async () => { await settle();\n"
    "  const rows = els['mcl-rows'].children; const first = rows[0] ? rows[0].children[0].textContent : null;\n"
    "  const rm = rows[0] ? rows[0].children[2].children[0] : null;\n"
    "  const out = {rows: rows.length, first, removeArgs: rm && rm.attrs['data-args'],\n"
    "    enabled: !els['mcl-value'].disabled};\n"
    "  for (const v of ['Steve\\nstop', 'Ste ve', '@a', 'ab']) { els['mcl-value'].value = v;\n"
    "    window.mclAdd({preventDefault() {}}); await settle(); }\n"
    "  out.refusedPosts = posts.length; out.refusedMsg = els['mcl-msg'].textContent;\n"
    "  els['mcl-value'].value = ' Alex '; window.mclAdd({preventDefault() {}}); await settle();\n"
    "  window.mclTab('ipbans'); await settle();\n"
    "  els['mcl-value'].value = '2001:db8::5'; window.mclAdd({preventDefault() {}}); await settle();\n"
    "  out.v6Msg = els['mcl-msg'].textContent;\n"
    "  els['mcl-value'].value = '203.0.113.7'; els['mcl-reason'].value = 'bot\\nstop';\n"
    "  window.mclAdd({preventDefault() {}}); await settle(); out.reasonMsg = els['mcl-msg'].textContent;\n"
    "  els['mcl-reason'].value = 'bot farm'; window.mclAdd({preventDefault() {}}); await settle();\n"
    "  out.posts = posts; console.log(JSON.stringify(out)); })();\n"))
if _out170 is not None:
    check("mc lists card: names from the file are drawn as text (no markup), each with its own remove button",
          _out170.get("rows") == 2 and _out170.get("first") == "<img src=x onerror=alert(1)>"
          and _out170.get("removeArgs") == '["ops","<img src=x onerror=alert(1)>"]'
          and _out170.get("enabled") is True,
          repr(_out170))
    check("mc lists card: a name with a line break, a space, a selector or too few letters posts nothing and says "
          "the name rule",
          _out170.get("refusedPosts") == 0 and _out170.get("refusedMsg") == _mcl170._MCL_BAD_NAME, repr(_out170))
    check("mc lists card: an IPv6 address and a reason with a line break are refused in the page too; a good name "
          "and a good IP ban are posted to their list",
          _out170.get("v6Msg") == _mcl170._MCL_IPV6 and _out170.get("reasonMsg") == _mcl170._MCL_BAD_REASON
          and _out170.get("posts") == [["/api/server/9/mc-lists/ops",
                                        {"action": "add", "value": "Alex", "reason": ""}],
                                      ["/api/server/9/mc-lists/ipbans",
                                       {"action": "add", "value": "203.0.113.7", "reason": "bot farm"}]],
          repr(_out170))
