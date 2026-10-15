"""Part 81 of the unit suite: the tenth review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* a delegated log viewer granted the panel's own host does not read that host's administration
  (an address blocked through /api/remote/<local id>/security/block was theirs to read).
* install.sh: a unique-local IPv6 is not the fallback "public" address; the distro's Node.js is
  seen on a host that is not in English.
* the i18n gates: a wrapper or a fed callback whose sink is in a lambda, a lambda's own parameter,
  a tooltip the translator skips, and a title split by a glued {% if %}.
* pages: two quick language picks, a dashboard swap that failed, the host page's backup interval,
  the update card when its check fails, a failed same-folder refresh with a field open, the
  version re-read on a chat line, and the panel host's reachability tooltip.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node, and install.sh's functions in bash, on this
part's own fixtures.
"""
import html as _html81
import importlib.util as _ilu81
import json as _json81
import os
import re as _re81
import shutil as _shutil81
import subprocess as _sp81  # nosec B404 - runs bash on install.sh's own functions
import tempfile as _tf81

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part72 import _DOM72
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_restore_all)
from panel.db.models import (AuditLog as _AL81, Group as _G81, RemoteServer as _RS81, User as _U81,
                             db as _db81)
from panel.ops import system_ops as _so81
from panel.routes import audit as _audit81, remote_security as _rs81
from panel.security import auth as _auth81, banlist as _bl81

_JS81 = os.path.join(_root, "static", "js")
_XHR81 = {"X-Requested-With": "XMLHttpRequest"}
_TRIP81_START = len(_P9_TRIPPED)
_spec81 = _ilu81.spec_from_file_location("i18n_scan_p81", os.path.join(_root, "tools", "i18n_scan.py"))
_scan81 = _ilu81.module_from_spec(_spec81)
_spec81.loader.exec_module(_scan81)
_ES81, _FR81 = _scan81.load_catalog("es"), _scan81.load_catalog("fr")


def _read81(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node81(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or81(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _line81(src, head):
    """The one line of `src` that starts at `head` (a `var …;` declaration), or a comment naming it."""
    i = src.find(head)
    return src[i:src.index("\n", i)] if i >= 0 else "/* MISSING %s */" % head


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A log viewer granted the panel's own host does not read its administration
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The /api/remote/<id>/… twins of the panel host's firewall routes audit BY ROW, with the address
# as the target; audit_scope only kept out target == "Panel Server", so a VIEW_LOGS group whose
# whole-host grant covered the panel host read which addresses a superadmin blocked there.
_mine81 = {"users": [], "groups": []}
_rows81 = {}
try:
    with _p9.app_context():
        _g81 = _G81(name="p81_logs", description="", is_default=False)
        _g81.set_permissions([_auth81.VIEW_LOGS])
        _g81.servers.extend([_db81.session.get(_RS81, P9_LOCAL), _db81.session.get(_RS81, P9_HOST)])
        _v81 = _U81(username="p81_viewer", password_hash=_auth81.hash_password("Str0ng!passw0rd-p81"),
                    display_name="p81 viewer", is_superadmin=False, is_active=True)
        _v81.groups.append(_g81)
        _db81.session.add_all([_g81, _v81])
        _db81.session.commit()
        _mine81["users"].append(_v81.id)
        _mine81["groups"].append(_g81.id)
    _p9_arm(who="part81")
    _p9_patch(_rs81, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_rs81, "_whitelisted", lambda ip: False)
    _p9_patch(_rs81, "remote_ufw_deny_ip", lambda remote, ip: (True, "Blocked."))
    _p9_patch(_bl81, "refresh_soon", lambda *a, **k: None)
    _sa81 = _p9_client(P9_ADMIN)
    for _k81, _rid81, _ip81 in (("local", P9_LOCAL, "198.51.100.81"), ("remote", P9_HOST, "198.51.100.82")):
        _r81 = _sa81.post("/api/remote/%d/security/block" % _rid81, json={"ip": _ip81}, headers=_XHR81)
        with _p9.app_context():
            _row81 = _AL81.query.filter_by(action="ufw_block", target=_ip81).order_by(_AL81.id.desc()).first()
            _rows81[_k81] = (_r81.status_code, _p9_json(_r81).get("success"),
                             _row81.id if _row81 else None, _row81.remote_id if _row81 else None)
    with _p9.app_context():
        _scope81 = _audit81.audit_scope(_db81.session.get(_U81, _mine81["users"][0]))
        _seen81 = {k: _AL81.query.filter(_AL81.id == v[2]).filter(_scope81).count() == 1
                   for k, v in _rows81.items() if v[2] is not None}
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _v in _rows81.values():
            if _v[2] is not None:
                _db81.session.delete(_db81.session.get(_AL81, _v[2]))
        for _uid81 in _mine81["users"]:
            _db81.session.delete(_db81.session.get(_U81, _uid81))
        for _gid81 in _mine81["groups"]:
            _db81.session.delete(_db81.session.get(_G81, _gid81))
        _db81.session.commit()
check("audit scope: (premise) a superadmin's block on the panel host and on a remote, through the "
      "/api/remote/<id> route, each wrote a row filed under that host",
      _rows81.get("local", ())[:2] == (200, True) and _rows81.get("local", (0,) * 4)[3] == P9_LOCAL
      and _rows81.get("remote", ())[:2] == (200, True) and _rows81.get("remote", (0,) * 4)[3] == P9_HOST,
      repr(_rows81))
check("audit scope: a log viewer whose group grants the panel host does not read the panel host's "
      "own administration (the address a superadmin blocked there); the remote's row they do read",
      _seen81 == {"local": False, "remote": True}, repr(_seen81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. install.sh: a unique-local IPv6 is not the way in from outside
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #428 skipped private IPv4s and only fe80: on the IPv6 side, so a ULA (the tailnet's fd7a:…,
# docker's and LXD's fd00::/8 bridges) beat a LAN IPv4, and a global IPv6 listed after it.
_INS81 = _read81("install.sh")
_i81 = _INS81.find("\nhost_addr_fallback() {")
_FALLBACK81 = _INS81[_i81:_INS81.find("\n}\n", _i81)] + "\n}\n" if _i81 >= 0 else "exit 3\n"


def _fallback81(addrs):
    script = ("set -euo pipefail\naddrs=\"$1\"\nhostname() { echo \"${addrs}\"; }\n" + _FALLBACK81
              + "host_addr_fallback\n")
    r = _sp81.run(["bash", "-c", script, "p81", addrs],  # nosec B603 B607 - bash, fixed script
                  capture_output=True, text=True, timeout=60)
    return (r.stdout + r.stderr).strip()


_fb81 = {a: _fallback81(a) for a in (
    "192.168.1.5 100.101.1.2 fd7a:115c:a1e0::1234", "192.168.1.5 10.40.0.1 fd42:9b1c:7e2a::1",
    "192.168.1.5 172.17.0.1 fd00::1 2001:db8::9", "fd00::1 2001:db8::9", "FC00::1 192.168.1.5",
    "febf::1 192.168.1.5", "fcd::1 192.168.1.5", "fe8::1 192.168.1.5", "fd00::1",
    "2001:db8::5 172.17.0.1", "203.0.113.9 2001:db8::5", "fe80::1 192.168.1.5")}
check("install.sh: with no lookup answering, a unique-local IPv6 (fc00::/7: the tailnet's fd7a:…, "
      "a docker or LXD bridge) loses to a LAN IPv4 and to a global IPv6, as fe80::/10 does",
      [_fb81[a] for a in ("192.168.1.5 100.101.1.2 fd7a:115c:a1e0::1234",
                          "192.168.1.5 10.40.0.1 fd42:9b1c:7e2a::1", "192.168.1.5 172.17.0.1 fd00::1 2001:db8::9",
                          "fd00::1 2001:db8::9", "FC00::1 192.168.1.5", "febf::1 192.168.1.5")]
      == ["192.168.1.5", "192.168.1.5", "2001:db8::9", "2001:db8::9", "192.168.1.5", "192.168.1.5"],
      repr(_fb81))
check("install.sh: ...a first group shorter than four digits (fcd::, fe8::) is NOT in those ranges, "
      "a lone ULA is still printed, and #428's cases hold (controls)",
      [_fb81[a] for a in ("fcd::1 192.168.1.5", "fe8::1 192.168.1.5", "fd00::1", "2001:db8::5 172.17.0.1",
                          "203.0.113.9 2001:db8::5", "fe80::1 192.168.1.5")]
      == ["fcd::1", "fe8::1", "fd00::1", "2001:db8::5", "203.0.113.9", "192.168.1.5"], repr(_fb81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. install.sh: the distro's Node.js is seen on a host that is not in English
# ════════════════════════════════════════════════════════════════════════════════════════════════
# `apt-cache policy` labels its candidate in the host's language ("Installationskandidat:"), so a
# German 24.04 host read no candidate and was given NodeSource's third-party repo instead.
_j81 = _INS81.find("\nensure_nodejs() {")
_NODEJS81 = _INS81[_j81:_INS81.find("\n}\n", _j81)] + "\n}\n" if _j81 >= 0 else "exit 3\n"
_NODE_STUBS81 = r'''
d="$1"; log="$d/log"; NODESOURCE_NODE_MAJOR=22
id() { echo 0; }
info() { echo "info $*" >> "$log"; }
warn() { echo "warn $*" >> "$log"; }
tee() { cat > /dev/null; }
chmod() { :; }
jq() { :; }; curl() { :; }; pigz() { :; }; npm() { :; }
apt-get() { echo "apt-get $*" >> "$log"; [[ "$*" != *nodejs* ]] || : > "$d/node-installed"; }
nodesource_setup() { echo "nodesource" >> "$log"; return 1; }
node() { if [[ -e "$d/node-installed" ]]; then echo v18.19.1; else echo v12.22.9; fi; }
apt-cache() {
    case "${LC_ALL:-${LANG:-}}" in
        C|C.*|POSIX) printf 'nodejs:\n  Installed: 12.22.9\n  Candidate: 18.19.1+dfsg-6ubuntu5\n' ;;
        *) printf 'nodejs:\n  Installiert: 12.22.9\n  Installationskandidat: 18.19.1+dfsg-6ubuntu5\n' ;;
    esac
}
'''


def _nodejs81():
    d = _tf81.mkdtemp(prefix="lgsm-unit-p81-")
    try:
        env = {k: v for k, v in os.environ.items() if not k.startswith("LC_") and k != "LANGUAGE"}
        env.update(LANG="de_DE.UTF-8")
        _sp81.run(["bash", "-c", "set -euo pipefail\n" + _NODE_STUBS81 + _NODEJS81 + "ensure_nodejs\n",
                   "p81", d],  # nosec B603 B607 - bash, fixed script
                  capture_output=True, text=True, timeout=60, env=env)
        try:
            with open(os.path.join(d, "log"), encoding="utf-8") as fh:
                return fh.read().splitlines()
        except OSError:
            return []
    finally:
        _shutil81.rmtree(d, ignore_errors=True)


_nlog81 = _nodejs81()
check("install.sh: on a German host the distro's Node.js 18 candidate is read and installed, and "
      "NodeSource's third-party repo is not added (the translated \"Candidate:\" label read as none)",
      "apt-get install -y nodejs" in _nlog81 and "nodesource" not in _nlog81, repr(_nlog81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The i18n gates find a wrapper, and a fed callback, whose sink sits inside a lambda
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #428 moved the sink walks onto _r18c_shown_nodes but left two on _py_own_nodes: the wrapper
# table (so `_reply`, whose jsonify is in a lambda, was no wrapper and every message handed to it
# passed spliced_py, route_answer_keys and shown_literals_py) and the callback-fed calls.
_td81 = os.path.realpath(_tf81.mkdtemp(prefix="lgsm-unit-p81-"))
try:
    os.makedirs(os.path.join(_td81, "panel", "routes"))
    with open(os.path.join(_td81, "app.py"), "w") as _fh81:
        _fh81.write("")
    with open(os.path.join(_td81, "panel", "routes", "r.py"), "w") as _fh81:
        _fh81.write(
            "def _reply(text):\n"
            "    return later(lambda: jsonify({'message': text}))\n"
            "def _reply2(text):\n"
            "    return jsonify({'message': text})\n"
            "def route(y):\n"
            "    _reply(f'Built for {y}')\n"
            "    _reply2(f'Also built {y}')\n"
            "    return _reply('Fixed sentence here.')\n"
            "def install(x, on_progress=None):\n"
            "    on_progress('Fixed step one.')\n"
            "    later(lambda: on_progress(f'Built step {x}'))\n"
            "def run():\n"
            "    install(1, on_progress=lambda m: _p(8, m))\n"
            # A lambda's own parameter is not the enclosing function's local or parameter.
            "def shadow(y, text):\n"
            "    msg = f'Built {y}'\n"
            "    flash_later(lambda msg: flash(msg))\n"
            "    return later(lambda text: jsonify({'message': text}))\n")
    _wr81 = sorted(_scan81._py_wrappers(_scan81._py_trees(_td81)))
    _spl81 = sorted((f, line) for f, line, _w in _scan81.spliced_py(root=_td81))
    _rak81 = _scan81.route_answer_keys(root=_td81)
    _steps81 = _scan81.step_names_built(root=_td81)
finally:
    _shutil81.rmtree(_td81, ignore_errors=True)
_rf81 = os.path.join("panel", "routes", "r.py")
check("i18n gate: a function whose sink is inside a lambda is a wrapper, so spliced_py reports the "
      "message built for it and route_answer_keys asks es/fr for the fixed one",
      _wr81 == ["_reply", "_reply2"] and _spl81 == [(_rf81, 6), (_rf81, 7)]
      and "Fixed sentence here." in _rak81, repr((_wr81, _spl81, sorted(_rak81))))
check("i18n gate: ...but a lambda's own parameter is neither the enclosing function's built local "
      "(a false \"built message\") nor its parameter (a false wrapper)",
      "shadow" not in _wr81 and all(line < 14 for _f, line in _spl81), repr((_wr81, _spl81)))
check("i18n gate: a callback's keyword called inside a lambda in the callee is read by the job step "
      "walk (its built text is reported)",
      _steps81 == [(_rf81, 11)], repr(_steps81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Two quick language picks end in the language picked last
# ════════════════════════════════════════════════════════════════════════════════════════════════
# fr then es on a slow link: the fr catalog arriving last put the page (and every picker) back in
# French, and the two saves raced on the server. The real handler, with fetch answered by hand.
_PJ81 = _read81("static", "js", "panel.js")
_HANDLER81 = "document.addEventListener('change', function(e){\n  var el = e.target;\n  if (!el || !el.matches || !el.matches('select[data-lang-select]')"
_lang_prog81 = (
    _SETTLE47 + "global.window = global; global.MOUNT = '';\n"
    "const handlers = [], pickers = [{value: 'en'}], pending = [], posts = [], applied = [];\n"
    "global.document = {addEventListener: (t, f) => handlers.push(f), querySelectorAll: () => pickers};\n"
    "global.fetch = (url, opts) => { let res; const p = new Promise(r => { res = r; });\n"
    "  pending.push({url, res}); if (opts && opts.method === 'POST') posts.push(url); return p; };\n"
    "window.setLang = l => applied.push(l);\n"
    "const answer = (url, body) => pending.find(x => x.url === url).res({ok: true, json: () => Promise.resolve(body)});\n"
    "%s\n%s);\n"
    "const pick = lang => handlers[0]({target: {value: lang, matches: () => true, getAttribute: () => '/lang/LANGCODE'}});\n"
    "(async () => {\n"
    "  pick('fr'); pick('es'); await settle();\n"
    "  const postsFirst = posts.slice();\n"
    "  answer('/api/i18n/es', {}); await settle(); answer('/api/i18n/fr', {}); await settle();\n"
    "  answer('/lang/fr?ajax=1', {success: true}); await settle();\n"
    "  console.log(JSON.stringify({applied, picker: pickers[0].value, postsFirst, posts}));\n"
    "})();\n") % (_line81(_PJ81, "var _r20cLangSeq"), _cut_or81(_PJ81, _HANDLER81))
_lang81 = _node81("panel.js: two quick language picks", _lang_prog81)
if _lang81 is not None:
    check("language picker: fr then es, the fr catalog answering last, leaves the page and the picker "
          "in es, and the es save is sent only after the fr one answered (the page went back to fr)",
          _lang81 == {"applied": ["es"], "picker": "es", "postsFirst": ["/lang/fr?ajax=1"],
                      "posts": ["/lang/fr?ajax=1", "/lang/es?ajax=1"]}, repr(_lang81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The dashboard re-asks for a changed server list until the page shows it
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The new set was adopted when the swap was ASKED, so one failed swap (a blip, a restart, a login
# page) left a new server missing, and a removed one listed, until a reload.
_DJ81 = _read81("static", "js", "dashboard.js")
_dash_prog81 = (
    _SETTLE47 + "global.window = global; global.MOUNT = ''; let clock = 1e6; Date.now = () => clock;\n"
    "let rendered = ['1', '2'], live = [1, 2, 3], swaps = 0, landing = false;\n"
    "global.document = {querySelectorAll: () => rendered.map(i => ({id: 'status-' + i}))};\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve(live.map(id => ({id})))});\n"
    "window.refreshSection = (sel, after) => { swaps++; if (!landing) return;\n"
    "  rendered = live.map(String); window[after](); };\n"
    "function _dashShowCounts(){} function _dashResyncFailedBanners(){} function _dashSyncServer(){}\n"
    "function restoreBulkSelection(){} function bindDragRegions(){}\n"
    "%s\n%s\n%s\n%s\n%s\n%s\n%s\n"
    "const poll = async () => { refreshStatus(); await settle(); clock += 8000; };\n"
    "(async () => {\n"
    "  _serverIdsBaseline = renderedServerIds();\n"
    "  await poll();                                  // asks; the swap fails\n"
    "  await poll(); await poll();                    // in flight: not asked again for 20 s\n"
    "  const quiet = swaps; landing = true;\n"
    "  await poll(); await poll(); await poll();\n"
    "  const retry = {quiet, swaps, rendered: rendered.join(','), base: _serverIdsBaseline};\n"
    # A page that never shows the set (every swap fails): five tries, then adopted, no more fetches.
    "  landing = false; live = [1, 2, 3, 4]; swaps = 0;\n"
    "  for (let i = 0; i < 30; i++) await poll();\n"
    "  console.log(JSON.stringify({retry, capped: swaps, cappedBase: _serverIdsBaseline}));\n"
    "})();\n") % (
        _line81(_DJ81, "var _serverIdsBaseline"), _line81(_DJ81, "var _r20cIdsAsked"),
        _cut_or81(_DJ81, "function renderedServerIds("), _cut_or81(_DJ81, "function _r20cIdsChanged("),
        _cut_or81(_DJ81, "function _r20cIdsLanded("), _cut_or81(_DJ81, "function refreshStatus("),
        _cut_or81(_DJ81, "window.afterDashRefresh = function("))
_dash81 = _node81("dashboard.js: a failed swap of a changed server list", _dash_prog81)
if _dash81 is not None:
    check("dashboard: a changed server list whose swap failed is asked for again (once the in-flight "
          "one has had 20 s) until the page shows it — the new server stayed missing until a reload",
          _dash81.get("retry") == {"quiet": 1, "swaps": 2, "rendered": "1,2,3", "base": "1,2,3"}, repr(_dash81))
    check("dashboard: ...and a list the page never shows is asked for five times, then left alone "
          "(no fetch of the whole page every 8 s)",
          _dash81.get("capped") == 5 and _dash81.get("cappedBase") == "1,2,3,4", repr(_dash81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The host page's backup interval keeps a stored value its list does not offer
# ════════════════════════════════════════════════════════════════════════════════════════════════
# fb-interval offers 1/7/14/30 and the API takes 0-365: a stored 3 left the select with no
# selection, and the next save of anything on the card posted parseInt('')||7 (weekly).
_RB81 = _read81("static", "js", "remote_manage_backups.js")
_fb_prog81 = (
    "global.window = global; global.MOUNT = ''; let posted = null;\n"
    "global.tf = (k, v) => k.replace('{n}', v.n);\n"
    "const mkSel = vals => ({options: vals.map(value => ({value, textContent: value})), _v: vals[0], disabled: false,\n"
    "  appendChild(o){ this.options.push(o); },\n"
    "  get value(){ return this._v; }, set value(v){ this._v = this.options.some(o => o.value === v) ? v : ''; }});\n"
    "const els = {'fb-interval': mkSel(['1', '7', '14', '30']), 'fb-auto-enabled': {checked: false},\n"
    "  'fb-keep': {value: ''}, 'bk-enabled': {checked: true}, 'bk-keep': {value: '7'}};\n"
    "global.document = {getElementById: id => els[id] || null,\n"
    "  createElement: () => ({attrs: {}, setAttribute(k, v){ this.attrs[k] = v; }})};\n"
    "global.fetch = (u, o) => { posted = JSON.parse(o.body); return new Promise(() => {}); };\n"
    "function fbSummary(){}\n"
    "%s\n%s\n%s\n"
    "bkRenderFullSchedule({interval_days: 3, keep: 2});\n"
    "const sel = els['fb-interval'];\n"
    "saveBackupSettings();\n"
    "const o = sel.options.find(x => x.value === sel.value) || {attrs: {}};\n"
    "console.log(JSON.stringify({value: sel.value, label: o.textContent, posted: posted && posted.full_interval_days,\n"
    "  relabel: [o.attrs['data-i18n-text'], o.attrs['data-i18n-vars']]}));\n") % (
        _cut_or81(_RB81, "function _r20cIntervalOption("), _cut_or81(_RB81, "function bkRenderFullSchedule("),
        _cut_or81(_RB81, "function saveBackupSettings("))
_fbi81 = _node81("remote_manage_backups.js: a stored interval the list lacks", _fb_prog81)
if _fbi81 is not None:
    check("host page backups: a stored 3-day interval is shown (\"3 days\") and a later save keeps it "
          "(it showed nothing and saved weekly)",
          _fbi81 == {"value": "3", "label": "3 days", "posted": 3, "relabel": ["{n} days", '{"n":3}']},
          repr(_fbi81))
check("host page backups: the default-schedule line says any other interval's number (3 days read "
      "\"once a month\")",
      "'By default, each server is backed up every {n} days.'" in _RB81 and "tfHtml(every, {n: days})" in _RB81
      and "By default, each server is backed up every {n} days." in _ES81
      and "By default, each server is backed up every {n} days." in _FR81, "missing")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. The update card shows its two states only, when the check itself fails
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The route's failure answer took the not-a-git-checkout branch ("Internal server error" printed,
# Update hidden), and a fetch that failed printed "Update check failed." — third states, which the
# owner's rule forbids: "Update available" or "You're up to date", nothing else.
def _boom81(*_a, **_k):
    raise RuntimeError("p81: the update check broke")


try:
    _p9_arm(who="part81")
    _p9_patch(_so81, "panel_update_status", _boom81)
    _p9_patch(_so81, "panel_version", lambda: "2026.10.13")
    _p9_patch(_so81, "panel_commit", lambda: "a1b2c3d")
    _upd81 = _p9_json(_p9_client(P9_ADMIN).get("/api/panel/update-status"))
finally:
    _p9_restore_all()
_RMH81 = _read81("static", "js", "remote_manage_host.js")
_upd_prog81 = (
    "global.window = global; global.MOUNT = ''; global.escapeHtml = s => String(s); global.t = s => s;\n"
    "global.tfHtml = (k, v) => k.replace(/\\{(\\w+)\\}/g, (m, n) => (v[n] && v[n].html) || v[n]);\n"
    "const el = () => ({innerHTML: '', textContent: '', style: {}, appendChild(){}});\n"
    "const els = {'pu-status': el(), 'pu-update-btn': el(), 'pu-changes': el(), 'pu-current': el(),\n"
    "  'pu-changes-list': el()};\n"
    "els['pu-current'].textContent = '2026.10.13 · a1b2c3d';\n"
    "global.document = {getElementById: id => els[id] || null};\n"
    "let answer; global.fetch = () => answer;\n"
    "%s\n%s\n%s\n"
    "const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"
    "const st = els['pu-status'], btn = els['pu-update-btn'];\n"
    "(async () => {\n"
    "  renderUpdate(%s); const failedRoute = [st.innerHTML, btn.style.display];\n"
    "  _r20cUpdateShown = null; answer = Promise.reject(new Error('offline'));\n"
    "  checkPanelUpdate(true); await settle(); const failedFirst = [st.innerHTML, btn.style.display];\n"
    "  renderUpdate({git: true, update_available: true, behind: 2, remote_version: '2026.10.14', current_sha: 'a1b2c3d'});\n"
    "  answer = Promise.reject(new Error('offline'));\n"
    "  checkPanelUpdate(true); await settle(); const failedAfterOffer = [st.innerHTML, btn.style.display];\n"
    "  console.log(JSON.stringify({failedRoute, failedFirst, failedAfterOffer}));\n"
    "})();\n") % (_line81(_RMH81, "var _r20cUpdateShown"), _cut_or81(_RMH81, "function renderUpdate("),
                  _cut_or81(_RMH81, "function checkPanelUpdate("), _json81.dumps(_upd81))
_card81 = _node81("remote_manage_host.js: the update card when the check fails", _upd_prog81)
if _card81 is not None:
    _ok81 = '<span class="text-success"><i class="bi bi-check-circle"></i> '
    check("update card: a check the server could not make reads \"You're up to date (sha)\" (it printed "
          "\"Internal server error\" and hid Update), and its answer still carries the reason",
          _upd81.get("check_failed") is True and _upd81.get("message") == "Internal server error"
          and (_card81.get("failedRoute") or [""])[0] == _ok81 + "You're up to date (a1b2c3d).</span>",
          repr((_upd81, _card81)))
    check("update card: ...a fetch that failed shows no \"Update check failed.\" line: \"You're up to "
          "date\" with nothing shown yet, and an offer already shown stays offered",
          (_card81.get("failedFirst") or [""])[0] == _ok81 + "You're up to date.</span>"
          and "Update available" in (_card81.get("failedAfterOffer") or [""])[0]
          and (_card81.get("failedAfterOffer") or ["", "x"])[1] == "", repr(_card81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. A failed refresh of the same folder keeps a half-typed New file / rename name
# ════════════════════════════════════════════════════════════════════════════════════════════════
# browse() cleared the open create and rename fields and wiped the list before it read d.error, so
# an upload's refresh during a host blip threw away what was being typed.
_SF81 = _read81("static", "js", "server_files.js")
_br_prog81 = (
    _SETTLE47 + "global.window = global; global.MOUNT = ''; global.serverId = 1; const toasts = [];\n"
    "window.toast = (m, k) => toasts.push([m, k]); global.esc = s => s;\n"
    "const list = {innerHTML: 'LISTED'};\n"
    "global.document = {getElementById: id => id === 'file-list' ? list : null, activeElement: null};\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve({error: 'Host unreachable'})});\n"
    "let curDir = 'cfg', _creating = null, _renaming = null;\n"
    "%s\n%s\n%s\n%s\n%s\n"
    "(async () => {\n"
    "  _creating = {input: {}, box: {}}; browse('cfg'); await settle();\n"
    "  const open = {list: list.innerHTML, kept: _creating !== null, toasts: toasts.slice()};\n"
    "  _creating = null; browse('cfg'); await settle();\n"
    "  const none = list.innerHTML;\n"
    "  list.innerHTML = 'LISTED'; _renaming = {path: 'cfg/a', input: {}}; browse('other'); await settle();\n"
    "  console.log(JSON.stringify({open, none, other: list.innerHTML, renaming: _renaming}));\n"
    "})();\n") % (_line81(_SF81, "var _browseSeq"), _line81(_SF81, "var _browseWant"),
                  _cut_or81(_SF81, "function browse("), _cut_or81(_SF81, "function _r14c_openEditors("),
                  _cut_or81(_SF81, "function _r20cKeptOnError("))
_br81 = _node81("server_files.js: a failed same-folder refresh with a field open", _br_prog81)
if _br81 is not None:
    _err81 = '<div class="text-danger small p-2">Host unreachable</div>'
    check("file browser: a same-folder refresh that fails while New file/folder is open keeps the list, "
          "the field and its text, and says why (the field and the typed name were thrown away)",
          _br81.get("open") == {"list": "LISTED", "kept": True, "toasts": [["Host unreachable", "danger"]]},
          repr(_br81))
    check("file browser: ...with no field open, or opening another folder, the error replaces the list "
          "as before (controls)",
          _br81.get("none") == _err81 and _br81.get("other") == _err81 and _br81.get("renaming") is None,
          repr(_br81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 10. Only the panel's own push re-reads the game version
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The listener tested every console_output, game log pushes included: a player's chat line holding
# "[panel] " made every open page of the server re-read /version.
_SD81 = _read81("static", "js", "server_detail.js")
_ver_prog81 = (
    "const handlers = [], timers = []; global.serverId = 4;\n"
    "global.socket = {on: (e, f) => handlers.push(f)};\n"
    "global.setTimeout = (f, ms) => timers.push(ms);\n"
    "function loadGameVersion(){}\n"
    "%s\n%s);\n"
    "const h = handlers[0];\n"
    "h({server_id: 4, data: 'Bob: [panel] update finished'});\n"
    "const chat = timers.length;\n"
    "h({server_id: 4, data: '[panel] update finished', panel: true, ts: 1});\n"
    "h({server_id: 4, data: '[panel] update started', panel: true, ts: 2});\n"
    "console.log(JSON.stringify({chat, after: timers.length}));\n") % (
        _cut_or81(_SD81, "function _isActionEnd("),
        _cut_or81(_SD81, "socket.on('console_output', function(data) {\n"
                         "  if (data.server_id !== serverId || typeof data.data !== 'string') return;"))
_ver81 = _node81("server_detail.js: the version re-read listener", _ver_prog81)
if _ver81 is not None:
    check("server page: a game log line holding \"[panel] \" (a player's chat) does not re-read the "
          "game version; the panel's own end marker does, its start marker does not",
          _ver81 == {"chat": 0, "after": 1}, repr(_ver81))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 11. Tooltips the translator never reads, and the gate that missed them
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The page translator returns at a data-no-i18n element (or a <code>/<pre>) before its attributes,
# so a catalog key in a title there was English for every viewer, and scan_template — mirroring the
# runtime — never collected it. Also: a {% else %} glued to an attribute (`{% else %}title="…"`)
# put its mark in the attribute's NAME, so the main template gate never read that title.
_td81 = os.path.realpath(_tf81.mkdtemp(prefix="lgsm-unit-p81-"))
try:
    with open(os.path.join(_td81, "t.html"), "w", encoding="utf-8") as _fh81:
        _fh81.write(
            '<span title="Whole host" data-no-i18n>{{ n }}</span>\n'
            '<div data-no-i18n><span title="Single game server">x</span></div>\n'
            '<code title="Click to copy">1.2.3.4</code>\n'
            '<span data-no-i18n {% if m %}title="Alerts are muted for this tag"{% endif %}>t</span>\n'
            '<code title="~/.ssh/id_rsa">p</code>\n'
            '<span title="Whole host"><span data-no-i18n>{{ n }}</span></span>\n'
            '<code title="{{ t(\'Click to copy\') }}">x</code>\n'
            '<b {% if a %}title="Fixture: first branch words"{% else %}title="Fixture: other branch words"{% endif %}>x</b>\n')
    _ga81 = _scan81.guarded_attrs(template_dir=_td81, catalog={
        "Whole host", "Single game server", "Click to copy", "Alerts are muted for this tag"})
    _st81, _dyn81 = _scan81.scan_template(os.path.join(_td81, "t.html"))
finally:
    _shutil81.rmtree(_td81, ignore_errors=True)
check("i18n gate: a catalog-key tooltip the translator skips (on or under data-no-i18n, on a <code>, "
      "or behind a glued {% if %}) is reported; a path is not, nor one rendered with t() or moved off "
      "the guard",
      sorted(_ga81) == [("t.html", "Alerts are muted for this tag"), ("t.html", "Click to copy"),
                        ("t.html", "Single game server"), ("t.html", "Whole host")], repr(_ga81))
check("i18n gate: ...the templates have none (the dashboard's in-game name and muted tag chip, the "
      "group page's host and server badges, and three click-to-copy / unknown-IP code tooltips)",
      _scan81.guarded_attrs() == [], repr(_scan81.guarded_attrs()))
check("i18n gate: the template scan reads both branches of a title split by a glued {% if %}/"
      "{% else %} (the else branch's title was read by no gate)",
      {"Fixture: first branch words", "Fixture: other branch words"} <= set(_st81), repr(sorted(_st81)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 12. The panel's own host is not said to be reached over SSH
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The local transport reads the panel's own machine; its green badge said "The panel can reach this
# host over SSH" on the dashboard card and the host page header, and on every repaint.
_dpage81 = _smpage81 = ""
_lgs81 = None
try:
    _lgs81 = _p9_new_server(P9_LOCAL, "p81local", "csgo", 27981)   # a host card needs a server
    _p9_arm(who="part81")
    _p9_patch(_so81, "get_server_status", lambda: {})
    _dpage81 = _p9_client(P9_ADMIN).get("/").get_data(as_text=True)
    _smpage81 = _p9_client(P9_ADMIN).get("/server-management").get_data(as_text=True)
finally:
    _p9_restore_all()
    if _lgs81 is not None:
        _p9_delete_server(_lgs81)


def _reach81(page, rid):
    m = _re81.search(r'<span id="host-reach-%d"([^>]*)>' % rid, page)
    t = _re81.search(r'title="([^"]*)"', m.group(1)) if m else None
    return ("data-local" in m.group(1), _html81.unescape(t.group(1))) if t else None


_hdr81 = _re81.search(r'id="remote-status"\s+title="([^"]*)"', _smpage81)
check("dashboard and host page: the panel host's badge says the panel runs there (not \"over SSH\"); "
      "a remote's still says SSH",
      _reach81(_dpage81, P9_LOCAL) == (True, "The panel is running on this host")
      and _reach81(_dpage81, P9_HOST) == (False, "The panel can reach this host over SSH")
      and bool(_hdr81) and _html81.unescape(_hdr81.group(1)) == "The panel is running on this host",
      repr((_reach81(_dpage81, P9_LOCAL), _reach81(_dpage81, P9_HOST), _hdr81 and _hdr81.group(1))))
_rch_prog81 = (
    "global.window = global; const mk = local => ({className: '', textContent: '', attrs: local ? {'data-local': '1'} : {},\n"
    "  hasAttribute(k){ return k in this.attrs; }, setAttribute(k, v){ this.attrs[k] = v; }});\n"
    "const els = {'host-reach-1': mk(true), 'host-reach-2': mk(false), 'remote-status': mk(false)};\n"
    "global.document = {getElementById: id => els[id] || null};\n"
    "%s\n%s\n%s\n%s\n"
    "paintHostReach(1, {reachable: true}); const lYes = els['host-reach-1'].attrs.title;\n"
    "paintHostReach(1, {reachable: false, probed: true}); const lNo = els['host-reach-1'].attrs.title;\n"
    "paintHostReach(2, {reachable: true}); const rYes = els['host-reach-2'].attrs.title;\n"
    "window.IS_LOCAL = true; _r18cPaintHostBadge(true); const hLocal = els['remote-status'].attrs.title;\n"
    "window.IS_LOCAL = false; _r18cPaintHostBadge(true); const hRemote = els['remote-status'].attrs.title;\n"
    "console.log(JSON.stringify({lYes, lNo, rYes, hLocal, hRemote}));\n") % (
        _cut_or81(_DJ81, "var HOST_REACH = {"), _cut_or81(_DJ81, "var _R20C_LOCAL_REACH = {"),
        _cut_or81(_DJ81, "function paintHostReach("),
        _cut_or81(_read81("static", "js", "remote_manage.js"), "function _r18cPaintHostBadge("))
_rch81 = _node81("dashboard.js / remote_manage.js: the local host's repainted badge", _rch_prog81)
if _rch81 is not None:
    check("dashboard and host page: ...and the 10 s / live repaint keeps it so (both states on the "
          "dashboard); a remote's repaint still names SSH",
          _rch81 == {"lYes": "The panel is running on this host",
                     "lNo": "The panel's last check of this host failed — the servers below show their "
                            "last known state",
                     "rYes": "The panel can reach this host over SSH",
                     "hLocal": "The panel is running on this host",
                     "hRemote": "The panel can reach this host over SSH"}, repr(_rch81))



# ════════════════════════════════════════════════════════════════════════════════════════════════
# 13. A live language switch re-renders what the walk cannot reach
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Rendered with t() where the translator skips (a muted tag chip's tooltip, a <code>'s, the security
# log <pre>'s placeholder), it stayed in the old language after a switch until a reload. The real
# i18n.js over part72's DOM; the attribute names the English key.
_SKEYS81 = ("Alerts are muted for this tag", "Click to copy",
            'Pick a log above, or "view log" on a jail above, to see its recent lines.', "{n} days")
_live_prog81 = _DOM72 + (
    "const ES = %s, FR = %s;\n"
    "const all = (n, out) => { (n.childNodes || []).forEach(c => { if (c.nodeType === 1) { out.push(c); all(c, out); } });"
    " return out; };\n"
    "document.querySelectorAll = sel => all(document.body, []).filter(e => e.hasAttribute(sel.slice(1, -1)));\n"
    "window.LANG = 'es'; window.I18N = ES;\n"
    "require('vm').runInThisContext(%s);\n"
    "const b = document.body, mk = (tag, attrs, text) => { const e = b.appendChild(document.createElement(tag));\n"
    "  Object.keys(attrs).forEach(k => e.setAttribute(k, attrs[k])); if (text) e.textContent = text; return e; };\n"
    "const chip = mk('span', {'data-no-i18n': '', title: ES[%s], 'data-i18n-title': %s}, 'prod');\n"
    "const code = mk('code', {title: ES[%s], 'data-i18n-title': %s}, '1.2.3.4:27015');\n"
    "const pre = mk('pre', {'data-i18n-text': %s}, ES[%s]);\n"
    "const logPre = mk('pre', {}, 'sshd: Accepted publickey');\n"
    "const opt = mk('option', {'data-i18n-text': '{n} days', 'data-i18n-vars': '{\"n\":3}'}, '3 días');\n"
    "const read = () => [chip.getAttribute('title'), code.getAttribute('title'), pre.textContent, logPre.textContent,"
    " chip.textContent, opt.textContent];\n"
    "window.setLang('fr', FR); const fr = read();\n"
    "window.setLang('en', {}); const en = read();\n"
    "console.log(JSON.stringify({fr, en}));\n"
) % (_json81.dumps({k: _ES81[k] for k in _SKEYS81}), _json81.dumps({k: _FR81[k] for k in _SKEYS81}),
     _json81.dumps(_read81("static", "js", "i18n.js")),
     _json81.dumps(_SKEYS81[0]), _json81.dumps(_SKEYS81[0]), _json81.dumps(_SKEYS81[1]), _json81.dumps(_SKEYS81[1]),
     _json81.dumps(_SKEYS81[2]), _json81.dumps(_SKEYS81[2]))
_live81 = _node81("i18n.js: a live switch and data-i18n-title / data-i18n-text", _live_prog81)
if _live81 is not None:
    check("i18n.js: a live switch re-renders a tooltip on a guarded chip or a <code>, a <pre>'s placeholder "
          "and a filled option label that t()/tf() rendered (they stayed in the old language); a log and a "
          "name are untouched",
          _live81 == {"fr": [_FR81[_SKEYS81[0]], _FR81[_SKEYS81[1]], _FR81[_SKEYS81[2]],
                             "sshd: Accepted publickey", "prod", _FR81["{n} days"].replace("{n}", "3")],
                      "en": list(_SKEYS81[:3]) + ["sshd: Accepted publickey", "prod", "3 days"]}, repr(_live81))
# Every key such an attribute names is one the catalogs hold (it is looked up as it is written).
_named81 = set()
for _dir81, _ext81 in (("templates", ".html"), (os.path.join("static", "js"), ".js")):
    for _fn81 in sorted(os.listdir(os.path.join(_root, _dir81))):
        if _fn81.endswith(_ext81):
            _src81 = _read81(_dir81, _fn81)
            _named81 |= {(_html81.unescape(m.group(2)), _fn81) for m in _re81.finditer(
                r"""data-i18n-(?:title|text)(?:=|',\s*)(["'])((?:(?!\1).)+)\1""", _src81)}
_unknown81 = sorted((k, f) for k, f in _named81 if k not in _ES81 or k not in _FR81)
check("i18n gate: every data-i18n-title / data-i18n-text names an es and fr catalog key (the five "
      "sites are read)", len(_named81) >= 5 and not _unknown81, repr((_unknown81, sorted(_named81))))

check("part81: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP81_START, repr(_P9_TRIPPED[_TRIP81_START:][:6]))
