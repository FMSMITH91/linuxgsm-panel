"""Part 78 of the unit suite: the ninth review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* a host that cannot be reached is said to be unreachable, in the viewer's language (close port
  22's dialog read a `message` the answer did not have). The firewall writes, which have no handler
  of their own, are held in the smoke suite: the app-wide error handler is create_app's.
* the page translator looks past ✅/❌ as it does ✓/✗, and text a script wrote ALREADY translated
  follows a live language switch (it was stored as the node's English, so it stayed in the old
  language); the five sites the review named write English, and a key whose translation another
  key shares is never written translated into the page.
* a file upload's "could the host be checked first" is the batch's own, not the last batch's.
* the server page's Connect row brackets an IPv6 host; the group form says when it has no server.
* the i18n gates read a sink inside a lambda in every walk, not only shown_literals_py.
* install.sh's fallback address on an IPv6-only host with a private IPv4 (docker0) is the IPv6 one.
* the panel host's own page never paints its header "Unreachable" from a failed local read.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node, and install.sh's function in bash, on this
part's own fixtures.
"""
import importlib.util as _ilu78
import json as _json78
import os
import re as _re78
import shutil as _shutil78
import subprocess as _sp78  # nosec B404 - runs bash on install.sh's own function
import tempfile as _tf78

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_host_row,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_set_host)
from unit.part47 import _cut47, _node47
from unit.part72 import _DOM72
from panel.db.models import User as _U78, db as _db78
from panel.routes import close_port22 as _cp78, server_detail as _sd78

_JS78 = os.path.join(_root, "static", "js")
_XHR78 = {"X-Requested-With": "XMLHttpRequest"}


def _read78(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node78(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or78(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _lang78(lang):
    with _p9.app_context():
        _db78.session.get(_U78, P9_ADMIN).language = lang
        _db78.session.commit()


_spec78 = _ilu78.spec_from_file_location("i18n_scan_p78", os.path.join(_root, "tools", "i18n_scan.py"))
_scan78 = _ilu78.module_from_spec(_spec78)
_spec78.loader.exec_module(_scan78)
_ES78, _FR78 = _scan78.load_catalog("es"), _scan78.load_catalog("fr")
_TRIP78_START = len(_P9_TRIPPED)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A host that cannot be reached is said to be unreachable, in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
# http._unreachable answered {"error": "Host unreachable"} — English, and no `message`, which is the
# field close port 22's dialog writes: an es viewer whose host was down saw an empty red line.
_host_was78 = _p9_host_row(P9_HOST)
try:
    _p9_arm(who="part78")
    _lang78("es")

    def _down78(*_a, **_k):
        raise ConnectionError("p78: the host is switched off")

    _p9_patch(_cp78, "_tailnet_ssh_state", _down78)
    _r78 = _p9_client(P9_ADMIN).post("/api/remote/%d/close-port-22" % P9_HOST, headers=_XHR78)
    _cp_body78 = _p9_json(_r78)
finally:
    _lang78("en")
    _p9_restore_all()
check("unreachable: close port 22 on a host that is down answers \"Host unreachable\" as its message, "
      "in the viewer's language (the dialog read a message the answer did not have)",
      _r78.status_code == 200 and _cp_body78.get("unreachable") is True
      and _cp_body78.get("message") == _ES78.get("Host unreachable") != "Host unreachable"
      and _cp_body78.get("error") == _cp_body78.get("message"), repr((_r78.status_code, _cp_body78)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The page translator: ✅/❌ marks, and text a script wrote already translated
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The real i18n.js over part72's small DOM, in node. A node first seen holding a translation
# ("(conectado)", written by t()) recorded it as its English: no key, so setLang('en') had nothing
# to look up or go back to.
_KEYS78 = ("Port required", "Host unreachable", "(connected)", "Customise", "all healthy",
           "New file name", "Saved")
_SHARED78 = ("Done", "Complete")         # one French translation for two keys
_ES_SUB78 = {k: _ES78[k] for k in _KEYS78 if k in _ES78}
_FR_SUB78 = {k: _FR78[k] for k in _KEYS78 + _SHARED78 if k in _FR78}
_prog78 = _DOM72 + (
    "const ES = %s, FR = %s;\n"
    "window.LANG = 'es'; window.I18N = ES;\n"
    "require('vm').runInThisContext(%s);\n"
    "const b = document.body,\n"
    "  put = s => b.appendChild(document.createElement('div')).appendChild(document.createTextNode(s));\n"
    # What a page writes: English after a mark, and translations that t() handed back.
    "put('\\u274c Port required'); put('\\u2705 Saved'); put('\\u274c Not a message anyone wrote.');\n"
    "put(t('(connected)')); put(' ' + t('Customise') + ' '); put('\\u2717 ' + t('Host unreachable'));\n"
    "const el = b.appendChild(document.createElement('input')); el.setAttribute('aria-label', t('New file name'));\n"
    "window.setLang('es', ES);\n"
    "const texts = () => b.childNodes.filter(d => d.tagName === 'DIV').map(d => d.textContent);\n"
    "const es = texts(), esLabel = el.getAttribute('aria-label');\n"
    "window.setLang('en', {});\n"
    "const en = texts(), enLabel = el.getAttribute('aria-label');\n"
    "window.setLang('fr', FR);\n"
    "const fr = texts(), frLabel = el.getAttribute('aria-label');\n"
    # A translation two keys share cannot say which was meant: kept as it was, never guessed.
    "b.textContent = ''; put(FR['Done']); window.setLang('fr', FR); window.setLang('en', {});\n"
    "const shared = texts()[0];\n"
    "console.log(JSON.stringify({es, en, fr, esLabel, enLabel, frLabel, shared}));\n"
) % (_json78.dumps(_ES_SUB78), _json78.dumps(_FR_SUB78), _json78.dumps(_read78("static", "js", "i18n.js")))
_out78 = _node78("i18n.js: ✅/❌ marks and text written already translated", _prog78)
if _out78 is not None:
    check("i18n.js: a message behind ❌ or ✅ is translated with its mark kept, as one behind ✓/✗ is "
          "(\"❌ Port required\" stayed English for every es/fr viewer); an unknown one stays",
          (_out78.get("es") or [None] * 3)[:3] == ["❌ " + _ES78["Port required"], "✅ " + _ES78["Saved"],
                                                   "❌ Not a message anyone wrote."]
          and (_out78.get("en") or [None] * 3)[:3] == ["❌ Port required", "✅ Saved",
                                                       "❌ Not a message anyone wrote."], repr(_out78))
    check("i18n.js: text a script wrote already translated (t() into textContent or an aria-label) "
          "follows a live switch es -> en -> fr, blanks and a mark kept — it stayed Spanish",
          (_out78.get("en") or [None] * 6)[3:] == ["(connected)", " Customise ", "✗ Host unreachable"]
          and (_out78.get("fr") or [None] * 6)[3:] == [_FR78["(connected)"], " %s " % _FR78["Customise"],
                                                       "✗ " + _FR78["Host unreachable"]]
          and (_out78.get("esLabel"), _out78.get("enLabel"), _out78.get("frLabel"))
          == (_ES78["New file name"], "New file name", _FR78["New file name"]), repr(_out78))
    check("i18n.js: ...and a translation two keys share (fr \"Done\" and \"Complete\") is left as it was, "
          "not guessed back to one of them",
          _FR78["Done"] == _FR78["Complete"] and _out78.get("shared") == _FR78["Done"], repr(_out78))

# The five persistent nodes the review named write English, so they never depend on the lookup
# back (and "Done" could not use it at all).
_sites78 = {
    "server_detail.js ws status": ("server_detail.js", ["wsStatus.textContent = '(connected)';",
                                                        "wsStatus.textContent = '(disconnected)';"]),
    "server_detail.js gap notice": ("server_detail.js", ["? 'Some output from while the connection was down",
                                                         ": 'Some output from while this tab was in the"]),
    "panel.js Customise/Done": ("panel.js", ["label.textContent = on ? 'Done' : 'Customise';"]),
    "remote_manage_host.js all healthy": ("remote_manage_host.js", ["s==='ok' ? 'all healthy' :"]),
    "server_files.js create field": ("server_files.js", [
        "input.setAttribute('aria-label', kind==='folder' ? 'New folder name' : 'New file name');",
        "ok.textContent='Create';", "no.textContent='Cancel';"]),
}
_missing78 = [k for k, (f, needles) in _sites78.items() if not all(n in _read78("static", "js", f) for n in needles)]
check("pages: the socket status, the console's gap notice, Customise/Done, the diagnostics badge and "
      "the New file/New folder field write English for the translator (not t()'s translation)",
      not _missing78, repr(_missing78))

# A GATE for the class: a key whose es or fr translation another key shares cannot be looked back
# up, so a script must not write it translated into the page. Every literal t('…') in a page script
# is read; the ones left are transient (a palette label built with a name, a busy label for the
# length of one request, a confirm dialog's button) and named here, so a new one has to be decided.
_TRANSIENT78 = {"Reboot", "Removing…", "Turn it off"}
_amb78 = {}
for _lang_cat78 in (_ES78, _FR78):
    _seen78 = {}
    for _k78, _v78 in _lang_cat78.items():
        if isinstance(_v78, str):
            _n78 = " ".join(_v78.split())
            if _n78 and _n78 != _k78 and "{" not in _n78:
                _seen78.setdefault(_n78, set()).add(_k78)
    for _ks78 in _seen78.values():
        if len(_ks78) > 1:
            _amb78.update((k, sorted(_ks78)) for k in _ks78)
_tkeys78 = {}
for _fn78 in sorted(os.listdir(_JS78)):
    if _fn78.endswith(".js"):
        for _m78 in _re78.finditer(r"\bt\(\s*'((?:[^'\\]|\\.)*)'", _read78("static", "js", _fn78)):
            _tkeys78.setdefault(_m78.group(1).replace("\\'", "'"), _fn78)
_frozen78 = sorted((k, f, _amb78[k]) for k, f in _tkeys78.items() if k in _amb78 and k not in _TRANSIENT78)
check("i18n gate: no page script writes t('…') of a key whose translation another key shares (the "
      "translator cannot look it back up after a live switch) — write the English instead",
      len(_tkeys78) > 50 and not _frozen78, repr(_frozen78))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. An upload's "the host could not be checked first" is its own batch's
# ════════════════════════════════════════════════════════════════════════════════════════════════
# One page-wide _uploadChecked: a second batch started before the first finished overwrote it, and
# the first batch's clash summary then spoke of the other's pre-flight.
_SF78 = _read78("static", "js", "server_files.js")
_du78 = _cut_or78(_SF78, "function _doUpload(")
_uf78 = _cut_or78(_SF78, "function uploadFiles(")
check("file browser: each upload batch carries its own pre-flight result into its summary (one "
      "page-wide flag was the last batch's)",
      "_uploadChecked" not in _SF78 and _du78.startswith("function _doUpload(entries, ovw, base, checked)")
      and "tf(checked ? " in _du78 and "var checked=true;" in _uf78
      and _uf78.count(", base, checked)") == 2, _du78[:120])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The server page's Connect row, and the group form's empty server list
# ════════════════════════════════════════════════════════════════════════════════════════════════
# An IPv6-only host has no IPv4 public address to resolve, so the page shows remote.host, and the
# row read "2001:db8::5:27015" — and click-to-copy put that on the clipboard.
_page78 = ""
try:
    _p9_arm(who="part78")
    _p9_patch(_sd78, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd78, "_host_timezone_cached", lambda *a, **k: "")   # its miss starts a host read
    _p9_set_host(P9_HOST, host="2001:db8::5", public_ip=None)
    _page78 = _p9_client(P9_ADMIN).get("/server/%d" % P9_GS).get_data(as_text=True)
finally:
    _p9_restore_all()
    _p9_set_host(P9_HOST, host=_host_was78.host, public_ip=_host_was78.public_ip)
_conn78 = _re78.search(r'<code class="text-info copy-addr"[^>]*data-copy="([^"]*)"[^>]*>([^<]*)</code>', _page78)
check("server page: an IPv6 host's Connect row (and what click-to-copy copies) is [2001:db8::5]:port",
      bool(_conn78) and _conn78.groups() == ("[2001:db8::5]:27015", "[2001:db8::5]:27015"),
      repr(_conn78.groups() if _conn78 else _page78[:300]))

# The empty state was the for-loop's else over HOSTS, which the panel's own machine always fills:
# with no game server the box was blank.
# The macro on its own (importing the page would render base.html around it).
_MG78 = _read78("templates", "manage_groups.html")
_mi78 = _MG78.find("{% macro game_server_access(")
_MACRO78 = _MG78[_mi78:_MG78.find("{% endmacro %}", _mi78) + len("{% endmacro %}")] if _mi78 >= 0 else ""
with _p9.test_request_context("/"):
    _mac78 = _p9.jinja_env.from_string(
        _MACRO78 + '{{ game_server_access(hosts, servers, [], "x", filtered=filtered) }}')
    _hosts78 = [type("H", (), {"id": 1, "display_name": "panel host"})()]
    _srv78 = [type("S", (), {"id": 7, "remote_id": 1, "name": "cs", "game_type": "csgo"})()]
    _empty78 = {k: _mac78.render(hosts=_hosts78, servers=s, filtered=f)
                for k, s, f in (("sa none", [], False), ("delegated none", [], True), ("some", _srv78, False))}
_said78 = {k: _re78.findall(r"No game servers[^<]*", v) for k, v in _empty78.items()}
check("group form: with hosts but no game server the list says so (\"No game servers yet.\" to a "
      "superadmin, \"…you can grant.\" to a delegated admin) — it was blank; a list with one says nothing",
      _said78 == {"sa none": ["No game servers yet."], "delegated none": ["No game servers you can grant."],
                  "some": []} and 'value="7"' in _empty78["some"], repr(_said78))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The i18n gates read a sink inside a lambda in every walk
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #427 taught shown_literals_py to enter a lambda; spliced_py (and its tr() half), route_answer_keys
# and the job step walk still stopped there, so a message BUILT in a lambda passed every gate.
_td78 = os.path.realpath(_tf78.mkdtemp(prefix="lgsm-unit-p78-"))
try:
    os.makedirs(os.path.join(_td78, "panel", "routes"))
    with open(os.path.join(_td78, "app.py"), "w") as _fh78:
        _fh78.write("")
    with open(os.path.join(_td78, "panel", "routes", "r.py"), "w") as _fh78:
        _fh78.write(
            "def register(app):\n"
            "    app.register_error_handler(500, lambda e: (jsonify({'error': f'Server error: {e}'}), 500))\n"
            "    app.register_error_handler(404, lambda e: jsonify({'message': 'Said from a lambda.'}))\n"
            "    app.register_error_handler(405, lambda e: i18n.tr(f'Built for tr: {e}'))\n"
            "    start(on_progress=lambda n: _p(5, f'Step {n} built'))\n"
            "def plain(e):\n"
            "    return jsonify({'error': f'Plain error: {e}'})\n")
    _spl78 = sorted((f, line) for f, line, _w in _scan78.spliced_py(root=_td78))
    _rak78 = _scan78.route_answer_keys(root=_td78)
    _steps78 = _scan78.step_names_built(root=_td78)
finally:
    _shutil78.rmtree(_td78, ignore_errors=True)
_rf78 = os.path.join("panel", "routes", "r.py")
check("i18n gate: spliced_py reports a message built in a lambda's sink, and a tr() fed a built string "
      "in a lambda, as it does in a function",
      _spl78 == [(_rf78, 2), (_rf78, 4), (_rf78, 7)], repr(_spl78))
check("i18n gate: route_answer_keys reads a lambda's answer (its sentence is asked of es/fr)",
      "Said from a lambda." in _rak78, repr(sorted(_rak78)))
check("i18n gate: the job step walk reports a step text built inside a lambda",
      _steps78 == [(_rf78, 5)], repr(_steps78))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. install.sh: an IPv6-only host with a private IPv4 hands out its IPv6 address
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Once both IPv4 lookups have failed, a private IPv4 (docker0, a LAN, the tailnet) is not the way
# in: the fresh install printed http://172.17.0.1:5000/setup?token=… as the public address.
_INS78 = _read78("install.sh")
_i78 = _INS78.find("\nhost_addr_fallback() {")
_FALLBACK78 = _INS78[_i78:_INS78.find("\n}\n", _i78)] + "\n}\n" if _i78 >= 0 else "exit 3\n"


def _fallback78(addrs):
    script = ("set -euo pipefail\naddrs=\"$1\"\nhostname() { echo \"${addrs}\"; }\n" + _FALLBACK78
              + "host_addr_fallback\n")
    r = _sp78.run(["bash", "-c", script, "p78", addrs],  # nosec B603 B607 - bash, fixed script
                  capture_output=True, text=True, timeout=60)
    return (r.stdout + r.stderr).strip()


_fb78 = {a: _fallback78(a) for a in (
    "2001:db8::5 172.17.0.1", "10.0.0.2 100.101.1.2 2001:db8::9", "fe80::1 192.168.1.5 2001:db8::5",
    "172.17.0.1 203.0.113.9", "203.0.113.9 2001:db8::5", "192.168.1.5 10.0.0.3", "172.32.0.1 2001:db8::5",
    "100.128.0.1 2001:db8::5", "fe80::1 192.168.1.5")}
check("install.sh: with no lookup answering, a host whose only IPv4 is private (docker0, a LAN, the "
      "tailnet) hands out its IPv6 address (bracketed by the caller), not the private one",
      [_fb78[a] for a in ("2001:db8::5 172.17.0.1", "10.0.0.2 100.101.1.2 2001:db8::9",
                          "fe80::1 192.168.1.5 2001:db8::5")] == ["2001:db8::5", "2001:db8::9", "2001:db8::5"],
      repr(_fb78))
check("install.sh: ...a public IPv4 still wins over IPv6, 172.32/100.128 are public, and a host with "
      "no global IPv6 still gets its first IPv4 one, over a link-local IPv6 (controls)",
      [_fb78[a] for a in ("172.17.0.1 203.0.113.9", "203.0.113.9 2001:db8::5", "192.168.1.5 10.0.0.3",
                          "172.32.0.1 2001:db8::5", "100.128.0.1 2001:db8::5", "fe80::1 192.168.1.5")]
      == ["203.0.113.9", "203.0.113.9", "192.168.1.5", "172.32.0.1", "100.128.0.1", "192.168.1.5"],
      repr(_fb78))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The panel host's own page never calls itself unreachable over SSH
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM78 = _read78("static", "js", "remote_manage.js")
_badge78 = {}
for _local78 in (True, False):
    _o78 = _node78("host page: the local header badge on a failed local read", (
        "const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"
        "global.window = global; global.MOUNT = ''; global.REMOTE_ID = 3; global.t = s => s;\n"
        "global.IS_LOCAL = %s;\n"
        "const badge = {className: 'badge bg-success', textContent: 'Reachable', attrs: {},\n"
        "  setAttribute(k, v){ this.attrs[k] = v; }};\n"
        "global.document = {getElementById: id => ({'remote-status': badge})[id] || null};\n"
        "global.fetch = () => Promise.resolve({json: () => Promise.resolve({error: 'x', unreachable: true})});\n"
        "function _livePaintCpu(){} function _livePaintMemory(){} function _livePaintDisk(){}\n"
        "%s\n%s\n"
        "(async () => { pollLive(); await settle(); console.log(JSON.stringify(badge.textContent)); })();\n")
        % ("true" if _local78 else "false", _cut_or78(_RM78, "function _r18cPaintHostBadge("),
           _cut_or78(_RM78, "function pollLive(")))
    _badge78[_local78] = _o78
if None not in _badge78.values():
    check("host page: on the panel host's own page a failed local read leaves the header badge (it said "
          "\"cannot reach this host over SSH\" of the machine serving the page); a remote's turns Unreachable",
          _badge78 == {True: "Reachable", False: "Unreachable"}, repr(_badge78))


check("part78: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP78_START, repr(_P9_TRIPPED[_TRIP78_START:][:6]))
