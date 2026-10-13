"""Part 72 of the unit suite: the seventh review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* an id past SQLite's range (a URL, a query string, a JSON body, a socket event) is "no such row",
  never the OverflowError its bind raised — and a hand-edited non-numeric panel port is not a 500.
* route answers reach es/fr viewers translated, and the gates that say so catch what they missed.
* pages: a message behind a ✓/✗ glyph is its own text node, and a sentence built by tfNodes follows
  a live language switch.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import json as _json72
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_so)
from unit.part47 import _cut47, _node47
from panel.db.models import RemoteServer as _RS72, User as _U72, db as _db72
from panel.security import auth as _auth72
from panel.routes import remote_security as _rs72, server_files as _sf72

_JS72 = os.path.join(_root, "static", "js")


def _read72(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node72(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _status72(call):
    """The response's status code, or the name of the exception the request raised."""
    try:
        return call().status_code
    except Exception as e:      # a 500 the test client re-raised: the finding itself
        return type(e).__name__


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An id past SQLite's range is no row, not a 500
# ════════════════════════════════════════════════════════════════════════════════════════════════
# int() and Werkzeug's int converter read any length of digits, and SQLite's driver raises
# OverflowError binding a number past 2**63-1 — so every lookup of such an id was a bare 500 with
# a traceback, and a superadmin's console join of one left the poller raising on every pass.
_HUGE72 = 10 ** 20
# part12's transport tripwire, armed at the top of each route block below (review 1012c: none was
# armed, so a route that gained a host call ran it for real with every check green); the part ends
# by checking nothing it drove reached one.
_TRIP72_START = len(_P9_TRIPPED)
try:
    _p9_arm(who="part72")
    _A72 = _p9_client(P9_ADMIN)
    check("row id: /api/free-port with a remote_id past SQLite's range is 'no suggestion'",
          _p9_json(_A72.get("/api/free-port?remote_id=%d&game=csgo&desired=27015" % _HUGE72))
          == {"port": None})
    # A route that looks its id up itself (db.session.get), not through get_game/get_remote.
    _tagdel72 = _status72(lambda: _A72.post("/api/tags/%d/delete" % _HUGE72))
    check("row id: an <int:…> route past SQLite's range is a 404 (the URL converter's bound)",
          _tagdel72 == 404, repr(_tagdel72))
    _bulk72 = _status72(lambda: _A72.post("/api/servers/bulk-action",
                                          json={"action": "restart", "server_ids": [_HUGE72]}))
    check("row id: a bulk action naming an id past SQLite's range is no 500", _bulk72 != 500
          and isinstance(_bulk72, int), repr(_bulk72))
    _tags72 = _status72(lambda: _A72.post("/api/server/%d/tags" % P9_GS, json={"tag_ids": [_HUGE72]}))
    check("row id: a tag set naming a tag id past SQLite's range is no 500", _tags72 == 200, repr(_tags72))
    _add72 = _status72(lambda: _A72.post("/servers/add", data={"remote_id": str(_HUGE72),
                                                               "game_type": "csgo",
                                                               "server_name": "csgoserver"}))
    check("row id: an install naming a host id past SQLite's range is get_remote's 404", _add72 == 404,
          repr(_add72))
    with _p9.app_context():
        _viewer72 = _db72.session.get(_U72, P9_VIEWER)
        try:
            _cas72 = _auth72.can_access_server(_viewer72, _HUGE72)
        except Exception as e:
            _cas72 = type(e).__name__
    check("row id: can_access_server answers False for an id past SQLite's range", _cas72 is False,
          repr(_cas72))

    # The console socket, as a superadmin (who passes can_access_server without a lookup).
    _sio72 = _p9.socketio.test_client(_p9, flask_test_client=_p9_client(P9_ADMIN))
    _joinerr72 = None
    try:
        _sio72.emit("join_console", {"server_id": _HUGE72})
    except Exception as e:      # the check reads what the join left behind; the raise is its detail
        _joinerr72 = type(e).__name__
    with _sf72._viewers_lock:
        _joined72 = _HUGE72 in _sf72._console_viewers
        _sf72._console_viewers.pop(_HUGE72, None)
    try:
        _sio72.emit("term_open", {"remote_id": _HUGE72, "cols": 80, "rows": 24})
        _term72 = [(m.get("args") or [{}])[0] for m in _sio72.get_received()
                   if m.get("name") == "term_error"]
    except Exception as e:      # the handler's OverflowError, re-raised by the test client
        _term72 = [type(e).__name__]
    _sio72.disconnect()
    check("row id: a console join naming a server id past SQLite's range is not watched (the poller "
          "would look it up every pass)", not _joined72, repr(_joinerr72))
    check("row id: a terminal naming a host id past SQLite's range is 'No host was named.'",
          [p.get("message") if isinstance(p, dict) else p for p in _term72] == ["No host was named."], repr(_term72))

    # A hand-edited `port` in config.json that is not a number: Change Port read it with int().
    _p9_patch(_rs72, "load_config", lambda: {"port": "5000x"})
    # part53's change-port stand-ins: a refusal that came too late would otherwise reach the host.
    _p9_patch(_p9_so, "host_has_ip", lambda ip: True)
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "restart_panel", lambda: (True, "scheduled"))
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
    _p9_patch(_rs72, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_rs72, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
    _cp72 = _status72(lambda: _A72.post("/api/panel/change-port", json={"port": 1}))
    check("change port: a hand-edited non-numeric panel port is a refusal, not a 500", _cp72 == 400,
          repr(_cp72))
finally:
    _p9_restore_all()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The catalog gates: a call written into a sink, a wrapper, a local assigned a literal
# ════════════════════════════════════════════════════════════════════════════════════════════════
# route_answer_keys followed a call only through a local bound from it, and read sinks without the
# wrapper table; no gate resolved a local assigned a literal. "Internal server error" (76 routes,
# `"message": _log_and_generic(…)`), the console-send refusals and the full backup's three answers
# had no es/fr entry, and every gate passed.
import importlib.util as _ilu72  # noqa: E402
import shutil as _shutil72  # noqa: E402
import tempfile as _tf72  # noqa: E402

_spec72 = _ilu72.spec_from_file_location("i18n_scan_p72", os.path.join(_root, "tools", "i18n_scan.py"))
_scan72 = _ilu72.module_from_spec(_spec72)
_spec72.loader.exec_module(_scan72)

_td72 = os.path.realpath(_tf72.mkdtemp(prefix="lgsm-unit-p72-"))
try:
    for _d72 in (("panel", "routes"), ("translations", "es")):
        os.makedirs(os.path.join(_td72, *_d72))
    with open(os.path.join(_td72, "app.py"), "w") as _fh72:
        _fh72.write("")
    with open(os.path.join(_td72, "translations", "es", "x.json"), "w") as _fh72:
        _fh72.write('{"Already here.": "Ya está."}')
    with open(os.path.join(_td72, "panel", "routes", "r.py"), "w") as _fh72:
        _fh72.write(
            "def generic(ctx):\n"
            "    return 'Something went wrong here'\n"
            "def pair(h):\n"
            "    return False, 'Item one of a pair'\n"
            "def _refuse(message):\n"
            "    return jsonify({'success': False, 'message': message})\n"
            "def a():\n"
            "    return jsonify({'message': generic('x')})\n"                 # a call into a sink
            "def b(h):\n"
            "    return jsonify({'message': pair(h)[1]})\n"                   # f(…)[i]
            "def c():\n"
            "    return _refuse('Handed to a wrapper')\n"                     # a wrapper's parameter
            "def d(mode):\n"
            "    if mode:\n"
            "        msg = 'Held in a local'\n"
            "    else:\n"
            "        msg = 'Already here.'\n"
            "    return jsonify({'message': msg})\n")                         # a local assigned a literal
    _gaps72 = sorted(k for k, _w in _scan72.route_answer_gaps("es", root=_td72,
                                                            translation_dir=os.path.join(_td72, "translations")))
    _shown72 = sorted(_scan72.shown_literals_py(root=_td72))
finally:
    _shutil72.rmtree(_td72, ignore_errors=True)
check("i18n gate: a route answer that is a call written into the sink (helper(), helper()[1]), a "
      "wrapper's parameter, or a local assigned a literal is a key (a keyed one is not reported)",
      _gaps72 == ["Handed to a wrapper", "Held in a local", "Item one of a pair", "Something went wrong here"],
      repr(_gaps72))
check("i18n gate: shown_literals_py reads a message held in a local assigned a literal",
      "Held in a local" in _shown72, repr(_shown72))
_rg72 = [(_L72, k) for _L72 in ("es", "fr") for k, _w in _scan72.route_answer_gaps(_L72)]
_lg72 = [(_L72, k) for _L72 in ("es", "fr") for k, _w in _scan72.literal_gaps_py(_L72)]
_lg72 += [(_L72, k) for _L72 in ("es", "fr") for k, _w in _scan72.tr_gaps_py(_L72)]
check("i18n gate: with those followed, every route answer, shown literal and tr() sentence has an es "
      "and fr entry (\"Internal server error\", the console-send refusals and the full backup's answers "
      "had none)", not _rg72 and not _lg72, repr((_rg72 + _lg72)[:6]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Route answers reach a Spanish viewer in Spanish
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The pages print these behind "✓ "/"✗ ", one text node no key matched, so the route translates.
from flask_login import login_user as _login72  # noqa: E402
from types import SimpleNamespace as _NS72  # noqa: E402
from panel.core import i18n as _i18n72, http as _http72  # noqa: E402
from panel.core.panel_state import _full_backup_lock as _fbl72  # noqa: E402
from panel.routes import (discover as _disc72, panel_backup as _pb72, server_detail as _sd72,  # noqa: E402
                          ubuntu_pro as _up72)


def _lang72(lang):
    with _p9.app_context():
        _db72.session.get(_U72, P9_ADMIN).language = lang
        _db72.session.commit()


_ES72 = _scan72.load_catalog("es")
with _p9.app_context():
    _LANG72_WAS = _db72.session.get(_U72, P9_ADMIN).language
try:
    _p9_arm(who="part72")
    _lang72("es")
    _A72 = _p9_client(P9_ADMIN)
    # The full backup: already running (the lock held), and started (the thread stood in for).
    _fbl72.acquire()
    try:
        _busy72 = _p9_json(_A72.post("/api/panel/backup/full", json={"mode": ""})).get("message")
    finally:
        _fbl72.release()
    _p9_patch(_pb72, "threading", _NS72(Thread=lambda target=None, daemon=None: _NS72(start=lambda: None)))
    try:
        _start72 = _p9_json(_A72.post("/api/panel/backup/full", json={"mode": "wait"})).get("message")
    finally:
        if _fbl72.locked():
            _fbl72.release()        # the stand-in thread never ran the worker that releases it
    check("es: a full backup's answers are Spanish (already running; started, waiting for empty)",
          _busy72 == _ES72["A full backup is already running."]
          and _start72 == _ES72["Backing up empty servers now; any with players will back up automatically "
                                "once they're empty."], repr((_busy72, _start72)))
    from unit.part12 import P9_HOST as _H72  # noqa: E402
    _p9_patch(_up72, "pro_attach", lambda remote, token: (True, "Attached to Ubuntu Pro."))
    _p9_patch(_up72, "pro_detach", lambda remote: (True, "Detached from Ubuntu Pro."))
    _p9_patch(_up72, "_pro_status_cached", lambda remote, force=False: None)
    _att72 = _p9_json(_A72.post("/api/remote/%d/pro-attach" % _H72, json=dict(token=os.urandom(4).hex()))).get("message")
    _det72 = _p9_json(_A72.post("/api/remote/%d/pro-detach" % _H72)).get("message")
    check("es: Ubuntu Pro attach and detach answer in Spanish",
          (_att72, _det72) == (_ES72["Attached to Ubuntu Pro."], _ES72["Detached from Ubuntu Pro."]),
          repr((_att72, _det72)))
    _p9_patch(_pb72.bk, "delete_backup", lambda name: (False, "No such backup."))
    _del72 = _p9_json(_A72.post("/api/panel/backup/delete", json={"name": "x"})).get("message")
    check("es: a panel backup delete answers in Spanish", _del72 == _ES72["No such backup."], repr(_del72))

    # Helpers that word a route's answer, in a Spanish viewer's request.
    with _p9.app_context(), _p9.test_request_context("/"):
        _login72(_db72.session.get(_U72, P9_ADMIN))
        _gen72 = _http72._log_and_generic("p72: a stand-in failure")
        _cs72 = (_sd72._console_send_failure(3, ""), _sd72._console_send_failure(1, ""))
        _host72 = _db72.session.get(_RS72, _H72)
        _out72 = _disc72._discover_import_outcome(
            _host72, [], [], [],
            [{"user": "acct", "reason": _i18n72.Sentence(
                "it is not a game account the panel may run as: {detail}", detail="in group sudo")}],
            [{"user": "mc", "reason": _disc72._import_port_problem(None, False, set())},
             {"user": "rust", "reason": _disc72._import_port_problem(22, True, {22})}])
    check("es: \"Internal server error\" is Spanish", _gen72 == _ES72.get("Internal server error"), repr(_gen72))
    check("es: the console-send refusals are Spanish",
          _cs72 == (_ES72.get("That server isn't running, so there's no console session to send to."),
                    _ES72.get("The panel could not run that on the host, and it gave no reason.")), repr(_cs72))
    _reasons72 = [r["reason"] for r in _out72["refused"] + _out72["unread"]]
    check("es: an import's reasons are Spanish, the host's detail kept as written, and so is the frame",
          _reasons72 == [
              "no es una cuenta de juego con la que el panel pueda ejecutarse: in group sudo",
              _ES72["its game port is not set in its LinuxGSM config, and LinuxGSM's details did not answer, "
                    "so its port could not be read — try the import again"],
              "no se pudo usar su puerto: el puerto 22 es el SSH de este host o el propio panel; corrígelo en "
              + "la configuración del juego y luego impórtalo"]
          and _reasons72[0] in _out72.get("message", "") and "Not imported" not in _out72.get("message", ""),
          repr((_reasons72, _out72.get("message"))))
finally:
    _lang72(_LANG72_WAS)
    _p9_restore_all()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The page translator: a ✓/✗ in front of a message, and a tfNodes sentence on a live switch
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The real i18n.js over a small DOM (elements with children, text nodes, attributes), in node.
_DOM72 = r"""
class T72 { constructor(v){ this.nodeType = 3; this.nodeValue = v; this.parentNode = null; }
  get nextSibling(){ const s = this.parentNode && this.parentNode.childNodes; return s ? s[s.indexOf(this) + 1] || null : null; }
  get textContent(){ return this.nodeValue; } }
class E72 { constructor(tag){ this.nodeType = 1; this.tagName = tag.toUpperCase(); this.childNodes = [];
    this.attrs = {}; this.parentNode = null; }
  get firstChild(){ return this.childNodes[0] || null; }
  get nextSibling(){ const s = this.parentNode && this.parentNode.childNodes; return s ? s[s.indexOf(this) + 1] || null : null; }
  appendChild(c){ if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.childNodes.push(c); return c; }
  removeChild(c){ const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; return c; }
  set textContent(v){ this.childNodes.slice().forEach(c => this.removeChild(c)); if (v) this.appendChild(new T72(String(v))); }
  get textContent(){ return this.childNodes.map(c => c.textContent).join(''); }
  hasAttribute(k){ return k in this.attrs; } getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v){ this.attrs[k] = String(v); } }
global.window = global;
global.document = { body: new E72('body'), documentElement: {}, readyState: 'complete',
  createElement: t => new E72(t), createTextNode: v => new T72(v), addEventListener(){} };
global.MutationObserver = class { observe(){} };
"""
_I18N72 = _read72(_JS72, "i18n.js")
_TPL72 = "{host} needs to reboot to finish applying system updates."
_out72 = _node72("i18n.js: a status mark and a live language switch", _DOM72 + (
    "const ES = %s, FR = %s;\n"
    "window.LANG = 'es'; window.I18N = ES;\n"
    "const b = document.body, add = s => b.appendChild(document.createElement('div')).appendChild(document.createTextNode(s));\n"
    "add('\\u2713 A full backup is already running.'); add('\\u2717 Not a message anyone wrote.'); add('\\u2713 Saved');\n"
    "require('vm').runInThisContext(%s);\n"
    "const marks = b.childNodes.map(d => d.textContent);\n"
    "window.setLang('en', {});\n"
    "const marksEn = b.childNodes.map(d => d.textContent);\n"
    "window.setLang('es', ES);\n"
    "b.textContent = '';\n"
    "const banner = b.appendChild(document.createElement('div'));\n"
    "const host = document.createElement('strong'); host.textContent = 'the panel host';\n"
    "tfNodes(%s, {host: host}).forEach(n => banner.appendChild(n));\n"
    "window.setLang('es', ES);\n"
    "const es = banner.textContent;\n"
    "window.setLang('en', {});\n"
    "const en = banner.textContent;\n"
    "window.setLang('fr', FR);\n"
    "const fr = banner.textContent;\n"
    "console.log(JSON.stringify({marks, marksEn, es, en, fr}));\n"
) % (_json72.dumps({k: _ES72[k] for k in ("A full backup is already running.", "Saved", "the panel host", _TPL72)}
                   | {"✓ Saved": "✓ Guardado (whole key)"}),
     _json72.dumps({k: _scan72.load_catalog("fr")[k] for k in ("the panel host", _TPL72)}),
     _json72.dumps(_I18N72), _json72.dumps(_TPL72)))
if _out72 is not None:
    check("i18n.js: a message behind a ✓/✗ is translated with its mark kept; a whole key wins, an "
          "unknown message stays, and a switch to English says the English again",
          _out72.get("marks") == ["✓ " + _ES72["A full backup is already running."],
                                  "✗ Not a message anyone wrote.", "✓ Guardado (whole key)"]
          and _out72.get("marksEn") == ["✓ A full backup is already running.",
                                        "✗ Not a message anyone wrote.", "✓ Saved"], repr(_out72))
    _FR72 = _scan72.load_catalog("fr")
    check("i18n.js: a tfNodes sentence follows a live language switch (es -> en -> fr), its value element "
          "translated with it — it stayed in the language it was built in",
          _out72.get("es") == _ES72[_TPL72].replace("{host}", _ES72["the panel host"])
          and _out72.get("en") == _TPL72.replace("{host}", "the panel host")
          and _out72.get("fr") == _FR72[_TPL72].replace("{host}", _FR72["the panel host"]), repr(_out72))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Phone layouts (measured at 375px in a browser; held here by their rules)
# ════════════════════════════════════════════════════════════════════════════════════════════════
import re as _re72  # noqa: E402

_CSS72 = _re72.sub(r"/\*.*?\*/", "", _read72(_root, "static", "css", "panel.css"), flags=_re72.S)
_DASH72 = _read72(_root, "templates", "dashboard.html")
from unit.part69 import _r17d_media_bodies  # noqa: E402

_PHONE72 = "@media (width <= 767.98px)"


def _r18d_name_floor72(css):
    """Is the Server column's 120px floor set inside the phone block (where it was measured)?"""
    return any(_re72.search(r"\.dash-srv-table\s+\.dash-col-name\s*\{[^}]*min-width:\s*120px", _b)
               for _b in _r17d_media_bodies(css, _PHONE72))


def _r18d_unscoped_wraps72(css):
    """The selectors of every rule, at any depth, that sets flex-wrap on a bare `.page-title`.

    Only the first `.page-title {` rule was read (review 1012c): a `flex-wrap: wrap` put back into
    the phone block's own rule wrapped every heading at exactly the 375px width it was measured at.
    A selector list naming .page-title counts too; the `:has(> [data-no-i18n])` rule is the scoped one.
    """
    return [_sel.strip() for _sel, _body in _re72.findall(r"([^{}]+)\{([^{}]*)\}", css)
            if "flex-wrap" in _body
            and any(_re72.search(r"(?<![\w-])\.page-title$", _one.strip()) for _one in _sel.split(","))]


# A viewer with no start/stop/restart/update has no checkbox column: :nth-child(2) was Type.
check("375px: the dashboard's server-name floor is on the Server column by class, not by position "
      "(no checkbox column for a view-only viewer moved it onto the hidden Type column), in the phone block",
      _re72.search(r"dash-srv-table[^{]*:nth-child", _CSS72) is None
      and _r18d_name_floor72(_CSS72)
      and _re72.search(r'<th class="[^"]*\bdash-col-name\b[^"]*" data-sortkey="name"', _DASH72) is not None
      and _re72.search(r'\{% endif %\}\s*<td class="dash-col-name">', _DASH72) is not None,
      "the name column's floor or its class is missing")
_ptbad72 = _r18d_unscoped_wraps72(_CSS72)
check("375px: a page heading wraps its flex row only when it carries a name (a long translated title "
      "kept its icon beside it), in every .page-title rule, the phone block's included",
      _re72.search(r"(?<![\w-])\.page-title\s*\{", _CSS72) is not None and _ptbad72 == []
      and _re72.search(r"\.page-title:has\(>\s*\[data-no-i18n\]\)\s*\{\s*flex-wrap:\s*wrap", _CSS72) is not None,
      repr(_ptbad72))
# Controls: the wrap put back into the phone block's rule, or on a selector list, is named; the
# floor moved out of the phone block is not the phone's floor.
_ptctl72 = _CSS72.replace(_PHONE72 + " {", _PHONE72 + " {\n.page-title { flex-wrap: wrap; }", 1)
_flctl72 = _re72.sub(r"(\.dash-srv-table\s+\.dash-col-name\s*\{[^}]*)min-width:\s*120px", r"\1min-width: 0",
                     _CSS72) + "\n.dash-srv-table .dash-col-name { min-width: 120px; }\n"
check("375px: ...a flex-wrap in the phone block's .page-title rule or in a selector list naming it is "
      "named, and a name floor outside the phone block is not counted (control)",
      _r18d_unscoped_wraps72(_ptctl72) == [".page-title"]
      and _r18d_unscoped_wraps72(".x, .page-title { flex-wrap: wrap }") == [".x, .page-title"]
      and _r18d_unscoped_wraps72(".page-title:has(> [data-no-i18n]) { flex-wrap: wrap }") == []
      and not _r18d_name_floor72(_flctl72),
      repr((_r18d_unscoped_wraps72(_ptctl72), _r18d_name_floor72(_flctl72))))
_fw72 = _read72(_root, "templates", "remote_firewall.html")
_lim72 = _fw72[_fw72.index('id="limit-port"') - 400:_fw72.index('data-action="unlimitPort"')]
check("375px: the rate-limit row gives its port the whole row below 576px (the × ran past the card "
      "in French and Spanish)",
      'class="col-12 col-sm-6"' in _lim72 and 'class="col-6 col-sm-3"' in _lim72
      and 'class="col-6 col-sm-3 d-flex gap-1"' in _lim72, _lim72[-300:])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The terminal writes a panel message as text, never as control sequences
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A host's name may hold ESC (SAFE_LABEL_RE refuses only < > " ' ` \ and newlines), and a refusal
# such as "Could not start a shell on {host}…" was written into xterm as it was.
_out72t = _node72("terminal: a host name's control characters are not written into xterm", (
    "global.window = global; global.REMOTE_ID = 1; const writes = [], on = {}; global.addEventListener = () => 0;\n"
    "global.t = s => s; global.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => k in v ? String(v[k]) : m);\n"
    "global.document = { getElementById: id => (id === 'terminal' ? {clientWidth: 800, clientHeight: 400} : null),\n"
    "  querySelector: () => null, addEventListener(){} };\n"
    "global.getComputedStyle = () => ({paddingLeft: '0', paddingRight: '0', paddingTop: '0', paddingBottom: '0'});\n"
    "window.getComputedStyle = global.getComputedStyle;\n"
    "global.Terminal = function(){ this.cols = 80; this.rows = 24; };\n"
    "Terminal.prototype = {open(){}, resize(c, r){ this.cols = c; this.rows = r; }, focus(){}, onData(){},\n"
    "  write(s){ writes.push(s); }};\n"
    "global.io = () => ({on: (ev, fn) => { on[ev] = fn; }, emit(){}});\n"
    "require('vm').runInThisContext(%s);\n"
    "initTerminal();\n"
    "const evil = 'box\\u001b[2J\\u001b]0;pwned\\u0007\\u009b31m';\n"
    "on.term_error({message: 'x', message_key: 'Could not start a shell on {host} ({error}).',\n"
    "               message_vals: {host: evil, error: 'OSError'}});\n"
    "on.term_exit({reason: evil});\n"
    "console.log(JSON.stringify({writes}));\n") % _json72.dumps(_read72(_JS72, "host_terminal.js")))
if _out72t is not None:
    _w72 = _out72t.get("writes") or []
    # Each write keeps the page's own colour codes (ESC [31m … ESC [0m) and nothing else.
    _inner72 = [w.replace("\x1b[31m", "").replace("\x1b[33m", "").replace("\x1b[0m", "").strip("\r\n")
                for w in _w72]
    check("terminal: a host name's ESC/BEL/CSI never reach xterm in an error or close line (its text stays)",
          len(_w72) == 2 and all(not any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f for c in w) for w in _inner72)
          and "box[2J]0;pwned31m" in _inner72[0], repr(_out72t))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The console: Clear while the first window's catch-up is still out, then the re-prime
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The re-prime after Clear ends the catch-up the first window asked for (_primeAt -> _startResync
# -> _endResync), which shows the panel pushes it held — AFTER the wipe. A held push newer than the
# backlog the poll read was then put back a second time by the reshow (_r13c_reshowPanelPushes):
# the same [panel] line twice. refreshConsole, clearConsole, the priming catch-up and the backlog
# helpers are cut from the real file; `shown` is what the console holds, in order.

_SD72 = _read72(_JS72, "server_detail.js")
_CON72 = (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "global.setTimeout = () => 0; global.clearTimeout = () => 0;\n"
    "var shown = [], _consoleLines = [], _consolePrimed = false, _consoleSig = null, _lastPanelT = 0;\n"
    "var _returnOwed = false, _panelBacklogShown = false, _r13c_panelPushes = [], _R13C_PANEL_KEEP = 200;\n"
    "var _r15c_clearedAt = null, _logAt = null, _resync = null, _resyncSeq = 0, _shownOnReturn = {};\n"
    "var _primeOwed = false, _RESYNC_MAX_MS = 45000;\n"
    "var consoleEl = {set innerHTML(v){ shown.length = 0; }};\n"
    "var socket = {connected: true};\n"
    "function _rebuildMark(){ return 0; } function _rebuildRestore(){} function updateTsNotice(){}\n"
    "function _showTsOffNote(){} function stickConsole(){} function consoleAtBottom(){ return true; }\n"
    "function _notePanelMarker(){} function _newConsoleRows(){ return []; }\n"
    "function _resyncAsk(){} function _resyncGiveUp(){}\n"
    "function _appendConsoleRows(rows){ (rows || []).forEach(r => shown.push(r.line)); }\n"
    "function appendConsole(text){ shown.push(text); }\n"
    "function _panelShownAt(t){ if (Number(t) > _lastPanelT) _lastPanelT = Number(t); }\n"
    "function _renderPanelLines(rows){ rows.forEach(r => { shown.push(r.line); _panelShownAt(r.t); }); }\n"
    + "".join(_cut47(_SD72, h) + "\n" for h in (
        "function _r13c_notePanelPush(", "function _r13c_reshowPanelPushes(", "function refreshConsole(",
        "function showPanelBacklog(", "function _newerPanelRows(", "function _panelLinesWiped(",
        "function _r13c_primeWipesPushes(", "function clearConsole(", "function _primeAt(",
        "function _primeCatchUp(", "function _startResync(", "function _endResync(",
        "function _showPanelPush(", "function _resyncTake("))
    + "var backlog = [], logN = 0;\n"
    "global.fetch = () => { logN++; return Promise.resolve({ok: true, json: () => Promise.resolve(\n"
    "  {lines: [{line: 'log' + logN}], panel_lines: backlog.slice(), at: [1, 1, logN]})}); };\n"
    # a [panel] push as the socket handler takes it: held while a catch-up is out, else shown
    "function push(ts, data){ const d = {panel: true, ts: ts, data: data}; if (_resyncTake(d)) return;\n"
    "  appendConsole(d.data); _panelShownAt(d.ts); _r13c_notePanelPush(d); }\n")
_out72c = _node72("console: Clear while the first catch-up is out, then the re-prime", _CON72 + (
    "(async () => { const out = {};\n"
    "  backlog = [{t: 100, line: '[panel] old'}]; refreshConsole(true); await settle();\n"
    "  out.primed = shown.slice(); out.catching = !!_resync;\n"
    # Clear, then an update's line pushed (held: the first window's catch-up is still out), written
    # after the server read the backlog the re-prime brings
    "  clearConsole(); push(110, '[panel] u1');\n"
    "  refreshConsole(false); await settle(); out.after = shown.slice();\n"
    # the same, with the backlog holding it
    "  push(120, '[panel] u2'); backlog.push({t: 110, line: '[panel] u1'}, {t: 120, line: '[panel] u2'});\n"
    "  clearConsole(); push(130, '[panel] u3'); backlog.push({t: 130, line: '[panel] u3'});\n"
    "  refreshConsole(false); await settle(); out.inBacklog = shown.slice();\n"
    "  console.log(JSON.stringify(out)); })();\n"))
if _out72c is not None:
    check("console: a [panel] line pushed after Clear, while the first window's catch-up was still out, "
          "shows once after the re-prime (it was put back twice)",
          _out72c.get("catching") is True and _out72c.get("after") == ["log2", "[panel] u1"], repr(_out72c))
    # u2 came while the second window's catch-up was out, so it was held and never on the page when
    # Clear was pressed: it is shown, as u3 is, and neither twice.
    check("console: ...and with the re-prime's backlog holding them, each held line shows once (control)",
          _out72c.get("inBacklog") == ["log3", "[panel] u2", "[panel] u3"], repr(_out72c))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. Pages at 375px and for a screen reader (measured in a browser; held here by their markup)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF72 = _read72(_root, "templates", "server_files.html")
_edh72 = _re72.search(r'<div class="([^"]*)">\s*<code class="([^"]*)" id="editor-path">', _SF72)
check("375px: the file editor's header wraps and its path breaks (a long path pushed Save and Close off "
      "the card, the page 740px wide)",
      _edh72 is not None and "flex-wrap" in _edh72.group(1).split() and "text-break" in _edh72.group(2).split(),
      _edh72.group(0) if _edh72 else "no editor header")
_FWJS72 = _read72(_JS72, "remote_firewall.js")
_bjs72 = _FWJS72[_FWJS72.index("function _fwRenderBlocks("):_FWJS72.index("function _fwUnlisted(")]
_btpl72 = _fw72[_fw72.index('id="blocks-list"'):_fw72.index('id="blocks-body"')]
check("375px: the blocked-IPs table pins its Unblock button and lets an address break, in the template and "
      "the repaint (an IPv6 address hid the button under the box's scroll)",
      "table-pin-actions" in _btpl72 and '<code class="text-break">{{ g.block_ip }}</code>' in _fw72
      and "table-pin-actions" in _bjs72 and "<code class=\"text-break\">'" in _bjs72, _bjs72[:400])
check("i18n: the repainted Unblock tooltip is one translated sentence ('Unblock ' + ip was English)",
      "tf('Unblock {ip}', {ip: g.block_ip})" in _bjs72 and "'Unblock '" not in _bjs72
      and "Unblock {ip}" in _ES72 and "Unblock {ip}" in _scan72.load_catalog("fr"), _bjs72[-500:])
_MG72 = _read72(_root, "templates", "manage_groups.html")
check("a11y: the edit form's permission boxes are a group named by its heading, as the Add modal's are",
      'id="edit-perms-label-{{ group.id }}"' in _MG72
      and _re72.search(r'role="group"\s+aria-labelledby="edit-perms-label-\{\{ group\.id \}\}"', _MG72) is not None,
      "no named group on the edit form's permissions")
_MR72 = _read72(_root, "templates", "manage_remotes.html")
_sub72 = _re72.search(r'<button type="submit" class="btn btn-primary btn-sm w-100"([^>]*)>\s*<i class="bi bi-check">', _MR72)
check("a11y: the host edit form's icon-only submit has a name", _sub72 is not None
      and 'aria-label="Save changes"' in _sub72.group(1), _sub72.group(0) if _sub72 else "no such button")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. The server page's Connect row at 375px, and literal English written straight into the page
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Measured in a browser: with a Join button the row (label, address pill, Join) could not wrap, so
# /server/<id> was 399px wide in Spanish and 381px in English, Join past the screen's edge.
_SDT72 = _read72(_root, "templates", "server_detail.html")
_conn72 = _re72.search(r'<div class="([^"]*)">\s*<span class="text-secondary small">Connect:</span>', _SDT72)
_pill72 = _re72.search(r"\.connect-pill\s*\{([^}]*)\}", _CSS72)
_addr72 = _re72.search(r"\.connect-pill\s+#connect-addr\s*\{([^}]*)\}", _CSS72)
check("375px: the server page's Connect row wraps, its pill fits the row and a long address breaks "
      "(Join ran past a phone's edge, the page 399px wide in Spanish)",
      _conn72 is not None and "flex-wrap" in _conn72.group(1).split()
      and _pill72 is not None and _re72.search(r"max-width:\s*100%", _pill72.group(1)) is not None
      and _addr72 is not None and _re72.search(r"overflow-wrap:\s*anywhere", _addr72.group(1)) is not None,
      (_conn72.group(0) if _conn72 else "no Connect row") + " | " + (_pill72.group(1) if _pill72 else "no pill rule"))

# The stat tiles' sub-lines read 'not read' and the uptime tile 'stopped' in English for every
# viewer: plain literals, and no catalog key the page translator could match. Run the real tile
# functions on a read that failed and on a stopped game, with the real t() and each catalog.
_tiles72 = "".join(_cut47(_SD72, h) + "\n" for h in (
    "function _setStatText(", "function _showGameCpuTile(", "function _showGameRamTile(",
    "function _showGameUptimeTile(", "function _showServerTile("))
for _lang72 in ("es", "fr"):
    _cat72 = _scan72.load_catalog(_lang72)
    # Only the keys these functions' text could name: the whole catalog is past node's argv limit.
    _sub72 = {k: v for k, v in _cat72.items() if ("'%s'" % k) in _tiles72}
    _outt72 = _node72("stat tiles: a failed read and a stopped game in " + _lang72, _DOM72 + (
        "window.LANG = %s; window.I18N = %s;\n"
        "require('vm').runInThisContext(%s);\n"
        "const els = {}; document.getElementById = id => els[id] || (els[id] = document.createElement('span'));\n"
        "window.fmtUptime = s => s + 's';\n"
        "require('vm').runInThisContext(%s);\n"
        "const fail = {}, stop = {};\n"
        "[_showGameCpuTile, _showGameRamTile, _showGameUptimeTile, _showServerTile].forEach(f => f({}, false));\n"
        "Object.keys(els).forEach(k => { fail[k] = els[k].textContent; });\n"
        "_showGameUptimeTile({game_procs: 0}, true); stop.gup = els['stat-gup'].textContent;\n"
        "console.log(JSON.stringify({fail: fail, stop: stop}));\n"
    ) % (_json72.dumps(_lang72), _json72.dumps(_sub72), _json72.dumps(_I18N72), _json72.dumps(_tiles72)))
    if _outt72 is not None:
        _f72 = _outt72.get("fail", {})
        check("i18n: the stat tiles say 'not read' and 'stopped' in " + _lang72 + " (English for every viewer)",
              _cat72.get("not read") and _cat72.get("stopped")
              and [_f72.get(k) for k in ("stat-gcpu-sub", "stat-gram-sub", "stat-gup-sub")] == [_cat72["not read"]] * 3
              and _f72.get("stat-server-sub") == _cat72.get("The panel could not read this host")
              and _outt72.get("stop", {}).get("gup") == _cat72["stopped"], _outt72)

# The whole class, every script: a literal written straight into a text sink (textContent,
# innerText, a stat tile, a title/placeholder/aria-label, a text node) reaches the page as one text
# node the translator matches by its EXACT text, so it is English unless that text is a catalog key
# (a ✓/✗ mark in front is looked past, as i18n.js does). Literals handed to t()/tf() are the catalog
# gate's (part06). Left out on purpose: values that are not words to translate.
_SINK72 = _re72.compile(r"(?:\.textContent\s*\+?=|\.innerText\s*=|\.title\s*=|\.placeholder\s*="
                        r"|setAttribute\(\s*'(?:title|aria-label|placeholder)'\s*,|createTextNode\("
                        r"|_setStatText\([^,;]*,)([^;]*)$")
_NOTWORDS72 = {
    " MB": "a unit after a number, as on every other size the panel shows",
    "home": "a directory's name, under data-no-i18n (server_files.js)",
    "~/.ssh/id_rsa": "a path, as a placeholder",
}
_raw72 = []
for _fn72 in sorted(os.listdir(_JS72)):
    if not _fn72.endswith(".js"):
        continue
    _src72 = _read72(_JS72, _fn72)
    for _txt72, _ln72, _st72, _end72 in _scan72._js_string_spans(_src72):
        _bef72 = _src72[max(0, _st72 - 300):_st72]
        _sm72 = _SINK72.search(_bef72)
        _key72 = _re72.sub(r"\s+", " ", _txt72).strip()
        _lend72 = _src72.find("\n", _st72)
        if (not _sm72 or "\n\n" in _sm72.group(1) or not _re72.search(r"[A-Za-z]{2}", _txt72)
                or _txt72.startswith("data-") or _txt72 in _NOTWORDS72
                or _scan72.is_js_t_arg(_txt72, _bef72) or _re72.search(r"[=!]==?\s*$", _bef72)
                or _scan72.JS_IGNORE in _src72[_src72.rfind("\n", 0, _st72) + 1:_lend72 if _lend72 >= 0 else None]):
            continue
        _raw72.append(("%s:%d" % (_fn72, _ln72), _key72))
for _lang72 in ("es", "fr"):
    _cat72 = _scan72.load_catalog(_lang72)
    _gap72 = [(at, k) for at, k in _raw72
              if k not in _cat72 and _re72.sub(r"^[✓✗] ", "", k) not in _cat72]
    check("i18n: no script writes literal English into the page that the %s catalog cannot match "
          "(the stat tiles' 'not read', the console's '(connected)', the diagnostics badge)" % _lang72,
          len(_raw72) > 10 and not _gap72, "%d of %d: %s" % (len(_gap72), len(_raw72), _gap72[:12]))


# ── connect address: an IPv6 host goes in brackets ─────────────────────────────────────────────
# `2001:db8::7334:27016` gives no way to tell the address from the port, so the copyable address
# and the steam:// link reached nothing for a host whose public address is IPv6.
from panel.db.models import GameServer as _GS72  # noqa: E402

_gs72 = _GS72(game_type="css", port=27016)
_addr72 = {h: (_gs72.connect_address(h), _gs72.connect_uri(h))
           for h in ("2001:db8::7334", "203.0.113.10", "play.example.org", "")}
check("connect address: an IPv6 host is bracketed in the address and the steam:// link; IPv4, a "
      "hostname and no host are as before",
      _addr72 == {"2001:db8::7334": ("[2001:db8::7334]:27016", "steam://connect/[2001:db8::7334]:27016"),
                  "203.0.113.10": ("203.0.113.10:27016", "steam://connect/203.0.113.10:27016"),
                  "play.example.org": ("play.example.org:27016", "steam://connect/play.example.org:27016"),
                  "": ("", "")}, repr(_addr72))

check("part72: nothing its routes drove reached a real transport (part12's tripwire, armed in each)",
      len(_P9_TRIPPED) == _TRIP72_START, repr(_P9_TRIPPED[_TRIP72_START:][:6]))
