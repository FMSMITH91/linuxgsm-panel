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
from unit.part12 import (P9_ADMIN, P9_GS, P9_VIEWER, _p9, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from unit.part47 import _node47
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
try:
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
        from panel.db.models import User as _U72, db as _db72
        _viewer72 = _db72.session.get(_U72, P9_VIEWER)
        try:
            _cas72 = _auth72.can_access_server(_viewer72, _HUGE72)
        except Exception as e:
            _cas72 = type(e).__name__
    check("row id: can_access_server answers False for an id past SQLite's range", _cas72 is False,
          repr(_cas72))

    # The console socket, as a superadmin (who passes can_access_server without a lookup).
    _sio72 = _p9.socketio.test_client(_p9, flask_test_client=_p9_client(P9_ADMIN))
    try:
        _sio72.emit("join_console", {"server_id": _HUGE72})
    except Exception:           # nothing to see here: the check reads what the join left behind
        pass
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
          "would look it up every pass)", not _joined72)
    check("row id: a terminal naming a host id past SQLite's range is 'No host was named.'",
          [p.get("message") if isinstance(p, dict) else p for p in _term72] == ["No host was named."], repr(_term72))

    # A hand-edited `port` in config.json that is not a number: Change Port read it with int().
    _p9_patch(_rs72, "load_config", lambda: {"port": "5000x", "bind_host": "0.0.0.0"})  # nosec B104
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
from panel.db.models import User as _U72b, RemoteServer as _RS72, db as _db72b  # noqa: E402
from panel.routes import (discover as _disc72, panel_backup as _pb72, server_detail as _sd72,  # noqa: E402
                          ubuntu_pro as _up72)


def _lang72(lang):
    with _p9.app_context():
        _db72b.session.get(_U72b, P9_ADMIN).language = lang
        _db72b.session.commit()


_ES72 = _scan72.load_catalog("es")
try:
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
    _att72 = _p9_json(_A72.post("/api/remote/%d/pro-attach" % _H72, json={"token": "x"})).get("message")
    _det72 = _p9_json(_A72.post("/api/remote/%d/pro-detach" % _H72)).get("message")
    check("es: Ubuntu Pro attach and detach answer in Spanish",
          (_att72, _det72) == (_ES72["Attached to Ubuntu Pro."], _ES72["Detached from Ubuntu Pro."]),
          repr((_att72, _det72)))
    _p9_patch(_pb72.bk, "delete_backup", lambda name: (False, "No such backup."))
    _del72 = _p9_json(_A72.post("/api/panel/backup/delete", json={"name": "x"})).get("message")
    check("es: a panel backup delete answers in Spanish", _del72 == _ES72["No such backup."], repr(_del72))

    # Helpers that word a route's answer, in a Spanish viewer's request.
    with _p9.app_context(), _p9.test_request_context("/"):
        _login72(_db72b.session.get(_U72b, P9_ADMIN))
        _gen72 = _http72._log_and_generic("p72: a stand-in failure")
        _cs72 = (_sd72._console_send_failure(3, ""), _sd72._console_send_failure(1, ""))
        _host72 = _db72b.session.get(_RS72, _H72)
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
              "la configuración del juego y luego impórtalo"]
          and _reasons72[0] in _out72.get("message", "") and "Not imported" not in _out72.get("message", ""),
          repr((_reasons72, _out72.get("message"))))
finally:
    _lang72("en")
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
# A viewer with no start/stop/restart/update has no checkbox column: :nth-child(2) was Type.
check("375px: the dashboard's server-name floor is on the Server column by class, not by position "
      "(no checkbox column for a view-only viewer moved it onto the hidden Type column)",
      _re72.search(r"dash-srv-table[^{]*:nth-child", _CSS72) is None
      and _re72.search(r"\.dash-srv-table\s+\.dash-col-name\s*\{[^}]*min-width:\s*120px", _CSS72) is not None
      and _re72.search(r'<th class="[^"]*\bdash-col-name\b[^"]*" data-sortkey="name"', _DASH72) is not None
      and _re72.search(r'\{% endif %\}\s*<td class="dash-col-name">', _DASH72) is not None,
      "the name column's floor or its class is missing")
_ptbase72 = _re72.search(r"(?<![\w-])\.page-title\s*\{([^}]*)\}", _CSS72)
check("375px: a page heading wraps its flex row only when it carries a name (a long translated title "
      "kept its icon beside it)",
      _ptbase72 is not None and "flex-wrap" not in _ptbase72.group(1)
      and _re72.search(r"\.page-title:has\(>\s*\[data-no-i18n\]\)\s*\{\s*flex-wrap:\s*wrap", _CSS72) is not None,
      _ptbase72.group(1).strip() if _ptbase72 else "no .page-title rule")
_fw72 = _read72(_root, "templates", "remote_firewall.html")
_lim72 = _fw72[_fw72.index('id="limit-port"') - 400:_fw72.index('data-action="unlimitPort"')]
check("375px: the rate-limit row gives its port the whole row below 576px (the × ran past the card "
      "in French and Spanish)",
      'class="col-12 col-sm-6"' in _lim72 and 'class="col-6 col-sm-3"' in _lim72
      and 'class="col-6 col-sm-3 d-flex gap-1"' in _lim72, _lim72[-300:])
