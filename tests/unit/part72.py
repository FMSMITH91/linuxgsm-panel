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
                                          json={"action": "restart", "ids": [_HUGE72]}))
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
    _sio72.emit("join_console", {"server_id": _HUGE72})
    with _sf72._viewers_lock:
        _joined72 = _HUGE72 in _sf72._console_viewers
        _sf72._console_viewers.pop(_HUGE72, None)
    _sio72.emit("term_open", {"remote_id": _HUGE72, "cols": 80, "rows": 24})
    _term72 = [(m.get("args") or [{}])[0] for m in _sio72.get_received() if m.get("name") == "term_error"]
    _sio72.disconnect()
    check("row id: a console join naming a server id past SQLite's range is not watched (the poller "
          "would look it up every pass)", not _joined72)
    check("row id: a terminal naming a host id past SQLite's range is 'No host was named.'",
          [p.get("message") for p in _term72] == ["No host was named."], repr(_term72))

    # A hand-edited `port` in config.json that is not a number: Change Port read it with int().
    _p9_patch(_rs72, "load_config", lambda: {"port": "5000x", "bind_host": "0.0.0.0"})  # nosec B104
    _cp72 = _status72(lambda: _A72.post("/api/panel/change-port", json={"port": 1}))
    check("change port: a hand-edited non-numeric panel port is a refusal, not a 500", _cp72 == 400,
          repr(_cp72))
finally:
    _p9_restore_all()
