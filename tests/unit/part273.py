"""Part 273 of the unit suite: the Add-ons tab's B3 players section (B3's players and penalties).

1. The statements (services/b3_players.py): constant SQL with every value bound, a search through
   indexed columns only, a GUID searched by its start only for a viewer who may see GUIDs, and no IP
   address or GUID even selected for anyone else; the answers read into players, penalties and one
   player's history.
2. The routes (routes/addons_b3.py), through the app: Manage add-ons on every request, B3's own
   database found from its add-on record (and the Add-ons tab's own status read reused), read in a
   READ ONLY db-query, the empty and failed states each said, and an audit row per look that names
   the player's B3 id or the kind of search, never the text searched for.
3. The page: B3's section and script are on the Files & Config page of a game B3 runs on, and the
   script builds every row with textContent and sends the search text in a POST body.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host's status read and the
db-query verb are stubs answering in the client's own XML, read by db_data.parse.
"""
import base64 as _b64_273
import json as _json273
import os
import re as _re273
from types import SimpleNamespace as _NS273

from werkzeug.security import generate_password_hash as _gph273

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part261 import _addons_member261
from unit.part221 import _node221
from unit.part47 import _cut47
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core.config import encrypt_secret as _enc273
from panel.db import models as _m273
from panel.ops.ssh_manager import db_data as _dd273
from panel.routes import addons as _ra273, addons_b3 as _rb273, databases as _dbr273
from panel.security import auth as _auth273
from panel.security import privileged as _pv273
from panel.services import b3_players as _b3_273

_trips273 = len(_P9_TRIPPED)
_DBNAME273 = "gs1_b3players"
_STAND_IN273 = "p273-db-" + "value"


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The statements and their answers
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _all_sql273():
    """Every statement text the module can send."""
    return (list(_b3_273.SEARCH_SQL.values()) + list(_b3_273.CLIENT_SQL.values()) + [_b3_273.ALIASES_SQL]
            + list(_b3_273.ADDRESSES_SQL.values()) + [_b3_273.PENALTIES_SQL, _b3_273.RECENT_SQL])


def _statements273():
    sqls = _all_sql273()
    check("b3 players: every statement is one SELECT with no string literal but the LIKE escape character (every value "
          "is a bound parameter)",
          all(s.startswith("SELECT ") and ";" not in s and _re273.sub(r"ESCAPE '!'", "", s).count("'") == 0
              for s in sqls), repr([s[:60] for s in sqls]))
    check("b3 players: no statement reads B3's own sign-in columns (clients.password, clients.login) or the PunkBuster id",
          not any(_re273.search(r"\b(password|login|pbid)\b", s) for s in sqls), "")
    masked = [_b3_273.SEARCH_SQL[(False, False)], _b3_273.CLIENT_SQL[False], _b3_273.ADDRESSES_SQL[False]]
    check("b3 players: the statements for a viewer who may not see them select no IP address and no GUID (data "
          "minimisation: what is not shown is not read)",
          not any(_re273.search(r"\b(ip|guid)\b", s.split(" FROM ")[0]) for s in masked)
          and "ip, num_used" not in _b3_273.ADDRESSES_SQL[False], repr(masked))
    check("b3 players: ...and the unmasked ones do (control)",
          ", c.guid" in _b3_273.SEARCH_SQL[(True, False)] and "c.ip" in _b3_273.CLIENT_SQL[True]
          and "SELECT ip," in _b3_273.ADDRESSES_SQL[True], "")


def _search_sql273():
    for q, unmask in (("Snake", False), ("ABCDEF0123", False), ("ABCDEF0123", True), ("@12", True)):
        st = _b3_273.search_statement(q, unmask, (1700000000, 9))
        eq("b3 players: a search for %r (unmask=%s) binds one value per placeholder, within the verb's limits"
           % (q, unmask), (st["sql"].count("?"), len(st["params"]), 0 < st["cap"] <= _pv273.DB_QUERY_CAP_MAX),
           (len(st["params"]), st["sql"].count("?"), True))
        check("b3 players: ...and the text is never part of the statement (%r)" % q, q not in st["sql"], st["sql"])
    m, u = _b3_273.search_statement("ABCDEF0123", False), _b3_273.search_statement("ABCDEF0123", True)
    check("b3 players: a viewer who may not see GUIDs searches a GUID only whole (a search by its start would hand it "
          "over one character at a time)",
          "guid = ?" in m["sql"] and "guid LIKE" not in m["sql"] and m["params"][3] == "ABCDEF0123", repr(m))
    check("b3 players: ...one who may sees GUIDs starting with it (control)",
          "guid LIKE ? ESCAPE '!'" in u["sql"] and u["params"][3] == "ABCDEF0123%", repr(u))
    n = _b3_273.search_statement("Snake", True)
    check("b3 players: a text not shaped like a GUID asks no GUID by its start even for that viewer (a LIKE NULL part "
          "read the whole guid index)", "guid LIKE" not in n["sql"] and n["params"][3] is None, repr(n))


def _limits273():
    eq("b3 players: each list asks one row past its page (15 shown, the 16th says there is more) and each player's "
       "list one past its cap", [s.rsplit("LIMIT ", 1)[1] for s in (_b3_273.SEARCH_SQL[(True, True)], _b3_273.RECENT_SQL,
                                                                     _b3_273.ALIASES_SQL, _b3_273.PENALTIES_SQL)]
       + [_b3_273.PAGE_SIZE], ["16", "16", "51", "101", 15])
    eq("b3 players: B3's own % _ and ! are taken literally in a name search (LIKE ... ESCAPE '!')",
       _b3_273.like_prefix("100%_a!b"), "100!%!_a!!b%")
    eq("b3 players: the search text: trimmed; refused when empty, too long, with a control character, or not text",
       [_b3_273.clean_query(x) for x in ("  Snake ", "", "x" * 37, "a\x00b", "a\nb", 5, None, "x" * 36)],
       ["Snake", None, None, None, None, None, None, "x" * 36])
    eq("b3 players: a next-page mark is two numbers or nothing; anything else is refused (False)",
       [_b3_273.parse_after(x) for x in ("1700000000.12", "", None, "1.2.3", "a.b", "1700000000", 7)],
       [(1700000000, 12), None, None, False, False, False, False])
    eq("b3 players: the latest-penalties list fills its four type slots with NULL past the kinds asked",
       [_b3_273.recent_statement("bans", 40)["params"], len(_b3_273.recent_statement("all")["params"])],
       [["Ban", "TempBan", None, None, "40", "40"], 6])


def _sets273(cols, rows):
    return {"sets": [{"columns": list(cols), "rows": [list(r) for r in rows]}], "affected": -1}


def _answers273():
    now = 1700005000
    rows = [{"type": "Ban", "inactive": "0", "time_expire": "-1"}, {"type": "TempBan", "inactive": "0", "time_expire": "1700009000"},
            {"type": "TempBan", "inactive": "0", "time_expire": "1700000000"}, {"type": "Ban", "inactive": "1", "time_expire": "-1"},
            {"type": "Kick", "inactive": "0", "time_expire": "-1"}, {"type": "Warning", "inactive": "0", "time_expire": "1700004999"}]
    eq("b3 players: a penalty is active (permanent, or not expired yet), expired, lifted by an admin, or has no state "
       "(a kick)", [_b3_273.state(r, now) for r in rows], ["active", "active", "expired", "removed", "", "expired"])
    pen = _b3_273.penalty({"id": "3", "type": "Ban", "admin_id": "0", "reason": "^1aim^7bot", "time_add": "5",
                           "time_expire": "-1", "inactive": "0", "admin": None}, now)
    eq("b3 players: a penalty given by B3 itself (admin id 0) names B3, and colour codes leave the reason",
       (pen["admin"], pen["reason"]), ("B3", "aimbot"))
    cols = ("id", "name", "connections", "time_add", "time_edit", "grp", "guid")
    page = _b3_273.players(_sets273(cols, [(str(i), "p%d" % i, "1", "1", str(100 - i), "", "G%d" % i)
                                           for i in range(16)]), True)
    eq("b3 players: a full page keeps PAGE_SIZE rows and marks the next one by the last row's last-seen time and id",
       (len(page["players"]), page["after"]), (15, "86.14"))
    masked = _b3_273.players(_sets273(cols, [("1", "a", "1", "1", "1", "", "SECRETGUID")]), False)
    check("b3 players: a viewer who may not see GUIDs gets none, even if one came back", "guid" not in masked["players"][0],
          repr(masked))
    one = [_sets273(("id", "name", "connections", "time_add", "time_edit", "grp", "level"), [("4", "x", "2", "1", "2", "Admin", "40")]),
           _sets273(("alias", "num_used", "time_add", "time_edit"), [("old%d" % i, "1", "1", "1") for i in range(51)]),
           _sets273(("n",), [("7",)]), _sets273(("id", "type"), [])]
    d = _b3_273.detail(one, False, now)
    eq("b3 players: one player, masked: its earlier addresses are a count, no address or GUID, aliases capped and "
       "marked as cut", (d["address_count"], "ip" in d, "addresses" in d, "guid" in d, len(d["aliases"]), d["aliases_more"]),
       (7, False, False, False, _b3_273.ALIASES_MAX, True))
    check("b3 players: no player row is no player (None), not an empty one",
          _b3_273.detail([_sets273(("id",), [])] + one[1:], False, now) is None, "")
    _b3_273.remember(9273, {"b3": {"meta": {"database": "gs9_b3"}}}, now=100.0)
    eq("b3 players: B3's database name is reused for CACHE_SECONDS, then asked again (None)",
       (_b3_273.database_name(9273, now=100.0 + _b3_273.CACHE_SECONDS - 1),
        _b3_273.database_name(9273, now=100.0 + _b3_273.CACHE_SECONDS)), ("gs9_b3", None))
    _b3_273.remember(9273, {}, now=100.0)
    eq("b3 players: ...and a server without B3 is noted as such (\"\"), not as unknown", _b3_273.database_name(9273, now=101.0), "")
    _b3_273.forget(9273)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The routes
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _xml273(sets):
    """The client's XML answer for `sets` ([(columns, rows)] one per statement), with the verb's own marks."""
    def resultset(stmt, cols, rows):
        body = "".join("<row>%s</row>" % "".join(
            '<field name="%s" xsi:nil="true" />' % c if v is None else '<field name="%s">%s</field>' % (c, v)
            for c, v in zip(cols, r)) for r in rows)
        return '<resultset statement="%s" xmlns:xsi="x">%s</resultset>\n' % (stmt, body)
    out = resultset(_pv273.DB_QUERY_CONN_SQL, ["panel_conn"], [["7"]])
    for cols, rows in sets:
        out += resultset("EXECUTE panel_s", cols, rows) + resultset(_pv273.DB_QUERY_ROWS_SQL, ["panel_rows"], [["-1"]])
    return out


_PLAYER_COLS273 = ("id", "name", "connections", "time_add", "time_edit", "grp")


def _stubs273(sid, answer, status_db=_DBNAME273):
    """Stub the host (status read) and db-query; -> {"shells": [...], "runs": [(target, name, mode, statements)]}."""
    seen = {"shells": [], "runs": []}
    meta = _b64_273.b64encode(_json273.dumps({"database": status_db, "port": 0}).encode()).decode()
    status = "os=24.04\npodman=podman version 5.0\n" + ("meta.b3=%s\nstate.b3=active\n" % meta if status_db else "")
    _p9_patch(_ra273, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: seen["shells"].append(a[2]) or (status, "", 0))
    _p9_patch(_dbr273, "_restore_target", lambda gs, r: _NS273(flavor="mariadb", port=3306, address=""))

    def run(remote, target, name, pw, mode, statements):
        seen["runs"].append((target, name, mode, statements))
        got = answer(statements) if callable(answer) else answer
        return dict(_dd273.parse(got), rc=0)
    _p9_patch(_dd273, "run", run)
    _b3_273.forget(sid)
    return seen


def _user273(perms, name):
    with _p9.app_context():
        grp = _m273.Group(name=name, description="", is_default=False)
        grp.set_permissions([_auth273.VIEW_SERVERS] + perms)
        grp.servers.append(_m273.db.session.get(_m273.RemoteServer, P9_HOST))
        u = _m273.User(username=name, password_hash=_gph273(os.urandom(12).hex()), display_name=name,
                       is_superadmin=False, is_active=True)
        u.groups.append(grp)
        _m273.db.session.add_all([grp, u])
        _m273.db.session.commit()
        return u.id, grp.id


def _drop273(*pairs):
    with _p9.app_context():
        for model, key in pairs:
            obj = _m273.db.session.get(model, key) if key is not None else None
            if obj is not None:
                _m273.db.session.delete(obj)
        _m273.db.session.commit()


def _post273(c, sid, body):
    r = c.post("/api/server/%d/addons/b3/players/search" % sid, json=body)
    return r.status_code, r.get_json(silent=True) or {}


def _search_routes273(sid):
    found = _xml273([(_PLAYER_COLS273 + ("guid",), [("2", "Snake", "12", "1", "1700500000", "Super Admin", "GUIDTWO")])])
    seen = _stubs273(sid, found)
    before = _p9_audit_count("b3_player_search")
    st, d = _post273(_p9_client(P9_ADMIN), sid, {"q": "Sna%ke"})
    run = seen["runs"][0] if seen["runs"] else (None, None, None, [{}])
    eq("b3 players route: a search answers the players found, read from B3's own database in a READ ONLY db-query",
       (st, [p.get("name") for p in d.get("players", [])], run[1], run[2]), (200, ["Snake"], _DBNAME273, "ro"))
    check("b3 players route: ...the text is a bound value, escaped for LIKE, never in the statement",
          "Sna!%ke%" in run[3][0].get("params", []) and "Sna" not in run[3][0].get("sql", ""), repr(run[3])[:300])
    a = _p9_audit("b3_player_search")
    check("b3 players route: ...one audit row with the server, saying what kind of search found how many, never the "
          "text (personal data stays out of the log)",
          _p9_audit_count("b3_player_search") == before + 1 and a.success and "1 found" in a.detail
          and "Sna" not in a.detail, repr(a))
    check("b3 players route: ...a superadmin (who holds Manage a server's databases) sees GUIDs",
          d.get("masked") is False and d.get("players", [{}])[0].get("guid") == "GUIDTWO", repr(d))
    _post273(_p9_client(P9_ADMIN), sid, {"q": "Snake"})
    eq("b3 players route: B3's database name is read from the host once and reused for the next search",
       (len(seen["shells"]), len(seen["runs"])), (1, 2))
    runs = len(seen["runs"])
    bodies = ({"q": ""}, {"q": "x" * 37}, {"q": ["a"]}, {}, {"q": "a", "after": "1;2"})
    bad = [_post273(_p9_client(P9_ADMIN), sid, b)[0] for b in bodies]
    eq("b3 players route: an empty, too long or non-text search, or a bad page mark, is refused (400) before the "
       "database is asked", (bad, len(seen["runs"])), ([400] * 5, runs))


def _guid_route273(sid, uid):
    seen = _stubs273(sid, _xml273([(_PLAYER_COLS273, [("2", "Snake", "12", "1", "1700500000", "")])]))
    st, d = _post273(_p9_client(uid), sid, {"q": "ABCDEF0123"})
    run = seen["runs"][0][3][0] if seen["runs"] else {}
    check("b3 players route: a viewer with Manage add-ons but not Manage a server's databases gets the masked "
          "statement (no GUID selected, a GUID only whole) and is told so",
          st == 200 and d.get("masked") is True and run.get("sql") == _b3_273.SEARCH_SQL[(False, False)]
          and "ABCDEF0123" in run.get("params", []) and "guid" not in d.get("players", [{}])[0], repr((st, d, run))[:400])


def _player_routes273(sid, uid):
    def answer(statements):
        if len(statements) == 1:
            return _xml273([(("id",), [])])
        return _xml273([(("id", "name", "connections", "time_add", "time_edit", "grp", "level"),
                         [("12", "Snake", "3", "1", "2", "Admin", "40")]),
                        (("alias", "num_used", "time_add", "time_edit"), [("Old", "2", "1", "1")]),
                        (("n",), [("4",)]),
                        (("id", "type", "duration", "inactive", "reason", "keyword", "time_add", "time_expire",
                          "admin_id", "admin"), [("9", "Ban", "0", "0", "wall", "", "5", "-1", "0", None)])])
    seen = _stubs273(sid, answer)
    r = _p9_client(uid).get("/api/server/%d/addons/b3/players/12" % sid)
    d = (r.get_json(silent=True) or {}).get("player") or {}
    sql = [s["sql"] for s in seen["runs"][0][3]] if seen["runs"] else []
    eq("b3 players route: one player, for a masked viewer: four reads, the address count and no address, its "
       "penalty as B3's", (r.status_code, len(sql), d.get("address_count"), "ip" in d, d.get("penalties", [{}])[0].get("admin")),
       (200, 4, 4, False, "B3"))
    check("b3 players route: ...the masked statements ran (no IP address or GUID read)",
          sql[:1] == [_b3_273.CLIENT_SQL[False]] and sql[2:3] == [_b3_273.ADDRESSES_SQL[False]], repr(sql))
    a = _p9_audit("b3_player_view")
    check("b3 players route: ...audited with the server and the player's B3 id (who looked up which player)",
          a.success and "@12" in a.detail and "shown" not in a.detail, repr(a))
    runs = len(seen["runs"])
    big = _p9_client(uid).get("/api/server/%d/addons/b3/players/%d" % (sid, _b3_273.ID_MAX + 1))
    eq("b3 players route: an id past B3's column is no player (404) without asking the database",
       (big.status_code, len(seen["runs"])), (404, runs))
    _p9_patch(_dd273, "run", lambda *a, **k: dict(_dd273.parse(_xml273([(("id",), [])] * 4)), rc=0))
    gone = _p9_client(uid).get("/api/server/%d/addons/b3/players/77" % sid)
    eq("b3 players route: an id B3 does not have is said as such (404), not an empty player",
       (gone.status_code, (gone.get_json(silent=True) or {}).get("error")), (404, _rb273.S_NO_PLAYER))


def _states273(sid):
    """(status, error) for a search under each failure: no B3, a database not this server's, no tables, cut short."""
    out = {}
    seen = _stubs273(sid, _xml273([]), status_db="")
    out["no_b3"] = _post273(_p9_client(P9_ADMIN), sid, {"q": "a"}) + (len(seen["runs"]),)
    seen = _stubs273(sid, _xml273([]), status_db="gs1_someone_else")
    out["not_ours"] = _post273(_p9_client(P9_ADMIN), sid, {"q": "a"}) + (len(seen["runs"]),)
    _stubs273(sid, "ERROR 1146 (42S02) at line 9: Table 'gs1_b3players.clients' doesn't exist\n")
    out["no_tables"] = _post273(_p9_client(P9_ADMIN), sid, {"q": "a"}) + (0,)
    _stubs273(sid, _xml273([]).split("<resultset statement=\"EXECUTE")[0])
    out["cut"] = _post273(_p9_client(P9_ADMIN), sid, {"q": "a"}) + (0,)
    _stubs273(sid, _xml273([(_PLAYER_COLS273, [])]))
    out["none"] = _post273(_p9_client(P9_ADMIN), sid, {"q": "zz"}) + (0,)
    return out


def _state_checks273(sid):
    out = _states273(sid)
    eq("b3 players route: no B3 on the server is said, and no database is asked",
       (out["no_b3"][1].get("error"), out["no_b3"][2]), (_rb273.S_NOT_INSTALLED, 0))
    check("b3 players route: a database B3's record names that is another server's is refused unread",
          out["not_ours"][2] == 0 and "gs1_someone_else" in (out["not_ours"][1].get("error") or ""), repr(out["not_ours"]))
    eq("b3 players route: B3's tables not made yet (B3 never started) is said as such",
       out["no_tables"][1].get("error"), _rb273.S_NO_TABLES)
    eq("b3 players route: an answer cut before the statement finished is a failed read (502), never \"no players\"",
       (out["cut"][0], out["cut"][1].get("error")), (502, _rb273.S_UNREAD))
    eq("b3 players route: ...while a search that really found nobody is an empty list (control)",
       (out["none"][0], out["none"][1].get("players")), (200, []))


def _penalty_routes273(sid):
    seen = _stubs273(sid, _xml273([(("id", "type", "duration", "inactive", "reason", "keyword", "time_add", "time_expire",
                                     "admin_id", "admin", "client_id", "player"),
                                    [("31", "TempBan", "60", "0", "camping", "", "5", "1", "2", "Boss", "12", "Snake")])]))
    c = _p9_client(P9_ADMIN)
    r = c.get("/api/server/%d/addons/b3/penalties?kind=bans&before=40" % sid)
    d = r.get_json(silent=True) or {}
    params = seen["runs"][0][3][0].get("params") if seen["runs"] else []
    eq("b3 players route: the latest penalties, bans only, after a given id: the kinds and the mark bound",
       (r.status_code, [(x.get("id"), x.get("player"), x.get("state")) for x in d.get("penalties", [])], params),
       (200, [(31, "Snake", "expired")], ["Ban", "TempBan", None, None, "40", "40"]))
    check("b3 players route: ...audited with the server", _p9_audit("b3_penalties_view").success is True, "")
    bad = [c.get("/api/server/%d/addons/b3/penalties?%s" % (sid, q)).status_code
           for q in ("kind=Notice", "kind=all&before=-1", "kind=all&before=12345678901", "before=1e3",
                     "before=%C2%B2")]
    eq("b3 players route: a kind or a page mark the list did not give is refused (400), a superscript digit too (it "
       "is a digit to str.isdigit and not to int)", bad, [400] * 5)


def _permission_routes273(sid, uid_none, mc_sid):
    seen = _stubs273(sid, _xml273([]))
    c = _p9_client(uid_none)
    codes = [_post273(c, sid, {"q": "a"})[0], c.get("/api/server/%d/addons/b3/players/1" % sid).status_code,
             c.get("/api/server/%d/addons/b3/penalties" % sid).status_code]
    eq("b3 players route: a viewer with server access but without Manage add-ons is refused every route (403), and "
       "neither the host nor the database is asked", (codes, seen["shells"], seen["runs"]), ([403] * 3, [], []))
    other = _post273(_p9_client(P9_ADMIN), mc_sid, {"q": "a"})
    eq("b3 players route: a server whose game B3 does not run is refused (404), unread",
       (other[0], seen["shells"], seen["runs"]), (404, [], []))


def _tab_reuse273(sid):
    seen = _stubs273(sid, _xml273([(_PLAYER_COLS273 + ("guid",), [])]))
    c = _p9_client(P9_ADMIN)
    tab = c.get("/api/server/%d/addons" % sid)
    shells = len(seen["shells"])
    _post273(c, sid, {"q": "a"})
    eq("b3 players route: after the Add-ons tab's own status read, the players section asks the host nothing more "
       "(its B3 database name is reused)", (tab.status_code, shells, len(seen["shells"]), len(seen["runs"])), (200, 1, 1, 1))


def _routes273():
    sid = _p9_new_server(P9_HOST, "cod4b3p273", "cod4", 28973, name="p273-cod4")
    mc_sid = _p9_new_server(P9_HOST, "mcb3p273", "mc", 25573, name="p273-mc")
    with _p9.app_context():
        row = _m273.GameDatabase(remote_id=P9_HOST, game_server_id=sid, name=_DBNAME273, secret=_enc273(_STAND_IN273))
        # Another server's database, under the name a tampered add-on record could give.
        other = _m273.GameDatabase(remote_id=P9_HOST, game_server_id=mc_sid, name="gs1_someone_else",
                                   secret=_enc273(_STAND_IN273))
        _m273.db.session.add_all([row, other])
        _m273.db.session.commit()
        rid, oid = row.id, other.id
    masked, mg = _user273([_auth273.MANAGE_ADDONS], "p273_addons")
    none, ng = _user273([_auth273.VIEW_FILES], "p273_files")
    try:
        _search_routes273(sid)
        _guid_route273(sid, masked)
        _player_routes273(sid, masked)
        _state_checks273(sid)
        _penalty_routes273(sid)
        _permission_routes273(sid, none, mc_sid)
        _tab_reuse273(sid)
    finally:
        _p9_restore_all()
        _b3_273.forget(sid)
        _drop273((_m273.User, masked), (_m273.User, none), (_m273.Group, mg), (_m273.Group, ng),
                 (_m273.GameDatabase, rid), (_m273.GameDatabase, oid))
        _p9_delete_server(sid)
        _p9_delete_server(mc_sid)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The page and its script
# ════════════════════════════════════════════════════════════════════════════════════════════════
_JS273 = open(os.path.join(_root, "panel", "static", "js", "b3_players.js"), encoding="utf-8").read()
_TPL273 = open(os.path.join(_root, "panel", "templates", "_server_addons.html"), encoding="utf-8").read()


def _page273(page):
    check("b3 players page: a member with Manage add-ons gets B3's section and its script on a CoD4 server's Files & "
          "Config page", page[0] == 200 and 'id="b3p"' in page[1] and "js/b3_players.js" in page[1]
          and page[1].index("js/b3_players.js") < page[1].index("js/server_addons.js"), repr(page[0]))
    code = "\n".join(ln.split("//")[0] for ln in _JS273.splitlines())
    check("b3 players page: the script writes no markup from values (no innerHTML, outerHTML, insertAdjacentHTML or "
          "document.write): names, aliases and reasons are what players typed",
          not _re273.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", code), "")
    check("b3 players page: the search text goes in a POST body, never the address",
          _re273.search(r"postJson\(api\('/players/search'\), \{q: st\.q", code) is not None
          and "players/search?" not in code, "")
    check("b3 players page: the section is only on a page whose game B3 runs on, and the Players button only on an "
          "installed B3's row", "{% if 'b3' in addons_tab(server).offered %}" in _TPL273 and "id=\"b3p\"" in _TPL273, "")


def _players_button273():
    src = open(os.path.join(_root, "panel", "static", "js", "server_addons.js"), encoding="utf-8").read()
    prog = ("function node(){ return {appendChild: function(){}, setAttribute: function(){}}; }\n"
            "function button(label, icon, act){ return {act: act}; }\n"
            "function T(s){ return s; } function TF(s){ return s; } function geoSelect(){ return node(); }\n"
            "function ownPlugins(){}\n" + _cut47(src, "function settingsFold(") + "\n"
            "var bar = {kids: [{act: 'adAct'}, {act: 'adLog'}, {act: 'adRemove'}], insertBefore: function(n, ref){"
            " this.kids.splice(this.kids.indexOf(ref), 0, n); }};\n"
            "bar.lastChild = bar.kids[2];\n"
            "settingsFold({id: 'b3', switchable: [], geo_switchable: [], plugins: []}, node(), bar);\n"
            "console.log(JSON.stringify(bar.kids.map(function(k){ return k.act; })));\n")
    got = _node221("add-ons card: B3's Players button", prog)
    if got is not None:
        eq("b3 players page: an installed B3's row gets a Players button, before Remove (it opens the section)",
           got, ["adAct", "adLog", "b3pOpen", "adRemove"])


def _main273():
    _statements273()
    _search_sql273()
    _limits273()
    _answers273()
    _p9_arm(_p9_patch, who="part273")
    try:
        page = _addons_member261()
        _routes273()
    finally:
        _p9_restore_all()
    _page273(page)
    _players_button273()
    check("part273: no check reached a real transport", len(_P9_TRIPPED) == _trips273,
          repr(_P9_TRIPPED[_trips273:][:4]))


_main273()
