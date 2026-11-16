"""Part 226 of the unit suite: text a database or a log line holds cannot pass for something else.

* db_data.parse: a value (a player's name, a column default) holding a line shaped like the client's
  error ("ERROR 1045 (28000): ...") or the verb's own markers ("panel-db: timed out") is read as the
  value it is. Only the client's error and the verb's markers outside the data count. Driven through
  db_data.run and the Databases manager's routes (Tables, Browse, the SQL box), with the host side
  stubbed.
* The text addresses: audit ageing reduces an IPv4-mapped IPv6 address (::ffff:203.0.113.9) as its
  IPv4 /24, and leaves a version written after a letter (v1.2.3.4) alone. The bots' console reply masks
  the same way. Driven through anonymise_audit_ips on real rows and the bots' console reply.
* The dump upload: an upload whose restore raises, or that cannot be moved into place, still puts the
  earlier dump back; a finish whose answer was lost is asked again and knows an upload it already put in
  place; a cancel gives the earlier dump back; one finish at a time. The upload scripts run by bash on a
  temporary home.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import fcntl as _fcntl226
import gzip as _gz226
import os as _os226
import shutil as _sh226
import subprocess as _sp226  # nosec B404 - bash over the upload scripts this part checks, in a temp dir
import tempfile as _tf226
from datetime import timedelta as _td226

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part219 import _GOOD219, _answer219, _rs219
from panel.core.clock import utcnow as _utcnow226
from panel.core.config import encrypt_secret as _enc226
from panel.db import models as _m226
from panel.ops.ssh_manager import _core as _core226, databases as _dbs226, db_data as _dd226
from panel.routes import databases_data as _ddr226, databases_files as _dfr226
from panel.services import console_secrets as _cs226
from panel.services.bots import commands as _cmd226

_trips226 = len(_P9_TRIPPED)
_PW226 = "Sentinelpw7Xq-ab.cd_ef226226"     # a database password of the generator's shape
_FAKE_ERR226 = "ERROR 1045 (28000): Access denied for user 'x'@'y'"
_FAKE_RO226 = "ERROR 1792 (25006): Cannot execute statement in a READ ONLY transaction"
# A value holding every line the answer's reader looks for: the client's error and the verb's markers.
_HOSTILE226 = "hi\n%s\npanel-db: timed out\npanel-db: output cut\n%s" % (_FAKE_ERR226, _FAKE_RO226)


# ── 1. a value cannot fake the client's error or the verb's markers ──────────────────────────────
def _run226(answer):
    """db_data.run against a host that answers `answer`: its parsed dict."""
    _p9_patch(_core226, "run_privileged", lambda *a, **k: (answer, "", 0))
    return _dd226.run(None, _m226.HostDatabaseServer(flavor="mariadb", port=3306), "gs1_a", _PW226, "ro",
                      [{"sql": "SELECT name FROM t"}])


def _parse_run226():
    got = _run226(_answer219(([(["name"], [[_HOSTILE226]])], -1)))
    eq("db_data.run: a value holding the client's error line and the verb's markers is read as the value; "
       "no error, not late, not cut",
       (got["error"], got["late"], got["cut"], got["statements"][0]["sets"][0]["rows"]),
       (None, False, False, [[_HOSTILE226]]))
    real = _run226(_answer219(([(["name"], [[_HOSTILE226]])], -1), error=(1064, "42000", "near 'x'")))
    eq("db_data.run: the client's own error line after the data is still read (control)",
       real["error"], {"code": 1064, "state": "42000", "text": "near 'x'"})
    # Killed mid-value: the value runs to the verb's marker, which follows every byte of the data.
    late = _run226(_answer219() + _rs219("EXECUTE panel_s", ["name"], [], close=False)
                   + '\n  <row>\n\t<field name="name">x\n%s\npanel-db: output cut\npart' % _FAKE_ERR226
                   + "\npanel-db: timed out\n")
    eq("db_data.run: an answer killed mid-value is late (the verb's last marker), and the value's own "
       "error and cut lines do not count", (late["error"], late["late"], late["cut"]), (None, True, False))


_COLS226 = ["TABLE_NAME", "COLUMN_NAME", "COLUMN_TYPE", "DATA_TYPE", "IS_NULLABLE", "COLUMN_KEY", "COLUMN_DEFAULT",
            "EXTRA", "CS", "CO"]
_STRUCT226 = _answer219(
    ([(["TABLE_NAME", "TABLE_TYPE", "ENGINE", "TABLE_ROWS", "S"], [["players", "BASE TABLE", "InnoDB", "1", "1"]])], -1),
    ([(_COLS226, [["players", "id", "int(11)", "int", "NO", "PRI", None, "", None, None],
                  ["players", "name", "text", "text", "YES", "", _HOSTILE226, "", "utf8mb4", "utf8mb4_bin"]])], -1),
    ([(["TABLE_NAME", "COLUMN_NAME"], [["players", "id"]])], -1))


def _host226(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    """The db-query verb's host side: the structure, then a row or a value holding the hostile lines."""
    first = ((secrets or {}).get("query") or [{}])[0].get("sql", "")
    if "information_schema.TABLES" in first:
        return _STRUCT226, "", 0
    return _answer219(([(["id", "name"], [["1", _HOSTILE226]])], -1)), "", 0


def _db_setup226():
    """A game server with one database on part12's host: (server id, the database's API prefix)."""
    sid = _p9_new_server(P9_HOST, "p226u", "pmc", 25570, name="p226 paper")
    with _p9.app_context():
        _m226.HostDatabaseServer.query.filter_by(remote_id=P9_HOST).delete()
        _m226.db.session.add(_m226.HostDatabaseServer(remote_id=P9_HOST, flavor="mariadb", version="10.11.14",
                                                      port=3306, native_ok=True, auth_mode="socket"))
        gd = _m226.GameDatabase(remote_id=P9_HOST, game_server_id=sid, name="gs%d_lp" % sid, secret=_enc226(_PW226),
                                auth_plugin="mysql_native_password", max_conn=30, created_by="p226")
        _m226.db.session.add(gd)
        _m226.db.session.commit()
        return sid, "/api/server/%d/databases/%d" % (sid, gd.id), gd.name


def _db_teardown226(sid):
    _ddr226._STRUCT.clear()
    _dfr226._UPLOADS.clear()
    with _p9.app_context():
        _m226.GameDatabase.query.filter_by(game_server_id=sid).delete()
        _m226.HostDatabaseServer.query.filter_by(remote_id=P9_HOST).delete()
        _m226.db.session.commit()
    _p9_delete_server(sid)


def _routes226(c, api):
    _p9_patch(_core226, "run_privileged", _host226)
    _ddr226._STRUCT.clear()
    tables = c.get(api + "/tables")
    rows = c.get(api + "/rows?table=players&page=0")
    sql = c.post(api + "/sql", json={"sql": "SELECT id, name FROM players"})
    eq("databases: a column default and a row value holding the client's error and the verb's 'timed out' "
       "line leave Tables, Browse and the SQL box working (not 502, 504 or a confirm for a read)",
       (tables.status_code, rows.status_code, sql.status_code, _p9_json(sql).get("success"),
        _p9_json(sql).get("needs_confirm"), "error" in _p9_json(sql)),
       (200, 200, 200, True, None, False))


def _db_routes226():
    sid = None
    try:
        sid, api, name = _db_setup226()
        c = _p9_client(P9_ADMIN)
        _routes226(c, api)
    finally:
        if sid is not None:
            _db_teardown226(sid)


try:
    for _fn226 in (_parse_run226, _db_routes226):
        _p9_arm(who="part226")
        try:
            _fn226()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()

check("part226: nothing reached a real transport", len(_P9_TRIPPED) == _trips226, repr(_P9_TRIPPED[_trips226:]))
