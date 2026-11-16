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


# ── 3. an upload whose restore raises puts the earlier dump back ─────────────────────────────────
def _upload_raises226(c, api, name):
    cmds = []

    def _cmd(server, cmd, timeout=30, sudo=True, **kw):
        cmds.append(cmd)
        if ".piece" in cmd:
            return "__DBUP_SIZE__ 10", "", 0
        return ("__DBUP_STORED__" if "awk -v me=" in cmd else "__DBUP_READY__"), "", 0

    def _boom(*a, **k):
        raise OSError("the transport dropped")
    _p9_patch_sm("run_command", _cmd)
    _p9_patch(_dfr226, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch(_dbs226, "restore", _boom)
    uid = _p9_json(c.post(api + "/upload", json={"size": 10})).get("id", "")
    c.post(api + "/upload/%s?offset=0" % uid, data=b"0123456789")
    n = len(cmds)
    r = c.post(api + "/upload/%s/finish" % uid, json={"confirm": name})
    settle = [x for x in cmds[n:] if ".prev" in x and "awk -v me=" not in x]
    check("upload: a restore that raises still runs the settle step that puts the earlier dump back "
          "(.prev moved over the upload), and answers a failure",
          r.status_code >= 500 and len(settle) == 1 and "mv -f -- " in settle[0] and ".prev " in settle[0],
          repr((r.status_code, cmds[n:])))


def _upload_lost226(c, api, name):
    """A finish whose answer is lost answers retry and keeps the upload; asked again, it restores."""
    said = {"finish": ["", "__DBUP_STORED__"]}
    _p9_patch_sm("run_command", lambda server, cmd, timeout=30, sudo=True, **kw: (
        "__DBUP_SIZE__ 10" if ".piece" in cmd else (said["finish"].pop(0) if "awk -v me=" in cmd else "__DBUP_READY__"),
        "", 0))
    _p9_patch(_dbs226, "restore", lambda *a, **k: (True, ""))
    uid = _p9_json(c.post(api + "/upload", json={"size": 10})).get("id", "")
    c.post(api + "/upload/%s?offset=0" % uid, data=b"0123456789")
    first = _p9_json(c.post(api + "/upload/%s/finish" % uid, json={"confirm": name}))
    again = _p9_json(c.post(api + "/upload/%s/finish" % uid, json={"confirm": name}))
    eq("upload: a finish whose answer was lost says retry and keeps the upload; asked again it restores",
       (first.get("retry"), first.get("success"), again.get("success"), again.get("retry")), (True, False, True, None))


def _db_routes226():
    sid = None
    try:
        sid, api, name = _db_setup226()
        c = _p9_client(P9_ADMIN)
        _routes226(c, api)
        _upload_raises226(c, api, name)
        _upload_lost226(c, api, name)
    finally:
        if sid is not None:
            _db_teardown226(sid)


_T226 = _tf226.mkdtemp(prefix="lgsm-unit-p226-")
_HOME226 = _os226.path.join(_T226, "home", "gm226")
_DD226 = _os226.path.join(_HOME226, "panel-db-dumps")
_UID226 = "cd" * 16
_PART226 = _os226.path.join(_DD226, ".panel-upload-%s.part" % _UID226)
_DEST226 = _os226.path.join(_DD226, "gs12_lp.sql.gz")
_EARLIER226 = b"-- the earlier dump\n"


def _bash226(script, path=None):
    """The upload command `script` run by bash on this part's temp home: outcome()."""
    sh = script.replace("/home/gm226", _HOME226)
    env = dict(_os226.environ, PATH=path + ":" + _os226.environ.get("PATH", "")) if path else None
    p = _sp226.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60, check=False, env=env)  # nosec B603 B607
    return _dfr226.outcome(p.stdout + p.stderr)


def _fresh226():
    """An earlier dump in place and a whole upload on the host, ready for the finish."""
    _sh226.rmtree(_DD226, ignore_errors=True)
    _bash226(_dfr226.start_script("gm226", _UID226, 1))
    with open(_DEST226, "wb") as fh:
        fh.write(_gz226.compress(_EARLIER226))
    with open(_PART226, "wb") as fh:
        fh.write(_GOOD219.encode())
    return _dfr226.finish_script("gm226", _UID226, len(_GOOD219.encode()), "gs12_lp")


def _held226():
    """(what <name>.sql.gz holds or None, whether a .prev is left, the upload's own files left)."""
    held = None
    if _os226.path.exists(_DEST226):
        with _gz226.open(_DEST226, "rb") as fh:
            held = fh.read()
    return held, _os226.path.exists(_DEST226 + ".prev"), sorted(f for f in _os226.listdir(_DD226)
                                                                 if f.startswith(".panel-upload-"))


def _host_upload226():
    finish = _fresh226()
    lost = (_bash226(finish), _bash226(finish), _held226())
    _bash226(_dfr226.settle_script("gm226", "gs12_lp", False, _UID226))
    eq("upload finish asked again: an upload already put in place answers STORED again (the earlier dump still "
       "kept aside); the failed restore's settle puts the earlier dump back and leaves no mark; a third ask finds "
       "no upload", (lost, _held226(), _bash226(finish)),
       ((("ok", ""), ("ok", ""), (_GOOD219.encode(), True, [".panel-upload-%s.part.stored" % _UID226])),
        (_EARLIER226, False, []), ("refused", "NOPART")))
    finish = _fresh226()
    stored = _bash226(finish)
    eq("upload cancel: an upload put in place but never restored gives the earlier dump back, and nothing of "
       "the upload is left", (stored, _bash226(_dfr226.cancel_script("gm226", _UID226, "gs12_lp")), _held226()),
       (("ok", ""), ("ok", ""), (_EARLIER226, False, [])))
    # The move into place fails (a stand-in mv refusing the part file): the dump kept aside goes back.
    shim = _os226.path.join(_T226, "bin")
    _os226.makedirs(shim, exist_ok=True)
    with open(_os226.path.join(shim, "mv"), "w", encoding="utf-8") as fh:
        fh.write('#!/bin/bash\ncase "$3" in *.part) exit 1;; esac\nexec /bin/mv "$@"\n')
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in in this part's temp dir
    _os226.chmod(_os226.path.join(shim, "mv"), 0o700)  # nosec B103 - owner-only stand-in program in a temp dir
    eq("upload finish: when the upload cannot be moved into place, the earlier dump is put back",
       (_bash226(_fresh226(), path=shim), _held226()), (("refused", "FAIL"), (_EARLIER226, False, [])))


def _host_lock226():
    finish = _fresh226()
    if not _sh226.which("flock"):
        skip("upload finish: one asked while another still runs gives no answer", "no flock on this machine")
        return
    with open(_PART226 + ".lock", "a", encoding="utf-8") as lock:
        _fcntl226.flock(lock, _fcntl226.LOCK_EX | _fcntl226.LOCK_NB)
        busy = (_bash226(finish), _held226())
    eq("upload finish: one asked while another still runs gives no answer (read as ask again) and touches "
       "nothing; once that one ends, the finish runs and its lock file goes", (busy, _bash226(finish), _held226()[2]),
       ((("unread", ""), (_EARLIER226, False, [".panel-upload-%s.part" % _UID226,
                                               ".panel-upload-%s.part.lock" % _UID226])),
        ("ok", ""), [".panel-upload-%s.part.stored" % _UID226]))


# ── 2. addresses in text: mapped IPv6, versions ──────────────────────────────────────────────────
def _audit_text226():
    now = _utcnow226()
    seed = (("from ::ffff:203.0.113.9", "::ffff:198.51.100.7"), ("game v1.2.3.4 build 1.40.2.4 at 12:30:45 via 12:00:203.0.113.5", ""),
            ("ip:2001:db8:1:2::5, 64:ff9b::192.0.2.33", ""))
    ids = []
    with _p9.app_context():
        for detail, ip in seed:
            row = _m226.AuditLog(username="p226", action="login", target="", detail=detail, ip_address=ip,
                                 timestamp=now - _td226(days=200))
            _m226.db.session.add(row)
            _m226.db.session.commit()
            ids.append(row.id)
        try:
            _m226.anonymise_audit_ips(90)
            again = _m226.anonymise_audit_ips(90)
            got = [(r.detail, r.ip_address) for r in (_m226.db.session.get(_m226.AuditLog, i) for i in ids)]
        finally:
            for i in ids:
                row = _m226.db.session.get(_m226.AuditLog, i)
                if row is not None:
                    _m226.db.session.delete(row)
            _m226.db.session.commit()
    eq("audit ageing: an IPv4-mapped address (text and column) is reduced to its IPv4 /24; a version after a "
       "letter and a clock time stay; a bare 1.40.2.4 is an address, and so is one after a clock time; a second run "
       "changes nothing",
       (got, again),
       ([("from 203.0.113.0/24", "198.51.100.0/24"),
         ("game v1.2.3.4 build 1.40.2.0/24 at 12:30:45 via 12:00:203.0.113.0/24", ""),
         ("ip:2001:db8:1:2::/64, 64:ff9b::/64", "")], 0))


def _bot_console226():
    line = "Client \"bob\" connected (::ffff:203.0.113.9:27005) from 203.0.113.7 on v1.40.2.4 at 12:34:56"
    _p9_patch_sm("capture_console", lambda *a, **k: (line, "", 0))
    _p9_patch(_cs226, "mask_for", lambda gs, text: text)
    _p9_patch(_cmd226, "load_config", lambda: {"notifications": {}})
    got = _cmd226._console_text(_p9, "p9-cs")
    check("bots: a console reply masks a mapped IPv6 address whole and a plain IPv4 one, and keeps a version "
          "written after a letter and the clock time",
          "([address]:27005) from [address] on v1.40.2.4 at 12:34:56" in got and "203.0.113" not in got, got)


try:
    for _fn226 in (_parse_run226, _db_routes226, _host_upload226, _host_lock226, _audit_text226, _bot_console226):
        _p9_arm(who="part226")
        try:
            _fn226()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _sh226.rmtree(_T226, ignore_errors=True)

check("part226: nothing reached a real transport", len(_P9_TRIPPED) == _trips226, repr(_P9_TRIPPED[_trips226:]))
