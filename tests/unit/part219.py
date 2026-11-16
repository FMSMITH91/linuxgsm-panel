r"""Part 219 of the unit suite: the Databases manager (browse, edit rows, run SQL, dumps).

* The db-query verb, both copies (privileged.py, tools/panel-helper): the same script from the same
  request; a statement and every value reach the client as hexadecimal only, through PREPARE /
  EXECUTE ... USING; a request that does not fit is refused; no password on any command line.
* The helper's db-query through its real main(), and the remote rendering through bash, against a
  stand-in client: the sign-in file is the only option file (--defaults-file), --binary-mode and the
  database are on its command line, the answer is scrubbed of the password, cut at its size limit,
  and a run that outlives its time limit is killed and its statement ended with KILL QUERY.
* db-import runs its client in --binary-mode on both paths (no client command in a dump).
* ssh_manager.db_data: the XML answer read (NULL told from 'NULL', escapes, a cut answer), identifiers
  only from the structure and quoted, values as parameters, the SQL box's read/write split and the
  audit text with its literals masked.
* The routes through part12's app, with the host side recorded: the permission matrix (Manage
  databases browses, Edit database data changes rows and runs SQL), an unknown table refused before
  the host is asked, a change confirmed against exactly its statement, a "read" that writes sent to
  the confirm step, the step-up confirm before delete, restore, reset and an upload, a dump made as
  the database's own account, the upload checked on the host before it is restored.
* The upload's finish script, run by bash on a temporary home: hostile dumps refused, a plain one
  gzipped and put in place.
Nothing reaches a host, a database server or data/.
"""
import gzip as _gz219
import importlib.machinery as _mach219
import importlib.util as _ilu219
import io as _io219
import os as _os219
import shutil as _sh219
import subprocess as _sp219  # nosec B404 - bash over the renderings this part checks, in a temp dir
import sys as _sys219
import tempfile as _tf219
import time as _time219

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_new_server,
                         _p9_patch, _p9_restore_all)
from panel.db.models import (AuditLog as _AL219, GameDatabase as _GD219, Group as _G219, HostDatabaseServer as _HD219,
                             RemoteServer as _RS219, User as _U219, db as _db219)
from panel.ops.ssh_manager import _core as _core219, databases as _dbs219, db_data as _dd219
from panel.routes import databases as _dbr219, databases_data as _ddr219, databases_files as _dfr219
from panel.security import auth as _auth219, privileged as _priv219
from panel.core.config import encrypt_secret as _enc219

_trips219 = len(_P9_TRIPPED)
_K219 = "Sentinelpw7Xq-ab.cd_ef012345"     # a database password of the generator's shape
_T219 = _tf219.mkdtemp(prefix="lgsm-unit-p219-")

# A fresh copy of the helper: this part changes its TOOLS and limits, and part05's copy is shared.
_spec219 = _ilu219.spec_from_loader("ph219", _mach219.SourceFileLoader("ph219", _os219.path.join(_root, "tools",
                                                                                                "panel-helper")))
_h219 = _ilu219.module_from_spec(_spec219)
_spec219.loader.exec_module(_h219)


def _refused219(fn, *a):
    try:
        fn(*a)
        return False
    except ValueError:
        return True


# ── 1. the verb's script, both copies ────────────────────────────────────────────────────────────
_HOSTILE219 = "x'; DROP TABLE t; -- \\! id\nsystem id\n\\. /etc/shadow é`\x00"
_RUNS219 = [
    ("mariadb", "ro", [{"sql": "SELECT * FROM `t` WHERE `a` = ? AND `b` = ?", "params": [_HOSTILE219, None], "cap": 51}]),
    ("mysql", "rw", [{"sql": _HOSTILE219}]),
    ("mariadb", "rw", [{"sql": "UPDATE t SET a = ?", "params": [""]}, {"sql": "SELECT 1", "cap": 3}]),
]
_scripts219 = [(_priv219.db_query_script(f, m, r), _h219.db_query_script(f, m, r)) for f, m, r in _RUNS219]
check("db-query: both copies make the same script from the same request",
      all(a == b for a, b in _scripts219), repr([a == b for a, b in _scripts219]))
_text219 = "\n".join(a for a, _b in _scripts219)
check("db-query: a statement and its values reach the client as hex only (no quote, backslash, DROP, NUL or "
      "client command of theirs in the script)",
      "DROP" not in _text219 and "\\" not in _text219 and "system id" not in _text219 and "\x00" not in _text219
      and "shadow" not in _text219 and _priv219.db_query_hex(_HOSTILE219) in _text219, _text219[:400])
check("db-query: each statement is PREPAREd from its hex and EXECUTEd with its values bound (USING), a NULL as "
      "NULL, its row count read after it, a cap set and reset around it",
      "SET @panel_p0 = X'" in _scripts219[0][0] and "@panel_p1 = NULL" in _scripts219[0][0]
      and "EXECUTE panel_s USING @panel_p0, @panel_p1;\nSELECT ROW_COUNT() AS panel_rows;" in _scripts219[0][0]
      and "SET SESSION sql_select_limit = 51;" in _scripts219[0][0]
      and "SET SESSION sql_select_limit = DEFAULT;" in _scripts219[0][0], _scripts219[0][0])
check("db-query: ro runs in a READ ONLY transaction that is rolled back; rw does not",
      "START TRANSACTION READ ONLY;" in _scripts219[0][0] and _scripts219[0][0].rstrip().endswith("ROLLBACK;")
      and "READ ONLY" not in _scripts219[1][0] and "ROLLBACK" not in _scripts219[1][0])
check("db-query: MariaDB limits every statement (max_statement_time), MySQL its SELECTs (max_execution_time, "
      "in ms), both with short lock waits",
      "SET SESSION max_statement_time=30;" in _scripts219[0][0]
      and "SET SESSION max_execution_time=30000;" in _scripts219[1][0]
      and "max_statement_time" not in _scripts219[1][0]
      and all("SET SESSION innodb_lock_wait_timeout=10;" in a for a, _b in _scripts219))
_BAD_RUNS219 = [None, [], [{"sql": ""}], [{"sql": "  "}], [{"sql": "x", "cap": True}], [{"sql": "x", "cap": -1}],
                [{"sql": "x", "cap": 10001}], [{"sql": "x", "params": "a"}], [{"sql": "x", "params": [1]}],
                [{"sql": "x", "params": [["a"]]}], [{"sql": "x", "extra": 1}], [{"sql": 1}],
                [{"sql": "x" * 65537}], [{"sql": "x"}] * 5, [{"sql": "x", "params": [None] * 513}],
                [{"sql": "x", "params": ["y" * 65537]}], [{"sql": "\ud800"}]]
_both219 = [(_refused219(_priv219.db_query_script, "mariadb", "ro", r), _refused219(_h219.db_query_script, "mariadb", "ro", r))
            for r in _BAD_RUNS219]
eq("db-query: a request that does not fit (no statement, empty, a bad cap, values that are not text or NULL, too "
   "long, too many) is refused by both copies", _both219, [(True, True)] * len(_BAD_RUNS219))
eq("db-query: an unknown flavor or mode is refused by both copies",
   [_refused219(m.db_query_script, f, md, [{"sql": "SELECT 1"}]) for m in (_priv219, _h219)
    for f, md in (("percona", "ro"), ("mariadb", "rwx"))], [True] * 4)
_args219 = ["mariadb", "3306@100.70.1.2", "gs12_lp", "ro"]
_q219 = [{"sql": "SELECT ?", "params": [_HOSTILE219]}]
eq("db-query: the verb's arguments are checked in both copies (a non-panel name, a non-tailnet address, a bad mode)",
   [_refused219(_priv219.check_args, "db-query", a) for a in (["mariadb", "3306", "mysql", "ro"],
                                                              ["mariadb", "3306@8.8.8.8", "gs12_lp", "ro"],
                                                              ["mariadb", "3306", "gs12_lp", "write"])],
   [True, True, True])
check("db-query: no password or statement on the helper's argv or in the remote command line; both on stdin",
      _K219 not in " ".join(_priv219.helper_argv("db-query", _args219))
      and _K219 not in _priv219.remote_command("db-query", _args219)
      and "SELECT" not in _priv219.remote_command("db-query", _args219)
      and _K219 in _priv219.helper_stdin("db-query", _args219, {"pw": _K219, "query": _q219})
      and _K219 in _priv219.remote_stdin("db-query", _args219, {"pw": _K219, "query": _q219}))
_doc219 = _priv219.helper_stdin("db-query", _args219, {"pw": _K219, "query": _q219})
check("db-query: the helper's stdin is the sign-in document, then the request as JSON after its end line",
      _doc219.startswith("pw %s\nend\n{" % _K219) and '"run":' in _doc219, _doc219[:80])
check("db-query: the helper runs it to its end (not a read a signal may stop) and reads its stdin",
      "db-query" not in _h219.READ_VERBS and "db-query" in _h219.STDIN_VERBS and "db-query" in _priv219.DB_PW_VERBS)
check("db-query and db-import: the client runs with --binary-mode on both paths (no client command but DELIMITER "
      "in what it reads)",
      "--binary-mode" in _priv219.DB_QUERY_OPTS and "--binary-mode" in _h219.DB_QUERY_OPTS
      and "--binary-mode --batch" in _priv219.remote_command("db-import", ["mariadb", "3306", "gm219", "gs12_lp"])
      and '"--binary-mode", "--batch", name]' in open(_os219.path.join(_root, "tools", "panel-helper"),
                                                       encoding="utf-8").read())

# ── 2 + 3. the helper's verb and its remote rendering, against a stand-in client ─────────────────
_O219 = _os219.path.join(_T219, "o")
_BIN219 = _os219.path.join(_T219, "bin")
for _d219 in (_O219, _BIN219):
    _os219.makedirs(_d219, exist_ok=True)
_FAKE219 = r'''#!/bin/bash
O=__O__
for a in "$@"; do case "$a" in "KILL QUERY"*) echo "$a" > "$O/kill"; exit 0;; esac; done
printf '%s\n' "$@" > "$O/argv"
for a in "$@"; do case "$a" in --defaults-file=*) cat "${a#*=}" > "$O/def";; --defaults-extra-file=*) echo extra > "$O/extra";; esac; done
cat > "$O/stdin"
if [ -f "$O/late" ]; then
  printf '<resultset statement="SELECT CONNECTION_ID() AS panel_conn" x="y">\n  <row>\n'
  printf '\t<field name="panel_conn">77</field>\n  </row>\n</resultset>\n'; exec sleep 20
fi
if [ -f "$O/big" ]; then head -c 3000000 /dev/zero | tr '\0' 'a'; exit 0; fi
cat "$O/answer"; echo "ERROR 1064 (42000) at line 9: near '$(grep -o 'password=.*' "$O/def")'" >&2; exit 1
'''
_ANSWER219 = ('<?xml version="1.0"?>\n\n<resultset statement="SELECT CONNECTION_ID() AS panel_conn\n" xmlns:xsi="x">\n'
              '  <row>\n\t<field name="panel_conn">42</field>\n  </row>\n</resultset>\n')
for _n219 in ("mariadb", "mysql"):
    with open(_os219.path.join(_BIN219, _n219), "w", encoding="utf-8") as _fh219:
        _fh219.write(_FAKE219.replace("__O__", _O219))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in in this part's temp dir
    _os219.chmod(_os219.path.join(_BIN219, _n219), 0o700)  # nosec B103 - owner-only stand-in program in a temp dir


def _rec219(name):
    p = _os219.path.join(_O219, name)
    return open(p, encoding="utf-8").read() if _os219.path.exists(p) else None


def _reset219(**files):
    for e in _os219.listdir(_O219):
        _os219.unlink(_os219.path.join(_O219, e))
    files.setdefault("answer", _ANSWER219)
    for k, v in files.items():
        with open(_os219.path.join(_O219, k), "w", encoding="utf-8") as fh:
            fh.write(v)


def _h_run219(args, query):
    doc = _priv219.helper_stdin("db-query", args, {"pw": _K219, "query": query})
    saved = (_sys219.stdin, _sys219.stdout, _sys219.stderr)
    _sys219.stdin, _sys219.stdout, _sys219.stderr = _io219.StringIO(doc), _io219.StringIO(), _io219.StringIO()
    try:
        rc = _h219.main(["panel-helper", "db-query"] + list(args))
        return rc, _sys219.stdout.getvalue() + _sys219.stderr.getvalue()
    finally:
        _sys219.stdin, _sys219.stdout, _sys219.stderr = saved


def _r_run219(args, query, swap=None):
    sh = _priv219.remote_command("db-query", args)
    if swap:
        sh = sh.replace(*swap)
    p = _sp219.run(["bash", "-c", "export PATH=%s:$PATH; %s" % (_BIN219, sh)],  # nosec B603 B607
                   input=_priv219.remote_stdin("db-query", args, {"pw": _K219, "query": query}),
                   capture_output=True, text=True, timeout=60, check=False)
    return p.returncode, p.stdout + p.stderr


_HSAVE219 = (_h219.TOOLS, _h219.DB_QUERY_SECONDS)
_h219.TOOLS = dict(_h219.TOOLS, mariadb=(_os219.path.join(_BIN219, "mariadb"),),
                   mysql=(_os219.path.join(_BIN219, "mysql"),))
_R219 = {}
try:
    for _how219, _fn219 in (("helper", _h_run219), ("remote", _r_run219)):
        _reset219()
        _rc219, _out219 = _fn219(["mariadb", "3306", "gs12_lp", "ro"], _q219)
        _R219[_how219] = (_rc219, _out219, (_rec219("argv") or "").split("\n"), _rec219("stdin") or "",
                          _rec219("def") or "", _rec219("extra"))
        _reset219(big="1")
        _R219[_how219 + "_big"] = _fn219(["mysql", "3306", "gs12_lp", "rw"], _q219)
        _reset219(late="1")
        _t0219 = _time219.monotonic()
        if _how219 == "helper":
            _h219.DB_QUERY_SECONDS = -3
            _late219 = _fn219(["mariadb", "3306", "gs12_lp", "rw"], _q219)
            _h219.DB_QUERY_SECONDS = _HSAVE219[1]
        else:
            _late219 = _fn219(["mariadb", "3306", "gs12_lp", "rw"], _q219, ("timeout -s KILL 35", "timeout -s KILL 2"))
        _R219[_how219 + "_late"] = (_late219, _time219.monotonic() - _t0219, _rec219("kill"))
finally:
    _h219.TOOLS, _h219.DB_QUERY_SECONDS = _HSAVE219

for _how219 in ("helper", "remote"):
    _rc219, _out219, _argv219, _stdin219, _def219, _extra219 = _R219.get(_how219, (None, "", [], "", "", None))
    check("db-query %s: the client reads ONLY the sign-in file (--defaults-file, first), connects over TCP, runs "
          "with --binary-mode, and the database is its default" % _how219,
          _argv219[:1] and _argv219[0].startswith("--defaults-file=") and "--protocol=tcp" in _argv219
          and "--binary-mode" in _argv219 and "--xml" in _argv219 and "gs12_lp" in _argv219 and _extra219 is None,
          repr(_argv219))
    check("db-query %s: the sign-in file is the database's own account" % _how219,
          _def219 == _priv219.db_defaults_text("gs12_lp", _K219), repr(_def219))
    eq("db-query %s: the client reads exactly the script privileged.py makes" % _how219,
       _stdin219, _priv219.db_query_script("mariadb", "ro", _q219))
    check("db-query %s: the answer comes back with the client's rc" % _how219,
          _rc219 == 1 and "panel_conn" in _out219 and "ERROR 1064" in _out219, repr((_rc219, _out219[-200:])))
    _bigrc219, _bigout219 = _R219.get(_how219 + "_big", (None, ""))
    check("db-query %s: an answer larger than its limit is cut there and said so" % _how219,
          _bigrc219 == 0 and _bigout219.rstrip().endswith("panel-db: output cut")
          and _priv219.DB_QUERY_OUT_MAX <= len(_bigout219) < _priv219.DB_QUERY_OUT_MAX + 100,
          repr((_bigrc219, len(_bigout219))))
    (_lrc219, _lout219), _lt219, _kill219 = _R219.get(_how219 + "_late", ((None, ""), 99, None))
    check("db-query %s: a run past its time limit is killed, its statement ended with KILL QUERY on its own "
          "connection, and the answer says it timed out (124)" % _how219,
          _lrc219 == 124 and "panel-db: timed out" in _lout219 and (_kill219 or "").strip() == "KILL QUERY 77"
          and _lt219 < 15, repr((_lrc219, _lout219[-60:], _kill219, _lt219)))
check("db-query helper: the client's words are scrubbed of the password before they are passed on",
      _K219 not in _R219.get("helper", (0, _K219))[1] and "***" in _R219.get("helper", (0, ""))[1])

# ── 4. ssh_manager.db_data ───────────────────────────────────────────────────────────────────────
_RS_HEAD219 = '<?xml version="1.0"?>\n\n<resultset statement="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'


def _rs219(statement, names, rows, close=True):
    """One resultset as the client's --xml writes it (values escaped as xmlencode_print does)."""
    out = _RS_HEAD219 % statement.replace("&", "&amp;").replace('"', "&quot;")
    for r in rows:
        out += "\n  <row>\n"
        for n, v in zip(names, r):
            if v is None:
                out += '\t<field name="%s" xsi:nil="true" />\n' % n
            else:
                out += '\t<field name="%s">%s</field>\n' % (n, v.replace("&", "&amp;").replace("<", "&lt;")
                                                           .replace(">", "&gt;").replace('"', "&quot;"))
        out += "  </row>\n"
    return out + ("</resultset>\n" if close else "")


def _answer219(*statements, error=None, tail=""):
    """A db-query answer: the connection id, then each statement's resultsets and its row count."""
    out = _rs219("SELECT CONNECTION_ID() AS panel_conn\n", ["panel_conn"], [["42"]])
    for sets, affected in statements:
        for names, rows in sets:
            out += _rs219("EXECUTE panel_s", names, rows)
        out += _rs219("SELECT ROW_COUNT() AS panel_rows", ["panel_rows"], [[str(affected)]])
    if error:
        out += "ERROR %d (%s) at line 9: %s\n" % error
    return out + tail


_p219 = _dd219.parse(_answer219(([(["a", "b", "c"], [["NULL", None, 'x </field> &amp; "q" <row>']])], -1)))
eq("db_data.parse: NULL is told from the text NULL, and escaped text comes back as typed",
   _p219["statements"][0]["sets"][0]["rows"], [["NULL", None, 'x </field> &amp; "q" <row>']])
eq("db_data.parse: the connection id, the statement's columns and its row count", (
    _p219["conn"], _p219["statements"][0]["sets"][0]["columns"], _p219["statements"][0]["affected"], _p219["error"]),
   ("42", ["a", "b", "c"], -1, None))
_cut219 = _dd219.parse(_rs219("SELECT CONNECTION_ID() AS panel_conn", ["panel_conn"], [["5"]])
                       + _rs219("EXECUTE panel_s", ["a"], [["1"], ["2"]], close=False) + "\n  <row>\n\t<field nam"
                       + "\npanel-db: output cut\n")
check("db_data.parse: an answer cut mid-row keeps the whole rows before the cut, and says it was cut",
      _cut219["cut"] and _cut219["pending"] == [{"columns": ["a"], "rows": [["1"], ["2"]]}]
      and _cut219["statements"] == [], repr(_cut219))
_err219 = _dd219.parse(_answer219(error=(1146, "42S02", "Table 'gs1_a.t' doesn't exist")))
eq("db_data.parse: the client's error line", _err219["error"],
   {"code": 1146, "state": "42S02", "text": "Table 'gs1_a.t' doesn't exist"})

_STRUCT_ANS219 = _answer219(
    ([(["TABLE_NAME", "TABLE_TYPE", "ENGINE", "TABLE_ROWS", "S"],
       [["players", "BASE TABLE", "InnoDB", "12", "16384"], ["we`ird", "BASE TABLE", "InnoDB", "1", "1"],
        ["nokey", "BASE TABLE", "InnoDB", None, None], ["v", "VIEW", None, None, None]])], -1),
    ([(["TABLE_NAME", "COLUMN_NAME", "COLUMN_TYPE", "DATA_TYPE", "IS_NULLABLE", "COLUMN_KEY", "COLUMN_DEFAULT",
        "EXTRA", "CS", "CO"],
       [["players", "id", "int(11)", "int", "NO", "PRI", None, "auto_increment", None, None],
        ["players", "name", "varchar(64)", "varchar", "YES", "", "NULL", "", "utf8mb4", "utf8mb4_unicode_ci"],
        ["players", "skin", "blob", "blob", "YES", "", None, "", None, None],
        ["players", "len", "int(11)", "int", "YES", "", None, "VIRTUAL GENERATED", None, None],
        ["we`ird", "k`ey", "varchar(9)", "varchar", "NO", "PRI", None, "", "latin1", "latin1_swedish_ci"],
        ["we`ird", "v", "text", "text", "YES", "", None, "", "utf8mb4", "bad collation name!"],
        ["nokey", "x", "int(11)", "int", "YES", "", None, "", None, None],
        ["v", "id", "int(11)", "int", "NO", "", None, "", None, None]])], -1),
    ([(["TABLE_NAME", "COLUMN_NAME"], [["players", "id"], ["we`ird", "k`ey"]])], -1))
_tables219 = _dd219.structure(_dd219.parse(_STRUCT_ANS219))
_pl219, _wd219 = (_tables219 or {}).get("players"), (_tables219 or {}).get("we`ird")
check("db_data.structure: tables, their columns and primary keys from information_schema",
      _tables219 is not None and sorted(_tables219) == sorted(["players", "v", "we`ird", "nokey"])
      and _pl219["pk"] == ["id"] and _pl219["rows"] == 12
      and [c["name"] for c in _pl219["columns"]] == ["id", "name", "skin", "len"]
      and _pl219["columns"][2]["binary"] and _pl219["columns"][3]["generated"]
      and _wd219["columns"][1]["collation"] == "", repr(_tables219)[:400])
eq("db_data.editable: a view and a table with no primary key are read-only; the others are not",
   {n: _dd219.editable(t) for n, t in (_tables219 or {}).items()},
   {"players": "", "we`ird": "", "nokey": "no_key", "v": "view"})
check("db_data.structure: an answer with an error or a statement missing is not a structure",
      _dd219.structure(_err219) is None and _dd219.structure(_dd219.parse(_answer219(([], -1)))) is None)
eq("db_data.quote_ident: a backtick inside a name is doubled; an empty, NUL or over-long name is refused",
   [_dd219.quote_ident("we`ird"), _refused219(_dd219.quote_ident, ""), _refused219(_dd219.quote_ident, "a\x00"),
    _refused219(_dd219.quote_ident, "x" * 65)], ["`we``ird`", True, True, True])
_rows_st219 = _dd219.rows_statement(_pl219, 2)
eq("db_data.rows_statement: key columns whole, text cut server-side, binary as its length, ordered by the key, a "
   "fixed page of 50 (+1 to tell there are more)", _rows_st219,
   {"sql": "SELECT `id`, REPLACE(CONVERT(LEFT(`name`, 257) USING utf8mb4), _utf8mb4 X'00', _utf8mb4 X'E29080'), "
           "LENGTH(`skin`), REPLACE(CONVERT(LEFT(`len`, 257) USING utf8mb4), _utf8mb4 X'00', _utf8mb4 X'E29080') "
           "FROM `players` ORDER BY `id` LIMIT 51 OFFSET 100"})
check("db_data.rows_statement: a page past the last is the last",
      _dd219.rows_statement(_pl219, 10 ** 9)["sql"].endswith(" LIMIT 51 OFFSET %d" % (_dd219.PAGE_MAX * 50)))
eq("db_data.update_statement: names from the structure, quoted; every value and the key bound as parameters; a "
   "text key compared in the column's own character set and collation; one row at most",
   _dd219.update_statement(_wd219, {"k`ey": "a'b"}, {"v": {"value": "x'); DROP TABLE t; --"}}),
   {"sql": "UPDATE `we``ird` SET `v` = CONVERT(? USING utf8mb4) WHERE `k``ey` = CONVERT(CONVERT(? USING utf8mb4) "
           "USING latin1) COLLATE latin1_swedish_ci LIMIT 1", "params": ["x'); DROP TABLE t; --", "a'b"]})
eq("db_data.insert_statement: a NULL, a number as text for the server to convert",
   _dd219.insert_statement(_pl219, {"name": {"null": True}, "id": {"value": "7"}}),
   {"sql": "INSERT INTO `players` (`name`, `id`) VALUES (?, ?)", "params": [None, "7"]})
eq("db_data.delete_statement", _dd219.delete_statement(_pl219, {"id": "7"}),
   {"sql": "DELETE FROM `players` WHERE `id` = ? LIMIT 1", "params": ["7"]})
eq("db_data: a column not in the structure, a binary or generated one, NULL in a NOT NULL one, a partial or extra "
   "key, or a value that is not text is refused before any statement exists",
   [_refused219(_dd219.update_statement, _pl219, {"id": "1"}, {"nope": {"value": "1"}}),
    _refused219(_dd219.update_statement, _pl219, {"id": "1"}, {"skin": {"value": "1"}}),
    _refused219(_dd219.update_statement, _pl219, {"id": "1"}, {"len": {"value": "1"}}),
    _refused219(_dd219.insert_statement, _pl219, {"id": {"null": True}}),
    _refused219(_dd219.delete_statement, _pl219, {"id": "1", "name": "x"}),
    _refused219(_dd219.delete_statement, _pl219, {}),
    _refused219(_dd219.delete_statement, _pl219, {"id": 1}),
    _refused219(_dd219.insert_statement, _pl219, {"name": {"value": 5}}),
    _refused219(_dd219.insert_statement, _pl219, {})], [True] * 9)
_SQL_KINDS219 = {
    "SELECT 1": ("read", "select"), "  (select * from t)": ("read", "select"), "show tables": ("read", "show"),
    "DESC t": ("read", "desc"), "explain select 1": ("read", "explain"),
    "EXPLAIN ANALYZE DELETE FROM t": ("write", "explain"), "-- note\nSELECT 1": ("read", "select"),
    "# note\nshow tables": ("read", "show"), "/* x */ select 1": ("read", "select"),
    "/*!50000 DELETE FROM t */": ("write", ""), "/*M!100000 DELETE FROM t */": ("write", ""),
    "--SELECT\nDELETE FROM t": ("write", ""), "WITH a AS (SELECT 1) DELETE FROM t": ("write", "with"),
    "UPDATE t SET a=1": ("write", "update"), "": ("write", ""), "/* unterminated select": ("write", ""),
}
eq("db_data.sql_kind: SELECT/SHOW/DESCRIBE/EXPLAIN read (comments and brackets skipped); EXPLAIN ANALYZE, an "
   "executable comment, WITH and the rest write", {k: _dd219.sql_kind(k) for k in _SQL_KINDS219}, _SQL_KINDS219)
eq("db_data.mask_literals: every quoted string, hex and bit literal masked, identifiers kept, one line",
   _dd219.mask_literals("UPDATE `us'er` SET pw = 'hunter2', n = \"x\\\"y\", b = X'ABCD', h = 0xFF\n WHERE a = 'it''s'"),
   "UPDATE `us'er` SET pw = '?', n = \"?\", b = X'?', h = 0x? WHERE a = '?'")
_bin219 = _dd219.sql_result(_dd219.parse(_answer219(([(["b"], [["\x00\ufffd"]])], -1))))
eq("db_data.sql_result: bytes that are not text are said to be binary, with no length guessed from what the "
   "client's decoding left of them (N8)", _bin219["sets"][0]["rows"], [[{"binary": None}]])
_nul219 = _dd219.rows(_dd219.parse(_answer219(([(["id", "name", "skin", "len"], [["1", "a\u2400b", "3", "4"]])], -1))),
                      _pl219)
eq("db_data.rows: a text value whose NUL the server marked (U+2400) is flagged, so the editor leaves it alone (N3)",
   _nul219["rows"][0]["cells"][1], {"text": "a\u2400b", "nul": True})
check("manager script: a cell flagged nul is not editable here, and says why",
      "cell.more || cell.nul" in open(_os219.path.join(_root, "panel", "static", "js", "databases_manager.js"),
                                      encoding="utf-8").read())
eq("db_data.mask_literals: a quote inside a comment opens no literal (the next literal is still masked), a comment "
   "is not logged, an executable comment's literal is masked, and an unclosed backtick ends the text",
   [_dd219.mask_literals(t) for t in ("-- it's mine\nUPDATE u SET pw='hunter2secret'", "# don't\nSELECT 'tok'",
                                      "/* it's */ SELECT 'tok'", "SELECT `a 'tok'", "/*!50000 UPDATE t SET a='x' */")],
   ["UPDATE u SET pw='?'", "SELECT '?'", "SELECT '?'", "SELECT `?", "/*!50000 UPDATE t SET a='?' */"])
check("db_data.mask_literals: an unterminated literal is masked to the end; long text is cut",
      _dd219.mask_literals("SELECT 'secret") == "SELECT '?'" and len(_dd219.mask_literals("x" * 999)) == 300)
_got219 = []


def _rp219(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    _got219.append((verb, list(args), timeout, secrets))
    return _answer219(([(["e"], [["near '%s'" % _K219]])], -1)), "", 1


_p9_patch(_core219, "run_privileged", _rp219)
try:
    _run219 = _dd219.run(None, _HD219(flavor="mysql", port=3307), "gs3_a", _K219, "ro", [{"sql": "SELECT 1"}])
finally:
    _p9_restore_all()
check("db_data.run: one db-query call (flavor, port, name, mode; password and statements as secrets), its answer "
      "scrubbed of the password on every transport",
      [g[:2] for g in _got219] == [("db-query", ["mysql", "3307", "gs3_a", "ro"])]
      and _got219[0][3] == {"pw": _K219, "query": [{"sql": "SELECT 1"}]} and _run219["rc"] == 1
      and _run219["conn"] == "42" and _K219 not in repr(_run219)
      and _run219["statements"][0]["sets"][0]["rows"] == [["near '***'"]], repr((_got219, _run219))[:300])

# ── 5. the routes, through part12's app ──────────────────────────────────────────────────────────
from unit.part12 import _p9_patch_sm  # noqa: E402 - beside the section that uses it

_CALLS219 = []          # (mode, [sql...], params of the first)
_SVC219 = []            # what ssh_manager.databases and the upload commands were asked


def _host219(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    """The db-query verb's host side: an answer made from the statements it was handed."""
    if verb != "db-query":
        _SVC219.append(("verb", verb))
        return "", "", 0
    run = (secrets or {}).get("query") or []
    sqls = [q["sql"] for q in run]
    _CALLS219.append((args[3], sqls, run[0].get("params"), list(args), (secrets or {}).get("pw")))
    first = sqls[0] if sqls else ""
    for test, answer in _HOST_ANSWERS219:
        if test(first, args[3]):
            return answer(first)
    return _answer219(([], 1 if first.startswith(("INSERT", "DELETE", "UPDATE `")) else 3)), "", 0


# (does this statement and mode match, what the host answers): the first that matches answers.
_HOST_ANSWERS219 = (
    (lambda q, m: "information_schema.TABLES" in q, lambda q: (_STRUCT_ANS219, "", 0)),
    (lambda q, m: q.startswith("SELECT `id`"), lambda q: (_answer219(([(["id", "name", "skin", "len"], [
        ["1", "x" * 300, "9", "5"], ["2", None, None, None]])], -1)), "", 0)),
    (lambda q, m: q.startswith("SELECT REPLACE("), lambda q: (_answer219(([(["v"], [["the whole value"]])], -1)), "", 0)),
    (lambda q, m: "writes" in q and m == "ro", lambda q: (_answer219(error=(
        1792, "25006", "Cannot execute statement in a READ ONLY transaction")), "", 1)),
    (lambda q, m: "OUTFILE" in q, lambda q: (_answer219(error=(
        1045, "28000", "Access denied for user 'gs1_lp'@'127.0.0.1' (using password: YES)")), "", 1)),
    (lambda q, m: "nosignin" in q, lambda q: (
        "ERROR 1045 (28000): Access denied for user 'gs1_lp'@'127.0.0.1' (using password: YES)\n", "", 1)),
    (lambda q, m: "boom" in q, lambda q: (_answer219(error=(1064, "42000", "You have an error near 'boom'")), "", 1)),
    (lambda q, m: q.upper().startswith(("SELECT", "SHOW")), lambda q: (_answer219(([(["n"], [["1"]])], -1)), "", 0)),
)


def _user219(tag, perms):
    with _p9.app_context():
        g = _G219(name="p219_" + tag, description="", is_default=False)
        g.set_permissions(perms)
        g.servers.append(_db219.session.get(_RS219, P9_HOST))
        u = _U219(username="p219_" + tag, password_hash=_auth219.hash_password("Str0ng!passw0rd-p219"),
                  display_name="p219", is_superadmin=False, is_active=True)
        u.groups.append(g)
        _db219.session.add_all([g, u])
        _db219.session.commit()
        return u.id, g.id


def _audits219(prefix):
    with _p9.app_context():
        return [(a.action, a.detail or "", a.success) for a in
                _AL219.query.filter(_AL219.action.like(prefix + "%")).order_by(_AL219.id).all()]


def _stale219(c):
    with c.session_transaction() as s:
        s["_auth_at"] = _time219.time() - 3600


_R5 = {}
_MINE219, _SID219, _DBID219 = [], None, None
try:
    _p9_arm(who="part219")
    _p9_patch(_core219, "run_privileged", _host219)
    _SID219 = _p9_new_server(P9_HOST, "p219u", "pmc", 25569, name="p219 paper")
    with _p9.app_context():
        _HD219.query.filter_by(remote_id=P9_HOST).delete()
        _db219.session.add(_HD219(remote_id=P9_HOST, flavor="mariadb", version="10.11.14", port=3306,
                                  native_ok=True, auth_mode="socket"))
        _gd219 = _GD219(remote_id=P9_HOST, game_server_id=_SID219, name="gs%d_lp" % _SID219, secret=_enc219(_K219),
                        auth_plugin="mysql_native_password", max_conn=30, created_by="p219")
        _db219.session.add(_gd219)
        _db219.session.commit()
        _DBID219 = _gd219.id
    _MINE219 = [_user219("view", ["view_servers"]), _user219("mgr", ["view_servers", "manage_databases"]),
                _user219("edit", ["view_servers", "manage_databases", "edit_database_data"]),
                _user219("editonly", ["view_servers", "edit_database_data"])]
    _V219, _M219, _E219, _EO219 = (_p9_client(u) for u, _g in _MINE219)
    _api219 = "/api/server/%d/databases/%d" % (_SID219, _DBID219)
    _NAME219 = "gs%d_lp" % _SID219
    _ddr219._STRUCT.clear()

    # ── 5a. who may browse, change rows and run SQL ──────────────────────────────────────────────
    _R5["view_tables"] = _V219.get(_api219 + "/tables").status_code
    _R5["view_calls"] = len(_CALLS219)
    _r219 = _M219.get(_api219 + "/tables")
    _R5["mgr_tables"] = (_r219.status_code, _p9_json(_r219))
    _R5["mgr_tables_call"] = list(_CALLS219)
    _R5["mgr_rows"] = _p9_json(_M219.get(_api219 + "/rows?table=players&page=0"))
    _R5["mgr_rows2"] = _M219.get(_api219 + "/rows?table=players&page=1").status_code
    _n219 = len(_CALLS219)
    _R5["mgr_unknown"] = (_M219.get(_api219 + "/rows?table=nope").status_code, len(_CALLS219) - _n219)
    _R5["mgr_cell"] = _p9_json(_M219.post(_api219 + "/cell", json={"table": "players", "column": "name", "key": {"id": "1"}}))
    _R5["mgr_cell_call"] = _CALLS219[-1]
    _R5["mgr_row"] = _M219.post(_api219 + "/row", json={"op": "delete", "table": "players", "key": {"id": "1"}}).status_code
    _R5["mgr_sql"] = _M219.post(_api219 + "/sql", json={"sql": "SELECT 1"}).status_code
    _R5["editonly"] = [_EO219.get(_api219 + "/tables").status_code,
                       _EO219.post(_api219 + "/sql", json={"sql": "SELECT 1"}).status_code]
    _R5["other_db"] = _M219.get("/api/server/%d/databases/%d/tables" % (_SID219, _DBID219 + 999)).status_code

    # ── 5b. changing rows ────────────────────────────────────────────────────────────────────────
    _n219 = len(_CALLS219)
    _r219 = _E219.post(_api219 + "/row", json={"op": "update", "table": "players", "key": {"id": "1"},
                                                "values": {"name": {"value": "x'); DROP TABLE t; --"}}})
    _R5["update"] = (_r219.status_code, _p9_json(_r219), _CALLS219[_n219:])
    _n219 = len(_CALLS219)
    _R5["update_refused"] = [
        _E219.post(_api219 + "/row", json={"op": "delete", "table": "nokey", "key": {"x": "1"}}).status_code,
        _E219.post(_api219 + "/row", json={"op": "update", "table": "players", "key": {"id": "1"},
                                            "values": {"`id` = 1; --": {"value": "1"}}}).status_code,
        _E219.post(_api219 + "/row", json={"op": "drop", "table": "players"}).status_code,
        len(_CALLS219) - _n219]
    # What a refusal says back: a sentence from db_data.ROW_REFUSALS, and for any other bad value a fixed
    # one, never an exception's own text (CodeQL py/stack-trace-exposure).
    def _refusal_text219(values):
        return _p9_json(_E219.post(_api219 + "/row", json={"op": "update", "table": "players", "key": {"id": "1"},
                                                           "values": values})).get("message")
    _upd219 = _dd219.update_statement
    _R5["refused_text"] = [_refusal_text219({"`id` = 1; --": {"value": "1"}})]
    _p9_patch(_dd219, "update_statement", lambda *a, **k: int("internal detail"))
    _R5["refused_text"].append(_refusal_text219({"name": {"value": "x"}}))
    _p9_patch(_dd219, "update_statement", _upd219)

    # ── 5c. the SQL box ──────────────────────────────────────────────────────────────────────────
    _n219 = len(_CALLS219)
    _R5["sql_read"] = (_p9_json(_E219.post(_api219 + "/sql", json={"sql": "SELECT 'hunter2' AS n"})), _CALLS219[_n219:])
    _n219 = len(_CALLS219)
    _w219 = "UPDATE players SET name = 'hunter2' WHERE id > 0"
    _r219 = _E219.post(_api219 + "/sql", json={"sql": _w219})
    _R5["sql_write_ask"] = (_r219.status_code, _p9_json(_r219), len(_CALLS219) - _n219)
    _tok219 = _p9_json(_r219).get("confirm") or ""
    _R5["sql_other"] = [_E219.post(_api219 + "/sql", json={"sql": _w219 + " ", "confirm": _tok219}).status_code,
                        _p9_client(P9_ADMIN).post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok219}).status_code,
                        _E219.post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok219 + "x"}).status_code,
                        len(_CALLS219) - _n219]
    _n219 = len(_CALLS219)
    _r219 = _E219.post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok219})
    _R5["sql_write"] = (_r219.status_code, _p9_json(_r219), _CALLS219[_n219:])
    # ...and the same token again: spent (M1, OWASP Transaction Authorization 1.5 / 2.10).
    _n219 = len(_CALLS219)
    _r219 = _E219.post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok219})
    _R5["sql_replay"] = (_r219.status_code, _p9_json(_r219).get("message", ""), len(_CALLS219) - _n219)
    _tok2 = _p9_json(_E219.post(_api219 + "/sql", json={"sql": _w219})).get("confirm") or ""
    _p9_patch(_ddr219, "_BOOT", "another-process")
    _n219 = len(_CALLS219)
    _R5["sql_restarted"] = (_E219.post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok2}).status_code,
                            len(_CALLS219) - _n219)
    _tok3 = _p9_json(_E219.post(_api219 + "/sql", json={"sql": _w219})).get("confirm") or ""
    _R5["sql_fresh"] = _E219.post(_api219 + "/sql", json={"sql": _w219, "confirm": _tok3}).status_code
    # A statement the server refuses with 1045 after signing in, and a sign-in it refuses (N2).
    _R5["sql_outfile"] = (lambda r: (r.status_code, _p9_json(r)))(
        _E219.post(_api219 + "/sql", json={"sql": "SELECT 1 INTO OUTFILE '/tmp/x'", "confirm": None}))
    _R5["sql_nosignin"] = (lambda r: (r.status_code, _p9_json(r)))(
        _E219.post(_api219 + "/sql", json={"sql": "SELECT nosignin"}))
    _r219 = _E219.post(_api219 + "/sql", json={"sql": "SELECT writes()"})
    _R5["sql_sneaky"] = (_r219.status_code, _p9_json(_r219).get("needs_confirm"), _CALLS219[-1][0])
    _R5["sql_error"] = _p9_json(_E219.post(_api219 + "/sql", json={"sql": "SELECT boom"}))
    _R5["sql_empty"] = _E219.post(_api219 + "/sql", json={"sql": "  "}).status_code

    # ── 5d. the step-up confirm, and the dumps ───────────────────────────────────────────────────
    for _n5, _fn5 in (("drop", lambda *a: _SVC219.append(("drop",) + a[2:]) or (True, "")),
                      ("dump", lambda *a: _SVC219.append(("dump", a[1], a[2], a[3], a[4])) or (True, "")),
                      ("restore", lambda *a: _SVC219.append(("restore",) + a[2:]) or (
                          (False, "The restore did not finish.") if _R5.get("restore_fail") else (True, ""))),
                      ("set_password", lambda *a: _SVC219.append(("password",)) or (True, ""))):
        _p9_patch(_dbs219, _n5, _fn5)
    _p9_patch(_dbr219, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch(_dfr219, "game_account_write_refusal", lambda remote, user, **k: None)
    _old219 = _p9_client(_MINE219[1][0])
    _stale219(_old219)
    _R5["stale"] = [(_old219.post(_api219 + tail, json=body, headers={"X-Requested-With": "XMLHttpRequest"}).status_code)
                    for tail, body in (("/delete", {"confirm": _NAME219}), ("/restore", {"confirm": _NAME219}),
                                       ("/reset-password", {}), ("/upload", {"size": 10}))]
    _R5["stale_body"] = _p9_json(_old219.post(_api219 + "/delete", json={"confirm": _NAME219},
                                              headers={"X-Requested-With": "XMLHttpRequest"}))
    _R5["stale_svc"] = list(_SVC219)
    _R5["dump"] = _p9_json(_M219.post(_api219 + "/dump"))
    _R5["dump_svc"] = [s for s in _SVC219 if s[0] == "dump"]
    _p9_patch_sm("stat_path", lambda server, user, rel: {"type": "f", "size": 5, "name": "x", "rel": rel}
                 if rel == "panel-db-dumps/%s.sql.gz" % _NAME219 else None)
    _p9_patch_sm("stream_path", lambda server, user, rel, as_tar=False, limit=None, chunk=262144: iter([b"\x1f\x8b", b"abc"]))
    _r219 = _M219.get(_api219 + "/dump/download")
    _R5["download"] = (_r219.status_code, _r219.data, _r219.headers.get("Content-Disposition", ""),
                       _r219.headers.get("Content-Length"))
    _R5["download_view"] = _V219.get(_api219 + "/dump/download").status_code

    # ── 5e. an upload to restore ─────────────────────────────────────────────────────────────────
    _UPC219 = []

    def _upcmd219(server, cmd, timeout=30, sudo=True, **kw):
        _UPC219.append(cmd)
        if ".piece" in cmd:
            return "__DBUP_SIZE__ 10", "", 0
        if "awk -v me=" in cmd:
            return ("__DBUP_SWITCH__" if _R5.get("switch") else "__DBUP_STORED__"), "", 0
        return "__DBUP_READY__", "", 0
    _p9_patch_sm("run_command", _upcmd219)
    _uid219 = _p9_json(_M219.post(_api219 + "/upload", json={"size": 10})).get("id", "")
    _R5["up_big"] = _M219.post(_api219 + "/upload", json={"size": 3 * 1024 ** 3}).status_code
    _R5["up_piece"] = _p9_json(_M219.post(_api219 + "/upload/%s?offset=0" % _uid219, data=b"0123456789"))
    _R5["up_noname"] = _M219.post(_api219 + "/upload/%s/finish" % _uid219, json={"confirm": "x"}).status_code
    _n219 = len(_SVC219)
    _R5["up_finish"] = _p9_json(_M219.post(_api219 + "/upload/%s/finish" % _uid219, json={"confirm": _NAME219}))
    _R5["up_restore"] = _SVC219[_n219:]
    _R5["switch"] = True
    _uid219 = _p9_json(_M219.post(_api219 + "/upload", json={"size": 10})).get("id", "")
    _n219 = len(_SVC219)
    _r219 = _M219.post(_api219 + "/upload/%s/finish" % _uid219, json={"confirm": _NAME219})
    _R5["up_switch"] = (_r219.status_code, _p9_json(_r219), _SVC219[_n219:])
    _R5["up_cmds"] = list(_UPC219)
    # A dump the scan passed whose restore then fails: the dump the files held goes back in place.
    _R5["switch"], _R5["restore_fail"] = False, True
    _uid219 = _p9_json(_M219.post(_api219 + "/upload", json={"size": 10})).get("id", "")
    _c0 = len(_UPC219)
    _r219 = _M219.post(_api219 + "/upload/%s/finish" % _uid219, json={"confirm": _NAME219})
    _R5["up_failed"] = (_r219.status_code, _p9_json(_r219).get("message", ""), _UPC219[_c0:])
    _R5["restore_fail"] = False
    _c0 = len(_UPC219)
    _M219.post(_api219 + "/upload/%s/finish" % _p9_json(_M219.post(_api219 + "/upload", json={"size": 10})).get("id", ""),
               json={"confirm": _NAME219})
    _R5["up_settled"] = _UPC219[_c0:]

    # ── 5f. the Databases page ───────────────────────────────────────────────────────────────────
    _R5["page"] = {k: c.get("/databases").get_data(as_text=True) for k, c in (("view", _V219), ("mgr", _M219),
                                                                               ("edit", _E219))}
finally:
    _p9_restore_all()
    _ddr219._STRUCT.clear()
    _dfr219._UPLOADS.clear()
    with _p9.app_context():
        _GD219.query.filter_by(game_server_id=_SID219).delete()
        _HD219.query.filter_by(remote_id=P9_HOST).delete()
        for _uid5, _gid5 in _MINE219:
            for _mdl5, _i5 in ((_U219, _uid5), (_G219, _gid5)):
                _row5 = _db219.session.get(_mdl5, _i5)
                if _row5 is not None:
                    _db219.session.delete(_row5)
        _db219.session.commit()
    if _SID219 is not None:
        from unit.part12 import _p9_delete_server
        _p9_delete_server(_SID219)

eq("manager: without Manage databases the tables are refused (403) before the host is asked",
   (_R5.get("view_tables"), _R5.get("view_calls")), (403, 0))
_mt219 = _R5.get("mgr_tables", (0, {}))
_mc219 = _R5.get("mgr_tables_call") or [("", [], None, [], None)]
check("manager: Manage databases opens a database: ONE read-only db-query as the database's own account, at its "
      "port on this host", _mt219[0] == 200 and len(_mc219) == 1 and _mc219[0][0] == "ro"
      and _mc219[0][3] == ["mariadb", "3306", _NAME219 if _SID219 else "", "ro"] and _mc219[0][4] == _K219
      and len(_mc219[0][1]) == 3, repr(_mc219)[:400])
check("manager: the tables, their columns, which are read-only and why; no edit offered without Edit database data",
      [t["name"] for t in _mt219[1].get("tables", [])] == ["nokey", "players", "v", "we`ird"]
      and _mt219[1].get("can_edit") is False
      and {t["name"]: t["readonly"] for t in _mt219[1].get("tables", [])}.get("nokey") == "no_key", repr(_mt219)[:300])
_mr219 = _R5.get("mgr_rows", {})
check("manager: a page of rows: long text cut with more, binary as its length, NULL as null, the key kept whole",
      _mr219.get("rows", [{}])[0].get("cells") == [{"text": "1"}, {"text": "x" * 256, "more": True}, {"binary": 9},
                                                    {"text": "5"}]
      and _mr219.get("rows", [{}, {}])[1].get("cells", [None])[1] == {"null": True}
      and _mr219.get("rows", [{}])[0].get("key") == {"id": "1"} and _mr219.get("columns") == ["id", "name", "skin", "len"],
      repr(_mr219)[:400])
eq("manager: an unknown table is refused (404) without asking the host (the structure is reused)",
   _R5.get("mgr_unknown"), (404, 0))
check("manager: opening a table is audited once (page 0 only), naming the table, never a value",
      len([a for a in _audits219("db_browse") if "players" in a[1]]) == 1)
check("manager: Show all reads one value by the row's key, bound as a parameter, read-only",
      _R5.get("mgr_cell", {}).get("text") == "the whole value" and _R5.get("mgr_cell_call", ("",))[0] == "ro"
      and _R5.get("mgr_cell_call", ("", [""]))[1][0].startswith(
          "SELECT REPLACE(CONVERT(LEFT(`name`, 262144) USING utf8mb4), _utf8mb4 X'00', _utf8mb4 X'E29080') FROM "
          "`players` WHERE `id` = ?")
      and _R5.get("mgr_cell_call", ("", "", None))[2] == ["1"], repr(_R5.get("mgr_cell_call")))
eq("manager: changing a row and the SQL box need Edit database data (403), and Edit database data alone does not "
   "open a database; another server's database id is 404",
   (_R5.get("mgr_row"), _R5.get("mgr_sql"), _R5.get("editonly"), _R5.get("other_db")), (403, 403, [403, 403], 404))
_up219 = _R5.get("update", (0, {}, [("", [""], None)]))
check("editor: a row update runs the statement db_data made from the structure, the value and key bound, read-write",
      _up219[0] == 200 and _up219[1].get("affected") == 1 and len(_up219[2]) == 1 and _up219[2][0][0] == "rw"
      and _up219[2][0][1] == ["UPDATE `players` SET `name` = CONVERT(? USING utf8mb4) WHERE `id` = ? LIMIT 1"]
      and _up219[2][0][2] == ["x'); DROP TABLE t; --", "1"], repr(_up219)[:400])
_ua219 = _audits219("db_row_update")
check("editor: the change is audited with the table, the columns and the rows changed, never the value",
      len(_ua219) == 1 and "updated 1 row(s) in" in _ua219[0][1] and "players" in _ua219[0][1]
      and "(columns: name)" in _ua219[0][1] and "DROP" not in _ua219[0][1], repr(_ua219))
eq("editor: a table with no key (409), a column not in the table (400) and an unknown operation (400) are refused "
   "without asking the host", _R5.get("update_refused"), [409, 400, 400, 0])
eq("row change: a refusal says only a fixed sentence, never an exception's own text",
   _R5.get("refused_text"), ["That change doesn't fit the table: not a column that can be set.",
                             "That change doesn't fit the table: a value is not one the column takes."])
_sr219 = _R5.get("sql_read", ({}, [("", [""])]))
check("sql: a SELECT runs at once, in a read-only transaction, its rows capped", _sr219[0].get("success") is True
      and _sr219[1][0][0] == "ro" and _sr219[0].get("result", {}).get("sets", [{}])[0].get("rows") == [[{"text": "1"}]],
      repr(_sr219)[:300])
_wa219 = _R5.get("sql_write_ask", (0, {}, 1))
check("sql: a change is not run: it answers 409 with the statement, the database and a confirm token",
      _wa219[0] == 409 and _wa219[1].get("needs_confirm") is True and _wa219[1].get("sql") == _w219
      and _wa219[1].get("database", "").endswith("_lp") and _wa219[1].get("confirm") and _wa219[2] == 0,
      repr(_wa219)[:300])
eq("sql: the token confirms only that statement, for that viewer, unaltered (409 for another statement, another "
   "user, a forged token; nothing run)", _R5.get("sql_other"), [409, 409, 409, 0])
_sw219 = _R5.get("sql_write", (0, {}, [("",)]))
check("sql: with its token the statement runs read-write and its row count comes back",
      _sw219[0] == 200 and _sw219[2][0][0] == "rw" and _sw219[1].get("result", {}).get("affected") == 3,
      repr(_sw219)[:300])
_sa219 = _audits219("db_sql")
check("sql: each statement is audited (kind, database, rows) with its string literals masked",
      len(_sa219) >= 3 and all("hunter2" not in a[1] for a in _sa219)
      and any(a[1].startswith("update (write) in ") and "3 row(s)" in a[1] and "name = '?'" in a[1] for a in _sa219)
      and any(a[1].startswith("select (read) in ") for a in _sa219), repr(_sa219))
_rp5 = _R5.get("sql_replay", (0, "", 1))
check("sql: a confirm token runs its statement once: used again it is refused (409, said as used) and nothing runs",
      _rp5[0] == 409 and "was used already" in _rp5[1] and _rp5[2] == 0, repr(_rp5))
eq("sql: a token made before the panel restarted is refused, and a fresh one still works",
   (_R5.get("sql_restarted"), _R5.get("sql_fresh")), ((409, 0), 200))
_of5 = _R5.get("sql_outfile", (0, {}))
check("sql: a statement the server refuses with 1045 after the sign-in worked (INTO OUTFILE without FILE) says the "
      "server's own words, not that the account was refused", _of5[0] == 200
      and _of5[1].get("error", {}).get("code") == 1045 and "Access denied" in _of5[1].get("message", "")
      and "Reset password" not in repr(_of5[1]), repr(_of5))
_ns5 = _R5.get("sql_nosignin", (0, {}))
check("sql: ...and a sign-in the server refuses (no connection id came back) still says use Reset password",
      _ns5[0] == 502 and "Reset password" in _ns5[1].get("message", ""), repr(_ns5))
eq("sql: a 'read' the read-only transaction refused (it writes) is sent to the confirm step (409)",
   _R5.get("sql_sneaky"), (409, True, "ro"))
check("sql: the server's error comes back with its code (the viewer's own statement, as text)",
      _R5.get("sql_error", {}).get("error", {}).get("code") == 1064 and _R5.get("sql_error", {}).get("success") is False)
eq("sql: an empty statement is refused", _R5.get("sql_empty"), 400)
eq("step-up: delete, restore, reset and an upload after the confirm window answer reauth_required (403)",
   _R5.get("stale"), [403, 403, 403, 403])
check("step-up: ...and nothing was asked of the host", _R5.get("stale_body", {}).get("error") == "reauth_required"
      and not [s for s in _R5.get("stale_svc", []) if s[0] in ("drop", "restore", "password")], repr(_R5.get("stale_svc")))
_ds219 = (_R5.get("dump_svc") or [("", None, "", "", [])])[0]
check("dump: made into the server's files as the database's own account (a login of its own name), never root's "
      "socket or the admin login", _R5.get("dump", {}).get("success") is True and _ds219[2] == "game"
      and _ds219[3] == "p219u" and getattr(_ds219[1], "auth_mode", "") == "login"
      and getattr(_ds219[1], "admin_user", "") == _ds219[4][0], repr(_ds219))
_dl219 = _R5.get("download", (0, b"", "", None))
check("dump: the download streams that file, with its length and a dated attachment name",
      _dl219[0] == 200 and _dl219[1] == b"\x1f\x8babc" and _dl219[3] == "5"
      and _dl219[2].startswith('attachment; filename="gs') and '.sql.gz"' in _dl219[2], repr(_dl219))
eq("dump: the download needs Manage databases", _R5.get("download_view"), 403)
check("upload: a dump over 2 GiB is refused; a piece is appended at its offset",
      _R5.get("up_big") == 400 and _R5.get("up_piece", {}).get("received") == 10, repr((_R5.get("up_big"), _R5.get("up_piece"))))
eq("upload: the finish needs the database's name typed", _R5.get("up_noname"), 400)
check("upload: a dump the host check stored is restored by the import as the game account, as the database's own "
      "account", _R5.get("up_finish", {}).get("success") is True
      and [s[:3] for s in _R5.get("up_restore", [])] == [("restore", "p219u", _NAME219)]
      and _R5.get("up_restore", [("",) * 4])[0][3] == _K219, repr(_R5.get("up_restore")))
_uf219 = _R5.get("up_failed", (0, "", []))
check("upload: a restore that fails puts the dump the files held back (settle as the game account) and says so",
      _uf219[0] == 502 and "the dump they had before" in _uf219[1] and len(_uf219[2]) == 2
      and ".prev" in _uf219[2][1] and "mv -f" in _uf219[2][1], repr(_uf219)[:400])
check("upload: ...and one that works drops the copy kept aside",
      len(_R5.get("up_settled", [])) == 3 and "rm -f" in _R5.get("up_settled", ["", "", ""])[2]
      and ".prev" in _R5.get("up_settled", ["", "", ""])[2], repr(_R5.get("up_settled"))[:300])
_usw219 = _R5.get("up_switch", (0, {}, ["x"]))
check("upload: a dump the check refused (it switches database) is not restored, and says why",
      _usw219[0] == 409 and _usw219[2] == [] and "switches to another database" in _usw219[1].get("message", ""),
      repr(_usw219)[:300])
check("upload: every upload command runs as the game account, in its own panel-db-dumps",
      _R5.get("up_cmds") and all(c.startswith("sudo -u p219u bash -c") and "panel-db-dumps" in c
                                 for c in _R5.get("up_cmds", [])), repr(_R5.get("up_cmds", [])[:1])[:200])
_pg219 = _R5.get("page", {})
check("page: a viewer gets the list only; a manager gets Add a database, a Manage button per database and the "
      "manager's dialog and script; the SQL tab only with Edit database data",
      "dbm-modal" not in _pg219.get("view", "x") and "databases_manager.js" not in _pg219.get("view", "x")
      and all(k in _pg219.get("mgr", "") for k in ("dbm-modal", "databases_manager.js", 'data-action="dbmOpen"', "dbm-add"))
      and 'data-dbm-pane="sql"' not in _pg219.get("mgr", "x") and 'data-dbm-pane="sql"' in _pg219.get("edit", ""))
check("manager routes reached no host transport", len(_P9_TRIPPED) == _trips219, repr(_P9_TRIPPED[_trips219:][:3]))

# ── 6. the upload's commands, run by bash on a temporary home ────────────────────────────────────
_HOME219 = _os219.path.join(_T219, "home", "gm219")
_DD219 = _os219.path.join(_HOME219, "panel-db-dumps")
_UID219 = "ab" * 16
_GOOD219 = ("-- MariaDB dump 10.19\n/*!40101 SET NAMES utf8mb4 */;\nDROP TABLE IF EXISTS `players`;\n"
            "CREATE TABLE `players` (\n  `id` int(11) NOT NULL,\n  PRIMARY KEY (`id`)\n);\n"
            "INSERT INTO `players` VALUES (1,'USE gs9_x; `mysql`.`user`.');\n"
            "CREATE VIEW `v` AS select `players`.`id` from `gs12_lp`.`players`;\n")
# A dump well past the 64 KB the format checks read: those checks must not read an early stop as a failure.
_LARGE219 = b"".join(b"INSERT INTO `players` VALUES (%d);\n" % i for i in range(20000))
_HOSTILE_DUMPS219 = {
    "use another": "-- dump\nUSE `gs9_other`;\nCREATE TABLE t (i int);\n",
    "create database": "-- dump\nCREATE DATABASE /*!32312 IF NOT EXISTS*/ `gs9_other`;\n",
    "executable-comment use": "-- dump\n/*!40000 USE gs9_other */;\n",
    "drop schema": "-- dump\nDROP SCHEMA gs9_other;\n",
    "another panel database": "-- dump\nCREATE TABLE `gs9_other`.`t` (i int);\n",
    "a system schema": "-- dump\nINSERT INTO t SELECT * FROM `mysql`.`user`;\nUPDATE `mysql` . `user` SET x=1;\n",
    "an INSERT into another panel database": "-- dump\nINSERT INTO `gs9_other`.`t` VALUES (1);\n",
    "an UPDATE of another database chained on an INSERT line":
        "-- dump\nINSERT INTO `t` VALUES (1); UPDATE `gs9_other`.`t` SET a=1;\n",
    "a USE chained on an INSERT line": "-- dump\nINSERT INTO `t` VALUES (1);USE gs9_other;\n",
    "a DROP DATABASE chained on an INSERT line": "-- dump\nINSERT INTO `t` VALUES (1); DROP DATABASE IF EXISTS `gs9_o`;\n",
    "an unquoted INSERT into another database chained on an INSERT line":
        "-- dump\nINSERT INTO `t` VALUES (1); INSERT INTO gs9_other.items VALUES (2);\n",
    "an unquoted UPDATE of another database": "-- dump\nUPDATE gs9_other.items SET score = -8;\n",
    "an unquoted system schema": "-- dump\nSELECT * FROM mysql.user;\n",
    "an unquoted INSERT head": "-- dump\nINSERT INTO gs9_other.t VALUES (1);\n",
    "an unquoted name in an executable comment": "-- dump\n/*!50001 CREATE VIEW v AS SELECT * FROM gs9_x.t */;\n",
    "a DROP DATABASE chained on a plain line": "-- dump\nSELECT * FROM `gs12_lp`.`t`;\tDROP DATABASE IF EXISTS `gs9_x`;\n",
    "a USE chained on a SET line": "-- dump\nSET @a = 1; USE mysql;\n",
    "an upper-case schema chained on an INSERT line":
        "-- dump\nINSERT INTO `t` VALUES (0,'');\tCREATE \tSCHEMA `INFORMATION_SCHEMA`;\n",
}
_INSERT_VERDICT219 = {"an unquoted INSERT into another database chained on an INSERT line": "OTHER",
                      "an unquoted UPDATE of another database": "OTHER", "an unquoted system schema": "OTHER",
                      "an unquoted INSERT head": "OTHER", "an unquoted name in an executable comment": "OTHER",
                      "a DROP DATABASE chained on a plain line": "SWITCH", "a USE chained on a SET line": "SWITCH",
                      "an upper-case schema chained on an INSERT line": "SWITCH",
                      "an INSERT into another panel database": "OTHER",
                      "an UPDATE of another database chained on an INSERT line": "OTHER",
                      "a USE chained on an INSERT line": "SWITCH", "a DROP DATABASE chained on an INSERT line": "SWITCH"}


def _bash219(script, stdin=None):
    sh = script.replace("/home/gm219", _HOME219)
    p = _sp219.run(["bash", "-c", sh], input=stdin, capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607
    return p.stdout + p.stderr


def _finish219(data, gz=False):
    """(the finish script's verdict, the stored dump unpacked or None) for an upload of `data`."""
    _bash219(_dfr219.start_script("gm219", _UID219, 1))
    body = _gz219.compress(data) if gz else data
    with open(_os219.path.join(_DD219, ".panel-upload-%s.part" % _UID219), "wb") as fh:
        fh.write(body)
    out = _bash219(_dfr219.finish_script("gm219", _UID219, len(body), "gs12_lp"))
    dest = _os219.path.join(_DD219, "gs12_lp.sql.gz")
    stored = None
    if _os219.path.exists(dest):
        with _gz219.open(dest, "rb") as fh:
            stored = fh.read()
        _os219.unlink(dest)
    return _dfr219.outcome(out), stored


_os219.makedirs(_HOME219, exist_ok=True)
_R6 = {"plain": _finish219(_GOOD219.encode()), "gz": _finish219(_GOOD219.encode(), gz=True),
       "nul": _finish219(b"-- dump\nINSERT INTO t VALUES ('\x00');\n"),
       "notsql": _finish219(b"hello world\nthis is a letter\n"),
       "empty-gz": _finish219(b"", gz=True),
       "damaged": _finish219(_gz219.compress(_GOOD219.encode() * 50)[:-30], gz=False),
       "large": _finish219(_GOOD219.encode() + _LARGE219, gz=True)}
_R6.update({k: _finish219(v.encode()) for k, v in _HOSTILE_DUMPS219.items()})
eq("upload check: a plain dump is stored gzipped as <name>.sql.gz, as uploaded; INSERT data and the database's "
   "own name are not mistaken for a switch", (_R6["plain"][0], _R6["plain"][1]), (("ok", ""), _GOOD219.encode()))
eq("upload check: a gzip dump is stored as it is", (_R6["gz"][0], _R6["gz"][1]), (("ok", ""), _GOOD219.encode()))
eq("upload check: a dump far larger than the format checks read is stored whole", (_R6["large"][0], len(_R6["large"][1] or b"")),
   (("ok", ""), len(_GOOD219.encode() + _LARGE219)))
eq("upload check: a dump that switches to or names another database is refused, and nothing is stored",
   {k: _R6[k] for k in _HOSTILE_DUMPS219},
   {"use another": (("refused", "SWITCH"), None), "create database": (("refused", "SWITCH"), None),
    "executable-comment use": (("refused", "SWITCH"), None), "drop schema": (("refused", "SWITCH"), None),
    "another panel database": (("refused", "OTHER"), None), "a system schema": (("refused", "OTHER"), None),
    **{k: (("refused", v), None) for k, v in _INSERT_VERDICT219.items()}})
_chat219 = (b"-- dump\n-- see mysql.com and gs9_x.t (a comment)\n"
            b"INSERT INTO `chat` VALUES (0,'see mysql.user too'),(1,'ok; use /help; things; select settings'),"
            b"(2,'USE gs9_x; then `mysql`.`user`.; drop database x'),(3,'runs on mysql 8; select a kit');\n"
            b"INSERT INTO `gs12_lp`.`chat` VALUES (3,'mine'); UPDATE gs12_lp.chat SET a=1;\n")
eq("upload check: data in an INSERT that only mentions statements or other databases, and an INSERT into the "
   "database's own name, are stored", _finish219(_chat219), (("ok", ""), _chat219))
eq("upload check: NUL bytes, a file that is not SQL, an empty one and a damaged gzip are refused",
   [_R6[k] for k in ("nul", "notsql", "empty-gz", "damaged")],
   [(("refused", "NOTTEXT"), None), (("refused", "NOTSQL"), None), (("refused", "FORMAT"), None),
    (("refused", "DAMAGED"), None)])
import ast as _ast219  # noqa: E402 - beside the check that uses it
_scan_mod219 = _os219.path.join(_root, "panel", "ops", "ssh_manager", "db_upload_scan.py")
with open(_scan_mod219, encoding="utf-8") as _fh219:
    _scan_tree219 = _ast219.parse(_fh219.read())
check("upload scan: its program lives in a module with no imports (a fuzz harness loads it without the app), and "
      "the finish runs that same program",
      not [n for n in _ast219.walk(_scan_tree219) if isinstance(n, (_ast219.Import, _ast219.ImportFrom))]
      and _dfr219._SCAN_AWK is __import__("panel.ops.ssh_manager.db_upload_scan", fromlist=["x"]).SCAN_AWK)
# A NUL byte past the first 64 KB, on a line that holds a chained statement: Ubuntu 22.04's mawk ends a
# string at a NUL, which a stand-in awk imitates here (it cuts each line at its first NUL, then runs gawk).
_NULBIN219 = _os219.path.join(_T219, "nulbin")
_os219.makedirs(_NULBIN219, exist_ok=True)
with open(_os219.path.join(_NULBIN219, "awk"), "w", encoding="utf-8") as _fh219:
    _fh219.write("#!/bin/bash\nLC_ALL=C sed 's/\\x00.*//' | exec gawk \"$@\"\n")
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in in this part's temp dir
_os219.chmod(_os219.path.join(_NULBIN219, "awk"), 0o700)  # nosec B103 - owner-only stand-in program in a temp dir
_nuldump219 = (_GOOD219.encode() + _LARGE219 + b"INSERT INTO `t` VALUES (0,'a\x00b'); DROP SCHEMA gs9_x;\n")
_bash219(_dfr219.start_script("gm219", _UID219, 1))
with open(_os219.path.join(_DD219, ".panel-upload-%s.part" % _UID219), "wb") as _fh219:
    _fh219.write(_nuldump219)
_nulout219 = _bash219("export PATH=%s:$PATH\n" % _NULBIN219
                      + _dfr219.finish_script("gm219", _UID219, len(_nuldump219), "gs12_lp"))
eq("upload check: a NUL past the first 64 KB does not hide the rest of its line from the scan (an awk that ends "
   "strings at a NUL, as Ubuntu 22.04's mawk does, still sees the chained DROP SCHEMA)",
   _dfr219.outcome(_nulout219), ("refused", "SWITCH"))
# The dump the files held is kept aside until the restore works, and put back when it does not.
_DEST219 = _os219.path.join(_DD219, "gs12_lp.sql.gz")


def _stored219():
    with open(_DEST219, "rb") as fh:
        return _gz219.decompress(fh.read())


def _keep219(restored, had_one):
    """(what <name>.sql.gz holds after a stored upload and settle_script, whether a .prev is left)."""
    for f in (_DEST219, _DEST219 + ".prev"):
        if _os219.path.exists(f):
            _os219.unlink(f)
    if had_one:
        with open(_DEST219, "wb") as fh:
            fh.write(_gz219.compress(b"-- the backup's dump\n"))
    _bash219(_dfr219.start_script("gm219", _UID219, 1))
    with open(_os219.path.join(_DD219, ".panel-upload-%s.part" % _UID219), "wb") as fh:
        fh.write(_GOOD219.encode())
    first = _dfr219.outcome(_bash219(_dfr219.finish_script("gm219", _UID219, len(_GOOD219.encode()), "gs12_lp")))
    aside = _os219.path.exists(_DEST219 + ".prev")
    _bash219(_dfr219.settle_script("gm219", "gs12_lp", restored))
    got = _stored219() if _os219.path.exists(_DEST219) else None
    return first, aside, got, _os219.path.exists(_DEST219 + ".prev")


eq("upload keep: the stored dump is kept aside while the restore runs; a failed restore puts it back, a working "
   "one drops it, and with none before a failed upload leaves no dump",
   [_keep219(False, True), _keep219(True, True), _keep219(False, False)],
   [(("ok", ""), True, b"-- the backup's dump\n", False), (("ok", ""), True, _GOOD219.encode(), False),
    (("ok", ""), False, None, False)])
check("upload check: a refused upload's part file is removed",
      not [f for f in _os219.listdir(_DD219) if f.startswith(".panel-upload-")], repr(_os219.listdir(_DD219)))
_bash219(_dfr219.start_script("gm219", _UID219, 1))
_pc219 = [_dfr219.outcome(_bash219(_dfr219.piece_script("gm219", _UID219, 0), "aGVsbG8=")),
          _dfr219.outcome(_bash219(_dfr219.piece_script("gm219", _UID219, 0), "aGVsbG8=")),
          _dfr219.outcome(_bash219(_dfr219.finish_script("gm219", _UID219, 99, "gs12_lp")))]
eq("upload pieces: appended at their offset; a piece at a stale offset says where the file is; a finish of the "
   "wrong size is refused", _pc219, [("ok", "5"), ("offset", 5), ("offset", 5)])
check("upload commands: a bad upload id is refused before a command exists",
      _refused219(_dfr219.start_script, "gm219", "../x", 1) and _refused219(_dfr219.cancel_script, "gm219", "AB" * 16))

# ── 7. the manager's script: values on the page as text only ─────────────────────────────────────
_js219 = open(_os219.path.join(_root, "panel", "static", "js", "databases_manager.js"), encoding="utf-8").read()
check("manager script: nothing it shows goes through innerHTML or insertAdjacentHTML (textContent only)",
      "innerHTML" not in _js219 and "insertAdjacentHTML" not in _js219 and "outerHTML" not in _js219
      and _js219.count("textContent") >= 10)


# ── 8. two database messages and a way out (from the remote-database proof on a real MySQL) ─────
_N219 = {}


def _n1_rp219(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    return ("ERROR 2061 (HY000): Authentication plugin 'caching_sha2_password' reported error: Authentication "
            "requires secure connection.", "", 1)


def _n2_rp219(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    return ("ERROR 4006 (HY000): Operation RENAME USER failed for 'gs1_mv'@'100.70.1.2' as it is referenced as a "
            "definer account in an event.", "", 1)


_login_hd219 = _dbs219.target_view(_HD219(flavor="mysql", port=3306, native_ok=False, auth_mode="login",
                                           admin_user="rootadmin", admin_secret=_enc219("Zadmin219" + "q" * 20)))
try:
    _p9_patch(_core219, "run_privileged", _n1_rp219)
    _N219["create"] = _dbs219.create(None, _login_hd219, "gs1_sk", _K219, 30)
    _p9_patch(_core219, "run_privileged", _n2_rp219)
    _N219["move"] = _dbs219.rehost(None, _login_hd219, "gs1_mv", "100.70.1.2", "100.70.1.3")
    _drops219 = []
    _p9_patch(_dbr219, "own_view", lambda local_hd, r: "own-account")
    _p9_patch(_dbr219._net, "admin_target", lambda gs_remote, local_hd, r: ("remote", _login_hd219))
    _p9_patch(_dbs219, "dump", lambda remote, hostdb, dest, account, names: (False, "refused"))
    _p9_patch(_dbs219, "drop", lambda remote, hostdb, account, name: _drops219.append(
        (remote, getattr(hostdb, "copy_kept", False), name)) or (True, "dropped"))
    _N219["drop"] = (_dbr219.drop_row("game-host", None, _GD219(name="gs1_mv"), None), list(_drops219))
finally:
    _p9_restore_all()
eq("create: an admin login whose own sign-in hits 2061 (no TLS, no key from the server) is said as that, not as "
   "the server refusing the database", _N219.get("create"), (False, _dbs219.S_NET_KEY))
check("move: MySQL refusing to move a definer account (4006) also says how its administrator moves it as root",
      _N219.get("move", (None,))[0] is False and "RENAME USER 'gs1_mv'@'100.70.1.2' TO 'gs1_mv'@'100.70.1.3';"
      in str(_N219.get("move", ("", ""))[1]) and "Nothing was changed" in str(_N219.get("move", ("", ""))[1]),
      repr(_N219.get("move")))
eq("delete: when the database's own account can't make the copy (it signs in from an old address), the drop is "
   "still asked, to keep its own copy where the accounts are made (it deletes only an empty database without one)",
   _N219.get("drop"), ((True, "dropped"), [("remote", False, "gs1_mv")]))

_sh219.rmtree(_T219, ignore_errors=True)
