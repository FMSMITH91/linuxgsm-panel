r"""Part 207 of the unit suite: a game server's MariaDB/MySQL databases, the backend.

* The db-* verbs' validators, in both copies (privileged.py and tools/panel-helper), against hostile
  names, sign-ins and passwords; the stdin document that carries the secrets.
* The SQL both copies build: byte for byte the same, `_` escaped in every database-level GRANT, both
  accounts (localhost and 127.0.0.1), MAX_USER_CONNECTIONS, native or caching_sha2 by server.
* No secret on any command line: the helper's argv and every remote rendering; they travel on stdin.
* The helper's verbs through its real main(), against stand-in tools (bash scripts in a temp dir, no
  mysqld): create (refuses an existing name, cleans up a failed one), the stderr scrub of both
  passwords, harden's refusal of a server holding other databases, drop's archive copy, a dump into a
  game's files written AFTER the drop to the account and never through a link, the import's sandbox
  line, and the probe.
* The same verbs' remote renderings, run by bash with the same stand-ins as shell functions.
* panel/ops/ssh_manager/databases.py through a stubbed run_privileged: names, passwords, the probe's
  states and warnings, every call's verb, arguments and secrets, the root-capable-account guard
  before a dump into a game's files or an import.
* run_privileged itself: the secrets on stdin and scrubbed from the answer on all three transports.
* The models (both tables, AUTOINCREMENT, the delete rules) and the MANAGE_DATABASES permission.

Nothing here reaches a host, a database server or data/.
"""
import gzip as _gz207
import io as _io207
import json as _js207
import os as _os207
import pwd as _pwd207
import re as _re207
import shutil as _sh207
import subprocess as _sp207  # nosec B404 - bash over the renderings this part checks, in a temp dir
import sys as _sys207
import tempfile as _tf207
import types as _ty207

from unit.part01 import check, eq
from unit.part05 import _helper, _root
from unit.part12 import _P9_TRIPPED, _p9
from panel.db.models import (GameDatabase as _GD207, GameServer as _GS207, HostDatabaseServer as _HD207,
                             RemoteServer as _RS207, db as _db207)
from panel.ops.ssh_manager import _core as _smc207, databases as _dbs207
from panel.security import auth as _auth207, privileged as _priv207

_trips207 = len(_P9_TRIPPED)
_PW = "Sentinelpw7Xq-ab.cd_ef012345"          # a database password of the generator's shape
_APW = 'Adm in#"\\pw\\b x'                    # an admin password with every option-file hazard
_ADMIN = ("rootadmin", _APW)
_ACCT = "gm207"

# ── 1. the validators, both copies ───────────────────────────────────────────────────────────────
_NAMES_OK = ["gs12_lp", "gs1_a", "gs1234567890_abcdefghijklmnop", "gs9_data2"]
_NAMES_BAD = ["a';DROP", "gs12_lp`", "gs12_l%", "gs12_", "_gs12_lp", "GS12_LP", "gs12_LP",
              "gs12_abcdefghijklmnopq", "gs0_x", "gs012_x", "mysql", "gs12_lp\n", "gs12_l-p", "gs12_l p",
              "gs12345678901_x", "gs12_l_p", "information_schema", ""]


def _takes(fn, v):
    try:
        fn(v)
        return True
    except ValueError:
        return False


for _side, _fn in (("panel", _priv207._db_name), ("helper", _helper.v_db_name)):
    eq("db names (%s): the gs<id>_<slug> shapes pass" % _side, [n for n in _NAMES_OK if not _takes(_fn, n)], [])
    eq("db names (%s): injection shapes, wildcards, case, length and system names are refused" % _side,
       [n for n in _NAMES_BAD if _takes(_fn, n)], [])
_AUTH = ["socket", "tcp3306", "tcp1", "tcp65535", "tcp0", "tcp65536", "tcp", "tcp3306;x", "TCP3306", "sock",
         "tcp03306", " socket"]
eq("db sign-in: the two copies give the same verdict on every shape",
   [a for a in _AUTH if _takes(_priv207._db_auth, a) != _takes(_helper.v_db_auth, a)], [])
eq("db sign-in: only socket and tcp<1..65535> pass",
   [a for a in _AUTH if _takes(_helper.v_db_auth, a)], ["socket", "tcp3306", "tcp1", "tcp65535"])
eq("db sign-in: an admin check takes tcp<port> only (both copies)",
   [_takes(f, "socket") for f in (_priv207._db_auth_tcp, _helper.v_db_auth_tcp)]
   + [_takes(f, "tcp3306") for f in (_priv207._db_auth_tcp, _helper.v_db_auth_tcp)], [False, False, True, True])
_MC = ["1", "30", "500", "0", "501", "030", "-1", "1e3", ""]
eq("db connection cap: 1..500 in both copies",
   [[m for m in _MC if _takes(f, m)] for f in (_priv207._db_maxconn, _helper.v_db_maxconn)],
   [["1", "30", "500"], ["1", "30", "500"]])

# The stdin document: the helper's reader against the panel's writer, and hostile documents.
_doc_full = _priv207.db_doc("db-create", ["mysql", "tcp3306", "gs12_lp", "sha2", "30"],
                            {"admin": _ADMIN, "pw": _PW})
eq("db document: the panel writes it and the helper reads back the same secrets",
   _helper.db_read_doc(_doc_full, True, True), (_ADMIN, _PW))
_DOCS_BAD = {
    "no end line": "pw %s\n" % _PW,
    "a password with a quote": "pw %s'x\nend\n" % _PW[:30],
    "a short password": "pw Abc123\nend\n",
    "an extra line": "pw %s\nhello\nend\n" % _PW,
    "two passwords": "pw %s\npw %s\nend\n" % (_PW, _PW),
    "an admin the verb does not sign in with": "admin a\nb\npw %s\nend\n" % _PW,
    "a password missing": "end\n",
    "too long": "pw %s\n%s\nend\n" % (_PW, "x" * 5000),
}
eq("db document: every malformed document is refused by the helper",
   [k for k, d in _DOCS_BAD.items() if _takes(lambda t: _helper.db_read_doc(t, False, True), d)], [])
eq("db document: an admin login with a control character or a bad user is refused",
   [_takes(lambda t: _helper.db_read_doc(t, True, False), d)
    for d in ("admin root\npa\tss\nend\n", "admin ro'ot\npass\nend\n", "admin root\n\nend\n")],
   [False, False, False])
_PANEL_BAD = [("db-create", {"pw": _PW + "'"}), ("db-create", {}), ("db-create", {"pw": "short1A"}),
              ("db-password", {"pw": _PW, "admin": ("root", "")})]
_pb = []
for _v, _s in _PANEL_BAD:
    _a = (["mariadb", "socket", "gs12_lp", "native", "30"] if _v == "db-create"
          else ["mysql", "tcp3306", "gs12_lp", "native"])
    if _takes(lambda s: _priv207.db_doc(_v, _a, s), _s):
        _pb.append(_v)
eq("db document: the panel refuses a bad password or a login missing its password before sending", _pb, [])

# ── 2. the SQL, both copies ──────────────────────────────────────────────────────────────────────
_SQL_CASES = [("db_sql_create", ("mariadb", "gs12_lp", "native", "30", _PW)),
              ("db_sql_create", ("mysql", "gs12_lp", "native", "7", _PW)),
              ("db_sql_create", ("mysql", "gs12_lp", "sha2", "500", _PW)),
              ("db_sql_password", ("mariadb", "gs3_x", "native", _PW)),
              ("db_sql_password", ("mysql", "gs3_x", "sha2", _PW)),
              ("db_sql_exists", ("gs3_x",)), ("db_sql_drop", ("gs3_x",)), ("db_sql_tables", ("gs3_x",)),
              ("db_sql_sizes", (["gs3_x", "gs3_y"],)), ("db_sql_harden", (_PW,)),
              ("db_defaults_text", ("root", _APW)), ("db_grant_target", ("gs12_l_",))]
eq("db SQL: the helper and the panel build the same bytes for every statement",
   [c for c, a in _SQL_CASES if getattr(_helper, c)(*a) != getattr(_priv207, c)(*a)], [])
eq("db constants: both copies agree on every shared constant",
   [k for k in dir(_priv207) if k.startswith("DB_") and k != "DB_VERBS" and hasattr(_helper, k)
    and getattr(_helper, k) != getattr(_priv207, k)]
   + [k for k in dir(_priv207) if k.startswith("DB_") and k != "DB_VERBS" and not hasattr(_helper, k)], [])
_c = _helper.db_sql_create("mariadb", "gs12_lp", "native", "30", _PW)
check("db SQL: the GRANT escapes `_` (`gs12\\_lp`.*), for both accounts, and never names the bare pattern",
      _c.count("GRANT ALL PRIVILEGES ON `gs12\\_lp`.* TO 'gs12_lp'@'localhost';") == 1
      and _c.count("GRANT ALL PRIVILEGES ON `gs12\\_lp`.* TO 'gs12_lp'@'127.0.0.1';") == 1
      and "ON `gs12_lp`" not in _c, _c)
check("db SQL: both accounts are made, each capped, with MariaDB's native password syntax",
      all("CREATE USER 'gs12_lp'@'%s' IDENTIFIED VIA mysql_native_password USING PASSWORD('%s') "
          "WITH MAX_USER_CONNECTIONS 30;" % (h, _PW) in _c for h in ("localhost", "127.0.0.1"))
      and _c.startswith("CREATE DATABASE `gs12_lp` CHARACTER SET utf8mb4;\n"), _c)
check("db SQL: MySQL takes native where it is offered and caching_sha2_password otherwise",
      "IDENTIFIED WITH mysql_native_password BY '%s'" % _PW in _helper.db_sql_create("mysql", "gs1_a", "native", "1", _PW)
      and "IDENTIFIED WITH caching_sha2_password BY '%s'" % _PW in _helper.db_sql_create("mysql", "gs1_a", "sha2", "1", _PW))
eq("db SQL: a MariaDB account is never made with sha2 (both copies refuse)",
   [_takes(lambda f: f("mariadb", "sha2", _PW), f) for f in (_helper.db_identified, _priv207.db_identified)],
   [False, False])
check("db SQL: harden drops anonymous and remote root accounts and `test`, then keys the panel's admin",
      all(s in _helper.db_sql_harden(_PW) for s in (
          "DELETE FROM mysql.global_priv WHERE User='';",
          "DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');",
          "DROP DATABASE IF EXISTS test;", "Db='test\\\\_%'",
          "CREATE USER IF NOT EXISTS 'linuxgsm_panel_admin'@'localhost'", "ALTER USER 'linuxgsm_panel_admin'@",
          "TO 'linuxgsm_panel_admin'@'localhost' WITH GRANT OPTION;")))
eq("db option file: quotes and backslashes are escaped, # and spaces kept inside the quotes",
   _helper.db_defaults_text("root", 'a"b\\c #d '), '[client]\nuser="root"\npassword="a\\"b\\\\c #d "\n')
eq("db grants: ALL on *.* WITH GRANT OPTION, or MySQL's spelled-out list with CREATE USER, is ok; less is not",
   [_helper.db_grants_verdict(t) for t in (
       "1\nGRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION",
       "GRANT SELECT, INSERT, CREATE USER, RELOAD ON *.* TO `a`@`%` WITH GRANT OPTION\nGRANT X ON *.* TO `a`@`%`",
       "GRANT ALL PRIVILEGES ON *.* TO `a`@`%`",
       "GRANT ALL PRIVILEGES ON `gs1\\_a`.* TO `a`@`%` WITH GRANT OPTION",
       "GRANT CREATE USER ON *.* TO `a`@`%`\nGRANT SELECT ON *.* TO `a`@`%` WITH GRANT OPTION")],
   ["ok", "ok", "lacks_grants", "lacks_grants", "lacks_grants"])
eq("db harden: only the system schemas and gs<n>_* databases count as the panel's",
   _helper.db_foreign("information_schema\nmysql\nperformance_schema\nsys\ntest\ngs3_lp\nlegacy\ngs0_x\n"),
   ["legacy", "gs0_x"])

# ── 3. no secret on any command line ─────────────────────────────────────────────────────────────
_VERB_ARGS = {
    "db-harden": (["mariadb"], {"pw": _PW}),
    "db-create": (["mysql", "tcp3306", "gs12_lp", "sha2", "30"], {"admin": _ADMIN, "pw": _PW}),
    "db-password": (["mariadb", "tcp3307", "gs12_lp", "native"], {"admin": _ADMIN, "pw": _PW}),
    "db-sizes": (["mariadb", "tcp3306", "gs12_lp", "gs12_x"], {"admin": _ADMIN}),
    "db-dump": (["mariadb", "tcp3306", "game", _ACCT, "gs12_lp"], {"admin": _ADMIN}),
    "db-import": (["mariadb", "3306", _ACCT, "gs12_lp"], {"pw": _PW}),
    "db-drop": (["mysql", "tcp3306", "gs12_lp"], {"admin": _ADMIN}),
    "db-admin-check": (["mysql", "tcp3306"], {"admin": _ADMIN}),
}
eq("db verbs: every db-* verb is exercised here", sorted(list(_VERB_ARGS) + ["db-probe"]), sorted(_priv207.DB_VERBS))
_on_argv, _off_stdin = [], []
for _v, (_a, _s) in _VERB_ARGS.items():
    _secret_vals = [x for x in (_s.get("pw"), (_s.get("admin") or ("", ""))[1]) if x]
    for _label, _cmd in (("helper argv", " ".join(_priv207.helper_argv(_v, _a))),
                         ("remote", _priv207.remote_command(_v, _a))):
        if any(x in _cmd for x in _secret_vals) or "Sentinelpw" in _cmd or "Adm in" in _cmd:
            _on_argv.append("%s %s" % (_v, _label))
    _hin, _rin = _priv207.helper_stdin(_v, _a, _s), _priv207.remote_stdin(_v, _a, _s)
    if not all(x in _hin for x in _secret_vals):
        _off_stdin.append("%s helper" % _v)
    if not all(_priv207.db_option_value(x)[1:-1] in _rin or x in _rin for x in _secret_vals):
        _off_stdin.append("%s remote" % _v)
eq("db secrets: no password or admin login is on the helper's argv or in any remote command line", _on_argv, [])
eq("db secrets: ...they are on stdin instead, on both paths (positive control)", _off_stdin, [])
eq("db secrets: a verb with nothing secret still sends a document that ends (no stdin left open)",
   (_priv207.helper_stdin("db-sizes", ["mariadb", "socket", "gs1_a"], {}),
    _priv207.remote_stdin("db-sizes", ["mariadb", "socket", "gs1_a"], {})), ("end\n", ""))
eq("db verbs: none is local-only (a game server on a remote needs databases too)",
   sorted(_priv207.DB_VERBS & _priv207.LOCAL_ONLY_VERBS), [])
eq("db verbs: the helper treats the probe, sizes and admin check as reads, and nothing else",
   sorted(v for v in _helper.READ_VERBS if v.startswith("db-")), ["db-admin-check", "db-probe", "db-sizes"])

# ── 4 + 5. the helper's verbs and their remote renderings, against stand-in tools ───────────────
_T = _tf207.mkdtemp(prefix="lgsm-unit-p207-")
_O = _os207.path.join(_T, "out")
_BIN = _os207.path.join(_T, "bin")
_HOME = _os207.path.join(_T, "home", _ACCT)
for _d in (_O, _BIN, _HOME, _os207.path.join(_T, "tmp"), _os207.path.join(_T, "elsewhere")):
    _os207.makedirs(_d, exist_ok=True)
_CLIENT_SH = r'''#!/bin/bash
O=__O__
for a in "$@"; do [ "$a" = --help ] && { cat "$O/help" 2>/dev/null; exit 0; }; done
n=$(cat "$O/n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$O/n"
printf '%s\n' "$@" > "$O/argv.$n"
for a in "$@"; do case "$a" in --defaults-extra-file=*) f=${a#*=}; cat "$f" > "$O/def.$n"; echo "$f" > "$O/defpath.$n";; esac; done
sql=; prev=; for a in "$@"; do [ "$prev" = -e ] && sql=$a; prev=$a; done
[ -z "$sql" ] && sql=$(cat)
printf '%s' "$sql" > "$O/sql.$n"
case "$sql" in
  *"SELECT (SELECT COUNT"*) cat "$O/exists" 2>/dev/null || echo 0;;
  *"SHOW DATABASES"*) cat "$O/dbs";;
  *"SHOW GLOBAL VARIABLES"*) if [ -f "$O/probe_err" ]; then cat "$O/probe_err" >&2; exit 1; fi; cat "$O/probe";;
  *"SHOW GRANTS"*) if [ -f "$O/grants_err" ]; then cat "$O/grants_err" >&2; exit 1; fi; cat "$O/grants";;
  *"WHERE TABLE_SCHEMA="*) cat "$O/tables" 2>/dev/null || echo 0;;
  *"COALESCE(SUM"*) cat "$O/sizes";;
  *"CREATE DATABASE"*|*"ALTER USER"*|*"CREATE USER IF NOT EXISTS"*)
    if [ -f "$O/fail_write" ]; then
      echo "ERROR 1064 (42000): near '$(grep -o "PASSWORD('[^']*')\|BY '[^']*'" <<<"$sql" | head -1)' as $(cat "$O/def.$n" 2>/dev/null)" >&2
      exit 1
    fi;;
esac
exit 0
'''
_TOOLS_SH = {
    "mariadb": _CLIENT_SH,
    "mysql": _CLIENT_SH,
    "mariadb-dump": '#!/bin/bash\nO=__O__\nprintf "%s\\n" "$@" > "$O/dumpargv"\n'
                    'if [ -f "$O/dump_fail" ]; then echo "mysqldump: Got error 2002" >&2; exit 2; fi\n'
                    'printf -- "-- dump of %s\\nCREATE TABLE t (i int);\\n" "${@: -1}"\n',
    "mysqldump": None,
    "dpkg-query": '#!/bin/bash\ncat __O__/dpkg 2>/dev/null; exit 1\n',
    "systemctl": '#!/bin/bash\necho "$*" >> __O__/systemctl\n[ "$1" = is-active ] && '
                 '{ cat "__O__/active.$2" 2>/dev/null || { echo inactive; exit 3; }; }\nexit 0\n',
    "ss": '#!/bin/bash\necho "$*" > __O__/ssargv\ncat __O__/ss 2>/dev/null\n',
}
_TOOLS_SH["mysqldump"] = _TOOLS_SH["mariadb-dump"]
for _n, _body in _TOOLS_SH.items():
    with open(_os207.path.join(_BIN, _n), "w", encoding="utf-8") as _fh:
        _fh.write(_body.replace("__O__", _O))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in in this part's temp dir
    _os207.chmod(_os207.path.join(_BIN, _n), 0o700)  # nosec B103 - owner-only stand-in program in a temp dir


def _reset(**files):
    """Empty the stand-ins' record and give them `files` (name -> text) to answer with."""
    for _e in _os207.listdir(_O):
        _p = _os207.path.join(_O, _e)
        if _os207.path.isdir(_p) and not _os207.path.islink(_p):
            _sh207.rmtree(_p)
        else:
            _os207.unlink(_p)
    for _k, _t in files.items():
        with open(_os207.path.join(_O, _k), "w", encoding="utf-8") as fh:
            fh.write(_t)


def _rec(name):
    p = _os207.path.join(_O, name)
    return open(p, encoding="utf-8").read() if _os207.path.exists(p) else None


def _sqls():
    return [_rec("sql.%d" % i) for i in range(1, int((_rec("n") or "0").strip() or 0) + 1)]


_me = _pwd207.getpwuid(_os207.getuid())
_FAKE_UID = _me.pw_uid if _me.pw_uid != 0 else 4242
_DROPS = _os207.path.join(_O, "drops")


def _fake_getpwnam(name):
    if name != _ACCT:
        raise KeyError(name)
    return _pwd207.struct_passwd((name, "x", _FAKE_UID, _me.pw_gid, "", _HOME, "/bin/sh"))


def _fake_drop(pw, own_groups=False):
    with open(_DROPS, "a", encoding="utf-8") as fh:
        fh.write("%s\n" % pw.pw_name)
    return not _os207.path.exists(_os207.path.join(_O, "nodrop"))


_HSAVE = {k: getattr(_helper, k) for k in ("TOOLS", "pwd", "_drop_to", "DB_ARCHIVE_ROOT", "DB_ARCHIVE_DIR",
                                           "DB_HARDEN_CNF")}
_ARCH = _os207.path.join(_T, "arch")
_helper.TOOLS = dict(_helper.TOOLS, **{n: (_os207.path.join(_BIN, n),) for n in _TOOLS_SH})
_helper.pwd = _ty207.SimpleNamespace(getpwnam=_fake_getpwnam, getpwuid=_pwd207.getpwuid)
_helper._drop_to = _fake_drop
_helper.DB_ARCHIVE_ROOT, _helper.DB_ARCHIVE_DIR = _ARCH, _ARCH + "/databases"
_helper.DB_HARDEN_CNF = _os207.path.join(_T, "etc", "mariadb.conf.d", "60-linuxgsm-panel.cnf")


def _h(verb, args, secrets=None, doc=None):
    """(rc, stdout, stderr) of the helper's real main() for `verb`, its stdin the panel's document."""
    doc = _priv207.helper_stdin(verb, args, secrets or {}) if doc is None else doc
    saved = (_sys207.stdin, _sys207.stdout, _sys207.stderr)
    _sys207.stdin, _sys207.stdout, _sys207.stderr = _io207.StringIO(doc), _io207.StringIO(), _io207.StringIO()
    try:
        rc = _helper.main(["panel-helper", verb] + list(args))
        return rc, _sys207.stdout.getvalue(), _sys207.stderr.getvalue()
    finally:
        _sys207.stdin, _sys207.stdout, _sys207.stderr = saved


_FUNCS = "".join('%s() { %s "$@"; }; export -f %s; ' % (n, _os207.path.join(_BIN, n), n) for n in _TOOLS_SH)
_FUNCS += 'runuser() { shift 3; "$@"; }; export -f runuser; export TMPDIR=%s; ' % _os207.path.join(_T, "tmp")


def _r(verb, args, secrets=None):
    """(rc, output) of the verb's remote rendering, run by bash with the stand-ins as functions."""
    sh = (_priv207.remote_command(verb, args)
          .replace(_priv207.DB_ARCHIVE_DIR, _ARCH + "/databases").replace(_priv207.DB_ARCHIVE_ROOT, _ARCH)
          .replace(_priv207.DB_HARDEN_CNF, _helper.DB_HARDEN_CNF)
          .replace(_os207.path.dirname(_priv207.DB_HARDEN_CNF), _os207.path.dirname(_helper.DB_HARDEN_CNF))
          .replace("/home/" + _ACCT, _HOME))
    p = _sp207.run(["bash", "-c", _FUNCS + sh], input=_priv207.remote_stdin(verb, args, secrets or {}),  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, check=False)
    return p.returncode, p.stdout + p.stderr


try:
    # db-create: a free name is made, as the panel's statements, signed in with the login file.
    for _side, _run in (("helper", _h), ("remote", _r)):
        _reset()
        _res = _run("db-create", *_VERB_ARGS["db-create"])
        _s = _sqls()
        check("db-create (%s): a free name is created, with the panel's own statements" % _side,
              _res[0] == 0 and "created" in _res[1] and len(_s) == 2
              and _s[1].strip() == _helper.db_sql_create("mysql", "gs12_lp", "sha2", "30", _PW).strip(), repr((_res, _s)))
        check("db-create (%s): the client signs in with the login in an option file, gone afterwards" % _side,
              _rec("def.1") == _helper.db_defaults_text(*_ADMIN)
              and (_rec("argv.1") or "").splitlines()[0].startswith("--defaults-extra-file=")
              and not _os207.path.exists((_rec("defpath.1") or "x").strip()), repr((_rec("def.1"), _rec("argv.1"))))
        _reset(exists="2\n")
        _res = _run("db-create", *_VERB_ARGS["db-create"])
        check("db-create (%s): a name that exists already is refused (rc 3) and nothing is created" % _side,
              _res[0] == 3 and len(_sqls()) == 1, repr((_res, _sqls())))
        _reset(fail_write="1")
        _res = _run("db-create", *_VERB_ARGS["db-create"])
        _s = _sqls()
        check("db-create (%s): a failed create drops what it made, so a retry starts clean" % _side,
              _res[0] != 0 and len(_s) == 3 and _s[2].strip() == _helper.db_sql_drop("gs12_lp").strip(), repr((_res, _s)))
        if _side == "helper":
            _scrubbed = _res[1] + _res[2]
        else:
            _scrubbed = _priv207.db_scrub(_res[1], [_PW, _APW])
        check("db-create (%s): the client's error quoting both passwords is passed on scrubbed" % _side,
              _PW not in _scrubbed and _APW not in _scrubbed and _priv207.db_option_value(_APW)[1:-1] not in _scrubbed
              and "***" in _scrubbed and "ERROR 1064" in _scrubbed,
              _scrubbed[-300:])
    _reset(fail_write="1")
    _hres = _h("db-create", *_VERB_ARGS["db-create"])
    check("db-create (helper): its stderr holds neither password (root-side scrub)",
          _PW not in _hres[2] and _APW not in _hres[2] and "***" in _hres[2], _hres[2][-300:])

    # db-password and db-sizes
    for _side, _run in (("helper", _h), ("remote", _r)):
        _reset()
        _res = _run("db-password", *_VERB_ARGS["db-password"])
        check("db-password (%s): both accounts get the new password" % _side,
              _res[0] == 0 and (_sqls() or [""])[-1].strip() == _helper.db_sql_password(
                  "mariadb", "gs12_lp", "native", _PW).strip(), repr((_res, _sqls())))
        _reset(sizes="gs12_lp\t49152\n")
        _res = _run("db-sizes", *_VERB_ARGS["db-sizes"])
        check("db-sizes (%s): one query for every name, its answer passed on" % _side,
              _res[0] == 0 and "gs12_lp\t49152" in _res[1] and len(_sqls()) == 1
              and "IN ('gs12_lp','gs12_x')" in _sqls()[0], repr((_res, _sqls())))

    # db-admin-check
    for _side, _run in (("helper", _h), ("remote", _r)):
        _got = []
        for _files in ({"grants": "1\nGRANT ALL PRIVILEGES ON *.* TO `r`@`localhost` WITH GRANT OPTION\n"},
                       {"grants": "1\nGRANT USAGE ON *.* TO `r`@`localhost`\n"},
                       {"grants_err": "ERROR 1045 (28000): Access denied for user 'r'@'localhost'\n"},
                       {"grants_err": "ERROR 2003 (HY000): Can't connect\n"}):
            _reset(**_files)
            _res = _run("db-admin-check", *_VERB_ARGS["db-admin-check"])
            _got.append((_res[0], _res[1].split()[-1] if _res[1].split() else ""))
        eq("db-admin-check (%s): ok, lacks_grants, denied (rc 0), and an unreadable answer is rc 1" % _side,
           _got, [(0, "ok"), (0, "lacks_grants"), (0, "denied"), (1, "unreadable")])

    # db-harden
    for _side, _run in (("helper", _h), ("remote", _r)):
        _cnf = _helper.DB_HARDEN_CNF
        if _os207.path.exists(_cnf):
            _os207.unlink(_cnf)
        _reset(dbs="information_schema\nmysql\nperformance_schema\nsys\nlegacy\n")
        _res = _run("db-harden", *_VERB_ARGS["db-harden"])
        check("db-harden (%s): a server holding a database the panel did not make is refused, untouched" % _side,
              _res[0] == 3 and not _os207.path.exists(_cnf) and _rec("systemctl") is None and len(_sqls()) == 1,
              repr((_res, _rec("systemctl"), _sqls())))
        _reset(dbs="information_schema\nmysql\nperformance_schema\nsys\ngs4_lp\n")
        _res = _run("db-harden", *_VERB_ARGS["db-harden"])
        _mode = oct(_os207.stat(_cnf).st_mode & 0o777) if _os207.path.exists(_cnf) else None
        check("db-harden (%s): a fresh server gets the loopback-only config (0644), a restart, then the SQL" % _side,
              _res[0] == 0 and "hardened" in _res[1] and _mode == "0o644"
              and open(_cnf, encoding="utf-8").read() == _helper.DB_HARDEN_CNF_TEXT
              and (_rec("systemctl") or "").strip() == "restart mariadb"
              and (_sqls() or [""])[-1].strip() == _helper.db_sql_harden(_PW).strip(), repr((_res, _mode, _rec("systemctl"))))
    check("db-harden: the config listens on loopback only, with LOCAL INFILE and name lookups off",
          all(x in _helper.DB_HARDEN_CNF_TEXT for x in ("bind-address = 127.0.0.1", "local-infile = 0",
                                                         "skip-name-resolve", "[mysqld]")))
    eq("db-harden: MySQL is never hardened (both copies refuse)",
       [_h("db-harden", ["mysql"], {"pw": _PW})[0], _takes(lambda a: _priv207.remote_command("db-harden", a), ["mysql"])],
       [2, False])

    # db-drop: an archive copy first; with none, only an empty database goes.
    for _side, _run in (("helper", _h), ("remote", _r)):
        _sh207.rmtree(_ARCH, ignore_errors=True)
        _reset()
        _res = _run("db-drop", *_VERB_ARGS["db-drop"])
        _files = _os207.listdir(_ARCH + "/databases") if _os207.path.isdir(_ARCH + "/databases") else []
        _kept = _gz207.open(_os207.path.join(_ARCH, "databases", _files[0])).read().decode() if _files else ""
        check("db-drop (%s): a gzip'd copy is kept in the root-only archive, then the database and both accounts go" % _side,
              _res[0] == 0 and "dropped" in _res[1] and len(_files) == 1
              and _re207.fullmatch(_helper.DB_ARCHIVE_FILE_RE, _files[0]) and "-- dump of gs12_lp" in _kept
              and oct(_os207.stat(_ARCH + "/databases").st_mode & 0o777) == "0o700"
              and oct(_os207.stat(_os207.path.join(_ARCH, "databases", _files[0])).st_mode & 0o777) == "0o600"
              and (_sqls() or [""])[-1].strip() == _helper.db_sql_drop("gs12_lp").strip(),
              repr((_res, _files, _sqls())))
        eq("db-drop (%s): the dump is MySQL's (gtid and tablespaces off), consistent and complete" % _side,
           (_rec("dumpargv") or "").splitlines()[-10:],
           list(_helper.DB_DUMP_OPTS + _helper.DB_DUMP_OPTS_MYSQL) + ["gs12_lp"])
        _reset(dump_fail="1", tables="3\n")
        _res = _run("db-drop", *_VERB_ARGS["db-drop"])
        check("db-drop (%s): no copy and a database with tables: refused (rc 3), nothing dropped" % _side,
              _res[0] == 3 and not any("DROP" in (s or "") for s in _sqls()), repr((_res, _sqls())))
        _reset(dump_fail="1", tables="0\n")
        _res = _run("db-drop", *_VERB_ARGS["db-drop"])
        check("db-drop (%s): no copy but an empty database: it goes" % _side,
              _res[0] == 0 and "DROP DATABASE IF EXISTS `gs12_lp`" in (_sqls() or [""])[-1], repr((_res, _sqls())))
    # The prune: whole days, as find -mtime +30 counts them.
    _pd = _os207.path.join(_T, "prune")
    _os207.makedirs(_pd, exist_ok=True)
    for _f, _age in (("gs1_a-20260101T000000Z.sql.gz", 31.2), ("gs1_a-20260102T000000Z.sql.gz", 30.9),
                     ("other.sql.gz", 90)):
        with open(_os207.path.join(_pd, _f), "w") as fh:
            fh.write("x")
        _os207.utime(_os207.path.join(_pd, _f), (1e9 - _age * 86400, 1e9 - _age * 86400))
    _helper._db_prune_archive(_pd, now=1e9)
    eq("db archive: dumps older than 30 whole days go; younger ones and other files stay",
       sorted(_os207.listdir(_pd)), ["gs1_a-20260102T000000Z.sql.gz", "other.sql.gz"])

    # db-dump into the game's files: written AS the account, after the drop, never through a link.
    _dd = _os207.path.join(_HOME, _helper.DB_DUMP_DIR)
    for _side, _run in (("helper", _h), ("remote", _r)):
        _sh207.rmtree(_dd, ignore_errors=True)
        _reset()
        _res = _run("db-dump", *_VERB_ARGS["db-dump"])
        _gzp = _os207.path.join(_dd, "gs12_lp.sql.gz")
        check("db-dump game (%s): ~/panel-db-dumps/<name>.sql.gz holds the dump, owner-only, no .tmp left" % _side,
              _res[0] == 0 and "dumped=gs12_lp" in _res[1] and _os207.path.isfile(_gzp)
              and "-- dump of gs12_lp" in _gz207.open(_gzp).read().decode()
              and oct(_os207.stat(_dd).st_mode & 0o777) == "0o700" and _os207.listdir(_dd) == ["gs12_lp.sql.gz"],
              repr((_res, _os207.listdir(_dd) if _os207.path.isdir(_dd) else None)))
    _reset()
    _res = _h("db-dump", *_VERB_ARGS["db-dump"])
    eq("db-dump game (helper): the writer drops to the game account before it writes",
       (_res[0], (_rec("drops") or "").split()), (0, [_ACCT]))
    _sh207.rmtree(_dd, ignore_errors=True)
    _reset(nodrop="1")
    _res = _h("db-dump", *_VERB_ARGS["db-dump"])
    check("db-dump game (helper): a drop that does not take writes nothing at all",
          _res[0] == 1 and "failed=gs12_lp" in _res[1] and not _os207.path.exists(_dd), repr(_res))
    _reset(dump_fail="1")
    _res = _h("db-dump", *_VERB_ARGS["db-dump"])
    check("db-dump game (helper): a dump that failed leaves no file and no .tmp behind",
          _res[0] == 1 and (not _os207.path.isdir(_dd) or _os207.listdir(_dd) == []), repr(_res))
    _sh207.rmtree(_dd, ignore_errors=True)
    _os207.symlink(_os207.path.join(_T, "elsewhere"), _dd)
    _reset()
    _res = _h("db-dump", *_VERB_ARGS["db-dump"])
    check("db-dump game (helper): a link planted at ~/panel-db-dumps is not followed",
          _res[0] == 1 and _os207.listdir(_os207.path.join(_T, "elsewhere")) == [], repr(_res))
    _os207.unlink(_dd)
    eq("db-dump: a dump into a server's files needs its account (both copies refuse '-')",
       [_h("db-dump", ["mariadb", "socket", "game", "-", "gs1_a"])[0],
        _takes(lambda a: _priv207.remote_command("db-dump", a), ["mariadb", "socket", "game", "-", "gs1_a"])],
       [2, False])

    # db-import: as the account, as the database's own user, the sandbox line dropped.
    _os207.makedirs(_dd, exist_ok=True)
    with _gz207.open(_os207.path.join(_dd, "gs12_lp.sql.gz"), "wb") as _fh:
        _fh.write(("%s\nCREATE TABLE luckperms_players (uuid varchar(36));\n" % _helper.DB_SANDBOX_LINE).encode())
    for _side, _run in (("helper", _h), ("remote", _r)):
        _reset(help="  --sandbox   Disallow commands that access the file system\n")
        _res = _run("db-import", *_VERB_ARGS["db-import"])
        _s = [s for s in _sqls() if s]
        _argv = (_rec("argv.1") or "").splitlines()
        check("db-import (%s): the dump is fed without its sandbox line, to the named database" % _side,
              _res[0] == 0 and len(_s) == 1 and _s[0].startswith("CREATE TABLE luckperms_players")
              and "enable the sandbox mode" not in _s[0] and _argv[-1] == "gs12_lp", repr((_res, _s, _argv)))
        check("db-import (%s): signed in as the database's own account over 127.0.0.1, with --sandbox" % _side,
              _rec("def.1") == _helper.db_defaults_text("gs12_lp", _PW) and _argv[0].startswith("--defaults-extra-file=")
              and "--sandbox" in _argv and "--protocol=tcp" in _argv and "--host=127.0.0.1" in _argv
              and "--port=3306" in _argv, repr((_rec("def.1"), _argv)))
    _reset(help="no such option here\n")
    _h("db-import", *_VERB_ARGS["db-import"])
    check("db-import (helper): a client without --sandbox is not handed it",
          "--sandbox" not in (_rec("argv.1") or ""), _rec("argv.1"))
    _reset()
    _h("db-import", *_VERB_ARGS["db-import"])
    eq("db-import (helper): the import runs after the drop to the game account", (_rec("drops") or "").split(), [_ACCT])
    _reset(nodrop="1")
    _res = _h("db-import", *_VERB_ARGS["db-import"])
    check("db-import (helper): a drop that does not take imports nothing", _res[0] == 1 and not _sqls(), repr(_res))
    _os207.unlink(_os207.path.join(_dd, "gs12_lp.sql.gz"))
    _os207.symlink(_os207.path.join(_T, "elsewhere", "x.sql.gz"), _os207.path.join(_dd, "gs12_lp.sql.gz"))
    with _gz207.open(_os207.path.join(_T, "elsewhere", "x.sql.gz"), "wb") as _fh:
        _fh.write(b"DROP TABLE x;\n")
    for _side, _run in (("helper", _h), ("remote", _r)):
        _reset()
        _res = _run("db-import", *_VERB_ARGS["db-import"])
        check("db-import (%s): a dump that is a link is refused, nothing fed to the client" % _side,
              _res[0] != 0 and not [s for s in _sqls() if s], repr((_res, _sqls())))

    # db-probe: the helper and the remote rendering say the same thing about the same host.
    _PROBE_FILES = {"dpkg": "mariadb-server\tii \t1:10.11.14-0ubuntu0.24.04.1\nmysql-server\tun \t\n",
                    "active.mariadb": "active\n", "ss": "LISTEN 0 80 127.0.0.1:3306 0.0.0.0:*\n",
                    "probe": "bind_address\t127.0.0.1\nlocal_infile\tON\nport\t3306\nsocket\t/run/mysqld/mysqld.sock\n"
                             "version\t10.11.14-MariaDB-0ubuntu0.24.04.1\nnative\tACTIVE\n"}
    _reset(**_PROBE_FILES)
    _hp = _h("db-probe", [])
    _reset(**_PROBE_FILES)
    _rp = _r("db-probe", [])
    eq("db-probe: the helper and the remote rendering print the same lines", _hp[1].strip(), _rp[1].strip())
    eq("db-probe: packages installed, services, loopback listener, socket root and the variables",
       _hp[1].strip().splitlines(),
       ["pkg=mariadb-server\t1:10.11.14-0ubuntu0.24.04.1", "active.mariadb=active", "active.mysql=inactive",
        "listen=127.0.0.1:3306", "socket_root=ok", "var.bind_address=127.0.0.1", "var.local_infile=ON",
        "var.port=3306", "var.socket=/run/mysqld/mysqld.sock", "var.version=10.11.14-MariaDB-0ubuntu0.24.04.1",
        "var.native=ACTIVE"])
    check("db-probe: it asks ss about the default port and signs in over the socket as root, naming no path",
          (_rec("ssargv") or "").strip() == "-Hltn sport = :3306"
          and (_rec("argv.1") or "").splitlines()[:2] == ["--protocol=socket", "--user=root"]
          and "--socket" not in (_rec("argv.1") or ""), repr((_rec("ssargv"), _rec("argv.1"))))
    for _err, _want in (("ERROR 1698 (28000): Access denied for user 'root'@'localhost'", "denied"),
                        ("ERROR 2002 (HY000): Can't connect to local server through socket", "nosocket"),
                        ("ERROR 1105: something else", "error")):
        _reset(probe_err=_err + "\n")
        _hp = _h("db-probe", [])
        _reset(probe_err=_err + "\n")
        _rp = _r("db-probe", [])
        eq("db-probe: a refused socket sign-in reads socket_root=%s on both paths" % _want,
           [("socket_root=" + _want) in x[1].splitlines() for x in (_hp, _rp)], [True, True])
    _reset(**_PROBE_FILES)
    _h("db-probe", [])
    eq("db-probe: it writes nothing (no database statement but the probe's own)",
       [s for s in (_sqls() or []) if s and "SHOW GLOBAL VARIABLES" not in s], [])
finally:
    for _k, _v in _HSAVE.items():
        setattr(_helper, _k, _v)

eq("db verbs: every action but the probe reads its document (STDIN_VERBS)",
   sorted(v for v in _helper.STDIN_VERBS if v.startswith("db-")),
   sorted(_priv207.DB_VERBS - {"db-probe"}))

# ── 6. databases.py, through a stubbed run_privileged ────────────────────────────────────────────
eq("databases: db_name builds gs<id>_<slug> and refuses anything else",
   [_dbs207.db_name(12, "luckperms")] + [_takes(lambda a: _dbs207.db_name(*a), a) for a in (
       (0, "x"), (-1, "x"), (True, "x"), ("12", "x"), (12, "Lp"), (12, "a_b"), (12, "x" * 17), (12, ""),
       (12, "lp\n"), (12345678901, "x"))],
   ["gs12_luckperms", False, False, False, False, False, False, False, False, False, False])
_pws = [_dbs207.new_password() for _ in range(1000)]
_badpw = [p for p in _pws if not (len(p) == 32 and p[0].isalpha() and _re207.fullmatch(_priv207.DB_PW_RE, p)
                                  and any(c.isupper() for c in p) and any(c.islower() for c in p)
                                  and any(c.isdigit() for c in p) and any(c in "-_." for c in p)
                                  and not any(c in ";,/?:@&=+$#'\"\\ " for c in p))]
eq("databases: 1000 new passwords are 32 characters, start with a letter, hold every class, need no quoting",
   _badpw[:3], [])
check("databases: ...all different, and drawn from `secrets`",
      len(set(_pws)) == 1000 and "_secrets.choice" in open(_dbs207.__file__, encoding="utf-8").read()
      and "import random" not in open(_dbs207.__file__, encoding="utf-8").read())

_CALLS = []
_ANSWERS = {}


def _fake_rp(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    _CALLS.append((verb, list(args), secrets, timeout))
    ans = _ANSWERS.get(verb, ("", "", 0))
    return ans(args) if callable(ans) else ans


_PROBES = {
    "mariadb 10.6 on 22.04": ("pkg=mariadb-server\t1:10.6.23-0ubuntu0.22.04.1\nactive.mariadb=active\nactive.mysql=active\n"
                              "listen=127.0.0.1:3306\nsocket_root=ok\nvar.version=10.6.23-MariaDB-0ubuntu0.22.04.1\n"
                              "var.bind_address=127.0.0.1\nvar.port=3306\nvar.native=ACTIVE\n",
                              ("ready", "mariadb", True, [])),
    "mariadb 11.8 with /run/mariadbd": ("pkg=mariadb-server\t1:11.8.9+ds-4\nactive.mariadb=active\nlisten=127.0.0.1:3306\n"
                                        "socket_root=ok\nvar.version=11.8.9-MariaDB-4\nvar.socket=/run/mariadbd/mariadbd.sock\n"
                                        "var.bind_address=127.0.0.1\nvar.port=3306\nvar.native=ACTIVE\n",
                                        ("ready", "mariadb", True, [])),
    "mysql 8.0": ("pkg=mysql-server\t8.0.46-0ubuntu0.24.04.1\nactive.mysql=active\nlisten=127.0.0.1:3306\nsocket_root=ok\n"
                  "var.version=8.0.46-0ubuntu0.24.04.1\nvar.version_comment=(Ubuntu)\nvar.bind_address=127.0.0.1\n"
                  "var.port=3306\nvar.native=ACTIVE\nvar.require_secure_transport=OFF\n", ("ready", "mysql", True, [])),
    "mysql 8.4, native off": ("pkg=mysql-server\t8.4.11\nsocket_root=ok\nvar.version=8.4.11-0ubuntu1\nvar.port=3306\n"
                              "var.bind_address=127.0.0.1\nvar.native=DISABLED\n",
                              ("ready", "mysql", False, ["old_logins_only"])),
    "mysql 9 (no native plugin), TLS required": ("socket_root=ok\nvar.version=9.7.2\nvar.port=3306\n"
                                                 "var.require_secure_transport=ON\nvar.bind_address=127.0.0.1\n",
                                                 ("ready", "mysql", False, ["tls_required", "old_logins_only"])),
    "docker listener, no package": ("active.mariadb=inactive\nactive.mysql=inactive\nlisten=0.0.0.0:3306\n"
                                    "socket_root=nosocket\n", ("needs_login", "mysql", False, ["exposed", "old_logins_only"])),
    "socket root refused": ("pkg=mysql-server\t8.0.46\nactive.mysql=active\nlisten=127.0.0.1:3306\nsocket_root=denied\n",
                            ("needs_login", "mysql", False, ["old_logins_only"])),
    "percona": ("pkg=percona-server-server\t8.0.36\nsocket_root=ok\nvar.version=8.0.36-28\n"
                "var.version_comment=Percona Server (GPL)\n", ("unsupported", "mysql", False, ["old_logins_only"])),
    "mariadb 10.3": ("socket_root=ok\nvar.version=10.3.39-MariaDB\nvar.native=ACTIVE\n", ("unsupported", "mariadb", True, [])),
    "exposed bind": ("pkg=mariadb-server\t1:10.11.14\nlisten=0.0.0.0:3306\nsocket_root=ok\nvar.version=10.11.14-MariaDB\n"
                     "var.bind_address=0.0.0.0\nvar.skip_networking=OFF\nvar.native=ACTIVE\n",
                     ("ready", "mariadb", True, ["exposed"])),
    "skip_networking": ("socket_root=ok\nvar.version=10.11.14-MariaDB\nvar.skip_networking=ON\nvar.native=ACTIVE\n",
                        ("ready", "mariadb", True, ["skip_networking"])),
    "nothing installed": ("active.mariadb=inactive\nactive.mysql=inactive\nsocket_root=noclient\n", ("none", "mysql", False, [])),
    "installed but stopped": ("pkg=mariadb-server\t1:10.11.14\nactive.mariadb=inactive\nsocket_root=nosocket\n",
                              ("unsupported", "mariadb", True, [])),
    "empty output": ("", ("unreadable", "", True, [])),
    "cut short (no socket line)": ("pkg=mariadb-server\t1:10.11.14\n", ("unreadable", "", True, [])),
}
_rp_saved = _smc207.run_privileged
_smc207.run_privileged = _fake_rp
try:
    _wrong = []
    for _k, (_out, _want) in _PROBES.items():
        _ANSWERS["db-probe"] = (_out, "", 0)
        _p = _dbs207.probe(object())
        if (_p["state"], _p["flavor"], _p["native_ok"], _p["warnings"]) != _want:
            _wrong.append("%s: %r" % (_k, (_p["state"], _p["flavor"], _p["native_ok"], _p["warnings"])))
    eq("databases: the probe reads every server shape into its state, flavor, native and warnings", _wrong, [])
    _ANSWERS["db-probe"] = ("socket_root=ok\nvar.version=10.11.14-MariaDB\n", "", 1)
    eq("databases: a probe that failed is unreadable, never 'none'", _dbs207.probe(object())["state"], "unreadable")
    _ANSWERS["db-probe"] = (_PROBES["mysql 8.0"][0].replace("port=3306", "port=3307"), "", 0)
    eq("databases: the probe reads the server's port", _dbs207.probe(object())["port"], 3307)

    _hd_sock = _ty207.SimpleNamespace(flavor="mariadb", native_ok=True, auth_mode="socket", port=3306,
                                      admin_user="", admin_secret="")
    from panel.core.config import encrypt_secret as _enc207
    _hd_login = _ty207.SimpleNamespace(flavor="mysql", native_ok=False, auth_mode="login", port=3307,
                                       admin_user="rootadmin", admin_secret=_enc207(_APW))
    eq("databases: plugin_for is native on MariaDB and where MySQL offers it, else sha2",
       [_dbs207.plugin_for(h) for h in (_hd_sock, _hd_login, _ty207.SimpleNamespace(flavor="mysql", native_ok=True))],
       ["native", "sha2", "native"])
    _CALLS.clear()
    _ANSWERS["db-create"] = ("created", "", 0)
    _ok = _dbs207.create(object(), _hd_login, "gs12_lp", _PW, 30)
    eq("databases: create sends db-create with the host's flavor, a tcp sign-in, sha2, the cap; the secrets apart",
       (_ok[0], _CALLS), (True, [("db-create", ["mysql", "tcp3307", "gs12_lp", "sha2", "30"],
                                  {"pw": _PW, "admin": ("rootadmin", _APW)}, 60)]))
    _CALLS.clear()
    _dbs207.create(object(), _hd_sock, "gs12_lp", _PW, 30)
    eq("databases: a socket host sends no admin login at all",
       _CALLS[0][:3], ("db-create", ["mariadb", "socket", "gs12_lp", "native", "30"], {"pw": _PW}))
    _rc_words = []
    for _rc in (3, 127, 2, 1):
        _ANSWERS["db-create"] = ("x", "", _rc)
        _rc_words.append(str(_dbs207.create(object(), _hd_sock, "gs12_lp", _PW, 30)[1]))
    eq("databases: create's answers are fixed sentences per outcome",
       _rc_words, [_dbs207.S_EXISTS.format(name="gs12_lp"), _dbs207.S_NO_CLIENT, _dbs207.S_REFUSED,
                   _dbs207.S_CREATE_FAILED.format(name="gs12_lp")])
    _ANSWERS["db-create"] = ("ERROR 1064 near 'PASSWORD('%s')'" % _PW, "", 1)
    check("databases: a failure never hands the client's words (or the password) to the caller",
          _PW not in str(_dbs207.create(object(), _hd_sock, "gs12_lp", _PW, 30)))
    _CALLS.clear()
    _dbs207.set_password(object(), _hd_login, "gs12_lp", _PW)
    _dbs207.drop(object(), _hd_login, _ACCT, "gs12_lp")
    eq("databases: set_password and drop send their verbs with the host's sign-in",
       [c[:3] for c in _CALLS], [("db-password", ["mysql", "tcp3307", "gs12_lp", "sha2"], {"pw": _PW, "admin": ("rootadmin", _APW)}),
                                  ("db-drop", ["mysql", "tcp3307", "gs12_lp"], {"admin": ("rootadmin", _APW)})])
    _ANSWERS["db-drop"] = ("panel-db: no copy", "", 3)
    eq("databases: a drop with no copy of a database holding tables says so",
       str(_dbs207.drop(object(), _hd_sock, _ACCT, "gs12_lp")[1]), _dbs207.S_NOT_EMPTY.format(name="gs12_lp"))
    _CALLS.clear()
    _ANSWERS["db-sizes"] = ("gs12_lp\t49152\n", "", 0)
    eq("databases: sizes makes ONE call for every name; a name with no tables is 0",
       (_dbs207.sizes(object(), _hd_sock, ["gs12_lp", "gs12_x"]), len(_CALLS)), ({"gs12_lp": 49152, "gs12_x": 0}, 1))
    _ANSWERS["db-sizes"] = ("", "", 1)
    eq("databases: sizes is None when unreadable, and {} with nothing asked (no call)",
       (_dbs207.sizes(object(), _hd_sock, ["gs12_lp"]), _dbs207.sizes(object(), _hd_sock, []), len(_CALLS)), (None, {}, 2))
    _verdicts = []
    for _ans in (("ok", "", 0), ("denied", "", 0), ("lacks_grants", "", 0), ("unreadable", "", 1), ("", "", 0)):
        _ANSWERS["db-admin-check"] = _ans
        _verdicts.append(_dbs207.check_admin_login(object(), 3307, "rootadmin", _APW))
    eq("databases: check_admin_login answers each verdict, and anything else is unreadable",
       _verdicts, ["ok", "denied", "lacks_grants", "unreadable", "unreadable"])
    _CALLS.clear()
    eq("databases: a login no client could be handed is denied without a call",
       (_dbs207.check_admin_login(object(), 3306, "root", "pä\nss"), _CALLS), ("denied", []))

    # The root-capable-account guard comes before any dump into a game's files, and any import.
    from panel.routes import _shared as _shared207
    _guard_saved = _shared207.game_account_write_refusal
    _GUARD = []
    try:
        _shared207.game_account_write_refusal = lambda r, u: _GUARD.append(u) or "refused: %s is root-capable" % u
        _CALLS.clear()
        _g1 = _dbs207.dump(object(), _hd_sock, "game", _ACCT, ["gs12_lp"])
        _g2 = _dbs207.restore(object(), _hd_sock, _ACCT, "gs12_lp", _PW)
        eq("databases: a root-capable account is refused before any dump into its files or import (no call made)",
           (_g1[0], _g2[0], _GUARD, _CALLS), (False, False, [_ACCT, _ACCT], []))
        _CALLS.clear()
        _dbs207.dump(object(), _hd_sock, "archive", "-", ["gs12_lp"])
        eq("databases: the root-only archive needs no account and asks no guard",
           (_CALLS[0][:2], _GUARD), (("db-dump", ["mariadb", "socket", "archive", "-", "gs12_lp"]), [_ACCT, _ACCT]))
        _shared207.game_account_write_refusal = lambda r, u: None
        _CALLS.clear()
        _ANSWERS["db-dump"] = ("dumped=gs12_lp\nfailed=gs12_x\n", "", 1)
        _d = _dbs207.dump(object(), _hd_sock, "game", _ACCT, ["gs12_lp", "gs12_x"])
        eq("databases: a plain account's dump is one call for every database; the failed ones are named",
           (len(_CALLS), _CALLS[0][1], _d[0], str(_d[1])),
           (1, ["mariadb", "socket", "game", _ACCT, "gs12_lp", "gs12_x"], False,
            _dbs207.S_DUMP_FAILED.format(names="gs12_x")))
        _CALLS.clear()
        _ANSWERS["db-import"] = ("panel-db: no dump", "", 4)
        _ri = _dbs207.restore(object(), _hd_login, _ACCT, "gs12_lp", _PW)
        eq("databases: restore imports as the account over the server's port with only the database's password",
           (_CALLS[0][:3], str(_ri[1])), (("db-import", ["mysql", "3307", _ACCT, "gs12_lp"], {"pw": _PW}),
                                          _dbs207.S_NO_DUMP.format(name="gs12_lp")))
    finally:
        _shared207.game_account_write_refusal = _guard_saved

    # install_mariadb: apt, universe when the package is not found, then harden with a new password.
    _CALLS.clear()
    _apt = iter([("E: Unable to locate package mariadb-server", "", 100), ("", "", 0)])
    _ANSWERS.update({"apt-install": lambda a: next(_apt), "apt-add-repo": ("", "", 0), "apt-update": ("", "", 0),
                     "db-harden": ("hardened", "", 0)})
    _inst = _dbs207.install_mariadb(object())
    eq("databases: install adds universe and retries when the package is not found, then hardens",
       ([c[0] for c in _CALLS], _inst[0], _CALLS[-1][1], set(_CALLS[-1][2]) == {"pw"},
        _CALLS[-1][2]["pw"] == _inst[2] and bool(_re207.fullmatch(_priv207.DB_PW_RE, _inst[2]))),
       (["apt-install", "apt-add-repo", "apt-update", "apt-install", "db-harden"], True, ["mariadb"], True, True))
    _CALLS.clear()
    _ANSWERS.update({"apt-install": ("E: dpkg was interrupted", "", 100)})
    eq("databases: an apt failure of another kind stops there, with no setup and no password",
       (_dbs207.install_mariadb(object()), [c[0] for c in _CALLS]), ((False, _dbs207.S_INSTALL_FAILED, ""), ["apt-install"]))
    _ANSWERS.update({"apt-install": ("", "", 0), "db-harden": ("panel-db: foreign", "", 3)})
    eq("databases: a server holding other databases is left alone, and says so",
       _dbs207.install_mariadb(object()), (False, _dbs207.S_FOREIGN, ""))
finally:
    _smc207.run_privileged = _rp_saved

# ── 7. run_privileged (through databases._verb): secrets on stdin, and scrubbed, on every transport ──
_TP = {}
_tp_saved = {k: getattr(_smc207, k) for k in ("is_local_server", "helper_present", "_exec_local_argv",
                                               "run_command", "_run_local")}
try:
    def _tp_exec(argv, timeout=30, stdin_text=None):
        _TP["helper"] = (list(argv), stdin_text)
        return ("ERROR near '%s' and %s" % (_PW, _APW), "", 1)

    def _tp_cmd(server, command, timeout=30, sudo=None, stdin_text=None):
        _TP["remote"] = (command, stdin_text, sudo)
        return ("ERROR near '%s' and %s" % (_PW, _APW), "", 1)

    def _tp_local(cmd, timeout=30, sudo=False, stdin_text=None):
        _TP["shell"] = (cmd, stdin_text, sudo)
        return ("ERROR near '%s' and %s" % (_PW, _APW), "", 1)

    _smc207._exec_local_argv, _smc207.run_command, _smc207._run_local = _tp_exec, _tp_cmd, _tp_local
    _smc207.helper_present = lambda recheck=False: True
    _a, _s = _VERB_ARGS["db-create"]
    _res = {}
    for _where, _local, _helped in (("helper", True, True), ("remote", False, True), ("shell", True, False)):
        _smc207.is_local_server = (lambda loc: (lambda s: loc))(_local)
        _smc207.helper_present = (lambda h: (lambda recheck=False: h))(_helped)
        _res[_where] = _dbs207._verb(object(), "db-create", _a, _s)
    eq("run_privileged: each transport was the one taken", sorted(_TP), ["helper", "remote", "shell"])
    eq("databases: what every transport answers is scrubbed of both secrets before a caller sees it",
       [w for w, r in _res.items() if _PW in r[1] or _APW in r[1] or "***" not in r[1] or r[0] != 1], [])
    check("run_privileged: the helper gets the document on stdin and no secret on argv",
          _TP["helper"][1] == _priv207.db_doc("db-create", _a, _s) and _PW not in " ".join(_TP["helper"][0])
          and _TP["helper"][0][3] == "db-create", repr(_TP["helper"]))
    check("run_privileged: a remote and the pre-helper shell get the option file and SQL on stdin, as root",
          all(_TP[w][1] == _priv207.db_remote_stdin("db-create", _a, _s) and _PW not in _TP[w][0]
              and _APW not in _TP[w][0] and _TP[w][2] is True for w in ("remote", "shell")),
          repr((_TP["remote"][2], _TP["shell"][2])))
finally:
    for _k, _v in _tp_saved.items():
        setattr(_smc207, _k, _v)

# ── 8. the models and the permission ─────────────────────────────────────────────────────────────
eq("models: both new tables keep their ids (AUTOINCREMENT) and are in the rebuild list",
   [_HD207.__table__.dialect_options["sqlite"]["autoincrement"], _GD207.__table__.dialect_options["sqlite"]["autoincrement"]],
   [True, True])
with _p9.app_context():
    _rs = _RS207(name="p207 host", host="203.0.113.207", username="p207", auth_method="key")
    _db207.session.add(_rs)
    _db207.session.commit()
    _gs = _GS207(remote_id=_rs.id, name="p207", short_name="pmcserver", game_type="pmc", port=25565)
    _db207.session.add(_gs)
    _db207.session.commit()
    _db207.session.add(_HD207(remote_id=_rs.id, flavor="mariadb", auth_mode="login", admin_user="rootadmin",
                              admin_secret=_enc207(_APW)))
    _db207.session.add(_GD207(remote_id=_rs.id, game_server_id=_gs.id, name="gs%d_lp" % _gs.id, secret=_enc207(_PW)))
    _db207.session.commit()
    _raw = _db207.session.execute(_db207.text("SELECT admin_user, admin_secret FROM host_database_server "
                                              "WHERE remote_id=:r"), {"r": _rs.id}).fetchone()
    check("models: the admin login and the passwords are ciphertext at rest",
          _raw is not None and "rootadmin" not in str(_raw) and _APW not in str(_raw)
          and _PW not in str(_db207.session.execute(_db207.text("SELECT secret FROM game_database")).fetchall()), repr(_raw))
    _db207.session.delete(_gs)
    _db207.session.commit()
    _orph = _GD207.query.filter_by(remote_id=_rs.id).all()
    eq("models: a removed game server leaves its database rows as orphans (game_server_id NULL)",
       [(o.name.startswith("gs"), o.game_server_id) for o in _orph], [(True, None)])
    _rid = _rs.id
    _db207.session.delete(_rs)
    _db207.session.commit()
    eq("models: a removed host takes its database rows with it",
       (_GD207.query.filter_by(remote_id=_rid).count(), _HD207.query.filter_by(remote_id=_rid).count()), (0, 0))

eq("permission: MANAGE_DATABASES is grantable, with its label",
   _auth207.ALL_PERMISSIONS.get(_auth207.MANAGE_DATABASES),
   "Manage a server's databases: add, delete, restore and reset them, and see their passwords")
_cats = {}
for _lang in ("es", "fr"):
    _cats[_lang] = {}
    for _f in _os207.listdir(_os207.path.join(_root, "panel", "translations", _lang)):
        with open(_os207.path.join(_root, "panel", "translations", _lang, _f), encoding="utf-8") as _fh:
            _cats[_lang].update(_js207.load(_fh))
_want_tr = [_auth207.ALL_PERMISSIONS[_auth207.MANAGE_DATABASES]] + [getattr(_dbs207, k) for k in dir(_dbs207)
                                                                     if k.startswith("S_")]
eq("permission + sentences: the label and every service sentence are translated in es and fr",
   [(lang, t[:40]) for lang in _cats for t in _want_tr if t not in _cats[lang]], [])
check("permission: no group is given it by default (the seeded Everyone group holds two view permissions)",
      "manage_databases" not in open(_os207.path.join(_root, "panel", "db", "models.py"), encoding="utf-8").read())

_sh207.rmtree(_T, ignore_errors=True)
check("part207: nothing reached a host (the transport tripwire is untouched)",
      len(_P9_TRIPPED) == _trips207, repr(_P9_TRIPPED[_trips207:][:4]))
