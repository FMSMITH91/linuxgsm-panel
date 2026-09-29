"""AUTOINCREMENT on the tables whose ids other things keep, for a database made before it existed.

A plain INTEGER PRIMARY KEY is SQLite's rowid, and the next INSERT gets max(rowid)+1 — so deleting
the newest host, game server, user or group hands its id to the very next one created. Everything
that remembered the old id then lands on the new row: a worker still running for the deleted
server, a job or cache entry keyed by it, an association row a bulk delete missed, a login cookie
of a deleted account. With AUTOINCREMENT, SQLite records the largest id it has ever handed out in
`sqlite_sequence` and never goes below it.

create_all() gives a new install that from the models (`sqlite_autoincrement`). SQLite cannot add
it to a table that exists, so an older install's tables are rebuilt ONCE, each in a transaction of
its own, the way SQLite documents for any change ALTER TABLE cannot make
(https://www.sqlite.org/lang_altertable.html#otheralter): the rows are copied aside, the table is
dropped and created again from the model (AUTOINCREMENT, its indexes), and the rows are copied back
with their ids. Safe here because the panel never turns on PRAGMA foreign_keys (DROP TABLE deletes
nothing else) and no panel database holds a trigger or a view (a restore refuses one), and it is
the new-table-then-rename order that matters: renaming the OLD table away first would rewrite
every other table's REFERENCES to the old name.

A table that cannot be copied without losing something — a column the model no longer declares,
a row the model's constraints refuse — is left exactly as it was, and logged. The panel runs on it
as before, and the next start tries again.
"""
import logging
import re

import sqlalchemy as sa

_log = logging.getLogger("panel.db.id_sequence")

# The keyword SQLite stores in the table's own CREATE statement, which is the only place it lives.
_AUTOINCREMENT = re.compile(r"\bAUTOINCREMENT\b", re.IGNORECASE)
_COPY_PREFIX = "_idseq_copy_"
_MASTER = sa.table("sqlite_master", sa.column("type"), sa.column("name"), sa.column("sql"))
_SEQUENCE = sa.table("sqlite_sequence", sa.column("name"), sa.column("seq"))


def lacks_autoincrement(conn, name):
    """True when table `name` exists and was created without AUTOINCREMENT."""
    row = conn.execute(sa.select(_MASTER.c.sql).where(
        _MASTER.c.type == "table", sa.func.lower(_MASTER.c.name) == name.lower())).first()
    return row is not None and not _AUTOINCREMENT.search(row[0] or "")


def _copy_columns(conn, table):
    """The columns the rows are carried through, or None when the copy would drop one.

    Every column the database has must be one the model declares: the model is what the table is
    created again from, and a column only an older version knew is not this migration's to lose.
    """
    have = {c["name"].lower() for c in sa.inspect(conn).get_columns(table.name)}
    declared = [c.name for c in table.columns]
    if not have <= {name.lower() for name in declared}:
        return None
    return [name for name in declared if name.lower() in have]


def _highest_reference(conn, refs):
    """The largest id any of `refs` (columns elsewhere that hold this table's ids) still holds."""
    insp, best = sa.inspect(conn), 0
    for col in refs:
        if not insp.has_table(col.table.name):
            continue
        if col.name not in {c["name"] for c in insp.get_columns(col.table.name)}:
            continue
        top = conn.execute(sa.select(sa.func.max(col))).scalar()
        if isinstance(top, int) and top > best:
            best = top
    return best


def _raise_sequence(conn, name, floor):
    """Make sure the next id SQLite hands out for `name` is above `floor`."""
    cur = conn.execute(sa.select(_SEQUENCE.c.seq).where(_SEQUENCE.c.name == name)).first()
    if cur is None:
        if floor > 0:
            conn.execute(sa.insert(_SEQUENCE).values(name=name, seq=floor))
    elif floor > (cur[0] or 0):
        conn.execute(sa.update(_SEQUENCE).where(_SEQUENCE.c.name == name).values(seq=floor))


def _count(conn, table):
    return conn.execute(sa.select(sa.func.count()).select_from(table)).scalar()


def _rebuild_in(conn, table, refs):
    """Rebuild `table` on `conn`, inside the caller's transaction. False when it is left alone."""
    if not lacks_autoincrement(conn, table.name):
        return False
    cols = _copy_columns(conn, table)
    if cols is None:
        _log.warning("%s has a column the panel no longer declares; it keeps plain rowids",
                     table.name)
        return False
    aside = sa.Table(_COPY_PREFIX + table.name, sa.MetaData(),
                     *[sa.Column(c, table.c[c].type) for c in cols])
    before = _count(conn, table)
    aside.create(conn)
    conn.execute(sa.insert(aside).from_select(
        cols, sa.select(*[table.c[c] for c in cols]), include_defaults=False))
    table.drop(conn)
    table.create(conn)          # the model's DDL: AUTOINCREMENT, and the table's own indexes
    conn.execute(sa.insert(table).from_select(
        cols, sa.select(*[aside.c[c] for c in cols]), include_defaults=False))
    aside.drop(conn)
    if _count(conn, table) != before:
        raise RuntimeError("%s: the row count changed in the copy" % table.name)
    # The copy leaves the sequence at the largest id copied. An id above that which a deleted row
    # had and something still names — an association row, an audit row — must not come back.
    _raise_sequence(conn, table.name, _highest_reference(conn, refs))
    return True


def rebuild_one(engine, table, refs=()):
    """Give `table` AUTOINCREMENT if it lacks it, in one transaction. True when it was rebuilt."""
    with engine.connect() as conn:
        # One transaction for the whole copy, so a failure anywhere leaves the table as it was.
        # pysqlite would open its own only before the first INSERT, after the CREATE of the copy.
        conn.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            done = _rebuild_in(conn, table, refs)
        except Exception:
            conn.rollback()
            raise
        if done:
            conn.commit()
        else:
            conn.rollback()
        return done


def references_to(table, metadata, extra=()):
    """Every column in `metadata` holding `table`'s ids: its foreign keys, plus `extra`."""
    cols = [fk.parent for t in metadata.tables.values() for fk in t.foreign_keys
            if fk.references(table)]
    return cols + list(extra)


def rebuild_for_autoincrement(engine, metadata, tables, extra_refs=None):
    """Rebuild each of `tables` that lacks AUTOINCREMENT. Returns the names rebuilt; never raises."""
    rebuilt = []
    for table in tables:
        refs = references_to(table, metadata, (extra_refs or {}).get(table.name, ()))
        try:
            if rebuild_one(engine, table, refs):
                rebuilt.append(table.name)
                _log.info("%s rebuilt with AUTOINCREMENT: its ids are never handed out again",
                          table.name)
        except Exception:
            _log.warning("could not rebuild %s with AUTOINCREMENT; it keeps plain rowids until "
                         "the next start", table.name, exc_info=True)
    return rebuilt
