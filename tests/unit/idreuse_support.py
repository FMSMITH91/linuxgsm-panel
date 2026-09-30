"""Test support, not a part: tables that hand a deleted row's id to the next row, on demand.

The models create game_server, remote_server and the other keyed tables with AUTOINCREMENT, so a
fresh test database never reuses an id. Every install made before that change still does until
its tables are rebuilt (panel/db/id_sequence.py), and a rebuild can be skipped — so the workers
still have to cope with reuse, and the checks that prove they do need it to happen. This rebuilds
the named tables of a live test database WITHOUT AUTOINCREMENT, exactly as create_all() made them
before, and put_back() gives them AUTOINCREMENT again through the panel's own migration.
"""
import sqlalchemy as sa


def _old_schema(metadata, names):
    """A copy of every table in `metadata`, the ones in `names` without AUTOINCREMENT."""
    old = sa.MetaData()
    for t in metadata.sorted_tables:
        c = t.to_metadata(old)
        if t.name in names:
            c.dialect_options["sqlite"]["autoincrement"] = False
    return old


def reuse_ids(db, names):
    """Rebuild tables `names` of `db`'s current engine with plain rowids. Call in an app context."""
    old = _old_schema(db.metadata, names)
    with db.engine.connect() as conn:
        conn.exec_driver_sql("BEGIN IMMEDIATE")
        for name in names:
            table = old.tables[name]
            cols = [c.name for c in table.columns]
            aside = sa.Table("_reuse_aside_" + name, sa.MetaData(),
                             *[sa.Column(c, table.c[c].type) for c in cols])
            aside.create(conn)
            conn.execute(sa.insert(aside).from_select(cols, sa.select(*table.c),
                                                      include_defaults=False))
            table.drop(conn)
            table.create(conn)
            conn.execute(sa.insert(table).from_select(cols, sa.select(*aside.c),
                                                      include_defaults=False))
            aside.drop(conn)
        conn.commit()
    db.session.remove()


def plain_rowids(db, name):
    """True when table `name` of `db` has no AUTOINCREMENT (ids are reused)."""
    from panel.db.id_sequence import lacks_autoincrement
    with db.engine.connect() as conn:
        return lacks_autoincrement(conn, name)


def put_back(db):
    """AUTOINCREMENT on every keyed table again, by the panel's own migration: the names rebuilt."""
    from panel.db import models
    db.session.remove()
    return models._give_keyed_tables_autoincrement()
