"""The Databases manager's data routes: browse a database's tables and rows, edit rows, run SQL.

Every route works on one of a game server's own databases (GameDatabase, gs<id>_*; never any other
database on the server) and signs in as THAT database's own account, never the admin login, so the
database server itself keeps every statement inside that one database (ssh_manager.db_data, the
db-query verb). The client runs where the database's other commands run: on the game host for a
server on another machine, on the database's own host otherwise.

PERMISSION. Browsing (tables, structure, rows, one whole value) takes MANAGE_DATABASES and access to
the server, as the rest of the Databases tab does. Changing rows and the SQL box take
EDIT_DATABASE_DATA as well (granted to no group by default; a superadmin holds every permission).

SAFETY. A table or column named in a request is looked up in the structure the database's own
information_schema gave (cached STRUCT_FRESH seconds per database) and quoted by db_data; values are
bound parameters. A row is addressed by its primary key; a table without one (or a view) is read-only.
The SQL box runs one statement, as a READ ONLY transaction unless it is not a SELECT / SHOW / DESCRIBE
/ EXPLAIN, which first takes a confirm step: the page shows the statement, and the server hands back
a token bound to exactly that statement, this viewer, this database and a few minutes. Every change
and every SQL statement writes an audit row: what kind, which database, how many rows, and the
statement with its string literals masked (db_data.mask_literals), never a value.
"""
import hashlib
import time

from flask import current_app, jsonify, request
from flask_login import current_user, login_required
from itsdangerous import BadSignature, URLSafeTimedSerializer

from panel.core import i18n
from panel.core.config import decrypt_secret
from panel.core.http import _json_body, _json_str
from panel.ops.ssh_manager import db_data as _dd
from panel.routes import databases as _dbr
from panel.security.auth import (EDIT_DATABASE_DATA, MANAGE_DATABASES, get_game, has_permission, log_action,
                                 server_access_required)

STRUCT_FRESH = 60           # seconds a database's structure is reused for its rows and edits
CONFIRM_MAX_AGE = 300       # seconds a SQL confirm token stays good
_STRUCT = {}                # GameDatabase id -> (monotonic time, {table name: table})

_DENIED = "Permission denied"
S_NOT_READY = "This database's server is not set up in the panel any more."
S_NO_TABLE = "There is no table by that name in this database."
S_NO_CLIENT = "This host has no database client (mariadb or mysql), so the panel can't open the database."
S_REFUSED_LOGIN = ("The database server refused this database's own account. If its password was changed "
                   "outside the panel, use Reset password.")
S_UNREACHABLE = "The database server could not be reached from {host}."
S_LATE = "The statement ran longer than {s} seconds and was stopped."
S_UNREAD = "The database's answer could not be read. Nothing was changed by the panel."
S_READONLY = {"view": "This is a view: its rows are changed in the tables it reads.",
              "no_key": "This table has no primary key, so the panel can't tell one row from another: it is read-only "
                        "here. Use the SQL box to change it."}
S_UNSUPPORTED_PS = ("MySQL can't run this kind of statement from the panel's SQL box (each statement runs as a "
                    "prepared statement). For DESCRIBE use SHOW COLUMNS FROM the table.")


def _say(status, sentence, **extra):
    return _dbr._say(status, sentence, **extra)


def _row(server_id, db_id):
    """(server, its database `db_id` or None)."""
    gs = get_game(server_id)
    return gs, _dbr._own_row(gs, db_id)


def _where(gs, r):
    """(remote the client runs on, the target it signs in to) for database `r`, or (None, None)."""
    target = _dbr._restore_target(gs, r)
    return (gs.remote, target) if target is not None else (None, None)


def _query(gs, r, mode, statements):
    """db_data.run for database `r` signed in as its own account; None when its server is not set up."""
    remote, target = _where(gs, r)
    if target is None:
        return None
    return _dd.run(remote, target, r.name, decrypt_secret(r.secret) or "", mode, statements)


def _problem(gs, ans):
    """The fixed sentence for an answer that did not work (sign-in, reach, time, no client), else None."""
    if ans is None:
        return 409, S_NOT_READY
    if ans.get("rc") == 127:
        return 502, S_NO_CLIENT
    if ans.get("late"):
        return 504, i18n.Sentence(S_LATE, s=_dd._priv.DB_QUERY_SECONDS)
    code = (ans.get("error") or {}).get("code")
    if code in (1045, 1698):
        return 502, S_REFUSED_LOGIN
    if code in (2002, 2003, 2013, 2005):
        return 502, i18n.Sentence(S_UNREACHABLE, host=gs.remote.name if gs.remote else "")
    if ans.get("rc") == 2:
        return 400, _dbr._dbs.S_REFUSED
    return None


def _structure(gs, r, fresh=False):
    """({table name: table}, None) for database `r`, or (None, (status, sentence)). Reused STRUCT_FRESH seconds."""
    got = _STRUCT.get(r.id)
    if got and not fresh and time.monotonic() - got[0] < STRUCT_FRESH:
        return got[1], None
    ans = _query(gs, r, "ro", list(_dd.STRUCTURE_SQL))
    bad = _problem(gs, ans)
    if bad:
        return None, bad
    tables = _dd.structure(ans)
    if tables is None:
        return None, (502, S_UNREAD)
    _STRUCT[r.id] = (time.monotonic(), tables)
    return tables, None


def forget(db_id):
    """Drop what is cached of database `db_id` (it was changed, restored or deleted)."""
    _STRUCT.pop(db_id, None)


def _table_json(t):
    why = _dd.editable(t)
    return {"name": t["name"], "type": t["type"], "engine": t["engine"], "rows": t["rows"], "bytes": t["bytes"],
            "view": t["view"], "pk": t["pk"], "readonly": why, "readonly_text": i18n.tr(S_READONLY[why]) if why else "",
            "columns": [{k: c[k] for k in ("name", "type", "nullable", "key", "default", "extra", "binary", "generated")}
                        for c in t["columns"]]}


def _audit_text(text):
    """A name read from the database, fit for an audit row: printable, one line, at most 64 characters."""
    return "".join(c if c.isprintable() else "?" for c in str(text or ""))[:64]


# ── answers ──────────────────────────────────────────────────────────────────────────────────────
def _tables_answer(gs, r):
    tables, bad = _structure(gs, r, fresh=True)
    if bad:
        return _say(*bad)
    return jsonify({"success": True, "database": r.name, "page_rows": _dd.PAGE_ROWS,
                    "can_edit": has_permission(current_user, EDIT_DATABASE_DATA),
                    "tables": [_table_json(t) for t in sorted(tables.values(), key=lambda t: t["name"].lower())]})


def _page_arg():
    try:
        return max(0, min(int(request.args.get("page", "0")), _dd.PAGE_MAX))
    except ValueError:
        return 0


def _rows_answer(gs, r):
    tables, bad = _structure(gs, r)
    if bad:
        return _say(*bad)
    t = tables.get(request.args.get("table", ""))
    if t is None:
        return _say(404, S_NO_TABLE)
    page = _page_arg()
    ans = _query(gs, r, "ro", [_dd.rows_statement(t, page)])
    bad = _problem(gs, ans)
    got = None if bad else _dd.rows(ans, t)
    if bad or got is None:
        return _say(*(bad or (502, S_UNREAD)))
    if page == 0:
        log_action(current_user, "db_browse", target=gs.name, server=gs,
                   detail="opened table %s.%s" % (r.name, _audit_text(t["name"])))
    why = _dd.editable(t)
    return jsonify(dict(got, success=True, page=page, columns=[c["name"] for c in t["columns"]],
                        readonly=why, readonly_text=i18n.tr(S_READONLY[why]) if why else ""))


def _keyed_table(gs, r, body):
    """(the table `body` names, None) when its rows can be addressed by key, else (None, a refusal)."""
    tables, bad = _structure(gs, r)
    if bad:
        return None, _say(*bad)
    t = tables.get(_json_str(body, "table"))
    if t is None:
        return None, _say(404, S_NO_TABLE)
    if _dd.editable(t):
        return None, _say(409, S_READONLY[_dd.editable(t)])
    return t, None


def _cell_answer(gs, r):
    body = _json_body()
    t, refused = _keyed_table(gs, r, body)
    if refused:
        return refused
    try:
        stmt = _dd.cell_statement(t, _json_str(body, "column"), body.get("key"))
    except ValueError:
        return _say(400, "That value can't be read: name a text column and the row's whole key.")
    ans = _query(gs, r, "ro", [stmt])
    bad = _problem(gs, ans)
    if bad:
        return _say(*bad)
    return _cell_value(ans)


def _cell_value(ans):
    """The one value a cell statement read, or the row's absence."""
    st = ans.get("statements") or []
    rows = st[0]["sets"][0]["rows"] if st and st[0]["sets"] else []
    if not rows:
        return _say(404, "That row is not in the table any more.")
    v = rows[0][0]
    return jsonify({"success": True, "null": v is None, "text": v or "",
                    "more": v is not None and len(v) >= _dd.FULL_CHARS})


# What the audit row says each did (its action is db_row_<op>).
_ROW_OPS = {"insert": "inserted", "update": "updated", "delete": "deleted"}


def _row_statement(t, op, body):
    """The statement for a row change; ValueError for a request that does not fit the table."""
    if op == "insert":
        return _dd.insert_statement(t, body.get("values"))
    if op == "update":
        return _dd.update_statement(t, body.get("key"), body.get("values"))
    return _dd.delete_statement(t, body.get("key"))


def _row_change_answer(gs, r):
    body = _json_body()
    op = _json_str(body, "op")
    if op not in _ROW_OPS:
        return _say(400, "Say what to do with the row: insert, update or delete.")
    t, refused = _keyed_table(gs, r, body)
    if refused:
        return refused
    try:
        stmt = _row_statement(t, op, body)
    except ValueError as e:
        return _say(400, i18n.Sentence("That change doesn't fit the table: {why}.", why=str(e)))
    ans = _query(gs, r, "rw", [stmt])
    values = body.get("values") if op != "delete" and isinstance(body.get("values"), dict) else {}
    return _row_change_done(gs, r, t, (op, values), ans)


def _affected(ans):
    """The first statement's row count in an answer, or None."""
    st = (ans or {}).get("statements") or []
    return st[0]["affected"] if st else None


def _row_audit(gs, r, t, change, outcome):
    """The row change's audit row: which table and columns, how many rows (never a value), or why not."""
    (op, values), (ok, affected, err) = change, outcome
    verb = _ROW_OPS[op]
    detail = "%s %s row(s) in %s.%s" % (verb, affected if ok else 0, r.name, _audit_text(t["name"]))
    if values:
        detail += " (columns: %s)" % ", ".join(sorted(_audit_text(n) for n in values))[:300]
    if not ok:
        detail += ": " + ("error %s" % err["code"] if err else "failed")
    log_action(current_user,
               "db_row_insert" if op == "insert" else ("db_row_update" if op == "update" else "db_row_delete"),
               target=gs.name, server=gs, detail=detail, success=ok)


def _row_change_done(gs, r, t, change, ans):
    """The answer to a row change, and its audit row."""
    op = change[0]
    bad = _problem(gs, ans)
    err = (ans or {}).get("error")
    affected = _affected(ans)
    ok = not bad and not err and affected is not None
    _row_audit(gs, r, t, change, (ok, affected, err))
    if bad:
        return _say(*bad)
    if err:
        return jsonify({"success": False, "code": err["code"], "message": i18n.tr(
            i18n.Sentence("The database refused the change (error {code}): {text}", code=err["code"],
                          text=err["text"]))}), 200
    if not ok:
        return _say(502, S_UNREAD)
    if op != "update":
        forget(r.id)
    msg = (_ROW_DONE[op] if affected else
           "No row was changed: it may have been changed or deleted already. Reload the page.")
    return jsonify({"success": affected > 0, "affected": affected, "message": i18n.tr(msg)})


_ROW_DONE = {"insert": "Row added.", "update": "Row saved.", "delete": "Row deleted."}


# ── the SQL box ──────────────────────────────────────────────────────────────────────────────────
def _confirm_serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="db-sql-confirm")


def _confirm_claim(r, text):
    return {"u": current_user.id, "d": r.id, "h": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def confirm_token(r, text):
    """A token that confirms exactly `text` in database `r` for this viewer, for CONFIRM_MAX_AGE seconds."""
    return _confirm_serializer().dumps(_confirm_claim(r, text))


def confirmed(r, text, token):
    """Whether `token` confirms exactly `text` in database `r` for this viewer, and is still fresh."""
    if not isinstance(token, str) or not token or len(token) > 500:
        return False
    try:
        return _confirm_serializer().loads(token, max_age=CONFIRM_MAX_AGE) == _confirm_claim(r, text)
    except BadSignature:
        return False


_SQL_MAX = 65536


def _sql_text(body):
    """The statement a SQL box request carries, or None when it is not one (empty, not text, too long)."""
    text = body.get("sql")
    if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8", "replace")) > _SQL_MAX:
        return None
    return text


def _confirm_refusal(r, text, token, kind):
    """A confirm step the statement still needs (a change with no token), or a token that is not for it; else None."""
    if token is not None and not confirmed(r, text, token):
        return _say(409, "That confirmation is for another statement or has expired. Run the statement again.")
    if token is None and kind[0] == "write":
        return _needs_confirm(r, text, kind[1])
    return None


def _sql_answer(gs, r):
    body = _json_body()
    text = _sql_text(body)
    if text is None:
        return _say(400, "Type one SQL statement (at most 64 KB).")
    kind, word = _dd.sql_kind(text)
    token = body.get("confirm") or None
    refused = _confirm_refusal(r, text, token, (kind, word))
    if refused:
        return refused
    if token is not None:
        kind = "write"
    ans = _query(gs, r, "rw" if kind == "write" else "ro", [_dd.sql_statement(text)])
    if kind == "read" and _error_code(ans) == 1792:
        # A "read" statement that writes after all (a stored function, EXPLAIN ANALYZE...): the READ
        # ONLY transaction refused it, and it takes the confirm step like any other change.
        return _needs_confirm(r, text, word)
    return _sql_done(gs, r, (text, kind, word), ans)


def _error_code(ans):
    """The client's error code in an answer, or None."""
    return ((ans or {}).get("error") or {}).get("code")


def _needs_confirm(r, text, word):
    return jsonify({"success": False, "needs_confirm": True, "kind": word, "database": r.name, "sql": text,
                    "confirm": confirm_token(r, text),
                    "message": i18n.tr(i18n.Sentence("This statement can change {name}. Check it, then confirm.",
                                                     name=r.name))}), 409


def _sql_rows(res):
    """How many rows a statement changed (its row count) or returned (the rows shown)."""
    affected = res["affected"]
    return affected if (affected is not None and affected >= 0) else sum(len(s["rows"]) for s in res["sets"])


def _sql_audit(gs, r, stmt, outcome):
    """The statement's audit row: its kind, the database, how many rows or the error, its literals masked."""
    (text, kind, word), (ok, res, err) = stmt, outcome
    said = ("%d row(s)" % _sql_rows(res)) if ok else ("error %s" % err["code"] if err else "failed")
    log_action(current_user, "db_sql", target=gs.name, server=gs, success=ok, detail="%s (%s) in %s, %s: %s" % (
        word or "?", kind, r.name, said, _dd.mask_literals(text)))


def _sql_done(gs, r, stmt, ans):
    """The SQL box's answer, and the statement's audit row."""
    kind = stmt[1]
    bad = _problem(gs, ans)
    err = (ans or {}).get("error")
    res = None if (bad or ans is None) else _dd.sql_result(ans)
    ok = not bad and not err and res is not None
    _sql_audit(gs, r, stmt, (ok, res, err))
    if kind == "write" and ok:
        forget(r.id)
    if bad:
        return _say(*bad)
    return jsonify(_sql_reply(ok, kind, res, ans)), 200


def _sql_reply(ok, kind, res, ans):
    """The SQL box's JSON: the result, or the server's error (its code and its own words) or why not."""
    err = ans.get("error")
    out = {"success": ok, "kind": kind, "result": res, "cut": bool(ans.get("cut")), "rows_max": _dd.SQL_ROWS}
    if err:
        out["error"] = {"code": err["code"], "state": err["state"], "text": err["text"]}
        out["message"] = i18n.tr(S_UNSUPPORTED_PS) if err["code"] == 1295 else err["text"]
    elif res is None:
        out["message"] = i18n.tr(S_UNREAD)
    return out


# ── routes ───────────────────────────────────────────────────────────────────────────────────────
def _guarded(server_id, db_id, answer, what):
    """`answer(gs, row)` for one of the server's own databases (the route has checked the permission)."""
    gs, r = _row(server_id, db_id)
    if r is None:
        return _say(404, _dbr._NO_SUCH)
    try:
        return answer(gs, r)
    except Exception as exc:
        return _dbr._failed(exc, what)


def _browse_routes(app):
    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/tables")
    @login_required
    @server_access_required
    def api_server_database_tables(server_id, db_id):
        """The database's tables, their row counts, sizes and columns (read as the database's own account)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _tables_answer, "browse")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/rows")
    @login_required
    @server_access_required
    def api_server_database_rows(server_id, db_id):
        """One page of a table's rows (a fixed page size), long values cut, binary ones as their length."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _rows_answer, "browse")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/cell", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_cell(server_id, db_id):
        """One whole value of a row, addressed by its primary key (POST: the key never goes in a URL)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _cell_answer, "browse")


def _edit_routes(app):
    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/row", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_row(server_id, db_id):
        """Insert, update or delete one row (addressed by its primary key), as the database's own account."""
        if not (has_permission(current_user, MANAGE_DATABASES) and has_permission(current_user, EDIT_DATABASE_DATA)):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _row_change_answer, "row change")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/sql", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_sql(server_id, db_id):
        """Run one SQL statement as the database's own account (a change takes the confirm step first)."""
        if not (has_permission(current_user, MANAGE_DATABASES) and has_permission(current_user, EDIT_DATABASE_DATA)):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _sql_answer, "sql")


def register(app):
    """The manager's browse, edit and SQL routes."""
    _browse_routes(app)
    _edit_routes(app)
