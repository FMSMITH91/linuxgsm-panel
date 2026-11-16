"""Browse, edit and query one of the panel's databases, signed in as that database's own account.

The service layer of the Databases manager (routes/databases_data.py). Every call is ONE db-query
verb (privileged.py and tools/panel-helper hold it): the client runs where the database's other
commands run (the game host, or the panel's host) and signs in as the database's own account, whose
grant is that one database, so the database server itself keeps every statement inside it.

What this module adds is the statements, and reading the answer:
* Identifiers (a table, a column) are never taken from a request: the caller looks the name up in the
  structure this module read from information_schema (structure()), and quote_ident() writes it.
* Values are bound parameters: each `?` gets one value through EXECUTE ... USING (see db-query).
* The answer is the client's XML (NULL is told from the text "NULL"), read by parse().

This module is not one of the package's _MODULES: import it by name,
`from panel.ops.ssh_manager import db_data`.
"""
import html
import re

from panel.ops.ssh_manager import _core
from panel.security import privileged as _priv

PAGE_ROWS = 50              # rows per page of Browse
PAGE_MAX = 200000           # the last page Browse goes to (offset PAGE_MAX * PAGE_ROWS)
PREVIEW_CHARS = 256         # characters of a value Browse shows before "Show all"
FULL_CHARS = 262144         # characters "Show all" fetches at most
SQL_ROWS = 200              # rows the SQL box shows of one statement
SQL_CELL_CHARS = 2000       # characters of one value the SQL box shows
TABLES_MAX = 1000
COLUMNS_MAX = 10000
# The panel waits longer than the verb's own limit (its statement time + its kill + the transport).
TIMEOUT = _priv.DB_QUERY_SECONDS + 30

# Types whose values are bytes: Browse shows their length, and the editor leaves them alone.
BINARY_TYPES = frozenset(("binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit", "geometry",
                          "point", "linestring", "polygon", "multipoint", "multilinestring", "multipolygon",
                          "geometrycollection", "vector"))
_CHARSET_RE = re.compile(r"[A-Za-z0-9_]{1,64}\Z")

# The statements the SQL box runs without the confirm step, in a READ ONLY transaction (the server
# refuses any write one of them would make, a stored function's included).
READ_WORDS = frozenset(("select", "show", "describe", "desc", "explain"))

_RESULTSET_RE = re.compile(r'<resultset statement="([^"]*)"[^>]*>')
_ROW_RE = re.compile(r"<row>(.*?)</row>", re.S)
_FIELD_RE = re.compile(r'<field name="([^"]*)"(?: xsi:nil="true" />|>(.*?)</field>)', re.S)
# What decoding puts in place of bytes that are not UTF-8 (a binary value in the SQL box's answer).
_REPLACED = chr(0xFFFD)
_ERROR_RE = re.compile(r"^ERROR (\d{1,5}) \(([0-9A-Z]{5})\)(?: at line \d+)?: (.*)$", re.M)



# Why a row change does not fit its table: the only sentences a refusal may say back to the browser.
ROW_REFUSALS = ("not an identifier", "not this table's key", "not a text column", "no values",
                "not a column that can be set", "that column can't be empty (NULL)", "not a value")


class RowRefused(ValueError):
    """A request that does not fit the table; its text is one of ROW_REFUSALS."""


def quote_ident(name):
    """`name` as a quoted identifier (backticks, a backtick inside doubled). Only for a name structure() read."""
    if not isinstance(name, str) or not name or len(name) > 64 or "\x00" in name:
        raise RowRefused("not an identifier")
    return "`" + name.replace("`", "``") + "`"


def target_arg(target):
    """db-query's target: the server's port, and its tailnet address for a server on another machine."""
    addr = getattr(target, "address", "") or ""
    return str(int(target.port or 3306)) + ("@" + addr if addr else "")


def run(remote, target, name, pw, mode, statements):
    """Run `statements` ([{"sql", "params", "cap"}]) in database `name` as its own account: parse()'s dict.

    `mode` 'ro' (a READ ONLY transaction, rolled back) or 'rw'. Also "rc", the verb's exit status
    (2: the request was refused before anything ran; 127: no client on the host).
    """
    try:
        out, err, rc = _core.run_privileged(remote, "db-query", [target.flavor, target_arg(target), name, mode],
                                            timeout=TIMEOUT, secrets={"pw": pw, "query": statements})
    except _priv.VerbError:
        return dict(parse(""), rc=2)
    text = _priv.db_scrub("\n".join(x for x in (out, err) if x), [pw])
    return dict(parse(text), rc=rc)


# ── reading the answer ───────────────────────────────────────────────────────────────────────────
def _unescape(text):
    return html.unescape(text)


def _rows_of(body):
    """The rows of one resultset's body: [(names, values)], each value text or None (NULL)."""
    out = []
    for row in _ROW_RE.findall(body):
        names, values = [], []
        for name, value in ((m.group(1), m.group(2)) for m in _FIELD_RE.finditer(row)):
            names.append(_unescape(name))
            values.append(None if value is None else _unescape(value))
        out.append((names, values))
    return out


def _resultsets(text):
    """Each resultset in `text`: (statement, column names, rows). One cut short keeps its whole rows."""
    marks = list(_RESULTSET_RE.finditer(text))
    sets = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[m.end():end]
        close = body.find("</resultset>")
        rows = _rows_of(body[:close] if close >= 0 else body)
        sets.append((_unescape(m.group(1)).strip(), rows[0][0] if rows else [], [v for _n, v in rows]))
    return sets


def _error(text):
    """The client's error line as {"code", "state", "text"}, or None."""
    m = _ERROR_RE.search(text or "")
    return {"code": int(m.group(1)), "state": m.group(2), "text": m.group(3).strip()[:500]} if m else None


def _count(n):
    """A row count the server printed (-1 for a statement that returns rows), or None."""
    return int(n) if n and re.fullmatch(r"-?\d{1,19}", n) else None


def parse(text):
    """The db-query answer `text`, read.

    {"conn": connection id or None, "statements": [{"sets": [{"columns", "rows"}], "affected": n or
    None}] (one per statement that finished), "error": _error(), "cut": the answer was cut at its
    size limit, "late": the run outlived its time limit}.
    """
    conn, done, cur = None, [], []
    for statement, columns, rows in _resultsets(text or ""):
        first = rows[0][0] if rows and rows[0] else None
        if statement.startswith(_priv.DB_QUERY_CONN_SQL) and conn is None:
            conn = first
        elif statement.startswith(_priv.DB_QUERY_ROWS_SQL):
            done.append({"sets": cur, "affected": _count(first)})
            cur = []
        else:
            cur.append({"columns": columns, "rows": rows})
    lines = (text or "").splitlines()
    return {"conn": conn, "statements": done, "pending": cur, "error": _error(text),
            "cut": "panel-db: output cut" in lines, "late": "panel-db: timed out" in lines}


# ── the database's structure ─────────────────────────────────────────────────────────────────────
STRUCTURE_SQL = (
    {"sql": "SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH + INDEX_LENGTH "
            "FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME", "cap": TABLES_MAX},
    {"sql": "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA, "
            "CHARACTER_SET_NAME, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
            "ORDER BY TABLE_NAME, ORDINAL_POSITION", "cap": COLUMNS_MAX},
    {"sql": "SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() "
            "AND INDEX_NAME = 'PRIMARY' ORDER BY TABLE_NAME, SEQ_IN_INDEX", "cap": COLUMNS_MAX},
)


def _dd_int(v):
    return int(v) if isinstance(v, str) and v.isdecimal() else None


def _column(f):
    """One information_schema.COLUMNS row as the manager's column."""
    data_type = (f[3] or "").lower()
    cs, coll = f[8] or "", f[9] or ""
    return {"name": f[1], "type": f[2] or "", "data_type": data_type, "nullable": f[4] == "YES",
            "key": f[5] or "", "default": f[6], "extra": f[7] or "",
            "binary": data_type in BINARY_TYPES,
            "generated": "GENERATED" in (f[7] or "").upper(),
            "charset": cs if _CHARSET_RE.match(cs) else "", "collation": coll if _CHARSET_RE.match(coll) else ""}


def structure(ans):
    """The tables of a STRUCTURE_SQL run's answer, by name; None when the answer is not whole.

    {name: {"name", "type", "engine", "rows", "bytes", "columns", "pk", "view"}}. Not whole: an
    error, or a statement missing.
    """
    st = ans.get("statements") or []
    if not _whole(ans, st):
        return None
    tables = {f[0]: _table(f) for f in st[0]["sets"][0]["rows"] if len(f) == 5 and f[0]}
    for f in _rows_for(st[1], 10, tables):
        tables[f[0]]["columns"].append(_column(f))
    for f in _rows_for(st[2], 2, tables):
        tables[f[0]]["pk"].append(f[1])
    return tables


def _whole(ans, st):
    """Whether a structure answer has no error and all three statements, each with its resultset."""
    return not ans.get("error") and len(st) == 3 and all(s["sets"] for s in st)


def _table(f):
    """One information_schema.TABLES row as the manager's table (its columns and key added after)."""
    return {"name": f[0], "type": f[1] or "", "engine": f[2] or "", "rows": _dd_int(f[3]), "bytes": _dd_int(f[4]),
            "columns": [], "pk": [], "view": (f[1] or "") == "VIEW"}


def _rows_for(statement, width, tables):
    """The rows of `statement`'s first resultset that have `width` values and name a table in `tables`."""
    return [f for f in statement["sets"][0]["rows"] if len(f) == width and f[0] in tables]


def editable(table):
    """Why `table` is read-only in the editor ('view', 'no_key'), or "" when its rows can be changed."""
    if table["view"]:
        return "view"
    names = {c["name"] for c in table["columns"]}
    if not table["pk"] or not set(table["pk"]) <= names:
        return "no_key"
    return ""


# ── statements built from that structure ─────────────────────────────────────────────────────────
def _col(table, name):
    """The column `name` of `table` (from structure()), or None."""
    return next((c for c in table["columns"] if c["name"] == name), None)


# The client's XML writes a NUL byte as a space, so a text value read for the page has each NUL put back as
# NUL_MARK (U+2400, "␀") on the server: visible, and a value holding it is not offered to the editor (a
# save would write the mark, or a space, where the NUL was). CONVERT first: REPLACE then works in utf8mb4,
# whatever the column's character set, with the two literals (coercible) taking its collation.
NUL_MARK = chr(0x2400)


def _nul_marked(expr):
    """`expr` (text) with every NUL byte shown as NUL_MARK."""
    return "REPLACE(CONVERT(%s USING utf8mb4), _utf8mb4 X'00', _utf8mb4 X'E29080')" % expr


def _select_expr(c, is_key):
    q = quote_ident(c["name"])
    if c["binary"]:
        return "LENGTH(%s)" % q
    return q if is_key else _nul_marked("LEFT(%s, %d)" % (q, PREVIEW_CHARS + 1))


def rows_statement(table, page):
    """The statement for one page of `table`'s rows: its key columns whole, binary ones as their length."""
    page = max(0, min(int(page), PAGE_MAX))
    keys = set(table["pk"]) if not editable(table) else set()
    exprs = ", ".join(_select_expr(c, c["name"] in keys) for c in table["columns"])
    order = (" ORDER BY " + ", ".join(quote_ident(k) for k in table["pk"])) if keys else ""
    # Identifiers quoted from the structure; the page numbers are ints this function made.
    sql = "SELECT %s FROM %s%s LIMIT %d OFFSET %d" % (  # nosec B608 - see the line above
        exprs, quote_ident(table["name"]), order, PAGE_ROWS + 1, page * PAGE_ROWS)
    return {"sql": sql}


def _cell(c, v, is_key):
    """One value as the page shows it: text (cut at PREVIEW_CHARS), NULL, or a binary value's length."""
    if v is None:
        return {"null": True}
    if c["binary"]:
        return {"binary": _dd_int(v)}
    out = {"text": v[:PREVIEW_CHARS], "more": True} if not is_key and len(v) > PREVIEW_CHARS else {"text": v}
    if NUL_MARK in v:
        out["nul"] = True
    return out


def rows(ans, table):
    """One page of rows read from a rows_statement answer: {"rows": [{"cells", "key"}], "more"}, or None."""
    st = ans.get("statements") or []
    if ans.get("error") or not st:
        return None
    if not st[0]["sets"]:
        return {"rows": [], "more": False}
    keys = set(table["pk"]) if not editable(table) else set()
    cols = table["columns"]
    got = [r for r in st[0]["sets"][0]["rows"] if len(r) == len(cols)]
    return {"rows": [_page_row(cols, r, keys) for r in got[:PAGE_ROWS]], "more": len(got) > PAGE_ROWS}


def _page_row(cols, r, keys):
    """One row of a page: its cells, and its key values when the table has a key the editor uses."""
    return {"cells": [_cell(c, v, c["name"] in keys) for c, v in zip(cols, r)],
            "key": {c["name"]: v for c, v in zip(cols, r) if c["name"] in keys} if keys else None}


def _key_match(table, key):
    """The WHERE clause and its values for the row `key` ({key column: value}) addresses; ValueError if not whole."""
    if not isinstance(key, dict) or set(key) != set(table["pk"]) or not all(isinstance(v, str) for v in key.values()):
        raise RowRefused("not this table's key")
    parts, params = [], []
    for name in table["pk"]:
        c = _col(table, name)
        q = quote_ident(name)
        if c["charset"] and c["collation"]:
            # The column's own character set and collation: the value is compared as the column's
            # text (and its index used), never by an implicit collation that may not match it.
            parts.append("%s = CONVERT(CONVERT(? USING utf8mb4) USING %s) COLLATE %s" % (q, c["charset"], c["collation"]))
        else:
            parts.append("%s = ?" % q)
        params.append(key[name])
    return " AND ".join(parts), params


def cell_statement(table, column, key):
    """The statement that reads one whole value (at most FULL_CHARS characters) of the row `key` addresses."""
    c = _col(table, column)
    if c is None or c["binary"]:
        raise RowRefused("not a text column")
    where, params = _key_match(table, key)
    sql = "SELECT %s FROM %s WHERE %s LIMIT 1" % (  # nosec B608 - quoted identifiers, bound values
        _nul_marked("LEFT(%s, %d)" % (quote_ident(column), FULL_CHARS)), quote_ident(table["name"]), where)
    return {"sql": sql, "params": params}


def _value_param(c, v):
    """The placeholder for a value assigned to column `c`: text arrives as UTF-8 and is converted by the server."""
    if v is None:
        return "?"
    return "CONVERT(? USING utf8mb4)" if c["charset"] else "?"


def _values(table, values):
    """[(column, value or None)] for `values` ({column: {"null": bool, "value": text}}); ValueError on a bad one."""
    if not isinstance(values, dict) or not values:
        raise RowRefused("no values")
    return [_value(_col(table, name), v) for name, v in values.items()]


def _value(c, v):
    """(column, value or None) for one value set on column `c` (None: not in the table); ValueError if not fit."""
    if c is None or c["binary"] or c["generated"] or not isinstance(v, dict):
        raise RowRefused("not a column that can be set")
    if v.get("null"):
        if not c["nullable"]:
            raise RowRefused("that column can't be empty (NULL)")
        return c, None
    if isinstance(v.get("value"), str) and len(v["value"].encode("utf-8", "replace")) <= _priv.DB_QUERY_VALUE_MAX:
        return c, v["value"]
    raise RowRefused("not a value")


def insert_statement(table, values):
    """INSERT one row with `values` (a column left out gets its default)."""
    vals = _values(table, values)
    sql = "INSERT INTO %s (%s) VALUES (%s)" % (  # nosec B608 - quoted identifiers, bound values
        quote_ident(table["name"]), ", ".join(quote_ident(c["name"]) for c, _v in vals),
        ", ".join(_value_param(c, v) for c, v in vals))
    return {"sql": sql, "params": [v for _c, v in vals]}


def update_statement(table, key, values):
    """UPDATE the one row `key` addresses with `values`."""
    vals = _values(table, values)
    where, wparams = _key_match(table, key)
    sets = ", ".join("%s = %s" % (quote_ident(c["name"]), _value_param(c, v)) for c, v in vals)
    sql = "UPDATE %s SET %s WHERE %s LIMIT 1" % (  # nosec B608 - quoted identifiers, bound values
        quote_ident(table["name"]), sets, where)
    return {"sql": sql, "params": [v for _c, v in vals] + wparams}


def delete_statement(table, key):
    """DELETE the one row `key` addresses."""
    where, params = _key_match(table, key)
    sql = "DELETE FROM %s WHERE %s LIMIT 1" % (quote_ident(table["name"]), where)  # nosec B608 - quoted identifiers, bound values
    return {"sql": sql, "params": params}


# ── the SQL box ──────────────────────────────────────────────────────────────────────────────────
def _skip_comments(text):
    """`text` from its first statement word on: leading spaces, '(' and comments skipped.

    An executable comment (/*! ... */, MariaDB's /*M! ... */) is not skipped: the server runs what it
    holds, so it is where the statement starts.
    """
    s = text
    while True:
        s = s.lstrip(" \t\r\n\f\v(")
        rest = _past_comment(s)
        if rest is None:
            return s
        s = rest


def _comment_end(text, i):
    """The index just past the comment that starts at text[i], or None when none starts there.

    MySQL's and MariaDB's comment syntax: # to the end of the line; -- followed by a space or a
    control character (a tab, a line break) or the end, to the end of the line; /* ... */. An
    executable comment (/*! ... */, MariaDB's /*M! ... */) is not one: the server runs what it holds.
    """
    if text.startswith("#", i) or (text.startswith("--", i) and (i + 2 == len(text) or ord(text[i + 2]) <= 32)):
        nl = text.find("\n", i)
        return len(text) if nl < 0 else nl + 1
    if text.startswith("/*", i) and not text.startswith("/*!", i) and not text[i:i + 4].upper() == "/*M!":
        end = text.find("*/", i + 2)
        return len(text) if end < 0 else end + 2
    return None


def _past_comment(s):
    """`s` after the comment it starts with, or None when it starts with none (or an executable one)."""
    end = _comment_end(s, 0)
    return None if end is None else s[end:]


def sql_kind(text):
    """("read" or "write", its first word in lower case) for a statement typed into the SQL box.

    "read": SELECT, SHOW, DESCRIBE/DESC or EXPLAIN (but EXPLAIN ANALYZE / ANALYZE, which run the
    statement). Anything else, an executable comment first included, is "write" and takes the confirm
    step; a "read" one runs in a READ ONLY transaction, so the server refuses it if it writes after all.
    """
    s = _skip_comments(text or "")
    m = re.match(r"[A-Za-z_]+", s)
    word = m.group(0).lower() if m else ""
    if word not in READ_WORDS:
        return "write", word[:20]
    nxt = re.match(r"[A-Za-z_]+", _skip_comments(s[len(word):]))
    if word in ("explain", "describe", "desc") and nxt and nxt.group(0).lower() == "analyze":
        return "write", word
    return "read", word


def _scan_literal(text, i, escapes=True):
    """The index just past the quoted literal that starts at text[i] (a doubled quote stays inside).

    escapes: a backslash escapes the next character, as the servers read it by default; without it, as
    they read it under sql_mode NO_BACKSLASH_ESCAPES.
    """
    q, j = text[i], i + 1
    while j < len(text):
        ch = text[j]
        if ch == "\\" and escapes:
            j += 2
            continue
        if ch == q:
            if j + 1 < len(text) and text[j + 1] == q:
                j += 2
                continue
            return j + 1
        j += 1
    return len(text)


_HEX_NUM_RE = re.compile(r"0[xXbB][0-9A-Fa-f]+")


def _exec_open(text, i):
    """The index just past an executable comment's opening at text[i] (/*! or /*M!, its version digits), or None."""
    if text.startswith("/*!", i):
        j = i + 3
    elif text[i:i + 4].upper() == "/*M!":
        j = i + 4
    else:
        return None
    while j < len(text) and text[j] in "0123456789":
        j += 1
    return j


def _mask_comment(text, i, out, in_exec):
    """(index after, still in an executable comment) for a comment or an executable comment's edge at text[i], or None.

    An executable comment's opening is kept and its content read as code; its "*/" is kept whole, so the "/"
    of it never starts a comment with what follows. A comment (one inside an executable comment included)
    is one space. A second opening inside one is read as a comment, up to its "*/".
    """
    if in_exec and text.startswith("*/", i):
        out.append("*/")
        return i + 2, False
    j = _exec_open(text, i)
    if j is not None and not in_exec:
        out.append(text[i:j] + " ")
        return j, True
    end = _comment_end(text, i)
    if end is None and j is not None:
        end = text.find("*/", i + 2)
        end = len(text) if end < 0 else end + 2
    if end is None:
        return None
    out.append(" ")
    return end, in_exec


def _mask_quoted(text, i, out):
    """(index after, lost track) for the literal or identifier at text[i], or None when none starts there.

    Lost track: where the literal ends depends on sql_mode (a backslash before its quote); the rest of
    the text is then masked too (never let text through). An identifier never closed takes the rest.
    """
    ch = text[i]
    if ch in "'\"":
        out.append(ch + "?" + ch)
        end = _scan_literal(text, i)
        return end, end != _scan_literal(text, i, escapes=False)
    if ch == "`":
        j = text.find("`", i + 1)
        if j < 0:
            out.append("`?")
            return len(text), False     # the rest is inside it, and not logged
        out.append(text[i:j + 1])
        return j + 1, False
    return None


def _mask_next(text, i, out, in_exec):
    """Append what mask_literals keeps of the token at text[i] to `out`: (index after, in an executable comment).

    Where it loses track the index is the text's end, the rest not logged.
    """
    if in_exec and text.startswith("*/*", i):
        # The servers close the executable comment there, but a reader can't tell that from a comment
        # opening inside it: what follows is not logged.
        out.append("*/…")
        return len(text), False
    got = _mask_comment(text, i, out, in_exec)
    if got is not None:
        return got
    got = _mask_quoted(text, i, out)
    if got is None:
        out.append(text[i])
        return i + 1, in_exec
    if got[1]:
        out.append("…")
        return len(text), in_exec
    return got[0], in_exec


def mask_literals(text, limit=300):
    """The statement for the audit log, its literals masked, on one line, at most `limit` characters.

    Each string literal ('...', "...", X'...') becomes '?', 0x... numbers 0x?, each comment one space
    (a quote inside a comment opens no literal, and what a comment says is not logged), every run of
    spaces and line breaks one space. Identifiers in backticks are kept. Where the masking can't be sure
    what the server reads (a literal whose end depends on sql_mode, an executable comment's "*/" followed
    by "*", an identifier never closed), the rest is not logged: it ends as '?'…, */… or `?. Nothing typed
    between quotes reaches the log.
    """
    out, i, text, in_exec = [], 0, text or "", False
    while i < len(text):
        i, in_exec = _mask_next(text, i, out, in_exec)
    flat = re.sub(r"\s+", " ", _HEX_NUM_RE.sub(lambda m: m.group(0)[:2] + "?", "".join(out))).strip()
    flat = "".join(c if c.isprintable() else "?" for c in flat)
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def sql_statement(text):
    """The SQL box's statement: one statement, its rows capped at SQL_ROWS (+1, to tell that more were left)."""
    return {"sql": text, "cap": SQL_ROWS + 1}


def _sql_value(v):
    """One value of a SQL box answer: text (cut at SQL_CELL_CHARS), NULL, or bytes that are not text."""
    if v is None:
        return {"null": True}
    if _REPLACED in v:
        # Bytes that are not UTF-8 reach the panel already replaced, so their count is not known here
        # (Browse asks the server for LENGTH instead).
        return {"binary": None}
    if len(v) > SQL_CELL_CHARS:
        return {"text": v[:SQL_CELL_CHARS], "more": True}
    return {"text": v}


def sql_result(ans):
    """What the SQL box shows of an answer: {"sets": [{"columns", "rows", "more"}], "affected"} or None."""
    st = ans.get("statements") or []
    pending = ans.get("pending") or []
    if not st and not pending:
        return None
    sets = (st[0]["sets"] if st else []) + pending
    return {"sets": [{"columns": s["columns"], "rows": [[_sql_value(v) for v in r] for r in s["rows"][:SQL_ROWS]],
                      "more": len(s["rows"]) > SQL_ROWS} for s in sets],
            "affected": st[0]["affected"] if st else None}
