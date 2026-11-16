#!/usr/bin/env python3
"""Atheris fuzz harness: the Databases manager's readers (ssh_manager.db_data, databases).

The first byte of an input picks what the rest feeds:

0. The db-query answer: the mysql/mariadb client's XML, whose values players and plugins write.
   `parse` reads it, and `structure`, `rows`, `rows_statement` and `sql_result` read what `parse`
   made, as the routes do. None may raise; a statement builder may refuse a name with RowRefused.
1. `sql_kind` on a generated statement: comments, spaces and '(' before its first word, then the
   word. The answer must be ("read", word) for SELECT, SHOW, DESCRIBE, DESC and EXPLAIN only, and
   "write" for everything else, an executable comment first included.
2. `mask_literals` on a generated statement whose every string literal holds a marker: words,
   identifiers in backticks, line and block comments (with quotes in them) and executable comments.
   The marker must never reach the audit line it makes, and the line must fit its limit.
3. `quote_ident` (a name it accepts reads back as itself) and `databases._parse_probe` (the probe's
   key=value lines) on the raw text.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_db_data.py -max_total_time=60 tests/fuzz/corpus/db_data
"""
import importlib
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Pre-load the heavy dependencies uninstrumented (see fuzz_game_status); part29 holds the list.
# eventlet.tpool is the first eventlet import: greendns off, so no dnspython (panel/core/green_dns.py).
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
for _dep in ("paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
             "sqlalchemy.dialects.sqlite", "cryptography.hazmat.primitives.kdf.hkdf", "panel.core.config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    from panel.ops.ssh_manager import databases as _dbs, db_data as _dd

MARK = "KEEPOUT"
_WORDS = ["SELECT", "UPDATE", "INSERT", "INTO", "t", "SET", "x", "=", ",", "(", ")", ";", "1", "WHERE",
          "FROM", "VALUES", "AND", "*", "+", "users", "pw"]
_STARTS = ["SELECT", "select", "Show", "DESCRIBE", "desc", "EXPLAIN", "UPDATE", "drop", "INSERT", "Delete",
           "CREATE", "set", "Call", "with", "grant", "use", "handler", "do", "replace", "load", "analyze"]


def _free(fdp, n, banned=()):
    """Up to `n` fuzzed characters with the marker and every string in `banned` taken out."""
    s = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, n))
    # Until none is left: taking one out can join its neighbours into another ("**//" -> "*/").
    while any(b in s for b in (MARK,) + tuple(banned)):
        for b in (MARK,) + tuple(banned):
            s = s.replace(b, "")
    return s


def _line_comment(fdp):
    # "--" starts a comment when a space or a control character follows it (MySQL "Comments").
    lead = fdp.PickValueInList(["#", "-- ", "--\t", "--\r", "--\x0b", "--\n"])
    return lead if lead == "--\n" else lead + _free(fdp, 24, ("\n",)) + "\n"


def _block_comment(fdp):
    body = _free(fdp, 24, ("*/",))
    # A body that starts with "!" (or MariaDB's "M!") makes the comment an executable one: not this case.
    while body[:1] == "!" or body[:2].upper() == "M!":
        body = body[1:]
    return "/*" + body + "*/"


def _literal(fdp):
    q = fdp.PickValueInList(["'", '"'])
    body = _free(fdp, 16) + MARK + _free(fdp, 16)
    body = body.replace("\\", "\\\\")
    body = body.replace(q, fdp.PickValueInList([q + q, "\\" + q]))
    return fdp.PickValueInList(["", "X", "_utf8mb4", "N"]) + q + body + q


def _ident(fdp):
    return "`" + _free(fdp, 12).replace("`", "``") + "`"


def _gap(fdp):
    """Spaces, '(' and comments: what may stand before a statement's first word."""
    out = []
    for _ in range(fdp.ConsumeIntInRange(0, 4)):
        k = fdp.ConsumeIntInRange(0, 3)
        out.append((" ", "(", _line_comment, _block_comment)[k] if k < 2 else
                   (_line_comment, _block_comment)[k - 2](fdp))
    return "".join(out)


def _token(fdp, depth=0):
    k = fdp.ConsumeIntInRange(0, 6)
    if k == 0:
        return _literal(fdp)
    if k == 1:
        return _ident(fdp)
    if k == 2:
        return _line_comment(fdp)
    if k == 3:
        return _block_comment(fdp)
    if k == 4 and depth == 0:
        inner = "".join(_token(fdp, 1) for _ in range(fdp.ConsumeIntInRange(0, 3)))
        return fdp.PickValueInList(["/*!", "/*!40101 ", "/*M!100100 "]) + inner + " */"
    return fdp.PickValueInList(_WORDS) + fdp.PickValueInList([" ", "\n", "\t", ""])


def _answer(text):
    ans = _dd.parse(text)
    _dd.sql_result(ans)
    tables = _dd.structure(ans)
    for table in list((tables or {}).values())[:4]:
        _dd.editable(table)
        _dd.rows(ans, table)
        try:
            _dd.rows_statement(table, 0)
        except _dd.RowRefused:
            continue    # a refusal is a documented answer for a table that does not fit, not a crash


def _kind(fdp):
    gap = _gap(fdp)
    word = fdp.PickValueInList(_STARTS)
    # A character that ends the word comes after it, so the free text never joins it.
    text = gap + word + fdp.PickValueInList([" ", "\n", "\t", "(", "`", ";"]) + _free(fdp, 30)
    got = _dd.sql_kind(text)
    low = word.lower()
    # The free text after the word may itself start with ANALYZE; EXPLAIN/DESCRIBE ANALYZE runs the statement.
    if low in _dd.READ_WORDS and not (low in ("explain", "describe", "desc") and got[0] == "write"):
        assert got == ("read", low), (text, got)
    elif low not in _dd.READ_WORDS:
        assert got == ("write", low[:20]), (text, got)
    executable = fdp.PickValueInList(["/*!", "/*!50000", "/*M!", "/*m!100100"]) + " SELECT 1 */"
    assert _dd.sql_kind(gap + executable)[0] == "write", gap + executable


def _mask(fdp):
    text = "".join(_token(fdp) for _ in range(fdp.ConsumeIntInRange(1, 12)))
    limit = fdp.ConsumeIntInRange(2, 400)
    whole = _dd.mask_literals(text, limit=1 << 20)
    assert MARK not in whole, (text, whole)
    cut = _dd.mask_literals(text, limit=limit)
    assert len(cut) <= limit and MARK not in cut, (text, cut, limit)


def _names(text):
    try:
        q = _dd.quote_ident(text)
    except _dd.RowRefused:
        q = None
    if q is not None:
        assert q[0] == q[-1] == "`" and q[1:-1].replace("``", "`") == text, (text, q)
        assert "`" not in q[1:-1].replace("``", ""), q
    _dbs._parse_probe(text)


def TestOneInput(data):
    if not data:
        return
    mode, rest = data[0] % 4, data[1:]
    if mode == 0:
        _answer(rest.decode("utf-8", "replace"))
    elif mode == 3:
        _names(rest.decode("utf-8", "replace"))
    else:
        fdp = atheris.FuzzedDataProvider(rest)
        (_kind if mode == 1 else _mask)(fdp)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
