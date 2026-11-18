#!/usr/bin/env python3
"""Atheris fuzz harness: the upload scan of a database dump (ssh_manager.db_upload_scan, an awk program).

The scan runs on the game host, as `LC_ALL=C awk -v me=<database> -v max=<bytes>` with the dump on its
stdin, and must print exactly one verdict: SCANNED, SWITCH, OTHER, OPAQUE or BIG. Atheris sees no
coverage inside awk, so this harness is grammar-driven: the bytes choose a dump's lines from what a dump
holds (mysqldump's header, table, trigger and view lines, INSERT lines whose values are fuzzed text
escaped as mysqldump escapes it, comments, statements on the database itself) and, in some inputs, one
statement the scan must refuse:

* one that switches to or names another database (a system one or another panel database), its words
  apart by any blank SQL allows (spaces, tabs, \\v, \\f, line breaks, comments), in any case, quoted or
  not, in an executable comment or not, on its own line or chained after a ";" on another line;
* one the scan cannot read safely: an sql_mode or client character set that changes how quotes are
  read, PREPARE/EXECUTE, LOAD DATA, a client command, a DELIMITER with a quote, an executable comment
  a server older than its version would end early.

Checked, with every awk on the machine (mawk and gawk when both are there; the verdicts must agree):

* exactly one verdict line, and awk exits 0;
* a dump with one of those statements is never SCANNED;
* a dump without one is SCANNED (or BIG, past `max`): data that only mentions statements or names, and
  the database's own `me`.t, are never refused.

An input that starts with "#scan" and a line break is a dump as it is (the corpus seeds of the
statements an earlier text scan missed, and what the fuzzer makes of them): only the first check and
the agreement apply to it.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_upload_scan.py -max_total_time=60 tests/fuzz/corpus/upload_scan
"""
import importlib
import os
import shutil
import subprocess  # nosec B404 - runs awk, a fixed argv, no shell
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
    from panel.ops.ssh_manager import db_upload_scan

# Every awk here; mawk is Ubuntu's default awk, gawk the other common one. A plain environment: C locale
# as the finish script sets, and no LD_PRELOAD from a sanitizer build reaching the child.
_AWKS = [p for p in (shutil.which(n) for n in ("mawk", "gawk")) if p] or [shutil.which("awk") or "/usr/bin/awk"]
_ENV = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
ME = "gs12_lp"   # the database the dump is for; _BENIGN names it
_VERDICTS = {"SCANNED", "SWITCH", "OTHER", "OPAQUE", "BIG"}
_LITERAL = b"#scan\n"
_OTHERS = ["mysql", "sys", "information_schema", "performance_schema", "gs9_x", "gs12_lq", "gs1_lp"]
_BENIGN = ["-- MySQL dump 10.13  Distrib 8.0", "/*!40101 SET NAMES utf8mb4 */;", "DROP TABLE IF EXISTS `t`;",
           "CREATE TABLE `t` (`id` int NOT NULL, `name` varchar(64), PRIMARY KEY (`id`)) ENGINE=InnoDB;",
           "LOCK TABLES `t` WRITE;", "UNLOCK TABLES;", "SET @a = 1;", "SELECT * FROM `gs12_lp`.`t`;",
           "UPDATE gs12_lp.t SET name = 'x';", "DELIMITER ;;", "", "# a note", "/*!40000 ALTER TABLE `t` DISABLE KEYS */;",
           "COMMIT;", "START TRANSACTION;", "/*M!999999\\- enable the sandbox mode */",
           "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;",
           "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;", "/*!50503 SET character_set_client = utf8mb4 */;",
           "/*!40101 SET @saved_cs_client     = @@character_set_client */;",
           "/*!40101 SET character_set_client = @saved_cs_client */;",
           "/*!50001 VIEW `v` AS select `t`.`id` AS `id` from `t` USE INDEX (`PRIMARY`) */;",
           "/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `tr` BEFORE INSERT ON `t` "
           "FOR EACH ROW SET NEW.name = 'it''s' */;",
           "CREATE TABLE `characters` (`names` varchar(9) CHARACTER SET latin1, `use` int);",
           "/* a comment\nover two lines */", "SELECT 'a string\nover two lines';"]
# Statements to refuse, as words: {db} a name, {q} one quoted or not; the blanks between words are fuzzed.
_FORBIDDEN = [["USE", "{q}"], ["CREATE", "DATABASE", "{q}"], ["CREATE", "SCHEMA", "IF", "NOT", "EXISTS", "{q}"],
              ["DROP", "DATABASE", "IF", "EXISTS", "{q}"], ["DROP", "SCHEMA", "{q}"],
              ["ALTER", "DATABASE", "{q}", "CHARACTER", "SET", "utf8mb4"], ["CREATE", "OR", "REPLACE", "DATABASE", "{q}"],
              ["SELECT", "*", "FROM", "{q}", ".", "`t`"], ["UPDATE", "{q}", ".", "t", "SET", "a", "=", "1"],
              ["DELETE", "FROM", "{q}", ".", "`t`"], ["INSERT", "INTO", "{q}", ".", "t", "VALUES", "(1)"],
              ["CALL", "{q}", ".", "p()"], ["GRANT", "ALL", "ON", "{q}", ".", "*", "TO", "x"], ["TRUNCATE", "{q}", ".", "t"]]
_OPAQUE = ["SET sql_mode = 'NO_BACKSLASH_ESCAPES'", "SET SESSION sql_mode='ANSI_QUOTES,STRICT_TRANS_TABLES'",
           "SET @@sql_mode = CONCAT(@@sql_mode, ',ANSI')", "SET @m = 'ansi';\nSET sql_mode = @m", "SET NAMES gbk",
           "SET CHARACTER SET 'sjis'", "SET character_set_client = big5", "PREPARE s FROM 'SELECT 1'",
           "EXECUTE IMMEDIATE 'SELECT 1'", "LOAD DATA LOCAL INFILE '/etc/hosts' INTO TABLE t", "\\C gbk",
           "DELIMITER '", "/*!99999 SELECT '*/' */", "/*!50000 SELECT /* a */ 1 */", "SELECT /*+ 'x' */ 1"]
_BLANKS = [" ", "\t", "  ", "\n", "\x0b", "\x0c", "\r\n", "/**/", "/* c */", " -- c\n", "#c\n", "\n\n "]


def _case(fdp, s):
    k = fdp.ConsumeIntInRange(0, 2)
    return s if k == 0 else s.lower() if k == 1 else s.upper()


def _data(fdp):
    """Fuzzed text, escaped as mysqldump escapes a value: it may say anything a statement says."""
    s = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 40))
    if fdp.ConsumeBool():
        s += fdp.PickValueInList(["'; USE mysql; -- ", "\"; DROP DATABASE gs9_x; #", " mysql.user ", "/*!50000 USE mysql */",
                                  "\\'; SET NAMES gbk; ", "`gs9_x`.`t`", "\n-- x\nUSE gs1_lp;"])
    for a, b in (("\\", "\\\\"), ("'", "\\'"), ('"', '\\"'), ("\n", "\\n"), ("\r", "\\r"), ("\0", "\\0")):
        s = s.replace(a, b)
    return s


def _insert(fdp):
    rows = ",".join("(%d,'%s')" % (i, _data(fdp)) for i in range(fdp.ConsumeIntInRange(1, 3)))
    return "INSERT INTO `t` VALUES " + rows + ";"  # nosec B608 - a dump line the scan reads as text; nothing runs it


def _name(fdp):
    db = _case(fdp, fdp.PickValueInList(_OTHERS))
    return "`%s`" % db if fdp.ConsumeBool() else db


def _bad(fdp):
    if fdp.ConsumeIntInRange(0, 3) == 0:
        stmt = fdp.PickValueInList(_OPAQUE)
    else:
        q = _name(fdp)
        words = [q if w == "{q}" else _case(fdp, w) for w in fdp.PickValueInList(_FORBIDDEN)]
        stmt = words[0] + "".join(fdp.PickValueInList(_BLANKS) + w for w in words[1:])
        lead = fdp.PickValueInList(["", "", "/*!40101 ", "/*!", "/*M!100100 ", "  ", "\t"])
        stmt = lead + stmt + (" */" if lead.startswith("/*") else "")
    stmt += ";"
    # DELIMITER is the client's command only at the start of a line (later on a line it is SQL text).
    where = 0 if stmt.startswith("DELIMITER") else fdp.ConsumeIntInRange(0, 2)
    if where == 1:
        # Not after DELIMITER, whose argument is the rest of its line, nor after an open comment or string.
        prev = [b for b in _BENIGN if b.endswith(";") and not b.startswith(("DELIMITER", "/*!50003", "SELECT 'a"))]
        return fdp.PickValueInList(prev) + fdp.PickValueInList(["", " "]) + stmt
    if where == 2:
        return _insert(fdp) + fdp.PickValueInList(["", " ", "\t"]) + stmt
    return stmt


def _dump(fdp):
    lines, bad = [], False
    for _ in range(fdp.ConsumeIntInRange(1, 10)):
        k = fdp.ConsumeIntInRange(0, 5)
        if k == 5 and not bad:
            lines.append(_bad(fdp))
            bad = True
        elif k >= 3:
            lines.append(_insert(fdp))
        else:
            lines.append(fdp.PickValueInList(_BENIGN))
    return "\n".join(lines) + fdp.PickValueInList(["\n", "", "\n\n"]), bad


def _scan(awk, text, limit):
    # As the finish script feeds it: NUL bytes as spaces (Ubuntu 22.04's mawk ends a string at a NUL).
    r = subprocess.run([awk, "-v", "me=" + ME, "-v", "max=%d" % limit, db_upload_scan.SCAN_AWK],  # nosec B603
                       input=text.replace(b"\0", b" "), capture_output=True, env=_ENV, timeout=20, check=False)
    out = r.stdout.decode("utf-8", "replace").splitlines()
    assert r.returncode == 0 and len(out) == 1 and out[0] in _VERDICTS, (awk, text, r.returncode, out, r.stderr[-300:])
    return out[0]


def _verdict(text, limit):
    verdicts = {awk: _scan(awk, text, limit) for awk in _AWKS}
    assert len(set(verdicts.values())) == 1, (text, verdicts)
    return next(iter(verdicts.values()))


def TestOneInput(data):
    if data.startswith(_LITERAL):
        _verdict(data[len(_LITERAL):], 1 << 30)
        return
    fdp = atheris.FuzzedDataProvider(data)
    text, bad = _dump(fdp)
    limit = 1 << 30 if fdp.ConsumeBool() else fdp.ConsumeIntInRange(1, 4096)
    raw = text.encode("utf-8")
    got = _verdict(raw, limit)
    size = len(raw) + (0 if text.endswith("\n") else 1)
    if bad:
        assert got != "SCANNED", (text, got)
    else:
        assert got == ("SCANNED" if size <= limit else "BIG"), (text, got, size, limit)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
