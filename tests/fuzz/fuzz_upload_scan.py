#!/usr/bin/env python3
"""Atheris fuzz harness: the upload scan of a database dump (ssh_manager.db_upload_scan, an awk program).

The scan runs on the game host, as `LC_ALL=C awk -v me=<database> -v max=<bytes>` with the dump on its
stdin, and must print exactly one verdict: SCANNED, SWITCH, OTHER or BIG. Atheris sees no coverage
inside awk, so this harness is grammar-driven: the bytes choose a dump's lines from what a dump holds
(mysqldump's header and table lines, INSERT lines whose values are fuzzed text, comments, statements
on the database itself) and, in some inputs, one statement that switches to or names another database
(a system one or another panel database), written each way the scan's contract covers: case, spaces
or tabs, backticks or none, an executable comment first, on its own line or chained after a ";" on
another statement's line (an INSERT's included). Checked, with every awk on the machine (mawk and gawk
when both are there; the verdicts must agree):

* exactly one verdict line, and awk exits 0;
* a dump with one of those statements is never SCANNED;
* a dump without one is SCANNED (or BIG, past `max`): the database's own `me`.t and data that only
  mentions a word are never refused.

Statements the contract does not cover (a keyword split over two lines, a comment or a vertical tab
between keywords) are not generated: the database server's own grant refuses those (the account's
grant is one database), and the scan is the early, readable refusal for what a dump usually holds.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_upload_scan.py -max_total_time=60 tests/fuzz/corpus/upload_scan
"""
import importlib
import os
import re
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
_VERDICTS = {"SCANNED", "SWITCH", "OTHER", "BIG"}
_OTHERS = ["mysql", "sys", "information_schema", "performance_schema", "gs9_x", "gs12_lq", "gs1_lp"]
_BENIGN = ["-- MySQL dump 10.13  Distrib 8.0", "/*!40101 SET NAMES utf8mb4 */;", "DROP TABLE IF EXISTS `t`;",
           "CREATE TABLE `t` (`id` int NOT NULL, `name` varchar(64), PRIMARY KEY (`id`)) ENGINE=InnoDB;",
           "LOCK TABLES `t` WRITE;", "UNLOCK TABLES;", "SET @a = 1;", "SELECT * FROM `gs12_lp`.`t`;",
           "UPDATE gs12_lp.t SET name = 'x';", "DELIMITER ;;", "", "# a note", "/*!40000 ALTER TABLE `t` DISABLE KEYS */;",
           "COMMIT;", "START TRANSACTION;"]
_FORBIDDEN = ["USE {db}", "USE `{db}`", "use{sp}`{db}`", "CREATE DATABASE {db}", "create{sp}schema `{db}`",
              "DROP DATABASE IF EXISTS `{db}`", "DROP SCHEMA{sp}{db}", "ALTER DATABASE `{db}` CHARACTER SET utf8mb4",
              "SELECT * FROM `{db}`.`t`", "UPDATE {db}.t SET a = 1", "DELETE FROM `{db}` . `t`",
              "INSERT INTO {db}.t VALUES (1)", "INSERT INTO `{db}`.`t` (`a`) VALUES (1)", "CALL {db}.p()",
              "GRANT ALL ON `{db}`.* TO x", "REPLACE INTO `{db}`.t VALUES (1)", "TRUNCATE {db}.t"]
# What fuzzed data loses before it goes in a value: anything a refused statement could be made of.
_NAMES_RE = re.compile(r"(?i)mysql|sys|_schema|gs[0-9]|[\r\n'\\]")


def _case(fdp, s):
    k = fdp.ConsumeIntInRange(0, 2)
    return s if k == 0 else s.lower() if k == 1 else s.upper()


def _data(fdp):
    s = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 40))
    while _NAMES_RE.search(s):
        s = _NAMES_RE.sub("", s)
    return s


def _insert(fdp):
    rows = ",".join("(%d,'%s')" % (i, _data(fdp)) for i in range(fdp.ConsumeIntInRange(1, 3)))
    return "INSERT INTO `t` VALUES " + rows + ";"  # nosec B608 - a dump line the scan reads as text; nothing runs it


def _bad(fdp):
    sp = fdp.PickValueInList([" ", "\t", "  ", " \t"])
    stmt = fdp.PickValueInList(_FORBIDDEN).format(db=_case(fdp, fdp.PickValueInList(_OTHERS)), sp=sp)
    stmt = _case(fdp, stmt) if "VALUES" not in stmt else stmt
    lead = fdp.PickValueInList(["", "", "/*!40101 ", "/*!", "  ", "\t"])
    stmt = lead + stmt + (" */" if lead.startswith("/*!") else "") + ";"
    where = fdp.ConsumeIntInRange(0, 2)
    if where == 1:
        # Not after DELIMITER, whose argument is the rest of its line.
        return fdp.PickValueInList([b for b in _BENIGN if b.endswith(";") and not b.startswith("DELIMITER")]) + fdp.PickValueInList(["", " "]) + stmt
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
                       input=text.replace("\0", " ").encode("utf-8"), capture_output=True, env=_ENV, timeout=20, check=False)
    out = r.stdout.decode("utf-8", "replace").splitlines()
    assert r.returncode == 0 and len(out) == 1 and out[0] in _VERDICTS, (awk, text, r.returncode, out, r.stderr[-300:])
    return out[0]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text, bad = _dump(fdp)
    limit = 1 << 30 if fdp.ConsumeBool() else fdp.ConsumeIntInRange(1, 4096)
    verdicts = {awk: _scan(awk, text, limit) for awk in _AWKS}
    assert len(set(verdicts.values())) == 1, (text, verdicts)
    got = next(iter(verdicts.values()))
    size = len(text.encode("utf-8")) + (0 if text.endswith("\n") else 1)
    if bad:
        assert got != "SCANNED", (text, got)
    else:
        assert got == ("SCANNED" if size <= limit else "BIG"), (text, got, size, limit)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
