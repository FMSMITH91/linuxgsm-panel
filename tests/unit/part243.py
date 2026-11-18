r"""Part 243 of the unit suite: the upload scan reads a dump's SQL as tokens (ssh_manager/db_upload_scan.py).

* Through the upload's finish script, run by bash on a temporary home as the host runs it: each
  statement a line-by-line text scan missed (a keyword split over lines, a comment, \v or \f between
  words, a name and its dot on two lines, a USE after an INSERT) is refused with its verdict, and so is
  each text the client or the server would read differently from the scan (NO_BACKSLASH_ESCAPES, a gbk
  client character set, a version-gated comment, a block comment inside an executable one, a quoted
  DELIMITER, a client command) and SQL built or loaded while it runs. Nothing is stored for any of them.
* A real mysqldump (trigger, view, event, routines; data that mentions statements, other databases
  and settings) is stored as it was uploaded.
* The corpus seeds: bypass-* and refuse-* are refused, clean-* passes, with every awk on the machine.
* The two ways the program reads strings (one gsub; a split at the quotes, gawk's fast way) give the
  same verdicts, and the program uses nothing mawk lacks.
* OPAQUE is a refusal the route knows: its mark, its sentence, and the sentence in es and fr.

Nothing reaches a host, a database server or data/.
"""
import glob as _glob243
import gzip as _gz243
import json as _json243
import os as _os243
import re as _re243
import shutil as _sh243
import subprocess as _sp243  # nosec B404 - bash and awk over this part's own scratch files
import tempfile as _tf243

from unit.part01 import check, eq
from unit.part05 import _root
from panel.ops.ssh_manager import db_upload_scan as _mod243
from panel.routes import databases_files as _dfr243

_T243 = _tf243.mkdtemp(prefix="lgsm-unit-p243-")
_HOME243 = _os243.path.join(_T243, "home", "gm243")
_DD243 = _os243.path.join(_HOME243, "panel-db-dumps")
_UID243 = "cd" * 16
_os243.makedirs(_HOME243, exist_ok=True)
_SEEDS243 = _os243.path.join(_root, "tests", "fuzz", "corpus", "upload_scan")
_AWKS243 = [p for p in (_sh243.which(n) for n in ("mawk", "gawk")) if p] or [_sh243.which("awk") or "/usr/bin/awk"]


def _bash243(script):
    p = _sp243.run(["bash", "-c", script.replace("/home/gm243", _HOME243)], capture_output=True, text=True,
                   timeout=60, check=False)  # nosec B603 B607 - bash over the finish script this part checks
    return p.stdout + p.stderr


def _finish243(data):
    """(the finish script's outcome, the stored dump unpacked or None) for an upload of `data`."""
    _bash243(_dfr243.start_script("gm243", _UID243, 1))
    with open(_os243.path.join(_DD243, ".panel-upload-%s.part" % _UID243), "wb") as fh:
        fh.write(data)
    out = _bash243(_dfr243.finish_script("gm243", _UID243, len(data), "gs12_lp"))
    dest = _os243.path.join(_DD243, "gs12_lp.sql.gz")
    stored = None
    if _os243.path.exists(dest):
        with _gz243.open(dest, "rb") as fh:
            stored = fh.read()
        _os243.unlink(dest)
    return _dfr243.outcome(out), stored


def _scan243(awk, data, program=None):
    """The verdict of the scan (or `program`) run by `awk` on `data`, as the finish script runs it."""
    r = _sp243.run([awk, "-v", "me=gs12_lp", "-v", "max=%d" % (1 << 30), program or _mod243.SCAN_AWK],
                   input=data.replace(b"\0", b" "), capture_output=True, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                   timeout=60, check=False)  # nosec B603 - a fixed argv: awk and the program under test
    return r.stdout.decode("utf-8", "replace").strip()


def _seed243(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return data[len(b"#scan\n"):] if data.startswith(b"#scan\n") else None


# ── 1. through the finish script ────────────────────────────────────────────────────────────────
_REFUSE243 = {
    "DROP and DATABASE on two lines": (b"-- dump\nDROP\nDATABASE gs9_x;\n", "SWITCH"),
    "a comment between DROP and DATABASE": (b"-- dump\nDROP/* x */DATABASE gs9_x;\n", "SWITCH"),
    "a vertical tab after USE": (b"-- dump\nUSE\x0bmysql;\n", "SWITCH"),
    "a form feed in CREATE SCHEMA": (b"-- dump\nCREATE\x0cSCHEMA `gs9_x`;\n", "SWITCH"),
    "CREATE OR REPLACE DATABASE, a word a line": (b"-- dump\nCREATE\nOR\nREPLACE\nDATABASE gs9_x;\n", "SWITCH"),
    "a USE of any database after an INSERT": (b"-- dump\nINSERT INTO `t` VALUES (1,'a');\tUSE otherdb;\n", "SWITCH"),
    "a USE after a line comment, its name after another": (b"-- dump\nSELECT 1 # x\n; USE\n-- c\nmysql;\n", "SWITCH"),
    "a USE after a dash and a control byte": (b"-- dump\nSELECT 1 --\x01 x; USE mysql;\n", "SWITCH"),
    "a quoted name and its dot apart": (b"-- dump\nSELECT * FROM `mysql`\n  /* c */ .`user`;\n", "OTHER"),
    "an unquoted name and its dot on two lines": (b"-- dump\nUPDATE gs9_x\n.t SET a = 1;\n", "OTHER"),
    "a version-gated comment a quote would hide": (b"-- dump\n/*!99999 ' */ USE mysql; -- '\n", "OPAQUE"),
    "a block comment inside an executable one": (b"-- dump\n/*!50000 /* a */ ' */ USE mysql; SELECT '\n", "OPAQUE"),
    "NO_BACKSLASH_ESCAPES": (b"-- dump\nSET sql_mode='NO_BACKSLASH_ESCAPES';\nSELECT 'x\\'; USE mysql; -- ';\n", "OPAQUE"),
    "ANSI_QUOTES through a variable": (b"-- dump\nSET @m = 'ANSI_QUOTES';\nSET SESSION sql_mode = @m;\n", "OPAQUE"),
    "an sql_mode made at run time": (b"-- dump\nSET @@sql_mode = CONCAT(@@sql_mode, ',ANSI');\n", "OPAQUE"),
    "an sql_mode in two strings on two lines": (b"-- dump\nSET sql_mode = 'NO_BACKSLASH'\n'_ESCAPES';\n", "OPAQUE"),
    "a gbk client character set": (b"-- dump\nSET NAMES gbk;\nSELECT '\xbf\\'; USE mysql; -- ';\n", "OPAQUE"),
    "CHARACTER SET sjis, a word a line": (b"-- dump\nSET\nCHARACTER\nSET\nsjis;\n", "OPAQUE"),
    "PREPARE": (b"-- dump\nPREPARE s FROM CONCAT('SELECT * FROM my', 'sql.user');\nEXECUTE s;\n", "OPAQUE"),
    "LOAD DATA LOCAL": (b"-- dump\nLOAD DATA LOCAL INFILE '/etc/hosts' INTO TABLE t;\n", "OPAQUE"),
    "a client command": (b"-- dump\n\\C gbk\n", "OPAQUE"),
    "a quoted DELIMITER": (b"-- dump\nDELIMITER '\nSELECT 1'USE mysql'\n", "OPAQUE"),
}
_R243 = {name: _finish243(sql) for name, (sql, _v) in _REFUSE243.items()}
eq("upload scan: each statement a line-by-line scan missed, each text read differently by the client or the "
   "server, and SQL built or loaded at run time are refused by the finish script, and nothing is stored",
   _R243, {name: (("refused", v), None) for name, (_sql, v) in _REFUSE243.items()})

_CLEAN243 = _seed243(_os243.path.join(_SEEDS243, "clean-mysqldump")) or b""
eq("upload scan: a real mysqldump (trigger, view, event, routines, data that mentions USE, other databases, "
   "NO_BACKSLASH_ESCAPES and DELIMITER) is stored as it was uploaded",
   (_finish243(_CLEAN243), len(_CLEAN243) > 4000), ((("ok", ""), _CLEAN243), True))

# ── 2. the corpus seeds, with every awk here ────────────────────────────────────────────────────
_SV243 = {}
for _p243 in sorted(_glob243.glob(_os243.path.join(_SEEDS243, "*"))):
    _d243 = _seed243(_p243)
    if _d243 is not None:
        _SV243[_os243.path.basename(_p243)] = {_scan243(a, _d243) for a in _AWKS243}
check("upload scan: the corpus's bypass-* and refuse-* dumps are refused and clean-* passes, each with one "
      "verdict from every awk here",
      len(_SV243) >= 18 and all(len(v) == 1 for v in _SV243.values())
      and all(v == {"SCANNED"} for k, v in _SV243.items() if k.startswith("clean-"))
      and all(v <= {"SWITCH", "OTHER", "OPAQUE"} for k, v in _SV243.items() if k.startswith(("bypass-", "refuse-")))
      and {k.split("-")[0] for k in _SV243} == {"bypass", "refuse", "clean"}, repr((_AWKS243, _SV243)))

# ── 3. both ways of reading strings, and nothing mawk lacks ─────────────────────────────────────
_SPLIT243 = _mod243.SCAN_AWK.replace('G = PROCINFO["version"] != ""', "G = 1")
_GSUB243 = _mod243.SCAN_AWK.replace('G = PROCINFO["version"] != ""', "G = 0")
_WAYS243 = [_CLEAN243, _CLEAN243 + b"USE mysql;\n", b"SELECT 'a', 'b\nc'; USE x;\n", b"SELECT 'it''s'; DROP\nSCHEMA x;\n",
            b"SELECT 'odd\n'' USE x;\n';\n", b"INSERT INTO `t` VALUES ('\\'', 'x');\nSELECT 1;\n"]
_W243 = [(_scan243(_AWKS243[0], d, _SPLIT243), _scan243(_AWKS243[0], d, _GSUB243)) for d in _WAYS243]
check("upload scan: the split at the quotes and the gsub of strings give the same verdict on each dump, and "
      "differ from the scan's default nowhere", _SPLIT243 != _mod243.SCAN_AWK != _GSUB243
      and all(a == b for a, b in _W243) and [w[0] for w in _W243] == ["SCANNED", "SWITCH", "SWITCH", "SWITCH",
                                                                      "SCANNED", "SCANNED"], repr(_W243))
_GAWK_ONLY243 = _re243.findall(r"\b(gensub|strftime|systime|mktime|asorti?|patsplit|isarray|typeof|"
                               r"switch|BEGINFILE|ENDFILE|IGNORECASE|RT\b|FPAT)\b|\{[0-9]+(,[0-9]*)?\}",
                               _mod243.SCAN_AWK)
check("upload scan: the program uses no gawk-only function or variable and no regex interval (Ubuntu 22.04's "
      "mawk has none)", not _GAWK_ONLY243, repr(_GAWK_ONLY243))

# ── 4. the route knows the refusal ──────────────────────────────────────────────────────────────


def _catalog243(lang):
    with open(_os243.path.join(_root, "panel", "translations", lang, "dbmgr.json"), encoding="utf-8") as fh:
        return _json243.load(fh)


_OPQ243 = _dfr243._REFUSALS.get("OPAQUE", "")
check("upload scan: OPAQUE is a refusal the route reads, its sentence says what to do, and es and fr have it",
      _dfr243.outcome("x\n__DBUP_OPAQUE__\n") == ("refused", "OPAQUE") and "mysqldump" in _OPQ243
      and all(_catalog243(lang).get(_OPQ243) for lang in ("es", "fr"))
      and "BIG|SWITCH|OTHER|OPAQUE)" in _dfr243.finish_script("gm243", _UID243, 1, "gs12_lp"), _OPQ243)

_sh243.rmtree(_T243, ignore_errors=True)
