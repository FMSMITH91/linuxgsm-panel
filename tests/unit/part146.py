"""Part 146 of the unit suite: the opt-in debug log.

The panel makes DEBUG records all along (its loops record what they skipped and why, the bots
their replies) and the journal never sees them: the stderr handler is at WARNING. On a test box a
fault then had to be guessed at. config.json "debug_log": true now sends them to data/debug.log.
Held here:

* off unless the key is exactly true (a hand-edited "true" string does not switch it on);
* on: DEBUG records of 'panel' and 'notifications' reach the file, with time, level and logger;
* the file is the owner's alone (0600), capped at 5 MB with 3 older files kept;
* attaching twice adds nothing; the journal (stderr) still gets WARNING and up only.
"""
import logging
import os
import pathlib
import shutil
import stat
import tempfile

from unit.part01 import check

import app as _app146
from panel.ops.debug_report import errors as _err146

_dir146 = pathlib.Path(tempfile.mkdtemp(prefix="lgsm-unit-p146-"))
_saved146 = _app146.DATA_DIR
_flask146 = type("_App146", (), {"logger": logging.getLogger("p146.flask")})()


def _ours146():
    """Every debug-log handler attached to the two loggers right now."""
    return [h for n in _err146.LOGGERS for h in logging.getLogger(n).handlers
            if getattr(h, _err146._MARK, None) == "debugfile"]


def _drop146():
    for n in _err146.LOGGERS:
        lg = logging.getLogger(n)
        for h in [h for h in lg.handlers if getattr(h, _err146._MARK, None) == "debugfile"]:
            lg.removeHandler(h)
            h.close()


_before146 = len(_ours146())
try:
    _app146.DATA_DIR = _dir146
    _log146 = _dir146 / "debug.log"
    _app146._attach_debug_logging(_flask146, {"debug_log": "true"})
    _app146._attach_debug_logging(_flask146, {})
    _off146 = (_log146.exists(), len(_ours146()))
    _app146._attach_debug_logging(_flask146, {"debug_log": True})
    _on146 = len(_ours146())
    _app146._attach_debug_logging(_flask146, {"debug_log": True})
    _again146 = len(_ours146())
    logging.getLogger("panel.p146").debug("p146 panel record %s", "one")
    logging.getLogger("notifications").debug("p146 bot record")
    logging.getLogger("p146.elsewhere").warning("p146 not ours")
    for _h in _ours146():
        _h.flush()
    _text146 = _log146.read_text(encoding="utf-8") if _log146.exists() else ""
    _mode146 = stat.S_IMODE(os.stat(_log146).st_mode) if _log146.exists() else None
    _h146 = _ours146()[0] if _ours146() else None
    _cap146 = (getattr(_h146, "maxBytes", None), getattr(_h146, "backupCount", None),
               getattr(_h146, "level", None))
    _stderr146 = [h.level for h in logging.getLogger("panel").handlers
                  if getattr(h, _err146._MARK, None) == "stderr"]
    # detach_log_handlers takes every marked handler off, the suite's own too: put those back after.
    _snap146 = {n: (list(logging.getLogger(n).handlers), logging.getLogger(n).level) for n in _err146.LOGGERS}
    try:
        _err146.detach_log_handlers()
        _closed146 = (_h146 is not None and getattr(_h146, "stream", "open") is None, len(_ours146()))
    finally:
        for _n146, (_hs146, _lv146) in _snap146.items():
            _lg146 = logging.getLogger(_n146)
            _lg146.handlers[:] = [h for h in _hs146 if h is not _h146]
            _lg146.setLevel(_lv146)
finally:
    _drop146()
    _app146.DATA_DIR = _saved146
    shutil.rmtree(_dir146, ignore_errors=True)

check("debug log: off unless config says exactly true — the string \"true\" and a missing key leave "
      "no file and no handler", _off146 == (False, _before146), repr(_off146))
check("debug log: on, one handler serves both loggers, and attaching again adds none",
      _on146 == _before146 + 2 and _again146 == _on146, repr((_before146, _on146, _again146)))
check("debug log: DEBUG records of 'panel' and 'notifications' reach the file, with level and logger",
      "DEBUG panel.p146 [" in _text146 and "p146 panel record one" in _text146
      and "DEBUG notifications [" in _text146 and "p146 bot record" in _text146, repr(_text146[-400:]))
check("debug log: a logger outside the panel's two is not written", "p146 not ours" not in _text146,
      repr(_text146[-400:]))
check("debug log: the file is the owner's alone (0600)", _mode146 == 0o600, repr(_mode146))
check("debug log: capped at 5 MB a file with 3 older ones kept (20 MB at most), at DEBUG",
      _cap146 == (5 * 1024 * 1024, 3, logging.DEBUG), repr(_cap146))
check("debug log: the journal's handler stays at WARNING, so DEBUG still goes only to the file",
      _stderr146 and all(lv == logging.WARNING for lv in _stderr146), repr(_stderr146))
check("debug log: detaching the handlers closes the file too (no descriptor left open on it)",
      _closed146 == (True, 0), repr(_closed146))
check("debug log: the suite's own loggers are left as found (no handler of this part remains)",
      len(_ours146()) == _before146, repr(len(_ours146())))
