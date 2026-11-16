"""Part 225 of the unit suite: which panel log lines reach the journal, and at which priority.

* The stderr handler passes INFO and up (DEBUG stays out), on 'panel', 'notifications' and Flask's app
  logger, where it replaces Flask's default handler; app.py's create_app hook attaches it.
* When stderr is the journal stream systemd named in JOURNAL_STREAM (device:inode, compared with fd's
  own), every line starts with its sd-daemon priority: <2> critical, <3> error, <4> warning, <6> info,
  a traceback's lines and a 500's included, and a message argument's newline or NUL cannot start a
  line at a priority of its own. Anywhere else the lines are plain, as before.
Every check goes through the real logger and handler, writing to a temporary file standing in for the
journal stream; nothing reaches a host, the real journal or data/.
"""
import logging as _log225
import os as _os225
import sys as _sys225
import tempfile as _tf225
from contextlib import contextmanager as _cm225

from flask import Flask as _Flask225
from flask.logging import default_handler as _flask_default225

import app as _app225
from unit.part01 import check, eq
from panel.ops.debug_report import errors as _err225

_CHAINS225 = ("panel", "notifications")
_FORGED225 = "line one\n<0>forged emergency\x00<1>forged alert"


def _set_aside225():
    """Take the panel's own handlers off its two chains; what was there, to put back."""
    saved = {n: [h for h in _log225.getLogger(n).handlers if getattr(h, _err225._MARK, None)]
             for n in _CHAINS225}
    for name, handlers in saved.items():
        for handler in handlers:
            _log225.getLogger(name).removeHandler(handler)
    return saved, {n: _log225.getLogger(n).level for n in _CHAINS225}


def _put_back225(saved, levels):
    """Drop what a check attached to the two chains and restore what _set_aside225 took off."""
    for name in _CHAINS225:
        lg = _log225.getLogger(name)
        for handler in [h for h in lg.handlers if getattr(h, _err225._MARK, None)]:
            lg.removeHandler(handler)
        for handler in saved[name]:
            lg.addHandler(handler)
        lg.setLevel(levels[name])


def _set_env225(text):
    """Set JOURNAL_STREAM to `text`, or remove it when `text` is empty or None."""
    if text:
        _os225.environ["JOURNAL_STREAM"] = text
    else:
        _os225.environ.pop("JOURNAL_STREAM", None)


@_cm225
def _stream225(journal=True, value=None):
    """Make a temporary file the process's stderr, named (or not) by JOURNAL_STREAM; yield a reader.

    `value` replaces the variable's text ("" removes it); otherwise it names the file when `journal`
    is true and a different inode when not. The panel's own handlers are set aside for the duration.
    """
    saved, levels = _set_aside225()
    old_env, old_err = _os225.environ.get("JOURNAL_STREAM"), _sys225.stderr
    with _tf225.TemporaryFile("w+", encoding="utf-8") as tmp:
        st = _os225.fstat(tmp.fileno())
        _set_env225(value if value is not None else "%d:%d" % (st.st_dev, st.st_ino + (0 if journal else 1)))
        _sys225.stderr = tmp
        try:
            yield lambda: (tmp.flush(), tmp.seek(0), tmp.read())[2]
        finally:
            _sys225.stderr = old_err
            _set_env225(old_env)
            _put_back225(saved, levels)


def _emit225():
    """One record at each level on a panel logger, the error with a real traceback."""
    lg = _log225.getLogger("panel.p225")
    lg.debug("p225 debug stays out")
    lg.info("p225 info %s", _FORGED225)
    lg.warning("p225 warning")
    try:
        raise OSError("p225 broken pipe")
    except OSError:
        lg.error("p225 error", exc_info=True)
    lg.critical("p225 critical")


def _flask500():
    """A Flask app whose one route raises; its logger is the one attach_log_handlers is given."""
    fapp = _Flask225("p225app")

    @fapp.route("/boom")
    def _boom225():
        raise RuntimeError("p225 route failed")

    return fapp


# ── on the journal: every line prefixed ──────────────────────────────────────────────────────────
_japp225 = _flask500()
with _stream225(journal=True) as _read225:
    _err225.attach_log_handlers(_japp225.logger)
    try:
        _emit225()
        _status225 = _japp225.test_client().get("/boom").status_code
        _japp225.logger.info("p225 app info")
    finally:
        _err225.detach_log_handlers(_japp225.logger)
    _jout225 = _read225().split("\n")
_tb225 = [ln for ln in _jout225 if ln.startswith("<3>") and "p225" not in ln]
eq("journal: INFO, WARNING, ERROR and CRITICAL each start with their sd-daemon priority, DEBUG is not "
   "written, and a message's newline and NUL each start a line at the RECORD's priority",
   [ln for ln in _jout225 if ("p225" in ln or "forged" in ln)
    and not ln.startswith(("<3>  ", "<3>Traceback"))][:6],
   ["<6>INFO panel.p225: p225 info line one", "<6><0>forged emergency", "<6><1>forged alert",
    "<4>WARNING panel.p225: p225 warning", "<3>ERROR panel.p225: p225 error",
    "<3>OSError: p225 broken pipe"])
check("journal: every line of the error's traceback carries <3>, and the critical line <2>",
      "<3>Traceback (most recent call last):" in _jout225 and "<2>CRITICAL panel.p225: p225 critical"
      in _jout225 and not any(ln and not ln.startswith(("<2>", "<3>", "<4>", "<6>")) for ln in _jout225)
      and "p225 debug stays out" not in "\n".join(_jout225), repr(_jout225))
check("journal: a route's 500 is logged by Flask's app logger through the stderr handler: its message "
      "and every traceback line at <3>, then the app logger's INFO at <6>",
      _status225 == 500 and "<3>ERROR p225app: Exception on /boom [GET]" in _jout225
      and "<3>RuntimeError: p225 route failed" in _jout225 and len(_tb225) > 4
      and _jout225[-2:] == ["<6>INFO p225app: p225 app info", ""], repr(_jout225))
check("journal: detaching puts Flask's default handler back on the app logger",
      _japp225.logger.handlers == [_flask_default225] and _japp225.logger.level == _log225.NOTSET,
      repr(_japp225.logger.handlers))

# ── not the journal: plain text ──────────────────────────────────────────────────────────────────
_plain225 = {}
for _name225, _kw225 in (("another inode", {"journal": False}), ("unset", {"value": ""}),
                         ("not dev:ino", {"value": "abc:12"})):
    with _stream225(**_kw225) as _read225:
        _err225.attach_log_handlers()
        _log225.getLogger("panel.p225").warning("p225 plain %s", _name225)
        _plain225[_name225] = _read225()
eq("not the journal (JOURNAL_STREAM naming another inode, unset, or not dev:ino): the line is plain, "
   "with no priority prefix", _plain225,
   {"another inode": "WARNING panel.p225: p225 plain another inode\n",
    "unset": "WARNING panel.p225: p225 plain unset\n",
    "not dev:ino": "WARNING panel.p225: p225 plain not dev:ino\n"})
check("not the journal: a stream with no descriptor is never the journal",
      _err225.stream_is_journal(object(), {"JOURNAL_STREAM": "1:2"}) is False)

# ── an app logger inside a chain: one line, not two ──────────────────────────────────────────────
_capp225 = _Flask225("panel.p225app")
with _stream225(journal=True) as _read225:
    _err225.attach_log_handlers(_capp225.logger)
    try:
        _capp225.logger.warning("p225 once")
        _cout225 = _read225()
    finally:
        _err225.detach_log_handlers(_capp225.logger)
eq("an app logger named inside 'panel' reaches that chain's stderr handler only: one line, not two",
   _cout225, "<4>WARNING panel.p225app: p225 once\n")

# ── the caller: create_app's hook ────────────────────────────────────────────────────────────────
_happ225 = _Flask225("p225hook")
with _stream225(journal=True) as _read225:
    _app225._attach_debug_logging(_happ225)
    try:
        _happ225.logger.info("reduced the IP on %d audit entries to a network prefix", 3)
        _log225.getLogger("panel.models").info("dropped the IPv6 zone text from the IP of %d audit entries", 2)
        _hout225 = _read225()
    finally:
        _err225.detach_log_handlers(_happ225.logger)
eq("app.py's create_app hook: a startup INFO line on Flask's logger and on a panel logger reaches the "
   "journal at <6>", _hout225,
   "<6>INFO p225hook: reduced the IP on 3 audit entries to a network prefix\n"
   "<6>INFO panel.models: dropped the IPv6 zone text from the IP of 2 audit entries\n")
