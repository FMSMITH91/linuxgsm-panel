"""Part 33 of the unit suite: game-server backups (ws3), driven through the real sweeps.

What it tests, one section each:
  A. the backup-ticker pass: every step runs on its own, a failed pass is counted under the loop's
     own name and does not beat;
  B. a server that players keep from its scheduled backup is reported ONCE per clock value, and
     that survives a restart; the 'wait until empty' queue likewise when the server's own schedule
     is off; each report says only what is known (the clock's age, THIS attempt) and is filed
     under its own audit action, never as a scheduled backup;
  C. "Back up game servers now" moves each archived server's clock, so the ticker does not archive
     it again, and records when it queued one (not again for one already waiting); a clock write
     that fails is not a failed backup;
  D. a backup that RAISES alerts once per streak, across BOTH sweeps, and audits every attempt; an
     audit write that fails neither swallows an alert nor stops the sweep;
  E. the debug report: the automatic schedule per server, what the unattended runs recorded (the
     reports counted apart), the manual run labelled as the manual run's, and the notification
     events that are off, by key;
  F. the Backups page: the payload's newest scheduled backup (and the newest that worked, when it
     failed), the manual status under its button and the automatic one in the schedule's row (the
     JS run under node);
  G. paramiko: an exec request the remote never answers is bounded (commands and both download
     streams), a sweep holding the global backup lock against such a host lets it go, and the
     wedged client is dropped from the pool so the next command reconnects;
  H. the panel's own backup: a temp dir that cannot be made leaves no empty archive behind.

HOW IT RUNS. Its own Flask app and SQLite file in a temp dir (db.init_app + create_all), never the
checkout's data/. config.json is the runner's throwaway one, snapshotted at the start and put back
in the finally. The sweeps, _record_backup_outcome, log_action and the config writers are the real
ones (D's refused audit write wraps the real log_action); run_game_backup (on both route modules)
and notify are recorded stand-ins. G runs a paramiko server on 127.0.0.1 inside this process and
points _core.get_connection (or, for the pool check, _core._open_client behind the real pool) at a
client of it. Every attribute replaced is put back in the finally, and the in-memory maps this part
fills are emptied.
"""
import datetime as _dt33
import json as _json33
import logging as _logging33
import os
import pathlib as _pl33
import shutil as _shutil33
import socket as _socket33
import subprocess as _sp33  # nosec B404 - runs node on this part's own harness, argv list only
import tempfile as _tf33
import threading as _th33
import time as _t33
from types import SimpleNamespace as NS

import paramiko as _pk33
from flask import Flask as _Flask33
from flask.logging import default_handler as _flask_default_handler33

from unit.part01 import check, eq
from panel.core import config as _cfg33
from panel.core import panel_state as _ps33
from panel.core import runtime_stats as _rs33
from panel.db.models import AuditLog, GameServer, RemoteServer, db
from panel.ops import backup as _bk33
from panel.ops.debug_report import data as _data33
from panel.ops.debug_report import notifications as _nsec33
from panel.ops.debug_report._base import Ctx as _Ctx33
from panel.ops.ssh_manager import _core as _core33
from panel.ops.ssh_manager import cron as _cron33
from panel.ops.ssh_manager import files as _files33
from panel.ops.ssh_manager import game as _game33
from panel.routes import _shared as _sh33
from panel.routes import panel_backup as _pb33
from panel.security import auth as _auth33
from panel.services import notifications as _notif33

_ROOT33 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_T33 = _tf33.mkdtemp(prefix="lgsm-unit-p33-")
_DB33 = os.path.join(_T33, "p33.db")
_DAY33 = 86400
_saved33 = []
_CFG33_SNAPSHOT = _cfg33.CONFIG_FILE.read_bytes() if _cfg33.CONFIG_FILE.exists() else None
_MAPS33 = (_sh33._backup_raise_streak, _sh33._overdue_reported, _sh33._queue_wait_reported)
_GBS33_SNAP = dict(_ps33._game_backup_status)
_HB33 = (_rs33.snapshot("heartbeat").get("backup-ticker"),
         _rs33.snapshot("loopfail").get("backup-ticker"))


def _p33(owner, name, value):
    """Replace owner.name for this part; _restore33 puts every one back, newest first."""
    _saved33.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _restore33():
    while _saved33:
        owner, name, value = _saved33.pop()
        setattr(owner, name, value)


# ── the app, its database and the recorded stand-ins ────────────────────────────────────────────
_APP33 = _Flask33("unit_part33")
_APP33.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + _DB33,
                     SQLALCHEMY_TRACK_MODIFICATIONS=False, LOGIN_DISABLED=True)
db.init_app(_APP33)


class _Logs33(_logging33.Handler):
    """Collect the formatted messages of the part's app logger."""

    def __init__(self):
        super().__init__(_logging33.DEBUG)
        self.msgs = []

    def emit(self, record):
        """Keep the message, level first."""
        self.msgs.append("%s %s" % (record.levelname, record.getMessage()))


_LOGS33 = _Logs33()
_APP33.logger.addHandler(_LOGS33)
_APP33.logger.removeHandler(_flask_default_handler33)   # the sweeps' expected tracebacks: collected
_APP33.logger.propagate = False
_NOTES33 = []      # (event, title, body) of every notify()
_RUNS33 = []       # short names the stand-in runner was asked to back up
_SCRIPT33 = {}     # short name -> (ok, reason, skipped) or an exception to raise


def _runner33(_remote, short, _lgsm, _keep, **_kw):
    _RUNS33.append(short)
    r = _SCRIPT33.get(short, (True, "Backed up", False))
    if isinstance(r, Exception):
        raise r
    return r


def _host33():
    with _APP33.app_context():
        h = RemoteServer(name="p33-host", host="192.0.2.33", port=22, username="root",
                         auth_method="key", auth_credential="")
        db.session.add(h)
        db.session.commit()
        return h.id


def _new33(name, short, rid, **kw):
    """A fresh installed server (ids are never reused here: nothing is deleted)."""
    with _APP33.app_context():
        gs = GameServer(remote_id=rid, name=name, short_name=short, game_type=kw.pop("game", "zz"),
                        port=kw.pop("port", 27100), installed=True, **kw)
        db.session.add(gs)
        db.session.commit()
        return gs.id


def _only33(*sids):
    """Leave only `sids` installed, so a sweep sees exactly the servers a check is about."""
    with _APP33.app_context():
        for gs in GameServer.query.all():
            gs.installed = gs.id in sids
        db.session.commit()


def _set33(sid, **fields):
    with _APP33.app_context():
        gs = db.session.get(GameServer, sid)
        for k, v in fields.items():
            setattr(gs, k, v)
        db.session.commit()


def _entry33(sid, **fields):
    """Write fields into server `sid`'s game_schedules entry (None removes one)."""
    def _mut(cfg):
        sched = cfg.setdefault("game_schedules", {})
        e = sched.setdefault(str(sid), {})
        for k, v in fields.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
    _cfg33.update_config(_mut)


def _audits33(action, target):
    with _APP33.app_context():
        return [NS(success=a.success, detail=a.detail or "") for a in
                AuditLog.query.filter_by(action=action, target=target).order_by(AuditLog.id).all()]


def _notes33(target):
    return [n for n in _NOTES33 if n[0] == "backup_failed" and target in n[2]]


def _restart33():
    """What a panel restart forgets: every in-memory map this part's code keeps."""
    for m in _MAPS33:
        m.clear()
    _ps33._game_backup_status.clear()


def _setup33():
    _cfg33.save_config(dict(_cfg33.DEFAULT_CONFIG, setup_complete=True))
    _bk33.set_full_settings(interval_days=7, keep=3)
    with _APP33.app_context():
        db.create_all()
    _p33(_sh33, "run_game_backup", _runner33)
    _p33(_pb33, "run_game_backup", _runner33)
    _p33(_notif33, "notify", lambda key, title, body="": _NOTES33.append((key, title, body)))
    _p33(_notif33, "alerts_muted", lambda gs: False)
    _restart33()
    return _host33()


# ══ A. the backup-ticker pass ═════════════════════════════════════════════════════════════════
def _a_step(label, fail=False):
    def _step(*_args):
        _A33.append(label)
        if fail:
            raise OSError("%s broke" % label)
    return _step


_A33 = []


def _a_pass(failing):
    del _A33[:], _LOGS33.msgs[:]
    hb0 = (_rs33.snapshot("heartbeat").get("backup-ticker") or {}).get("passes", 0)
    lf0 = _rs33.snapshot("loopfail").get("backup-ticker", 0)
    failed = _sh33._backup_ticker_pass(_APP33, tuple(
        (label, _a_step(label, label == failing), ()) for label in
        ("daily panel backup", "scheduled game backups", "queued game backups")))
    hb1 = (_rs33.snapshot("heartbeat").get("backup-ticker") or {}).get("passes", 0)
    return failed, list(_A33), hb1 - hb0, _rs33.snapshot("loopfail").get("backup-ticker", 0) - lf0


def _a_ticker():
    got = _a_pass("daily panel backup")
    check("backup ticker: a daily panel backup that raises still runs BOTH game sweeps of its pass",
          got[:2] == (1, ["daily panel backup", "scheduled game backups", "queued game backups"]),
          repr(got))
    check("backup ticker: ...the pass is a failed pass under the loop's own name, and does not beat",
          got[2:] == (0, 1), repr(got))
    check("backup ticker: ...and the failure is logged at WARNING, naming the step",
          any(m.startswith("WARNING") and "daily panel backup" in m for m in _LOGS33.msgs),
          repr(_LOGS33.msgs))
    got = _a_pass("scheduled game backups")
    check("backup ticker: a scheduled sweep that raises still lets the queued sweep run",
          got[1] == ["daily panel backup", "scheduled game backups", "queued game backups"]
          and got[0] == 1, repr(got))
    got = _a_pass(None)
    check("backup ticker: a clean pass beats once and counts no failure", got == (
        0, ["daily panel backup", "scheduled game backups", "queued game backups"], 1, 0),
          repr(got))


# ══ B. players online at every attempt ═══════════════════════════════════════════════════════
_BUSY33 = (False, "2 player(s) online — backup skipped so nobody gets disconnected", True)


def _b_sweep(n=1):
    for _ in range(n):
        _sh33._run_due_game_backups(_APP33)


def _b_overdue(rid):
    now = _t33.time()
    sid = _new33("p33-busy", "busyserver", rid)
    _only33(sid)
    _entry33(sid, last=int(now - 15 * _DAY33))
    _SCRIPT33["busyserver"] = _BUSY33
    _b_sweep()
    rows, notes = _audits33("scheduled_backup_overdue", "p33-busy"), _notes33("p33-busy")
    check("players online: a server kept from its backup for twice its interval is audited and "
          "alerted", all((len(rows) == 1, rows and rows[0].success is False,
                          rows and "clock last moved 15 days ago" in rows[0].detail, len(notes) == 1,
                          notes and notes[0][1] == "Scheduled backup overdue")),
          repr((rows, notes)))
    check("players online: ...and its clock is left alone (it stays due; nobody is disconnected)",
          _bk33.get_game_schedule(sid)["last"] == int(now - 15 * _DAY33) and _RUNS33.count(
              "busyserver") == 1, repr((_bk33.get_game_schedule(sid), _RUNS33)))
    _b_sweep(2)
    _restart33()
    _b_sweep()
    check("players online: the report is sent ONCE per clock value — not again on later ticks, "
          "nor after a restart", (len(_audits33("scheduled_backup_overdue", "p33-busy")),
                                  len(_notes33("p33-busy"))) == (1, 1),
          repr(_notes33("p33-busy")))
    _entry33(sid, last=int(now - 16 * _DAY33))
    _b_sweep()
    check("players online: once the clock moves, the next overdue streak is reported again",
          len(_notes33("p33-busy")) == 2, repr(_notes33("p33-busy")))
    return sid


def _b_not_yet(rid):
    sid = _new33("p33-busy8", "busy8server", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    _SCRIPT33["busy8server"] = _BUSY33
    _b_sweep()
    check("players online: a server overdue by less than a whole interval is not reported yet",
          not _notes33("p33-busy8") and not _audits33("scheduled_backup_overdue", "p33-busy8")
          and _RUNS33.count("busy8server") == 1, repr(_notes33("p33-busy8")))


def _b_refused_write(rid):
    sid = _new33("p33-busyro", "busyroserver", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 20 * _DAY33))
    _SCRIPT33["busyroserver"] = _BUSY33
    del _LOGS33.msgs[:]
    _p33(_bk33, "mark_overdue_alerted", _raise33(_cfg33.ConfigUnreadable("unreadable")))
    try:
        _b_sweep(3)
    finally:
        _restore_one33(_bk33, "mark_overdue_alerted")
    check("players online: when config.json refuses the mark, the report still goes out once per "
          "process, and the refused write is logged", all((
              len(_notes33("p33-busyro")) == 1,
              any("could not save" in m for m in _LOGS33.msgs))),
          repr((_notes33("p33-busyro"), _LOGS33.msgs[-3:])))


def _b_reenabled(rid):
    """A schedule turned back on over an old clock: the clock is old, but not because of players."""
    sid = _new33("p33-reon", "reonserver", rid)
    _only33(sid)
    _bk33.set_game_schedule(sid, 0, _bk33.UNCHANGED)        # off: the sweep never touches the clock
    _entry33(sid, last=int(_t33.time() - 20 * _DAY33))
    _SCRIPT33["reonserver"] = _BUSY33
    _b_sweep()
    _bk33.set_game_schedule(sid, None, _bk33.UNCHANGED)     # back on, at the default 7 d
    _b_sweep()
    rows, notes = _audits33("scheduled_backup_overdue", "p33-reon"), _notes33("p33-reon")
    want = ("its backup clock last moved 20 days ago (every 7 d); skipped at this attempt: "
            + _BUSY33[1])
    check("players online: a schedule turned back on over a 20-day-old clock and skipped ONCE is "
          "reported as what is known (the clock's age, THIS attempt), not as players on at every "
          "attempt", all((_RUNS33.count("reonserver") == 1, [r.detail for r in rows] == [want],
                          [n[2] for n in notes] == [
                              "p33-reon is overdue for its scheduled backup: " + want])),
          repr((_RUNS33.count("reonserver"), rows, notes)))


def _b_report_not_a_backup(rid):
    """The overdue report is not a backup attempt, so the Backups page must not read it as one."""
    with _APP33.app_context():
        db.session.add(AuditLog(username="system", action="scheduled_backup", success=True,
                                target="p33-ok-elsewhere"))
        db.session.commit()
    sid = _new33("p33-busypg", "busypgserver", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 15 * _DAY33))
    _SCRIPT33["busypgserver"] = _BUSY33
    _b_sweep()
    with _APP33.app_context():
        got = _pb33._last_scheduled_backup()
    check("players online: the overdue report has its own audit action, so the Backups page's newest "
          "automatic backup is still the one that worked, not a 'failed' one",
          len(_notes33("p33-busypg")) == 1 and (got or {}).get("ok") is True, repr(got))


def _raise33(exc):
    def _f(*_a, **_k):
        raise exc
    return _f


def _restore_one33(owner, name):
    for i in range(len(_saved33) - 1, -1, -1):
        if _saved33[i][0] is owner and _saved33[i][1] == name:
            setattr(owner, name, _saved33.pop(i)[2])
            return


def _b_queue(rid):
    sid = _new33("p33-queue", "queueserver", rid, backup_pending=True)
    _only33(sid)
    _bk33.set_game_schedule(sid, 0, _bk33.UNCHANGED)      # its own schedule: off
    _SCRIPT33["queueserver"] = _BUSY33
    _sh33._run_pending_backups(_APP33)
    since = _bk33.queued_since(sid)
    check("queued backup: a queued server with no queue time recorded starts its wait at first sight"
          " (an upgrade), and is not reported yet",
          abs(since - _t33.time()) < 60 and not _notes33("p33-queue"), repr((since, _NOTES33[-2:])))
    _entry33(sid, queued_at=int(_t33.time() - 8 * _DAY33))
    _sh33._run_pending_backups(_APP33)
    rows, notes = _audits33("queued_backup_waiting", "p33-queue"), _notes33("p33-queue")
    check("queued backup: still waiting a whole default interval later, with its schedule off, it "
          "is audited and alerted", all((
              len(rows) == 1, rows and rows[0].success is False,
              rows and "queued 8 days ago and still waiting" in rows[0].detail,
              [n[1] for n in notes] == ["Queued backup still waiting"])), repr((rows, notes)))
    want = "queued 8 days ago and still waiting; skipped at this attempt: " + _BUSY33[1]
    check("queued backup: the report says what is known — when it was queued, and that players were "
          "on at THIS attempt — not that they were on at every attempt",
          [r.detail for r in rows] == [want]
          and [n[2] for n in notes] == ["The queued backup of p33-queue is still waiting: " + want],
          repr((rows, notes)))
    _restart33()
    _sh33._run_pending_backups(_APP33)
    check("queued backup: ...once: not again after a restart, and it stays queued",
          len(_notes33("p33-queue")) == 1 and _row33(sid).backup_pending is True,
          repr(_notes33("p33-queue")))
    sid2 = _new33("p33-queue7", "queue7server", rid, backup_pending=True)
    _only33(sid2)
    _entry33(sid2, last=int(_t33.time() - _DAY33), queued_at=int(_t33.time() - 30 * _DAY33))
    _SCRIPT33["queue7server"] = _BUSY33
    _sh33._run_pending_backups(_APP33)
    check("queued backup: with its own schedule on, the queue's wait is not reported a second way "
          "(the schedule's overdue report covers it)", not _notes33("p33-queue7"),
          repr(_notes33("p33-queue7")))


def _row33(sid):
    with _APP33.app_context():
        gs = db.session.get(GameServer, sid)
        return NS(backup_pending=gs.backup_pending, installed=gs.installed)


# ══ C. "Back up game servers now" and the per-server clocks ══════════════════════════════════
def _c_full_run(defer=False):
    """The manual full run, handed the lock already held as _trigger_full_backup hands it."""
    if not _sh33._full_backup_lock.acquire(timeout=10):
        return False
    _pb33._run_full_backup(_APP33, defer=defer)
    return True


def _c_clocks(rid):
    now = _t33.time()
    sids = [_new33("p33-f" + x, "f%sserver" % x, rid) for x in ("ok", "busy", "fail")]
    _only33(*sids)
    near = int(now - 7 * _DAY33 + 1800)        # due half an hour from now
    for sid in sids:
        _entry33(sid, last=near)
    _SCRIPT33.update(fokserver=(True, "Backed up", False), fbusyserver=_BUSY33,
                     ffailserver=(False, "Not enough disk space", False))
    ran = _c_full_run(defer=True)
    lasts = [_bk33.get_game_schedule(s)["last"] for s in sids]
    check("full backup now: the server it archived has its own schedule clock moved; the skipped "
          "and the failed ones stay due", ran and abs(lasts[0] - now) < 60 and lasts[1:] == [near,
                                                                                         near],
          repr((ran, lasts, near)))
    check("full backup now: a server it queues ('wait until empty') has its queue time recorded",
          abs(_bk33.queued_since(sids[1]) - now) < 60 and _row33(sids[1]).backup_pending is True,
          repr(_bk33.queued_since(sids[1])))
    del _RUNS33[:]
    _p33(_bk33, "time", NS(time=lambda: _t33.time() + 3600, sleep=_t33.sleep))
    try:
        _sh33._run_due_game_backups(_APP33)
    finally:
        _restore_one33(_bk33, "time")
    check("full backup now: an hour later the ticker does NOT archive the server it just backed up "
          "again (it still archives the ones that stayed due)",
          sorted(_RUNS33) == ["fbusyserver", "ffailserver"], repr(_RUNS33))


def _c_requeue(rid):
    """'Back up game servers now' (wait until empty) pressed again while a server already waits."""
    sid = _new33("p33-frq", "frqserver", rid, backup_pending=True)
    _only33(sid)
    since = int(_t33.time() - 8 * _DAY33)
    _entry33(sid, queued_at=since)
    _SCRIPT33["frqserver"] = _BUSY33
    ran = _c_full_run(defer=True)
    check("full backup now: pressed again while a server is already queued, its wait is NOT restarted "
          "(the long-queue report measures from the first press)",
          ran and _bk33.queued_since(sid) == since and _row33(sid).backup_pending is True,
          repr((ran, _bk33.queued_since(sid), since)))


def _c_clock_write_fails(rid):
    sid = _new33("p33-fdisk", "fdiskserver", rid)
    _only33(sid)
    del _NOTES33[:]
    _p33(_pb33, "_record_game_clock", _raise33(OSError(28, "No space left on device")))
    try:
        ran = _c_full_run()
    finally:
        _restore_one33(_pb33, "_record_game_clock")
    summary = _bk33.get_full_settings()["summary"]
    check("full backup now: a clock write that fails after a backup that worked is logged, not "
          "counted (or alerted) as a failed backup", all((
              ran, summary.startswith("1 server(s) backed up"), "failed" not in summary,
              not [n for n in _NOTES33 if n[0] == "backup_failed"])),
          repr((summary, _NOTES33)))


# ══ D. a backup that RAISES: one alert per streak, both sweeps ═══════════════════════════════
def _d_tick():
    _sh33._run_due_game_backups(_APP33)
    _sh33._run_pending_backups(_APP33)


def _d_raises(rid):
    sid = _new33("p33-raise", "raiseserver", rid, backup_pending=True)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    _SCRIPT33["raiseserver"] = OSError("ssh dropped")
    for _ in range(3):
        _d_tick()
    notes = _notes33("p33-raise")
    sched, queued = _audits33("scheduled_backup", "p33-raise"), _audits33("queued_backup", "p33-raise")
    check("raised backup: due AND queued on a host that raises, three hourly ticks send ONE alert",
          len(notes) == 1, repr(notes))
    check("raised backup: ...while every attempt of both sweeps is still on the audit log as failed",
          all((len(sched) == 3, len(queued) == 3,
               all(a.success is False and "backup error (OSError)" in a.detail
                   for a in sched + queued))), repr((sched, queued)))
    _SCRIPT33["raiseserver"] = (True, "Backed up", False)
    _d_tick()
    _set33(sid, backup_pending=True)
    _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    _SCRIPT33["raiseserver"] = OSError("ssh dropped again")
    _d_tick()
    check("raised backup: once a backup has RETURNED, the next raise is a new streak, and alerts",
          len(_notes33("p33-raise")) == 2, repr(_notes33("p33-raise")))


def _d_queued_only(rid):
    sid = _new33("p33-qraise", "qraiseserver", rid, backup_pending=True)
    _only33(sid)
    _bk33.set_game_schedule(sid, 0, _bk33.UNCHANGED)
    _SCRIPT33["qraiseserver"] = OSError("ssh dropped")
    for _ in range(3):
        _d_tick()
    check("raised backup: a server whose schedule is off (the scheduled pass never reaches the host)"
          " still alerts once for its queued backup, not every tick",
          len(_notes33("p33-qraise")) == 1, repr(_notes33("p33-qraise")))


def _poison_log33(times):
    """A log_action whose first `times` calls fail the way a refused commit does.

    The flush raises (NOT NULL), and the session then refuses every query until it is rolled back
    (PendingRollbackError) — what SQLite "database is locked" leaves behind as well.
    """
    real, left = _sh33.log_action, [times]

    def _log(*a, **k):
        if left[0] > 0:
            left[0] -= 1
            db.session.add(AuditLog(username="system", action=None))
            db.session.commit()
        return real(*a, **k)
    return _log


def _sweep_with_poison33(times, sweep):
    """Run `sweep` with the poisoned log_action in place; the exception it raised, or None."""
    _p33(_sh33, "log_action", _poison_log33(times))
    try:
        sweep(_APP33)
        return None
    except Exception as e:  # noqa: BLE001 - returned to the check
        return e
    finally:
        _restore_one33(_sh33, "log_action")


def _d_audit_fails(rid):
    sid = _new33("p33-busylk", "busylkserver", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 15 * _DAY33))
    _SCRIPT33["busylkserver"] = _BUSY33
    err = _sweep_with_poison33(99, _sh33._run_due_game_backups)
    check("audit write refused: the overdue alert still goes out (its mark is saved before it, so a "
          "skipped alert was never sent)", err is None and [n[1] for n in _notes33("p33-busylk")] == [
              "Scheduled backup overdue"], repr((err, _notes33("p33-busylk"))))
    sid = _new33("p33-raiselk", "raiselkserver", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    _SCRIPT33["raiselkserver"] = OSError("ssh dropped")
    err = _sweep_with_poison33(99, _sh33._run_due_game_backups)
    check("audit write refused: a host's first raise still alerts (the streak is marked before it, so "
          "a skipped alert muted the whole outage)", err is None and [
              n[1] for n in _notes33("p33-raiselk")] == ["Scheduled backup failed"],
          repr((err, _notes33("p33-raiselk"))))
    sids = [_new33("p33-lk" + x, "lk%sserver" % x, rid) for x in ("a", "b")]
    _only33(*sids)
    for sid in sids:
        _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    err = _sweep_with_poison33(1, _sh33._run_due_game_backups)
    rows = _audits33("scheduled_backup", "p33-lkb")
    check("audit write refused: the sweep goes on — the next server is still backed up and on the "
          "audit log (the failed write is rolled back, not left to fail every later query)",
          err is None and "lkbserver" in _RUNS33 and [r.success for r in rows] == [True],
          repr((err, _RUNS33[-3:], rows)))


def _d_replaced(rid):
    sid = _new33("p33-gone", "goneserver", rid)
    with _APP33.app_context():
        _sh33._backup_raise_streak.pop(sid, None)
        _sh33._record_raised_backup(_APP33, (sid, "p33-gone", _dt33.datetime(2000, 1, 1)),
                                    OSError("x"), "scheduled_backup", "Scheduled backup failed")
    check("raised backup: a raise for a server whose id is now another row's alerts, but does not "
          "mark the streak (the new server's first alert is not muted)",
          sid not in _sh33._backup_raise_streak and len(_notes33("p33-gone")) == 1,
          repr((dict(_sh33._backup_raise_streak), _notes33("p33-gone"))))


# ══ E. the debug report ══════════════════════════════════════════════════════════════════════
def _e_seed(rid):
    now = _t33.time()
    sids = [_new33("p33-rep-" + x, "rep%sserver" % x, rid, game=g)
            for x, g in (("a", "gmod"), ("b", "mc"), ("c", "csgo"), ("d", "rust"))]
    _only33(*sids)
    _entry33(sids[0], last=int(now - 2 * _DAY33 - 60))
    _entry33(sids[1], last=int(now - 8 * _DAY33))
    _bk33.set_game_schedule(sids[2], 0, _bk33.UNCHANGED)
    _entry33(sids[3], last=None)
    with _APP33.app_context():
        AuditLog.query.filter(AuditLog.action.in_((
            "scheduled_backup", "queued_backup", "scheduled_backup_overdue",
            "queued_backup_waiting"))).delete(synchronize_session=False)
        old = _dt33.datetime.fromtimestamp(now - 40 * _DAY33, _dt33.timezone.utc).replace(tzinfo=None)
        db.session.add_all([AuditLog(username="system", action="scheduled_backup", success=True,
                                     target="p33-rep-a"),
                            AuditLog(username="system", action="scheduled_backup", success=False,
                                     target="p33-rep-b"),
                            AuditLog(username="system", action="scheduled_backup", success=True,
                                     target="p33-rep-a", timestamp=old),
                            AuditLog(username="system", action="scheduled_backup_overdue",
                                     success=False, target="p33-rep-b")])
        db.session.commit()
    _cfg33.update_config(lambda c: c.pop("full_backup_last", None))
    return sids


def _e_report():
    res = _data33.section_backups(_Ctx33())
    return "\n".join(res.lines), res.findings


def _e_section(rid):
    sids = _e_seed(rid)
    _p33(_cfg33, "DB_PATH", _pl33.Path(_DB33))
    _rs33.beat("backup-ticker", 3600, 1.0)          # a pass that started after gs b fell due
    text, finds = _e_report()
    check("report: the manual 'Back up game servers now' run is labelled as that, and the schedule "
          "has its own line with its default", all((
              "**Manual 'Back up game servers now'**: never run" in text,
              "Game-server backups, automatic** (default every 7 d, keep 3" in text,
              "4 installed · 1 due · 1 clock not started · 1 on schedule · 1 off" in text)), text)
    check("report: each server's own clock is printed by id and game: 2 days old, due, off by its "
          "own setting, not started", all((
              "gs %d · gmod · every 7 d · last 2 d ago · next in" % sids[0] in text,
              "gs %d · mc · every 7 d · last 8 d ago · due since 24 h" % sids[1] in text,
              "gs %d · csgo · off (its own setting)" % sids[2] in text,
              "gs %d · rust · every 7 d · clock not started" % sids[3] in text)), text)
    check("report: what the unattended runs recorded in 30 days, from the audit log (the old row "
          "is outside it)", "scheduled: 1 ok, 1 failed, newest " in text and "queued: none" in text,
          text)
    check("report: an overdue report is counted as a report, not as a failed scheduled backup",
          "scheduled: 1 ok, 1 failed, newest " in text and "reported overdue: 1, newest " in text,
          text)
    check("report: no game-server name is printed", "p33-rep" not in text, text)
    check("report: a server due since before the backup-ticker's last pass began is a warning",
          any(f["level"] == "warn" and "1 game server(s) due" in f["text"] for f in finds),
          repr(finds))
    return sids


def _e_gates():
    _rs33._GROUPS.get("heartbeat", {}).pop("backup-ticker", None)
    _text, finds = _e_report()
    check("report: ...but not before the ticker has completed a pass (a report taken just after a "
          "restart)", not [f for f in finds if "due for a scheduled backup" in f["text"]],
          repr(finds))
    _bk33.set_full_settings(interval_days=0)
    text, _f = _e_report()
    check("report: a default interval of 0 reads 'default: off', and the per-server lines still "
          "say which servers back up", "(default: off, keep 3;" in text and " · off" in text, text)
    _bk33.set_full_settings(interval_days=7)
    good = _cfg33.CONFIG_FILE.read_bytes()
    _cfg33.CONFIG_FILE.write_text("{ this is not json")
    try:
        text, finds = _e_report()
    finally:
        _cfg33.CONFIG_FILE.write_bytes(good)
    check("report: an unreadable config.json is said as such (the sweeps skip), never as every "
          "clock 'not started'", "config.json could not be read" in text
          and "clock not started" not in text
          and any("scheduled game backups are skipped" in f["text"] for f in finds), text)


def _e_events():
    form = {"telegram": {}, "discord": {}, "ntfy": {}, "thresholds": {},
            "events": {"backup_failed": False, "server_up": True, "ip_banned": False,
                       "server_down": True, "Bad Key; x": False}}
    _p33(_notif33, "settings_for_form", lambda: form)
    res = _nsec33.section_notifications(_Ctx33())
    text = "\n".join(res.lines)
    check("report: the notification events that are OFF are named by key (backup_failed among them)"
          ", and a key that is not one is never printed",
          "Events on: 2 of 5 (off: backup_failed, ip_banned) ·" in text and "Bad Key" not in text,
          text)


# ══ F. the Backups page ══════════════════════════════════════════════════════════════════════
_JS33 = r"""
const fs = require('fs'), vm = require('vm');
class El {
  constructor(){ this.children = []; this.attrs = {}; this._t = ''; this.disabled = false; }
  set textContent(v){ this.children = []; this._t = String(v); }
  get textContent(){ return this._t + this.children.map(c => c.textContent).join(''); }
  appendChild(c){ this.children.push(c); return c; }
  setAttribute(k, v){ this.attrs[k] = String(v); }
}
const els = {};
const doc = {getElementById: id => (els[id] = els[id] || new El()),
             createElement: () => new El(), createTextNode: t => ({textContent: String(t)}),
             querySelectorAll: () => [], addEventListener: () => {}};
const ctx = {document: doc, window: {agoText: e => 'AGO(' + e + ')'}, console,
             fetch: () => new Promise(() => {}), setTimeout: () => 0, setInterval: () => 0,
             MOUNT: '', IS_LOCAL: false};
ctx.window.document = doc;
vm.createContext(ctx);
try { vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx); } catch (e) {}
const out = {loaded: typeof ctx.bkRenderFullStatus === 'function'};
function run(d){
  for (const k of ['fb-now', 'fb-status', 'fb-auto-status']) els[k] = new El();
  ctx.bkRenderFullStatus(d, d.full || {});
  if (typeof ctx.bkRenderAutoStatus === 'function') ctx.bkRenderAutoStatus(d);
  const value = n => (els[n].children.find(c => c.attrs && 'data-no-i18n' in c.attrs) || {}).textContent;
  return {manual: els['fb-status'].textContent, auto: els['fb-auto-status'].textContent,
          manual_value: value('fb-status'), auto_value: value('fb-auto-status'),
          auto_values: els['fb-auto-status'].children
            .filter(c => c.attrs && 'data-no-i18n' in c.attrs).map(c => c.textContent),
          disabled: els['fb-now'].disabled};
}
if (out.loaded) {
  out.reassured = run({full: {last: 1000, summary: '4 server(s) backed up'}, scheduled: {at: 5, ok: true}});
  out.never = run({full: {last: 0}, scheduled: {at: 7, ok: true}});
  out.none = run({full: {last: 0}, scheduled: null});
  out.failed = run({full: {last: 0}, scheduled: {at: 9, ok: false}});
  out.running = run({full: {last: 1000}, full_running: true, scheduled: null});
  out.partial = run({full: {last: 0}, scheduled: {at: 9, ok: false, ok_at: 4}});
}
console.log(JSON.stringify(out));
"""


def _f_node():
    node = _shutil33.which("node")
    if not node:
        return None
    js = os.path.join(_ROOT33, "static", "js", "remote_manage_backups.js")
    r = _sp33.run([node, "-", js], input=_JS33, capture_output=True, text=True,  # nosec B603
                  timeout=60, check=False)
    try:
        return _json33.loads((r.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-400:]}


def _f_js_source():
    src = open(os.path.join(_ROOT33, "static", "js", "remote_manage_backups.js"),
               encoding="utf-8").read()
    check("backups page (no node): the manual status names its button and the schedule has its "
          "own line", all(("'“Back up game servers now” has never been run.'" in src,
                           "function bkRenderAutoStatus(d)" in src, "'Never run'" not in src,
                           "'The newest attempt failed:'" in src)), "")


def _f_js():
    out = _f_node()
    if out is None:
        _f_js_source()
        return
    rs, nv = out.get("reassured") or {}, out.get("never") or {}
    check("backups page: a manual run yesterday does not read as the schedule's status — the "
          "schedule's line shows the newest SCHEDULED backup", all((
              rs.get("manual") == "Last “Back up game servers now”: AGO(1000) — 4 server(s) backed up",
              rs.get("auto") == "Last automatic backup: AGO(5)")), repr(out))
    check("backups page: a button never pressed says so, naming the button, beside a schedule that "
          "has run", all((nv.get("manual") == "“Back up game servers now” has never been run.",
                          nv.get("auto") == "Last automatic backup: AGO(7)")), repr(nv))
    check("backups page: no scheduled backup yet, a failed one, and a running backup are each said",
          all(((out.get("none") or {}).get("auto") == "No automatic backup has run yet.",
               (out.get("failed") or {}).get("auto") == "Last automatic backup failed: AGO(9)",
               (out.get("running") or {}).get("manual") == "A backup is running now…",
               (out.get("running") or {}).get("disabled") is True)), repr(out))
    check("backups page: the per-request part of each line (an age, a summary naming servers) is "
          "kept out of the translator", (rs.get("manual_value"), rs.get("auto_value")) == (
              "AGO(1000) — 4 server(s) backed up", "AGO(5)"), repr(rs))
    pt = out.get("partial") or {}
    check("backups page: when the newest automatic backup failed and an older one worked, the one "
          "that worked is said first, then the failed attempt (one failing host no longer hides "
          "the rest)", (pt.get("auto"), pt.get("auto_values")) == (
              "Last automatic backup: AGO(4) · The newest attempt failed: AGO(9)",
              ["AGO(4)", "AGO(9)"]), repr(pt))


def _f_template():
    src = open(os.path.join(_ROOT33, "templates", "remote_manage.html"), encoding="utf-8").read()
    i_now, i_auto, i_disk = (src.index('id="fb-now"'), src.index('id="fb-auto-enabled"'),
                             src.index('id="fb-disk"'))
    check("backups page: the manual status sits with its button, and the Automatic-backups row "
          "holds the schedule's own status", all((
              src.count('id="fb-status"') == 1, i_now < src.index('id="fb-status"') < i_auto,
              'id="fb-auto-status"' in src[i_auto:i_disk], 'id="fb-status"' not in src[i_auto:i_disk])),
          src[i_now:i_now + 400])


def _f_route():
    t_ok, t_fail = int(_t33.time()) - 2 * _DAY33, int(_t33.time()) - 3600

    def _naive(ts):
        return _dt33.datetime.fromtimestamp(ts, _dt33.timezone.utc).replace(tzinfo=None)
    with _APP33.app_context():
        db.session.add_all([
            AuditLog(username="system", action="scheduled_backup", success=True,
                     target="p33-route-ok", timestamp=_naive(t_ok)),
            AuditLog(username="system", action="scheduled_backup", success=False,
                     target="p33-route-fail", timestamp=_naive(t_fail))])
        db.session.commit()
    want = {"at": t_fail, "ok": False}
    _p33(_auth33, "current_user", NS(is_authenticated=True, is_superadmin=True))
    _p33(_pb33, "list_game_backups", lambda remote, short: [])
    _p33(_pb33, "backup_disk_info", lambda remote, short: {"free": 1, "total": 2})
    _p33(_bk33, "BACKUP_DIR", _pl33.Path(os.path.join(_T33, "panel-backups")))
    if "api_panel_backups" not in _APP33.view_functions:
        _pb33._register_backup_overview(_APP33)
    got = _APP33.test_client().get("/api/panel/backups").get_json() or {}
    sched = got.get("scheduled") or {}
    eq("backups page: the payload carries the newest scheduled backup from the audit log",
       {k: sched.get(k) for k in want}, want)
    eq("backups page: ...and, when that one failed, the newest that worked (ok_at)",
       sched.get("ok_at"), t_ok)


# ══ G. paramiko: an exec request the remote never answers ═════════════════════════════════════
class _Sshd33(_pk33.ServerInterface):
    """A paramiko server that answers every exec ("ok", rc 0), or answers none of them (wedged)."""

    def __init__(self, wedged):
        self.wedged, self.release, self.execs = wedged, _th33.Event(), []

    def get_allowed_auths(self, username):  # pylint: disable=unused-argument
        return "publickey"

    def check_auth_publickey(self, username, key):  # pylint: disable=unused-argument
        return _pk33.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):  # pylint: disable=unused-argument
        return (_pk33.OPEN_SUCCEEDED if kind == "session"
                else _pk33.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_exec_request(self, channel, command):
        self.execs.append(command)
        if self.wedged:
            self.release.wait(120)      # holds the reply: the request is never answered
            return False
        _th33.Thread(target=_g_reply, args=(channel,), daemon=True).start()
        return True


def _g_reply(channel):
    _t33.sleep(0.05)
    try:
        channel.sendall(b"ok\n")
        channel.send_exit_status(0)
        channel.close()
    except Exception:  # nosec B110 - the client may already have gone; nothing to report
        pass


def _g_serve(wedged):
    """(client, teardown): a connected SSHClient whose server is `wedged` or answering."""
    host_key, user_key = _pk33.ECDSAKey.generate(), _pk33.ECDSAKey.generate()
    iface, lsock, held = _Sshd33(wedged), _socket33.socket(), []
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    def _accept():
        conn, _addr = lsock.accept()
        t = _pk33.Transport(conn)
        t.add_server_key(host_key)
        held.append(t)
        t.start_server(server=iface)
    _th33.Thread(target=_accept, daemon=True).start()
    port = lsock.getsockname()[1]
    client = _pk33.SSHClient()
    client.get_host_keys().add("[127.0.0.1]:%d" % port, host_key.get_name(), host_key)
    client.connect("127.0.0.1", port=port, username="p33", pkey=user_key, look_for_keys=False,
                   allow_agent=False, timeout=10)
    return client, (iface, lsock, held)


def _g_teardown(client, held):
    iface, lsock, transports = held
    iface.release.set()
    tr = client.get_transport()
    for ch in list(getattr(tr, "_channels", {}).values() if tr else []):
        try:
            ch.close()                  # wakes a wait the old exec_command left blocked
        except Exception:  # nosec B110 - teardown of a throwaway connection
            pass
    client.close()
    for t in transports:
        t.close()
    lsock.close()
    # Transport.close() returns before its thread has seen the socket close (paramiko stops
    # joining once the packetizer is closed), so wait for each, or its read outlives the part.
    for t in transports + ([tr] if tr is not None else []):
        _join33(t, 10)


def _join33(thread, limit):
    """thread.join(limit), never raising.

    Under eventlet a join that times out RAISES eventlet's Timeout, a BaseException, which ended the
    whole suite instead of failing the check that was waiting (it is how the unbounded exec showed
    up the first time this part was mutation-tested).
    """
    try:
        thread.join(limit)
    except BaseException:  # noqa: BLE001 - the caller reads is_alive() and reports it
        pass


def _g_call(fn, limit):
    """Run fn() in a thread; (finished, result or exception, seconds)."""
    box, t0 = {}, _t33.monotonic()

    def _run():
        try:
            box["r"] = fn()
        except Exception as e:  # noqa: BLE001 - returned to the check
            box["r"] = e
    th = _th33.Thread(target=_run, daemon=True)
    th.start()
    _join33(th, limit)
    return not th.is_alive(), box.get("r"), _t33.monotonic() - t0, th


_G_REMOTE33 = NS(id=0, name="p33-ssh", host="127.0.0.1", port=22, username="p33",
                 auth_method="key", sudo_enabled=False, is_local=False)


def _g_run_command(wedged):
    client, held = _g_serve(wedged)
    _p33(_core33, "get_connection", lambda server, **k: client)
    got = (False, None, 0.0, None)
    try:
        got = _g_call(lambda: _core33.run_command(_G_REMOTE33, "echo ok", timeout=30), 20)
    finally:
        _g_teardown(client, held)
        if got[3] is not None:
            _join33(got[3], 10)
        _restore_one33(_core33, "get_connection")
    return got[:3]


def _g_sweep(rid):
    sid = _new33("p33-wedged", "wedgedserver", rid)
    _only33(sid)
    _entry33(sid, last=int(_t33.time() - 8 * _DAY33))
    with _APP33.app_context():
        h = db.session.get(RemoteServer, rid)
        h.auth_method = "key"
        db.session.commit()
    client, held = _g_serve(True)
    _p33(_core33, "get_connection", lambda server, **k: client)
    _p33(_sh33, "run_game_backup", _game33.run_game_backup)     # the real one, end to end
    got = (False, None, 0.0, None)
    try:
        got = _g_call(lambda: _sh33._run_due_game_backups(_APP33), 60)
    finally:
        _g_teardown(client, held)
        if got[3] is not None:
            _join33(got[3], 20)
        _restore_one33(_sh33, "run_game_backup")
        _restore_one33(_core33, "get_connection")
    return got[:3] + (list(held[0].execs),)


def _g_stream(fn):
    """next() of a download stream against a wedged server: (finished, result or exception, s)."""
    client, held = _g_serve(True)
    _p33(_core33, "get_connection", lambda server, **k: client)
    got = (False, None, 0.0, None)
    try:
        got = _g_call(lambda: next(fn()), 20)
    finally:
        _g_teardown(client, held)
        if got[3] is not None:
            _join33(got[3], 10)
        _restore_one33(_core33, "get_connection")
    return got[:3]


def _g_streams():
    _p33(_core33, "STREAM_IDLE_TIMEOUT", 1)
    try:
        backup = _g_stream(lambda: _cron33.stream_game_backup(_G_REMOTE33, "p33server",
                                                               "p33.tar.gz", 1024))
        browse = _g_stream(lambda: _files33._stream_paramiko(_G_REMOTE33, "cat", "x", 1024))
    finally:
        _restore_one33(_core33, "STREAM_IDLE_TIMEOUT")
    check("paramiko exec: the backup download and the file download are bounded the same way "
          "against a remote that never answers the exec request", all((
              backup[0], isinstance(backup[1], Exception), browse[0],
              isinstance(browse[1], Exception))), repr((backup, browse)))


def _g_paramiko(rid):
    _p33(_core33, "_DRAIN_IDLE_FLOOR", 1)
    ok = _g_run_command(False)
    stuck = _g_run_command(True)
    sweep = _g_sweep(rid)
    check("paramiko exec: a remote that answers still runs the command (control)",
          ok[0] and ok[1] == ("ok", "", 0), repr(ok))
    check("paramiko exec: a remote that never answers the exec request is given up on within the "
          "bound, as a ConnectionError", all((stuck[0], isinstance(stuck[1], ConnectionError),
                                              stuck[2] < 15)), repr(stuck))
    check("paramiko exec: a scheduled sweep against such a host ends, and frees the global backup "
          "lock", sweep[0] and not _sh33._full_backup_lock.locked() and len(sweep[3]) >= 1,
          repr(sweep))
    rows = _audits33("scheduled_backup", "p33-wedged")
    check("paramiko exec: ...and the failed backup is on the record and alerted, not silently "
          "skipped", all((len(rows) == 1, rows and "backup error (ConnectionError)" in rows[0].detail,
                          len(_notes33("p33-wedged")) == 1)), repr((rows, _notes33("p33-wedged"))))


def _g_pool_drop():
    """A host that left an exec unanswered: the NEXT command must not get the same wedged client."""
    wedged, held_w = _g_serve(True)
    good, held_g = _g_serve(False)
    key = _core33._conn_key(_G_REMOTE33.username, _G_REMOTE33.host, _G_REMOTE33.port)
    prev = _core33._connections.get(key)
    _core33._connections[key] = wedged
    _p33(_core33, "_open_client", lambda server: good)     # the reconnect, to the answering server
    first = second = (False, None, 0.0, None)
    try:
        first = _g_call(lambda: _core33.run_command(_G_REMOTE33, "echo ok", timeout=30), 20)
        second = _g_call(lambda: _core33.run_command(_G_REMOTE33, "echo ok", timeout=30), 20)
    finally:
        with _core33._conn_lock:
            _core33._connections.pop(key, None)
            if prev is not None:
                _core33._connections[key] = prev
            _core33._remote_conn_keys.pop(_G_REMOTE33.id, None)
        _restore_one33(_core33, "_open_client")
        wedged_alive = bool(wedged.get_transport() and wedged.get_transport().is_active())
        for client, held in ((wedged, held_w), (good, held_g)):
            _g_teardown(client, held)
        for got in (first, second):
            if got[3] is not None:
                _join33(got[3], 10)
    check("paramiko exec: a host that left an exec unanswered has its pooled connection closed and "
          "dropped, so the next command opens a new one instead of waiting the whole bound again",
          all((isinstance(first[1], ConnectionError), second[0], second[1] == ("ok", "", 0),
               not wedged_alive)), repr((first[:3], second[:3], wedged_alive)))


# ══ H. the panel's own daily backup ══════════════════════════════════════════════════════════
def _h_claim_leak():
    bdir = os.path.join(_T33, "claim-backups")
    _p33(_bk33, "BACKUP_DIR", _pl33.Path(bdir))
    _p33(_bk33, "tempfile", NS(mkdtemp=_raise33(OSError(28, "No space left on device"))))
    try:
        got = _bk33.create_backup("daily")
    except Exception as e:  # noqa: BLE001 - the unfixed code raises; the check below says so
        got = "raised %s" % type(e).__name__
    finally:
        _restore_one33(_bk33, "tempfile")
    left = sorted(os.listdir(bdir)) if os.path.isdir(bdir) else []
    _restore_one33(_bk33, "BACKUP_DIR")
    check("panel backup: a temp dir that cannot be made fails the backup and leaves no empty "
          "archive behind (an empty one read as today's daily, so none was taken for 23 h)",
          isinstance(got, tuple) and got[0] is False and left == [], repr((got, left)))


# ══ run ══════════════════════════════════════════════════════════════════════════════════════
def _run33():
    rid = _setup33()
    for fn, args in ((_a_ticker, ()), (_b_overdue, (rid,)), (_b_not_yet, (rid,)),
                     (_b_refused_write, (rid,)), (_b_reenabled, (rid,)),
                     (_b_report_not_a_backup, (rid,)), (_b_queue, (rid,)), (_c_clocks, (rid,)),
                     (_c_requeue, (rid,)), (_c_clock_write_fails, (rid,)), (_d_raises, (rid,)),
                     (_d_queued_only, (rid,)), (_d_audit_fails, (rid,)), (_d_replaced, (rid,)),
                     (_e_section, (rid,)), (_e_gates, ()), (_e_events, ()), (_f_js, ()),
                     (_f_template, ()), (_f_route, ()), (_g_paramiko, (rid,)), (_g_pool_drop, ()),
                     (_g_streams, ()), (_h_claim_leak, ())):
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001 - a harness failure fails by name, not the suite
            import traceback as _tb33
            check("part33: %s ran to the end" % fn.__name__, False,
                  "raised %s: %s @ %s" % (type(e).__name__, e, _tb33.format_exc()[-700:]))


try:
    _run33()
finally:
    _restore33()
    _restart33()
    _ps33._game_backup_status.update(_GBS33_SNAP)
    _hb = _rs33._GROUPS.setdefault("heartbeat", {})
    _lf = _rs33._GROUPS.setdefault("loopfail", {})
    for _grp, _val in ((_hb, _HB33[0]), (_lf, _HB33[1])):
        if _val is None:
            _grp.pop("backup-ticker", None)
        else:
            _grp["backup-ticker"] = _val
    _APP33.logger.removeHandler(_LOGS33)
    try:
        with _APP33.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110 - best-effort cleanup of a throwaway database
        pass
    if _CFG33_SNAPSHOT is None:
        if _cfg33.CONFIG_FILE.exists():
            _cfg33.CONFIG_FILE.unlink()
    else:
        _cfg33.CONFIG_FILE.write_bytes(_CFG33_SNAPSHOT)
    _shutil33.rmtree(_T33, ignore_errors=True)
