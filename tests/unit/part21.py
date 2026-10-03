"""Part 21 of the unit suite: the debug report's diagnostics, root-owned pieces, updates and data.

Builder B2's half of the report rework (panel/ops/debug_report/{_src_db,diagnostics,root_pieces,
updates,data}.py) and the system_ops readers it fixed on the way: the Diagnostics card's checks
(R8-R14, R57), the privileged-call counters (R25), the CI gate's record (R31), and the panel-host
fail2ban and UFW readers that answered an unread state as a reassuring one (R42).

HOW IT RUNS. Everything it changes is put back in the finally at the bottom (_restore21). It reads
and writes only its own temp dir: the database, the root-owned directory, the self-update log and
the backups directory are all pointed there. Nothing here runs sudo, ssh, or a command on this
machine other than git in the checkout (read-only) and sqlite on the temp files. A route is driven
through part12's app and admin client.
"""
import json as _json21
import os
import pathlib as _pl21
import re as _re21
import shutil as _sh21
import sqlite3 as _sq21
import subprocess as _sp21  # nosec B404 - the suite's stubs; no command is run through it
import tempfile as _tf21
import threading as _th21
import time as _t21
import urllib.error as _ue21
import urllib.request as _ur21
from types import SimpleNamespace as NS

from flask import Flask as _Flask21

from unit.part01 import check, eq
from panel.core import config as _cfg21
from panel.core import runtime_stats as _rs21
from panel.db import models as _m21
from panel.db.models import RemoteServer, db
from panel.ops import backup as _bk21
from panel.ops import system_ops as _so21
from panel.ops.debug_report import _src_db as _db21
from panel.ops.debug_report import _src_systemd as _sd21
from panel.ops.debug_report import data as _data21
from panel.ops.debug_report import diagnostics as _diag21
from panel.ops.debug_report import root_pieces as _rp21
from panel.ops.debug_report import updates as _upd21
from panel.ops.debug_report._base import Ctx as _Ctx21
from panel.ops.ssh_manager import _core as _core21
from panel.security import auth as _auth21
from panel.security import privileged as _priv21

_ROOT21 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_T21 = _tf21.mkdtemp(prefix="lgsm-unit-p21-")
_saved21 = []


def _p21(owner, name, value):
    """Replace owner.name for this part; _restore21 puts every one back, newest first."""
    _saved21.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _restore21():
    while _saved21:
        owner, name, value = _saved21.pop()
        setattr(owner, name, value)


class _Over21:
    """A module stand-in: the named attributes replaced, everything else the real module's."""

    def __init__(self, real, **over):
        self._real = real
        self.__dict__.update(over)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _raiser(exc):
    def _f(*_a, **_k):
        raise exc
    return _f


def _garbage(path, n=9000):
    with open(path, "wb") as fh:
        fh.write(b"this is not a database " * (n // 23))
    return path


def _good_db(path):
    con = _sq21.connect(path)
    con.execute("CREATE TABLE t (x INTEGER)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    return path


def _fresh_integrity():
    _db21._cache.update(key=None, at=0.0, res=None)


def _call21(fn, *args):
    """fn(*args), or the exception it raised as a string -- so a check FAILS BY NAME on a raise."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - returned for the check to see
        return "raised %s" % type(exc).__name__


def _join21(thread):
    """Wait up to 10 s for `thread`, never raising.

    Under eventlet a join that times out RAISES (eventlet's Timeout, a BaseException), which would
    end the whole suite instead of failing one check.
    """
    try:
        thread.join(10)
    except BaseException:  # noqa: BLE001 - the check after this reports the thread did not finish
        pass


def _lv(pair, level, *subs, absent=()):
    """Whether a (level, text) answer has `level`, holds every one of `subs` and none of `absent`."""
    text = (pair or ("", ""))[1] or ""
    return all([(pair or ("",))[0] == level] + [s in text for s in subs]
               + [s not in text for s in absent])


def _privileged_delta(before, after):
    return {k: after[k] - before.get(k, 0) for k in after
            if isinstance(after[k], int) and after[k] != before.get(k, 0)}


# ══ A. _src_db: one read-only integrity check, off the hub, bounded (R12, R57, R58) ═════════════
def _a_integrity_states():
    good = _good_db(os.path.join(_T21, "good.db"))
    bad = _garbage(os.path.join(_T21, "bad.db"))
    states = {}
    for label, path in (("good", good), ("absent", os.path.join(_T21, "absent.db")),
                        ("garbage", bad), ("dir", _T21)):
        _p21(_cfg21, "DB_PATH", _pl21.Path(path))
        _fresh_integrity()
        r = _db21.integrity()
        states[label] = (r["state"], r["backup"])
    _sh21.copy(good, bad + ".backup")
    _fresh_integrity()
    _p21(_cfg21, "DB_PATH", _pl21.Path(bad))
    states["garbage+good backup"] = (_db21.integrity()["state"], _db21.integrity()["backup"])
    _garbage(bad + ".backup")
    _fresh_integrity()
    states["garbage+bad backup"] = (_db21.integrity()["state"], _db21.integrity()["backup"])
    os.remove(bad + ".backup")
    eq("_src_db.integrity: ok / ok when absent / damaged with no backup / not checked when it cannot "
       "be opened / the backup checked only when the main file is damaged",
       states, {"good": ("ok", None), "absent": ("ok", None), "garbage": ("damaged", "missing"),
                "dir": ("not_checked", None), "garbage+good backup": ("damaged", "ok"),
                "garbage+bad backup": ("damaged", "damaged")})
    # The same answers as the self-heal's own check (models._db_quick_check), so the two cannot drift.
    agree = []
    for path in (good, bad, os.path.join(_T21, "absent.db")):
        _p21(_cfg21, "DB_PATH", _pl21.Path(path))
        _fresh_integrity()
        agree.append((_m21._db_quick_check(path), _db21.integrity()["state"]))
    eq("_src_db.integrity: ...answers as models._db_quick_check does on the same files",
       agree, [(True, "ok"), (False, "damaged"), (True, "ok")])


def _a_integrity_read_only():
    # A read-write connection to a file whose header is not SQLite's deletes the -wal beside it
    # when it closes; the -wal holds committed transactions the self-heal moves aside to keep.
    bad = _garbage(os.path.join(_T21, "ro.db"))
    with open(bad + "-wal", "wb") as fh:
        fh.write(b"\x37\x7f\x06\x82" + b"\0" * 60)
    _p21(_cfg21, "DB_PATH", _pl21.Path(bad))
    _fresh_integrity()
    _db21.integrity()
    check("_src_db.integrity: a damaged file's -wal is still there after the check (read-only)",
          os.path.exists(bad + "-wal"), "the check deleted the -wal")


def _a_integrity_off_hub_and_cached():
    calls = []
    real = _auth21.run_off_hub

    def _rec(fn, *args):
        calls.append(fn.__name__)
        return real(fn, *args)
    _p21(_auth21, "run_off_hub", _rec)
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "good.db")))
    _fresh_integrity()
    first = _db21.integrity()
    second = _db21.integrity()
    eq("_src_db.integrity: the sqlite work goes through auth.run_off_hub (tpool under eventlet), "
       "and a second check within the minute reuses the first",
       (calls, first["state"], second["state"]), (["_integrity_job"], "ok", "ok"))
    _db21._cache["at"] = _t21.monotonic() - 3600
    _db21.integrity()
    eq("_src_db.integrity: ...and a stale result is read again", calls,
       ["_integrity_job", "_integrity_job"])


def _a_run_ro():
    good = os.path.join(_T21, "good.db")
    _p21(_cfg21, "DB_PATH", _pl21.Path(good))
    got = _db21.run_ro({"n": ("SELECT COUNT(*) FROM t", ()), "bad": ("SELECT nope FROM t", ()),
                        "w": ("INSERT INTO t VALUES (2)", ())})
    eq("_src_db.run_ro: rows per query, an error by class, and a write is refused (mode=ro)",
       got, {"n": [(1,)], "bad": "error:OperationalError", "w": "error:OperationalError"})
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "nothere.db")))
    eq("_src_db.run_ro: no database file is an error for every query, never an empty answer",
       _db21.run_ro({"a": ("SELECT 1", ()), "b": ("SELECT 2", ())}),
       {"a": "error:FileNotFoundError", "b": "error:FileNotFoundError"})


def _a_run_ro_interrupted():
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "good.db")))
    slow = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 300000000) "
            "SELECT COUNT(*) FROM c", ())
    ended = {}
    real = _db21._run_ro_job

    def _job(path, queries, holder):
        out = real(path, queries, holder)
        ended.update(at=_t21.monotonic(), res=out.get("slow"))
        return out
    _p21(_db21, "_run_ro_job", _job)
    t0 = _t21.monotonic()
    got = _db21.run_ro({"slow": slow}, timeout=1)
    took = _t21.monotonic() - t0
    while "at" not in ended and _t21.monotonic() - t0 < 90:
        _t21.sleep(0.2)
    job_s = ended.get("at", t0 + 999) - t0
    check("_src_db.run_ro: past its timeout the statement is INTERRUPTED -- the answer is a Timeout "
          "in about the time asked, and the worker's statement ended then, not when it finished",
          got == {"slow": "error:Timeout"} and took < 5 and job_s < 5
          and isinstance(ended.get("res"), _sq21.OperationalError),
          repr((got, round(took, 2), round(job_s, 2), ended.get("res"))))


# ══ B. panel_diagnostics (R8-R14, R57) ═══════════════════════════════════════════════════════════
def _unit(scope="system", **props):
    base = {"UnitFileState": "enabled", "ActiveState": "active", "SubState": "running",
            "MainPID": str(os.getpid()), "WorkingDirectory": _so21.PANEL_DIR}
    base.update(props)
    return {"scope": scope, "props": base, "error": None}


def _b_service():
    _p21(_so21, "_USER_UNIT", os.path.join(_T21, "no-user.service"))
    _p21(_so21, "_SYSTEM_UNIT", os.path.join(_T21, "no-system.service"))
    _p21(_so21, "_linger_on", lambda: False)
    got = {
        "unread": _so21._diag_service({"scope": None, "props": {}, "error": "unreadable"}),
        "ok": _so21._diag_service(_unit()),
        "linger": _so21._diag_service(_unit("user")),
        "elsewhere": _so21._diag_service(_unit(WorkingDirectory="/home/alice/old-panel")),
        "disabled": _so21._diag_service(_unit(UnitFileState="disabled")),
        "notme": _so21._diag_service(_unit(MainPID="1")),
    }
    check("diagnostics Service: systemd that cannot be read is a warning saying so, never 'ok'",
          _lv(got["unread"], "warn", "systemd state unreadable"), repr(got["unread"]))
    check("diagnostics Service: an enabled, running system unit that is this process is ok",
          _lv(got["ok"], "ok", "MainPID is this process: yes"), repr(got["ok"]))
    check("diagnostics Service: a user unit with linger OFF warns that it does not start at boot",
          _lv(got["linger"], "warn", "linger is OFF"), repr(got["linger"]))
    check("diagnostics Service: a unit whose WorkingDirectory is not this checkout warns, without "
          "printing the directory",
          _lv(got["elsewhere"], "warn", "not this checkout", absent=("alice",)), repr(got["elsewhere"]))
    check("diagnostics Service: a disabled unit, and a MainPID that is not this process, warn",
          all([_lv(got["disabled"], "warn", "does not start at boot"),
               _lv(got["notme"], "warn", "MainPID is not this process")]),
          repr((got["disabled"], got["notme"])))
    for p in (_so21._USER_UNIT, _so21._SYSTEM_UNIT):
        open(p, "w").close()
    both = _so21._diag_service(_unit())
    check("diagnostics Service: a per-user AND a system unit both present warns of two installs",
          _lv(both, "warn", "BOTH", absent=(_T21,)), repr(both))


def _b_stub_quiet_diag():
    """Stub the reads panel_diagnostics makes that are not under test here.

    data/ is pointed at a temp dir: the checkout's own data/ is never read.
    """
    ddir = os.path.join(_T21, "diagdata")
    os.makedirs(ddir, exist_ok=True)
    _p21(_cfg21, "DATA_DIR", _pl21.Path(ddir))
    _p21(_so21, "panel_integrity", lambda force=False: {"git": True, "verified": True, "clean": True,
                                                        "current_sha": "abc1234"})
    _p21(_so21, "_git", lambda args, timeout=45: ("H app.py", "", 0))
    _p21(_so21, "unattended_upgrades_status", lambda: {"enabled": True, "detail": "on"})
    _p21(_so21, "_helper_present", lambda: False)
    _p21(_core21, "helper_on_disk", lambda: False)


def _b_shared_reads():
    _b_stub_quiet_diag()
    calls = {"unit": 0, "db": 0}

    def _us(timeout=5):
        calls["unit"] += 1
        return _unit()

    def _ig(timeout=20):
        calls["db"] += 1
        return {"state": "ok", "backup": None, "took": 0.01}
    _p21(_sd21, "unit_show", _us)
    _p21(_db21, "integrity", _ig)
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "good.db")))
    ctx = _Ctx21()
    res = _diag21.section_diagnostics(ctx)
    _diag21.shared_unit(ctx)
    _diag21.shared_integrity(ctx)
    eq("diagnostics section: ONE systemctl show and ONE integrity check per report, shared through "
       "the memo with every other section", calls, {"unit": 1, "db": 1})
    order = {"fail": 0, "warn": 1, "ok": 2}
    levels = [_re21.match(r"- \[(\w+)\]", ln).group(1) for ln in res.lines]
    check("diagnostics section: its lines are the public summary, worst first",
          res.summary_lines == res.lines and len(set(levels)) > 1
          and levels == sorted(levels, key=lambda s: order.get(s, 3)), repr(res.lines))
    _p21(_db21, "integrity", _raiser(AssertionError("integrity was read again")))
    d = _so21.panel_diagnostics(db_check={"state": "damaged", "backup": "missing"}, unit=_unit())
    lv = {c["name"]: (c["level"], c["detail"]) for c in d["checks"]}
    eq("diagnostics: a result passed in is used, not read again (one check per report)",
       lv.get("Database integrity"), ("fail", _so21._DB_DAMAGED_TEXT[None]))


def _b_no_paths_in_summary():
    _b_stub_quiet_diag()
    data = os.path.join(_T21, "datafile")
    open(data, "w").close()                 # a FILE where data/ should be: not writable as a dir
    _p21(_cfg21, "DATA_DIR", _pl21.Path(data))
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "good.db")))
    _p21(_sd21, "unit_show", lambda timeout=5: _unit(WorkingDirectory=os.path.join(_T21, "x")))
    _p21(_db21, "integrity", lambda timeout=20: {"state": "not_checked", "backup": None,
                                                 "detail_class": "OperationalError"})
    res = _diag21.section_diagnostics(_Ctx21())
    text = "\n".join(res.summary_lines)
    dd = [ln for ln in res.lines if "Data directory" in ln]
    check("diagnostics: data/ that is not writable names its owner as a role and its mode, not its "
          "path", dd and _re21.search(r"owner: (the panel account|root), mode 0[0-7]{3}", dd[0])
          and data not in dd[0], repr(dd))
    check("diagnostics: the public summary carries neither DATA_DIR, the temp dirs nor PANEL_DIR",
          data not in text and _T21 not in text and _so21.PANEL_DIR not in text, text)


def _probe_harness(first):
    """The helper check with `sudo -n` stubbed: (calls made, the answer to give next)."""
    _b_stub_quiet_diag()
    _p21(_so21, "_helper_present", lambda: True)
    _p21(_so21, "origin_category", lambda: "canonical-https")
    _p21(_so21, "_tracked_branch", lambda: "main")
    _p21(_so21, "_is_system_service", lambda: True)
    sd = os.path.join(_T21, "sudoers.d")
    os.makedirs(sd, exist_ok=True)
    for n in ("90-cloud-init-users", "linuxgsm-panel", "panel-extra", "zz-alice", "x.conf"):
        open(os.path.join(sd, n), "w").close()
    _p21(_so21, "_SUDOERS_D", sd)
    calls, answer = [], {"r": first}

    def _run(argv, **kw):
        calls.append((list(argv), kw))
        if isinstance(answer["r"], Exception):
            raise answer["r"]
        return answer["r"]
    _p21(_so21, "subprocess", _Over21(_sp21, run=_run))
    _p21(_so21, "os", _Over21(os, geteuid=lambda: 1000))
    _so21._HELPER_PROBE.update(at=0.0, res=None)
    return calls, answer


def _b_helper_probe():
    calls, answer = _probe_harness(_sp21.CompletedProcess([], 1, "", "sudo: a password is required\n"))
    refused = _so21._diag_privileged_helper()
    argv, kw = calls[0] if calls else ([], {})
    eq("helper check: it runs `sudo -n <helper> --list-verbs`, as every real call is shaped",
       argv, ["sudo", "-n", _priv21.HELPER_PATH, "--list-verbs"])
    check("helper check: ...no shell, stdin closed, its own session, and a timeout of 10 s or less",
          all([kw.get("shell") is False, kw.get("stdin") == _sp21.DEVNULL,
               kw.get("start_new_session") is True, 0 < (kw.get("timeout") or 99) <= 10]), repr(kw))
    check("helper check: sudo refusing the helper is a FAILURE naming the refusal as a class and "
          "the sudoers.d files that sort after the grant, by count when not a known name",
          _lv(refused, "fail", "a password is required", "2 other file(s)",
              absent=("alice", "panel-extra")), repr(refused))
    answer["r"] = _sp21.CompletedProcess([], 0, "\n".join(v + "\t1" for v in _priv21.verbs()), "")
    cached = _so21._diag_privileged_helper()
    check("helper check: the probe is cached (a refused `sudo -n` is logged every time it runs)",
          all([len(calls) == 1, cached == refused]), repr((len(calls), cached)))
    _so21._HELPER_PROBE["at"] = 0.0
    ok = _so21._diag_privileged_helper()
    check("helper check: ...and asked again once the cache is stale; a current table is ok",
          all([len(calls) == 2, _lv(ok, "ok", "Installed and current")]), repr(ok))


def _b_helper_probe_2():
    _calls, answer = _probe_harness(
        _sp21.CompletedProcess([], 1, "", "sudo: alice is not in the sudoers file.\n"))
    named = _so21._diag_privileged_helper()
    check("helper check: a refusal that names the account is reduced to its class",
          _lv(named, "fail", "not in the sudoers file", absent=("alice",)), repr(named))
    _p21(_so21, "origin_category", lambda: "fork")
    withheld = _so21._diag_privileged_helper()
    _p21(_so21, "_is_system_service", lambda: False)
    per_user = _so21._diag_privileged_helper()
    check("helper check: the remedy is worded by install model -- a system install with a reorder, "
          "an untrusted origin as withheld by design, a per-user install as re-run as its account",
          all([_lv(named, "fail", "reorder the rule"),
               _lv(withheld, "fail", "withholds its pieces", absent=("reorder",)),
               _lv(per_user, "fail", "per-user install", "panel's own account",
                   absent=("withholds",))]), repr((named, withheld, per_user)))
    _so21._HELPER_PROBE.update(at=0.0, res=None)
    answer["r"] = _sp21.TimeoutExpired("sudo", 10)
    stall = _so21._diag_privileged_helper()
    check("helper check: sudo that does not answer is a stall (warn), NOT a refusal",
          _lv(stall, "warn", "not a refusal"), repr(stall))
    _p21(_so21, "os", _Over21(os, geteuid=lambda: 0))
    eq("helper check: as root the helper is run directly, without sudo",
       _so21._helper_probe_argv(), [_priv21.HELPER_PATH, "--list-verbs"])


def _b_helper_absent():
    _b_stub_quiet_diag()
    ran = []
    _p21(_so21, "subprocess", _Over21(_sp21, run=lambda *a, **k: ran.append(a)))
    _p21(_core21, "helper_on_disk", lambda: True)
    late = _so21._diag_privileged_helper()
    _p21(_core21, "helper_on_disk", lambda: False)
    gone = _so21._diag_privileged_helper()
    check("helper check: no helper in use is not probed; one placed after the panel started says "
          "restart the panel", not ran and late[0] == "warn" and "Restart the panel" in late[1]
          and gone[1].startswith("Not installed"), repr((ran, late, gone)))
    empty = os.path.join(_T21, "sudoers-empty")
    os.makedirs(empty)
    _p21(_so21, "_SUDOERS_D", empty)
    no_grant = _so21._sudoers_after_grant()
    _p21(_so21, "_SUDOERS_D", os.path.join(_T21, "no-such-dir"))
    unread = _so21._sudoers_after_grant()
    check("helper check: no grant file, and an unreadable sudoers.d, are each said as such",
          "no /etc/sudoers.d/linuxgsm-panel grant" in no_grant and "not readable" in unread,
          repr((no_grant, unread)))


def _b_file_integrity():
    _p21(_so21, "panel_integrity", lambda force=False: {"git": True, "verified": True, "clean": True,
                                                        "current_sha": "abc1234"})
    out = {"v": ("H app.py\nS tools/hidden.py\nh lib/assumed.py\n", "", 0)}
    _p21(_so21, "_git", lambda args, timeout=45: out["v"] if args[:1] == ["ls-files"] else ("", "", 0))
    hidden = _so21._diag_file_integrity()
    out["v"] = ("", "fatal", 128)
    unread = _so21._diag_file_integrity()
    out["v"] = ("\n".join("S p%02d.py" % i for i in range(30)), "", 0)
    capped = _so21._diag_file_integrity()
    check("file integrity: a path hidden from git (skip-worktree, assume-unchanged) is named and "
          "counted -- `git diff` cannot see it", hidden[0] == "warn"
          and "skip-worktree 1, assume-unchanged 1): tools/hidden.py, lib/assumed.py" in hidden[1],
          repr(hidden))
    check("file integrity: an ls-files that failed says it could not check, never a clean 0",
          unread[0] == "warn" and "Could not check for paths hidden from git" in unread[1], repr(unread))
    check("file integrity: at most 20 hidden paths are listed", "p19.py" in capped[1]
          and "p20.py" not in capped[1] and "30 tracked path(s)" in capped[1], capped[1][-120:])
    _p21(_so21, "panel_integrity", lambda force=False: {
        "git": True, "verified": True, "clean": False, "count": 2, "current_sha": "abc1234",
        "modified": [{"path": "panel/x.py", "status": "modified"},
                     {"path": "static/y.js", "status": "deleted"}]})
    out["v"] = ("H a", "", 0)
    eq("file integrity: differing files are NAMED, repo-relative, with their status",
       _so21._diag_file_integrity(),
       ("fail", "2 panel file(s) differ from the installed version: panel/x.py (modified), "
                "static/y.js (deleted)."))


def _b_integrity_during_update():
    seen = []
    _p21(_so21, "_is_git_checkout", lambda: True)
    _p21(_so21, "_git", lambda args, timeout=45: (seen.append(list(args)), ("abc1234", "", 0))[1])
    _p21(_so21, "_update_in_progress", lambda: True)
    during = _so21._compute_panel_integrity()
    seen_during = list(seen)
    _p21(_so21, "_update_in_progress", lambda: False)
    after = _so21._compute_panel_integrity()
    check("file integrity: NOT read while an update runs (git diff takes the index lock "
          "install.sh's reset needs); unverified, never clean",
          during["verified"] is False and "being installed" in during.get("message", "")
          and not any(a[:1] == ["diff"] for a in seen_during), repr((during, seen_during)))
    check("file integrity: ...and read again once it has finished (control)",
          after["verified"] is True and ["diff", "--name-status", "HEAD"] in seen, repr(seen))


def _b_tls():
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p21.example")])
    now = datetime.now(timezone.utc)
    pem = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
           .public_key(key.public_key()).serial_number(21)
           .not_valid_before(now - timedelta(days=60)).not_valid_after(now - timedelta(days=4))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    ddir = os.path.join(_T21, "tlsdata")
    os.makedirs(os.path.join(ddir, "ssl"))
    with open(os.path.join(ddir, "ssl", "cert.pem"), "wb") as fh:
        fh.write(pem)
    app = _Flask21("p21tls")
    got = {}
    for label, conf in (("failed", {"BOOT_TLS": False, "BOOT_TLS_ERROR": "SSLError"}),
                        ("leak", {"BOOT_TLS": False, "BOOT_TLS_ERROR": "/home/alice/x: boom"}),
                        ("off", {"BOOT_TLS": False, "BOOT_TLS_ERROR": None}),
                        ("on", {"BOOT_TLS": True, "BOOT_TLS_ERROR": None}), ("norec", {})):
        for k in ("BOOT_TLS", "BOOT_TLS_ERROR"):
            app.config.pop(k, None)
        app.config.update(conf)
        with app.app_context():
            got[label] = _so21._diag_tls(ddir)
    check("TLS: a TLS start that FAILED at boot is a failure, by exception class only",
          got["failed"][0] == "fail" and "TLS FAILED to start at boot (SSLError)" in got["failed"][1]
          and got["leak"][0] == "fail" and "alice" not in got["leak"][1], repr(got))
    check("TLS: an expired cert the panel does NOT serve is a leftover, never a warning",
          got["off"][0] == "ok" and "Not in use" in got["off"][1], repr(got["off"]))
    check("TLS: an expired cert the panel DOES serve is a failure; without a boot record it is "
          "'in use: unknown' and a warning, not a failure",
          got["on"][0] == "fail" and "Expired" in got["on"][1] and got["norec"][0] == "warn"
          and "In use: unknown" in got["norec"][1], repr((got["on"], got["norec"])))
    check("TLS: the certificate's subject is never printed", "p21.example" not in repr(got), "")


def _b_host_credentials():
    from cryptography.fernet import Fernet
    app = _Flask21("p21db")
    path = os.path.join(_T21, "creds.db")
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + path,
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    db.init_app(app)
    keyf = _pl21.Path(os.path.join(_T21, "cred_key"))
    keyf.write_bytes(Fernet.generate_key())
    _p21(_cfg21, "CRED_KEY_FILE", keyf)
    other = Fernet(Fernet.generate_key())
    with app.app_context():
        db.create_all()
        good = RemoteServer(name="p21-good", host="198.51.100.21", port=22, username="root",
                            auth_method="key", auth_credential="")
        bad = RemoteServer(name="p21-bad", host="198.51.100.22", port=22, username="root",
                           auth_method="password", auth_credential="")
        db.session.add_all([good, bad])
        db.session.commit()
        bad_id = bad.id
        foreign = "enc:v1:" + other.encrypt(b"secret-host.example").decode()
        db.session.execute(db.text("UPDATE remote_server SET host = :h, auth_credential = :h "
                                   "WHERE id = :i"), {"h": foreign, "i": bad_id})
        db.session.commit()
        broken = _so21._diag_host_credentials()
        keyf.unlink()
        missing = _so21._diag_host_credentials()
        created = keyf.exists()
        keyf.write_bytes(Fernet.generate_key())
        db.session.execute(db.text("DELETE FROM remote_server"))
        db.session.commit()
        db.session.add(RemoteServer(name="p21-ok", host="198.51.100.23", port=22, username="root",
                                    auth_method="key", auth_credential=""))
        db.session.commit()
        fine = _so21._diag_host_credentials()
        db.session.remove()
        db.engine.dispose()
    outside = _so21._diag_host_credentials()
    check("host credentials: a host whose fields this cred_key cannot decrypt FAILS, naming the "
          "host id and the columns, never a value",
          broken[0] == "fail" and ("host %d: host, auth_credential" % bad_id) in broken[1]
          and "secret-host" not in broken[1] and "198.51.100" not in broken[1], repr(broken))
    check("host credentials: with cred_key MISSING it fails without decrypting -- and no new key "
          "is minted over the lost one", missing[0] == "fail" and "MISSING" in missing[1]
          and created is False, repr((missing, created)))
    check("host credentials: every field decrypting is ok, with counts (control)",
          fine[0] == "ok" and fine[1].startswith("Every stored host field decrypts ("), repr(fine))
    check("host credentials: a table that cannot be read is a warning by class, never 'decrypts'",
          outside[0] == "warn" and "Could not read the hosts table (" in outside[1], repr(outside))


# ══ C. R42: the panel host's fail2ban and UFW readers ════════════════════════════════════════════
def _verb_by(table):
    def _rv(verb, args=(), timeout=30, merge_stderr=True):
        v = table.get(verb, ("", "", 0))
        return v(list(args)) if callable(v) else v
    return _rv


def _c_fail2ban():
    _p21(_so21, "_run", lambda cmd, timeout=30, sudo=False, text=True: ("yes", "", 0))
    stopped = ("", "Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban "
                   "running?", 255)
    _p21(_so21, "_run_verb", _verb_by({"f2b-status": stopped, "f2b-status-jail": stopped}))
    ov_stopped, st_stopped = _so21.fail2ban_overview(), _so21.panel_fail2ban_status()
    _p21(_so21, "_run_verb", _verb_by({"f2b-status": ("Status\n|- nothing useful", "", 0),
                                       "f2b-status-jail": ("", "Sorry but the jail 'linuxgsm-panel' "
                                                               "does not exist", 255)}))
    ov_nolist, st_nojail = _so21.fail2ban_overview(), _so21.panel_fail2ban_status()
    jd = ("Status for the jail: sshd\n|- Total failed: 4\n`- Actions\n   |- Currently banned: 1\n"
          "   |- Total banned: 2\n   `- Banned IP list: 203.0.113.9\n")
    _p21(_so21, "_run_verb", _verb_by({"f2b-status": ("`- Jail list:\tsshd", "", 0),
                                       "f2b-status-jail": (jd, "", 0)}))
    ov_ok = _so21.fail2ban_overview()
    eq("fail2ban overview: a stopped fail2ban is UNREADABLE, not 'no jails found'",
       ov_stopped, {"installed": True, "jails": [], "unreadable": True})
    eq("fail2ban overview: an answer with no 'Jail list:' line is unreadable too",
       ov_nolist, {"installed": True, "jails": [], "unreadable": True})
    check("fail2ban overview: ...while one that answered lists its jails (control)",
          "unreadable" not in ov_ok and [j["jail"] for j in ov_ok["jails"]] == ["sshd"], repr(ov_ok))
    eq("panel_fail2ban_status: a stopped fail2ban is flagged unreadable; installed/enabled keep "
       "their meaning", st_stopped, {"installed": True, "enabled": False, "banned": 0,
                                     "unreadable": True})
    eq("panel_fail2ban_status: a jail that does not exist is a reading, not unreadable",
       st_nojail, {"installed": True, "enabled": False, "banned": 0})


def _c_callers_keep_meaning():
    rewrote = []
    _p21(_so21, "panel_fail2ban_status", lambda: {"installed": True, "enabled": False, "banned": 0,
                                                  "unreadable": True})
    _p21(_so21, "configure_panel_fail2ban", lambda *a, **k: (rewrote.append(a), (True, "ok"))[1])
    _p21(_so21, "_panel_login_proxied", lambda: False)
    _so21.ensure_panel_fail2ban("/x/auth.log", 5000, [])
    check("panel_fail2ban_status's callers: an unreadable jail still sends the self-heal down the "
          "rewrite-and-reload path (enabled=False kept its meaning)", len(rewrote) == 1, repr(rewrote))
    unbanned = []
    _p21(_so21, "_fail2ban_jails", lambda: None)
    _p21(_so21, "_run_verb", lambda verb, args=(), **k: (unbanned.append(verb), ("", "", 0))[1])
    res = _so21.fail2ban_unban("sshd", "203.0.113.9")
    check("fail2ban_unban: jails that could not be read refuse the unban and say why",
          res[0] is False and "Couldn't read fail2ban's jails" in res[1] and not unbanned,
          repr((res, unbanned)))


def _c_ufw():
    _p21(_so21, "_run_verb", _verb_by({"ufw-status": ("ERROR: problem running iptables", "", 1)}))
    broken = _so21.ufw_status()
    _p21(_so21, "_run_verb", _verb_by({"ufw-status": ("sudo: ufw: command not found", "", 1)}))
    absent = _so21.ufw_status()
    eq("ufw_status: a failed read is flagged unreadable (enabled stays False for its callers); a "
       "missing ufw is not_installed, not unreadable",
       (broken, absent),
       ({"enabled": False, "status_text": "inactive", "rules": [], "unreadable": True},
        {"enabled": False, "status_text": "not_installed", "rules": []}))


def _c_route():
    # part12 has already run by now (it is earlier in _PARTS): importing it runs nothing again.
    from unit.part12 import P9_ADMIN, _p9_client, _p9_json
    _p21(_so21, "_run", lambda cmd, timeout=30, sudo=False, text=True: ("yes", "", 0))
    _p21(_so21, "_run_verb", _verb_by({"f2b-status": ("", "Failed to access socket path", 255)}))
    d = _p9_json(_p9_client(P9_ADMIN).get("/api/panel/security/bans"))
    eq("Security card route: /api/panel/security/bans says UNREADABLE for a stopped fail2ban, which "
       "the card renders as 'Could not read fail2ban'", d,
       {"installed": True, "jails": [], "unreadable": True})


# ══ D. R25: privileged-call counters and the fresh helper check ═════════════════════════════════
def _d_counters():
    before = _rs21.snapshot("privileged")
    answers = {"ufw-status": ("helper", ("", "sudo: a password is required", 1)),
               "apt-upgrade": ("helper", ("", "Command timed out", -1)),
               "f2b-status": ("helper", ("", "panel-helper: unknown verb 'f2b-status'", 2)),
               "journal": ("root", ("lines", "", 0)),
               "reboot": ("", ("", "invalid argument", -1))}
    _p21(_so21, "_run_verb_once", lambda verb, args, timeout, merge: answers[verb])
    rets = [_so21._run_verb(v) for v in answers]
    after = _rs21.snapshot("privileged")
    delta = _privileged_delta(before, after)
    eq("privileged counters: _run_verb counts each call by verb, outcome and path -- refused, "
       "timed out, 'unknown verb', ok -- and not a refused argument",
       delta, {"ufw-status|refused": 1, "apt-upgrade|timeout": 1, "f2b-status|unknown_verb": 1,
               "journal|ok": 1, "via|helper": 3, "via|root": 1})
    eq("privileged counters: ...and every answer is passed back unchanged",
       rets, [a[1] for a in answers.values()])
    check("privileged counters: the latest refusal is kept as the verb's name, never stderr",
          isinstance(after.get("last|refused"), tuple) and after["last|refused"][1] == "ufw-status"
          and "password" not in repr(after), repr(after.get("last|refused")))
    _p21(_rs21, "bump", _raiser(RuntimeError("stats broke")))
    survived = _call21(_so21._run_verb, "journal")
    check("privileged counters: instrumentation that raises cannot change the call's answer",
          survived == ("lines", "", 0), repr(survived))


def _d_core_counters():
    before = _rs21.snapshot("privileged")
    _p21(_core21, "helper_present", lambda recheck=False: True)
    _p21(_core21, "_exec_local_argv", lambda argv, timeout=30, stdin_text=None: ("out", "", 0))
    _core21.run_privileged(NS(is_local=True), "ufw-status", ["verbose"])
    _p21(_core21, "helper_present", lambda recheck=False: False)
    _p21(_core21, "_run_local", lambda cmd, timeout=30, sudo=False, **k: ("", "boom", 1))
    _core21.run_privileged(NS(is_local=True), "ufw-status", ["verbose"])
    delta = _privileged_delta(before, _rs21.snapshot("privileged"))
    eq("privileged counters: ssh_manager's local run_privileged counts the helper and the "
       "pre-helper shell paths too", delta,
       {"ufw-status|ok": 1, "ufw-status|failed": 1, "via|helper": 1, "via|shell": 1})
    check("privileged counters: note_privileged on a malformed answer does not raise",
          _call21(_core21.note_privileged, "x", "helper", None) is None, "")


def _d_fresh_helper():
    helper = os.path.join(_T21, "panel-helper")
    with open(helper, "w") as fh:
        fh.write("#!/bin/sh\n")
    # An executable stand-in at a scratch path: the fixture the helper's stat must find.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(helper, 0o755)                       # nosec B103 - a fixture the stat must find
    _p21(_priv21, "HELPER_PATH", helper)
    _core21._HELPER_STATE["present"] = False
    on_disk = _core21.helper_on_disk()
    check("helper fresh check: a stat that finds the helper never writes the cached state the "
          "process is using", all([on_disk is True, _core21._HELPER_STATE["present"] is False]),
          repr((on_disk, _core21._HELPER_STATE)))
    _p21(_core21, "helper_on_disk", lambda: True)
    _p21(_so21, "_HELPER_STATE", {"present": False})
    res = _rp21.section_root_pieces(_Ctx21())
    line = next((ln for ln in res.lines if ln.startswith("- **Helper**")), "")
    check("root pieces: a helper on disk that this process cached as absent says restart the panel",
          "on disk now: yes" in line and "this process is using it: NO" in line
          and "restart the panel" in line
          and any(f["text"].startswith("helper placed after") for f in res.findings), line)


# ══ E. R27, R28, R29: root-owned pieces, origin, host tools ═════════════════════════════════════
def _e_root_pieces():
    rdir = os.path.join(_T21, "rootdir")
    os.makedirs(rdir)
    with open(os.path.join(rdir, "install.sh"), "wb") as fh:
        fh.write(b"#!/bin/bash\necho same\n")
    with open(os.path.join(rdir, "db_maintenance.py"), "wb") as fh:
        fh.write(b"old version\n")
    os.makedirs(os.path.join(rdir, "panel-helper"))          # a directory: cannot be read as a file
    same = _so21._git_blob_id(os.path.join(rdir, "install.sh"))
    _p21(_so21, "_root_dir", lambda: rdir)
    _p21(_so21, "_head_blobs", lambda: {"install.sh": same, "tools/panel-helper": "1" * 40,
                                        "db_maintenance.py": "2" * 40})
    states = {k: v["state"] for k, v in _so21.root_piece_state(force=True).items()}
    eq("root pieces: the installed copy = HEAD's / DIFFERS / unreadable, never 'differs' for one "
       "it could not read", states,
       {"install.sh": "same", "db_maintenance.py": "differs", "panel-helper": "unreadable"})
    os.rmdir(os.path.join(rdir, "panel-helper"))
    check("root pieces: a missing piece is 'missing'",
          _so21.root_piece_state(force=True)["panel-helper"]["state"] == "missing", "")
    hello = os.path.join(_T21, "hello.txt")
    with open(hello, "wb") as fh:
        fh.write(b"hello\n")
    # `printf 'hello\n' | git hash-object --stdin` -- git's documented example object id.
    eq("root pieces: the blob id is computed in Python exactly as git computes it",
       _so21._git_blob_id(hello), "ce013625030ba8dba906f756967f9e9ca394464a")


def _e_head_blobs_parse():
    seen = []
    _p21(_so21, "_git", lambda args, timeout=45: (seen.append(list(args)), (
        "100755 blob %s\tdb_maintenance.py\n100755 blob %s\tinstall.sh\n"
        "100755 blob %s\ttools/panel-helper" % ("1" * 40, "2" * 40, "3" * 40), "", 0))[1])
    got = _so21._head_blobs()
    eq("root pieces: ONE git ls-tree names HEAD's blob for all three pieces",
       (got, len(seen), seen[0][:3] if seen else None),
       ({"db_maintenance.py": "1" * 40, "install.sh": "2" * 40, "tools/panel-helper": "3" * 40},
        1, ["ls-tree", "HEAD", "--"]))
    _p21(_so21, "_git", lambda args, timeout=45: ("", "fatal", 128))
    rdir = os.path.join(_T21, "rootdir-unknown")
    os.makedirs(rdir)
    with open(os.path.join(rdir, "install.sh"), "wb") as fh:
        fh.write(b"#!/bin/bash\n")
    _p21(_so21, "_root_dir", lambda: rdir)
    states = {k: v["state"] for k, v in _so21.root_piece_state(force=True).items()}
    check("root pieces: a failed ls-tree is 'not compared', never 'differs'",
          all([_so21._head_blobs() is None, states.get("install.sh") == "unknown"]), repr(states))


def _e_older_commit_and_conf():
    seen = []
    _p21(_so21, "_git", lambda args, timeout=45: (seen.append(list(args)), ("abc1234", "", 0))[1])
    _p21(_so21, "_update_in_progress", lambda: True)
    during = _rp21._older_commit("install.sh", "a" * 40)
    _p21(_so21, "_update_in_progress", lambda: False)
    found = _rp21._older_commit("install.sh", "a" * 40)
    check("root pieces: the commit a stale piece matches is looked up with -n 2 and a timeout, and "
          "NOT while an update runs", during == "not looked up while an update runs"
          and found == "matches abc1234" and len(seen) == 1 and "-n" in seen[0]
          and "--find-object=" + "a" * 40 in seen[0], repr((during, found, seen)))
    rdir = os.path.join(_T21, "confdir")
    os.makedirs(rdir)
    _p21(_so21, "_root_dir", lambda: rdir)
    with open(os.path.join(rdir, "panel.conf"), "w") as fh:
        fh.write("db_path=/home/alice/x.db\npanel_dir=/home/alice/elsewhere\n")
    other = _rp21._panel_conf_line()
    with open(os.path.join(rdir, "panel.conf"), "w") as fh:
        fh.write("panel_dir=%s\n" % _so21.PANEL_DIR)
    mine = _rp21._panel_conf_line()
    check("root pieces: panel.conf is printed as 'is this checkout: yes/no', never its values",
          other == "panel_dir is this checkout: NO" and mine == "panel_dir is this checkout: yes",
          repr((other, mine)))
    with open(os.path.join(rdir, ".source-floor"), "w") as fh:
        fh.write("b" * 40 + "\n")
    _p21(_so21, "_git", lambda args, timeout=45: ("", "", 0 if args[0] == "merge-base" else 1))
    os.makedirs(os.path.join(rdir, ".source.git"))
    with open(os.path.join(rdir, ".source.git", "packed-refs"), "w") as fh:
        fh.write("# pack-refs with: peeled\n%s refs/root-src/tip\n" % ("c" * 40))
    eq("root pieces: root's source floor (HEAD contains it) and fetched tip, from a packed ref",
       (_rp21._floor_line(), _rp21._tip_line()), ("bbbbbbb (HEAD contains it: yes)", "ccccccc"))
    for svc, helper, want in ((True, True, "panel-self-update"), (True, False, "sudo systemd-run"),
                              (False, True, "systemd-run --user")):
        _p21(_so21, "_is_system_service", lambda s=svc: s)
        _p21(_so21, "_helper_present", lambda h=helper: h)
        check("root pieces: the self-update launcher line follows _launch_installer's predicate "
              "(system=%s, helper=%s)" % (svc, helper), want in _rp21._launcher_line(),
              _rp21._launcher_line())


def _e_origin():
    url = {"v": ""}
    _p21(_so21, "_git", lambda args, timeout=45: (url["v"], "", 0 if url["v"] else 128))
    got = {}
    for u in ("https://github.com/FMSMITH91/linuxgsm-panel.git",
              "https://github.com/FMSMITH91/linuxgsm-panel",
              "git@github.com:FMSMITH91/linuxgsm-panel.git",
              "https://alice:tok3n@github.com/alice/linuxgsm-panel.git", ""):
        url["v"] = u
        got[u] = _so21.origin_category()
    eq("origin: judged as install.sh judges it -- exact https forms trusted, ssh untrusted, a fork "
       "a fork, unreadable untrusted",
       list(got.values()), ["canonical-https", "canonical-https", "canonical-other-form", "fork",
                            "unreadable"])
    url["v"] = "https://alice:tok3n@github.com/alice/linuxgsm-panel.git"
    res = _rp21.Result()
    _rp21._origin_lines(res)
    check("origin: the section prints a category, never the URL, its token or its owner",
          "tok3n" not in repr(res.lines) and "alice" not in repr(res.lines)
          and "not the canonical repository" in res.lines[0], repr(res.lines))
    sh = open(os.path.join(_ROOT21, "install.sh"), encoding="utf-8").read()
    check("origin: _TRUSTED_ORIGIN is install.sh's REPO_URL",
          ('REPO_URL="%s"' % _so21._TRUSTED_ORIGIN) in sh, _so21._TRUSTED_ORIGIN)


def _e_tools():
    asked = []

    def _which(tool, path=None):
        asked.append((tool, path))
        return None if tool in ("wget", "gamedig") else "/usr/bin/" + tool
    _p21(_rp21, "shutil", _Over21(_sh21, which=_which))
    # The service's own PATH, minimal (a systemd unit's can lack /usr/sbin and /usr/local/bin).
    _p21(_rp21, "os", _Over21(os, environ={"PATH": "/opt/p21-only"}))
    gd = os.path.join(_T21, "gamedig", "current", "node_modules", ".bin")
    os.makedirs(gd)
    open(os.path.join(gd, "gamedig"), "w").close()
    _p21(_priv21, "GAMEDIG_DIR", os.path.join(_T21, "gamedig"))
    res = _rp21.Result()
    _rp21._tools_lines(res)
    path = next((p for t, p in asked if t == "ufw"), "") or ""
    check("host tools: a tool on none of the paths is ✗ and a finding; the gamedig TREE counts",
          "wget ✗" in res.lines[0] and "gamedig ✓" in res.lines[0]
          and any("wget" in f["text"] for f in res.findings), repr(res.lines))
    check("host tools: looked up on the helper's and cron's PATH too, not only the service's",
          "/usr/sbin" in path.split(os.pathsep) and "/usr/local/bin" in path.split(os.pathsep), path)


# ══ F. Updates: R30-R35 ══════════════════════════════════════════════════════════════════════════
def _f_cache():
    asked = []
    _p21(_so21, "panel_update_status", lambda force=False: asked.append(force))
    _p21(_so21, "_update_cache", {"ts": 0.0, "data": None})
    res = _upd21.Result()
    _upd21._cache_lines(res)
    cold = list(res.lines)
    _p21(_so21, "_update_cache", {"ts": _t21.time() - 40 * 60, "data": {
        "update_available": False, "branch": "main", "current_sha": "abc1234",
        "remote_sha": "def5678", "behind": 3, "behind_tip": 3, "ci_state": "failing",
        "target_sha": "d" * 40, "docs_only": False, "repo_url": "https://github.com/someowner/fork",
        "fetched": True}})
    res = _upd21.Result()
    _upd21._cache_lines(res)
    text = "\n".join(res.lines)
    check("updates: an empty cache says it was not computed since start, never 'up to date'",
          cold and "not computed since the panel started" in cold[0] and "up to date" not in cold[0],
          repr(cold))
    check("updates: the cached status is printed (behind, ci_state, target) with no check run, and "
          "an hour-old one is flagged as a possibly stuck update thread",
          not asked and "ci_state=failing" in text and "behind 3" in text and "may be stuck" in text
          and any("35 minutes" in f["text"] for f in res.findings), text)
    check("updates: repo_url (a fork owner's name) is left out", "someowner" not in text, text)
    done = []
    with _so21._update_lock:
        t = _th21.Thread(target=lambda: done.append(_upd21._cache_lines(_upd21.Result())))
        t.start()
        _join21(t)
    check("updates: reading the cache never waits on _update_lock (a check holds it across a fetch)",
          len(done) == 1, "blocked on the lock")


class _Resp21:
    def __init__(self, runs, headers):
        self._b = _json21.dumps({"check_runs": runs}).encode()
        self.headers = headers

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_REQ21 = [{"name": n, "status": "completed", "conclusion": "success"}
          for n in ("checks (ubuntu)", "coverage", "js coverage", "gamedig lockfile (x)",
                    "Analyze (python)", "Open code-scanning alerts")]


def _f_ci_record():
    _p21(_so21, "_repo_slug", lambda: "o/r")
    _p21(_so21, "_ci_suite_expected", lambda sha, runs: True)
    hdr = {"X-RateLimit-Remaining": "41", "X-RateLimit-Limit": "60",
           "X-RateLimit-Reset": "1790000000", "Authorization": "token SECRETTOKEN"}
    runs = {"v": [{"name": "checks (ubuntu)", "status": "completed", "conclusion": "failure"},
                  {"name": "coverage", "status": "in_progress", "conclusion": None}]}
    _p21(_ur21, "urlopen", lambda req, timeout=8: _Resp21(runs["v"], hdr))
    sha1 = "1" * 40
    st1 = _so21._remote_ci_state(sha1)
    runs["v"] = list(_REQ21)
    st_pass = _so21._remote_ci_state("2" * 40)
    runs["v"] = _REQ21[:-1]
    st_absent = _so21._remote_ci_state("3" * 40)
    snap = _rs21.snapshot("ci_walk")
    eq("CI gate: the decision is unchanged by the recording (pending / passing / pending on a "
       "required check absent)", (st1, st_pass, st_absent), ("pending", "passing", "pending"))
    e1 = (snap.get("1111111") or (0, {}))[1]
    e3 = (snap.get("3333333") or (0, {}))[1]
    check("CI gate: what held a commit is recorded -- failing, pending, and required-but-absent "
          "check names", all([e1.get("failing") == ["checks (ubuntu)"],
                              e1.get("pending") == ["coverage"],
                              e3.get("absent") == ["Open code-scanning alerts"]]), repr((e1, e3)))
    rate = (snap.get("ratelimit") or (0, {}))[1]
    check("CI gate: GitHub's X-RateLimit answer is recorded, and nothing else of the headers",
          all([rate.get("remaining") == 41, rate.get("limit") == 60, "SECRET" not in repr(snap)]),
          repr(rate))
    _p21(_rs21, "put", _raiser(RuntimeError("stats broke")))
    _p21(_ur21, "urlopen", lambda req, timeout=8: _Resp21(list(_REQ21), hdr))
    check("CI gate: recording that raises cannot change or break the answer",
          _call21(_so21._remote_ci_state, "5" * 40) == "passing", "")


def _f_ci_rate_limited():
    _p21(_so21, "_repo_slug", lambda: "o/r")

    def _http403(req, timeout=8):
        raise _ue21.HTTPError("u", 403, "rate limited", {"X-RateLimit-Remaining": "0",
                                                         "X-RateLimit-Limit": "60"}, None)
    _p21(_ur21, "urlopen", _http403)
    st403 = _so21._remote_ci_state("4" * 40)
    rate = (_rs21.snapshot("ci_walk").get("ratelimit") or (0, {}))[1]
    check("CI gate: a 403 is still 'pending', and its rate-limit answer is recorded",
          all([st403 == "pending", rate.get("code") == 403, rate.get("remaining") == 0]), repr(rate))
    res = _upd21.Result()
    _upd21._rate_lines(_rs21.snapshot("ci_walk"), res)
    check("CI gate: the report says 'pending' is the rate limit, not CI",
          all([res.lines, "the rate limit, not CI" in "".join(res.lines), res.findings]),
          repr(res.lines))


def _f_ci_no_deadlock():
    _p21(_so21, "_repo_slug", lambda: "o/r")
    _p21(_so21, "_ci_suite_expected", lambda sha, runs: True)
    _p21(_ur21, "urlopen", lambda req, timeout=8: _Resp21(list(_REQ21), {}))
    out = []
    with _so21._update_lock:      # the status computation holds it across the whole walk
        t = _th21.Thread(target=lambda: out.append(_so21._remote_ci_state("6" * 40)))
        t.start()
        _join21(t)
    eq("CI gate: recording inside the walk never takes _update_lock (it is held, non-reentrant)",
       out, ["passing"])


def _f_walk_recorded():
    c1, c2 = "a" * 40, "b" * 40

    def _git(args, timeout=45):
        a = list(args)
        if a[:1] == ["rev-parse"]:
            return ("aaaaaaa" if "--short" in a else c2, "", 0)
        if a[:2] == ["rev-list", "--first-parent"] and "--count" in a:
            return ("2", "", 0)
        if a[:2] == ["rev-list", "--first-parent"]:
            return ("%s\n%s" % (c1, c2), "", 0)
        return ("", "", 0)
    for name, val in (("_is_git_checkout", lambda: True), ("panel_version", lambda: "v1"),
                      ("_tracked_branch", lambda: "main"), ("_git", _git),
                      ("github_repo_url", lambda: "https://github.com/o/r"),
                      ("_remote_ci_state", lambda sha: {c1: "failing", c2: "passing"}[sha]),
                      ("_update_touches_runtime", lambda ref: False),
                      ("version_for_commit", lambda c="HEAD": "v2")):
        _p21(_so21, name, val)
    st = _so21._compute_update_status()
    walk = (_rs21.snapshot("ci_walk").get("walk") or (0, {}))[1]
    check("CI gate: the walk records which commits it looked at and which it offered",
          walk.get("commits") == ["aaaaaaa", "bbbbbbb"] and walk.get("offered") == "bbbbbbb"
          and st.get("target_sha") == c2, repr((walk, st.get("target_sha"))))


def _f_branch_and_checkout():
    conf = {"v": {}}
    _p21(_cfg21, "load_config", lambda: conf["v"])
    got = []
    for val in (None, "x..y", "feature-x", "main"):
        conf["v"] = {} if val is None else {"panel_branch": val}
        res = _upd21.Result()
        got.append(_upd21._branch_config_line(res))
    eq("updates: the tracked branch -- the default, an invalid value by its LENGTH only, an opt-in "
       "branch marked as not CI-gated",
       got, ["main (panel_branch unset, so the default)",
             "config value is invalid (4 characters), so main is used",
             "'feature-x' (opt-in test branch: updates are NOT CI-gated)", "main"])
    conf["v"] = {}
    _p21(_so21, "_update_in_progress", lambda: False)
    _p21(_so21, "_git", lambda args, timeout=45: ("", "fatal: not a git repository", 128))
    res = _upd21.Result()
    _upd21._checkout_lines(res)
    check("updates: a checkout git cannot read says '(git failed)', never 'clean'",
          "(git failed)" in "\n".join(res.lines) and "clean" not in "\n".join(res.lines),
          repr(res.lines))


def _f_run_outcome():
    now = _t21.time()
    cases = {
        "124": {"exit_code": 124, "lines": ["✓ Health check passed (HTTP 200)",
                                            "=== installer exit 124 (stopped after 30 minutes) ==="]},
        "done": {"exit_code": 0, "outcome": "done",
                 "lines": ["✓ Update complete: 2026.09.30 → 2026.10.01", "=== installer exit 0 ==="]},
        "bare": {"exit_code": 0, "outcome": "done", "lines": ["=== installer exit 0 ==="]},
        "died": {"exit_code": None, "lines": ["[3/6] Pulling"]},
    }
    got = {k: _upd21.run_outcome(v, now - (40 * 60 if k == "died" else 5), now=now)
           for k, v in cases.items()}
    got["live"] = _upd21.run_outcome(cases["died"], now - 5, now=now)
    check("last run: the EXIT STATUS comes first -- exit 124 after 'Health check passed' FAILED",
          _lv(got["124"], "fail", "FAILED — the installer was stopped after 30 minutes (exit 124)",
              "even though 'Health check passed'"), repr(got["124"]))
    check("last run: exit 0 ('done') is a success, with or without the marker, never 'unknown'",
          all([got["done"] == ("ok", "succeeded — Update complete: 2026.09.30 → 2026.10.01"),
               _lv(got["bare"], "ok", "succeeded"), "unknown" not in repr(got)]), repr(got))
    check("last run: no exit line in a log silent for 20 minutes is a run that DIED; a fresh one "
          "is still running", all([_lv(got["died"], "fail", "DIED — the log stopped at"),
                                   got["live"] == ("ok", "running (no exit line yet)")]),
          repr((got["died"], got["live"])))


# The test VPS's data/self-update.log of 2026-09-19 (the proof of #393), colour codes and all, the
# account and the database traceback shortened. Launched by a panel-helper from before #363, which
# wrote no "=== installer exit N ===" line; install.sh's own last line says it completed.
_HELPER_LOG21 = (
    "=== panel self-update ===\n"
    "\x1b[0;36m[1/6] Snapshotting current version + database → /home/panel/linuxgsm-panel/data/"
    ".backups/20260919-190410\x1b[0m\n"
    "\x1b[0;32m✓\x1b[0m Snapshot saved\n"
    "\x1b[1;33m[!]\x1b[0m Database maintenance reported a non-fatal issue (rc=1) — continuing.\n"
    "\x1b[0;36m[3/6] Fetching the new version…\x1b[0m\n"
    "  Updating to verified commit 18bafd3a14ad5225de94b79b9435a8881f2dab3f\n"
    "\x1b[0;32m✓\x1b[0m Code updated (0.10.0-alpha → 0.10.0-alpha)\n"
    "\x1b[0;36m[5/6] Starting the service…\x1b[0m\n"
    "\x1b[0;36m[6/6] Verifying the panel came back up…\x1b[0m\n"
    "\x1b[0;32m✓\x1b[0m Health check passed (HTTP 302) — now running version 0.10.0-alpha\n"
    "\n"
    "\x1b[0;32m✓\x1b[0m Update complete: 0.10.0-alpha → 0.10.0-alpha\n")


def _f_run_outcome_no_exit_line():
    """A log a helper from before the exit line wrote: install.sh's own last line decides."""
    log = os.path.join(_T21, "self-update-old-helper.log")
    with open(log, "w", encoding="utf-8") as fh:
        fh.write(_HELPER_LOG21)
    old = _t21.time() - 13 * 86400
    os.utime(log, (old, old))
    _p21(_so21, "_update_log_path", lambda: log)
    res = _upd21.Result()
    _, word = _upd21._last_run_lines(res, "canonical-https")
    text = "\n".join(res.lines)
    check("last run: a completed run whose launcher wrote no exit line (the test VPS's log of "
          "2026-09-19) is 'succeeded' by install.sh's own last line, not 'DIED mid-run' and no "
          "[fail]", all(("**Outcome**: succeeded — Update complete: 0.10.0-alpha → 0.10.0-alpha · "
                         "no exit line" in text, "DIED" not in text, word == "succeeded",
                         not res.findings)), repr((word, res.findings, res.lines)))
    stale = _t21.time() - 3600
    got = [_upd21.run_outcome({"exit_code": None, "lines": lines}, stale)
           for lines in (["✓ Already up to date (version 2026.10.1) — no snapshot taken"],
                         ["[!] Not updated: held at 1234567890, because the pin is unverified."],
                         ["✓ Update complete: a → b", "[ERROR] Something failed after it"],
                         ["[3/6] Fetching the new version…"])]
    check("last run: ...the no-op endings read the same way, and a log whose last word is an "
          "[ERROR], or a step, still DIED",
          [g[0] for g in got] == ["ok", "ok", "fail", "fail"]
          and got[0][1].startswith("nothing to install — Already up to date")
          and got[1][1].startswith("NOT UPDATED — Not updated: held")
          and all(g[1].startswith("DIED") for g in got[2:]), repr(got))


# The system_ops wrapper's log (a per-user install): its dated header, and install.sh's HTTPS hint
# after "Update complete". That wrapper has written the exit line since 2026-07-04, so a log of its
# with none was stopped after install.sh's ending, not launched by an old helper.
_WRAPPER_LOG21 = ["=== panel self-update Fri Oct  3 12:00:00 UTC 2026 ===",
                  "[5/6] Starting the service…", "[6/6] Verifying the panel came back up…",
                  "✓ Update complete: a → b",
                  "This panel now serves HTTPS on port 5000 (it served plain HTTP before this "
                  "update).",
                  "Set up Tailscale Serve or a domain for a trusted cert."]


def _f_run_outcome_wrapper_no_exit_line():
    """The outcome for a log with no exit line says only what the log shows."""
    level, text = _upd21.run_outcome({"exit_code": None, "lines": _WRAPPER_LOG21},
                                     _t21.time() - 3600)
    check("last run: a log with no exit line whose launcher is the wrapper (dated header) still "
          "reads succeeded by install.sh's ending line, with a line after it, and the outcome "
          "names no cause it never checked: not 'a helper from before the exit line wrote none', "
          "not 'install.sh's own last line'",
          level == "ok" and text.startswith("succeeded — Update complete: a → b · no exit line")
          and "a run stopped after install.sh's ending leaves none" in text
          and "existed wrote none" not in text and "own last line" not in text,
          repr((level, text)))


def _f_last_run_lines():
    log = os.path.join(_T21, "self-update.log")
    with open(log, "w") as fh:
        fh.write("=== panel self-update ===\n✓ Update complete: a → b\n=== installer exit 0 ===\n")
    os.utime(log, (1790000000, 1790000000))
    _p21(_so21, "_update_log_path", lambda: log)
    res = _upd21.Result()
    _upd21._last_run_lines(res, "canonical-https")
    first = res.lines[0] if res.lines else ""
    check("last run: dated from the log's mtime, with its exit status",
          all([first.startswith("- **Last run**: %s" % _t21.strftime(
              "%Y-%m-%d %H:%M UTC", _t21.gmtime(1790000000))), "exit 0" in first]), repr(res.lines))
    _p21(_so21, "_update_log_path", lambda: os.path.join(_T21, "no-such.log"))
    res = _upd21.Result()
    _upd21._last_run_lines(res, "canonical-https")
    first = res.lines[0] if res.lines else ""
    check("last run: no log says updates over SSH or deploy write none -- not 'no update was ever run'",
          all(["updates run over SSH or by deploy do not write one" in first,
               "has been run through the panel yet" not in first]), repr(res.lines))


def _f_history():
    path = os.path.join(_T21, "hist.db")
    con = _sq21.connect(path)
    con.executescript(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, user_id INT, username TEXT, action TEXT, "
        "target TEXT, detail TEXT, ip_address TEXT, timestamp DATETIME, success BOOLEAN);")
    con.executemany("INSERT INTO audit_log (user_id, username, action, target, detail, ip_address, "
                    "timestamp, success) VALUES (?, ?, ?, ?, ?, ?, datetime('now', ?), ?)",
                    [(None, "telegram:42 (bob)", "panel_self_update", "Panel Server",
                      "Update started — the panel is backing up", "203.0.113.5", "-2 hours", 1),
                     (7, "alice", "panel_switch_branch", "secret-branch", "my private plan",
                      "203.0.113.6", "-1 hours", 0)])
    con.commit()
    con.close()
    _p21(_cfg21, "DB_PATH", _pl21.Path(path))
    rows = _upd21._audit_history()
    text = repr(rows)
    check("history: the panel's own launches, actor as a category, detail only from the fixed set",
          "self-update · telegram · ok (started)" in text
          and "branch switch · web · REFUSED (detail withheld)" in text, text)
    check("history: never a username, target, free-text detail or address",
          not any(s in text for s in ("bob", "alice", "secret-branch", "private plan", "203.0.113")),
          text)
    t0 = 1790000000
    _p21(_so21, "_git", lambda args, timeout=45: (
        "abc1234\tHEAD@{%d}\treset: moving to secret-branch-name\n"
        "def5678\tHEAD@{%d}\tcommit: my private message" % (t0, t0 - 100), "", 0))
    reflog = _upd21._reflog_history()
    check("history: reflog entries as SHA plus action keyword only, never the subject",
          [r[1] for r in reflog] == ["HEAD reset → abc1234 (git reflog)",
                                     "HEAD commit → def5678 (git reflog)"]
          and "secret" not in repr(reflog) and "private" not in repr(reflog), repr(reflog))
    alone = _upd21._history_rows([], reflog)
    near = _upd21._history_rows([(t0 - 60, "self-update · web · ok (started)", True)], reflog)
    check("history: a HEAD reset with no panel launch near it is called an update made outside the "
          "panel; one right after a launch is not",
          "updated outside the panel" in alone[0][1] and "outside" not in near[0][1],
          repr((alone, near)))


def _f_installer_said():
    lines = ["[!] This checkout's git origin is 'https://alice:tok3n@github.com/alice/fork', not "
             "https://github.com/FMSMITH91/linuxgsm-panel.git.",
             "  noise line", "[ERROR] Couldn't fetch https://bob:pw@example.org/x",
             "     from 203.0.113.9 after 3 tries", "next ordinary line",
             "✓ sudo grant: narrow (panel-helper for root)", "  Keeping abc1234: on main"]
    said = _upd21.installer_said(lines, "fork")
    text = "\n".join(said)
    check("installer said: the origin warning is reduced to its category -- no URL, token or owner",
          said[0] == "[!] This checkout's git origin is not the repository install.sh trusts (fork)"
          and "tok3n" not in text and "alice" not in text, text)
    check("installer said: an [ERROR] keeps its continuation lines; URL userinfo and IPv4 are masked",
          "[ERROR] Couldn't fetch https://[userinfo]@example.org/x" in text
          and "from [ip] after 3 tries" in text and "bob:pw" not in text and "203.0.113" not in text,
          text)
    check("installer said: the grant and Keeping lines are kept; ordinary lines are not",
          "✓ sudo grant: narrow (panel-helper for root)" in text and "Keeping abc1234: on main" in text
          and "noise line" not in text and "next ordinary line" not in text, text)


# ══ G. Data: the database and the backups (R59-R62) ═════════════════════════════════════════════
def _g_app(name):
    app = _Flask21("p21" + name.split(".")[0])
    path = os.path.join(_T21, name)
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + path,
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        db.session.execute(db.text(
            "INSERT INTO audit_log (user_id, username, action, target, detail, ip_address, "
            "timestamp, success) VALUES (NULL, 'zed_user', 'login_failed', 'x', 'hunter2', "
            "'198.51.100.77', datetime('now', '-1 hours'), 0), (NULL, 'zed_user', 'bad action!', 'x', "
            "'', '', datetime('now', '-1 hours'), 0), (3, 'adm', 'panel_change_binding', "
            "'0.0.0.0:443', '', '198.51.100.78', datetime('now', '-2 hours'), 0)"))
        db.session.execute(db.text("INSERT INTO metric_sample (server_id, ts, cpu, ram_mb) VALUES "
                                   "(1, datetime('now', '-40 days'), 1, 1)"))
        db.session.execute(db.text("DROP INDEX ix_metric_sample_server_ts"))
        db.session.commit()
    return app, path


def _g_section(app):
    with app.app_context():
        res = _data21.section_database(_Ctx21())
        db.session.remove()
        db.engine.dispose()
    return res, "\n".join(res.lines)


def _g_database():
    app, path = _g_app("data.db")
    _p21(_cfg21, "DB_PATH", _pl21.Path(path))
    _p21(_cfg21, "load_config", lambda: {"audit_ip_retention_days": 90})
    open(path + ".corrupt-1700000000", "w").close()
    open(path + ".corrupt-1700000000-wal", "w").close()
    _p21(_db21, "integrity", lambda timeout=20: {"state": "damaged", "backup": "missing",
                                                 "detail": "Page 7: btreeInitPage() error 11",
                                                 "took": 0.12})
    res, text = _g_section(app)
    levels = [f["level"] for f in res.findings]
    check("database: a damaged file is DAMAGED (fail) with its first message, from the shared check",
          all(["**health**: DAMAGED: Page 7: btreeInitPage() error 11" in text, "fail" in levels]),
          text[:400])
    check("database: moved-aside copies are listed by basename (once, not their -wal), no rolling "
          "backup is a warning", all(["moved-aside copies**: 1 (data.db.corrupt-1700000000)" in text,
                                      "rolling backup**: none on disk" in text, _T21 not in text]),
          text)
    check("database: schema drift names a declared index that is missing",
          "missing declared indexes ix_metric_sample_server_ts" in text, text)
    check("database: metric_sample older than its retention is flagged (the prune has not run)",
          all(["**metric_sample** 1 rows · oldest 40.0 d (retention 14 d ✗)" in text,
               any("metric_sample is older" in f["text"] for f in res.findings)]), text)
    check("database: the audit digest prints action names only -- never a username, target, "
          "detail or address, and a malformed action name is dropped",
          all(["login_failed ×1" in text, "panel_change_binding" in text, "bad action" not in text]
              + [s not in text for s in ("zed_user", "hunter2", "198.51.100", "0.0.0.0:443")]), text)
    eq("database: the network-and-security SQL has one placeholder per action",
       _data21._NETSEC_SQL.count("?"), len(_data21._NETSEC_ACTIONS))


def _g_database_unread():
    app, path = _g_app("data2.db")
    _p21(_cfg21, "DB_PATH", _pl21.Path(path))
    _p21(_cfg21, "load_config", lambda: {"audit_ip_retention_days": 90})
    _p21(_db21, "integrity", lambda timeout=20: {"state": "not_checked", "backup": None,
                                                 "detail_class": "OperationalError", "took": 0.01})
    _p21(_db21, "run_ro", lambda queries, timeout=10: {k: "error:OperationalError" for k in queries})
    res, text = _g_section(app)
    levels = [f["level"] for f in res.findings]
    check("database: a check that could not run is NOT CHECKED (warn), and tables that could not "
          "be counted say so -- never 0 rows",
          all(["NOT CHECKED: could not be read (OperationalError)" in text,
               "**metric_sample**: could not count (OperationalError)" in text,
               " 0 rows" not in text, "warn" in levels, "fail" not in levels]), text)


def _g_backups():
    from cryptography.fernet import Fernet
    bdir = _pl21.Path(os.path.join(_T21, "backups"))
    _p21(_bk21, "BACKUP_DIR", bdir)
    # The section reads the game servers and the audit log too: never the checkout's own database.
    _p21(_cfg21, "DB_PATH", _pl21.Path(os.path.join(_T21, "absent-backups.db")))
    keyf = _pl21.Path(os.path.join(_T21, "bk_cred_key"))
    _p21(_cfg21, "CRED_KEY_FILE", keyf)
    foreign = "enc:v1:" + Fernet(Fernet.generate_key()).encrypt(b"passphrase-xyz").decode()
    conf = {"backup_enabled": True, "backup_passphrase": foreign,
            "full_backup_last": int(_t21.time()) - 4 * 86400,
            "full_backup_summary": "6 server(s) backed up, 1 failed — charlie: disk full"}
    _p21(_bk21, "load_config", lambda: conf)
    res = _data21.section_backups(_Ctx21())
    text = "\n".join(res.lines)
    check("backups: cred_key missing reads the passphrase as unreadable WITHOUT decrypting (no key "
          "is created), and data/backups is not created by listing it",
          "cred_key is missing" in text and not keyf.exists() and not bdir.exists(), text)
    check("backups: the full-backup result is COUNTS from its fixed prefix, never the server names",
          "6 backed up, 1 failed, 0 skipped" in text and "charlie" not in text
          and "disk full" not in text, text)
    keyf.write_bytes(Fernet.generate_key())
    os.makedirs(str(bdir))
    for n in ("panel-backup-20261001-030000-daily.tar.gz", "panel-backup-20261001-040000-manual"
              ".tar.gz.enc", "not-a-backup.txt"):
        open(os.path.join(str(bdir), n), "w").close()
    res = _data21.section_backups(_Ctx21())
    text = "\n".join(res.lines)
    check("backups: a passphrase this cred_key cannot decrypt is a FAILURE (every backup refused)",
          "CANNOT be decrypted" in text and any(f["level"] == "fail" for f in res.findings)
          and "passphrase-xyz" not in text, text)
    check("backups: the archives are counted by kind from their names",
          "**Archives**: 2 (1 daily, 1 manual)" in text, text)


def _g_snapshots():
    pd = os.path.join(_T21, "panel")
    root = os.path.join(pd, "data", ".backups")
    os.makedirs(os.path.join(root, "20261001-140200"))
    with open(os.path.join(root, "20261001-140200", "code.tgz"), "wb") as fh:
        fh.write(b"x" * 2048)
    outside = os.path.join(_T21, "outside")
    os.makedirs(outside)
    os.symlink(outside, os.path.join(root, "20261002-000000"))
    os.makedirs(os.path.join(root, "not-a-stamp"))
    _p21(_so21, "PANEL_DIR", pd)
    res = _data21.Result()
    _data21._snapshots_line(res)
    eq("backups: update snapshots -- STAMP-shaped directories only, a symlink not followed",
       res.lines, ["- **Update snapshots** (data/.backups): 1, newest 20261001-140200 (host time), "
                   "2 KB"])


def _run21():
    for fn in (_a_integrity_states, _a_integrity_read_only, _a_integrity_off_hub_and_cached,
               _a_run_ro, _a_run_ro_interrupted,
               _b_service, _b_shared_reads, _b_no_paths_in_summary, _b_helper_probe,
               _b_helper_probe_2,
               _b_helper_absent, _b_file_integrity, _b_integrity_during_update, _b_tls,
               _b_host_credentials,
               _c_fail2ban, _c_callers_keep_meaning, _c_ufw, _c_route,
               _d_counters, _d_core_counters, _d_fresh_helper,
               _e_root_pieces, _e_head_blobs_parse, _e_older_commit_and_conf, _e_origin, _e_tools,
               _f_cache, _f_ci_record, _f_ci_rate_limited, _f_ci_no_deadlock, _f_walk_recorded,
               _f_branch_and_checkout,
               _f_run_outcome, _f_run_outcome_no_exit_line, _f_run_outcome_wrapper_no_exit_line,
               _f_last_run_lines, _f_history, _f_installer_said,
               _g_database, _g_database_unread, _g_backups, _g_snapshots):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
            import traceback as _tb21
            check("part21: %s ran to the end" % fn.__name__, False,
                  "raised %s: %s @ %s" % (type(e).__name__, e, _tb21.format_exc()[-600:]))
        finally:
            _restore21()
            _fresh_integrity()
            _so21._HELPER_PROBE.update(at=0.0, res=None)
            _so21._root_pieces_cache.update(at=0.0, res=None)


_h_state21 = (dict(_so21._HELPER_STATE), dict(_core21._HELPER_STATE))
try:
    _run21()
finally:
    _restore21()
    _so21._HELPER_STATE.clear()
    _so21._HELPER_STATE.update(_h_state21[0])
    _core21._HELPER_STATE.clear()
    _core21._HELPER_STATE.update(_h_state21[1])
    _sh21.rmtree(_T21, ignore_errors=True)
