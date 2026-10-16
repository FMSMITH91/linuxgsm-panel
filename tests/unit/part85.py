"""Part 85 of the unit suite: the twelfth review's fixes by builder A.

Install, the test runner, core and the debug report. Held here, each against the code path the finding named:

* install.sh's update prunes old snapshots as root over data/.backups, which the panel user owns:
  a link at data/.backups (or at data/) must not have root delete stamp-named directories
  elsewhere.
* tools/run-tests.sh: the sequential mode deleted the checkout's own data/panel.db and its backup;
  a failed lane copy did not stop the run; nothing held the lanes to running every suite; and
  Ctrl-C left the lanes running.
* a data migration that works through the ORM recorded itself done when its commit then failed.
* a bracketed IPv6 peer went to ping (and to is_tailscale_ip) with its brackets on.
* the debug report's "Ways in" line: sshd's real ports, port ranges and lists, UFW's first match.
* a content account with a `.` in its name got an /etc/cron.d file Debian's cron never runs.

HOW IT RUNS. Shell functions are cut out of the real scripts and run under bash in throwaway
directories (never the checkout's data/); the migration on its own SQLite file through part18's
app; everything else on the module functions with stand-ins, undone in a finally.
"""
import atexit as _atexit85
import os
import shutil as _shutil85
import signal as _signal85
import sqlite3 as _sq85
import subprocess as _sp85  # nosec B404 - bash over the repo's own scripts, in throwaway dirs
import sys
import tempfile as _tf85
import time as _time85
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper, _root
from unit.part18 import _app18
from panel.db import models as _m85
from panel.db.models import RemoteServer as _RS85, db as _db85
from panel.ops import tailscale_integration as _ts85
from panel.ops.debug_report import network as _nw85
from panel.ops.ssh_manager import gmod as _gm85
from panel.security import privileged as _priv85

_TMP85 = _tf85.mkdtemp(prefix="p85-")
_atexit85.register(_shutil85.rmtree, _TMP85, True)


def _read85(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn85(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "exit 97\n"
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash85(script, cwd, timeout=60):
    """(rc, stdout + stderr) of `script` under bash in `cwd`."""
    r = _sp85.run(["bash", "-c", script],  # nosec B603 B607 - bash over this part's own script
                  cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


# ════════════════════════════════════════════════════════════════════════════════════════════
# 1. install.sh: the snapshot prune never follows a link at data/.backups or data/
# ════════════════════════════════════════════════════════════════════════════════════════════
_INS85 = _read85("install.sh")
_PRUNE85 = _fn85(_INS85, "_r22a_prune_snapshots")
_STAMPS85 = ["20260101-00000%d" % i for i in range(5)]


def _prune85(layout):
    """Names left in the outside directory and in the real .backups, after one prune.

    `layout` is "real" (data/.backups a real directory of five snapshots), "link" (data/.backups
    a link to a directory of five stamp-named directories that are not the panel's), or
    "datalink" (data/ itself a link to a directory holding such a .backups).
    """
    base = _tf85.mkdtemp(dir=_TMP85)
    panel, outside = os.path.join(base, "panel"), os.path.join(base, "outside")
    os.makedirs(os.path.join(panel, "data") if layout != "datalink" else panel)
    os.makedirs(outside)
    for s in _STAMPS85:
        os.makedirs(os.path.join(outside, ".backups" if layout == "datalink" else "", s))
        with open(os.path.join(outside, ".backups" if layout == "datalink" else "", s, "keep"), "w"):
            pass
    if layout == "real":
        os.rename(outside, os.path.join(panel, "data", ".backups"))
        os.makedirs(outside)
    elif layout == "link":
        os.symlink(outside, os.path.join(panel, "data", ".backups"))
    else:
        os.symlink(outside, os.path.join(panel, "data"))
    rc, out = _bash85('set -euo pipefail\nwarn() { echo "WARN $*"; }\nKEEP_BACKUPS=3\n'
                      'PANEL_DIR=%s\n%s_r22a_prune_snapshots\n' % (panel, _PRUNE85), base)
    real = os.path.join(panel, "data", ".backups")
    return (rc, sorted(os.listdir(os.path.join(outside, ".backups") if layout == "datalink"
                                  else outside)),
            sorted(os.listdir(real)) if layout == "real" else None, out)


_pr85 = {k: _prune85(k) for k in ("real", "link", "datalink")}
check("install.sh: the update's snapshot prune keeps the newest KEEP_BACKUPS in a real "
      "data/.backups and removes the older ones (control)",
      _pr85["real"][0] == 0 and _pr85["real"][2] == _STAMPS85[2:], repr(_pr85["real"]))
check("install.sh: ...and a data/.backups the panel user turned into a link has root delete "
      "nothing in the link's target (an operator's own stamp-named backups)",
      _pr85["link"][0] == 0 and _pr85["link"][1] == _STAMPS85 and "WARN" in _pr85["link"][3],
      repr(_pr85["link"]))
check("install.sh: ...nor a data/ that is itself a link", _pr85["datalink"][0] == 0
      and _pr85["datalink"][1] == _STAMPS85, repr(_pr85["datalink"]))
check("install.sh: the update path calls the prune (it is not left defined and unused)",
      "\n        _r22a_prune_snapshots\n" in _INS85
      and 'rm -rf -- "${_snaps[_i]}"' not in _INS85, "")

# ════════════════════════════════════════════════════════════════════════════════════════════
# 2. tools/run-tests.sh
# ════════════════════════════════════════════════════════════════════════════════════════════
_RT85 = _read85("tools", "run-tests.sh")
_RUN_SUITE85 = _fn85(_RT85, "run_suite")
_li85 = _RT85.find("\nlane_tree() {")
_LANES85 = (_RT85[_li85 + 1:_RT85.index("\n}\n", _RT85.index("\nrun_lanes() {")) + 3]
            if _li85 >= 0 else "exit 97\n")
_di85 = _RT85.find('\nif [[ "${RUN_TESTS_PARALLEL:-0}" = "1" ]]; then')
_DISPATCH85 = _RT85[_di85 + 1:_RT85.index("\nfi\n", _di85) + 4] if _di85 >= 0 else "exit 97\n"
_OK_SUITE85 = os.path.join(_TMP85, "ok_suite.py")
with open(_OK_SUITE85, "w", encoding="utf-8") as _fh85:
    _fh85.write("print('PASS  x')\nprint()\nprint('1 / 1 checks passed')\n")


def _checkout85():
    """A git checkout holding a developer's own data/panel.db and its backup."""
    d = _tf85.mkdtemp(dir=_TMP85)
    _sp85.run(["git", "init", "-q", d],  # nosec B603 B607 - git, a fixed argv
              check=True, capture_output=True, timeout=30)
    os.makedirs(os.path.join(d, "data"))
    for name, text in ((".gitignore", "data/\n"), ("a.txt", "a\n"),
                       ("data/panel.db", "MINE"), ("data/panel.db.backup", "MINE")):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    return d


def _run_tests85(parallel, dispatch=None):
    """(rc, output, the checkout's data/ afterwards) for one whole run over stand-in suites.

    The real run_suite, lane_tree, run_lanes and the mode dispatch; each DB-owning stand-in
    suite goes through run_suite, which clears data/ where it runs.
    """
    d = _checkout85()
    stubs = ("unit_suite() { echo '1 / 1 checks passed'; }\n"
             + "".join('%s() { run_suite %s "%s"; }\n' % (n, n, _OK_SUITE85)
                       for n in ("other_suites", "smoke_suite", "rbac_suite")))
    script = ("set -euo pipefail\nPY=%s\nRT_TMP=$(mktemp -d %s/rt-XXXXXX)\nRT_ROOT=\"$PWD\"\n"
              "RUN_TESTS_PARALLEL=%d\n%s%s%s%s"
              % (sys.executable, _TMP85, 1 if parallel else 0, _RUN_SUITE85, _LANES85, stubs,
                 dispatch or _DISPATCH85))
    rc, out = _bash85(script, d, timeout=120)
    return rc, out, sorted(os.listdir(os.path.join(d, "data")))


_seq85, _par85 = _run_tests85(False), _run_tests85(True)
check("run-tests: the sequential mode runs every DB-owning suite in a copy, so the checkout's "
      "own data/panel.db and panel.db.backup (a developer's panel) survive a passing run",
      _seq85[0] == 0 and _seq85[2] == ["panel.db", "panel.db.backup"], repr(_seq85))
check("run-tests: ...and so does the parallel mode (control)",
      _par85[0] == 0 and _par85[2] == ["panel.db", "panel.db.backup"], repr(_par85))
_rsd85 = _checkout85()
_rs85 = _bash85("set -e\nPY=%s\nRT_ROOT=\"$PWD\"\n%srun_suite x %s"
                % (sys.executable, _RUN_SUITE85, _OK_SUITE85), _rsd85)
check("run-tests: run_suite refuses to run in the checkout itself rather than delete its "
      "data/panel.db", _rs85[0] != 0
      and sorted(os.listdir(os.path.join(_rsd85, "data"))) == ["panel.db", "panel.db.backup"],
      repr(_rs85))


def _lanes_rc85(lanes_text):
    """run_lanes' status with every suite a passing stand-in and `lanes_text` as its lanes."""
    fns = _LANES85.replace('local -a lanes=("unit_suite" "other_suites rbac_suite" "smoke_suite")',
                           "local -a lanes=(%s)" % lanes_text)
    stubs = "".join("%s() { echo '1 / 1 checks passed'; }\n" % n
                    for n in ("unit_suite", "other_suites", "smoke_suite", "rbac_suite"))
    rc, out = _bash85("set -euo pipefail\nRT_TMP=$(mktemp -d %s/rl-XXXXXX)\n%s%s"
                      'lane_tree() { mktemp -d "$RT_TMP/lane-XXXXXX"; }\nrun_lanes\n'
                      % (_TMP85, fns, stubs), _TMP85)
    return rc, 'local -a lanes=("unit_suite" "other_suites rbac_suite" "smoke_suite")' in _LANES85, out


_lc85 = {k: _lanes_rc85(v) for k, v in (
    ("control", '"unit_suite" "other_suites rbac_suite" "smoke_suite"'),
    ("rbac dropped", '"unit_suite" "other_suites" "smoke_suite"'),
    ("smoke twice", '"unit_suite" "other_suites rbac_suite smoke_suite" "smoke_suite"'))}
check("run-tests: run_lanes refuses lanes that do not run every suite exactly once (rbac "
      "dropped from its lane, a suite in two lanes), and passes the real lanes",
      _lc85["control"][:2] == (0, True) and _lc85["rbac dropped"][0] != 0
      and _lc85["smoke twice"][0] != 0 and _lc85["rbac dropped"][1], repr(_lc85))

# Every tests/*_test.py runs from a function ALL_SUITES names, not merely somewhere in the file.
_ai85 = _RT85.find("\nALL_SUITES=(")
_all85 = (_RT85[_ai85 + len("\nALL_SUITES=("):_RT85.index(")", _ai85)].replace('"', "").split()
          if _ai85 >= 0 else [])
_bodies85 = "".join(_fn85(_RT85, n) for n in _all85)
_suites85 = sorted(n for n in os.listdir(os.path.join(_root, "tests")) if n.endswith("_test.py"))
_unrun85 = [s for s in _suites85 if "tests/" + s not in _bodies85]
check("run-tests: every tests/*_test.py is run by a suite function ALL_SUITES names (the "
      "list both modes and the lane check use)",
      len(_all85) >= 4 and len(_suites85) >= 6 and not _unrun85, repr((_all85, _unrun85)))

_lt85 = _fn85(_RT85, "lane_tree")
_nogit85 = _tf85.mkdtemp(dir=_TMP85)
_ltr85 = {
    "no mktemp": _bash85('set -euo pipefail\nRT_TMP=/nonexistent/p85\n%sd="$(lane_tree)"\n'
                         'echo "continued [$d]"\n' % _lt85, _nogit85),
    "no git": _bash85('set -euo pipefail\nRT_TMP=$(mktemp -d %s/lt-XXXXXX)\n%sd="$(lane_tree)"\n'
                      'echo "continued [$d]"\n' % (_TMP85, _lt85), _nogit85),
}
check("run-tests: a lane copy that failed (no scratch directory, a copy that did not complete) "
      "stops the run before any lane starts in it",
      all(rc != 0 and "continued" not in out for rc, out in _ltr85.values()), repr(_ltr85))

# Ctrl-C: every process in the process group gets SIGINT, as from a terminal. The lanes ignore
# it (bash starts them so), so only run_lanes' own trap can stop them.
_pidf85 = os.path.join(_TMP85, "sleeper.pid")
_sleeper_py85 = os.path.join(_TMP85, "sleeper.py")
with open(_sleeper_py85, "w", encoding="utf-8") as _fh85:
    _fh85.write("import os, sys, time\nwith open(sys.argv[1], 'w') as fh:\n"
                "    fh.write(str(os.getpid()))\ntime.sleep(120)\n")
_sleeper85 = '"%s" "%s" "%s"' % (sys.executable, _sleeper_py85, _pidf85)
_ctl85 = ("set -euo pipefail\nRT_TMP=$(mktemp -d %s/ci-XXXXXX)\n%s"
          "unit_suite() { %s; }\n"
          "other_suites() { echo '1 / 1 checks passed'; }\nrbac_suite() { :; }\nsmoke_suite() { :; }\n"
          'lane_tree() { mktemp -d "$RT_TMP/lane-XXXXXX"; }\nrun_lanes\n'
          % (_TMP85, _LANES85, _sleeper85))


def _pid_of85(path):
    """The pid the stand-in suite wrote to `path`, waiting up to 10 s; None if it never did."""
    for _ in range(100):
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read().strip()
        except FileNotFoundError:
            text = ""
        if text:
            return int(text)
        _time85.sleep(0.1)
    return None


def _gone85(pid):
    """Whether process `pid` has ended (within 5 s)."""
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        _time85.sleep(0.1)
    return False


def _kill85(pgid, pid):
    """Leave nothing of the run behind, whatever the check found."""
    for fn, target in ((os.killpg, pgid), (os.kill, pid)):
        if target:
            try:
                fn(target, _signal85.SIGKILL)
            except ProcessLookupError:
                pass  # already gone: the check's own run ended it first


def _ctrl_c85():
    """(the lane's suite pid, the run's exit status, whether that suite ended) after a Ctrl-C."""
    # SIGINT at its default, whatever this suite inherited: under CI's own parallel lanes the unit
    # suite runs with SIGINT ignored, and a shell that starts with a signal ignored cannot trap it,
    # so the run under test never saw the Ctrl-C (#433, the 26.04 leg). A terminal's Ctrl-C reaches
    # a shell with SIGINT at its default, which is what this check is about.
    proc = _sp85.Popen(["env", "--default-signal=INT", "bash", "-c", _ctl85],  # nosec B603 B607 - this part's script
                       cwd=_TMP85, start_new_session=True, stdout=_sp85.DEVNULL, stderr=_sp85.DEVNULL)
    spid = None
    try:
        spid = _pid_of85(_pidf85)
        _time85.sleep(0.3)
        os.killpg(proc.pid, _signal85.SIGINT)
        try:
            rc = proc.wait(timeout=15)
        except _sp85.TimeoutExpired:
            rc = "still running"
        return spid, rc, (_gone85(spid) if spid else None)
    finally:
        _kill85(proc.pid, spid)
        proc.wait()


_spid85, _crc85, _ended85 = _ctrl_c85()
check("run-tests: Ctrl-C during the lanes stops the run (130) and the suite running in a lane, "
      "which ignores SIGINT",
      _spid85 is not None and _crc85 == 130 and _ended85 is True,
      repr((_spid85, _crc85, _ended85)))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 3. a data migration through the ORM is counted only with its rewrite
# ════════════════════════════════════════════════════════════════════════════════════════════
def _migrate85(fail):
    """(user_version, the stored host) after one start's migrations from count 1."""
    path = os.path.join(_tf85.mkdtemp(dir=_TMP85), "m.db")
    app = _app18(path)
    with app.app_context():
        _db85.create_all()
        # Core, past the model's canonicalising validator: a row written before it.
        _db85.session.execute(_RS85.__table__.insert().values(
            name="p85", host="[2001:db8::5]", username="root"))
        _db85.session.commit()
    con = _sq85.connect(path)
    con.execute("PRAGMA user_version = 1")
    con.commit()
    con.close()

    def _boom():
        # The commit fails ("database is locked" past the busy timeout, a full disk) after
        # everything before it went through.
        raise OSError("p85: database is locked")
    with app.app_context():
        if fail:
            _db85.session.commit = _boom
        try:
            _m85._run_data_migrations()
        finally:
            if fail:
                del _db85.session.commit
        _db85.session.rollback()
        host = _RS85.query.filter_by(name="p85").one().host
        _db85.session.remove()
    con = _sq85.connect(path)
    uv = con.execute("PRAGMA user_version").fetchone()[0]
    con.close()
    return uv, host


_mg85 = {"ok": _migrate85(False), "fails": _migrate85(True)}
check("data migration: the canonical-hosts rewrite runs and is counted (control)",
      _mg85["ok"] == (2, "2001:db8::5"), repr(_mg85))
check("data migration: ...and when its write fails the count stays where it was, so the next "
      "start runs it again (the PRAGMA ran in autocommit before the ORM flushed anything)",
      _mg85["fails"] == (1, "[2001:db8::5]"), repr(_mg85))

# ════════════════════════════════════════════════════════════════════════════════════════════
# 4. a bracketed IPv6 peer reaches ping, and is_tailscale_ip, without its brackets
# ════════════════════════════════════════════════════════════════════════════════════════════
_argv85 = []


def _run85(argv, **kw):
    _argv85.append(list(argv))
    return NS(returncode=0, stdout="64 bytes from x: icmp_seq=1 ttl=64 time=1.5 ms\n", stderr="")


_saved_sp85 = _ts85.subprocess
_ts85.subprocess = NS(run=_run85)
try:
    _cp85 = _ts85.check_peer_reachability("[fd7a:115c:a1e0::1]")
    _cpn85 = _ts85.check_peer_reachability("peer-1.tail1234.ts.net")
    _cpd85 = _ts85.check_peer_reachability("-c9")
finally:
    _ts85.subprocess = _saved_sp85
check("tailscale: a bracketed IPv6 peer is pinged as the bare address (ping read the brackets "
      "as a host name and the peer as not responding); a name is passed unchanged",
      [a[-1] for a in _argv85] == ["fd7a:115c:a1e0::1", "peer-1.tail1234.ts.net"]
      and _cp85["reachable"] and _cpd85 == {"reachable": False, "latency_ms": 0},
      repr((_argv85, _cp85, _cpn85, _cpd85)))
check("tailscale: ...and is_tailscale_ip knows the bracketed form; still nothing outside the "
      "tailnet ranges", _ts85.is_tailscale_ip("[fd7a:115c:a1e0::1]")
      and not _ts85.is_tailscale_ip("[2001:db8::1]") and not _ts85.is_tailscale_ip("[fd7a:115c:a1e0::1"),
      "")

# ════════════════════════════════════════════════════════════════════════════════════════════
# 5. the debug report's "Ways in": sshd's ports, ranges and lists, first match
# ════════════════════════════════════════════════════════════════════════════════════════════
_UFWHEAD85 = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), "
              "deny (routed)\nNew profiles: skip\n\nTo                         Action      From\n"
              "--                         ------      ----\n")


def _ways85(rows, ssh_ports=(2222,), port=5000):
    text = _UFWHEAD85 + "".join("%-26s %-11s %s\n" % r for r in rows)
    u = _nw85.ufw_classify(text, "", 0)
    return _nw85._ways_in(u, port, {}, list(ssh_ports) if ssh_ports else None)


_A85 = "Anywhere"
_IN85 = [  # (rows, what the SSH part must say)
    ([("2222/tcp", "ALLOW IN", _A85)], "SSH ALLOW from Anywhere (on sshd's own ports)"),
    ([("2222", "LIMIT IN", _A85)], "SSH LIMIT from Anywhere"),
    ([("2200:2300/tcp", "ALLOW IN", _A85)], "SSH ALLOW from Anywhere"),
    ([("80,2222/tcp", "ALLOW IN", _A85)], "SSH ALLOW from Anywhere"),
    ([(_A85, "ALLOW IN", _A85)], "SSH ALLOW from Anywhere"),
    ([(_A85, "DENY IN", "203.0.113.7"), ("2222/tcp", "ALLOW IN", _A85)], "SSH ALLOW from Anywhere"),
    ([("2222/tcp", "DENY IN", _A85), ("2222/tcp (v6)", "ALLOW IN", "Anywhere (v6)")],
     "SSH ALLOW from Anywhere"),
    ([("2222/udp", "DENY IN", _A85), ("2222/tcp", "ALLOW IN", _A85)], "SSH ALLOW from Anywhere"),
    ([("2222/tcp", "ALLOW IN", "127.0.0.1")], "SSH ALLOW from a specific source"),
    ([("2222/tcp", "ALLOW IN", "::1")], "SSH ALLOW from a specific source"),
]
_OUT85 = [  # rows that are no way in to sshd on 2222
    [("22/tcp", "ALLOW IN", _A85)],
    [("OpenSSH", "ALLOW IN", _A85)],
    [("2222/udp", "ALLOW IN", _A85)],
    [("2222/tcp on lo", "ALLOW IN", _A85)],
    [("2222/tcp on docker0", "ALLOW IN", _A85)],
    [("2222/tcp", "ALLOW OUT", _A85)],
    [("2222/tcp", "ALLOW FWD", _A85)],
    [("2222/tcp", "DENY IN", _A85), ("2222/tcp", "ALLOW IN", _A85)],
    [("2222/tcp", "REJECT IN", _A85), ("2222/tcp", "ALLOW IN", _A85)],
    [(_A85, "DENY IN", _A85), ("2222/tcp", "ALLOW IN", _A85)],
    [("2000:2100/tcp", "ALLOW IN", _A85)],
]
_inbad85 = [(r, _ways85(r)) for r, want in _IN85 if want not in _ways85(r)]
_outbad85 = [(r, _ways85(r)) for r in _OUT85 if "SSH: no rule (on sshd's own ports)" not in _ways85(r)]
check("debug report: Ways in counts an SSH rule on sshd's real port, through a range, a list or "
      "every port, below a DENY that does not cover it (one source, the other family, UDP)",
      not _inbad85, repr(_inbad85))
check("debug report: ...and counts no rule on another port (22 or the OpenSSH profile with sshd "
      "on 2222), UDP, on lo or a docker bridge, OUT or FWD, or below a DENY/REJECT from Anywhere",
      not _outbad85, repr(_outbad85))
_pp85 = [_ways85([(r, "ALLOW IN", _A85)]) for r in ("5000:5010/tcp", "5000,8080/tcp")]
_ppn85 = _ways85([("5000/tcp", "DENY IN", _A85), ("5000/tcp", "ALLOW IN", _A85)])
check("debug report: ...the panel port through a range or a list is allowed, and below a DENY "
      "from Anywhere it is not",
      all("panel port 5000: allowed from Anywhere" in t for t in _pp85)
      and "panel port 5000: not allowed" in _ppn85, repr((_pp85, _ppn85)))
_unread85 = _ways85([("22/tcp", "LIMIT IN", _A85)], ssh_ports=None)
check("debug report: ...with sshd's ports unread it says it checked port 22 only",
      "SSH LIMIT from Anywhere (port 22; sshd's own ports not read)" in _unread85, _unread85)

_saved_pr85 = _nw85.priv_read
_sr85 = {}
try:
    for _k85, _ans85 in (("read", ("Port 2222\nport 443\npermitrootlogin no\n", "", 0)),
                         ("refused", ("", "sudo: a password is required", 1)), ("none", None)):
        _nw85.priv_read = lambda verb, args, timeout, _a=_ans85: _a if verb == "sshd-effective-config" else None
        _sr85[_k85] = _nw85.sshd_ports_read()
finally:
    _nw85.priv_read = _saved_pr85
check("debug report: sshd's ports come from its effective config; a refused or impossible read "
      "is None", _sr85 == {"read": [443, 2222], "refused": None, "none": None}, repr(_sr85))

_saved_bd85 = _nw85.bounded
_u85 = _nw85.ufw_classify(_UFWHEAD85 + "2222/tcp                   ALLOW IN    Anywhere\n", "", 0)
_nw85.bounded = lambda ctx, jobs, reserve=0.5: dict(
    {n: ("timeout", None) for n, _f in jobs}, ufw=("ok", _u85), sshd=("ok", [2222]))
try:
    _sec85 = _nw85.section_network(NS(app=NS(config={"BOOT_PORT": 5000})))
finally:
    _nw85.bounded = _saved_bd85
_sect85 = "\n".join(_sec85.lines)
check("debug report: the network section reads sshd beside UFW and hands its ports to Ways in",
      "SSH ALLOW from Anywhere (on sshd's own ports)" in _sect85, _sect85)

# ════════════════════════════════════════════════════════════════════════════════════════════
# 6. a content account with a `.` gets a cron.d file name cron runs
# ════════════════════════════════════════════════════════════════════════════════════════════
_saved_cc85 = _helper.CONTENT_CRON_PREFIX
_crond85 = os.path.join(_TMP85, "cron.d")
os.makedirs(_crond85)
_helper.CONTENT_CRON_PREFIX = os.path.join(_crond85, "lgsm-gmod-content")
try:
    _body85 = _gm85._content_update_cron_body("my.srcds", ["cssserver"])
    _wrc85 = _helper.do_content_cron_write(["my.srcds"], _body85)
    _wrote85 = sorted(os.listdir(_crond85))
    _wrc85b = _helper.do_content_cron_write(["gmodcontent"], _body85.replace("my.srcds", "gmodcontent"))
    _wrote85b = sorted(os.listdir(_crond85))
    with open(os.path.join(_crond85, "lgsm-gmod-content-my.srcds"), "w", encoding="utf-8"):
        pass                                  # the file the old writer left
    _helper.do_content_cron_remove(["my.srcds"], "")
    _left85 = sorted(os.listdir(_crond85))
finally:
    _helper.CONTENT_CRON_PREFIX = _saved_cc85
_hex85 = "lgsm-gmod-content--" + "my.srcds".encode().hex()
check("content cron: a content account named with a `.` gets a cron.d file whose name has none "
      "(Debian's cron skips it otherwise); a plain name keeps its old file name",
      _wrc85 == 0 and _wrote85 == [_hex85] and _wrc85b == 0
      and _wrote85b == sorted(["lgsm-gmod-content-gmodcontent", _hex85]),
      repr((_wrc85, _wrote85, _wrc85b, _wrote85b)))
check("content cron: ...removing it removes that file and the old writer's",
      _left85 == ["lgsm-gmod-content-gmodcontent"], repr(_left85))
_rcmd85 = _priv85.remote_content_cron_command("my.srcds", "x")
_rrm85 = _priv85.remote_command("content-cron-remove", ["my.srcds"])
_names85 = ("my.srcds", "gmodcontent", "a.b.c", "_x-y")
check("content cron: ...and on a remote (no helper) the same file names: written there, and "
      "both removed, by the helper's rule",
      "/etc/cron.d/" + _hex85 in _rcmd85 and "lgsm-gmod-content-my.srcds " not in _rcmd85
      and "/etc/cron.d/" + _hex85 in _rrm85 and "/etc/cron.d/lgsm-gmod-content-my.srcds" in _rrm85
      and [_priv85._r22a_content_cron_path(n) for n in _names85]
      == [_helper._r22a_content_cron_path(n) for n in _names85],
      repr((_rcmd85, _rrm85)))
