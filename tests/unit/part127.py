"""Part 127 of the unit suite: review 1022b's integration (integrator J), the SSH move's unconfirmed restore.

* A move whose undo restore could not be confirmed (a Tailscale or local transport answers -1 rather
  than raising) left the drop-in sshd -t had rejected on disk, the good one only in the snapshot, and a
  message saying "nothing changed": the host's next ssh restart (a reboot) started on the rejected
  config. The restore now COPIES the snapshot back and keeps it, so it is tried once more at once; a
  second one not confirmed either leaves the running sshd alone and says so, naming the file.
* The next move's snapshot step keeps a snapshot that is already there and DIFFERS from the drop-in
  (an earlier move did not finish: it may be the last good copy), whatever `sshd -t` says, and the move
  stops naming both files; one identical to the drop-in (what a confirmed restore leaves) is replaced
  as usual, in the helper and the remote shell form. It held on `sshd -t` rejecting instead: every move
  refused over an unrelated sshd_config error, blaming the snapshot, and an accepted config replaced a
  good snapshot with an unrestored drop-in (review 1022b, L1/L2).
* After COMMIT the snapshot's discard is tried once more when it did not answer 0, and a snapshot that
  may still be there is said in the success message (the next move refuses over it).
* The update gate ignores "Scorecard analysis": it rates the repository, not the commit's code, and a
  GitHub-side error in it (2026-10-22) held every panel's update. Every check that verifies code still
  gates, and only the jobs of the four workflows that verify nothing may be ignored.

HOW IT RUNS. The move over part125's stand-in host (part120's, able to succeed) on part12's stand-ins
with its transport tripwire armed; the helper loaded by file with its paths and its `sshd` in this
part's temp dir; the remote shell forms under bash (and dash, where installed) over this part's own
files with an `sshd` stand-in first on PATH. Nothing reaches a host, sudo or the checkout's data/.
"""
import importlib.machinery as _mach127
import importlib.util as _ilu127
import os
import re as _re127
import shutil as _shutil127
import subprocess as _sp127  # nosec B404 - bash/dash over this part's own temp files, fixed argv
import tempfile as _tf127

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_patch, _p9_restore_all
from unit.part125 import _Box125, _move125
from panel.ops import system_ops as _so127
from panel.security import privileged as _priv127

_TRIP127_START = len(_P9_TRIPPED)
_TMP127 = _tf127.mkdtemp(prefix="lgsm-unit-p127-")
_ROOT127 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SHELLS127 = [s for s in ("bash", "dash") if _shutil127.which(s)]


def _put127(path, text):
    with open(path, "w") as f:
        f.write(text)


def _read127(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def _sshd127(rc):
    """A directory holding an `sshd` stand-in whose `-t` answers `rc` (0 accepts the config)."""
    d = os.path.join(_TMP127, "sshd-%d" % rc)
    if not os.path.isdir(d):
        os.makedirs(d)
        _put127(os.path.join(d, "sshd"), "#!/bin/sh\nexit %d\n" % rc)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- stand-in
        os.chmod(os.path.join(d, "sshd"), 0o700)
    return os.path.join(d, "sshd")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. change_ssh_port: a restore not confirmed twice, and a snapshot the verb kept
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _moves127():
    both = {("sshd-restore-dropin", 1), ("sshd-restore-dropin", 2)}
    sock = {("sshd-socket-restore", 1), ("sshd-socket-restore", 2)}
    got = {
        # sshd -t rejects the new drop-in; both restores answer -1 without running
        "restore unconfirmed twice": _move125(_Box125(reject_new=True, noop=both)),
        "socket: restore unconfirmed twice": _move125(_Box125(socket=True, reject_new=True, noop=sock)),
        # the first answers -1, the second runs (part125 has the restart this allows)
        "control: second restore confirmed": _move125(_Box125(reject_new=True, noop={("sshd-restore-dropin", 1)})),
        # 2a: the snapshot verb kept the snapshot that was there (it differs from the drop-in)
        "snapshot held": _move125(_Box125(backup_rc=_priv127.R35J_SNAPSHOT_HELD)),
        "socket: snapshot held": _move125(_Box125(socket=True, backup_rc=_priv127.R35J_SNAPSHOT_HELD)),
    }
    shape = {case: (r["ok"], r["restores"], r["restarts"], r["allow left"], r["written"]) for case, r in got.items()}
    check("ssh port move: an undo restore answered -1 is tried once more (it copies the snapshot back and keeps "
          "it), and when that one is not confirmed either nothing restarts sshd onto the config step 3 "
          "rejected; a snapshot the verb kept stops the move with nothing written and no restart",
          shape == {"restore unconfirmed twice": (False, 2, 0, False, 1),
                    "socket: restore unconfirmed twice": (False, 2, 0, False, 1),
                    "control: second restore confirmed": (False, 2, 1, False, 1),
                    "snapshot held": (False, 0, 0, False, 0), "socket: snapshot held": (False, 0, 0, False, 0)},
          repr(shape))
    msgs = {case: r["msg"] for case, r in got.items()}
    un, sun = msgs["restore unconfirmed twice"], msgs["socket: restore unconfirmed twice"]
    held, sheld = msgs["snapshot held"], msgs["socket: snapshot held"]
    check("ssh port move: ...and says so, naming the file to check and where the previous one is kept (it said "
          "'nothing changed' while the rejected drop-in was on disk for the next ssh restart); the kept "
          "snapshot's refusal names both files and says how to clear it, without claiming sshd -t rejects anything "
          "(it may not); a restore that was confirmed keeps the plain message (control)",
          all(["could not be confirmed" in un, _priv127.SSHD_DROPIN + " " in un, _priv127.SSHD_DROPIN_BAK in un,
               "nothing changed" not in un,
               _priv127.SSHD_SOCKET_DROPIN + " " in sun, _priv127.SSHD_SOCKET_DROPIN_BAK in sun,
               _priv127.SSHD_DROPIN_BAK + " differs" in held, _priv127.SSHD_DROPIN + ":" in held,
               "sshd -t" not in held, "reject" not in held, "could not be backed up" not in held,
               "delete " + _priv127.SSHD_DROPIN_BAK in held,
               _priv127.SSHD_SOCKET_DROPIN_BAK + " differs" in sheld, _priv127.SSHD_SOCKET_DROPIN + ":" in sheld,
               "could not be confirmed" not in msgs["control: second restore confirmed"]]), repr(msgs))


def _discard127(box):
    r = _move125(box)
    return r["ok"], box.calls.get("sshd-socket-discard" if box.socket else "sshd-discard-backup", 0), r["msg"]


def _discards127():
    got = {
        "discard -1 twice": _discard127(_Box125(noop={("sshd-discard-backup", 1), ("sshd-discard-backup", 2)})),
        "socket: discard -1 twice": _discard127(_Box125(socket=True, noop={("sshd-socket-discard", 1),
                                                                          ("sshd-socket-discard", 2)})),
        "discard raises twice": _discard127(_Box125(unsent={("sshd-discard-backup", 1), ("sshd-discard-backup", 2)})),
        "discard -1, then runs": _discard127(_Box125(noop={("sshd-discard-backup", 1)})),
        "control: discard runs": _discard127(_Box125()),
    }
    check("ssh port move: a snapshot discard after COMMIT that did not answer 0 is tried once more (a snapshot "
          "left behind differs from the new drop-in, so the next move's snapshot verb refuses over it)",
          {case: g[:2] for case, g in got.items()}
          == {"discard -1 twice": (True, 2), "socket: discard -1 twice": (True, 2), "discard raises twice": (True, 2),
              "discard -1, then runs": (True, 2), "control: discard runs": (True, 1)}, repr(got))
    left = {case: g[2] for case, g in got.items()}
    check("ssh port move: ...and when neither was confirmed the move still stands and its message names the "
          "snapshot that may be left and that the next move refuses until it is deleted; a discard that ran "
          "says nothing of it",
          all(["refuses until you delete it" in left["discard -1 twice"],
               _priv127.SSHD_DROPIN_BAK + " may not" in left["discard -1 twice"],
               _priv127.SSHD_SOCKET_DROPIN_BAK + " may not" in left["socket: discard -1 twice"],
               "refuses until" in left["discard raises twice"],
               "SSH now listens on port 2022" in left["discard -1 twice"],
               "may not have been removed" not in left["discard -1, then runs"],
               "may not have been removed" not in left["control: discard runs"]]), repr(left))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The verbs: the remote shell forms and the helper
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _sh127(sh, form, sshd_rc=0):
    env = dict(os.environ, PATH=os.path.dirname(_sshd127(sshd_rc)) + os.pathsep + os.environ.get("PATH", ""))
    return _sp127.run([sh, "-c", form], capture_output=True, timeout=20, check=False,  # nosec B603
                      env=env).returncode


def _shell_dir127(sh, case):
    d = os.path.join(_TMP127, "sh-%s-%s" % (sh, case.replace(" ", "-").replace(":", "").replace(",", "")))
    os.makedirs(d)
    return d, os.path.join(d, "drop.conf"), os.path.join(d, "drop.conf.bak")


def _shell_restore127(sh, case):
    """A restore case: (both runs' rcs, the drop-in, the snapshot, the drop-in's mode, the files left)."""
    d, drop, bak = _shell_dir127(sh, case)
    _put127(drop, "REJECTED\n")
    if case != "restore, no snapshot":
        _put127(bak, "GOOD\n")
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a temp file
        os.chmod(bak, 0o600)
    form = _priv127._r35j_restore_sh(drop, bak)
    rcs = (_sh127(sh, form), _sh127(sh, form))
    mode = oct(os.stat(drop).st_mode & 0o777) if os.path.exists(drop) else None
    return rcs, _read127(drop), _read127(bak), mode, sorted(os.listdir(d))


def _snap_case_files127(case, drop, bak):
    """Lay out a snapshot case: the drop-in, and a snapshot equal to it, different, or none."""
    _put127(drop, "NEW\n")
    if "identical" in case:
        _put127(bak, "NEW\n")
    elif "differs" in case:
        _put127(bak, "GOOD\n")


def _shell_snapshot127(sh, case):
    """A snapshot case: (its rc, the drop-in, the snapshot)."""
    _d, drop, bak = _shell_dir127(sh, case)
    _snap_case_files127(case, drop, bak)
    rc = _sh127(sh, _priv127._r35b_snapshot_sh(drop, bak), sshd_rc=0 if case.endswith("accepts") else 255)
    return rc, _read127(drop), _read127(bak)


def _shells127():
    got = {sh: dict({case: _shell_restore127(sh, case) for case in ("restore, run twice", "restore, no snapshot")},
                    **{case: _shell_snapshot127(sh, case) for case in _SNAP_CASES127}) for sh in _SHELLS127}
    want = dict({"restore, run twice": ((0, 0), "GOOD\n", "GOOD\n", "0o600", ["drop.conf", "drop.conf.bak"]),
                 "restore, no snapshot": ((0, 0), None, None, None, [])}, **_SNAP_WANT127)
    check("ssh port move verbs (remote shell form, bash and dash): the restore copies the snapshot back with its "
          "mode and keeps it, so running it twice restores the same file (it MOVED the snapshot, and a second run "
          "deleted the drop-in); the snapshot keeps one already there that DIFFERS from the drop-in, answering "
          "R35J_SNAPSHOT_HELD even when sshd -t accepts (it replaced the last good copy with the unrestored "
          "drop-in), and replaces one IDENTICAL to it even when sshd -t rejects (every move refused, blaming "
          "the snapshot), or takes one when none was there",
          bool(got) and all(g == want for g in got.values()), repr(got))
    forms = (_priv127._REMOTE_ACTIONS["sshd-restore-dropin"]([]), _priv127._REMOTE_ACTIONS["sshd-socket-restore"]([]))
    check("ssh port move verbs (remote shell form): the sshd and ssh.socket restore verbs are that restore of "
          "their own drop-ins",
          forms == (_priv127._r35j_restore_sh(_priv127.SSHD_DROPIN, _priv127.SSHD_DROPIN_BAK),
                    _priv127._r35j_restore_sh(_priv127.SSHD_SOCKET_DROPIN, _priv127.SSHD_SOCKET_DROPIN_BAK)),
          repr(forms))


_SNAP_CASES127 = ("snapshot identical, sshd -t rejects", "snapshot identical, sshd -t accepts",
                  "snapshot differs, sshd -t accepts", "snapshot differs, sshd -t rejects",
                  "snapshot, none there, sshd -t rejects")
_SNAP_WANT127 = {"snapshot identical, sshd -t rejects": (0, "NEW\n", "NEW\n"),
                 "snapshot identical, sshd -t accepts": (0, "NEW\n", "NEW\n"),
                 "snapshot differs, sshd -t accepts": (_priv127.R35J_SNAPSHOT_HELD, "NEW\n", "GOOD\n"),
                 "snapshot differs, sshd -t rejects": (_priv127.R35J_SNAPSHOT_HELD, "NEW\n", "GOOD\n"),
                 "snapshot, none there, sshd -t rejects": (0, "NEW\n", "NEW\n")}


def _helper127(d, sshd_rc):
    spec = _ilu127.spec_from_loader("ph_p127", _mach127.SourceFileLoader(
        "ph_p127", os.path.join(_ROOT127, "tools", "panel-helper")))
    m = _ilu127.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.SSHD_DROPIN = os.path.join(d, "99-panel-sshport.conf")
    m.SSHD_DROPIN_BAK = m.SSHD_DROPIN + ".bak"
    m.SSHD_SOCKET_DROPIN = os.path.join(d, "sock.conf")
    m.SSHD_SOCKET_DROPIN_BAK = m.SSHD_SOCKET_DROPIN + ".bak"
    # the helper's own `sshd -t`, through resolve(), on this part's stand-in
    m.TOOLS = dict(m.TOOLS, sshd=(_sshd127(sshd_rc),))
    return m


def _helper_case127(case):
    d = os.path.join(_TMP127, "helper-" + case.replace(" ", "-").replace(",", ""))
    os.makedirs(d)
    h = _helper127(d, 0 if case.endswith("accepts") else 255)
    for drop, bak in ((h.SSHD_DROPIN, h.SSHD_DROPIN_BAK), (h.SSHD_SOCKET_DROPIN, h.SSHD_SOCKET_DROPIN_BAK)):
        if case.startswith("restore"):
            _put127(drop, "REJECTED\n")
            _put127(bak, "GOOD\n")
        else:
            _snap_case_files127(case, drop, bak)
    if case.startswith("restore"):
        rcs = (h.do_sshd_restore([], None), h.do_sshd_restore([], None),
               h.do_sshd_socket_restore([], None), h.do_sshd_socket_restore([], None))
    else:
        rcs = (h.do_sshd_backup([], None), h.do_sshd_socket_backup([], None))
    return rcs, [(_read127(p), _read127(p + ".bak")) for p in (h.SSHD_DROPIN, h.SSHD_SOCKET_DROPIN)]


def _helpers127():
    got = {case: _helper_case127(case) for case in ("restore, run twice",) + _SNAP_CASES127}
    held = _priv127.R35J_SNAPSHOT_HELD
    want = dict({"restore, run twice": ((0, 0, 0, 0), [("GOOD\n", "GOOD\n")] * 2)},
                **{case: ((rc, rc), [(drop, bak)] * 2) for case, (rc, drop, bak) in _SNAP_WANT127.items()})
    check("ssh port move verbs (panel-helper, sshd and ssh.socket): the restore run twice restores the same file "
          "and keeps the snapshot; the snapshot keeps one already there that differs from the drop-in "
          "(R35J_SNAPSHOT_HELD) even when the helper's sshd -t accepts, and replaces one identical to it even "
          "when sshd -t rejects; the helper and the remote form answer with the same code",
          got == want and _helper127(os.path.join(_TMP127, "const"), 0).R35J_SNAPSHOT_HELD == held, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The update gate and Scorecard
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gate127(extra):
    """The update gate's verdict on a commit carrying every required check (green) plus `extra`."""
    runs = [{"name": n + ("x)" if n.endswith("(") else ""), "status": "completed", "conclusion": "success"}
            for n in _so127._CI_REQUIRED] + extra
    _p9_patch(_so127, "_repo_slug", lambda: "o/r")
    _p9_patch(_so127, "_ci_fetch_runs", lambda slug, sha, seen, _r=runs: [dict(r) for r in _r])
    _p9_patch(_so127, "_ci_suite_expected", lambda sha, runs: True)
    try:
        return _so127._remote_ci_state_read("a" * 40, {})
    finally:
        # ...and the part's tripwire put back with them: the restore drops it too, and the next gate call
        # ran unarmed (review 1022c lead).
        _p9_restore_all()
        _p9_arm(who="part127")


def _job_names127(name):
    with open(os.path.join(_ROOT127, ".github", "workflows", name), encoding="utf-8") as f:
        text = "\n".join(ln for ln in f.read().splitlines() if not ln.lstrip().startswith("#"))
    return [m.strip() for m in _re127.findall(r"^    name: (.+)$", text, _re127.M)]


def _scorecard127():
    def _run(name, status, conclusion):
        return [{"name": name, "status": status, "conclusion": conclusion}]
    got = {
        "Scorecard failed": _gate127(_run("Scorecard analysis", "completed", "failure")),
        "Scorecard running": _gate127(_run("Scorecard analysis", "in_progress", None)),
        "control: a CI leg failed beside it": _gate127(_run("Scorecard analysis", "completed", "success")
                                                       + _run("checks (y)", "completed", "failure")),
        "control: Lighthouse failed": _gate127(_run("lighthouse", "completed", "failure")),
        "control: pip-audit failed": _gate127(_run("pip-audit", "completed", "failure")),
        "control: open alerts": _gate127(_run("Open code-scanning alerts", "completed", "failure")),
    }
    check("update gate: a failed or running Scorecard analysis no longer holds a commit back (a GitHub-side "
          "error in it held every panel's update on 2026-10-22), while a failing CI leg, Lighthouse, pip-audit "
          "or the open code-scanning alerts check beside it still does",
          got == {"Scorecard failed": "passing", "Scorecard running": "passing",
                  "control: a CI leg failed beside it": "failing", "control: Lighthouse failed": "failing",
                  "control: pip-audit failed": "failing", "control: open alerts": "failing"}, repr(got))
    allowed = {n for wf in ("deploy.yml", "codacy-coverage.yml", "codeql-alerts.yml", "scorecard.yml")
               for n in _job_names127(wf)}
    check("update gate: every check it ignores is a job of a workflow that verifies no code (deploy, the "
          "coverage upload, the alerts job's own run, Scorecard), the name is that job's, and none is a "
          "required check",
          "Scorecard analysis" in _job_names127("scorecard.yml") and _so127._CI_IGNORE <= allowed
          and not any(_so127._ci_name_matches(r, n) for r in _so127._CI_REQUIRED for n in _so127._CI_IGNORE),
          repr((sorted(_so127._CI_IGNORE), sorted(allowed))))


try:
    _p9_arm(who="part127")
    os.makedirs(os.path.join(_TMP127, "const"))
    for _fn127 in (_moves127, _discards127, _shells127, _helpers127, _scorecard127):
        _fn127()
        _p9_restore_all()
        _p9_arm(who="part127")
finally:
    _p9_restore_all()
    _shutil127.rmtree(_TMP127, ignore_errors=True)

check("part127: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP127_START, repr(_P9_TRIPPED[_TRIP127_START:][:6]))
