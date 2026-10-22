"""Part 118 of the unit suite: an OS update never stops on a package apt would DOWNGRADE.

A host whose apt pinning prefers an older version of a package (a Pin-Priority over 1000, often left
by a third-party repo's setup) made `full-upgrade` plan a downgrade, and under -y apt refused the
whole run ("Packages were downgraded and -y was used without --allow-downgrades"): not one of the
real updates installed, and the card said only "Finished with errors (exit 100)". Both forms of the
job — the helper's on the panel host, the remote shell over SSH — now keep such a package at the
version installed, for that run only, through a preferences file of their own, and say so.

HOW IT RUNS. The helper in-process (part05's), its subprocess calls stood in. The remote job's
shell runs under bash in this part's own temp dir, with stand-in apt-get and mktemp first on PATH
and the job's log moved there. Nothing reaches apt, a host or the checkout's data/.
"""
import os
import shutil as _shutil118
import subprocess as _sp118  # nosec B404 - bash over this part's own temp dir, fixed argv
import tempfile as _tf118
import time as _time118

from unit.part01 import check
from unit.part05 import _helper as _h118
from panel.security import privileged as _priv118

# A C-locale `apt-get -s full-upgrade` plan: one real upgrade, one downgrade the host's pin asks for.
_SIM118 = ("Inst tzdata [2024a-3] (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])\n"
           "Inst proftpd-core [1.3.8.b+dfsg-4ubuntu1] (1.3.8.b+dfsg-4 Ubuntu:24.04/noble [amd64])\n"
           "Conf tzdata (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])\n")


_DPKG118 = ("#!/bin/bash\n"
            "# dpkg --compare-versions A lt B, by sort -V (the build machine need not have dpkg).\n"
            "[ \"$1\" = --compare-versions ] && [ \"$3\" = lt ] || exit 2\n"
            "[ \"$2\" != \"$4\" ] && [ \"$(printf '%s\\n%s\\n' \"$2\" \"$4\" | sort -V | head -1)\" "
            "= \"$2\" ]\n")


def _standin118(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o700)  # nosec B103 - this part's own temp dir


def _keep118(sim_out):
    """Run the helper's planner with a stand-in apt-get and dpkg; (opts, preferences text, log)."""
    tmp = _tf118.mkdtemp(prefix="p118-")
    try:
        apt = os.path.join(tmp, "apt-get")
        _standin118(apt, "#!/bin/bash\nprintf '%s' \"$SIM118\"\n")
        _standin118(os.path.join(tmp, "dpkg"), _DPKG118)
        env = dict(_h118._clean_env(), PATH=tmp + ":/usr/bin:/bin", SIM118=sim_out)
        log = __import__("io").StringIO()
        # dpkg by the helper's own lookup (resolve), pointed at the stand-in for this call.
        real_resolve = _h118.resolve
        _h118.resolve = lambda prog: os.path.join(tmp, prog) if prog == "dpkg" else real_resolve(prog)
        try:
            opts = _h118._r33_keep_installed_opts(apt, env, tmp, log)
        finally:
            _h118.resolve = real_resolve
        prefs = os.path.join(tmp, "preferences")
        text = open(prefs, encoding="utf-8").read() if os.path.exists(prefs) else None
        return opts, text, log.getvalue()
    finally:
        _shutil118.rmtree(tmp, ignore_errors=True)


_opts, _prefs, _log = _keep118(_SIM118)
check("os update (panel host): a package the plan would DOWNGRADE is kept at its installed version "
      "for this run, through a preferences file of the job's own; the real upgrade is left to apt",
      bool(_opts) and _opts[0] == "-o" and _opts[1].startswith("Dir::Etc::Preferences=")
      and _prefs is not None
      and "Package: proftpd-core\nPin: version 1.3.8.b+dfsg-4ubuntu1\nPin-Priority: 32000" in _prefs
      and "tzdata" not in _prefs and "proftpd-core 1.3.8.b+dfsg-4ubuntu1" in _log,
      repr((_opts, _prefs, _log)))
_opts2, _prefs2, _log2 = _keep118(_SIM118.splitlines()[0] + "\n")
check("os update (panel host): ...and a plan with no downgrade adds nothing (control)",
      _opts2 == [] and _prefs2 is None and _log2 == "", repr((_opts2, _prefs2, _log2)))


def _r34d_job118(sim_out):
    """Run the helper's OS-update job body (_os_update_run) with a stand-in apt-get and dpkg.

    (rc, apt-get calls, the preferences file full-upgrade was handed, log): the CALLER of the planner
    driven end to end (review 1022a: the checks above call the planner alone, and part06's runner
    prints no plan, so `+ keep` could be dropped from the full-upgrade argv with every check green).
    """
    tmp = _tf118.mkdtemp(prefix="p118j-")
    calls, plan, log = (os.path.join(tmp, _n) for _n in ("calls", "plan", "os-update.log"))
    with open(plan, "w", encoding="utf-8") as fh:
        fh.write(sim_out)
    _standin118(os.path.join(tmp, "apt-get"),
                "#!/bin/bash\n"
                "for a in \"$@\"; do [ \"$a\" = -s ] && { cat %s; exit 0; }; done\n"
                "echo \"$*\" >> %s\n"
                "for a in \"$@\"; do case $a in Dir::Etc::Preferences=*) cp \"${a#*=}\" %s/prefs.seen;; "
                "esac; done\nexit 0\n" % (plan, calls, tmp))
    _standin118(os.path.join(tmp, "dpkg"), _DPKG118)
    saved = (_h118.resolve, _h118.OS_UPDATE_LOG, _h118.CHILD_PATH)
    # apt-get and dpkg both by the helper's own lookup (resolve), as the job finds them: dpkg was looked
    # up on PATH when this was written, and a PATH stand-in alone left the job with no dpkg once it no
    # longer was (review 1022a).
    _h118.resolve = (lambda prog: os.path.join(tmp, prog) if prog in ("apt-get", "dpkg")
                     else saved[0](prog))
    _h118.OS_UPDATE_LOG = log
    _h118.CHILD_PATH = tmp + ":/usr/bin:/bin"
    try:
        rc = _h118._os_update_run()
    finally:
        _h118.resolve, _h118.OS_UPDATE_LOG, _h118.CHILD_PATH = saved
    read = (lambda p: open(p, encoding="utf-8").read() if os.path.exists(p) else "")
    out = (rc, read(calls), read(os.path.join(tmp, "prefs.seen")), read(log))
    _shutil118.rmtree(tmp, ignore_errors=True)
    return out


_jrc, _jcalls, _jprefs, _jlog = _r34d_job118(_SIM118)
_jup = [ln for ln in _jcalls.splitlines() if ln.endswith("full-upgrade")]
_jrc2, _jcalls2, _jprefs2, _ = _r34d_job118(_SIM118.splitlines()[0] + "\n")
_jup2 = [ln for ln in _jcalls2.splitlines() if ln.endswith("full-upgrade")]
check("os update (panel host): the job itself hands full-upgrade the preferences file that keeps the "
      "package the plan would DOWNGRADE, and finishes; with no downgrade planned it hands none (control)",
      _jrc == 0 and len(_jup) == 1 and "-o Dir::Etc::Preferences=" in _jup[0]
      and "Package: proftpd-core\nPin: version 1.3.8.b+dfsg-4ubuntu1\nPin-Priority: 32000" in _jprefs
      and _h118.OS_UPDATE_DONE + "0" in _jlog
      and _jrc2 == 0 and len(_jup2) == 1 and "Preferences" not in _jup2[0] and _jprefs2 == "",
      repr((_jrc, _jcalls, _jprefs, _jlog[-300:], _jrc2, _jcalls2)))


def _remote118(mktemp_ok=True):
    """Run the remote job's shell with stand-ins; (apt-get calls, preferences text, log text)."""
    tmp = _tf118.mkdtemp(prefix="p118r-")
    bin_ = os.path.join(tmp, "bin")
    os.mkdir(bin_)
    calls = os.path.join(tmp, "calls")
    kd = os.path.join(tmp, "kd")
    # apt-get: the plan for -s, a record of every other call (with the preferences file copied out).
    with open(os.path.join(bin_, "apt-get"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n"
                 "for a in \"$@\"; do [ \"$a\" = -s ] && { printf '%%s' \"$SIM118\"; exit 0; }; done\n"
                 "echo \"$*\" >> %s\n"
                 "for a in \"$@\"; do case $a in Dir::Etc::Preferences=*) cp \"${a#*=}\" %s/prefs.seen;; "
                 "esac; done\nexit 0\n" % (calls, tmp))
    with open(os.path.join(bin_, "mktemp"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\nmkdir -p %s && echo %s\n" % (kd, kd) if mktemp_ok else "#!/bin/bash\nexit 1\n")
    _standin118(os.path.join(bin_, "dpkg"), _DPKG118)
    for f in ("apt-get", "mktemp"):
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(os.path.join(bin_, f), 0o700)  # nosec B103 - this part's own temp dir
    log = os.path.join(tmp, "os-update.log")
    saved = _priv118.OS_UPDATE_LOG
    _priv118.OS_UPDATE_LOG = log
    try:
        cmd = _priv118._REMOTE_ACTIONS["os-update-run"]([])
    finally:
        _priv118.OS_UPDATE_LOG = saved
    env = {"PATH": bin_ + ":/usr/bin:/bin", "SIM118": _SIM118, "HOME": tmp, "LC_ALL": "C.UTF-8"}
    _sp118.run(["bash", "-c", cmd], env=env, capture_output=True, timeout=60)  # nosec B603 B607
    deadline = _time118.time() + 30
    while _time118.time() < deadline:
        if os.path.exists(log) and _priv118.OS_UPDATE_DONE in open(log, encoding="utf-8").read():
            break
        _time118.sleep(0.2)
    read = (lambda p: open(p, encoding="utf-8").read() if os.path.exists(p) else "")
    out = (read(calls), read(os.path.join(tmp, "prefs.seen")), read(log), os.path.exists(kd))
    _shutil118.rmtree(tmp, ignore_errors=True)
    return out


_calls, _rprefs, _rlog, _kd_left = _remote118()
_upgrade = [ln for ln in _calls.splitlines() if ln.endswith("full-upgrade")]
check("os update (remote): the job hands full-upgrade a preferences file that keeps the package the "
      "plan would DOWNGRADE at its installed version, names it in the log, and removes its temp dir",
      len(_upgrade) == 1 and "Dir::Etc::Preferences=" in _upgrade[0]
      and "Package: proftpd-core\nPin: version 1.3.8.b+dfsg-4ubuntu1\nPin-Priority: 32000" in _rprefs
      and "tzdata" not in _rprefs and "proftpd-core 1.3.8.b+dfsg-4ubuntu1" in _rlog
      and _priv118.OS_UPDATE_DONE + "0" in _rlog and not _kd_left,
      repr((_calls, _rprefs, _rlog[-400:], _kd_left)))

_calls2, _rprefs2, _rlog2, _ = _remote118(mktemp_ok=False)
_upgrade2 = [ln for ln in _calls2.splitlines() if ln.endswith("full-upgrade")]
check("os update (remote): ...and with no temp dir (mktemp failed) no preferences file is written "
      "anywhere and the upgrade still runs, as before the fix",
      len(_upgrade2) == 1 and "Dir::Etc::Preferences" not in _upgrade2[0] and _rprefs2 == ""
      and _priv118.OS_UPDATE_DONE + "0" in _rlog2, repr((_calls2, _rlog2[-300:])))
