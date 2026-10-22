"""Part 122 of the unit suite: the downgrade check never stops a full-upgrade (review 1022a, integrator).

Every full-upgrade the panel or its installer runs first simulates the upgrade and keeps, for that run,
a package the host's apt pinning would DOWNGRADE (parts 118 and 119). The check is a refinement of the
upgrade, never a condition of it. When it cannot finish (the simulation fails, or runs past its time
bound, or the host has no dpkg), the upgrade runs as it did before the check existed, with no keep
pins, and the log says the check could not run. A failed simulation used to read as an empty plan,
the same as "nothing to keep", with nothing said. A hung one held the whole update with it on a remote
and in install.sh, which had no time bound.

Covered in all five places: the helper's OS update job and its apt-full-upgrade verb (panel host),
the remote job and the remote apt-full-upgrade verb (privileged.py's shell), and install.sh.

HOW IT RUNS. The helper in-process (part05's), with apt-get and dpkg found through its own resolve and
pointed at stand-ins in this part's temp dir. The remote shell and install.sh's function run under
bash with a PATH made only of this part's stand-ins and links to the few real tools they use, so the
"no dpkg" cases hold on a machine that has dpkg. Nothing reaches apt, a host, sudo or data/.
"""
import io as _io122
import os
import shutil as _shutil122
import subprocess as _sp122  # nosec B404 - bash over this part's own temp dir, fixed argv
import sys as _sys122
import tempfile as _tf122
import time as _time122

from unit.part01 import check
from unit.part05 import _helper as _h122, _root
from unit.part118 import _DPKG118, _SIM118
from panel.security import privileged as _priv122

_TMP122 = _tf122.mkdtemp(prefix="lgsm-unit-p122-")
_SAID122 = "Could not check for packages apt would downgrade ("
_KEPT122 = "proftpd-core 1.3.8.b+dfsg-4ubuntu1"
# What the stand-in apt-get does for `-s`: the plan with a downgrade in it, then exit 0 (the control),
# the same plan then exit 100 (a simulation apt could not finish: the plan must not be used), or hang.
_SIMS122 = {
    "ok": "cat \"$P\"; exit 0",
    "fails": "cat \"$P\"; exit 100",
    "hangs": "exec sleep 30",
}
# The real tools the shell forms run, linked into a PATH of their own (dpkg is never one of them).
_TOOLS122 = ("bash", "env", "timeout", "sed", "cat", "rm", "mktemp", "setsid", "date", "sleep", "cp",
             "mkdir", "sort", "head")


def _standin122(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o700)  # nosec B103 - this part's own temp dir


def _read122(path):
    return open(path, encoding="utf-8").read() if os.path.exists(path) else ""


def _bin122(name, sim, dpkg=True):
    """A fresh dir: stand-in apt-get (`sim` for -s, a call log otherwise), dpkg if asked, tool links."""
    d = os.path.join(_TMP122, name)
    os.makedirs(d)
    with open(os.path.join(d, "plan"), "w", encoding="utf-8") as fh:
        fh.write(_SIM118)
    _standin122(os.path.join(d, "apt-get"),
                "#!/bin/bash\nP=%s\n"
                "for a in \"$@\"; do [ \"$a\" = -s ] && { %s; }; done\n"
                "echo \"$*\" >> %s/calls\n"
                "for a in \"$@\"; do case $a in Dir::Etc::Preferences=*) cp \"${a#*=}\" %s/prefs.seen;; "
                "esac; done\nexit 0\n" % (os.path.join(d, "plan"), _SIMS122[sim], d, d))
    if dpkg:
        _standin122(os.path.join(d, "dpkg"), _DPKG118)
    for tool in _TOOLS122:
        real = _shutil122.which(tool)
        if real:
            os.symlink(real, os.path.join(d, tool))
    return d


def _upgrades122(d):
    """The stand-in apt-get's recorded full-upgrade runs (the simulation is never recorded)."""
    return [ln for ln in _read122(os.path.join(d, "calls")).splitlines() if "full-upgrade" in ln.split()]


# ── 1. the helper's OS update job (panel host) ───────────────────────────────────────────────────
def _helper_job122(case, sim, dpkg=True):
    """(rc, full-upgrade runs, log) of the helper's _os_update_run over this case's stand-ins."""
    d = _bin122("job-" + case, sim, dpkg)
    log = os.path.join(d, "os-update.log")
    saved = (_h122.resolve, _h122.OS_UPDATE_LOG, _h122.CHILD_PATH, _h122._R34J_SIM_TIMEOUT)

    def resolve(prog):
        if prog in ("apt-get", "dpkg"):
            path = os.path.join(d, prog)
            if not os.path.exists(path):
                raise FileNotFoundError(prog)
            return path
        return saved[0](prog)
    _h122.resolve, _h122.OS_UPDATE_LOG, _h122.CHILD_PATH = resolve, log, d
    _h122._R34J_SIM_TIMEOUT = 2
    try:
        rc = _h122._os_update_run()
    finally:
        _h122.resolve, _h122.OS_UPDATE_LOG, _h122.CHILD_PATH, _h122._R34J_SIM_TIMEOUT = saved
    return rc, _upgrades122(d), _read122(log)


def _helper_job_checks122():
    got = {}
    for case, sim, dpkg in (("simulation fails", "fails", True), ("simulation hangs", "hangs", True),
                            ("no dpkg", "ok", False)):
        rc, ups, log = _helper_job122(case.replace(" ", "-"), sim, dpkg)
        got[case] = (rc, len(ups), any("Preferences" in u for u in ups), _SAID122 in log, _KEPT122 in log,
                     log.rstrip().endswith(_h122.OS_UPDATE_DONE + "0"))
    rc, ups, log = _helper_job122("control", "ok")
    control = (rc, len(ups), any("Preferences" in u for u in ups), _SAID122 in log, _KEPT122 in log)
    check("os update (panel host): when the downgrade check cannot finish (the simulation fails or runs past "
          "its time, no dpkg) full-upgrade still runs, with no keep pins, and the log says the check could "
          "not run (a failed simulation kept nothing and said nothing)",
          all(v == (0, 1, False, True, False, True) for v in got.values()), repr(got))
    check("os update (panel host): ...and a check that finishes still keeps the package (control)",
          control == (0, 1, True, False, True), repr(control))


# ── 2. the helper's apt-full-upgrade verb (the host bootstrap's, panel host) ─────────────────────
def _helper_verb_checks122():
    d = _bin122("verb", "fails")
    saved = (_h122.resolve, _sys122.stdout)
    out = _io122.StringIO()
    _h122.resolve = lambda prog: os.path.join(d, prog) if prog in ("apt-get", "dpkg") else saved[0](prog)
    _sys122.stdout = out
    try:
        rc = _h122.main(["panel-helper", "apt-full-upgrade"])
    finally:
        _h122.resolve, _sys122.stdout = saved
    ups = _upgrades122(d)
    got = (rc, len(ups), any("Preferences" in u for u in ups), _SAID122 in out.getvalue(),
           _KEPT122 in out.getvalue())
    check("helper: apt-full-upgrade with a simulation apt could not finish runs the upgrade with no keep pins "
          "and says the check could not run (its plan was read as 'nothing to keep')",
          got == (0, 1, False, True, False), repr((got, ups, out.getvalue()[-300:])))


# ── 3. the remote job and the remote apt-full-upgrade verb (privileged.py's shell) ───────────────
def _env122(d):
    return {"PATH": d, "HOME": d, "LC_ALL": "C.UTF-8", "TMPDIR": d}


def _bounded122(cmd):
    """`cmd` with the simulation's time bound cut to one second (the shell's own `timeout`)."""
    bound = "timeout %d apt-get -s" % _priv122._R34J_SIM_SECONDS
    return cmd.replace(bound, "timeout 1 apt-get -s") if bound in cmd else "exit 97"


def _remote_job122(case, sim, dpkg=True):
    """(full-upgrade runs, log, temp dirs left) of the remote os-update-run job over stand-ins."""
    d = _bin122("rjob-" + case, sim, dpkg)
    log = os.path.join(d, "os-update.log")
    saved = _priv122.OS_UPDATE_LOG
    _priv122.OS_UPDATE_LOG = log
    try:
        cmd = _bounded122(_priv122._REMOTE_ACTIONS["os-update-run"]([]))
    finally:
        _priv122.OS_UPDATE_LOG = saved
    _sp122.run([os.path.join(d, "bash"), "-c", cmd], env=_env122(d), capture_output=True,  # nosec B603
               timeout=60)
    deadline = _time122.time() + 30
    while _time122.time() < deadline and _priv122.OS_UPDATE_DONE not in _read122(log):
        _time122.sleep(0.2)
    return _upgrades122(d), _read122(log), [n for n in os.listdir(d) if n.startswith("tmp.")]


def _remote_checks122():
    got = {}
    for case, sim, dpkg in (("simulation fails", "fails", True), ("simulation hangs", "hangs", True),
                            ("no dpkg", "ok", False)):
        ups, log, left = _remote_job122(case.replace(" ", "-"), sim, dpkg)
        got[case] = (len(ups), any("Preferences" in u for u in ups), _SAID122 in log, _KEPT122 in log,
                     _priv122.OS_UPDATE_DONE + "0" in log, left)
    ups, log, left = _remote_job122("control", "ok")
    control = (len(ups), any("Preferences" in u for u in ups), _SAID122 in log, _KEPT122 in log, left)
    check("os update (remote): when the downgrade check cannot finish (the simulation fails or runs past its "
          "time, no dpkg) full-upgrade still runs, with no keep pins, and the log says the check could not "
          "run (a failed simulation kept nothing and said nothing; a hung one had no time bound)",
          all(v == (1, False, True, False, True, []) for v in got.values()), repr(got))
    check("os update (remote): ...and a check that finishes still keeps the package (control)",
          control == (1, True, False, True, []), repr(control))
    verb = {}
    for case, sim in (("simulation fails", "fails"), ("control", "ok")):
        d = _bin122("rverb-" + case.replace(" ", "-"), sim)
        r = _sp122.run([os.path.join(d, "bash"), "-c", _bounded122(  # nosec B603
            _priv122.remote_command("apt-full-upgrade", []))], env=_env122(d), capture_output=True,
            text=True, timeout=60)
        ups = _upgrades122(d)
        verb[case] = (r.returncode, len(ups), any("Preferences" in u for u in ups), _SAID122 in r.stdout,
                      _KEPT122 in r.stdout)
    check("remote: apt-full-upgrade with a simulation apt could not finish runs the upgrade with no keep pins "
          "and says the check could not run; one that finishes still keeps (control)",
          verb == {"simulation fails": (0, 1, False, True, False), "control": (0, 1, True, False, True)},
          repr(verb))


# ── 4. install.sh ────────────────────────────────────────────────────────────────────────────────
def _install_checks122():
    text = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
    i = text.index("\n_r34a_keep_installed() {\n") + 1
    fn = _bounded122(text[i:text.index("\n}\n", i) + 3])
    got = {}
    for case, sim, dpkg in (("simulation fails", "fails", True), ("simulation hangs", "hangs", True),
                            ("no dpkg", "ok", False), ("control", "ok", True)):
        d = _bin122("install-" + case.replace(" ", "-"), sim, dpkg)
        r = _sp122.run([os.path.join(d, "bash"), "-c",  # nosec B603
                        "set -euo pipefail\nwarn() { echo \"WARN $*\"; }\n_R34A_KEEP_OPTS=()\n"
                        + fn.replace("/etc/apt/preferences", os.path.join(d, "none"))
                        + "_r34a_keep_installed\necho \"OPTS<${_R34A_KEEP_OPTS[*]:-}>\"\n"
                        "[ -z \"${_R34A_KEEP_DIR}\" ] || rm -rf -- \"${_R34A_KEEP_DIR}\"\n"],
                       env=_env122(d), capture_output=True, text=True, timeout=60)
        got[case] = (r.returncode, "OPTS<>" in r.stdout, ("WARN " + _SAID122) in r.stdout, _KEPT122 in r.stdout)
    want = dict.fromkeys(("simulation fails", "simulation hangs", "no dpkg"), (0, True, True, False))
    want["control"] = (0, False, False, True)
    check("install.sh: when the downgrade check cannot finish (the simulation fails or runs past its time, no "
          "dpkg) the upgrade gets no keep pins and the screen says the check could not run; one that "
          "finishes still keeps (control)", got == want, repr(got))


# ── 5. SECURITY.md says what the keep step is, on the verb too, with the bound the code has ───────
def _security_doc_checks122():
    text = " ".join(open(os.path.join(_root, ".github", "SECURITY.md"), encoding="utf-8").read().split())
    i = text.find("**The detached OS-update job**")
    # The entry runs to the next list item (whitespace was folded, so it starts " - **").
    para = text[i:text.find(" - **", i)] if i >= 0 else ""
    bound = "bounded to %d seconds" % _priv122._R34J_SIM_SECONDS
    got = (i >= 0, "`apt-full-upgrade` verb" in para, bound in para,
           _h122._R34J_SIM_TIMEOUT == _priv122._R34J_SIM_SECONDS, "-o Dir::Etc::Preferences=" in para,
           "the upgrade runs exactly as before" in para)
    check("docs: SECURITY.md's OS-update entry describes the downgrade keep on the bootstrap's apt-full-upgrade "
          "verb too, with the simulation's time bound the helper and the remote shell both use",
          got == (True,) * 6, repr(got))


try:
    _helper_job_checks122()
    _helper_verb_checks122()
    _remote_checks122()
    _install_checks122()
    _security_doc_checks122()
finally:
    _shutil122.rmtree(_TMP122, ignore_errors=True)
