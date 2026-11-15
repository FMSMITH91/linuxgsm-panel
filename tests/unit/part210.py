"""Part 210 of the unit suite: the panel's own cost in CPU, memory, network and disk, cut where it was measured.

Held here, each against the code that made the cost:
* The host sample and the one-game sample run ONE `ps` each (they ran four), and still report every
  figure: both /proc/stat CPU lines, the jiffies on both sides of the window, RSS, process count and
  the oldest process's age.

HOW IT RUNS. Host commands are stubbed on their definition sites behind part12's tripwire; a sample
command runs for real, with bash, behind a `ps` that counts its runs. Routes run on part12's app.
"""
import os
import pwd as _pwd210
import shutil as _shutil210
import subprocess as _sp210  # nosec B404 - runs bash on this part's own fixtures
import tempfile as _tf210
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part12 import _p9_arm, _p9_patch_sm, _p9_restore_all
from panel.ops.ssh_manager import _core as _core210

_TMP210 = _tf210.mkdtemp(prefix="lgsm-unit-p210-")
_ME210 = _pwd210.getpwuid(os.getuid()).pw_name


# ── One ps per sample ──────────────────────────────────────────────────────────────────────────
def _ps_rig210():
    """(bin dir, log): a `ps` that writes one line to the log per run, then runs the real one."""
    d = os.path.join(_TMP210, "psbin")
    os.makedirs(d, exist_ok=True)
    log = os.path.join(_TMP210, "ps.log")
    with open(os.path.join(d, "ps"), "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho ps >> "%s"\nexec %s "$@"\n' % (log, _shutil210.which("ps")))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs
    os.chmod(os.path.join(d, "ps"), 0o700)  # nosec B103 - owner-only test stand-in
    return d, log


def _counted210(rig):
    """run_command's stand-in: the command run by bash behind the counting ps; (out, err, rc)."""
    d, log = rig
    outs = []

    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        r = _sp210.run(["bash", "-c", command], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                       env=dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", "")), check=False)
        outs.append(r.stdout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    return _run, outs, log


def _ps_runs210(log):
    try:
        with open(log, encoding="utf-8") as fh:
            n = fh.read().count("ps")
        os.remove(log)
        return n
    except OSError:
        return 0


def _tags210(out):
    """{tag: lines} of one sample's output, for the tags the samplers print per process set."""
    tags = {}
    for line in (out or "").splitlines():
        f = line.split()
        if f and f[0] in ("cpu", "GJA", "GJB", "GAMERAM", "GUP"):
            tags.setdefault(f[0], []).append(f)
    return tags


def _one_ps210():
    """host_live_metrics and server_live_metrics, each through run_command: one ps, every figure."""
    run, outs, log = _counted210(_ps_rig210())
    _p9_patch_sm("run_command", run)
    _ps_runs210(log)
    host = _core210.host_live_metrics(NS(id=-210), force=True)
    runs, tags = _ps_runs210(log), _tags210(outs[-1] if outs else "")
    mine = host["users"].get(_ME210, {})
    check("host sample: ONE ps for the whole sample (it ran four: the jiffies before and after the window, "
          "RSS, uptime), and every figure is still there",
          runs == 1 and len(tags.get("cpu", [])) == 2
          and any(f[1] == _ME210 for f in tags.get("GJA", [])) and any(f[1] == _ME210 for f in tags.get("GJB", []))
          and mine.get("game_procs", 0) >= 1 and mine.get("game_ram_mb", -1) >= 0
          and mine.get("game_uptime_secs", 0) > 0 and host["host"]["ram_total"] > 0,
          repr((runs, sorted(tags), mine)))
    game = _core210.server_live_metrics(NS(id=-210), short_name=_ME210, game_port=None, force=True)
    runs, tags = _ps_runs210(log), _tags210(outs[-1] if outs else "")
    check("one-game sample: ONE ps (it ran four, and an awk per process twice), and every figure is still there",
          runs == 1 and len(tags.get("cpu", [])) == 2 and len(tags.get("GJA", [])) == 1
          and len(tags.get("GJB", [])) == 1 and game["game_procs"] >= 1 and game["game_uptime_secs"] > 0
          and game["ram_total"] > 0, repr((runs, sorted(tags), game)))
    gone = _core210.server_live_metrics(NS(id=-2101), short_name="nosuchuser210", game_port=None, force=True)
    eq("one-game sample: an account with no process reads zero of everything, and the host's figures stay",
       ([f for k in ("GJA", "GJB", "GAMERAM", "GUP") for f in _tags210(outs[-1]).get(k, [])],
        gone["game_procs"], gone["ram_total"] > 0),
       ([["GJA", "0"], ["GJB", "0"], ["GAMERAM", "0", "0"], ["GUP", "0"]], 0, True))


try:
    for _fn210 in (_one_ps210,):
        _p9_restore_all()
        _p9_arm(who="part210")
        _fn210()
finally:
    _p9_restore_all()
    _shutil210.rmtree(_TMP210, ignore_errors=True)
