r"""Part 181 of the unit suite: review 1112's fixes, group r.

* A background Start/Stop/Restart or long action whose host call RAISES (a direct-SSH host that is
  down) writes its failed outcome row: `restart_server` / `update_complete`, as a tailscale or local
  host's rc -1 already did. Driven through the action route on part12's app.
* A full backup run counts a server held by its scheduled wipe (or a queued stop/restart) apart from
  "skipped (players online)", and in "disconnect players" mode queues it to back up afterwards.
* A switch to main hands over the required update stop (panel/install/update-stops) between this
  checkout and main's newest verified commit, as the installer installs it, and refuses while that
  stop is unsigned or its checks have not passed.
* The debug report's Updates section names the stop an update offers or is held by, instead of
  calling the stop origin's tip or the verified commit "unverified".
* uninstall.sh removes /usr/local/lib/linuxgsm-panel (the root-owned uninstaller copy) last, so a run
  stopped in a slow step can be finished by running that copy again.

HOW IT RUNS. The routes on part12's app with its transport tripwire armed and every host call
replaced; the stop rule over this part's own scratch git history (git on local paths only, CI and
signatures stood in); the uninstall region under bash on fixture paths, with the account, sysctl,
fail2ban and Tailscale commands replaced by shell functions. Nothing reaches a host, sudo or data/.
"""
import os
import shlex as _shlex181
import shutil as _sh181
import subprocess as _sp181  # nosec B404 - git and bash on this part's own fixtures, fixed argv
import tempfile as _tf181

from unit.part01 import _root, check
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _P9Thread, _p9_arm, _p9_audit, _p9_audit_count,
                         _p9_client, _p9_delete_server, _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm,
                         _p9_restore_all, _p9_row, _p9_threading)
from panel.core import runtime_stats as _rs181
from panel.ops import system_ops as _so181
from panel.ops.debug_report import updates as _up181
from panel.ops.debug_report._base import Result as _Result181
from panel.routes import _shared as _sh_r181, panel_backup as _pb181, server_detail as _sd181
from panel.services import lgsm_players as _lgp181

_TMP181 = _tf181.mkdtemp(prefix="p181-")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A background action whose host call raises is audited as failed (A08)
# ════════════════════════════════════════════════════════════════════════════════════════════════


def _host_down181(*a, **k):
    raise ConnectionError("p181: the host did not answer")


def _teed_down181(*a, **k):
    raise ConnectionError("p181: dropped mid-update")


_r181 = {}
_s181 = _p9_new_server(P9_HOST, "p181s", "csgo", 41810, name="p181-power", status="online")
try:
    _p9_arm(who="part181")
    _trips181 = len(_P9_TRIPPED)
    _p9_patch(_sd181, "threading", _p9_threading(_P9Thread))
    _p9_patch(_sh_r181, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd181, "_live_run_state", lambda gs, remote: True)
    _p9_patch(_lgp181, "allowance_seconds", lambda *a, **k: 0)
    _p9_patch_sm("run_as_game_user", _host_down181)
    _p9_patch(_sd181, "_run_teed", _teed_down181)
    _A181 = _p9_client(P9_ADMIN)
    for _act181, _row181 in (("restart", "restart_server"), ("update", "update_complete")):
        _n181 = _p9_audit_count(_row181)
        _resp181 = _A181.post("/api/server/%d/action" % _s181, json={"action": _act181})
        _p9_drain()
        _r181[_act181] = (_resp181.status_code, _p9_audit_count(_row181) - _n181, _p9_audit(_row181))
    _r181["trips"] = _P9_TRIPPED[_trips181:]
finally:
    _p9_restore_all()
    _p9_delete_server(_s181)

_rs_181 = _r181.get("restart", (0, 0, None))
check("A08: a background Restart whose host call raises (a direct-SSH host that is down) writes one failed "
      "restart_server row naming why, as a tailscale or local host's rc -1 is audited (it wrote no row at all)",
      _rs_181[0] == 200 and _rs_181[1] == 1 and _rs_181[2].success is False
      and _rs_181[2].target == "p181-power" and "the host did not answer" in _rs_181[2].detail, repr(_rs_181))
_up_181 = _r181.get("update", (0, 0, None))
check("A08: ...and a long action whose run raises writes its failed update_complete row (the log read as an "
      "update that started and never ended)",
      _up_181[0] == 200 and _up_181[1] == 1 and _up_181[2].success is False
      and "dropped mid-update" in _up_181[2].detail, repr(_up_181))
check("A08: ...with nothing sent to a host", _r181.get("trips") == [], repr(_r181.get("trips")))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A full backup run: a server held by its wipe is not "skipped (players online)" (A09)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_fb181 = {"summary": [], "queued": [], "ran": []}
_h181 = _p9_new_server(P9_HOST, "p181h", "csgo", 41820, name="p181-held")
_gbs181 = dict(_pb181._game_backup_status)


def _backup181(server, user, *a, **k):
    _fb181["ran"].append(user)
    return True, "backed up", False


try:
    _p9_arm(who="part181")
    _trips_fb181 = len(_P9_TRIPPED)
    _p9_patch(_pb181, "threading", _p9_threading(_P9Thread))
    _p9_patch(_pb181, "run_game_backup", _backup181)
    _p9_patch(_sh_r181, "_r39a_backup_held", lambda sid, wipe_ok=False: sid == _h181)
    _p9_patch(_pb181, "_record_full_clock", lambda app, summary: _fb181["summary"].append(summary))
    _p9_patch(_pb181, "_record_game_clock", lambda app, sid, gname: None)
    _p9_patch(_pb181.bk, "record_queued", _fb181["queued"].append)
    _A_fb181 = _p9_client(P9_ADMIN)
    _resp_fb181 = _A_fb181.post("/api/panel/backup/full", json={"mode": "now"})
    _p9_drain()
    _fb181["status"] = _resp_fb181.status_code
    _fb181["pending"] = _p9_row(_h181).backup_pending
    _fb181["trips"] = _P9_TRIPPED[_trips_fb181:]
finally:
    _p9_restore_all()
    _p9_delete_server(_h181)
    _pb181._game_backup_status.clear()
    _pb181._game_backup_status.update(_gbs181)

_sum181 = (_fb181["summary"] or [""])[-1]
check("A09: \"Back up game servers now\" (disconnect players) reports a server its scheduled wipe held as "
      "skipped for that, by name, never as \"skipped (players online)\"",
      _fb181.get("status") == 200 and "skipped (players online)" not in _sum181
      and "1 skipped (a scheduled wipe or a queued stop or restart was running: p181-held)" in _sum181
      and "p181h" not in _fb181["ran"], repr((_fb181, _sum181)))
check("A09: ...and queues it to back up once that is over, in that mode too (players were not what stopped it)",
      _fb181.get("pending") is True and _h181 in _fb181["queued"] and "will back up once empty: p181-held" in _sum181
      and _fb181.get("trips") == [], repr(_fb181))
_t181 = _pb181._FullBackupTally()
_t181.skip_n = 2
check("A09: ...while a players-online skip still reads as one (control)",
      _t181.summary() == "0 server(s) backed up, 2 skipped (players online)", _t181.summary())

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The required update stop: a switch to main, and the debug report (A02A05, A06A07)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_GENV181 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
                GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
                GIT_COMMITTER_EMAIL="t@example.invalid")


def _git181(*args):
    # git on this part's own fixture repositories, with no global or system config
    return _sp181.run(["git", *args], capture_output=True, text=True, env=_GENV181,  # nosec B603 B607
                      check=False).stdout.strip()


def _commit181(repo, msg, stops=None):
    if stops is not None:
        os.makedirs(os.path.join(repo, "panel", "install"), exist_ok=True)
        with open(os.path.join(repo, "panel", "install", "update-stops"), "w", encoding="utf-8") as fh:
            fh.write("# required stops\n" + "".join(s + "  a required release\n" for s in stops))
        _git181("-C", repo, "add", "-A")
    _git181("-C", repo, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", msg)
    return _git181("-C", repo, "rev-parse", "HEAD")


# main: A - S - B, where B (main's newest verified commit) lists S as a required stop.
_UP181 = os.path.join(_TMP181, "up")
_git181("init", "-q", "-b", "main", _UP181)
_C181 = {n: _commit181(_UP181, n) for n in ("A", "S")}
_C181["B"] = _commit181(_UP181, "B", stops=[_C181["S"]])
_CO181 = os.path.join(_TMP181, "co")
_git181("clone", "-q", _UP181, _CO181)
_git181("-C", _CO181, "reset", "-q", "--hard", _C181["A"])

_SAVED181 = {n: getattr(_so181, n) for n in ("PANEL_DIR", "_remote_ci_state", "_release_gate_for",
                                              "_update_touches_runtime", "_tracked_branch")}
_sw181 = {}
_dbg181 = {}
try:
    _so181.PANEL_DIR = _CO181
    _so181._remote_ci_state = lambda sha: "passing"
    _so181._update_touches_runtime = lambda ref: True
    _so181._tracked_branch = lambda: "main"
    for _k181, _signed181 in (("all signed", None), ("stop unsigned", _C181["S"])):
        _so181._release_gate_for = (lambda unsigned: (lambda branch: (lambda sha: sha != unsigned)))(_signed181)
        _tgt181, _msg181 = _so181._r37c_switch_target("main")
        _sw181[_k181] = (_tgt181, str(_msg181))
        # ...the caller: refused before the tracked branch is saved (nothing launches)
        if _k181 == "stop unsigned":
            _sw181["switch"] = _so181.panel_switch_branch("main")
        _st181 = _so181._compute_update_status()
        _res181 = _Result181()
        _up181._status_lines(_st181, _res181)
        _up181._walk_lines(_rs181.snapshot("ci_walk"), _res181)
        _dbg181[_k181] = "\n".join(_res181.lines)
finally:
    for _n181, _v181 in _SAVED181.items():
        setattr(_so181, _n181, _v181)

_S7_181, _B7_181 = _C181["S"][:7], _C181["B"][:7]
_ok_sw181 = _sw181.get("all signed", ("", ""))
check("A02A05: a switch to main behind a required update stop hands the installer the stop (what install.sh "
      "installs), and its message names it and the newer release that follows (it named main's newest verified "
      "commit)", _ok_sw181[0] == _C181["S"] and "a required update stop" in _ok_sw181[1]
      and _S7_181 in _ok_sw181[1] and _B7_181 in _ok_sw181[1], repr((_C181, _sw181)))
_held_sw181 = _sw181.get("stop unsigned", ("x", ""))
_call181 = _sw181.get("switch", (True, ""))
check("A02A05: ...and while that stop is unsigned the switch is refused naming it, through panel_switch_branch "
      "too, before the tracked branch is saved (the installer would hold on a branch already saved as main)",
      _held_sw181[0] == "" and _S7_181 in _held_sw181[1] and "'unsigned'" in _held_sw181[1]
      and _call181[0] is False and _S7_181 in str(_call181[1]), repr((_sw181, _call181)))
_da181 = _dbg181.get("all signed", "")
check("A06A07: the debug report's Updates section says an offered stop is a required update stop with the newer "
      "release after it, never origin's tip, and the CI walk line names the stop as what was offered",
      "offered %s (a required update stop; %s is offered after it)" % (_S7_181, _B7_181) in _da181
      and "origin/main's tip" not in _da181 and "→ offered %s" % _S7_181 in _da181, _da181)
_db181 = _dbg181.get("stop unsigned", "")
check("A06A07: ...and an update held by an unsigned stop is shown held by it, with the verified commit not "
      "called an unverified tip and the walk offering nothing",
      "held by required update stop %s (unsigned)" % _S7_181 in _db181
      and "held: required update stop %s is unsigned" % _S7_181 in _db181
      and "ci_state=unsigned" in _db181 and "newest unverified tip" not in _db181
      and "nothing offered" in _db181, _db181)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. uninstall.sh: the root-owned uninstaller copy outlives every slow step (A10)
# ════════════════════════════════════════════════════════════════════════════════════════════════
with open(os.path.join(_root, "panel", "install", "uninstall.sh"), encoding="utf-8") as _fh181:
    _UNI181 = _fh181.read()
_U_A181 = _UNI181.find("_gamedig_link_ours() {")
_U_B181 = _UNI181.find("# ── What stays: host configuration")
_UBLK181 = _UNI181[_U_A181:_U_B181] if 0 <= _U_A181 < _U_B181 else "echo NO_REGION\n"


def _uninst181(mode):
    """Run the shared-piece and account region as a `mode` uninstall on fixture paths; its output."""
    d = _tf181.mkdtemp(dir=_TMP181)
    lib, etc, homes = (os.path.join(d, n) for n in ("lib", "etc", "home"))
    for sub in (lib, os.path.join(etc, "sysctl.d"), os.path.join(etc, "fail2ban", "jail.d"),
                os.path.join(homes, "lgsmpanel"), os.path.join(d, "bin")):
        os.makedirs(sub)
    for f in (os.path.join(lib, "uninstall.sh"), os.path.join(etc, "sysctl.d", "99-linuxgsm-panel.conf"),
              os.path.join(etc, "fail2ban", "jail.d", "linuxgsm-panel.conf")):
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("x\n")
    probe = '[[ -e %s ]] && echo present || echo gone' % _shlex181.quote(os.path.join(lib, "uninstall.sh"))
    # Each stand-in writes to a trace file: the script sends their output to /dev/null.
    trace = os.path.join(d, "trace")
    tq = _shlex181.quote(trace)
    fbin = os.path.join(d, "bin") + "/"
    region = (_UBLK181.replace("/usr/local/lib/linuxgsm-panel", lib).replace("/etc/", etc + "/")
              .replace("/usr/local/bin/", fbin).replace("/usr/bin/", fbin)
              .replace("        _r25a_release_ts_operator\n", "        :\n"))
    script = ("set -euo pipefail\n"
              'ok(){ echo "OK: $*"; }\nwarn(){ echo "WARN: $*"; }\ninfo(){ echo "INFO: $*"; }\nsudo_note(){ :; }\n'
              'fail2ban-client(){ echo "COPY_AT_F2B=$(%s)" >> %s; }\n' % (probe, tq)
              + 'sysctl(){ echo "COPY_AT_SYSCTL=$(%s)" >> %s; }\n' % (probe, tq)
              + 'userdel(){ echo "COPY_AT_USERDEL=$(%s)" >> %s; }\n' % (probe, tq)
              + "id(){ return 0; }\nloginctl(){ :; }\n"
              + "getent(){ echo 'lgsmpanel:x:1:1::%s/lgsmpanel:/bin/bash'; }\n" % homes
              + "MODE=%s SERVICE_USER=lgsmpanel PANEL_USER=lgsmpanel HOMES=%s U_SUDO='' SHARED_MINE=1\n"
              % (mode, _shlex181.quote(homes))
              + region + '\necho "COPY_AT_END=$(%s)"\n' % probe)
    r = _sp181.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   stdin=_sp181.DEVNULL, check=False)
    traced = ""
    if os.path.exists(trace):
        with open(trace, encoding="utf-8") as fh:
            traced = fh.read()
    return "rc=%d\n%s%s%s" % (r.returncode, traced, r.stdout, r.stderr)


_un181 = {m: _uninst181(m) for m in ("system", "user")}
check("A10: uninstall.sh keeps the root-owned uninstaller copy through fail2ban's reload, the sysctl reload and "
      "the account's removal, so a run stopped in any of them can be finished by running that copy again (it "
      "was deleted before them)",
      all(("COPY_AT_%s=present" % k) in _un181["system"] for k in ("F2B", "SYSCTL", "USERDEL"))
      and "rc=0" in _un181["system"], _un181["system"][-1500:])
check("A10: ...and still removes it at the end, on a system and a per-user uninstall",
      all("COPY_AT_END=gone" in _un181[m] and "Removed the root-owned helper" in _un181[m] for m in _un181),
      repr({m: v[-600:] for m, v in _un181.items()}))

_sh181.rmtree(_TMP181, ignore_errors=True)
