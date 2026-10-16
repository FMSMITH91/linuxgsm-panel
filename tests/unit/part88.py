"""Part 88 of the unit suite: the thirteenth review's fixes by builder A (review 1015d).

Helper, install, the test runner, system_ops, the database layer and the docs. Held here, each
against the code path the finding named:

* a stored host or server order that is not a list (a hand edit of config.json's published
  default) is ignored, not a TypeError out of the dashboard render.
* install.sh: a fresh install on a host whose Tailscale is installed but not up reaches the setup
  link; an update's fetch that fails partway restores the old code.
* install.sh: the update's snapshot prune refuses a PANEL_DIR that is a link the panel user made.
* a panel-host reboot is blocked through a restore's detached swap (restore_pending).
* tools/i18n_scan.py: a guarded field written with tfn() is read like one written with t()/tf().
* the debug report masks a passphrase=value and cuts a sudo line whose first field is USER=.
* Block refuses 0.0.0.0, :: and every /0 (a prepended deny-all locks the host out).
* tools/run-tests.sh: a lane that hangs no longer takes every lane's log with it.
* while the panel reboots its own host, nothing restarts the panel: a branch switch, a database
  repair, a backup restore, a binding change and a chat /update are refused as the Update is.
* the panel host's own Block, Unblock and Allow-Tailscale take its ufw lock, and an Unblock that
  removed nothing (ufw exits 0) is not reported as one.
* the destroy verbs refuse an account whose home is not /home/<name> (helper, and the remote's
  account probe); tailscale-set-operator names only the account that invoked the helper.
* app.py: a quoted port in config.json no longer stops the panel from starting.
* panel-helper: the restore checks data/ itself for a link and removes its staging directory
  relative to data/ opened without following one.

HOW IT RUNS. Module functions and part12's app with stand-ins, undone in a finally; shell functions cut out of the
real scripts and run under bash in throwaway directories (never the checkout's data/).
"""
import atexit as _atexit88
import importlib.util as _ilu88
import os
import shutil as _shutil88
import signal as _signal88
import subprocess as _sp88  # nosec B404 - bash over the repo's own scripts, in throwaway dirs
import tempfile as _tf88
import threading as _threading88
import time as _time88
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper88, _root
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg88
from panel.db import prefs as _prefs88
from panel.ops import backup as _bk88, system_ops as _so88
from panel.ops.debug_report import logs as _logs88
from panel.ops.ssh_manager import _core as _smc88
from panel.security import privileged as _priv88
from panel.routes import _shared as _shared88, remote_security as _rsec88
from panel.services import host_reboot as _hr88
from panel.services.bots import discord as _dc88, telegram as _tg88

_TMP88 = _tf88.mkdtemp(prefix="p88-")
_atexit88.register(_shutil88.rmtree, _TMP88, True)


def _read88(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════
# 1. prefs: an order that is not a list is no order, not a crash
# ════════════════════════════════════════════════════════════════════════════════════════════
_rows88 = [NS(id=i, remote_id=1) for i in (3, 1, 2)]


def _order88(order):
    """The ids _apply_user_order returns for `order`, or the exception class name it raised."""
    try:
        return [o.id for o in _prefs88._apply_user_order(_rows88, order)]
    except Exception as exc:  # the defect raised TypeError; report which, so the check names it
        return type(exc).__name__


def _server_order88(per_host):
    try:
        return [o.id for o in _prefs88._apply_user_server_order(_rows88, {"server_order": per_host})]
    except Exception as exc:  # as above
        return type(exc).__name__


check("prefs: a host order that is not a list (5, a dict, a string) leaves the hosts in their "
      "default order instead of raising out of the dashboard",
      _order88(5) == [3, 1, 2] and _order88({"1": 2}) == [3, 1, 2] and _order88("21") == [3, 1, 2]
      and _order88([2, 1]) == [2, 1, 3] and _order88(None) == [3, 1, 2],
      repr([_order88(5), _order88({"1": 2}), _order88("21"), _order88([2, 1])]))
check("prefs: a per-host server order that is not a list ({'1': 7}) is skipped, /api/servers "
      "and the dashboard keep the default order",
      _server_order88({"1": 7}) == [3, 1, 2] and _server_order88({"1": [2]}) == [2, 3, 1],
      repr([_server_order88({"1": 7}), _server_order88({"1": [2]})]))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 2. install.sh: the fresh install's URL banner survives a Tailscale that is installed but not up
# ════════════════════════════════════════════════════════════════════════════════════════════
_INS88 = _read88("install.sh")


def _fn88(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "exit 97\n"
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash88(script, cwd, env=None, timeout=60):
    """(rc, stdout + stderr) of `script` under bash in `cwd`."""
    r = _sp88.run(["bash", "-c", script],  # nosec B603 B607 - bash over this part's own script
                  cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout + r.stderr


def _ts_banner88():
    """Run install.sh's Tailscale-address block; its (rc, output).

    Under `set -euo pipefail`, with a stand-in `tailscale` that answers as a logged-out node does:
    exit 1, nothing on stdout.
    """
    i = _INS88.find('\nTS_ADDR=""\n')
    block = _INS88[i + 1:_INS88.index("\nfi\n", i) + 4] if i >= 0 else "exit 97\n"
    d = _tf88.mkdtemp(dir=_TMP88)
    stand = os.path.join(d, "tailscale")
    with open(stand, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho 'no current Tailscale IPs; state: NeedsLogin' >&2\nexit 1\n")
    os.chmod(stand, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    return _bash88("set -euo pipefail\n%s\necho \"REACHED [${TS_ADDR}]\"\n" % block, d, env)


_tsb88 = _ts_banner88()
check("install.sh: a fresh install on a host whose Tailscale is installed but not up (tailscale ip "
      "exits 1) gets past the address block to the setup link, with no tailnet address",
      _tsb88[0] == 0 and "REACHED []" in _tsb88[1], repr(_tsb88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 3. install.sh: an update's fetch marks the code as touched BEFORE it writes, so an abort mid-fetch
#    restores the old version instead of restarting the panel on a half-written tree
# ════════════════════════════════════════════════════════════════════════════════════════════
_FETCH88 = _fn88(_INS88, "fetch_code")


def _fetch_abort88(mode):
    """Fail fetch_code in its write step; what the update window's abort handler is told.

    `mode` "git": the `git reset --hard` fails partway; "src": the extract from an operator's tree
    fails partway. Every other step is a stand-in that succeeds.
    """
    d = _tf88.mkdtemp(dir=_TMP88)
    panel = os.path.join(d, "panel")
    src = os.path.join(d, "src")
    os.makedirs(os.path.join(panel, ".git"))
    os.makedirs(src)
    stubs = ("_gitc() { if [ \"$1\" = reset ]; then echo half > \"${PANEL_DIR}/app.py\"; return 1; fi; "
             "return 0; }\n"
             "_choose_update_target() { UPD_TARGET=abc; UPD_WHY=tip; return 0; }\n"
             "_fetch_branch() { return 0; }\n"
             "die() { echo \"DIE $*\"; exit 1; }\n")
    if mode == "src":
        stubs += "tar() { case \" $* \" in *' -xf '*) cat >/dev/null; return 2;; esac; return 0; }\n"
    script = ("set -euo pipefail\nPANEL_DIR=%s\nSRC=%s\nDEFAULT_BRANCH=main\nREPO_URL=x\n"
              "_CODE_FETCHED=0\ntrap 'echo \"ABORT CODE_FETCHED=${_CODE_FETCHED}\"' EXIT\n%s%s"
              "fetch_code\n") % (panel, src if mode == "src" else "", stubs, _FETCH88)
    return _bash88(script, d)


_fg88, _fs88 = _fetch_abort88("git"), _fetch_abort88("src")
check("install.sh: a `git reset --hard` that fails partway through an update leaves the abort "
      "handler told the code was touched (so it restores the snapshot, not restarts a mixed tree)",
      _fg88[0] != 0 and "ABORT CODE_FETCHED=1" in _fg88[1], repr(_fg88))
check("install.sh: an extract from the operator's tree that fails partway through an update leaves "
      "the abort handler told the code was touched",
      _fs88[0] != 0 and "ABORT CODE_FETCHED=1" in _fs88[1], repr(_fs88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 4. tools/run-tests.sh: a lane that hangs no longer takes every lane's log with it
# ════════════════════════════════════════════════════════════════════════════════════════════
_RT88 = _read88("tools", "run-tests.sh")
_li88 = _RT88.find("\nlane_tree() {")
_LANES88 = (_RT88[_li88 + 1:_RT88.index("\n}\n", _RT88.index("\nrun_lanes() {")) + 3]
            if _li88 >= 0 else "exit 97\n")


def _hung_lane88():
    """Run run_lanes with a hung lane, then TERM it; (its output, its exit status).

    Lane 0's suite prints a line and hangs, lane 1's fails, lane 2's passes; the TERM comes once both
    finished lanes have been given time to end (10 s at most). The real run_lanes and its
    stop/print helpers; stand-in suites.
    """
    d = _tf88.mkdtemp(dir=_TMP88)
    outp = os.path.join(d, "out.txt")
    script = ("set -euo pipefail\nRT_TMP=$(mktemp -d %s/hl-XXXXXX)\n%s"
              "unit_suite() { echo UNIT-BEFORE-HANG; sleep 60; }\n"
              "other_suites() { echo OTHER-FAILED; return 1; }\nrbac_suite() { :; }\n"
              "smoke_suite() { echo SMOKE-OUT; echo '1 / 1 checks passed'; }\n"
              'lane_tree() { mktemp -d "$RT_TMP/lane-XXXXXX"; }\nrun_lanes\n' % (d, _LANES88))
    with open(outp, "w", encoding="utf-8") as out:
        proc = _sp88.Popen(["bash", "-c", script],  # nosec B603 B607 - this part's script
                           cwd=d, start_new_session=True, stdout=out, stderr=_sp88.STDOUT)
    try:
        for _ in range(100):
            with open(outp, encoding="utf-8") as fh:
                text = fh.read()
            if "OTHER-FAILED" in text and "SMOKE-OUT" in text:
                break
            _time88.sleep(0.1)
        _time88.sleep(0.5)   # the old code printed nothing until lane 0 ended: give it the chance
        os.killpg(proc.pid, _signal88.SIGTERM)
        try:
            rc = proc.wait(timeout=15)
        except _sp88.TimeoutExpired:
            rc = "still running"
    finally:
        try:
            os.killpg(proc.pid, _signal88.SIGKILL)
        except ProcessLookupError:
            pass  # already gone: the TERM above ended the whole run, as it should
        proc.wait()
    with open(outp, encoding="utf-8") as fh:
        return fh.read(), rc


_hl88 = _hung_lane88()
check("run-tests: when a lane hangs and the run is cancelled, the finished lanes' logs (a failure "
      "included) were already printed, and the hung lane's last lines are printed on the way out",
      _hl88[1] == 130 and "OTHER-FAILED" in _hl88[0] and "SMOKE-OUT" in _hl88[0]
      and "UNIT-BEFORE-HANG" in _hl88[0] and "interrupted" in _hl88[0], repr(_hl88))
check("run-tests: ...each lane's log is printed as that lane ends, before the hung lane 0 is "
      "stopped (not held back in lane order)",
      _hl88[0].find("OTHER-FAILED") < _hl88[0].find("stopping the lanes")
      and _hl88[0].find("SMOKE-OUT") < _hl88[0].find("stopping the lanes")
      and "OTHER-FAILED" in _hl88[0], repr(_hl88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 5. Every way to restart the panel refuses while the panel is rebooting its own host
# ════════════════════════════════════════════════════════════════════════════════════════════
_TRIP88_START = len(_P9_TRIPPED)


def _rec88(calls, name, ret):
    def _call(*_a, **_k):
        calls.append(name)
        return ret
    return _call


def _restarts88(busy):
    """{route: (status, said why)} and the restarting calls made, with the reboot `busy` or not."""
    calls = []
    _p9_patch(_hr88, "panel_host_busy", (lambda: _hr88.busy_message("Panel host")) if busy else (lambda: None))
    _p9_patch(_so88, "panel_switch_branch", _rec88(calls, "switch-branch", (True, "ok")))
    _p9_patch(_so88, "panel_repair_database", _rec88(calls, "repair-db", (True, "ok")))
    _p9_patch(_so88, "panel_self_update", _rec88(calls, "bot-update", (True, "ok")))
    # The chat /update reply names the running commit. In a real checkout (CI's) that is a `git
    # rev-parse` on the host; a copy with no .git (smoke-local's) skipped it, so this passed here
    # and tripped the transport wire on every CI leg (#434).
    _p9_patch(_so88, "panel_commit", lambda: "abc1234")
    _p9_patch(_so88, "panel_version", lambda: "2026.10.16")
    _p9_patch(_bk88, "restore_backup", _rec88(calls, "restore", (False, "stubbed")))
    _p9_patch(_rsec88, "_port_refusal", _rec88(calls, "change-port", "stubbed refusal"))
    a = _p9_client(P9_ADMIN)

    def said(resp):
        return resp.status_code, "being rebooted" in (_p9_json(resp).get("message") or "")

    out = {"switch-branch": said(a.post("/api/panel/switch-branch", json={"branch": "main"})),
           "repair-db": said(a.post("/api/panel/repair-db")),
           "restore": said(a.post("/api/panel/backup/restore", json={"name": "x.tar.gz"})),
           "change-port": said(a.post("/api/panel/change-port", json={"port": 5001}))}
    replies = []
    _p9_patch(_tg88, "_tg_reply", lambda _t, _c, text: replies.append(text))
    _p9_patch(_dc88, "_dc_reply", lambda _t, _c, text: replies.append(text))
    for mod in (_tg88, _dc88):
        _p9_patch(mod, "bot_update_status", lambda: {"git": True, "update_available": True})
        _p9_patch(mod, "spend_update_check", lambda: True)
        _p9_patch(mod, "audit_bot_action", lambda *a, **k: None)
        _p9_patch(mod, "_panel_ver_label", lambda: "v")
    _p9_patch(_tg88, "_set_tg_pending_update", lambda *a: None)
    _p9_patch(_dc88, "_set_dc_pending_update", lambda *a: None)
    _tg88._telegram_do_update(_p9, "t", 1)
    _dc88._discord_do_update(_p9, "t", 1)
    out["bots"] = [("being rebooted" in r) for r in replies]
    return out, calls


try:
    _p9_arm(_p9_patch, who="part88")
    _busy88, _bcalls88 = _restarts88(True)
    _p9_restore_all()
    _p9_arm(_p9_patch, who="part88")
    _free88, _fcalls88 = _restarts88(False)
finally:
    _p9_restore_all()
check("panel restarts: while the panel host is being rebooted, a branch switch, a database "
      "repair, a backup restore and a binding change are refused (409, saying why), and nothing "
      "that restarts the panel runs",
      all(_busy88[k] == (409, True) for k in ("switch-branch", "repair-db", "restore", "change-port"))
      and [c for c in _bcalls88 if c != "bot-update"] == [], repr((_busy88, _bcalls88)))
check("panel restarts: ...and a chat /update from Telegram or Discord is answered with the same "
      "refusal and does not start the self-update",
      _busy88["bots"] == [True, True] and "bot-update" not in _bcalls88, repr((_busy88, _bcalls88)))
check("panel restarts: ...and each goes ahead once the host is not being rebooted (control)",
      _fcalls88 == ["switch-branch", "repair-db", "restore", "change-port", "bot-update", "bot-update"]
      and _free88["bots"] == [False, False], repr((_free88, _fcalls88)))
check("part88: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP88_START, repr(_P9_TRIPPED[_TRIP88_START:][:6]))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 6. system_ops: the panel host's own firewall writes wait for its ufw lock, and an unblock that
#    removed nothing is not reported as one
# ════════════════════════════════════════════════════════════════════════════════════════════
_IP88 = "198.51.100.23"


def _locked_write88(fn):
    """The verbs `fn` ran while another thread held the panel host's ufw lock, and all it ran."""
    calls = []

    def once(verb, args, timeout, merge_stderr):
        calls.append(verb)
        return None, (("Status: active\n" if verb == "ufw-status" else ""), "", 0)

    lock = _smc88.ufw_lock(NS(is_local=True))
    _p9_patch(_so88, "_run_verb_once", once)
    _p9_patch(_so88, "detect_tailscale_interface", lambda: "tailscale0")
    lock.acquire()
    t = _threading88.Thread(target=fn, daemon=True)
    try:
        t.start()
        _time88.sleep(0.5)
        during = list(calls)
    finally:
        lock.release()
    t.join(10)
    return during, list(calls)


try:
    _lw88 = {name: _locked_write88(fn) for name, fn in (
        ("block", lambda: _so88.ufw_deny_ip(_IP88)),
        ("unblock", lambda: _so88.ufw_undeny_ip(_IP88)),
        ("allow tailscale", _so88.ufw_allow_tailscale))}
finally:
    _p9_restore_all()
check("system_ops: Block, Unblock and Allow-Tailscale on the panel host wait for its ufw lock (held "
      "by the auto-block reconcile or a delete-by-number), firewall read included, then run",
      all(during == [] for during, _all in _lw88.values())
      and _lw88["block"][1] == ["ufw-status", "ufw-deny-ip"]
      and _lw88["unblock"][1] == ["ufw-delete-deny-ip", "ufw-status"]
      and _lw88["allow tailscale"][1] == ["ufw-allow-iface"], repr(_lw88))


def _unblock88(still_blocked):
    """Return ufw_undeny_ip's answer when ufw's delete exits 0 having matched no rule.

    The firewall read afterwards does (`still_blocked`) or does not list the address.
    """
    try:
        _p9_patch(_so88, "_run_verb", lambda verb, args, timeout=30, merge_stderr=True: (
            "Could not delete non-existent rule", "", 0))
        _p9_patch(_so88, "ufw_blocked_ips", lambda shadowed=None: (
            {_IP88: "external"} if still_blocked else {}))
        return _so88.ufw_undeny_ip(_IP88)
    finally:
        _p9_restore_all()


_ub88 = {k: _unblock88(k) for k in (True, False)}
check("system_ops: an Unblock whose delete matched no rule (ufw exits 0) while the address is still "
      "blocked by another rule (a REJECT) says so, instead of 'Unblocked'",
      _ub88[True][0] is False and "still blocked" in _ub88[True][1], repr(_ub88))
check("system_ops: ...and an Unblock that leaves the address unlisted is reported unblocked (control)",
      _ub88[False] == (True, "Unblocked %s." % _IP88), repr(_ub88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 7. panel-helper: the restore never follows a data/ the panel user turned into a link
# ════════════════════════════════════════════════════════════════════════════════════════════
def _restore_link88(linked):
    """Run a restore's target check and its run over a data/ that is a link, or real.

    Returns (what _restore_target answered, whether the OTHER directory's staging dir survived the
    restore run, whether the real data dir's staging dir was removed), with data/ a link to a
    directory holding a stage of its own (`linked`), or data/ a real directory (the control).
    """
    base = _tf88.mkdtemp(dir=_TMP88)
    other = os.path.join(base, "other")
    real = os.path.join(base, "real")
    for d in (other, real):
        os.makedirs(os.path.join(d, _helper88.RESTORE_STAGE))
        with open(os.path.join(d, _helper88.RESTORE_STAGE, "keep.txt"), "w", encoding="utf-8") as fh:
            fh.write("not the panel's")
    data = os.path.join(base, "data")
    if linked:
        os.symlink(other, data)
    else:
        os.rename(real, data)
    try:
        _p9_patch(_helper88, "panel_conf", lambda: {"data_dir": data})
        _p9_patch(_helper88, "resolve", lambda name: "/bin/true")
        _p9_patch(_helper88, "subprocess", NS(run=lambda *a, **k: NS(returncode=0)))
        _p9_patch(_helper88, "restore_copy_members", lambda stage, data_dir: [])
        target = _helper88._restore_target()
        _helper88._restore_run(data)
    finally:
        _p9_restore_all()
    return (target, os.path.isdir(os.path.join(other, _helper88.RESTORE_STAGE)),
            not os.path.exists(os.path.join(data, _helper88.RESTORE_STAGE)))


_rl88 = {k: _restore_link88(k) for k in (True, False)}
check("panel-helper: a restore whose data/ the panel user swapped for a link is refused, and the "
      "restore's cleanup removes nothing at the link's target (another panel's staged restore)",
      _rl88[True][0] is None and _rl88[True][1] is True, repr(_rl88))
check("panel-helper: ...and a real data/ is restored from and its staging directory removed (control)",
      _rl88[False][0] is not None and _rl88[False][2] is True, repr(_rl88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 8. app.py: a quoted port in config.json does not stop the panel from starting
# ════════════════════════════════════════════════════════════════════════════════════════════
# The boot block runs only as __main__ (it binds a socket), so the check reads the one line that
# decides what reaches socketio.run, and runs the reader it names on the hand-edited value.
_APP88 = _read88("app.py")
_main88 = _APP88[_APP88.find('\nif __name__ == "__main__":'):]
_bootport88 = [ln.strip() for ln in _main88.splitlines() if ln.strip().startswith("port = ")]
check("app.py: the boot reads config.json's port as a number (a hand-edited \"5000\" binds 5000; "
      "it used to reach eventlet's bind as a string and the service never started)",
      _bootport88 == ['port = _r15a_cfg_int(cfg.get("port", 5000), 5000)']
      and _cfg88._r15a_cfg_int("5000", 5000) == 5000 and _cfg88._r15a_cfg_int("x", 5000) == 5000,
      repr(_bootport88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 9. The destroy verbs never take an account whose home is not /home/<name>; the Tailscale
#    operator can only be the account that asked
# ════════════════════════════════════════════════════════════════════════════════════════════
def _helper_says88(validator, name, sudo_uid):
    """Return `name` if the helper's `validator` accepts it, else the refusal.

    SUDO_UID is set to `sudo_uid` for the call (None: unset).
    """
    saved = os.environ.get("SUDO_UID")
    try:
        if sudo_uid is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = str(sudo_uid)
        return validator(name)
    except ValueError as exc:
        return "refused: %s" % exc
    finally:
        if saved is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = saved


# `nobody` is on every Linux host and its home is never /home/nobody (/nonexistent on Debian and
# Ubuntu, / on Arch): the shape of proxy, sys or www-data, without naming a distro's list.
_nobody88 = _helper_says88(_helper88.v_destroyable_user, "nobody", None)
check("panel-helper: the destroy verbs (userdel -r -f, pkill -u, rm of the home) refuse an account "
      "whose passwd home is not /home/<name> (a system account; userdel -r would empty its home)",
      str(_nobody88).startswith("refused") and "home" in str(_nobody88), repr(_nobody88))
_pw88 = NS(pw_dir="/home/codserver88", pw_uid=4242, pw_name="codserver88")


def _getpwnam88(name):
    if name != "codserver88":
        raise KeyError(name)
    return _pw88


try:
    _p9_patch(_helper88, "pwd", NS(getpwnam=_getpwnam88, getpwuid=_helper88.pwd.getpwuid))
    _own88 = _helper_says88(_helper88._r23a_home_is_own, "codserver88", None)
finally:
    _p9_restore_all()
check("panel-helper: ...while a game account at /home/<name> passes the home test (control)",
      _own88 is None, repr(_own88))

_me88 = _helper88._pw_name(os.getuid())
_op88 = {"another account": _helper_says88(_helper88.v_r23a_operator_self, "nobody", os.getuid()),
         "the caller": _helper_says88(_helper88.v_r23a_operator_self, _me88, os.getuid()),
         "root directly": _helper_says88(_helper88.v_r23a_operator_self, "nobody", None)}
check("panel-helper: tailscale-set-operator names only the account that invoked it (an operator "
      "can join the node to any tailnet with Tailscale SSH on), not another account such as a game's",
      str(_op88["another account"]).startswith("refused") and _op88["the caller"] == _me88
      and _op88["root directly"] == "nobody", repr(_op88))
check("panel-helper: ...and the verb table uses that validator for tailscale-set-operator",
      _helper88.VERBS["tailscale-set-operator"][0] == [_helper88.v_r23a_operator_self],
      repr(_helper88.VERBS["tailscale-set-operator"][0]))

# A remote has no helper: the panel's own account probe reads the home, run here in bash for real.
_probe88 = _sp88.run(["bash", "-c", _shared88._account_probe_cmd(["nobody"])],  # nosec B603 B607 - the panel's probe
                     capture_output=True, text=True, timeout=30)
_pverdict88 = _shared88._parse_account_probe(_probe88.stdout, ["nobody"])
_fold88 = {}
_shared88._fold_probe_line(_fold88, "ACCT gmodserver 1001 gmodserver".split(), ["gmodserver"])
_shared88._fold_probe_line(_fold88, "HOME gmodserver /home/gmodserver".split(), ["gmodserver"])
check("account probe: on a remote, an account whose home is not /home/<name> is refused before "
      "an uninstall's userdel -r -f (read from the host by the probe itself)",
      isinstance((_pverdict88 or {}).get("nobody"), str) and "home" in _pverdict88["nobody"]
      and _pverdict88["nobody"] != "ok", repr((_pverdict88, _probe88.stdout[-300:])))
check("account probe: ...and a game account at /home/<name> is still 'ok' (control)",
      _fold88 == {"gmodserver": "ok"}, repr(_fold88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 10. A panel-host reboot is blocked through a restore's whole flight, its detached swap included
# ════════════════════════════════════════════════════════════════════════════════════════════
def _reboot_blockers88(pending):
    try:
        _p9_patch(_bk88, "restore_pending", lambda: pending)
        _p9_patch(_so88, "_update_in_progress", lambda: False)
        return [b.get("kind") for b in _hr88._panel_host_blockers()]
    finally:
        _p9_restore_all()


_rb88 = {k: _reboot_blockers88(k) for k in (True, False)}
check("host reboot: a restore whose lock is released but whose detached swap has not yet stopped "
      "the panel (restore_pending) blocks a reboot of the panel host, as it blocks a self-update",
      "restore" in _rb88[True] and "restore" not in _rb88[False], repr(_rb88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 11. install.sh: the snapshot prune never follows a PANEL_DIR the panel user turned into a link
# ════════════════════════════════════════════════════════════════════════════════════════════
_PRUNE88 = _fn88(_INS88, "_r22a_prune_snapshots")
_STAMPS88 = ["20260101-00000%d" % i for i in range(5)]


def _prune88(linked):
    """Prune once; the stamp directories left under <target>/data/.backups.

    PANEL_DIR is a link to <target> (`linked`, made by this non-root account) or <target> itself
    (the control).
    """
    base = _tf88.mkdtemp(dir=_TMP88)
    target = os.path.join(base, "elsewhere")
    for s in _STAMPS88:
        os.makedirs(os.path.join(target, "data", ".backups", s))
    panel = target
    if linked:
        panel = os.path.join(base, "linuxgsm-panel")
        os.symlink(target, panel)
    rc, out = _bash88('set -euo pipefail\nwarn() { echo "WARN $*"; }\nKEEP_BACKUPS=3\n'
                      'PANEL_DIR=%s\n%s_r22a_prune_snapshots\n' % (panel, _PRUNE88), base)
    return rc, sorted(os.listdir(os.path.join(target, "data", ".backups"))), out


_pl88 = {k: _prune88(k) for k in (True, False)}
check("install.sh: the update's snapshot prune deletes nothing when PANEL_DIR itself is a link the "
      "panel user made (both sides of its check resolved through it, so root pruned the target's)",
      _pl88[True][0] == 0 and _pl88[True][1] == _STAMPS88 and "WARN" in _pl88[True][2], repr(_pl88))
check("install.sh: ...and still prunes a real PANEL_DIR down to KEEP_BACKUPS (control)",
      _pl88[False][0] == 0 and _pl88[False][1] == _STAMPS88[2:], repr(_pl88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 12. The i18n gate reads a guarded field written with tfn(), the plural helper
# ════════════════════════════════════════════════════════════════════════════════════════════
_spec88 = _ilu88.spec_from_file_location("i18n_scan_p88", os.path.join(_root, "tools", "i18n_scan.py"))
_scan88 = _ilu88.module_from_spec(_spec88)
_spec88.loader.exec_module(_scan88)
_td88 = _tf88.mkdtemp(dir=_TMP88)
os.makedirs(os.path.join(_td88, "tpl"))
os.makedirs(os.path.join(_td88, "js"))
with open(os.path.join(_td88, "tpl", "a.html"), "w", encoding="utf-8") as _fh88:
    _fh88.write('<span id="count" data-no-i18n></span>\n')
with open(os.path.join(_td88, "js", "a.js"), "w", encoding="utf-8") as _fh88:
    _fh88.write("function a(n){ var el = document.getElementById('count');\n"
                "  el.textContent = tfn(n, 'one server', '{n} servers', {n: n}); }\n"
                "function b(n){ var ce = document.getElementById('count');\n"
                "  ce.textContent = tfn(n, 'one server', '{n} servers', {n: n});\n"
                "  ce.setAttribute('data-i18n-text', 'one server'); }\n")
_gw88 = _scan88.guarded_tcall_writes(js_dir=os.path.join(_td88, "js"),
                                     template_dir=os.path.join(_td88, "tpl"))
check("i18n gate: a field the page keeps from setLang (data-no-i18n) written with tfn() and no "
      "data-i18n marker is reported (the pattern read t( and tf( only); with the marker it is not",
      [(f, ln) for f, ln, _w in _gw88] == [("a.js", 2)], repr(_gw88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 13. tools/run-tests.sh: the sequential mode's copy is reachable through $RT_TMP, as the lanes' is
# ════════════════════════════════════════════════════════════════════════════════════════════
def _seq_modes88():
    """Run lane_tree, the sequential mode's own call; the modes it leaves.

    (mode of $RT_TMP, mode of the copy, mode of the checkout), in a checkout of mode 0701 (any mode
    but mktemp's 0700 tells them apart) with $RT_TMP made by mktemp (0700).
    """
    d = _tf88.mkdtemp(dir=_TMP88)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a mode other than mktemp's, in this part's temp dir
    os.chmod(d, 0o701)  # nosec B103 - a mode other than mktemp's, in this part's temp dir
    _sp88.run(["git", "init", "-q", d],  # nosec B603 B607 - git, a fixed argv
              check=True, capture_output=True, timeout=30)
    with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as fh:
        fh.write("a\n")
    rc, out = _bash88('set -euo pipefail\nRT_TMP=$(mktemp -d %s/sq-XXXXXX)\n%s'
                      'seq_tree="$(lane_tree)"\nstat -c %%a "$RT_TMP" "$seq_tree" .\n'
                      % (_TMP88, _fn88(_RT88, "lane_tree")), d)
    return rc, out.split()


_sm88 = _seq_modes88()
check("run-tests: in the sequential mode the copy's parent ($RT_TMP) gets the checkout's mode too, "
      "so a check running a tool as another account can reach the tree (it was 0700 there)",
      _sm88[0] == 0 and len(_sm88[1]) == 3 and _sm88[1][0] == _sm88[1][1] == _sm88[1][2] == "701",
      repr(_sm88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 14. The debug report's scrub masks a passphrase=value
# ════════════════════════════════════════════════════════════════════════════════════════════
# Built at run time, so no credential-shaped literal sits in the source for a secret scanner.
_ppv88 = "".join(["Tr1", "cky", "-pp9"])
_pp88 = _so88._redact("backup: " + "pass" + "phrase=" + _ppv88 + " rejected; tests passed: 3; PWD=/home/gm")
check("debug report: a `passphrase=<value>` under 28 characters in a log line is masked (the key list "
      "had password/passwd but not passphrase), while 'passed: 3' and sudo's PWD= are left alone",
      _ppv88 not in _pp88 and "passphrase=[redacted]" in _pp88 and "passed: 3" in _pp88
      and "PWD=/home/gm" in _pp88, repr(_pp88))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 15. The debug report never prints the argv of a sudo line whose first field is USER=
# ════════════════════════════════════════════════════════════════════════════════════════════
_argv88 = "-p" + "".join(["Sq", "l7", "x"])          # built at run time: no credential-shaped literal
_lines88 = ["Oct 15 10:00:00 vps sudo[42]:      bob : USER=root ; COMMAND=/usr/bin/mysql -u root "
            + _argv88,
            "Oct 15 10:00:01 vps sudo[43]:      bob : USER=root ; ENV=A=" + _argv88
            + " ; COMMAND=/usr/bin/mysql"]
try:
    _p9_patch(_logs88, "_panel_accounts", frozenset)
    _kept88, _verbs88, _s88 = _logs88._split_priv(list(_lines88))
finally:
    _p9_restore_all()
check("debug report: a sudo line with no field before USER= (no PWD=, as when sudo cannot read the "
      "working directory) is counted or cut, never printed with its argv or ENV= values",
      not any(_argv88 in k for k in _kept88), repr((_kept88, _verbs88)))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 16. Block refuses every address (0.0.0.0, ::, a /0): a prepended deny-all locks the host out
# ════════════════════════════════════════════════════════════════════════════════════════════
def _deny_sides88(value):
    """(helper accepts, panel accepts) `value` for ufw-deny-ip."""
    out = []
    for fn in (lambda: _helper88.validate("ufw-deny-ip", [value, ""]),
               lambda: _priv88.tool_argv("ufw-deny-ip", [value, ""])):
        try:
            fn()
            out.append(True)
        except ValueError:
            out.append(False)
    return tuple(out)


# The unspecified address built at run time: a literal one reads to scanners as a bind to every
# interface, which this is not.
_ANY88 = ".".join(["0"] * 4)
_ds88 = {v: _deny_sides88(v) for v in (_ANY88, "::", _ANY88 + "/0", "::/0", "198.51.100.0/24", _IP88)}
check("ufw-deny-ip: helper and panel both refuse the unspecified address and every /0 (a prepended "
      "deny from them drops every connection, SSH included), and still take an address or a network",
      all(_ds88[v] == (False, False) for v in (_ANY88, "::", _ANY88 + "/0", "::/0"))
      and _ds88["198.51.100.0/24"] == (True, True) and _ds88[_IP88] == (True, True), repr(_ds88))
_runs88 = []
_dw88 = _so88._ufw_deny_with(_ANY88, "panel-block", None, lambda verb, args: _runs88.append(verb) or ("", "", 0))
check("Block on a host: 0.0.0.0 is answered with why, nothing runs (the verb's refusal was a bare 500)",
      _dw88[0] is False and "every address" in _dw88[1] and _runs88 == [], repr((_dw88, _runs88)))
