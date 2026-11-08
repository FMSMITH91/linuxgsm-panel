"""Part 156 of the unit suite: review 1107's reboot, update, install and What's new fixes.

Held here:

* A host reboot decides LinuxGSM maintenance once, before it touches anything: the census counts a
  maintenance command on a STOPPED server too, and the rescan after the stops waits only on the
  servers it stopped and on any found running, so a cron `update` on a server that was stopped all
  along (or one server's `monitor` at the deadline) no longer makes it stop everything, sit out the
  stop budget and roll back.
* A forced reboot's second stop (stoponlyifnoplayers set aside) of a game the panel runs under its
  OWN account, on its own host, runs as that account directly, not `sudo -u <itself>`.
* "Reboot now" says a 60-second warning only where the panel sends one: servers LinuxGSM warns are
  stopped after LinuxGSM's own countdown, and the reply says so.
* A switch to a branch other than main is refused, before the tracked branch is saved, when that
  branch's tip is not a signed release (install.sh would not move to it, and the panel was left
  tracking a branch its checkout was not on); a signed tip is handed to the installer by its id.
* install.sh's reason for not moving to an unsigned commit names what is really missing: a root run
  with a key at root's source floor (none placed yet) is "not signed with this host's release key",
  never "no release key, rerun with PANEL_ALLOW_UNSIGNED_UPDATE=1"; no ssh-keygen says so.
* Nothing tells an operator to UPDATE or RECOVER by piping a script from GitHub into a shell: the
  fresh install's banner names the installer already on the host (the signed path), as do
  install.sh's header, recover.sh's and the README's recovery section.
* tools/sign-release.sh's warning before signing lists every file root installs from a release and
  runs (install.sh's stage_root_source callers), held equal to them here.
* An account with no "What's new" stamp (an upgrade that died between adding the column and
  stamping it, a changelog unreadable then) is stamped at the next start, not left NULL for good.
* Closing "What's new" records the changelog the page was rendered from, not the one on disk when
  the POST lands: entries an update added meanwhile are shown on the next page. An older tab never
  takes back what a newer one recorded; a malformed stamp, or none, records the file as before.
* The reboot dialog, re-drawn when "Reboot now" answers 409 (someone joined after it opened), keeps
  the plan it was opened with: its warning lines, the wait limit and "After the reboot:".

HOW IT RUNS. Pure helpers with their host reads stubbed; the reboot job's steps on part12's app
with its transport tripwire armed. Nothing reaches a host or data/.
"""
import os
import re as _re156
import shlex as _shlex156
import shutil as _shutil156
import subprocess as _sp156  # nosec B404 - git, bash and ssh-keygen over this part's own scratch files
import tempfile as _tf156
import time as _time156

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _cut47, _node47
from unit.part12 import P9_ADMIN, P9_GS, _p9, _p9_client, _p9_patch, _p9_patch_sm, _p9_restore_all
from flask import Flask as _Flask156
from sqlalchemy import text as _sa_text156

from panel.core import config as _cfg156, whats_new as _wn156
from panel.db import models as _models156
from panel.ops import system_ops as _so156
from panel.routes import _shared as _sh156
from panel.services import host_reboot as _hr156, lgsm_players as _lgp156


def _read156(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── A02A05 M: the rescan waits only on what the reboot stopped or finds running ─────────────────
# A server stopped all along, not in the plan, with LinuxGSM's `update` in flight (a cron download),
# and an id the plan holds that has settled. At the deadline the old rescan refused the reboot.
_FAR156 = 987654                     # an id no fixture row has: a server the plan never held
_settled156 = {P9_GS: {"session": 0, "maint": 0, "inflight": 0, "warn": 0},
               _FAR156: {"session": 0, "maint": 1, "inflight": 1, "warn": 0}}
_sl156 = []
_got156 = _lgp156.settled_probes(lambda: dict(_settled156), lambda: True, _sl156.append, plan_ids={P9_GS})
_mon156 = _lgp156.settled_probes(lambda: {P9_GS: {"session": 0, "inflight": 0},
                                          _FAR156: {"session": 0, "inflight": 1}},
                                 lambda: True, _sl156.append, plan_ids={P9_GS})
# ...but a server the plan holds, or one found running, is still waited on.
_plan156 = _lgp156.settled_probes(lambda: {P9_GS: {"session": 0, "maint": 1, "inflight": 1}},
                                  lambda: True, _sl156.append, plan_ids={P9_GS})
_run156 = _lgp156.settled_probes(lambda: {_FAR156: {"session": 1, "inflight": 1}},
                                 lambda: True, _sl156.append, plan_ids={P9_GS})
check("A02A05 M rescan: a LinuxGSM update (or monitor) on a server stopped all along and not in the plan is "
      "not waited on — the reboot goes ahead, no reason to refuse",
      _got156 == (_settled156, "") and _mon156[1] == "" and _sl156 == [], repr((_got156, _mon156, _sl156)))
check("A02A05 M rescan: a command on a server the plan holds, or on one found running, is still waited on "
      "(still busy at the deadline refuses, as before)",
      _plan156 == ({}, _lgp156.LG264_STILL_BUSY) and _run156 == ({}, _lgp156.LG264_STILL_BUSY),
      repr((_plan156, _run156)))

# The job passes its plan's ids: driven through _rescan with the deadline already past.
_said156 = []
try:
    _p9_patch(_hr156, "_probe_rows",
              lambda remote, rows: {P9_GS: dict(_settled156[P9_GS]), _FAR156: dict(_settled156[_FAR156])})
    with _p9.app_context():
        _gs156 = _sh156.db.session.get(_sh156.GameServer, P9_GS)
        _j156 = object.__new__(_hr156._Job)
        _j156.remote, _j156.remote_id, _j156.job = _gs156.remote, _gs156.remote_id, {"mode": "now"}
        _j156.entries = [{"id": P9_GS, "stop": "stopped", "name": "x"}]
        _j156.bounce = _j156.bounce_joined = False
        _j156.bounce_unread = _j156.bounce_why = ""
        _j156.deadline = _time156.monotonic() - 1
        _j156._sleep = _said156.append
        _j156._restop = lambda e: _said156.append(("restop", e["id"]))
        _j156._join_plan = lambda gs, probe: None
        try:
            _j156._rescan()
            _r156 = (_j156.bounce_why, list(_said156))
        except Exception as _exc156:  # noqa: BLE001 - reported by the check below, by name
            _r156 = repr(_exc156)[:120]
finally:
    _p9_restore_all()
check("A02A05 M reboot: a cron update on a stopped server outside the plan does not make the job roll the "
      "reboot back at the deadline (_rescan hands settled_probes the plan's ids)",
      _r156 == ("", []), repr(_r156))

# The census decides it instead, before anything is stopped: maintenance on a stopped server blocks;
# a warning lock on a stopped one (LinuxGSM's countdown ends at its first status check) does not.
try:
    _p9_patch(_hr156._mon, "_host_reachable", lambda remote: True)
    _p9_patch(_hr156, "_row_blockers", lambda rows: [])
    _p9_patch(_hr156, "_host_blockers", lambda remote: [])
    _p9_patch(_hr156, "_count_players", lambda running, primaries: ([], []))
    _p9_patch(_hr156._mon, "_batched_slots", lambda rows: {})
    with _p9.app_context():
        _gc156 = _sh156.db.session.get(_sh156.GameServer, P9_GS)
        _ids156 = [g.id for g in _sh156.GameServer.query.filter_by(remote_id=_gc156.remote_id).all()]
        _pr156 = {i: {"session": 0, "maint": 0, "warn": 0} for i in _ids156}
        _pr156[P9_GS] = {"session": 0, "maint": 1, "warn": 0}
        _cm156 = _hr156.host_player_state(_gc156.remote, probes=dict(_pr156))
        _pr156[P9_GS] = {"session": 0, "maint": 0, "warn": 1}
        _cw156 = _hr156.host_player_state(_gc156.remote, probes=dict(_pr156))
        _pr156[P9_GS] = {"session": 1, "maint": 1, "warn": 1}
        _cr156 = _hr156.host_player_state(_gc156.remote, probes=dict(_pr156))
        _pr156.pop(P9_GS)                            # a probe that came back with nothing for it
        _cu156 = _hr156.host_player_state(_gc156.remote, probes=dict(_pr156))
        _nm156 = _gc156.name
except Exception as _exc156c:  # noqa: BLE001 - reported by the check below, by name
    _cm156 = _cw156 = _cr156 = _cu156 = {"state": repr(_exc156c)[:120], "blockers": []}
    _nm156 = None
finally:
    _p9_restore_all()
check("A02A05 M census: LinuxGSM maintenance on a STOPPED server blocks the reboot before anything is "
      "stopped (it is no longer waited out after the stops)",
      _cm156["state"] == "blocked" and [(b["kind"], b["name"]) for b in _cm156["blockers"]]
      == [("maintenance", _nm156)], repr(_cm156))
check("A02A05 M census: a warning lock on a stopped server is not a countdown; a running one's still is, "
      "and an unread probe raises nothing",
      _cw156["state"] != "blocked" and [b["kind"] for b in _cr156["blockers"]] == ["lgsm_warning"]
      and _cu156["blockers"] == [], repr((_cw156, _cr156, _cu156)))


# ── A02A05 L: the forced stop of a game under the panel's own account, on its own host ───────────
# LinuxGSM refuses the plain stop for players; the second run must not be `sudo -u <itself>`.
_E156 = "\x1b"
_REFUSED156 = ("%s[K[%s[36m INFO %s[0m]%s[0m Stopping s156: 2 players are on the server: stop prevented%s[0m\n"
               % ((_E156,) * 5))
_ran156 = []
try:
    _p9_patch_sm("run_as_game_user", lambda *a, **k: (_REFUSED156, "", 0))
    _p9_patch_sm("run_command", lambda server, cmd, timeout=30, sudo=False, **k: (
        _ran156.append(cmd), ("", "", 0))[1])
    _p9_patch_sm("is_local_server", lambda server: True)
    _p9_patch(_hr156, "_own_account", lambda: "u156")
    _p9_patch(_hr156, "probe_server", lambda remote, e: {"session": 0})
    _p9_patch(_lgp156, "warn_minutes", lambda server, user, selfname, fresh=False: 0)
    _js156 = object.__new__(_hr156._Job)
    _js156.remote, _js156.job = object(), {"mode": "now"}
    _es156 = {"id": 1, "user": "u156", "selfname": "s156", "game_type": "gmod", "name": "x"}
    try:
        _js156._stop_one(_es156)
        _fs156 = (list(_ran156), _es156.get("stop"))
    except Exception as _exc156s:  # noqa: BLE001 - reported by the check below, by name
        _fs156 = repr(_exc156s)[:120]
finally:
    _p9_restore_all()
check("A02A05 L forced reboot stop: a game under the panel's own account on its own host gets its second "
      "stop (stoponlyifnoplayers set aside) as that account directly, not through `sudo -u <itself>`",
      isinstance(_fs156, tuple) and len(_fs156[0]) == 1 and _fs156[0][0].startswith("cd /home/u156 && ")
      and "readonly stoponlyifnoplayers=off" in _fs156[0][0] and _fs156[1] == "stopped", repr(_fs156))


# ── A02A05 L: the reboot-now reply promises the panel's 60 s warning only where the panel sends it ─
_rows156 = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
_nows156 = {}
try:
    _p9_patch(_hr156, "preflight", lambda remote, census: (True, None))
    _p9_patch_sm("is_local_server", lambda server: False)
    _p9_patch(_hr156, "warnable", lambda census: list(_rows156))
    _p9_patch(_hr156, "start_clean_reboot", lambda remote, actor, origin, mode, delay=0: True)
    _rem156 = type("R156", (), {"id": 915601, "name": "h156", "display_name": "h156"})()
    with _p9.test_request_context("/"):
        for _case156, _own156 in (("lgsm", []), ("mixed", _rows156[:1]), ("panel", list(_rows156))):
            _p9_patch(_hr156._lgp, "panel_warned", lambda remote, rows, _o=_own156: list(_o))
            _st156, _b156 = _hr156._reboot_now(_rem156, None, "web", {"probes": {}}, 0)
            _nows156[_case156] = (_st156, str(_b156.get("message")),
                                  getattr(_b156.get("message"), "template", None))
except Exception as _exc156n:  # noqa: BLE001 - reported by the checks below, by name
    _nows156["error"] = repr(_exc156n)[:160]
finally:
    _p9_restore_all()
_cat156 = _read156("panel", "translations", "es", "r37c.json") + _read156("panel", "translations", "fr", "r37c.json")
check("A02A05 L reboot now: when every warned server is LinuxGSM's to warn, the reply promises no 60-second "
      "warning — it says they stop after LinuxGSM's own countdown",
      _nows156.get("lgsm", ("",))[0] == 202 and "60-second" not in _nows156["lgsm"][1]
      and "LinuxGSM's own player warning is set, after its countdown" in _nows156["lgsm"][1], repr(_nows156))
check("A02A05 L reboot now: mixed, it names both; only the panel's, the 60-second warning as before; each "
      "worded sentence has its es and fr entry",
      "60-second" in _nows156.get("mixed", ("", ""))[1] and "after its countdown instead" in _nows156["mixed"][1]
      and "60-second" in _nows156.get("panel", ("", ""))[1] and "LinuxGSM" not in _nows156["panel"][1]
      and all(_t and ('"%s"' % _t) in _cat156
              for _t in (_nows156["lgsm"][2], _nows156["mixed"][2])), repr(_nows156))


# ── A10 M / A02A05 L: a branch switch saves the branch only once the installer will move to it ───
_TIP156 = "c" * 40


def _git156(args, timeout=45):
    if args[:1] == ["ls-remote"]:
        return ("x\trefs/heads/%s\n" % args[-1].split("/", 2)[-1], "", 0)
    if args[:1] == ["rev-parse"]:
        return (_TIP156 + "\n", "", 0)
    return ("", "", 0)


def _switch156(signed):
    cfg, launched, asked = {"panel_branch": "main"}, [], []
    try:
        _p9_patch(_so156, "_is_git_checkout", lambda: True)
        _p9_patch(_so156, "_update_in_progress", lambda: False)
        _p9_patch(_so156, "_git", _git156)
        _p9_patch(_so156, "_release_gate_for",
                  lambda branch: (lambda sha: (asked.append((branch, sha)), signed)[1]))
        _p9_patch(_so156, "_launch_installer", lambda target_ref="", branch="", started_msg=None: (
            launched.append((target_ref, branch)), (True, str(started_msg)))[1])
        _p9_patch(_cfg156, "load_config", lambda: dict(cfg))
        _p9_patch(_cfg156, "update_config", lambda fn: (fn(cfg), dict(cfg))[1])
        got = _so156.panel_switch_branch("test-x")
    except Exception as exc:  # noqa: BLE001 - reported by the checks below, by name
        got = (None, repr(exc)[:160])
    finally:
        _p9_restore_all()
    return got, cfg, launched, asked


_no156 = _switch156(False)
_yes156 = _switch156(True)
check("A10 M switch-branch: a branch other than main whose tip is not a signed release is refused, saying "
      "so — the tracked branch is NOT saved and no installer is launched",
      _no156[0][0] is False and "is not a signed release" in str(_no156[0][1]) and _TIP156[:7] in str(_no156[0][1])
      and _no156[1] == {"panel_branch": "main"} and _no156[2] == [] and _no156[3] == [("test-x", _TIP156)],
      repr(_no156))
check("A10 M switch-branch: a signed tip is switched to, handed to the installer by its full id (what was "
      "checked is what is installed), and the message no longer says it installs the tip 'as it is'",
      _yes156[0][0] is True and _yes156[2] == [(_TIP156, "test-x")] and _yes156[1] == {"panel_branch": "test-x"}
      and "AS IT IS" not in _yes156[0][1] and "signed release" in _yes156[0][1], repr(_yes156))
_newcat156 = (_read156("panel", "translations", "es", "r37c.json")
              + _read156("panel", "translations", "fr", "r37c.json"))
check("A10 M switch-branch: its sentences (refusal, switching, the dialog's) have es and fr entries",
      _newcat156.count("Not switched: the newest commit of '{branch}' ({sha}) is not a signed release") == 2
      and _newcat156.count("Switching to '{branch}' at {sha}, its newest commit: a signed release") == 2
      and _newcat156.count("FOR TESTING: this installs the newest commit on") == 2, "")


# ── A10 L: install.sh says why it did not move: the real reason, never "rerun unsigned" with a key ─
_INST156 = _read156("install.sh")
_ENV156 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
for _k156 in ("PANEL_ALLOW_UNSIGNED_UPDATE", "PANEL_SELF_UPDATE", "SUDO_UID", "PANEL_UPDATE_REF"):
    _ENV156.pop(_k156, None)


def _shfn156(name):
    """One shell function out of install.sh, whole: its definition line to its closing brace."""
    i = _INST156.index("\n" + name + "() {\n") + 1
    return _INST156[i:_INST156.index("\n}\n", i) + 3]


def _run156(argv, **kw):
    # nosec B603 - fixed argv (git, bash, ssh-keygen) over this part's own scratch files
    return _sp156.run(argv, capture_output=True, text=True, env=kw.pop("env", _ENV156), timeout=60,  # nosec B603
                      check=False, **kw)


def _why156(sb, helper, floor, path=None, tail=None, panel_dir=None):
    """RELEASE_SIG_WHY of _update_target_signed on an unsigned commit, run as root (id -u answers 0).

    `tail`: shell run instead (die prints DIED and exits); `panel_dir`: the checkout, else sb/co.
    """
    pre = ("set -uo pipefail\nwarn() { echo \"WARN $*\" >&2; }\n"
           "die() { echo \"DIED ${*//$'\\n'/ }\"; exit 1; }\n"
           "id() { if [ \"$#\" -eq 1 ] && [ \"$1\" = -u ]; then echo 0; else command id \"$@\"; fi; }\n"
           "_gitc() { git -C %s \"$@\"; }\n_rootgit() { git --git-dir=%s \"$@\"; }\n"
           "PANEL_DIR=%s\nHELPER_DIR=%s\nROOT_SRC_FLOOR_FILE=%s\nROOT_SRC_FLOOR_SEED=%s\nDEFAULT_BRANCH=main\n"
           "UNSIGNED_OVERRIDE=\nRELEASE_SIG_NS=linuxgsm-panel-release\n"
           "RELEASE_SIG_BRANCH=release-signatures\nRELEASE_SIG_REF=refs/linuxgsm-panel/release-signatures\n"
           "RELEASE_SIGNERS=release-signers\n"
           "RELEASE_SIG_FETCHED=1\n" % tuple(_shlex156.quote(x) for x in (
               panel_dir or os.path.join(sb, "co"), os.path.join(sb, "root.git"), panel_dir or os.path.join(sb, "co"),
               helper, floor, "0" * 40)))
    names = ("_ref_exists", "_release_message", "_panel_started_run", "_unsigned_override", "_source_floor",
             "_release_key_file", "_release_signed", "_update_target_signed", "_fetch_release_signatures",
             "_check_fresh_clone_signed")
    body = "".join(_shfn156(n) for n in names)
    env = dict(_ENV156, PATH=path) if path else _ENV156
    tail = tail or "_update_target_signed %s; echo \"rc=$? WHY=${RELEASE_SIG_WHY}\"\n" % ("d" * 40)
    r = _run156([_shutil156.which("bash") or "/bin/bash", "-c", pre + body + tail], env=env)
    return (r.stdout.strip().splitlines() or [""])[-1] + ("" if r.stdout.strip() else " ERR " + r.stderr[-300:])


_HAVE156 = bool(_shutil156.which("ssh-keygen")) and bool(_shutil156.which("git"))
if not _HAVE156:
    skip("A10 L install.sh unsigned reason", "git or ssh-keygen is not installed")
else:
    _SB156 = _tf156.mkdtemp(prefix="p156-")
    try:
        _key156 = os.path.join(_SB156, "k")
        _run156(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", _key156])
        with open(_key156 + ".pub", encoding="utf-8") as _fh156:
            _pub156 = "release " + " ".join(_fh156.read().split()[:2]) + "\n"
        _up156 = os.path.join(_SB156, "up")
        _run156(["git", "init", "-q", "-b", "main", _up156])
        with open(os.path.join(_up156, "release-signers"), "w", encoding="utf-8") as _fh156:
            _fh156.write(_pub156)
        _run156(["git", "-C", _up156, "add", "release-signers"])
        _run156(["git", "-C", _up156, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "A"])
        _a156 = _run156(["git", "-C", _up156, "rev-parse", "HEAD"]).stdout.strip()
        _run156(["git", "clone", "-q", "--bare", _up156, os.path.join(_SB156, "root.git")])
        _run156(["git", "clone", "-q", _up156, os.path.join(_SB156, "co")])
        _helper156 = os.path.join(_SB156, "helper")
        os.makedirs(_helper156)
        _floor156 = os.path.join(_helper156, ".source-floor")
        with open(_floor156, "w", encoding="utf-8") as _fh156:
            _fh156.write(_a156 + "\n")
        _floorkey156 = _why156(_SB156, _helper156, _floor156)
        os.unlink(_floor156)
        _nokey156 = _why156(_SB156, _helper156, _floor156)
        with open(_floor156, "w", encoding="utf-8") as _fh156:
            _fh156.write(_a156 + "\n")
        # A PATH with what the gate needs but no ssh-keygen.
        _bin156 = os.path.join(_SB156, "bin")
        os.makedirs(_bin156, mode=0o700)
        for _t156 in ("git", "mktemp", "rm", "head", "tr", "cat", "env"):
            _w156 = _shutil156.which(_t156)
            if _w156:
                os.symlink(_w156, os.path.join(_bin156, _t156))
        _nossh156 = _why156(_SB156, _helper156, _floor156, path=_bin156)
        # The fresh-clone check (the panel deleted its checkout): this host trusts the key at root's
        # source floor, so an unsigned tip is not installed; a signed one is; a host with no key
        # anywhere is a first install, trusted on first use.
        _fr156 = os.path.join(_SB156, "fresh")

        def _fresh156():
            _shutil156.rmtree(_fr156, ignore_errors=True)
            _run156(["git", "clone", "-q", _up156, _fr156])
            return _why156(_SB156, _helper156, _floor156, panel_dir=_fr156,
                           tail="_check_fresh_clone_signed; echo PASSED\n")

        _frno156 = _fresh156()
        _frno_gone156 = not os.path.exists(_fr156)
        _msg156 = os.path.join(_SB156, "msg")
        with open(_msg156, "w", encoding="utf-8") as _fh156:
            _fh156.write("linuxgsm-panel release\nbranch main\ncommit %s\n" % _a156)
        _run156(["ssh-keygen", "-q", "-Y", "sign", "-f", _key156, "-n", "linuxgsm-panel-release", _msg156])
        with open(_msg156 + ".sig", encoding="utf-8") as _fh156:
            _blob156 = _run156(["git", "-C", _up156, "hash-object", "-w", "--stdin"],
                               input=_fh156.read()).stdout.strip()
        _sub156 = _run156(["git", "-C", _up156, "mktree"],
                          input="100644 blob %s\t%s.sig\n" % (_blob156, _a156)).stdout.strip()
        _top156 = _run156(["git", "-C", _up156, "mktree"], input="040000 tree %s\tmain\n" % _sub156).stdout.strip()
        _sc156 = _run156(["git", "-C", _up156, "commit-tree", "-m", "sigs", _top156]).stdout.strip()
        _run156(["git", "-C", _up156, "update-ref", "refs/heads/release-signatures", _sc156])
        _fryes156 = _fresh156()
        _run156(["git", "-C", _up156, "update-ref", "-d", "refs/heads/release-signatures"])
        os.unlink(_floor156)
        _frtofu156 = _fresh156()
    finally:
        _shutil156.rmtree(_SB156, ignore_errors=True)
    check("A10 L install.sh (root): a host with no root key copy yet but a key at root's source floor is told the "
          "commit is not signed with its release key — not 'no release key' with the unsigned-override remedy",
          _floorkey156.startswith("rc=1 ") and "is not signed with this host's release key" in _floorkey156
          and "PANEL_ALLOW_UNSIGNED_UPDATE" not in _floorkey156, _floorkey156)
    check("A10 L install.sh (root): ...while a host with no key anywhere still gets the no-key reason and its "
          "recovery", "no release key" in _nokey156 and "PANEL_ALLOW_UNSIGNED_UPDATE=1" in _nokey156, _nokey156)
    check("A10 lead install.sh (root): a fresh clone on a host whose key is at root's source floor (no root copy "
          "placed yet) is checked against it: an unsigned tip is refused and removed, a signed one kept",
          _frno156.startswith("DIED") and "not a release signed" in _frno156 and _frno_gone156
          and _fryes156 == "PASSED", repr((_frno156, _fryes156)))
    check("A10 lead install.sh (root): ...and a host with no key anywhere still takes its first clone on trust",
          _frtofu156 == "PASSED", _frtofu156)
    check("A10 L install.sh: with no ssh-keygen the reason says ssh-keygen is missing, not 'not signed'",
          _nossh156.startswith("rc=1 ") and "ssh-keygen is not installed" in _nossh156
          and "not signed" not in _nossh156, _nossh156)


# ── A10 L: the update and recovery advice is the signed path, never `curl … | bash` again ───────
_inst_tail156 = _INST156[_INST156.index('info "[4/4] Verifying the panel is up'):]
_banner156 = [ln for ln in _inst_tail156.splitlines() if 'echo -e "  Update:' in ln]
_hints156 = [ln.strip() for ln in _INST156.splitlines() if ln.strip().startswith("UPDATE_HINT=")]
_rec156 = _read156("recover.sh")
_readme156 = _read156("docs", "README.md")
_hdr156 = _INST156[:_INST156.index("# Fresh install behaviour:")]
check("A10 L install.sh: the fresh install's Update line names the installer already on the host (root: the "
      "root-owned copy; per-user: the checkout's), never 're-run this same command' (the curl one-liner)",
      len(_banner156) == 1 and "${UPDATE_HINT}" in _banner156[0] and "same command" not in _inst_tail156
      and sorted(_hints156) == sorted([
          'UPDATE_HINT="the panel\'s Update button, or as root over SSH: cd / && sudo bash ${HELPER_DIR}/install.sh"',
          'UPDATE_HINT="the panel\'s Update button, or: bash ${PANEL_DIR}/install.sh"']), repr((_banner156, _hints156)))
check("A10 L: install.sh's header offers curl only to install, and recover.sh's header and the README's recovery "
      "section no longer pipe recover.sh from GitHub into a root shell",
      "Install OR update with ONE command" not in _hdr156
      and "sudo bash /usr/local/lib/linuxgsm-panel/install.sh" in _hdr156
      and "recover.sh | sudo bash" not in _rec156 and "recover.sh | sudo bash" not in _readme156
      and "curl" not in _rec156.split("set -euo pipefail", 1)[0], "")


# ── A10 L: the signer's root-run warning lists every file root stages from a release ────────────
_sign156 = _read156("tools", "sign-release.sh")
_flag156 = _re156.search(r"FLAGGED=.*?grep -E '([^']+)'", _sign156, _re156.S)
_args156 = [a for ln in _INST156.splitlines() if not ln.lstrip().startswith("#")
            for a in _re156.findall(r'stage_root_source ("[^"]+"|[^\s)]+) ', ln)]
_gd156 = _re156.search(r"^GAMEDIG_FILES=\(([^)]*)\)", _INST156, _re156.M)
_staged156 = set()
for _arg156 in _args156:
    _path156 = _arg156.strip('"').replace("${RELEASE_SIGNERS}", "release-signers")
    if "${f}" in _path156 and _gd156:
        _staged156.update(_path156.replace("${f}", _g156) for _g156 in _gd156.group(1).split())
    else:
        _staged156.add(_path156)
_re_flag156 = _re156.compile(_flag156.group(1)) if _flag156 else None
_alts156 = _flag156.group(1)[2:-1].split("|") if _flag156 else []
_unflagged156 = sorted(p for p in _staged156 if not (_re_flag156 and _re_flag156.match(p)))
_stale156 = [a for a in _alts156 if not a.startswith("\\.github/")
             and not any(_re156.match("^(%s)" % a, p) for p in _staged156)]
check("A10 L sign-release.sh: its 'changes what runs as root' warning flags every file install.sh stages for "
      "root from a release (db_maintenance.py, recover.sh, uninstall.sh, gamedig's files included), and "
      "names none that root does not stage",
      len(_staged156) >= 9 and _staged156 >= {"db_maintenance.py", "recover.sh", "uninstall.sh", "install.sh",
                                              "tools/gamedig/install-gamedig.sh", "tools/panel-helper",
                                              "release-signers"}
      and _unflagged156 == [] and _stale156 == [], repr((sorted(_staged156), _unflagged156, _stale156)))
check("A10 L sign-release.sh: ...and CI's workflows and the scripts they run",
      bool(_re_flag156) and bool(_re_flag156.match(".github/workflows/ci.yml"))
      and bool(_re_flag156.match(".github/scripts/complexity_gate.py")), "")


# ── A01 L: an account left with no What's new stamp is stamped at the next start ───────────────
_NOLOGIN156 = "!"               # not a hash any password matches: these rows never sign in
_TMP156 = _tf156.mkdtemp(prefix="lgsm-unit-p156-")
_mig156 = _Flask156("unit_part156_mig")
_mig156.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP156, "nostamp.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
_models156.db.init_app(_mig156)
try:
    with _mig156.app_context():
        _models156.db.create_all()
        _models156.db.session.add(_models156.User(username="p156null", password_hash=_NOLOGIN156))
        _models156.db.session.add(_models156.User(username="p156kept", password_hash=_NOLOGIN156))
        _models156.db.session.commit()
        # The column is there already (an earlier start added it) and these rows were never stamped.
        _models156.db.session.execute(_sa_text156(
            "UPDATE user SET whats_new_seen = NULL WHERE username = 'p156null'"))
        _models156.db.session.execute(_sa_text156(
            "UPDATE user SET whats_new_seen = 'abc:1' WHERE username = 'p156kept'"))
        _models156.db.session.commit()
        _models156._run_light_migrations()
        _st156 = dict(_models156.db.session.execute(_sa_text156(
            "SELECT username, whats_new_seen FROM user")).all())
        _models156.db.session.remove()
except Exception as _exc156w:  # noqa: BLE001 - reported by the check below, by name
    _st156 = {"error": repr(_exc156w)[:160]}
finally:
    _shutil156.rmtree(_TMP156, ignore_errors=True)
_now156 = _wn156.current_stamp()
check("A01 L what's new: an account with no stamp (the start that added the column died before stamping it, "
      "or the changelog could not be read) is stamped at the next start; a stamped one is left alone",
      bool(_now156) and _st156.get("p156null") == _now156 and _st156.get("p156kept") == "abc:1",
      repr({k: (v or "")[:20] for k, v in _st156.items()}))


# ── A01 L: dismissing "What's new" records what the page showed, not the changelog at POST time ─
def _wnrow156():
    with _p9.app_context():
        return _models156.db.session.get(_models156.User, P9_ADMIN).whats_new_seen


def _wnput156(v):
    with _p9.app_context():
        _models156.db.session.get(_models156.User, P9_ADMIN).whats_new_seen = v
        _models156.db.session.commit()


def _wnkeys156(v):
    return set((v or "").partition(":")[2].split(",")) - {""}


_c1_156 = [{"category": "Added", "title": "C1 entry %d" % i, "body": "", "key": "%08x" % (0x156000 + i)}
           for i in range(6)]
_c2_156 = [{"category": "Fixed", "title": "C2 entry %d" % i, "body": "", "key": "%08x" % (0x156100 + i)}
           for i in range(2)] + _c1_156
_wnsaved156 = _wnrow156()
_wn156r = {}
try:
    _wcl156 = _p9_client(P9_ADMIN)
    _cur156 = {"e": _c1_156}
    _p9_patch(_wn156, "current_entries", lambda path=None: _cur156["e"])
    _wnput156(_wn156.stamp(_c1_156[3:]))                          # behind C1 by three entries
    _pg156 = _wcl156.get("/account").get_data(as_text=True)
    _m156 = _re156.search(r'data-seen-stamp="([^"]*)"', _pg156)
    _wn156r["rendered"] = _m156.group(1) if _m156 else None
    _cur156["e"] = _c2_156                                        # an update lands; then the dialog is closed
    _wn156r["post"] = _wcl156.post("/api/account/whats-new/seen", json={"stamp": _wn156r["rendered"]}).status_code
    _wn156r["row"] = _wnrow156()
    _nx156 = _wcl156.get("/account").get_data(as_text=True)
    _wn156r["next"] = _nx156[_nx156.find('<dialog id="whats-new"'):_nx156.find("</dialog>")]
    # An older tab closed after a newer one: what the newer recorded stays.
    _wnput156(_wn156.stamp(_c2_156))
    _wcl156.post("/api/account/whats-new/seen", json={"stamp": _wn156.stamp(_c1_156[3:])})
    _wn156r["older"] = _wnrow156()
    # Not a stamp (or none, a tab from before this): the changelog as it is, as before.
    _wnput156(_wn156.stamp(_c1_156))
    _wcl156.post("/api/account/whats-new/seen", json={"stamp": "zz:" + "1" * 9000})
    _wn156r["bad"] = _wnrow156()
    _wnput156(_wn156.stamp(_c1_156))
    _wcl156.post("/api/account/whats-new/seen")
    _wn156r["none"] = _wnrow156()
except Exception as _exc156x:  # noqa: BLE001 - reported by the checks below, by name
    _wn156r["error"] = repr(_exc156x)[:160]
finally:
    _p9_restore_all()
    _wnput156(_wnsaved156)
check("A01 L what's new: the dialog carries the stamp of the changelog it was rendered from",
      _wn156r.get("rendered") == _wn156.stamp(_c1_156), repr(_wn156r.get("rendered"))[:120])
check("A01 L what's new: closing it after an update landed records only what the page showed — the "
      "update's own entries are on the next page, and only they",
      _wn156r.get("post") == 200 and _wnkeys156(_wn156r.get("row")) == {e["key"] for e in _c1_156}
      and all("C2 entry %d" % i in _wn156r.get("next", "") for i in range(2))
      and "C1 entry" not in _wn156r.get("next", "x"), repr({k: str(v)[:80] for k, v in _wn156r.items()}))
check("A01 L what's new: a dialog closed in an older tab does not take back what a newer one recorded; a "
      "malformed stamp, or none, records the changelog as it is",
      _wnkeys156(_wn156r.get("older")) == {e["key"] for e in _c2_156}
      and _wn156r.get("bad") == _wn156.stamp(_c2_156) and _wn156r.get("none") == _wn156.stamp(_c2_156),
      repr({k: str(v)[:60] for k, v in _wn156r.items()}))
_appjs156 = _read156("panel", "static", "js", "app_shell.js")
check("A01 L what's new: the page posts the stamp it was rendered with when the dialog closes",
      "wn.getAttribute('data-seen-stamp')" in _appjs156 and "JSON.stringify({stamp: shown})" in _appjs156, "")


# ── A12a L: the reboot dialog keeps its plan when "Reboot now" answers 409 ───────────────────────
_nags156 = _read156("panel", "static", "js", "nags.js")
_prog156 = (
    "global.window = global; global.MOUNT = '';\n"
    "const renders = [];\n"
    "function _rbOpen(label){ return {label: label}; }\n"
    "function _rbRender(dlg, host, players, plan){ renders.push({players: players, plan: plan, host: host}); }\n"
    "function _rbFailed(){ renders.push('failed'); }\n"
    "function _rbDone(){ renders.push('done'); }\n"
    "const PLAN = {servers: [{id: 1, name: 'a', warn_minutes: 5}], wait_hours: 24};\n"
    "global.fetch = path => Promise.resolve({ok: true, json: () => Promise.resolve(\n"
    "  path.indexOf('/players') >= 0 ? {state: 'idle', busy: []} : PLAN)});\n"
    + _cut47(_nags156, "function _rbAnswer(") + "\n"
    + _cut47(_nags156, "window.rebootHost = function(") + "\n"
    "(async () => {\n"
    "  window.rebootHost(7, 'h', false);\n"
    "  for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));\n"
    "  const first = renders[0];\n"
    "  _rbAnswer({}, first.host, {code: 409, d: {needs_choice: true, players: {state: 'busy', busy: [{id: 1}]}}});\n"
    "  const again = renders[1];\n"
    "  console.log(JSON.stringify({n: renders.length, first: first.plan, again: again && again.plan,\n"
    "                              players: again && again.players}));\n"
    "})();\n")
_on156 = _node47(_prog156)
if _on156 is None:
    skip("A12a L reboot dialog keeps its plan on 409", "node is not installed")
else:
    check("A12a L reboot dialog: when 'Reboot now' answers 409 (a player joined after it opened), the dialog is "
          "re-drawn with the players AND the plan it was opened with (warning lines, wait limit, After the reboot)",
          _on156.get("n") == 2 and _on156.get("again") == _on156.get("first") is not None
          and (_on156.get("again") or {}).get("wait_hours") == 24
          and (_on156.get("players") or {}).get("state") == "busy", repr(_on156))
