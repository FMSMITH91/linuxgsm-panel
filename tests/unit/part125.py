"""Part 125 of the unit suite: the twenty-second review's SSH port move transaction and console drain (builder B).

* change_ssh_port is one transaction with a single COMMIT point (the table above hosts.py's
  _R32B_MOVE_UNDO). Once step 6 has verified the move nothing undoes it: the snapshot's discard that
  raised after running used to have the undo wrapper restore from a snapshot that was gone, which
  DELETES the verified drop-in (sshd back on sshd_config's port alone, the panel dialling the port just
  dropped). Before COMMIT each part of the undo runs at most once in effect, restarts only onto a config
  `sshd -t` accepts (also on _revert's own path, where a restore a transport answered -1 for may not have
  run), and a failed write's undo never restarts (nothing read the new drop-in).
* The snapshot (step 2a) is exact or the move stops: its rc is read (a failed copy exited 0 and the undo
  removed the drop-in or put half of one back), the copy lands whole or not at all, and a snapshot an
  earlier move left behind is removed when there is no drop-in, in the helper and the remote shell form.
* The live console drain of an action's output reads no further than the size it measured, so bytes
  SteamCMD appends between `stat` and `tail` are pushed once, on the next tick (they were pushed twice).
* An uninstall and a clean reboot of its host never overlap: the uninstall is refused while the reboot
  stops the host's servers (as every action that starts, stops or reconfigures one is), and a reboot is
  blocked while an uninstall runs (as it is by an install, a backup or an action).

HOW IT RUNS. On part12's stand-ins with its transport tripwire armed: the SSH move over part120's
stand-in host; the helper loaded by file with its paths in this part's temp dir; the remote shell form
and the drain's command under bash (and dash, where installed) over this part's own files. Nothing
reaches a host, sudo or the checkout's data/.
"""
import importlib.machinery as _mach125
import importlib.util as _ilu125
import os
import shutil as _shutil125
import subprocess as _sp125  # nosec B404 - bash/dash over this part's own temp files, fixed argv
import tempfile as _tf125
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_delete_server,
                         _p9_exists, _p9_json, _p9_ms, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all,
                         _p9_sh, _p9_state)
from unit.part120 import _Box120, _row120
from panel.ops.ssh_manager import hosts as _hosts125
from panel.security import privileged as _priv125
from panel.services import host_reboot as _hr125

_TRIP125_START = len(_P9_TRIPPED)
_TMP125 = _tf125.mkdtemp(prefix="lgsm-unit-p125-")
_ROOT125 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SHELLS125 = [s for s in ("bash", "dash") if _shutil125.which(s)]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The SSH port move: one COMMIT point, an undo that runs each part once before it
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Box125(_Box120):
    """part120's stand-in host, made able to SUCCEED, with the verbs this part's rows need.

    `up`: sshd comes up on 2022 once restarted (part120's never does). The discard removes the
    snapshot. `backup_rc` answers the snapshot with that rc, taking none. `reject_new`: `sshd -t`
    rejects any drop-in but the prior one. `noop` names (verb, nth call) pairs answered -1 without
    running, as the tailscale and local transports answer a lost command instead of raising.
    `write_rc` answers the drop-in write with that rc, writing nothing.
    """

    def __init__(self, up=True, backup_rc=0, reject_new=False, noop=(), write_rc=0, **kw):
        super().__init__(**kw)
        self.up, self.backup_rc, self.reject_new = up, backup_rc, reject_new
        self.noop, self.write_rc = set(noop), write_rc

    def priv(self, server, verb, args=(), **kw):
        nth = self.calls.get(verb, 0) + 1
        if (verb, nth) in self.unsent:
            return super().priv(server, verb, args, **kw)
        if (verb, nth) in self.noop:
            self._tick(verb)
            return "", "", -1
        if verb in ("sshd-backup-dropin", "sshd-socket-backup") and self.backup_rc:
            self._tick(verb)
            return "", "", self.backup_rc
        if verb in ("sshd-discard-backup", "sshd-socket-discard"):
            self.bak = None
            self._tick(verb)
            return "", "", 0
        return super().priv(server, verb, args, **kw)

    def _answer(self, verb):
        if verb == "listening-sockets" and self.up and self.calls.get("restart"):
            return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:*\n", "", 0
        if verb == "sshd-validate":
            return ("", "", 0) if not self.reject_new or self.dropin == "OLD" else ("", "Bad option", 255)
        if verb == "listening-sockets-owner":
            return "", "", 1                 # an older helper: "could not confirm", never a refusal
        return super()._answer(verb)

    def write(self, server, path, content, **kw):
        if self.write_rc:
            self._tick("write")
            return "", "refused", self.write_rc
        return super().write(server, path, content, **kw)


def _move125(box, f2b=("updated", "")):
    """One 22 -> 2022 move on `box`: what came of it, and what the host was left with."""
    _p9_patch(_p9_core, "run_privileged", box.priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_core, "write_root_file", box.write)
    _p9_patch(_hosts125, "_sshd_socket_activated", lambda s, _b=box: _b.socket)
    _p9_patch(_hosts125, "_restart_ssh_listener", box.restart)

    def _f2b(server, ports):
        if isinstance(f2b, Exception):
            raise f2b
        return f2b
    _p9_patch(_hosts125, "_point_f2b_sshd_at", _f2b)
    ok, msg = None, ""
    try:
        ok, msg = _hosts125.change_ssh_port(_row120(), 2022)
    except Exception:          # any raise is an answer here, never a crash of the part (a crash is not a catch)
        ok = "raised"
    _p9_restore_all()
    _p9_arm(who="part125")
    restore = box.calls.get("sshd-socket-restore" if box.socket else "sshd-restore-dropin", 0)
    return {"ok": ok, "kept new": str(box.dropin).startswith("# Managed"), "old": box.dropin == "OLD",
            "restores": restore, "restarts": box.calls.get("restart", 0), "allow left": box.added,
            "written": box.calls.get("write", 0), "msg": str(msg)}


def _pick125(got, *keys):
    return {case: tuple(r[k] for k in keys) for case, r in got.items()}


def _commit125():
    got = {
        "discard raises after running": _move125(_Box125(blow={("sshd-discard-backup", 1)})),
        "socket: discard raises after running": _move125(_Box125(socket=True, blow={("sshd-socket-discard", 1)})),
        "discard never sent": _move125(_Box125(unsent={("sshd-discard-backup", 1)})),
        "fail2ban step raises": _move125(_Box125(), f2b=RuntimeError("f2b")),
        "control: nothing raises": _move125(_Box125()),
    }
    check("ssh port move: once the move is VERIFIED (COMMIT) nothing undoes it — a snapshot discard that raised "
          "after running, or never reached the host, or a fail2ban step that raised, leaves the new drop-in, its "
          "allow and the answer 'moved' (the discard's raise restored from the snapshot it had just removed, "
          "which DELETES the verified drop-in: sshd back on sshd_config's port alone)",
          _pick125(got, "ok", "kept new", "restores", "restarts", "allow left")
          == {case: (True, True, 0, 1, True) for case in got}, repr(got))
    check("ssh port move: ...and a fail2ban step that raised after COMMIT is reported as fail2ban NOT updated, "
          "the move standing",
          "fail2ban was NOT" in got["fail2ban step raises"]["msg"]
          and "fail2ban was NOT" not in got["control: nothing raises"]["msg"], repr(got))


def _before_commit125():
    got = {
        # 2a: the snapshot is refused (a full disk): nothing goes on, the allow is taken back
        "snapshot refused": _move125(_Box125(backup_rc=1)),
        # 2a: the snapshot raised after it ran: no restore is owed (the drop-in was never written)
        "snapshot raises": _move125(_Box125(blow={("sshd-backup-dropin", 1)})),
        # 2b: the write failed (rc) and the close of the allow then raised: no restart owed
        "write refused, close raises": _move125(_Box125(write_rc=1, blow={("ufw-delete-allow-proto-port", 1)})),
        # 3 + _revert: the restore answered -1 without running (tailscale/local). It is tried once more
        # (review 1022b's integration: it copies the snapshot back, so a second run is safe), that one
        # puts the prior drop-in back, and sshd -t accepts it: the restart may run. part127 has the
        # case where the second one is not confirmed either.
        "restore not run, rejected config": _move125(_Box125(reject_new=True, noop={("sshd-restore-dropin", 1)})),
        # control: step 6 fails, _revert restores once and restarts once onto the restored config
        "control: not up, reverted": _move125(_Box125(up=False)),
    }
    check("ssh port move: before COMMIT an undo restores only a snapshot this move took and restarts only when "
          "the listener may have read the new drop-in and sshd -t accepts the config now — a refused snapshot "
          "stops the move with nothing written; a failed write never restarts, even when undoing it raises; a "
          "restore a transport answered -1 for never has _revert restart onto the config step 3 rejected",
          _pick125(got, "ok", "restores", "restarts", "allow left", "written")
          == {"snapshot refused": (False, 0, 0, False, 0), "snapshot raises": ("raised", 0, 0, False, 0),
              "write refused, close raises": ("raised", 1, 0, False, 1),
              "restore not run, rejected config": (False, 2, 1, False, 1),
              "control: not up, reverted": (False, 1, 2, False, 1)}, repr(got))
    check("ssh port move: ...a refused snapshot says so (it said nothing and went on), and the drop-in is "
          "back to the prior one wherever a restore ran",
          "could not be backed up" in got["snapshot refused"]["msg"]
          and got["write refused, close raises"]["old"] and got["control: not up, reverted"]["old"]
          and got["restore not run, rejected config"]["old"], repr(got))


# ── 2a's snapshot itself: the helper (panel host) and the remote shell form ─────────────────────────
def _helper125(d):
    spec = _ilu125.spec_from_loader("ph_p125", _mach125.SourceFileLoader(
        "ph_p125", os.path.join(_ROOT125, "tools", "panel-helper")))
    m = _ilu125.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.SSHD_DROPIN = os.path.join(d, "99-panel-sshport.conf")
    m.SSHD_DROPIN_BAK = m.SSHD_DROPIN + ".bak"
    m.SSHD_SOCKET_DROPIN = os.path.join(d, "sock.conf")
    m.SSHD_SOCKET_DROPIN_BAK = m.SSHD_SOCKET_DROPIN + ".bak"
    return m


def _put125(path, text):
    with open(path, "w") as f:
        f.write(text)


def _read125(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def _half_copy125(src, dst):
    _put125(dst, "Por")                    # what a full disk leaves of "Port 2222\n"
    raise OSError(28, "No space left on device")


def _helper_snapshot125():
    d = os.path.join(_TMP125, "helper")
    os.makedirs(d)
    h = _helper125(d)
    got = {}
    # an earlier move's snapshot left behind, and no drop-in now: the snapshot goes, the undo removes nothing
    _put125(h.SSHD_DROPIN_BAK, "Port 2222\nPort 22\n")
    _put125(h.SSHD_SOCKET_DROPIN_BAK, "[Socket]\n")
    h.do_sshd_backup([], None)
    h.do_sshd_socket_backup([], None)
    got["stale removed"] = (_read125(h.SSHD_DROPIN_BAK), _read125(h.SSHD_SOCKET_DROPIN_BAK))
    _put125(h.SSHD_DROPIN, "Port 2022\n")
    h.do_sshd_restore([], None)
    got["undo after it"] = _read125(h.SSHD_DROPIN)
    # a copy that fails part-way: an error, no half snapshot where the undo would read one. The snapshot
    # there is identical to the drop-in (what a confirmed restore leaves; part127 has one that differs).
    _put125(h.SSHD_DROPIN, "Port 2222\n")
    _put125(h.SSHD_DROPIN_BAK, "Port 2222\n")
    h.shutil = NS(copy2=_half_copy125)
    try:
        h.do_sshd_backup([], None)
        got["copy fails"] = "returned"
    except OSError:
        got["copy fails"] = "raised"
    got["after the failed copy"] = (_read125(h.SSHD_DROPIN_BAK), sorted(os.listdir(d)))
    h.shutil = _shutil125
    h.do_sshd_backup([], None)
    got["control: copied"] = _read125(h.SSHD_DROPIN_BAK)
    check("ssh port move snapshot (panel-helper): a snapshot an earlier move left is removed when there is no "
          "drop-in (the undo put it back), and a copy that fails raises with no half snapshot left (one was the "
          "file the undo restored); a drop-in is still copied whole (control)",
          got == {"stale removed": (None, None), "undo after it": None, "copy fails": "raised",
                  "after the failed copy": ("Port 2222\n", ["99-panel-sshport.conf", "99-panel-sshport.conf.bak"]),
                  "control: copied": "Port 2222\n"}, repr(got))


def _shell_snapshot_case125(sh, case):
    d = os.path.join(_TMP125, "sh-%s-%s" % (sh, case))
    os.makedirs(d)
    drop, bak = os.path.join(d, "drop.conf"), os.path.join(d, "drop.conf.bak")
    if case != "no drop-in":
        _put125(drop, "Port 2222\nPort 22\n")
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a temp file
        os.chmod(drop, 0o600)
    # A snapshot already there: identical to the drop-in (what a confirmed restore leaves) but 0o644, so
    # its mode says whether it was replaced; with no drop-in, one an earlier move left. part127 has one
    # that differs, which the verb keeps.
    _put125(bak, "STALE\n" if case == "no drop-in" else "Port 2222\nPort 22\n")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a temp file
    os.chmod(bak, 0o644)
    if case == "copy fails":
        # The temp name is taken by a directory: the copy cannot land (as root too, unlike a read-only dir).
        os.makedirs(bak + ".tmp/x")
    form = _priv125._r35b_snapshot_sh(drop, bak)
    rc = _sp125.run([sh, "-c", form], capture_output=True, timeout=20, check=False).returncode  # nosec B603
    mode = oct(os.stat(bak).st_mode & 0o777) if case != "no drop-in" and os.path.exists(bak) else None
    return rc == 0, _read125(bak), mode


def _shell_snapshot125():
    got = {sh: {case: _shell_snapshot_case125(sh, case) for case in ("drop-in", "no drop-in", "copy fails")}
           for sh in _SHELLS125}
    want = {"drop-in": (True, "Port 2222\nPort 22\n", "0o600"), "no drop-in": (True, None, None),
            "copy fails": (False, "Port 2222\nPort 22\n", "0o644")}
    check("ssh port move snapshot (remote shell form, bash and dash): exits non-zero when the copy fails, "
          "leaving the snapshot as it was (`|| true` exited 0, and the move went on with none), removes an "
          "earlier move's snapshot when there is no drop-in, and copies a drop-in whole with its mode",
          bool(got) and all(g == want for g in got.values()), repr(got))
    # both remote verbs render that snapshot for their own paths
    forms = (_priv125._REMOTE_ACTIONS["sshd-backup-dropin"]([]), _priv125._REMOTE_ACTIONS["sshd-socket-backup"]([]))
    check("ssh port move snapshot (remote shell form): the sshd and ssh.socket backup verbs are that exact "
          "snapshot of their own drop-ins",
          forms == (_priv125._r35b_snapshot_sh(_priv125.SSHD_DROPIN, _priv125.SSHD_DROPIN_BAK),
                    _priv125._r35b_snapshot_sh(_priv125.SSHD_SOCKET_DROPIN, _priv125.SSHD_SOCKET_DROPIN_BAK)),
          repr(forms))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The live console drain reads no further than the size it measured
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _drain125():
    d = os.path.join(_TMP125, "drain")
    shim = os.path.join(d, "bin")
    os.makedirs(shim)
    log = os.path.join(d, ".panel-update.log")
    _put125(log, "a1\na2\n")
    real_stat = _shutil125.which("stat")
    # `stat`, then SteamCMD appends a line before `tail` runs: the window the drain's own read sits in.
    _put125(os.path.join(shim, "stat"),
            '#!/bin/sh\n"%s" "$@"; n=$(cat "%s.n" 2>/dev/null || echo 0); n=$((n + 1)); '
            'echo "$n" > "%s.n"; echo "late$n" >> "%s"\n' % (real_stat, log, log, log))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- this part's stand-in
    os.chmod(os.path.join(shim, "stat"), 0o700)
    env = dict(os.environ, PATH=shim + os.pathsep + os.environ.get("PATH", ""))

    def _shell(server, user, sh, timeout=30, selfname=None):
        r = _sp125.run(["bash", "-c", sh], capture_output=True, text=True, timeout=20, env=env,  # nosec B603 B607
                       check=False)
        return r.stdout.strip(), r.stderr, r.returncode     # every transport strips stdout

    pushed = []
    _p9_patch_sm("shell_as_game_user", _shell)
    _p9_patch(_p9_sh, "_console_push", lambda app, sid, text, ts=None: pushed.append(text))
    _p9_state._action_output[90125] = {"action": "update", "path": log, "user": "p125", "pos": 0, "prev": None}
    try:
        for _ in range(3):
            _p9_sh._drain_action_output(_p9, NS(id=-125), 90125)
    finally:
        _p9_state._action_output.pop(90125, None)
    lines = [ln for text in pushed for ln in text.split("\n")]
    check("console: the live drain of an action's output reads no further than the size it measured, so a line "
          "SteamCMD appends between the drain's `stat` and `tail` reaches the console ONCE, on the next tick (it "
          "was pushed twice: a duplicated or split console line)",
          lines == ["a1", "a2", "late1", "late2"], repr(pushed))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. An uninstall and a clean reboot of its host never overlap
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _uninstall_reboot125():
    sid = _p9_new_server(P9_HOST, "p125gone", "csgo", 27125)
    ran = []
    client = _p9_client(P9_ADMIN)
    _p9_patch(_p9_ms, "_r25b_uninstall_claimed",
              lambda app, gs, remote, server_id, name: (ran.append(server_id), ("{}", 200))[1])
    got = {}
    try:
        for case, busy in (("reboot stopping the host's servers", True), ("control: no reboot", False)):
            ran.clear()
            _p9_patch(_hr125, "reboot_busy", lambda rid, _b=busy: _b)
            r = client.post("/servers/%d/delete" % sid, headers={"X-Requested-With": "XMLHttpRequest"})
            got[case] = (r.status_code, _p9_json(r).get("success"), len(ran), _p9_exists(sid),
                         sid in _p9_ms._uninstalling)
        # ...and the other way round: a reboot's preflight sees an uninstall that holds the server
        rows = [NS(id=sid, name="p125gone", status="offline")]
        with _p9_state._install_lock:
            _p9_ms._uninstalling.add(sid)
        try:
            got["reboot while it runs"] = [b["kind"] for b in _hr125._row_blockers(rows)]
        finally:
            with _p9_state._install_lock:
                _p9_ms._uninstalling.discard(sid)
        got["reboot, no uninstall (control)"] = [b["kind"] for b in _hr125._row_blockers(rows)]
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)
    check("uninstall: refused (409, nothing run, the row kept) while a clean reboot of its host is stopping the "
          "host's servers, as every action that stops or reconfigures a server there is; it went ahead and "
          "removed the account under the reboot plan; with no reboot it runs (control)",
          {k: got[k] for k in ("reboot stopping the host's servers", "control: no reboot")}
          == {"reboot stopping the host's servers": (409, False, 0, True, False),
              "control: no reboot": (200, None, 1, True, False)}, repr(got))
    check("clean reboot: an uninstall running on one of the host's servers blocks the reboot, as an install, "
          "a backup or an action does (the reboot was sent under it, leaving the account half removed)",
          got.get("reboot while it runs") == ["uninstall"] and got.get("reboot, no uninstall (control)") == [],
          repr(got))


try:
    _p9_arm(who="part125")
    for _fn125 in (_commit125, _before_commit125, _helper_snapshot125, _shell_snapshot125, _drain125,
                   _uninstall_reboot125):
        _fn125()
        _p9_restore_all()
        _p9_arm(who="part125")
finally:
    _p9_restore_all()
    _shutil125.rmtree(_TMP125, ignore_errors=True)

check("part125: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP125_START, repr(_P9_TRIPPED[_TRIP125_START:][:6]))
