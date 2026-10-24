"""Part 129 of the unit suite: review 1022c, builder B — an SSH port move's undo says what it could not confirm.

* The "restore could not be confirmed" message said "the previous one is kept at <bak>" whatever the
  snapshot (step 2a) had found. With no drop-in before the move there is no <bak> (the snapshot verb
  removes any), and the step that recovers that host, removing the drop-in, was not said. The snapshot
  verbs (the helper and the remote shell form) now print which of the two they did, and the message
  follows it; a helper too old to print it gets a message naming both cases.
* Each part of the undo was retired however it answered. A Tailscale or local transport answers a lost
  command -1 instead of raising, so a failed close of the step-1 allow left a public allow for a port
  nothing serves under "nothing changed" (also on step 1's own refusals), a failed daemon-reload left
  systemd holding the moved socket unit, and a failed restart was not said. The close and the reload
  are run once more (both idempotent: a by-spec `ufw delete` exits 0 removing nothing once the rule is
  gone); what is still not confirmed is added to the answer.
* A restore whose answer was lost after it went out (paramiko's `command_started`) was retired
  unconfirmed and unsaid. The restore copies and keeps the snapshot (or removes a drop-in that had
  none), so it is now run once more at once, and said when that is not confirmed either.
* Step 3's `sshd -t` that gave no answer (-1) no longer reports "sshd rejected the new config".

HOW IT RUNS. The move over part125's stand-in host (part120's, able to succeed) on part12's stand-ins
with its transport tripwire armed; the remote snapshot form under bash (and dash, where installed) over
this part's own files; the helper loaded by file with its paths in this part's temp dir. Nothing reaches
a host, sudo or the checkout's data/.
"""
import contextlib as _ctx129
import importlib.machinery as _mach129
import importlib.util as _ilu129
import io as _io129
import logging as _logging129
import os
import shutil as _shutil129
import subprocess as _sp129  # nosec B404 - bash/dash over this part's own temp files, fixed argv
import tempfile as _tf129

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_core, _p9_patch, _p9_restore_all
from unit.part120 import _row120
from unit.part125 import _Box125, _move125
from panel.ops.ssh_manager import hosts as _hosts129
from panel.security import privileged as _priv129

_TRIP129_START = len(_P9_TRIPPED)
_TMP129 = _tf129.mkdtemp(prefix="lgsm-unit-p129-")
_ROOT129 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SHELLS129 = [s for s in ("bash", "dash") if _shutil129.which(s)]
_D129, _B129 = _priv129.SSHD_DROPIN, _priv129.SSHD_DROPIN_BAK
_SD129, _SB129 = _priv129.SSHD_SOCKET_DROPIN, _priv129.SSHD_SOCKET_DROPIN_BAK


class _Box129(_Box125):
    """part125's stand-in host, with four more knobs.

    `none_before`: no drop-in before the move. `old_helper`: its snapshot verb prints nothing.
    `hide`: the firewall never lists the new port's allow. `restart_rc`: what restarting the
    listener answers.
    """

    def __init__(self, none_before=False, old_helper=False, hide=False, restart_rc=0, **kw):
        # The drop-in through the base's constructor, not set again here (CodeQL
        # py/overwritten-inherited-attribute).
        super().__init__(**dict(kw, dropin=None) if none_before else kw)
        self.old_helper, self.hide, self.restart_rc = old_helper, hide, restart_rc

    def _answer(self, verb):
        out, err, rc = super()._answer(verb)
        if self.old_helper and verb in ("sshd-backup-dropin", "sshd-socket-backup"):
            out = ""
        if self.hide and verb in ("ufw-status", "ufw-show-added"):
            out = "".join(ln for ln in out.splitlines(True) if "2022" not in ln)
        return out, err, rc

    def restart(self, server, socket_mode=False):
        self._tick("restart")
        return "", "", self.restart_rc


def _rs129(socket):
    return {("sshd-socket-restore" if socket else "sshd-restore-dropin", n) for n in (1, 2)}


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The unconfirmed restore's message follows what the snapshot found
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _prior129():
    got = {
        "no drop-in before": _move125(_Box129(none_before=True, reject_new=True, noop=_rs129(False))),
        "socket: no drop-in before": _move125(_Box129(socket=True, none_before=True, reject_new=True,
                                                      noop=_rs129(True))),
        "control: a drop-in before": _move125(_Box129(reject_new=True, noop=_rs129(False))),
        "old helper: not said": _move125(_Box129(old_helper=True, reject_new=True, noop=_rs129(False))),
    }
    m = {case: r["msg"] for case, r in got.items()}
    nb, snb, ctl, old = (m["no drop-in before"], m["socket: no drop-in before"], m["control: a drop-in before"],
                         m["old helper: not said"])
    check("ssh port move: a restore not confirmed after a move that found NO drop-in names no snapshot (none "
          "exists: the snapshot verb removes any) and says the drop-in was not there before and should be "
          "removed; one that found a drop-in still names where its copy is kept; a helper too old to say "
          "names both cases",
          all(["could not be confirmed" in nb, "there was no " + _D129 + " before" in nb, "remove it" in nb,
               _B129 not in nb, "kept at" not in nb,
               "there was no " + _SD129 + " before" in snb, _SB129 not in snb,
               "kept at " + _B129 in ctl, "there was no" not in ctl,
               "if " + _B129 + " exists" in old, "there was no " + _D129 in old, "kept at" not in old]),
          repr(m))


def _snap_shell129(sh, case):
    d = os.path.join(_TMP129, "sh-%s-%s" % (sh, case.replace(" ", "-")))
    os.makedirs(d)
    drop, bak = os.path.join(d, "drop.conf"), os.path.join(d, "drop.conf.bak")
    if case != "no drop-in":
        with open(drop, "w") as f:
            f.write("NEW\n")
    if case in ("held", "no drop-in"):
        with open(bak, "w") as f:
            f.write("GOOD\n")
    if case == "copy fails":
        os.makedirs(bak + ".tmp/x")     # the temp name is a directory: the copy cannot land
    r = _sp129.run([sh, "-c", _priv129._r35b_snapshot_sh(drop, bak)], capture_output=True, text=True,  # nosec B603
                   timeout=20, check=False)
    return r.returncode, r.stdout.strip(), _hosts129._r36b_snap_prior(r.stdout.strip())


def _helper129():
    spec = _ilu129.spec_from_loader("ph_p129", _mach129.SourceFileLoader(
        "ph_p129", os.path.join(_ROOT129, "tools", "panel-helper")))
    m = _ilu129.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _snap_helper129(h, case):
    d = os.path.join(_TMP129, "helper-" + case.replace(" ", "-"))
    os.makedirs(d)
    drop, bak = os.path.join(d, "drop.conf"), os.path.join(d, "drop.conf.bak")
    if case != "no drop-in":
        with open(drop, "w") as f:
            f.write("NEW\n")
    if case in ("held", "no drop-in"):
        with open(bak, "w") as f:
            f.write("GOOD\n")
    buf = _io129.StringIO()
    with _ctx129.redirect_stdout(buf):
        rc = h._r35b_snapshot(drop, bak)
    out = buf.getvalue().strip()
    return rc, out, _hosts129._r36b_snap_prior(out)


def _snap_verbs129():
    held = _priv129.R35J_SNAPSHOT_HELD
    got = {sh: {case: _snap_shell129(sh, case) for case in ("drop-in", "no drop-in", "held", "copy fails")}
           for sh in _SHELLS129}
    check("ssh port move snapshot (remote shell form, bash and dash): answering 0 it prints whether it copied a "
          "drop-in or there was none, which the move reads; a held or failed snapshot prints neither",
          bool(got) and all(g == {"drop-in": (0, _priv129.R36B_SNAP_COPIED, True),
                                  "no drop-in": (0, _priv129.R36B_SNAP_NONE, False),
                                  "held": (held, "", None), "copy fails": (1, "", None)}
                            for g in got.values()), repr(got))
    h = _helper129()
    hgot = {case: _snap_helper129(h, case) for case in ("drop-in", "no drop-in", "held")}
    check("ssh port move snapshot (panel-helper): prints the same two answers as the shell form, and nothing "
          "when it holds a snapshot that differs",
          hgot == {"drop-in": (0, h.R36B_SNAP_COPIED, True), "no drop-in": (0, h.R36B_SNAP_NONE, False),
                   "held": (held, "", None)}
          and (h.R36B_SNAP_COPIED, h.R36B_SNAP_NONE) == (_priv129.R36B_SNAP_COPIED, _priv129.R36B_SNAP_NONE),
          repr(hgot))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The undo's close, reload and restart: once more, then said
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DEL129 = "ufw-delete-allow-proto-port"


def _close129():
    got = {
        "close -1 twice": _Box129(reject_new=True, noop={(_DEL129, 1), (_DEL129, 2)}),
        "close -1, then runs": _Box129(reject_new=True, noop={(_DEL129, 1)}),
        "control: close runs": _Box129(reject_new=True),
    }
    res = {case: _move125(box) for case, box in got.items()}
    shape = {case: (r["ok"], r["allow left"], got[case].calls.get(_DEL129, 0)) for case, r in res.items()}
    check("ssh port move: the undo's close of the step-1 allow that answered -1 is run once more (it was retired "
          "however it answered)",
          shape == {"close -1 twice": (False, True, 2), "close -1, then runs": (False, False, 2),
                    "control: close runs": (False, False, 1)}, repr(shape))
    m = {case: r["msg"] for case, r in res.items()}
    check("ssh port move: ...and one still not confirmed is said, naming the port, after the step's own message "
          "(it said only 'nothing changed' over a public allow for a port nothing serves); one that ran says "
          "nothing of it",
          all(["sshd rejected the new config" in m["close -1 twice"],
               "port 2022/tcp could not be confirmed removed" in m["close -1 twice"],
               "host's Network tab" in m["close -1 twice"],
               "may not have been undone" not in m["close -1, then runs"],
               "may not have been undone" not in m["control: close runs"]]), repr(m))


def _refusals129():
    got = {
        "active: close -1 twice": _Box129(hide=True, noop={(_DEL129, 1), (_DEL129, 2)}),
        "inactive: close -1 twice": _Box129(hide=True, inactive=True, noop={(_DEL129, 1), (_DEL129, 2)}),
        "control: active, close runs": _Box129(hide=True),
        "control: inactive, close runs": _Box129(hide=True, inactive=True),
    }
    res = {case: _move125(box) for case, box in got.items()}
    shape = {case: (r["ok"], r["written"], r["allow left"], got[case].calls.get(_DEL129, 0),
                    "did not show port 2022/tcp open" in r["msg"],
                    "2022/tcp could not be confirmed removed" in r["msg"]) for case, r in res.items()}
    check("ssh port move: step 1's own refusal (the firewall does not show the new port open after opening it), "
          "active and inactive, runs its close once more when it answered -1, and says the rule may be left "
          "when that is not confirmed either (it said 'Nothing was changed')",
          shape == {"active: close -1 twice": (False, 0, True, 2, True, True),
                    "inactive: close -1 twice": (False, 0, True, 2, True, True),
                    "control: active, close runs": (False, 0, False, 1, True, False),
                    "control: inactive, close runs": (False, 0, False, 1, True, False)}, repr(shape))


def _reload_restart129():
    rl = "systemd-daemon-reload"
    got = {
        # step 2c's reload is the first; the undo's are the second and third
        "reload -1 twice": _Box129(socket=True, reject_new=True, noop={(rl, 2), (rl, 3)}),
        "reload -1, then runs": _Box129(socket=True, reject_new=True, noop={(rl, 2)}),
        "restart answers 1": _Box129(reject_new=True, restart_rc=1),
        "control": _Box129(socket=True, reject_new=True),
    }
    res = {case: _move125(box) for case, box in got.items()}
    shape = {case: (r["ok"], got[case].calls.get(rl, 0),
                    "systemd could not be confirmed" in r["msg"],
                    "may not be listening on any port" in r["msg"]) for case, r in res.items()}
    check("ssh port move: the undo's daemon-reload that answered -1 is run once more, and said when still not "
          "confirmed (systemd may hold the moved socket unit); a restart onto the restored config that "
          "answered non-zero is said as SSH maybe listening nowhere (both were retired however they answered)",
          shape == {"reload -1 twice": (False, 3, True, False), "reload -1, then runs": (False, 3, False, False),
                    "restart answers 1": (False, 0, False, True), "control": (False, 2, False, False)},
          repr(shape))


def _reload_skip129():
    rl = "systemd-daemon-reload"
    got = {
        "reload -1 twice": _Box129(socket=True, reject_new=True, noop={(rl, 2), (rl, 3)}),
        "reload raises twice (the wrapper's too)": _Box129(socket=True, reject_new=True, blow={(rl, 2), (rl, 3)}),
        "control: reload -1, then runs": _Box129(socket=True, reject_new=True, noop={(rl, 2)}),
        "control: reload raises, the wrapper's runs": _Box129(socket=True, reject_new=True, blow={(rl, 2)}),
    }
    res = {case: _move125(box) for case, box in got.items()}
    shape = {case: (r["ok"], r["restarts"], "so ssh.socket was not restarted" in r["msg"], "daemon-reload" in r["msg"])
             for case, r in res.items()}
    check("ssh port move (socket-activated): when the undo's daemon-reload is not confirmed (answered non-zero "
          "twice, or still owed after raising) ssh.socket is NOT restarted, and the note says so (the restart "
          "re-opened the moved port's listener with its firewall rule already closed); a reload confirmed on "
          "the second try still restarts",
          shape == {"reload -1 twice": (False, 0, True, True),
                    "reload raises twice (the wrapper's too)": ("raised", 0, False, False),
                    "control: reload -1, then runs": (False, 1, False, False),
                    "control: reload raises, the wrapper's runs": ("raised", 1, False, False)}, repr(shape))


class _Log129(_logging129.Handler):
    def __init__(self):
        super().__init__(_logging129.WARNING)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _restore_log129():
    log = _hosts129._core._log
    h, was = _Log129(), (log.level, log.disabled)
    log.addHandler(h)
    log.setLevel(_logging129.WARNING)
    log.disabled = False
    try:
        _move125(_Box129(up=False, reject_new=True, blow={("sshd-restore-dropin", 1), ("sshd-restore-dropin", 2)}))
    finally:
        log.removeHandler(h)
        log.setLevel(was[0])
        log.disabled = was[1]
    retry = [ln for ln in h.lines if "trying it once more" in ln]
    check("ssh port move: the restore retry's log line says the first answer was lost (it read 'answered None')",
          len(retry) == 1 and "its answer was lost" in retry[0] and "None" not in retry[0], repr(retry))


def _v4_close129():
    got = {}
    for case, rc in (("-1", -1), ("1", 1), ("control: 0", 0)):
        _p9_patch(_p9_core, "run_privileged", lambda *a, _rc=rc, **k: ("", "", _rc))
        got[case] = _hosts129._r25b_close_added_ssh_rule(_row120(), 2022, _hosts129._R25B_V4_ADDED)
        _p9_restore_all()
        _p9_arm(who="part129")
    got["nothing added"] = _hosts129._r25b_close_added_ssh_rule(_row120(), 2022, False)
    check("ssh port move: the IPv4-only close of the step-1 allow answers whether it was confirmed (its rc was "
          "dropped), and there being nothing to close is confirmed",
          got == {"-1": False, "1": False, "control: 0": True, "nothing added": True}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A restore whose answer was lost; step 3 that gave no answer
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restore_lost129():
    got = {
        "answer lost, second confirmed": _Box129(up=False, blow={("sshd-restore-dropin", 1)}),
        "answer lost twice": _Box129(up=False, reject_new=True, blow={("sshd-restore-dropin", 1),
                                                                      ("sshd-restore-dropin", 2)}),
        "answer lost, then -1": _Box129(up=False, reject_new=True, blow={("sshd-restore-dropin", 1)},
                                        noop={("sshd-restore-dropin", 2)}),
    }
    res = {case: _move125(box) for case, box in got.items()}
    shape = {case: (r["ok"], r["restores"], r["old"], "could not be confirmed" in r["msg"])
             for case, r in res.items()}
    check("ssh port move: an undo restore that raised after it went out (its answer lost) is run once more at "
          "once (it copies and keeps the snapshot, so that puts back the same file), and a second not "
          "confirmed is said, never 'nothing changed' (it was retired unconfirmed and unsaid)",
          shape == {"answer lost, second confirmed": (False, 2, True, False),
                    "answer lost twice": (False, 2, True, True),
                    "answer lost, then -1": (False, 2, True, True)}, repr(shape))


def _r36j_move129(box, after):
    """_move125's 22 -> 2022 move, ssh.socket answering active to the move's own read and `after` later.

    `after`: True, active; False, failed, inactive or unread.
    """
    asked = []
    _p9_patch(_p9_core, "run_privileged", box.priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_core, "write_root_file", box.write)
    _p9_patch(_hosts129, "_sshd_socket_activated", lambda s: (asked.append(1), len(asked) == 1 or after)[1])
    _p9_patch(_hosts129, "_restart_ssh_listener", box.restart)
    _p9_patch(_hosts129, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
    try:
        ok, msg = _hosts129.change_ssh_port(_row120(), 2022)
    except Exception:          # any raise is an answer here, never a crash of the part
        ok, msg = "raised", ""
    _p9_restore_all()
    _p9_arm(who="part129")
    return ok, box.calls.get("restart", 0), str(msg), len(asked)


def _r36j_socket_failed129():
    rl = "systemd-daemon-reload"
    # The undo's two reloads and the one more before its restart (_r36j_reload_again) all unconfirmed.
    got = {case: _r36j_move129(_Box129(socket=True, reject_new=True, noop={(rl, 2), (rl, 3), (rl, 4)}), after)
           for case, after in (("socket failed or inactive", False), ("control: socket active", True))}
    shape = {case: (r[0], r[1], "was not confirmed to be listening, so it was restarted" in r[2],
                    "so ssh.socket was not restarted" in r[2], r[3] >= 2) for case, r in got.items()}
    check("ssh port move (socket-activated): an undo whose daemon-reload is not confirmed still restarts "
          "ssh.socket when `systemctl is-active` does not answer active (a step 6 whose restart failed left "
          "no listener on any port, the old one included), and the note says it was restarted; while it is "
          "active the restart is skipped and the note says so (control)",
          shape == {"socket failed or inactive": (False, 1, True, False, True),
                    "control: socket active": (False, 0, False, True, True)}, repr(got))


def _r36j_down_case129(after=False, **kw):
    """One move on a _Box129(**kw) whose ssh.socket reads `after` to the undo: (ok, msg, what was sent)."""
    box = _Box129(**kw)
    ok, _n, msg, _asked = _r36j_move129(box, after)
    return ok, msg, list(box.sent)


def _r36j_reload_first129():
    rl = "systemd-daemon-reload"
    got = {case: _r36j_down_case129(socket=True, reject_new=True, noop=noop)
           for case, noop in (("reload unconfirmed, socket failed", {(rl, 2), (rl, 3)}),
                              ("the one more reload unconfirmed too", {(rl, 2), (rl, 3), (rl, 4)}))}
    shape = {case: (ok, sent.count("restart"), sent[:sent.index("restart")].count(rl) if "restart" in sent else -1,
                    sent[sent.index("restart") - 1] if "restart" in sent else "")
             for case, (ok, _m, sent) in got.items()}
    check("ssh port move (socket-activated): an undo whose daemon-reload was not confirmed, on a ssh.socket that "
          "is not active, issues one more daemon-reload right before restarting it (a restart without one "
          "rebinds the MOVED port list systemd still holds, fails again, and nothing listens on any port)",
          shape == {"reload unconfirmed, socket failed": (False, 1, 4, rl),
                    "the one more reload unconfirmed too": (False, 1, 4, rl)}, repr(shape))


def _r36j_down_message129():
    rl = "systemd-daemon-reload"
    unsure = {(rl, 2), (rl, 3)}
    got = {
        "socket restart answers 1": _r36j_down_case129(socket=True, up=False, restart_rc=1, noop=unsure),
        "socket restart answers -1": _r36j_down_case129(socket=True, up=False, restart_rc=-1, noop=unsure),
        "socket restart raises": _r36j_down_case129(socket=True, up=False, noop=unsure, blow={("restart", 2)}),
    }
    # Not socket-activated: _move125 (_r36j_move129's is-active answers "active" to the move's own read).
    _svc = _move125(_Box129(up=False, restart_rc=1))
    got["sshd restart answers 1"] = (_svc["ok"], _svc["msg"], [])
    shape = {case: (ok, "still works" in m, "may not be listening on any port" in m,
                    "`systemctl daemon-reload`, then `systemctl restart ssh.socket`" in m,
                    "`systemctl restart ssh`." in m, "it was restarted" in m) for case, (ok, m, _s) in got.items()}
    want_socket = (False, False, True, True, False, False)
    check("ssh port move: an undo whose restart is not confirmed (answers 1, -1, or raises) does NOT say 'Your "
          "existing SSH still works' (nothing may listen on any port), says SSH may not be listening on any "
          "port, and gives the recovery: daemon-reload then restart ssh.socket (socket-activated) or restart "
          "ssh",
          shape == {"socket restart answers 1": want_socket, "socket restart answers -1": want_socket,
                    "socket restart raises": want_socket,
                    "sshd restart answers 1": (False, False, True, False, True, False)}, repr(got))
    ok, m, _s = _r36j_down_case129(socket=True, up=False, noop=unsure | {("sshd-validate", 2)})
    check("ssh port move (socket-activated): an undo that does not restart a ssh.socket not confirmed active "
          "because `sshd -t` did not accept the config does not say SSH still works, and says to run `sshd -t` "
          "and fix it, then daemon-reload and restart ssh.socket",
          ok is False and "still works" not in m and "may not be listening on any port" in m
          and "run `sshd -t` and fix" in m and "`systemctl restart ssh.socket`" in m, repr(m))


def _r36j_restarted_control129():
    rl = "systemd-daemon-reload"
    got = {case: _r36j_down_case129(socket=True, up=False, noop=noop)
           for case, noop in (("one more reload unconfirmed", {(rl, 2), (rl, 3), (rl, 4)}),
                              ("one more reload confirmed", {(rl, 2), (rl, 3)}))}
    shape = {case: (ok, m.startswith("sshd didn't come up on port 2022 — reverted. Your existing SSH still works."),
                    "was not confirmed to be listening, so it was restarted" in m,
                    "may not be listening on any port" in m) for case, (ok, m, _s) in got.items()}
    check("ssh port move (control): an undo restart of ssh.socket that succeeds keeps the step's own message "
          "('Your existing SSH still works.'), with the 'restarted' note while systemd's re-read is still "
          "unconfirmed and none once the reload before the restart was confirmed",
          shape == {"one more reload unconfirmed": (False, True, True, False),
                    "one more reload confirmed": (False, True, False, False)}, repr(got))


def _r36j_old_helper129():
    lost = {("sshd-restore-dropin", 1)}
    got = {"old helper: answer lost": _move125(_Box129(up=False, old_helper=True, blow=lost)),
           "old helper: answered -1": _move125(_Box129(up=False, old_helper=True, noop=lost)),
           "control: helper says SNAPSHOT=, answer lost": _move125(_Box129(up=False, blow=lost))}
    shape = {case: (r["ok"], r["restores"], "could not be confirmed" in r["msg"]) for case, r in got.items()}
    check("ssh port move: with a helper too old to print SNAPSHOT= (its restore MOVES the snapshot back), a "
          "restore whose answer was lost or not 0 is NOT run again (a second run would delete the drop-in the "
          "first put back) and is said as not confirmed; with one that prints it, it is retried (control)",
          shape == {"old helper: answer lost": (False, 1, True), "old helper: answered -1": (False, 1, True),
                    "control: helper says SNAPSHOT=, answer lost": (False, 2, False)}, repr(shape))


def _validate129():
    got = {
        "sshd -t gave no answer": _move125(_Box129(noop={("sshd-validate", 1)})),
        "control: sshd -t rejects": _move125(_Box129(reject_new=True)),
    }
    m = {case: r["msg"] for case, r in got.items()}
    check("ssh port move: step 3's `sshd -t` that gave no answer (-1) is undone without claiming sshd rejected "
          "the config; one that rejects still says so",
          all(["could not be run" in m["sshd -t gave no answer"], "rejected" not in m["sshd -t gave no answer"],
               got["sshd -t gave no answer"]["ok"] is False,
               "sshd rejected the new config" in m["control: sshd -t rejects"]]), repr(m))


try:
    _p9_arm(who="part129")
    for _fn129 in (_prior129, _snap_verbs129, _close129, _refusals129, _reload_restart129, _reload_skip129,
                   _v4_close129, _restore_lost129, _restore_log129, _validate129, _r36j_socket_failed129,
                   _r36j_old_helper129, _r36j_reload_first129, _r36j_down_message129, _r36j_restarted_control129):
        _fn129()
        _p9_restore_all()
        _p9_arm(who="part129")
finally:
    _p9_restore_all()
    _shutil129.rmtree(_TMP129, ignore_errors=True)

check("part129: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP129_START, repr(_P9_TRIPPED[_TRIP129_START:][:6]))
