"""Part 123 of the unit suite: the twenty-first review's adversarial pass over its own fixes (review 1022a).

* An SSH port move whose step-3 revert lost the restore's answer (paramiko's `command_started`) has
  the restore retired as run, but it may not have run. The undo then restarted sshd on a drop-in
  `sshd -t` had just rejected: the serving daemon stopped and no new one could start. The undo now
  restarts only onto a config sshd-validate accepts.

HOW IT RUNS. On part12's stand-ins with its transport tripwire armed: the SSH move on part120's
stand-in host. Nothing reaches a host, sudo or the checkout's data/.
"""
from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_cfg, _p9_restore_all
from unit.part120 import _Box120, _move120

_TRIP123_START = len(_P9_TRIPPED)
_CFG123 = _p9_cfg.load_config()


# ── 1. the SSH move's undo never restarts sshd onto a config sshd -t rejects ─────────────────────
class _Box123(_Box120):
    """part120's host, with `sshd -t` judging the drop-in: the one the move wrote is rejected.

    `lost` names (verb, nth call) pairs that raise marked command_started WITHOUT doing their work:
    the exec request went out and the channel closed before the command ran.
    """

    def __init__(self, lost=(), **kw):
        super().__init__(**kw)
        self.lost = set(lost)

    def priv(self, server, verb, args=(), **kw):
        if (verb, self.calls.get(verb, 0) + 1) in self.lost:
            self._tick(verb)
            e = ConnectionError("Command failed: socket closed")
            e.command_started = True
            raise e
        return super().priv(server, verb, args, **kw)

    def _answer(self, verb):
        if verb == "sshd-validate":
            return ("", "", 0) if self.dropin == "OLD" else ("", "Bad configuration option", 255)
        return super()._answer(verb)


def _undo_validates123():
    got = {}
    for case, box in (("restore lost, drop-in still the rejected one", _Box123(lost={("sshd-restore-dropin", 1)})),
                      ("socket mode, restore lost", _Box123(socket=True, lost={("sshd-socket-restore", 1)})),
                      ("undo's validate cannot run", _Box123(lost={("sshd-restore-dropin", 1),
                                                                   ("sshd-validate", 2)})),
                      ("restore ran, answer lost (control)", _Box123(blow={("sshd-restore-dropin", 1)}))):
        raised, dropin, restores, restarts, left = _move120(box)[:5]
        got[case] = (raised, dropin == "OLD", restores, restarts, left, box.calls.get("sshd-validate", 0))
    check("ssh port move: an undo whose restore may not have run (its answer lost, command_started) never "
          "restarts sshd onto a config `sshd -t` rejects or could not check (it stopped the serving daemon and "
          "none could start: a lockout); a restore that ran is still restarted onto, once (control)",
          got == {"restore lost, drop-in still the rejected one": (True, False, 1, 0, False, 2),
                  "socket mode, restore lost": (True, False, 1, 0, False, 2),
                  "undo's validate cannot run": (True, False, 1, 0, False, 2),
                  "restore ran, answer lost (control)": (True, True, 1, 1, False, 2)}, repr(got))


try:
    _p9_arm(who="part123")
    _undo_validates123()
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG123)

check("part123: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP123_START, repr(_P9_TRIPPED[_TRIP123_START:][:6]))
