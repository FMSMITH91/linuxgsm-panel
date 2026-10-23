"""Part 123 of the unit suite: the twenty-first review's adversarial pass over its own fixes (review 1022a).

* An SSH port move whose step-3 revert lost the restore's answer (paramiko's `command_started`) has
  the restore retired as run, but it may not have run. The undo then restarted sshd on a drop-in
  `sshd -t` had just rejected: the serving daemon stopped and no new one could start. The undo now
  restarts only onto a config sshd-validate accepts.
* Change-port with no bind_host stored: an unchanged form (the 0.0.0.0 default) while the boot resolved
  loopback behind Serve is still refused as the panel's binding, never a restart onto every interface.

HOW IT RUNS. On part12's stand-ins with its transport tripwire armed: the SSH move on part120's
stand-in host, change-port on part116's stubs. Nothing reaches a host, sudo or the checkout's data/.
"""
from unit.part01 import check
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_cfg, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from unit.part12 import _p9_so
from unit.part108 import _ANY108
from unit.part116 import _LOOP116, _boot116
from panel.routes import remote_security as _rs123
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
    # Since review 1022c a restore whose answer was lost is run once more at once, so "may not have run"
    # is both runs lost (part129 has one lost and the second confirmed).
    for case, box in (("restore lost, drop-in still the rejected one",
                       _Box123(lost={("sshd-restore-dropin", 1), ("sshd-restore-dropin", 2)})),
                      ("socket mode, restore lost",
                       _Box123(socket=True, lost={("sshd-socket-restore", 1), ("sshd-socket-restore", 2)})),
                      ("undo's validate cannot run", _Box123(lost={("sshd-restore-dropin", 1),
                                                                   ("sshd-restore-dropin", 2),
                                                                   ("sshd-validate", 2)})),
                      ("restore ran, answer lost (control)", _Box123(blow={("sshd-restore-dropin", 1)}))):
        raised, dropin, restores, restarts, left = _move120(box)[:5]
        got[case] = (raised, dropin == "OLD", restores, restarts, left, box.calls.get("sshd-validate", 0))
    check("ssh port move: an undo whose restore may not have run (its answer lost, command_started) never "
          "restarts sshd onto a config `sshd -t` rejects or could not check (it stopped the serving daemon and "
          "none could start: a lockout); a restore that ran is still restarted onto, once (control)",
          got == {"restore lost, drop-in still the rejected one": (False, False, 2, 0, False, 2),
                  "socket mode, restore lost": (False, False, 2, 0, False, 2),
                  "undo's validate cannot run": (False, False, 2, 0, False, 2),
                  "restore ran, answer lost (control)": (False, True, 2, 1, False, 2)}, repr(got))


# ── 2. change-port: an unset bind_host's default is still "already the binding" ──────────────────
def _apply123(client, boot, stored):
    """One change-port to the same port and 0.0.0.0 on stand-ins: (success, refused as already, restarts)."""
    restarts = []
    _p9_patch(_rs123, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_rs123, "remote_ufw_close_port", lambda *a, **k: (True, "closed"))
    _p9_patch(_rs123, "remote_ufw_put_back_tcp", lambda *a, **k: (True, ""))
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: (True, "j"))
    _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": True})
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "record_panel_port", lambda port: (True, ""))
    _p9_patch(_p9_so, "restart_panel", lambda *a, **k: (restarts.append(1), (True, "p123"))[1])
    cfg = dict(_p9_cfg.load_config(), port=5000, tailscale_setup_done=True)
    cfg.pop("bind_host", None)
    if stored is not None:
        cfg["bind_host"] = stored
    _p9_cfg.save_config(cfg)
    with _boot116(BOOT_BIND=boot, BOOT_PORT=5000):
        body = _p9_json(client.post("/api/panel/change-port", json={"port": 5000, "bind_host": _ANY108}))
    return body.get("success"), "already" in str(body.get("message")), len(restarts)


def _unset_bind123(client):
    got = {case: _apply123(client, boot, stored) for case, boot, stored in (
        ("unset, boot loopback (Serve)", _LOOP116, None),
        ("unset, boot public", _ANY108, None),
        ("stored public, boot loopback", _LOOP116, _ANY108))}
    check("change-port: with no bind_host stored and the boot resolved loopback behind Serve, Apply on the "
          "unchanged form (its 0.0.0.0 default) is refused as the panel's binding, not saved and restarted onto "
          "every interface; with it stored, the bind waiting for its restart still applies (control)",
          got == {"unset, boot loopback (Serve)": (False, True, 0), "unset, boot public": (False, True, 0),
                  "stored public, boot loopback": (True, False, 1)}, repr(got))


try:
    _p9_arm(who="part123")
    _undo_validates123()
    _p9_restore_all()
    _p9_arm(who="part123")
    _unset_bind123(_p9_client(P9_ADMIN))
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG123)

check("part123: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP123_START, repr(_P9_TRIPPED[_TRIP123_START:][:6]))
