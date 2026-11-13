"""Part 188 of the unit suite: review pass 29's fixes (builder r).

Held here:
* A port saved during a Start or Restart: the stored port moves to the port the start was issued on
  (saved before it), and the later save waits for the next start.

HOW IT RUNS. No host is reached: routes run on part12's app with its transport tripwire armed and
every host call stubbed; the background power action's thread is queued and drained.
"""
from unit.part01 import eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _P9Thread, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row, _p9_set,
                         _p9_threading)
from panel.routes import _shared as _sh188, server_detail as _sd188
from panel.services import lgsm_players as _lgp188

_r188 = {}

# ── 1. a port saved during a Start or Restart ───────────────────────────────────────────────────
_pp188 = _p9_new_server(P9_HOST, "p188pp", "csgo", 43150, name="p188-pp", status="online")
_pp_during188 = []


def _pp_run188(*_a, **_k):
    """The stand-in power command: the Settings tab saves 43170 while it runs, then it exits 0."""
    for port in _pp_during188:
        _p9_set(_pp188, pending_port=port)
    return "Restarting csgoserver: OK", "", 0


def _pp_press188(client, pending, action="restart"):
    """Press `action` with `pending` saved before it; the worker drained. -> (port, pending_port)."""
    _p9_set(_pp188, port=43150, pending_port=pending, status="online" if action == "restart" else "offline")
    client.post("/api/server/%d/action" % _pp188, json={"action": action})
    _p9_drain()
    return _p9_row(_pp188).port, _p9_row(_pp188).pending_port


try:
    _p9_arm(who="part188")
    _n_trips188 = len(_P9_TRIPPED)
    _p9_patch(_sd188, "threading", _p9_threading(_P9Thread))
    _p9_patch_sm("run_as_game_user", _pp_run188)
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_lgp188, "allowance_seconds", lambda *a, **k: 0)
    _p9_patch_sm("_remote_listening_ports", lambda remote: set())
    _p9_patch_sm("protected_host_ports", lambda remote: {22})
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: True)
    _p9_patch_sm("remote_ufw_close_game_port", lambda *a, **k: (1, ""))
    _p9_patch(_sh188, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd188, "_live_run_state", lambda gs, remote: None)
    _A188 = _p9_client(P9_ADMIN)
    _pp_during188.append(43170)
    _r188["pp_restart"] = _pp_press188(_A188, 43160)
    _r188["pp_start"] = _pp_press188(_A188, 43160, action="start")
    _r188["pp_none_before"] = _pp_press188(_A188, None)
    _pp_during188[0] = 43160
    _r188["pp_back_to_bound"] = _pp_press188(_A188, 43160)
    _pp_during188.clear()
    _r188["pp_trips"] = _P9_TRIPPED[_n_trips188:]
finally:
    _p9_restore_all()
    _p9_delete_server(_pp188)
eq("pending port r42r: a port saved during a Restart or a Start leaves the stored port on the one the start "
   "was issued on (saved before it) and waits; with none saved before, the stored port stays; a save during "
   "the run of the same port settles it; nothing reaches a host",
   ([_r188[k] for k in ("pp_restart", "pp_start", "pp_none_before", "pp_back_to_bound")], _r188["pp_trips"]),
   ([(43160, 43170), (43160, 43170), (43150, 43170), (43160, None)], []))
