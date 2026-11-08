"""Part 156 of the unit suite: review 1107's reboot, update, install and What's new fixes.

Held here:

* A host reboot decides LinuxGSM maintenance once, before it touches anything: the census counts a
  maintenance command on a STOPPED server too, and the rescan after the stops waits only on the
  servers it stopped and on any found running, so a cron `update` on a server that was stopped all
  along (or one server's `monitor` at the deadline) no longer makes it stop everything, sit out the
  stop budget and roll back.

HOW IT RUNS. Pure helpers with their host reads stubbed; the reboot job's steps on part12's app
with its transport tripwire armed. Nothing reaches a host or data/.
"""
import os
import time as _time156

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import P9_GS, _p9, _p9_patch, _p9_restore_all
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
    _p9_patch(_hr156, "_probe_rows", lambda remote, rows: {P9_GS: dict(_settled156[P9_GS]),
                                                            _FAR156: dict(_settled156[_FAR156])})
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
