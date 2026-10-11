"""Part 51 of the unit suite: review 1011's core, system_ops, ssh-core and reboot findings.

* The recovery CLI (manage.py) starts none of the service's background workers.
* (further sections are added below, one per finding)

HOW IT RUNS. Every outside call is a stand-in (patched with part20's _patch / _patched, undone at
the end of each block); nothing touches the network, sudo, a real host or the checkout's data/.
"""
import os
import types as _types51

from unit.part01 import check
from unit.part05 import _root
from unit.part20 import _patch, _patched

import app as _app51  # noqa: E402

NS = _types51.SimpleNamespace

# ── A01: the recovery CLI starts no background workers ──────────────────────────────────────────


class _RecThread51:
    """A threading.Thread stand-in that records what was made and never runs it."""
    made = []

    def __init__(self, target=None, name=None, daemon=None, args=()):
        self.target, self.name = target, name
        _RecThread51.made.append(self)

    def start(self):
        """Never started."""


def _workers_started51(env_on):
    """[thread names] a supervisor and the hub-lag watch would start, with the CLI's flag on/off."""
    _RecThread51.made = []
    spawned = []
    saved = os.environ.pop(_app51.NO_WORKERS_ENV, None)
    try:
        if env_on:
            os.environ[_app51.NO_WORKERS_ENV] = "1"
        with _patched():
            _patch(_app51, "threading", NS(Thread=_RecThread51))
            _patch(_app51._dr_process, "start_hub_lag_watch",
                   lambda spawn=None: spawned.append("hub-lag-watch"))
            _app51._make_supervisor(NS(logger=NS(error=lambda *a, **k: None)))("p51-worker",
                                                                                lambda: None)
            _app51._start_hub_lag_watch()
    finally:
        os.environ.pop(_app51.NO_WORKERS_ENV, None)
        if saved is not None:
            os.environ[_app51.NO_WORKERS_ENV] = saved
    return [t.name for t in _RecThread51.made] + spawned


_w51_on = _workers_started51(True)
_w51_off = _workers_started51(False)
check("recovery CLI: with manage.py's flag set, neither a supervised ticker nor the hub-lag watch "
      "is started (and without it both still are)",
      _w51_on == [] and _w51_off == ["supervise-p51-worker", "hub-lag-watch"],
      repr((_w51_on, _w51_off)))
with open(os.path.join(_root, "manage.py"), encoding="utf-8") as _f51:
    _msrc51 = _f51.read()
check("recovery CLI: manage.py sets the no-workers flag BEFORE it builds the app",
      "os.environ[NO_WORKERS_ENV] = \"1\"" in _msrc51
      and _msrc51.index("os.environ[NO_WORKERS_ENV]") < _msrc51.index("app = create_app()"))
