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

# ── A01: allocating a port refuses when a valve sibling's config could not be read ──────────────


class _Q51:
    def __init__(self, rows):
        self._rows = rows

    def filter_by(self, **_kw):
        return self

    def all(self):
        return list(self._rows)


def _alloc51(read):
    """resolve_free_port's answer (or the exception it raised) over five stopped csgo siblings."""
    sibs = [NS(game_type="csgo", port=27015 + i, short_name="csgo%d" % i, lgsm_name="csgoserver")
            for i in range(5)]
    with _patched():
        _patch(_app51, "_remote_listening_ports", lambda remote: set())
        _patch(_app51, "GameServer", NS(query=_Q51(sibs)))
        _patch(_app51, "sm_game_engine", lambda gt: "valve")
        _patch(_app51, "lgsm_get_values", read)
        try:
            return _app51.resolve_free_port(NS(name="h51"), 1, 27015, "csgo")
        except Exception as e:  # noqa: BLE001 - the answer under test
            return e


def _first_unread51(remote, user, selfname, keys):
    """The first sibling's read did not complete (a tailscale timeout); the rest answer."""
    return None if user == "csgo0" else {"clientport": "", "sourcetvport": ""}


def _first_raises51(remote, user, selfname, keys):
    if user == "csgo0":
        raise OSError("the host did not answer")
    return {"clientport": "", "sourcetvport": ""}


_a51_none = _alloc51(_first_unread51)
_a51_raise = _alloc51(_first_raises51)
_a51_ok = _alloc51(lambda remote, user, selfname, keys: {
    "clientport": "", "sourcetvport": "27020" if user == "csgo0" else ""})
check("free-port: a valve sibling whose config could not be read (None, or a raise) refuses with "
      "PortScanUnreadable instead of handing out a port it may own",
      type(_a51_none).__name__ == "PortScanUnreadable"
      and type(_a51_raise).__name__ == "PortScanUnreadable"
      and "csgo0" in str(_a51_none), repr((_a51_none, _a51_raise)))
check("free-port: ...while a sibling read that answered still steers past its SourceTV port",
      _a51_ok == (27021, True), repr(_a51_ok))
with _patched():
    _patch(_app51, "_remote_listening_ports", lambda remote: set())
    _patch(_app51, "GameServer", NS(query=_Q51([NS(game_type="csgo", port=27015, short_name="csgo0",
                                                   lgsm_name="csgoserver")])))
    _patch(_app51, "sm_game_engine", lambda gt: "valve")
    _patch(_app51, "lgsm_get_values", lambda remote, user, selfname, keys:
           {"clientport": "27005", "sourcetvport": "27020"} if user == "new" else None)
    try:
        _aux51 = _app51._resolve_source_aux_ports(NS(name="h51"), 1, "new", "csgoserver", 27016)
    except Exception as _e51:  # noqa: BLE001 - the answer under test
        _aux51 = _e51
check("aux ports: the post-install move stays best-effort -- an unreadable sibling is skipped, "
      "not raised", _aux51 == {}, repr(_aux51))
