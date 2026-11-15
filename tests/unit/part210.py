"""Part 210 of the unit suite: the panel's own cost in CPU, memory, network and disk, cut where it was measured.

Held here, each against the code that made the cost:
* The host sample and the one-game sample run ONE `ps` each (they ran four), and still report every
  figure: both /proc/stat CPU lines, the jiffies on both sides of the window, RSS, process count and
  the oldest process's age.
* The server page's Players poll answers from the player poller's batch, which read the same gamedig
  reply: no gamedig of its own while that list is fresh. A refresh the page asks for still reads,
  and wins; a start, stop or restart drops the batch's list too.

HOW IT RUNS. Host commands are stubbed on their definition sites behind part12's tripwire; a sample
command runs for real, with bash, behind a `ps` that counts its runs. Routes run on part12's app.
"""
import json as _json210
import os
import pwd as _pwd210
import shutil as _shutil210
import subprocess as _sp210  # nosec B404 - runs bash on this part's own fixtures
import tempfile as _tf210
import time as _time210
from types import SimpleNamespace as NS

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _p9_arm, _p9_client, _p9_delete_server, _p9_json, _p9_new_server,
                         _p9_patch_sm, _p9_restore_all)
from panel.ops.ssh_manager import _core as _core210, cron as _cron210, game as _game210, portscan as _ps210

_TMP210 = _tf210.mkdtemp(prefix="lgsm-unit-p210-")
_ME210 = _pwd210.getpwuid(os.getuid()).pw_name
_JQ210 = _shutil210.which("jq")


# ── One ps per sample ──────────────────────────────────────────────────────────────────────────
def _ps_rig210():
    """(bin dir, log): a `ps` that writes one line to the log per run, then runs the real one."""
    d = os.path.join(_TMP210, "psbin")
    os.makedirs(d, exist_ok=True)
    log = os.path.join(_TMP210, "ps.log")
    with open(os.path.join(d, "ps"), "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho ps >> "%s"\nexec %s "$@"\n' % (log, _shutil210.which("ps")))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs
    os.chmod(os.path.join(d, "ps"), 0o700)  # nosec B103 - owner-only test stand-in
    return d, log


def _counted210(rig):
    """run_command's stand-in: the command run by bash behind the counting ps; (out, err, rc)."""
    d, log = rig
    outs = []

    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        r = _sp210.run(["bash", "-c", command], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                       env=dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", "")), check=False)
        outs.append(r.stdout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    return _run, outs, log


def _ps_runs210(log):
    try:
        with open(log, encoding="utf-8") as fh:
            n = fh.read().count("ps")
        os.remove(log)
        return n
    except OSError:
        return 0


def _tags210(out):
    """{tag: lines} of one sample's output, for the tags the samplers print per process set."""
    tags = {}
    for line in (out or "").splitlines():
        f = line.split()
        if f and f[0] in ("cpu", "GJA", "GJB", "GAMERAM", "GUP"):
            tags.setdefault(f[0], []).append(f)
    return tags


def _one_ps210():
    """host_live_metrics and server_live_metrics, each through run_command: one ps, every figure."""
    run, outs, log = _counted210(_ps_rig210())
    _p9_patch_sm("run_command", run)
    _ps_runs210(log)
    host = _core210.host_live_metrics(NS(id=-210), force=True)
    runs, tags = _ps_runs210(log), _tags210(outs[-1] if outs else "")
    mine = host["users"].get(_ME210, {})
    check("host sample: ONE ps for the whole sample (it ran four: the jiffies before and after the window, "
          "RSS, uptime), and every figure is still there",
          runs == 1 and len(tags.get("cpu", [])) == 2
          and any(f[1] == _ME210 for f in tags.get("GJA", [])) and any(f[1] == _ME210 for f in tags.get("GJB", []))
          and mine.get("game_procs", 0) >= 1 and mine.get("game_ram_mb", -1) >= 0
          and mine.get("game_uptime_secs", 0) > 0 and host["host"]["ram_total"] > 0,
          repr((runs, sorted(tags), mine)))
    game = _core210.server_live_metrics(NS(id=-210), short_name=_ME210, game_port=None, force=True)
    runs, tags = _ps_runs210(log), _tags210(outs[-1] if outs else "")
    check("one-game sample: ONE ps (it ran four, and an awk per process twice), and every figure is still there",
          runs == 1 and len(tags.get("cpu", [])) == 2 and len(tags.get("GJA", [])) == 1
          and len(tags.get("GJB", [])) == 1 and game["game_procs"] >= 1 and game["game_uptime_secs"] > 0
          and game["ram_total"] > 0, repr((runs, sorted(tags), game)))
    gone = _core210.server_live_metrics(NS(id=-2101), short_name="nosuchuser210", game_port=None, force=True)
    eq("one-game sample: an account with no process reads zero of everything, and the host's figures stay",
       ([f for k in ("GJA", "GJB", "GAMERAM", "GUP") for f in _tags210(outs[-1]).get(k, [])],
        gone["game_procs"], gone["ram_total"] > 0),
       ([["GJA", "0"], ["GJB", "0"], ["GAMERAM", "0", "0"], ["GUP", "0"]], 0, True))


# ── The Players poll answers from the player poller's batch ────────────────────────────────────
def _batch_out210(replies):
    """What a batch prints for `replies` ({key: gamedig reply}): each through the REAL jq filter."""
    lines = "\n".join(_json210.dumps({"k": k, "r": r}) for k, r in replies.items())
    r = _sp210.run([_JQ210, "-c", _cron210._batch_target_filter()], input=lines, capture_output=True,  # nosec B603
                   text=True, timeout=30, check=False)
    return r.stdout + _cron210._BATCH_END


def _batch_then_poll210():
    """A batch pass, then the page's timed poll, refresh and a restart, through the route."""
    sid = _p9_new_server(P9_HOST, "gmod210", "gmod", 27015, status="online")
    queried, batch = [], {}

    def _shell(server, user, sh, timeout=30, selfname=None, stdin_text=None):
        if "@@lgsm-batch-end" in sh:
            return batch["out"], "", 0
        queried.append(sh)
        return '{"p":[{"name":"Own","score":null,"time":null}],"c":1}', "", 0
    _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.210")
    _p9_patch_sm("shell_as_game_user", _shell)
    for cache in (_game210._playerlist_cache, _cron210._batch_lists):
        cache.clear()
    try:
        c, url = _p9_client(P9_ADMIN), "/api/server/%d/playerlist" % sid
        batch["out"] = _batch_out210({sid: {"players": [{"name": "Ann", "raw": {"score": 3, "time": 12}},
                                                        {"name": "Bob", "frags": 7}],
                                            "maxplayers": 16, "name": "Box", "numplayers": 2},
                                      sid + 1: {"error": "Failed all 1 attempts"}})
        got = _cron210.player_slots_batch(NS(id=P9_HOST), "gmod210", [(sid, "gmod", 27015, None),
                                                                     (sid + 1, "gmod", 27016, None)]) or {}
        a, b = _p9_json(c.get(url)), _p9_json(c.get(url))
        rows = [(p.get("name"), p.get("score"), p.get("time")) for p in a.get("players") or []]
        check("players poll: answered from the player poller's batch, which read the same reply: no gamedig "
              "of its own, the same names, scores and times its own query reads, on every poll",
              got.get(sid) == (2, 16, "Box") and queried == [] and a.get("unknown") is False
              and rows == [("Ann", 3, 12), ("Bob", 7, None)] and b.get("players") == a.get("players"),
              repr((got, queried, rows, b.get("players"))))
        eq("players poll: a target the batch could not read keeps no list, so its page still asks",
           _cron210.batch_list((P9_HOST, 27016, "garrysmod")), None)
        c.get(url + "?console=1")
        names = [p.get("name") for p in _p9_json(c.get(url)).get("players") or []]
        check("players poll: a refresh the page asks for still reads, and its newer list wins over the batch's",
              len(queried) == 1 and names == ["Own"], repr((queried, names)))
        _game210._playerlist_cache.clear()
        batch["out"] = _batch_out210({sid: {"players": [], "maxplayers": 16, "name": "Box", "numplayers": 5}})
        _cron210.player_slots_batch(NS(id=P9_HOST), "gmod210", [(sid, "gmod", 27015, None),
                                                               (sid + 1, "gmod", 27016, None)])
        hidden = _p9_json(c.get(url))
        check("players poll: a batch reply with no names while 5 are on reads 'cannot be read', as the poll's "
              "own query reads it, and asks nothing", hidden.get("unknown") is True and len(queried) == 1,
              repr((hidden, queried)))
        _ps210._invalidate_port_scan(P9_HOST)
        c.get(url)
        eq("players poll: a start, stop or restart (the port scan dropped) drops the batch's list as well, "
           "so the next poll reads", len(queried), 2)
        _cron210._batch_lists[(P9_HOST, 27015, "garrysmod")] = (_time210.time() - _cron210._BATCH_LIST_TTL - 1,
                                                                 {"p": [{"name": "Old"}], "c": 1})
        _game210._playerlist_cache.clear()
        c.get(url)
        eq("players poll: a batch list older than one poll period plus its margin is not served", len(queried), 3)
    finally:
        for cache in (_game210._playerlist_cache, _cron210._batch_lists):
            cache.clear()
        _p9_delete_server(sid)


def _players210():
    if not _JQ210:
        skip("players poll: answered from the player poller's batch", "no jq on this machine")
        return
    _batch_then_poll210()


try:
    for _fn210 in (_one_ps210, _players210):
        _p9_restore_all()
        _p9_arm(who="part210")
        _fn210()
finally:
    _p9_restore_all()
    _shutil210.rmtree(_TMP210, ignore_errors=True)
