"""Part 210 of the unit suite: the panel's own cost in CPU, memory, network and disk, cut where it was measured.

Held here, each against the code that made the cost:
* The host sample and the one-game sample run ONE `ps` each (they ran four), and still report every
  figure: both /proc/stat CPU lines, the jiffies on both sides of the window, RSS, process count and
  the oldest process's age.
* The server page's Players poll answers from the player poller's batch, which read the same gamedig
  reply: no gamedig of its own while that list is fresh. A refresh the page asks for still reads,
  and wins; a start, stop or restart drops the batch's list too.
* A watched console whose log has stopped growing rests: read every 6 s, not on every 2 s pass, and
  straight back to every pass when the log grows, a line is typed into it, or the panel says
  something in it. While output flows every pass reads it, as before.
* The player batch's node script goes to node on stdin, not into the command line sudo logs.

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
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core import panel_state as _pstate210
from panel.ops.ssh_manager import _core as _core210, cron as _cron210, game as _game210, portscan as _ps210
from panel.routes import _shared as _shared210, console_rest as _crest210, server_files as _sf210

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


# ── The idle console rests ─────────────────────────────────────────────────────────────────────
class _LogHost210:
    """read_as_game_user against this part's console log, run by bash; counts the console reads."""

    def __init__(self, log):
        self.log, self.reads = log, 0

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        if "__LGSMP_W0_B__" in sh:
            return "", "", 1                # the console-secrets config read: nothing to mask here
        self.reads += 1
        p = _sp210.run(["bash", "-c", sh], capture_output=True, text=True, timeout=30, check=False)  # nosec B603 B607
        return p.stdout, p.stderr, p.returncode


class _Sio210:
    def __init__(self):
        self.lines = []

    def emit(self, event, data=None, **_kw):
        if event == "console_output":
            self.lines += (data or {}).get("data", "").split("\n")


def _console_rig210():
    log = os.path.join(_TMP210, "crserver-console.log")
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("boot\n")
    host, sio, clock = _LogHost210(log), _Sio210(), [1000.0]
    gs = NS(id=-21001, console_log=log, remote=NS(id=-2109, timezone=""), short_name="cr210", lgsm_name="crserver")
    _p9_patch(_sf210, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("read_as_game_user", host)
    _p9_patch(_crest210, "time", NS(time=lambda: clock[0]))
    return log, host, sio, clock, gs


def _passes210(rig, n, grow=None):
    """`n` poller passes 2 s apart (the log grown by `grow` before the first); the reads they made."""
    log, host, sio, clock, gs = rig
    if grow:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(grow + "\n")
    before = host.reads
    for _ in range(n):
        clock[0] += 2.0
        _crest210.tick(_sf210._console_tick, _sf210._console_catchups, _p9, sio, gs, gs.id)
    return host.reads - before


def _rest210():
    rig = _console_rig210()
    sid = rig[4].id
    try:
        first = _passes210(rig, 1)
        flowing = [_passes210(rig, 1, grow="line %d" % i) for i in range(5)]
        quiet = _passes210(rig, 3)
        rest = [_passes210(rig, 1) for _ in range(6)]
        eq("console rest: while output flows every 2 s pass reads the log and pushes it; after 3 reads that "
           "found nothing the console rests, read every 6 s (every third pass) instead of every pass",
           (first, flowing, quiet, rest, rig[2].lines[-1:]), (1, [1] * 5, 3, [0, 0, 1, 0, 0, 1], ["line 4"]))
        late = [_passes210(rig, 1, grow="after the quiet")] + [_passes210(rig, 1) for _ in range(3)]
        eq("console rest: a line written while it rests is read on the next 6 s read, and from then on every "
           "pass reads again", (late, rig[2].lines[-1:]), ([0, 0, 1, 1], ["after the quiet"]))
        _passes210(rig, 3)
        _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("", "", 0))
        _core210.send_console_command(rig[4].remote, "cr210", "say hi", selfname="crserver")
        _core210.console_sent[(-2109, "cr210")] = rig[3][0] + 1.0     # sent after the last read
        sent = [_passes210(rig, 1) for _ in range(3)]
        _passes210(rig, 3)
        _shared210._console_push(NS(socketio=None), sid, "[panel] restart started")
        pushed = [_passes210(rig, 1) for _ in range(2)]
        _passes210(rig, 3)
        _sf210._console_catchups[sid] = {"x210": {"id": 1, "since": None, "tries": 0}}
        caught = _passes210(rig, 1)
        _sf210._console_catchups.pop(sid, None)
        eq("console rest: a line typed into it, the panel saying something in it, and a page asking to be "
           "caught up each wake it at once, back to every pass",
           (sent, pushed, caught), ([1, 1, 1], [1, 1], 1))
    finally:
        _core210.console_sent.pop((-2109, "cr210"), None)
        _crest210._woken.pop(sid, None)
        for m in (_sf210._console_offsets, _sf210._console_partial, _pstate210._console_backlog):
            m.pop(sid, None)


def _sent_stamp210():
    """send_console_command stamps when a line was typed, for the console poller to wake on."""
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("", "", 0))
    _core210.console_sent.pop((-2108, "cr210"), None)
    _core210.send_console_command(NS(id=-2108), "cr210", "say hi", selfname="crserver")
    stamped = _core210.console_sent.pop((-2108, "cr210"), None)
    _core210.send_console_command(NS(id=-2108), "cr210", "say \x07", selfname="crserver")
    eq("console rest: typing a line stamps its console's wake time; a refused line stamps nothing",
       (isinstance(stamped, float), _core210.console_sent.pop((-2108, "cr210"), None)), (True, None))


# ── The batch's node script is not in the command sudo logs ────────────────────────────────────
def _batch_stdin210():
    sent = []
    _p9_patch_sm("_gamedig_host", lambda server: "127.0.0.1")
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None, stdin_text=None:
                 (sent.append((sh, stdin_text)), ("", "", 1))[1])
    _cron210.player_slots_batch(NS(id=-2107), "gmod210", [(k, "gmod", 27014 + k, None) for k in range(1, 9)])
    sh, stdin = sent[-1] if sent else ("", None)
    check("player batch: node reads its script from stdin (`node -`), so the command sudo logs is short (8 "
          "targets: under 1000 characters, one syslog line) and holds none of the script",
          stdin == _cron210._BATCH_NODE and " node - " in sh and "GameDig" not in sh and len(sh) < 1000,
          repr((len(sh), sh[:200])))


def _console210():
    _rest210()
    _sent_stamp210()
    _batch_stdin210()


try:
    for _fn210 in (_one_ps210, _players210, _console210):
        _p9_restore_all()
        _p9_arm(who="part210")
        _fn210()
finally:
    _p9_restore_all()
    _shutil210.rmtree(_TMP210, ignore_errors=True)
