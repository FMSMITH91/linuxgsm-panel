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
* An unchanged session cookie is re-sent once it is 5 minutes old, not on every response; a changed
  one at once. A /static file carries no Set-Cookie and no `Vary: Cookie`. CSP, X-Frame-Options and
  Permissions-Policy are on every response a browser can show as a page, and not on JSON or assets.
* The metric-history tables lose their single-column server_id / remote_id indexes (an upgrade drops
  them); every lookup by that column alone uses the (id, ts) composite.
* paramiko is imported the first time a direct-SSH host is used, not when the panel starts.
* A batch target whose last query got no answer is asked with 500 ms per packet, not gamedig's 2 s,
  except every 10th failure in a row; an answer ends it.
* The server page reads /stats on a return to its tab only when the last read is older than one poll
  period (the page's own server_detail.js, run in node).

HOW IT RUNS. Host commands are stubbed on their definition sites behind part12's tripwire; a sample
command runs for real, with bash, behind a `ps` that counts its runs. Routes run on part12's app.
"""
import json as _json210
import os
import pwd as _pwd210
import re as _re210
import shutil as _shutil210
import subprocess as _sp210  # nosec B404 - runs bash on this part's own fixtures
import tempfile as _tf210
import time as _time210
from types import SimpleNamespace as NS

from unit.part01 import _root, check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core import panel_state as _pstate210
from panel.ops.ssh_manager import _core as _core210, cron as _cron210, game as _game210, portscan as _ps210
from panel.routes import _shared as _shared210, console_rest as _crest210, server_files as _sf210
from panel.security import session_cookie as _scookie210

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
          all((runs == 1, len(tags.get("cpu", [])) == 2, _ME210 in [f[1] for f in tags.get("GJA", [])],
               _ME210 in [f[1] for f in tags.get("GJB", [])], mine.get("game_procs", 0) >= 1,
               mine.get("game_ram_mb", -1) >= 0, mine.get("game_uptime_secs", 0) > 0, host["host"]["ram_total"] > 0)),
          repr((runs, sorted(tags), mine)))
    game = _core210.server_live_metrics(NS(id=-210), short_name=_ME210, game_port=None, force=True)
    runs, tags = _ps_runs210(log), _tags210(outs[-1] if outs else "")
    check("one-game sample: ONE ps (it ran four, and an awk per process twice), and every figure is still there",
          all((runs == 1, len(tags.get("cpu", [])) == 2, len(tags.get("GJA", [])) == 1, len(tags.get("GJB", [])) == 1,
               game["game_procs"] >= 1, game["game_uptime_secs"] > 0, game["ram_total"] > 0)),
          repr((runs, sorted(tags), game)))
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
              all((got.get(sid) == (2, 16, "Box"), queried == [], a.get("unknown") is False,
                   rows == [("Ann", 3, 12), ("Bob", 7, None)], b.get("players") == a.get("players"))),
              repr((got, queried, rows, b.get("players"))))
        eq("players poll: a target the batch could not read keeps no list, so its page still asks",
           _cron210.batch_list((P9_HOST, 27016, "garrysmod")), None)
        c.get(url + "?console=1")
        names = [p.get("name") for p in _p9_json(c.get(url)).get("players") or []]
        check("players poll: a refresh the page asks for still reads, and its newer list wins over the batch's",
              (len(queried), names) == (1, ["Own"]), repr((queried, names)))
        _game210._playerlist_cache.clear()
        batch["out"] = _batch_out210({sid: {"players": [], "maxplayers": 16, "name": "Box", "numplayers": 5}})
        _cron210.player_slots_batch(NS(id=P9_HOST), "gmod210", [(sid, "gmod", 27015, None),
                                                               (sid + 1, "gmod", 27016, None)])
        hidden = _p9_json(c.get(url))
        check("players poll: a batch reply with no names while 5 are on reads 'cannot be read', as the poll's "
              "own query reads it, and asks nothing", (hidden.get("unknown"), len(queried)) == (True, 1),
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


# ── The session cookie and the page-only headers ───────────────────────────────────────────────
def _client210():
    """A signed-in test client whose session is permanent, as every panel login makes it."""
    c = _p9_client(P9_ADMIN)
    with c.session_transaction() as sess:
        sess.permanent = True
    return c


def _cookie210():
    c, later = _client210(), [None]
    _p9_patch(_scookie210, "time", NS(time=lambda: (later[0] or _time210.time())))
    poll = c.get("/api/auth/ping")
    later[0] = _time210.time() + _scookie210._REISSUE_SECONDS + 1
    old = c.get("/api/auth/ping")
    later[0] = None
    again = c.get("/api/auth/ping")
    eq("session cookie: a poll with a cookie signed moments ago sends no Set-Cookie; one 5 minutes old is re-sent "
       "(the idle timeout still slides), and the re-sent one is new again",
       ("Set-Cookie" in poll.headers, "session=" in old.headers.get("Set-Cookie", ""),
        "Set-Cookie" in again.headers),
       (False, True, False))
    js = sorted(f for f in os.listdir(os.path.join(_root, "panel", "static", "js")) if f.endswith(".js"))[0]
    later[0] = _time210.time() + 10 * _scookie210._REISSUE_SECONDS
    st = c.get("/static/js/" + js)
    eq("static file: no Set-Cookie and no Vary: Cookie, even past the re-send age (the same bytes for every "
       "viewer, so the browser keeps its cache)",
       (st.status_code, "Set-Cookie" in st.headers, "cookie" in st.headers.get("Vary", "").lower()),
       (200, False, False))
    later[0] = None
    lang = c.get("/set-language/fr?ajax=1")
    eq("session cookie: a request that changes the session (a language switch) sends it at once",
       "Set-Cookie" in lang.headers, True)
    _p9_restore_all()
    _p9_arm(who="part210")


def _headers210():
    """Which types keep the page-only headers (the responses themselves: part13, on create_app's app)."""
    from panel.security import headers as _hdr210
    kept = [t for t in ("text/html", "image/svg+xml", "application/xml", "text/plain", "application/octet-stream",
                        "application/x-unknown") if _hdr210.renders_as_page(NS(mimetype=t))]
    eq("security headers: kept on every type a browser could show as a document, and on any type not "
       "known to be inert", len(kept), 6)


# ── The history tables' redundant indexes ──────────────────────────────────────────────────────
def _indexes210():
    from flask import Flask as _Flask210
    import sqlalchemy as _sa210
    from sqlalchemy import inspect as _inspect210, text as _sql210
    from panel.db import models as _models210
    app = _Flask210("unit_part210_mig")
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP210, "upgrade.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    _models210.db.init_app(app)
    with app.app_context():
        db = _models210.db
        db.create_all()
        fresh = {t: {ix["name"] for ix in _inspect210(db.engine).get_indexes(t)} for t in ("metric_sample", "host_sample")}
        # An install from before: the single-column indexes the columns used to declare.
        # On a Table of this check's own (not the models'): an Index on a model column joins that
        # model's declared indexes for the rest of the run.
        old_md = _sa210.MetaData()
        for table, column in (("metric_sample", "server_id"), ("host_sample", "remote_id")):
            t = _sa210.Table(table, old_md, _sa210.Column(column, _sa210.Integer))
            _sa210.Index("ix_%s_%s" % (table, column), t.c[column]).create(db.engine)
        _models210._run_light_migrations()
        after = {t: {ix["name"] for ix in _inspect210(db.engine).get_indexes(t)} for t in ("metric_sample", "host_sample")}
        # EXPLAIN takes no ORM form; these are this check's own fixed statements, nothing interpolated.
        # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
        explain = (_sql210("EXPLAIN QUERY PLAN DELETE FROM metric_sample WHERE server_id = 7"),
                   # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                   _sql210("EXPLAIN QUERY PLAN SELECT id FROM host_sample WHERE remote_id = 7 LIMIT 1"))
        plans = [" ".join(str(r[-1]) for r in db.session.execute(q)) for q in explain]
        db.session.remove()
        db.engine.dispose()
    want = {"metric_sample": {"ix_metric_sample_server_ts", "ix_metric_sample_ts"},
            "host_sample": {"ix_host_sample_remote_ts", "ix_host_sample_ts"}}
    eq("history tables: a new database has the (id, ts) composite and the ts index, and no single-column "
       "id index; an upgrade drops the old one", (fresh, after), (want, want))
    check("history tables: a lookup by server_id or remote_id alone uses the composite's leading column",
          "ix_metric_sample_server_ts" in plans[0] and "ix_host_sample_remote_ts" in plans[1], repr(plans))


# ── paramiko loads at first use ────────────────────────────────────────────────────────────────
_LAZY_PROBE210 = """
import sys
sys.path.insert(0, sys.argv[1])
import panel.ops.ssh_manager as sm
import panel.ops.ssh_manager.hosts
at_import = "paramiko" in sys.modules
sm._core._PinPolicy("")
after_policy = "paramiko" in sys.modules
client = sm._core.paramiko.SSHClient
print(at_import, after_policy, "paramiko" in sys.modules, client.__module__)
"""


def _lazy210():
    import sys as _sys210
    r = _sp210.run([_sys210.executable, "-I", "-W", "ignore", "-c", _LAZY_PROBE210, _root],  # nosec B603
                   capture_output=True, text=True, timeout=120, check=False, cwd=_root,
                   env=dict(os.environ, EVENTLET_NO_GREENDNS="yes"))
    eq("paramiko: importing the SSH package (and building a host-key policy) loads no paramiko; the first "
       "use of paramiko.SSHClient loads it", r.stdout.split(), ["False", "False", "True", "paramiko.client"])


# ── A failing batch target is asked with a short wait ─────────────────────────────────────────
def _waits210(sent):
    """{port: socketTimeout} of the targets in the last batch command sent."""
    m = _re210.search(r"'(\[\[.*?\]\])'", sent[-1] if sent else "")
    return {t[3]: t[4] for t in _json210.loads(m.group(1))} if m else {}


def _short_wait210():
    sent, answer = [], {"ok": set()}

    def _shell(server, user, sh, timeout=30, selfname=None, stdin_text=None):
        sent.append(sh)
        lines = [_json210.dumps({"k": k, "c": 1, "m": 8, "n": "x", "p": None, "ok": True, "l": []})
                 for k in sorted(answer["ok"])]
        return "\n".join(lines + [_cron210._BATCH_END]), "", 0
    _p9_patch_sm("_gamedig_host", lambda server: "127.0.0.1")
    _p9_patch_sm("shell_as_game_user", _shell)
    srv, targets = NS(id=-2106), [(1, "gmod", 27015, None), (2, "vh", 2456, None), (3, "mc", 25565, None)]
    for k in list(_cron210._batch_fail_streak):
        if k[0] == -2106:
            _cron210._batch_fail_streak.pop(k, None)
    try:
        answer["ok"] = {1}
        waits = []
        for _ in range(11):
            _cron210.player_slots_batch(srv, "gm210", targets)
            waits.append(_waits210(sent))
        eq("player batch: a target that got no answer is asked with 500 ms per packet on the next passes (a "
           "Minecraft one keeps its 500), the one that answered keeps gamedig's own wait, and every 10th "
           "failure in a row is asked with the full wait again",
           [(w.get(27015), w.get(2456), w.get(25565)) for w in waits],
           [(0, 0, 500)] + [(0, 500, 500)] * 9 + [(0, 0, 500)])
        answer["ok"] = {1, 2, 3}
        _cron210.player_slots_batch(srv, "gm210", targets)
        _cron210.player_slots_batch(srv, "gm210", targets)
        eq("player batch: ...and its first answer ends the short wait", _waits210(sent).get(2456), 0)
    finally:
        for k in list(_cron210._batch_fail_streak):
            if k[0] == -2106:
                _cron210._batch_fail_streak.pop(k, None)


# ── The server page's tab-return /stats read ───────────────────────────────────────────────────
_STATS_JS210 = """
let now = 1000000; Date.now = () => now;
const on = {}; let fetches = 0;
global.document = {hidden: false, addEventListener: (e, f) => { on[e] = f; }};
global.fetch = () => { fetches += 1; return Promise.resolve({json: () => ({status: 'online'})}); };
global.setTimeout = () => 1; global.clearTimeout = () => {};
global.MOUNT = ''; global.serverId = 1;
%s
%s
const flush = () => new Promise(r => setImmediate(r));
const back = async ms => { now += ms; document.hidden = true; on.visibilitychange(); document.hidden = false;
                           on.visibilitychange(); await flush(); return fetches; };
(async () => {
  pollStats(); await flush();
  const got = [fetches, await back(3000), await back(3000), await back(6000)];
  console.log(JSON.stringify(got));
})();
"""


def _stats_return210():
    if not _shutil210.which("node"):
        skip("server page: a tab return reads /stats only past one poll period", "no node on this machine")
        return
    with open(os.path.join(_root, "panel", "static", "js", "server_detail.js"), encoding="utf-8") as fh:
        src = fh.read()
    a = src.find("var _lastStatus = '';")
    b = src.find("// The connect address", a)
    c = src.find("document.addEventListener('visibilitychange', function(){", b)
    d = src.find("});", c)
    if min(a, b, c, d) < 0:
        check("server page: a tab return reads /stats only past one poll period", False, "source not found")
        return
    prog = _STATS_JS210 % (src[a:b], src[c:d + 3])
    r = _sp210.run(["node", "-"], input=prog, capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607
    eq("server page: a return to the tab 3 s and 6 s after the last /stats read reads nothing (the poll's "
       "own timer is due); one 12 s after it (past the 8 s period of a running server) reads at once",
       r.stdout.strip() or r.stderr[-300:], "[1,1,1,2]")


try:
    for _fn210 in (_one_ps210, _players210, _console210, _cookie210, _headers210, _indexes210, _lazy210,
                   _short_wait210, _stats_return210):
        _p9_restore_all()
        _p9_arm(who="part210")
        _fn210()
finally:
    _p9_restore_all()
    _shutil210.rmtree(_TMP210, ignore_errors=True)
