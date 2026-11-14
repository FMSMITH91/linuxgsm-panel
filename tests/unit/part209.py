"""Part 209 of the unit suite: what an open page costs the panel, cut where it was measured.

Held here, each against the code that made the cost:
* The player poll's batch runs ONE node process that loads gamedig once and queries every target,
  at most _BATCH_PARALLEL at once, each with the options the `gamedig` command would give it and its
  own deadline; one that cannot load gamedig leaves the batch unrun (asked per server), and a host
  with no `gamedig` at all reads every target unknown, as before.
* A Minecraft query, by the command or in the batch, waits 500 ms per packet, not gamedig's 2 s.
* The server page's Players poll: the shared list outlives the 15 s poll, a refresh the page asks
  for replaces it, and a start, stop or restart (the port-scan invalidation) drops it.
* The dashboard's map: no lookup for a server the port scan found offline, and a lookup whose query
  failed is remembered for minutes, not 30 s.
* Valheim, which listens on its port + 1 on -crossplay, reads online on the status poll and the
  server page.
* One `tailscale version` per binary, not two per reading.
* pollWhenVisible does not re-run a poll on the first return to a page that just loaded it.
* lgsm_data.warm() runs at the service's start, not in create_app.
* The plugin browser reads a Paper build's version from paper.jar when version_history.json is absent.

HOW IT RUNS. Host commands are stubbed on their definition sites behind part12's tripwire; the batch's
shell runs for real, with bash, against a fake gamedig package (bin/gamedig and lib/index.js, the
layout the real one has) and the real node and jq. Routes run on part12's app.
"""
import ast as _ast209
import json as _json209
import os
import shutil as _shutil209
import subprocess as _sp209  # nosec B404 - runs bash/node/jq on this part's own fixtures
import tempfile as _tf209
import time as _time209
from types import SimpleNamespace as NS

from unit.part01 import _root, check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.ops import tailscale_integration as _tsi209
from panel.ops.ssh_manager import cron as _cron209, game as _game209, portscan as _ps209
from panel.routes import api as _api209, modrinth_plugins as _mdr209, server_files as _sf209
from panel.services import monitoring as _mon209

_TMP209 = _tf209.mkdtemp(prefix="lgsm-unit-p209-")
_HAVE209 = bool(_shutil209.which("node") and _shutil209.which("jq"))
# The stand-in shell's PATH after the rig's bin/: where node and jq are, then /usr/bin and /bin.
_TOOLS209 = os.pathsep.join(sorted({os.path.dirname(p) for p in (_shutil209.which("node"), _shutil209.which("jq"))
                                    if p}) + ["/usr/bin", "/bin"])

# A gamedig package: bin/gamedig (never run by the batch) and lib/index.js, whose GameDig answers by
# port. Each answer carries what the batch handed it: the options (in the name), the queries in
# flight when it started (as maxplayers) and which instance asked. Every load appends to P209_LOG.
_FAKE_LIB209 = r"""
require("fs").appendFileSync(process.env.P209_LOG, "load\n");
let live = 0, made = 0;
class GameDig {
  constructor(o) { made += 1; this.i = made; }
  query(o) {
    live += 1;
    const at = live, i = this.i;
    if (o.port === "27999") return new Promise(() => {});
    if (o.port === "27998") return new Promise((r, j) => setTimeout(() => { live -= 1; j(new Error("Failed all 1 attempts")); }, 50));
    const n = JSON.stringify({p: o.port, st: o.socketTimeout === undefined ? null : o.socketTimeout, sc: o.stripColors,
                              pc: o.portCache, rp: o.requestPlayers, g: o.givenPortOnly, i: i});
    return new Promise(r => setTimeout(() => { live -= 1; r({players: [{name: "a"}], maxplayers: at, name: n}); }, 150));
  }
}
module.exports = { GameDig };
"""


def _rig209(name, with_lib=True):
    """A gamedig package dir under this part's temp dir; its bin/ goes on PATH."""
    base = os.path.join(_TMP209, name)
    os.makedirs(os.path.join(base, "bin"), exist_ok=True)
    with open(os.path.join(base, "bin", "gamedig"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho '{\"error\":\"the command was run\"}'\n")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(os.path.join(base, "bin", "gamedig"), 0o700)  # nosec B103 - owner-only test stub
    if with_lib:
        os.makedirs(os.path.join(base, "lib"), exist_ok=True)
        with open(os.path.join(base, "lib", "index.js"), "w", encoding="utf-8") as fh:
            fh.write(_FAKE_LIB209)
    return os.path.join(base, "bin")


def _bash209(path, log):
    """shell_as_game_user's stand-in: the body run by bash with `path` first on PATH."""
    def _run(server, user, sh, timeout=30, selfname=None):
        env = dict(os.environ, PATH=path + os.pathsep + _TOOLS209, P209_LOG=log)
        try:
            r = _sp209.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                           env=env, check=False)
        except (_sp209.TimeoutExpired,
                __import__("eventlet.patcher", fromlist=["original"]).original("subprocess").TimeoutExpired):
            return "", "Command timed out", -1
        return r.stdout.strip(), r.stderr, r.returncode
    return _run


def _loads209(log):
    try:
        with open(log, encoding="utf-8") as fh:
            return fh.read().count("load")
    except OSError:
        return 0


def _batch209():
    """The batch through player_slots_batch, run for real against the fake package."""
    log = os.path.join(_TMP209, "loads.log")
    targets = [(k, "gmod", 27014 + k, None) for k in range(1, 11)]
    targets += [(11, "mc", 25565, None), (12, "gmod", 27999, None), (13, "gmod", 27998, None)]
    _p9_patch_sm("_gamedig_host", lambda server: "127.0.0.1")
    _p9_patch(_cron209, "_BATCH_TARGET_TIMEOUT", 1)
    _p9_patch_sm("shell_as_game_user", _bash209(_rig209("pkg"), log))
    t0 = _time209.monotonic()
    got = _cron209.player_slots_batch(NS(id=209001), "gmodsrv209", targets) or {}
    took = _time209.monotonic() - t0
    opts = {k: _json209.loads(v[2]) for k, v in got.items() if v[2]}
    eq("batch: ONE node process loads gamedig once for all 13 targets (it was a gamedig per target)",
       (_loads209(log), len(got)), (1, 13))
    eq("batch: at most _BATCH_PARALLEL queries run at once, and that many do",
       max(v[1] or 0 for v in got.values()) if got else None, _cron209._BATCH_PARALLEL)
    eq("batch: a target past its own deadline, and one gamedig failed, read unknown; the others answer",
       (got.get(12), got.get(13), len(opts), took < 6), ((None, None, None), (None, None, None), 11, True))
    first = opts.get(1, {})
    eq("batch: each query gets the gamedig command's options (port as text, stripColors, portCache and "
       "requestPlayers on, givenPortOnly off) and an instance of its own",
       ([first.get(k) for k in ("p", "st", "sc", "pc", "rp", "g")], len({o.get("i") for o in opts.values()})),
       (["27015", None, True, True, True, False], len(opts)))
    eq("batch: a Minecraft target waits 500 ms per packet, the others gamedig's default",
       (opts.get(11, {}).get("st"), opts.get(2, {}).get("st")), (500, None))
    _batch_fallbacks209(targets, log)


def _batch_fallbacks209(targets, log):
    """The batch when gamedig cannot be loaded in-process, and on a host with no gamedig at all."""
    _p9_patch_sm("shell_as_game_user", _bash209(_rig209("nolib", with_lib=False), log))
    check("batch: a gamedig node cannot load in-process leaves the batch unrun (None: each server is "
          "then asked on its own), never 'every server unknown'",
          _cron209.player_slots_batch(NS(id=209001), "gmodsrv209", targets[:3]) is None)
    empty = os.path.join(_TMP209, "empty")
    os.makedirs(empty, exist_ok=True)
    if _shutil209.which("gamedig", path=_TOOLS209):
        skip("batch: no gamedig command reads every target unknown", "this machine has a gamedig on PATH")
        return
    _p9_patch_sm("shell_as_game_user", _bash209(empty, log))
    eq("batch: a host with no gamedig command reads every target unknown, as before",
       _cron209.player_slots_batch(NS(id=209001), "gmodsrv209", targets[:2]),
       {1: (None, None, None), 2: (None, None, None)})


def _cli_flags209():
    """Every single-target gamedig command gives Minecraft its 500 ms socket timeout."""
    sent = []
    _p9_patch_sm("_gamedig_host", lambda server: "127.0.0.1")
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None:
                 (sent.append(sh), ("", "", 1))[1])
    srv = NS(id=209002)
    for gt in ("mc", "gmod"):
        _cron209.player_slots(srv, "mcsrv209", gt, 25565)
        _cron209.player_count(srv, "mcsrv209", gt, 25565)
        _cron209._game_map_cache.clear()
        _cron209.game_map(srv, "mcsrv209", gt, 25565)
        _game209.player_list(srv, "mcsrv209", gt, 25565)
        _game209._queried_version(srv, "mcsrv209", gt, 25565)
    kinds = [("minecraft" if "--type minecraft" in s else "other", "127.0.0.1:25565 --socketTimeout 500 " in s,
              "socketTimeout" in s) for s in sent]
    eq("gamedig command: every Minecraft query (counts, slots, map, list, version) passes "
       "--socketTimeout 500 after its address, and no other game's does",
       kinds, [("minecraft", True, True)] * 5 + [("other", False, False)] * 5)


def _map209():
    """The dashboard's map lookup: skipped for an offline server, a failed one remembered."""
    asked = []
    _p9_patch(_mon209, "game_map", lambda remote, user, *a: (asked.append(user), "m")[1])
    sample = {"host": {"ram_total": 1, "cpu_percent": 0.0},
              "users": {u: {"game_procs": 1} for u in ("up209", "down209")}, "ports": set()}
    _p9_patch(_mon209, "host_live_metrics", lambda remote: sample)
    host = NS(id=209003)
    rows = [NS(installed=True, remote=host, remote_id=209003, id=i, short_name=u, port=27015 + i,
               game_type="gmod", query_type=None, status=st)
            for i, (u, st) in enumerate((("up209", "online"), ("down209", "offline")))]
    out = {sid: mp for work in _mon209._host_metrics_work(rows) for sid, _m, _r, mp in _mon209._query_host_metrics(work)}
    check("dashboard map: asked for the running server whose port is open, not for one the port scan "
          "found offline (both running)", asked == ["up209"] and out == {0: "m", 1: ""}, repr((asked, out)))
    sent = []
    answer = {"out": ""}
    _p9_patch_sm("_gamedig_host", lambda server: "127.0.0.1")
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None:
                 (sent.append(sh), (answer["out"], "", 0))[1])
    key = (209004, 27015)
    _cron209._game_map_cache.pop(key, None)
    first = _cron209.game_map(NS(id=209004), "gmodsrv209", "gmod", 27015)
    left = _cron209._game_map_cache.get(key, (0, None))[0] - _time209.time()
    again = _cron209.game_map(NS(id=209004), "gmodsrv209", "gmod", 27015)
    check("dashboard map: a lookup whose query failed is remembered for minutes, so the next polls ask "
          "nothing", first == "" and again == "" and len(sent) == 1 and left > 200, repr((len(sent), left)))
    _cron209._game_map_cache.pop(key, None)
    answer["out"] = "=gm_construct"
    got = _cron209.game_map(NS(id=209004), "gmodsrv209", "gmod", 27015)
    left = _cron209._game_map_cache.get(key, (0, None))[0] - _time209.time()
    check("dashboard map: ...while one that answered is kept 30 s, as before (an answer with no map too)",
          got == "gm_construct" and 0 < left <= 31, repr((got, left)))
    _cron209._game_map_cache.pop(key, None)


def _valheim209():
    """Valheim on -crossplay listens on port + 1: the status poll and the server page see it run."""
    rows = [NS(id=1, installed=True, status="offline", port=2456, game_type="vh"),
            NS(id=2, installed=True, status="offline", port=27015, game_type="gmod")]
    _flip, flipped = _api209._status_flips(_p9, [(rows, NS(id=209005, public_ip="203.0.113.9"), {2457, 27016})])
    eq("valheim: the status poll reads a Valheim listening on 2457 (port + 1) online; another game on "
       "port + 1 stays offline", flipped, {1: "online"})
    _ps209._port_scan_cache[209006] = (_time209.time() + 60, {2457})
    try:
        eq("valheim: ...and the server page's port check agrees (LinuxGSM says STARTED)",
           (_game209._really_serving(NS(id=209006), NS(port=2456, game_type="vh")),
            _game209._really_serving(NS(id=209006), NS(port=2456, game_type="gmod"))), (True, False))
    finally:
        _ps209._port_scan_cache.pop(209006, None)


def _playerlist209():
    """The Players poll through the route: shared past the 15 s poll, replaced and dropped on change."""
    sid = _p9_new_server(P9_HOST, "gmod209", "gmod", 27015, status="online")
    reads = []
    answer = {"out": '{"p":[{"name":"Ann","score":1,"time":5}],"c":1}'}
    _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.209")
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None:
                 (reads.append(sh), (answer["out"], "", 0))[1])
    _game209._playerlist_cache.clear()
    try:
        c = _p9_client(P9_ADMIN)
        url = "/api/server/%d/playerlist" % sid
        a, b = _p9_json(c.get(url)), _p9_json(c.get(url))
        left = _game209._playerlist_cache.get((P9_HOST, 27015, "garrysmod"), (0,))[0] - _time209.time()
        check("players poll: two polls are one gamedig read, and the shared list outlives the page's 15 s "
              "poll with a margin", len(reads) == 1 and a.get("players") == b.get("players") and left > 17,
              repr((len(reads), left)))
        answer["out"] = '{"p":[{"name":"Ann"},{"name":"Bob"}],"c":2}'
        c.get(url + "?console=1")
        names = [p.get("name") for p in _p9_json(c.get(url)).get("players") or []]
        check("players poll: a refresh the page asked for replaces the shared list, so the next timed "
              "poll shows it without another read", names == ["Ann", "Bob"] and len(reads) == 2,
              repr((names, len(reads))))
        _ps209._invalidate_port_scan(P9_HOST)
        c.get(url)
        eq("players poll: a start, stop or restart (the port scan dropped) drops the host's shared lists",
           len(reads), 3)
    finally:
        _game209._playerlist_cache.clear()
        _p9_delete_server(sid)


def _tailscale209():
    """One `tailscale version` per binary: not twice per reading, not again while the file is the same."""
    calls, binary = [], {"id": ("/usr/bin/tailscale", 1, 1, 1)}
    _p9_patch(_tsi209, "_run_ts", lambda args, timeout=5:
              (calls.append(list(args)), ("1.%d.0" % len(binary["id"]) if args == ["version"] else "", "", 1))[1])
    _p9_patch(_tsi209, "_binary_id", lambda: binary["id"])
    for name in ("_read_serve_status", "_detect_magic_dns"):
        _p9_patch(_tsi209, name, lambda info: None)
    saved = dict(_tsi209._cache)
    try:
        _tsi209._cache.update(info=None, ts=0)
        first = _tsi209.get_tailscale_info()
        n1 = calls.count(["version"])
        _tsi209._cache["ts"] = 0
        again = _tsi209.get_tailscale_info()
        n2 = calls.count(["version"])
        binary["id"] = ("/usr/bin/tailscale", 2, 2, 2, 2)
        _tsi209._cache["ts"] = 0
        upgraded = _tsi209.get_tailscale_info()
        check("tailscale: one `tailscale version` per reading (it was two), none on a later reading of the "
              "same binary, and a new one once the file changes",
              (n1, n2, calls.count(["version"])) == (1, 1, 2) and first.version == again.version == "1.4.0"
              and upgraded.version == "1.5.0" and upgraded.installed, repr((n1, n2, calls)))
    finally:
        _tsi209._cache.clear()
        _tsi209._cache.update(saved)


def _poll_js209():
    """panel.js's own pollWhenVisible, in node: a return right after loading runs nothing."""
    if not _shutil209.which("node"):
        skip("pollWhenVisible: no re-run on the first return", "no node on this machine")
        return
    with open(os.path.join(_root, "panel", "static", "js", "panel.js"), encoding="utf-8") as fh:
        js = fh.read()
    start = js.find("window.pollWhenVisible = function")
    src = js[start:js.find("\n};\n", start) + 3] if start >= 0 else ""
    prog = ("var t = 1000; Date.now = function(){ return t; }; var on = {}, n = 0;\n"
            "var document = {hidden: false, addEventListener: function(e, f){ on[e] = f; }};\n"
            "var window = {}, _visPolls = {}; var setInterval = function(){ return 1; };\n" + src
            + "\nwindow.pollWhenVisible(function(){ n++; }, 15000);\n"
            "on.visibilitychange(); var a = n; t += 15000; on.visibilitychange();\n"
            "console.log(JSON.stringify([a, n]));\n")
    r = _sp209.run(["node", "-"], input=prog, capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   check=False)
    eq("pollWhenVisible: a return to the tab just after the page loaded runs no poll again; one after "
       "the poll's interval still catches up", (r.stdout.strip(), bool(src)), ("[0,1]", True))


def _warm209():
    """lgsm_data.warm() runs in the service's start block, and not in create_app."""
    with open(os.path.join(_root, "panel", "install", "app.py"), encoding="utf-8") as fh:
        tree = _ast209.parse(fh.read())

    def _warms(node):
        return any(isinstance(n, _ast209.Call) and isinstance(n.func, _ast209.Attribute)
                   and n.func.attr == "warm" and getattr(n.func.value, "id", "") == "lgsm_data"
                   for n in _ast209.walk(node))
    main = [n for n in tree.body if isinstance(n, _ast209.If) and "__main__" in _ast209.dump(n.test)]
    create = [n for n in tree.body if isinstance(n, _ast209.FunctionDef) and n.name == "create_app"]
    eq("startup: lgsm_data.warm() runs where the service starts the panel, and not in create_app "
       "(which the suites call)", (bool(main) and _warms(main[0]), bool(create) and _warms(create[0])), (True, False))


def _paper209():
    """The plugin browser's version from paper.jar when Paper wrote no version_history.json."""
    sid = _p9_new_server(P9_HOST, "pmc209", "pmc", 25570, status="online")
    sent = []
    _p9_patch_sm("read_file", lambda *a, **k: (None, "File not found"))
    _p9_patch_sm("browse_dir", lambda *a, **k: {"path": "serverfiles/plugins", "entries": []})
    _p9_patch(_sf209, "_read_refused", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None:
                 (sent.append((user, sh)), ('{"id": "26.3", "name": "26.3"}', "", 0))[1])
    try:
        got = _p9_json(_p9_client(P9_ADMIN).get("/api/server/%d/plugins" % sid))
        check("plugins: with no version_history.json the list reads the version from paper.jar's "
              "version.json, as the game account", got.get("mc_version") == "26.3" and len(sent) == 1
              and sent[0][0] == "pmc209" and 'unzip -p "$sf/paper.jar" version.json' in sent[0][1], repr((got, sent)))
        _p9_patch_sm("read_file", lambda *a, **k: ('{"currentVersion": "1.21.4-212-abc (MC: 1.21.4)"}', None))
        eq("plugins: ...and version_history.json still comes first, with no second read",
           (_mdr209.mc_version(NS(remote=None, short_name="pmc209")), len(sent)), ("1.21.4", 1))
    finally:
        _p9_delete_server(sid)


try:
    _p9_arm(who="part209")
    if _HAVE209:
        _batch209()
    else:
        skip("batch: one node process for every target", "no node or jq on this machine")
    for _fn209 in (_cli_flags209, _map209, _valheim209, _playerlist209, _tailscale209, _poll_js209,
                   _warm209, _paper209):
        _p9_restore_all()
        _p9_arm(who="part209")
        _fn209()
finally:
    _p9_restore_all()
    _shutil209.rmtree(_TMP209, ignore_errors=True)
