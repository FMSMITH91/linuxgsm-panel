"""Part 34 of the unit suite: ws4-sudo — the panel's privileged-call flood, cut where it starts.

On the live host the panel unit's journal was 4964 sudo/pam lines out of every 5000: about 580
privileged calls an hour, three journal lines each, for three game servers. Each fix here removes
calls with no loss of function, and each check below fails on the code before it:

* A. the metrics sampler no longer runs a gamedig map lookup it throws away (want_map=False), and
     the dashboard, its only reader, still gets the map;
* B. the player poll carries the map in the same reply and fills game_map's cache; game_map runs
     one lookup per key at a time and never shortens a longer-lived entry; /playerlist's timed
     poll shares a list read seconds ago, and the page polls it only on the Console tab;
* C. one gamedig run per HOST, as one game account that is neither the panel's own account, its
     SSH login, nor (on the panel's host) an administrator or root-equivalent account; a target the
     batch could not read takes the usual fallbacks, and a batch that did not run to its end marker
     is retried per server;
* D. the priority keeper reads nice values unprivileged and renices only accounts that drifted —
     and a read whose getent failed is "could not tell", never "nothing to renice";
* E. restart flags are read for a host only while a server there has daily restart on or shows
     the banner, every ten minutes otherwise (a failed read is not counted as one), never for a
     host with nothing installed or a failed port scan;
* F. the ban-watcher reads UFW only when ufw's rule files changed (fail2ban every tick), keeps a
     tick's ban decision when a later step of that tick raises, and the debug report says "rule
     files unchanged" only after a check that really skipped;
* G. one console tick is one round trip — and the console still streams prompt, in order, complete
     and unduplicated, its pushes stitching byte-exact with the 30 s /api/console window, an idle
     tick reading nothing and counting as a good one;
* H. a running server gamedig cannot read no longer costs a LinuxGSM `details` per pass, and a
     config read that found nothing, or LinuxGSM's static query settings, is not re-read every pass;
* I. the debug report reads the panel's own output by indexed journal fields (sudo noise out
     BEFORE the line limit), counts the sudo calls from a read of their own, prints them once, and
     names the game-account reads by fixed labels.

HOW IT RUNS. Every host command is stubbed on the module that defines it, saved and restored in a
finally, behind a tripwire under every real transport. Where the SHELL a change builds is the thing
under test, the stub runs it for real, with bash, against a real file (the console) or a fake
`gamedig` on PATH piped through the real jq (the batched player query). The monitor and sampler run
against this part's own in-memory database; the priority keeper is driven through the loop
register_routes handed part12's supervisor, and the ban-watcher through its own 90 s loop.
"""
import ast as _ast34
import json as _json34
import os
import pwd as _pwd34
import re as _re34
import shutil as _shutil34
import subprocess as _sp34  # nosec B404 - runs bash/node/jq on this part's own fixtures
import tempfile as _tf34
import threading as _th34
import time as _time34
from types import SimpleNamespace as NS

from flask import Flask as _Flask34

from unit.part01 import check
from unit.part05 import _helper, _root
from unit.part12 import _p9, _p9_app, _p9_supervised
from unit.part20 import _env, _patch, _patched
import app as _app34mod
from panel.core import panel_state as _ps34
from panel.db.models import GameServer, HostSample, MetricSample, RemoteServer, db
from panel.ops import system_ops as _so34
from panel.ops.debug_report import _src_journal as _sj34
from panel.ops.debug_report import logs as _lg34
from panel.ops.debug_report import network as _nw34
from panel.ops.ssh_manager import _core as _core34
from panel.ops.ssh_manager import cron as _cron34
from panel.ops.ssh_manager import files as _files34
from panel.ops.ssh_manager import game as _game34
from panel.routes import api as _api34
from panel.routes import server_files as _sf34
from panel.security import banlist as _bl34
from panel.security import privileged as _priv34
from panel.services import monitoring as _mon34

_TMP34 = _tf34.mkdtemp(prefix="lgsm-unit-p34-")
_ABSENT34 = object()
_SAVED34 = {}


def _set34(owner, name, value):
    """owner.name = value, the original saved the first time (restored by _restore34)."""
    if (owner, name) not in _SAVED34:
        _SAVED34[(owner, name)] = (owner.__dict__.get(name, _ABSENT34)
                                   if isinstance(owner, type(os)) else getattr(owner, name))
    setattr(owner, name, value)


def _restore34():
    for (owner, name), value in list(_SAVED34.items()):
        if value is _ABSENT34:
            owner.__dict__.pop(name, None)
        else:
            setattr(owner, name, value)
    _SAVED34.clear()


# ── the tripwire: nothing here may reach a real transport ───────────────────────────────────────
_TRIP34 = []


def _arm34():
    for name in ("_run_via_ssh_cli", "get_connection", "_exec_local_shell", "_exec_local_argv"):
        def _tripped(*a, _n=name, **k):
            _TRIP34.append(_n)
            raise ConnectionError("part34 tripwire: a test reached the real %s" % _n)
        _set34(_core34, name, _tripped)


def _as_account34(user, sh, selfname=None):
    """`sh` as game_user_cmd quotes it, minus the `sudo -u <account>` (`bash -c '<sh>'`).

    So the quoting a host would unwrap is unwrapped here too, by bash, rather than assumed.
    """
    cmd = _core34.game_user_cmd(user, sh, selfname=selfname)
    prefix = "sudo -u %s " % user
    return cmd[len(prefix):] if cmd.startswith(prefix) else "false"


def _bash34(sh, env_path=None, timeout=60):
    """Run `sh` with bash, as a host would; (out, err, rc) shaped like run_command's (stripped)."""
    env = dict(os.environ)
    if env_path:
        env["PATH"] = env_path + os.pathsep + env.get("PATH", "")
    try:
        r = _sp34.run(["bash", "-c", sh],  # nosec B603 B607 - bash on this part's own fixtures
                      capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except _sp34.TimeoutExpired:
        return "", "Command timed out", -1
    return r.stdout.strip(), r.stderr, r.returncode


# ── this part's own database ─────────────────────────────────────────────────────────────────────
_app34 = _Flask34("unit_part34_db")
_app34.config.update(SECRET_KEY="unit-part34",  # nosec B106 - this part's throwaway app
                     SQLALCHEMY_DATABASE_URI="sqlite://", SQLALCHEMY_TRACK_MODIFICATIONS=False,
                     TESTING=True)
db.init_app(_app34)
_PSTATE34 = [(m, dict(m)) for entries in _ps34.keyed_state_with_locks() for m, _lock in entries]


def _fresh_db34():
    """An empty schema and no row-keyed state (a fresh DB hands out ids 1, 2, 3 again)."""
    db.drop_all()
    db.create_all()
    for m, _snap in _PSTATE34:
        m.clear()
    for cache in (_cron34._game_map_cache, _cron34._lgsm_query_cache, _game34._playerlist_cache,
                  _mon34._restart_flags_read_at, _mon34._batch_failed_at):
        cache.clear()


def _host34(name, **kw):
    kw.setdefault("auth_method", "local")
    kw.setdefault("is_local", kw["auth_method"] == "local")
    r = RemoteServer(name=name, host=kw.pop("host", "127.0.0.1"), username=kw.pop("username", "lgsm34"),
                     auth_credential="", **kw)
    db.session.add(r)
    db.session.commit()
    return r


def _server34(remote, short, game_type, port, **kw):
    kw.setdefault("installed", True)
    kw.setdefault("status", "online")
    g = GameServer(remote_id=remote.id, name=short, short_name=short, game_type=game_type,
                   port=port, **kw)
    db.session.add(g)
    db.session.commit()
    return g


# A gamedig stand-in: answers by port, as the real one would for three servers on one host.
_FAKE_GAMEDIG34 = r"""#!/bin/sh
case "$3" in
  *:27015) echo '{"players":[{"name":"a"},{"name":"b"}],"maxplayers":16,"name":"Box  Server","map":"gm_<b>construct</b>"}' ;;
  *:28960) echo '{"players":[],"maxplayers":"16","name":"COD","map":"mp_crash"}' ;;
  *:27020) exec sleep 30 ;;
  *) echo '{"error":"Failed all 1 attempts"}' ;;
esac
"""
_BIN34 = os.path.join(_TMP34, "bin")
os.makedirs(_BIN34, exist_ok=True)
with open(os.path.join(_BIN34, "gamedig"), "w", encoding="utf-8") as _fh34:
    _fh34.write(_FAKE_GAMEDIG34)
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
os.chmod(os.path.join(_BIN34, "gamedig"), 0o700)
_HAVE_JQ34 = _shutil34.which("jq") is not None


def _as_is34(out):
    """A rig's tamper hook when nothing is to be tampered with: the output as it came."""
    return out


class _GameShell34:
    """_core.shell_as_game_user, run for real by bash with the fake gamedig and the real jq.

    Records (account, command) for every call. `fail` makes the next call answer like a
    non-raising transport that timed out.
    """

    def __init__(self):
        self.calls, self.fail = [], 0
        self.tamper = _as_is34      # rewrites the next BATCH's output (rc stays 0), then is reset

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append((user, sh))
        if self.fail:
            self.fail -= 1
            return "", "SSH command timed out", -1
        out, err, rc = _bash34(_as_account34(user, sh, selfname), env_path=_BIN34, timeout=60)
        if "@@lgsm-batch-end" in sh:
            tamper, self.tamper = self.tamper, _as_is34
            out = tamper(out)
        return out, err, rc


# ════════════════════════════════════════════════════════════════════════════════════════════════
# A + B + C + H: the player poll, the sampler, game_map, and the fallback chain
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _poll_rig34():
    """Three gamedig-mapped running servers on the panel's host, one on a host of its own."""
    _fresh_db34()
    local = _host34("p34-local")
    other = _host34("p34-solo", auth_method="tailscale", is_local=False, host="192.0.2.34",
                    username="lgsmssh34")
    rows = {"gmod": _server34(local, "gmodsrv34", "gmod", 27015),
            "cod": _server34(local, "codsrv34", "cod", 28960),
            "mc": _server34(local, "mcsrv34", "mc", 25565),
            "solo": _server34(other, "solosrv34", "gmod", 27015)}
    return local, other, {k: v.id for k, v in rows.items()}


_ADMINS34 = set()          # the fixture accounts _admin_account answers "administrator" for


def _poll_stubs34(shell, cfg_reads, status_reads, lgsmq_reads):
    # The fixture accounts do not exist on this machine, and the real lookup answers "cannot tell,
    # treat as an administrator" for a missing one; _section_admin34 drives the real one.
    _set34(_mon34, "_admin_account", lambda user: user in _ADMINS34)
    _set34(_core34, "shell_as_game_user", shell)
    _set34(_core34, "_gamedig_host", lambda server: "127.0.0.1")
    _set34(_mon34, "lgsm_get_values", lambda *a, **k: (cfg_reads.append(a[1]), {})[1])
    _set34(_mon34, "sm_get_server_status",
           lambda remote, gs: (status_reads.append(gs.short_name), "online")[1])
    _set34(_mon34, "sm_player_count_via_lgsm_query",
           lambda *a, **k: (lgsmq_reads.append(a[1]), None)[1])


def _accounts34(shell):
    return [u for u, _sh in shell.calls]


def _batched34(shell):
    """The commands of `shell` that were batches, and those that were not."""
    batch = [sh for _u, sh in shell.calls if "@@lgsm-batch-end" in sh]
    return batch, [sh for _u, sh in shell.calls if "@@lgsm-batch-end" not in sh]


def _section_poll34():
    shell, cfg_reads, status_reads, lgsmq_reads = _GameShell34(), [], [], []
    _poll_stubs34(shell, cfg_reads, status_reads, lgsmq_reads)
    local, other, ids = _poll_rig34()
    _mon34._refresh_player_counts(_app34)
    counts = {k: (_ps34._player_counts.get(i) or {}) for k, i in ids.items()}
    batch, single = _batched34(shell)
    check("C batch: one player poll makes ONE gamedig run for the three servers on a host, and one "
          "for the host with one server — not one per server",
          all((len(shell.calls) == 2, len(batch) == 1)), repr(_accounts34(shell)))
    check("C batch: ...run as one of that host's own game accounts (never the panel's account, "
          "never root), and the one-server host as its own account, exactly as before",
          sorted(_accounts34(shell)) == ["gmodsrv34", "solosrv34"], repr(_accounts34(shell)))
    check("C batch: every answered server gets its own count, capacity and name from the shared "
          "reply (cod's capacity arrives as the TEXT \"16\" and is read as 16)",
          (counts["gmod"].get("count"), counts["gmod"].get("max"), counts["gmod"].get("name"),
           counts["cod"].get("count"), counts["cod"].get("max"), counts["solo"].get("count"))
          == (2, 16, "Box Server", 0, 16, 2), repr(counts))
    check("C batch: a server the batch could not read is UNKNOWN, never 0, and went down the usual "
          "fallbacks (LinuxGSM's own query) without a second gamedig run of its own",
          all((counts["mc"].get("count") is None, lgsmq_reads == ["mcsrv34"],
               not any("25565" in sh for sh in single))), repr((counts["mc"], lgsmq_reads)))
    check("H fallback: a server the monitor found LISTENING is not asked for a LinuxGSM `details` "
          "(a sudo'd du of its files) when nothing could read it — its count stays unknown",
          all((status_reads == [], counts["mc"].get("count") is None)), repr(status_reads))
    _section_map34(shell, local, ids)
    _section_poll_repeat34(cfg_reads, ids)
    return local, other, ids


def _section_map34(shell, local, ids):
    before = len(shell.calls)
    games = [(ids["gmod"], "gmodsrv34", 27015, "gmod", None), (ids["cod"], "codsrv34", 28960, "cod", None)]
    _set34(_mon34, "host_live_metrics", lambda remote, force=False: {"host": {"ram_total": 8000}})
    _set34(_mon34, "metrics_for_game",
           lambda sample, short, port: {"game_procs": 1, "ram_total": 8000, "game_cpu_percent": 1})
    maps = [row[3] for row in _mon34._query_host_metrics((NS(id=local.id), games))]
    check("B map: after one player poll the dashboard's map lookup runs NO gamedig: the poll's own "
          "reply carried it, sanitised as game_map sanitises (no angle brackets)",
          all((len(shell.calls) == before, maps == ["gm_bconstruct/b", "mp_crash"])),
          repr((len(shell.calls) - before, maps)))
    srv = _api34._sample_metrics([(NS(id=local.id, display_name="h", is_local=True), games)],
                                 {local.id: NS(display_name="h", is_local=True)}, {})
    check("A caller: /api/dashboard/metrics' sampler still returns each running server's map",
          srv.get(str(ids["gmod"]), {}).get("map") == "gm_bconstruct/b", repr(srv))


def _section_poll_repeat34(cfg_reads, ids):
    cfg_after_one = len(cfg_reads)
    _mon34._refresh_player_counts(_app34)
    check("H max: a config that was READ and names no capacity is not re-read on the next pass",
          all((len(cfg_reads) == cfg_after_one, cfg_after_one >= 1)), repr(cfg_reads))
    # a failed read is not an answer: it is retried
    _set34(_mon34, "lgsm_get_values", lambda *a, **k: (cfg_reads.append(a[1]), None)[1])
    _ps34._max_players_cache.pop(ids["mc"], None)
    _mon34._refresh_player_counts(_app34)
    _mon34._refresh_player_counts(_app34)
    check("H max: ...while an UNREADABLE config is retried on every pass, and never cached",
          all((cfg_reads.count("mcsrv34") >= cfg_after_one + 2,
               ids["mc"] not in _ps34._max_players_cache)), repr(cfg_reads))
    _set34(_mon34, "time", NS(time=lambda: _time34.time() + 601, monotonic=_time34.monotonic,
                              sleep=_time34.sleep))
    _set34(_mon34, "lgsm_get_values", lambda *a, **k: (cfg_reads.append(a[1]), {"maxplayers": "20"})[1])
    _ps34._max_players_cache[ids["mc"]] = (None, _time34.time())
    got = _mon34._server_max_config(NS(id=ids["mc"], remote=None, short_name="mcsrv34",
                                       lgsm_name="mcserver"))
    _restore_one34(_mon34, "time")
    check("H max: ...and a 'no capacity' answer expires (10 min), so a capacity added later is seen",
          got == 20, repr(got))


def _restore_one34(owner, name):
    value = _SAVED34.pop((owner, name))
    if value is _ABSENT34:
        owner.__dict__.pop(name, None)
    else:
        setattr(owner, name, value)


def _cut_batch34(out):
    """A batch's output cut off partway: its first reply whole, the next one broken off mid-line."""
    lines = out.splitlines()
    return "\n".join(lines[:1] + [ln[:25] for ln in lines[1:2]])


def _not_run_pass34(shell, ids):
    """One poll whose batch did not run; (per-server accounts asked, gmod's count, its host backed off)."""
    _ps34._player_counts.clear()
    _mon34._batch_failed_at.clear()
    del shell.calls[:]
    _mon34._refresh_player_counts(_app34)
    per_server = sorted(u for u, sh in shell.calls if "@@lgsm-batch-end" not in sh)
    gmod = (_ps34._player_counts.get(ids["gmod"]) or {}).get("count")
    return per_server, gmod, bool(_mon34._batch_failed_at)


def _section_batch_edges34():
    shell, cfg_reads, status_reads, lgsmq_reads = _GameShell34(), [], [], []
    _poll_stubs34(shell, cfg_reads, status_reads, lgsmq_reads)
    local, _other, ids = _poll_rig34()
    each = (["codsrv34", "gmodsrv34", "mcsrv34", "solosrv34"], 2, True)
    shell.tamper = lambda out: "\n".join(out.splitlines()[:-1])    # ran, rc 0, no end marker
    no_end = _not_run_pass34(shell, ids)
    shell.tamper = _cut_batch34                                    # cut off inside its 2nd reply
    cut = _not_run_pass34(shell, ids)
    check("C batch: a batch that answered rc 0 with NO end marker — or was cut off partway — did "
          "not run to its end: each server is then asked on its own, as its own account, and the "
          "host backs off", all((no_end == each, cut == each)), repr((no_end, cut)))
    shell.fail = 1                      # the batch itself: a non-raising transport that timed out
    timed_out = _not_run_pass34(shell, ids)
    check("C batch: a batch whose transport failed (rc -1, no output) is never 'everyone is empty': "
          "each server is then asked on its own, as its own account", timed_out == each,
          repr((_accounts34(shell), timed_out)))
    del shell.calls[:]
    _mon34._refresh_player_counts(_app34)
    check("C batch: ...and that host is polled per server for a while before the batch is tried "
          "again, so a refused account costs no failed batch on every pass",
          all((_batched34(shell)[0] == [], len(shell.calls) == 4)), repr(_accounts34(shell)))
    _mon34._batch_failed_at.clear()
    del shell.calls[:]
    _mon34._refresh_player_counts(_app34)
    check("C batch: (control) once the retry time has passed the host is batched again",
          len(_batched34(shell)[0]) == 1, repr(_accounts34(shell)))
    _section_batch_account34(local, ids)


def _section_batch_account34(local, ids):
    me = _pwd34.getpwuid(os.getuid()).pw_name
    rows = [db.session.get(GameServer, ids[k]) for k in ("gmod", "cod", "mc")]
    host = db.session.get(RemoteServer, local.id)
    mine = NS(id=-1, short_name=me, status="online", remote=host, port=1, game_type="gmod",
              query_type=None)
    acct_first_mine = _mon34._batch_account(host, [mine] + rows)
    acct_only_mine = _mon34._batch_account(host, [mine])
    acct_remote = _mon34._batch_account(NS(is_local=False, auth_method="tailscale",
                                           username="gmodsrv34"), rows)
    check("C batch: the account is never the panel's own (root-capable on a per-user install); a "
          "host whose only accounts are the panel's own is not batched",
          all((acct_first_mine in ("gmodsrv34", "codsrv34", "mcsrv34"), acct_only_mine is None)),
          repr((me, acct_first_mine, acct_only_mine)))
    check("C batch: ...and on a remote never the SSH login the panel escalates with",
          acct_remote == "codsrv34", repr(acct_remote))
    _ADMINS34.add("gmodsrv34")
    acct_admin = _mon34._batch_account(host, rows)
    _ADMINS34.clear()
    check("C batch: on the panel's host an account in an administrator group (an imported server "
          "run as a human's sudo account) is passed over for the next game account",
          acct_admin == "codsrv34", repr(acct_admin))
    bad = NS(id=99, short_name="x; id #", status="online", remote=host, port=27015,
             game_type="gmod", query_type=None)
    check("C batch: a row whose account is not a plain name never joins a batch (it is refused on "
          "its own path, as before)", not _mon34._batchable(bad), "")


def _section_batch_shell34():
    """The batch's own shell: one slow target does not cost the others their answer."""
    shell = _GameShell34()
    _set34(_core34, "shell_as_game_user", shell)
    _set34(_core34, "_gamedig_host", lambda server: "127.0.0.1")
    _set34(_cron34, "_BATCH_TARGET_TIMEOUT", 2)
    t0 = _time34.monotonic()
    got = _cron34.player_slots_batch(NS(id=3401), "gmodsrv34",
                                     [(1, "gmod", 27015, None), (2, "cod", 28960, None),
                                      (3, "gmod", 27020, None), (4, "mc", 25565, None),
                                      (5, "nosuchgame", 1, None)])
    took = _time34.monotonic() - t0
    _restore_one34(_cron34, "_BATCH_TARGET_TIMEOUT")
    check("C batch: one target that never answers is cut at its own timeout and reads unknown, "
          "while the others keep their answers; a game with no gamedig type is not queried",
          all((got == {1: (2, 16, "Box Server"), 2: (0, 16, "COD"), 3: (None, None, None),
                       4: (None, None, None)}, took < 15)),
          repr((got, round(took, 1))))
    body = shell.calls[-1][1] if shell.calls else ""
    many = _cron34._batch_body(NS(id=1), [(i, "garrysmod", 27015 + i) for i in range(17)])
    check("C batch: at most _BATCH_PARALLEL queries run at once (a `wait` after each group), and the "
          "whole command is ONE line (sudo logs it; a newline would print as a log line of its own)",
          all((many.count("wait;") == 3, "\n" not in many, "wait;" in body)), many[:120])


def _section_map_cache34():
    shell = _GameShell34()
    _set34(_core34, "shell_as_game_user", shell)
    _set34(_core34, "_gamedig_host", lambda server: "127.0.0.1")
    _cron34._game_map_cache.clear()
    got = _cron34.player_slots(NS(id=3402), "gmodsrv34", "gmod", 27015)
    jq_ran = [sh for _u, sh in shell.calls if "p:(.map" in sh]
    hit = _cron34._game_map_cache.get((3402, 27015), (0, None))
    check("B map: player_slots' query asks jq for the map (p) in the same reply, and its count, "
          "capacity and name are unchanged by it — piped through the REAL jq",
          all((_HAVE_JQ34, got == (2, 16, "Box Server"), len(jq_ran) == 1,
               hit[1] == "gm_bconstruct/b")), repr((_HAVE_JQ34, got, hit)))
    check("B map: ...cached for longer than one player-poll period (45 s + the pass)",
          hit[0] - _time34.time() > 60, repr(hit))
    _cron34._game_map_cache.clear()
    failed = _cron34.player_slots(NS(id=3403), "mcsrv34", "mc", 25565)
    check("B map: a failed query stays (None, None, None) and caches no map",
          all((failed == (None, None, None), not _cron34._game_map_cache)), repr(failed))
    _section_map_dedupe34()
    _section_map_race34()


def _section_map_dedupe34():
    """Two callers that miss together run ONE lookup."""
    slow = _GameShell34()

    def _slow(server, user, sh, timeout=30, selfname=None):
        _time34.sleep(0.4)
        return slow(server, user, sh, timeout=timeout)
    _set34(_core34, "shell_as_game_user", _slow)
    res = []

    def _lookup():
        res.append(_cron34.game_map(NS(id=3404), "gmodsrv34", "gmod", 27015))
    threads = [_th34.Thread(target=_lookup), _th34.Thread(target=_lookup), _th34.Thread(target=_lookup)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    check("B map: three lookups that miss the cache together run gamedig ONCE and share it",
          all((len(slow.calls) == 1, res == ["gm_bconstruct/b"] * 3)), repr((len(slow.calls), res)))


def _section_map_race34():
    """A poller entry written while a lookup ran is not shortened by that lookup's own write."""
    _cron34._game_map_cache.clear()

    def _racing(server, user, sh, timeout=30, selfname=None):
        _cron34._remember_map(NS(id=3405), 27015, "fresh_from_poll")
        return "old_map", "", 0
    _set34(_core34, "shell_as_game_user", _racing)
    _cron34.game_map(NS(id=3405), "gmodsrv34", "gmod", 27015)
    hit = _cron34._game_map_cache.get((3405, 27015)) or (0, None)
    check("B map: a lookup that ran while the poller wrote a fresher, longer-lived entry does not "
          "overwrite it (its 30 s expiry sent the next dashboard poll to gamedig again)",
          all((hit[1] == "fresh_from_poll", hit[0] - _time34.time() > 60)), repr(hit))


def _section_unmapped34():
    """A running game outside the gamedig map (Factorio: LinuxGSM querymode 1), polled twice."""
    settings, maxreads, status = [], [], []
    _set34(_files34, "lgsm_get_values",
           lambda *a, **k: (settings.append(a[1]), {"querymode": "1", "querytype": "",
                                                   "queryport": "", "port": ""})[1])
    _set34(_mon34, "lgsm_get_values", lambda *a, **k: (maxreads.append(a[1]), {"maxplayers": ""})[1])
    _set34(_mon34, "sm_get_server_status", lambda remote, gs: (status.append(gs.status), "offline")[1])
    _restore_one34(_mon34, "sm_player_count_via_lgsm_query")      # the real reader, through cron
    _cron34._lgsm_query_cache.clear()
    fctr = NS(id=3410, remote=NS(id=3411), short_name="fctrsrv34", game_type="fctr", port=34197,
              query_type=None, lgsm_name="fctrserver", status="online")
    _ps34._max_players_cache.pop(fctr.id, None)
    first = _mon34._query_server_slots(fctr)
    second = _mon34._query_server_slots(fctr)
    check("H unmapped: a running game outside the gamedig map reads LinuxGSM's query settings ONCE "
          "(static config, cached by the poller's call), not a sudo'd config read every 45 s",
          all((settings == ["fctrsrv34"], first == second == (fctr.id, (None, None, None)))),
          repr((settings, first, second)))
    check("H unmapped: ...its config with no capacity is read once too, and no `details` runs for a "
          "server the monitor found listening", all((maxreads == ["fctrsrv34"], status == [])),
          repr((maxreads, status)))
    got = _mon34._query_server_slots(NS(**dict(vars(fctr), id=3412, status="failed")))
    check("H unmapped: a server NOT seen listening still asks LinuxGSM whether it runs, and a "
          "stopped one is a confirmed 0", all((got == (3412, (0, None, None)), status == ["failed"])),
          repr((got, status)))
    _cron34.player_count_via_lgsm_query(NS(id=3411), "fctrsrv34", "fctrserver")
    _cron34.player_count_via_lgsm_query(NS(id=3411), "fctrsrv34", "fctrserver")
    check("H unmapped: (control) a caller that does not ask for the cache reads the config each time",
          settings.count("fctrsrv34") == 3, repr(settings))
    _set34(_files34, "lgsm_get_values", lambda *a, **k: (settings.append("fail"), None)[1])
    _cron34._lgsm_query_cache.clear()
    _cron34.player_count_via_lgsm_query(NS(id=3413), "fctrsrv34", "fctrserver", cached=True)
    _cron34.player_count_via_lgsm_query(NS(id=3413), "fctrsrv34", "fctrserver", cached=True)
    check("H unmapped: an UNREADABLE config is never cached: the next pass reads it again",
          all((settings.count("fail") == 2, not _cron34._lgsm_query_cache)), repr(settings))


def _section_sampler34():
    _fresh_db34()
    host = _host34("p34-sampler")
    for short, gt, port in (("gmodsrv34", "gmod", 27015), ("codsrv34", "cod", 28960),
                            ("mcsrv34", "mc", 25565)):
        _server34(host, short, gt, port)
    maps = []
    _set34(_mon34, "game_map", lambda *a, **k: (maps.append(a[1]), "a_map")[1])
    _set34(_mon34, "host_live_metrics",
           lambda remote, force=False: {"host": {"ram_total": 8000}})
    _set34(_mon34, "metrics_for_game",
           lambda sample, short, port: {"game_procs": 1, "ram_total": 8000, "ram_used": 100,
                                        "disk_total": 10, "disk_used": 1, "cpu_percent": 3,
                                        "game_cpu_percent": 1, "game_ram_mb": 10})
    _mon34._record_metric_samples(_app34)
    ms, hs = MetricSample.query.count(), HostSample.query.count()
    check("A sampler: a history pass over three running servers makes NO map lookup (it stores no "
          "map) and still writes every sample",
          all((maps == [], (ms, hs) == (3, 1))), repr((maps, ms, hs)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# B: /playerlist's short shared cache, and the page polling it only on the Console tab
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _section_playerlist34():
    shell = _GameShell34()
    _set34(_core34, "shell_as_game_user", shell)
    _set34(_core34, "_gamedig_host", lambda server: "127.0.0.1")
    srv = NS(id=3406)
    a = _game34.player_list(srv, "gmodsrv34", "gmod", 27015, shared=True)
    b = _game34.player_list(srv, "gmodsrv34", "gmod", 27015, shared=True)
    check("B playerlist: two timed polls inside the TTL share ONE gamedig run",
          all((len(shell.calls) == 1, a == b, [p.get("name") for p in a or []] == ["a", "b"])),
          repr((len(shell.calls), a)))
    for p in (b or [])[:1]:
        p["name"] = "mutated"
    c = _game34.player_list(srv, "gmodsrv34", "gmod", 27015, shared=True)
    check("B playerlist: ...each caller gets its own copy (one cannot edit another's list)",
          (c or [{}])[0].get("name") == "a", repr(c))
    _game34.player_list(srv, "gmodsrv34", "gmod", 27015)
    check("B playerlist: an explicit read (the refresh button, the re-read after a kick) always asks",
          len(shell.calls) == 2, repr(len(shell.calls)))
    _game34.player_list(NS(id=3407), "mcsrv34", "mc", 25565, shared=True)
    _game34.player_list(NS(id=3407), "mcsrv34", "mc", 25565, shared=True)
    check("B playerlist: a list gamedig could NOT read is never cached as an answer",
          len(shell.calls) == 4, repr(len(shell.calls)))
    _section_playerlist_page34()


def _fn34(path, name):
    """The FunctionDef `name` in the Python source at `path` (repo-relative), or an empty module."""
    with open(os.path.join(_root, path), encoding="utf-8") as fh:
        tree = _ast34.parse(fh.read())
    found = [n for n in _ast34.walk(tree) if isinstance(n, _ast34.FunctionDef) and n.name == name]
    return found[0] if found else _ast34.Module(body=[], type_ignores=[])


def _calls34(fn):
    """{callee text: [its keyword arguments as text]} for every call inside `fn`."""
    out = {}
    for c in _ast34.walk(fn):
        if isinstance(c, _ast34.Call):
            out.setdefault(_ast34.unparse(c.func), []).extend(
                "%s=%s" % (k.arg, _ast34.unparse(k.value)) for k in c.keywords)
    return out


def _section_playerlist_page34():
    kws = _calls34(_fn34("panel/routes/server_detail.py", "api_server_playerlist")).get("player_list")
    check("B playerlist: the route shares the timed poll and asks fresh on ?console=1",
          "shared=request.args.get('console') != '1'" in (kws or []), repr(kws))
    with open(os.path.join(_root, "static", "js", "server_detail.js"), encoding="utf-8") as fh:
        code = "\n".join(ln.split("//", 1)[0] for ln in fh.read().splitlines())
    poll = _re34.search(r"pollWhenVisible\((\w+), 15000\)", code)
    name = poll.group(1) if poll else "NONE"
    body = _re34.search(r"function %s\(\)\{([^}]*)\}" % name, code)
    text = body.group(1) if body else ""
    check("B playerlist: the page's 15 s players poll runs only while the Console tab shows (the "
          "card is not drawn on History or Details), and a switch back re-reads at once",
          all((name not in ("NONE", "loadPlayers"), "_sdTab==='console'" in text,
               "loadPlayers()" in text, "window.playersTabShown()" in code)), repr((name, text)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# D: the priority keeper renices only what drifted
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ps_out34(rows, getent=("gmodsrv34:x:1501:1501::/home/gmodsrv34:/bin/bash",
                            "codsrv34:x:1502:1502::/home/codsrv34:/bin/bash"), rc=0):
    return "\n".join(list(getent) + ["@@ %d" % rc] + ["%d %d %s" % r for r in rows]
                     + ["@@lgsm-ps-end"])


def _section_renice34():
    f = _core34._off_priority_from
    users = ["codsrv34", "gmodsrv34"]
    root = (0, 9999, "0")
    check("D renice: every settled game process at -1 -> nothing to renice",
          f(_ps_out34([root, (1501, 600, "-1"), (1502, 900, "-1")]), users, -1) == [], "")
    check("D renice: one account with a settled process at 0 (a cron restart) -> that account only",
          f(_ps_out34([root, (1501, 600, "0"), (1502, 900, "-1")]), users, -1) == ["gmodsrv34"], "")
    check("D renice: a process younger than 30 s at the panel's nice 10 (its own gamedig, console "
          "read or LinuxGSM's monitor cron) is not drift",
          f(_ps_out34([root, (1501, 5, "10"), (1502, 900, "-1")]), users, -1) == [], "")
    check("D renice: a process at another nice than the target, even a lower one, is pulled back "
          "(what the keeper always did)",
          f(_ps_out34([root, (1502, 900, "-5")]), users, -1) == ["codsrv34"], "")
    check("D renice: an account that no longer exists does not hide the others (getent answers for "
          "the ones that do)",
          f(_ps_out34([root, (1502, 900, "0")], getent=("codsrv34:x:1502:1502::/h:/bin/sh",), rc=2),
            users, -1) == ["codsrv34"], "")
    check("D renice: no root-owned process in sight (/proc hidepid) is 'could not tell', never "
          "'all at priority'", f(_ps_out34([(1501, 600, "-1")]), users, -1) is None, "")
    check("D renice: a read cut short (no end marker) is 'could not tell'",
          f(_ps_out34([root])[:-len("@@lgsm-ps-end")], users, -1) is None, "")
    _section_renice_read34(users)
    _section_keeper34()


def _section_renice_read34(users):
    sent = []

    def _run(server, cmd, timeout=30, sudo=None, stdin_text=None):
        sent.append((cmd, sudo))
        return _bash34(cmd)
    _set34(_core34, "run_command", _run)
    real = _core34.game_users_off_priority(NS(is_local=True), ["nosuchacct34"])
    first = sent[0] if sent else ("", None)
    check("D renice: the real getent/ps read parses on this host and runs WITHOUT sudo",
          all((real == [], first[1] is False, "ps -e -o ruid=,etimes=,ni=" in first[0])),
          repr((real, first)))
    _set34(_core34, "run_command", lambda *a, **k: ("", "SSH command timed out", -1))
    check("D renice: a read that did not run (non-raising transport) is 'could not tell'",
          _core34.game_users_off_priority(NS(), users) is None, "")
    _restore_one34(_core34, "run_command")
    _section_renice_getent34(users)


def _section_renice_getent34(users):
    """The real read, with a getent that answers nothing: missing (127) or a failed lookup (1)."""
    got = {}
    for rc in (127, 1):
        fake = os.path.join(_TMP34, "getent%d" % rc)
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "getent"), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit %d\n" % rc)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
        os.chmod(os.path.join(fake, "getent"), 0o700)
        _set34(_core34, "run_command",
               lambda server, cmd, timeout=30, sudo=None, stdin_text=None, _p=fake: _bash34(cmd, _p))
        got[rc] = _core34.game_users_off_priority(NS(is_local=True), users)
        _restore_one34(_core34, "run_command")
    check("D renice: a getent that is missing or whose lookup failed (it names no account, though "
          "root's processes are in sight) is 'could not tell' — never 'nothing to renice', which "
          "would stop the keeper renicing on that host for good",
          got == {127: None, 1: None}, repr(got))


def _keeper_loop34():
    """The priority keeper's loop body, as register_routes handed it to part12's supervisor."""
    for runner in _p9_supervised:
        cells = dict(zip(runner.__code__.co_freevars, (c.cell_contents for c in runner.__closure__ or ())))
        if cells.get("name") == "priority-keeper":
            return cells.get("target")
    return None


class _Stop34(Exception):
    """Raised by the fake sleep at the end of one keeper pass."""


def _keeper_pass34(loop):
    """Run the keeper until it sleeps its 120 s (one pass); True when it got there."""
    def _sleep(s):
        if s == 120:
            raise _Stop34()
    _set34(_p9_app, "time", NS(time=_time34.time, sleep=_sleep, monotonic=_time34.monotonic))
    try:
        loop()
    except _Stop34:
        return True
    finally:
        _restore_one34(_p9_app, "time")
    return False


def _keeper_row34():
    host = RemoteServer(name="p34-keeper", host="192.0.2.35", username="k34", auth_credential="")
    db.session.add(host)
    db.session.commit()
    gs = GameServer(remote_id=host.id, name="keepsrv34", short_name="keepsrv34",
                    game_type="gmod", port=27999, installed=True, status="online")
    db.session.add(gs)
    db.session.commit()
    return host.id, gs.id


def _section_keeper34():
    bulk, probed = [], []
    answer = {"v": []}
    _set34(_p9_app, "set_game_priority_bulk", lambda remote, users: bulk.append(list(users)))
    _set34(_p9_app, "game_users_off_priority",
           lambda remote, users, *a, **k: (probed.append(list(users)), answer["v"])[1])
    with _p9.app_context():
        hid, sid = _keeper_row34()
    loop = _keeper_loop34()
    ran_quiet = loop is not None and _keeper_pass34(loop)
    quiet = (list(bulk), list(probed))
    answer["v"] = None
    bulk.clear()
    ran_blind = loop is not None and _keeper_pass34(loop)
    with _p9.app_context():
        db.session.delete(db.session.get(GameServer, sid))
        db.session.delete(db.session.get(RemoteServer, hid))
        db.session.commit()
    check("D keeper: a pass where every game is at priority makes NO renice (it read every host)",
          all((ran_quiet, quiet[0] == [], ["keepsrv34"] in quiet[1])), repr((ran_quiet, quiet)))
    check("D keeper: ...and when the read cannot tell, every host's accounts are reniced, as before",
          all((ran_blind, ["keepsrv34"] in bulk, len(bulk) == len(probed) // 2)), repr((bulk, probed)))
    sent = []
    _set34(_app34mod, "set_game_priority_bulk", lambda remote, users: sent.append(list(users)))
    _set34(_app34mod, "game_users_off_priority", lambda remote, users, *a, **k: ["b"])
    _app34mod._keep_game_priority(NS(), {"a", "b", "c"})
    check("D keeper: only the drifted accounts are handed to the root renice",
          sent == [["b"]], repr(sent))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# E: the restart-flags read
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _flags_stubs34(reads, flagged, ports):
    def _priv(remote, verb, args=(), **k):
        if verb != "restart-flags":
            return "", "", 0
        reads.append(remote.name)
        if remote.name == "p34-plain":
            return flagged["v"], "", flagged.get("rc", 0)
        return "", "", 0
    _set34(_mon34, "run_privileged", _priv)
    _set34(_mon34, "_host_reachable", lambda r: True)
    _set34(_mon34, "_remote_listening_ports", lambda r: ports["v"])
    _set34(_mon34, "_host_disk_pct", lambda r: 10)
    _set34(_mon34, "_host_load_mem", lambda r: (1, 1))
    _set34(_mon34, "notifications", NS(notify=lambda *a, **k: None, alerts_muted=lambda gs: False,
                                       get_thresholds=_mon34.notifications.get_thresholds))


def _section_restart_flags34():
    _fresh_db34()
    plain = _host34("p34-plain")
    daily = _host34("p34-daily", host="127.0.0.2")
    empty = _host34("p34-empty", host="127.0.0.3")
    s_plain = _server34(plain, "plainsrv34", "gmod", 27015)
    _server34(daily, "dailysrv34", "gmod", 27015, daily_restart=True)
    reads, flagged, ports = [], {"v": ""}, {"v": {27015}}
    _flags_stubs34(reads, flagged, ports)

    def _pass():
        del reads[:]
        _mon34._monitor_pass()
        return sorted(reads)
    first = _pass()
    second = _pass()
    check("E flags: the first sweep reads every host that has a server (never one with none)",
          all((first == ["p34-daily", "p34-plain"], empty.name not in first)), repr(first))
    check("E flags: ...then only a host where daily restart is on — not every host every minute",
          second == ["p34-daily"], repr(second))
    _mon34._restart_flags_read_at[plain.id] = _time34.time() - 601
    flagged["v"] = "plainsrv34\n"
    due = _pass()
    shown = _ps34._cron_restart_pending.get(s_plain.id)
    flagged["v"] = ""
    while_shown = _pass()
    cleared = _ps34._cron_restart_pending.get(s_plain.id)
    after = _pass()
    check("E flags: a host with daily restart OFF is still re-read every 10 minutes, so a cron the "
          "column does not know about (an imported server, a terminal edit) shows its banner",
          all(("p34-plain" in due, shown is True)), repr((due, shown)))
    check("E flags: ...a host whose banner shows is read every sweep until the flag is gone, and "
          "the banner then clears (never left stuck on)",
          all(("p34-plain" in while_shown, cleared is False, "p34-plain" not in after)),
          repr((while_shown, cleared, after)))
    _section_flags_failed34(plain, _pass, flagged)
    ports["v"] = None
    no_scan = _pass()
    check("E flags: a failed port scan reads no flags (no server of the host is judged on it)",
          no_scan == [], repr(no_scan))


def _section_flags_failed34(plain, _pass, flagged):
    _mon34._restart_flags_read_at[plain.id] = _time34.time() - 601
    flagged["rc"] = 1                             # the helper's verb failed: no answer
    failed = _pass()
    flagged["rc"] = 0
    retried = _pass()
    settled = _pass()
    check("E flags: a read that FAILED is not stamped: a host with daily restart off is read again "
          "on the next sweep, not 10 minutes later — and, once a read returns, not after that",
          all(("p34-plain" in failed, "p34-plain" in retried, "p34-plain" not in settled)),
          repr((failed, retried, settled)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# F: the ban-watcher's UFW read
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _UfwRig34:
    """ufw's three rule files in this part's temp dir, a clock, and a read that is counted."""

    def __init__(self):
        self.files = [os.path.join(_TMP34, n) for n in ("user.rules", "user6.rules", "ufw.conf")]
        for p in self.files:
            self.append(p, "# rules\n", "w")
        self.clock = {"t": _time34.monotonic() + 100000.0}
        self.reads, self.answer = [], {"198.51.100.34": "panel"}

    @staticmethod
    def append(path, text, mode="a"):
        with open(path, mode, encoding="utf-8") as fh:
            fh.write(text)

    def read(self):
        self.reads.append(self.clock["t"])
        return self.answer

    def tick(self, dt=90):
        self.clock["t"] += dt
        return _bl34.watch_ufw(self.read)


def _section_banwatch34():
    rig = _UfwRig34()
    saved = (_bl34._f2b, _bl34._ufw, _bl34._allow, dict(_bl34._by_len), dict(_bl34._taken),
             dict(_bl34._ufw_gate), dict(_bl34._listeners))
    try:
        _bl34._listeners.clear()
        _set34(_bl34, "UFW_RULE_FILES", tuple(rig.files))
        _set34(_bl34, "time", NS(monotonic=lambda: rig.clock["t"], time=_time34.time))
        _bl34._ufw_gate.update(key=None, read_at=float("-inf"), checked_at=float("-inf"), skipped=0,
                               last_skipped=False)
        _section_ufw_gate34(rig)
        _section_banwatch_caller34(rig)
        _section_ufw_report34(rig)
        _section_banwatch_loop34()
    finally:
        (_bl34._f2b, _bl34._ufw, _bl34._allow) = saved[:3]
        for live, snap in ((_bl34._by_len, saved[3]), (_bl34._taken, saved[4]),
                           (_bl34._ufw_gate, saved[5])):
            live.clear()
            live.update(snap)
        _bl34._listeners.update(saved[6])


def _section_ufw_gate34(rig):
    first, again = rig.tick(), rig.tick()
    check("F ufw: the first tick reads UFW; the next, with ufw's rule files unchanged, does not",
          (first, again, len(rig.reads)) == (True, False, 1), repr((first, again, rig.reads)))
    rig.append(rig.files[0], "-A ufw-user-input -s 198.51.100.35 -j DROP\n")
    changed = rig.tick()
    check("F ufw: a rule added outside the panel (the file rewritten) is read on the next tick",
          all((changed is True, len(rig.reads) == 2)), repr(rig.reads))
    rig.append(rig.files[2], "ENABLED=no\n")     # `ufw disable` rewrites ufw.conf: that tick reads
    rig.answer = None
    nones = (rig.tick(), rig.tick())
    check("F ufw: a reading of None (ufw inactive or unreadable) never advances the gate, so it is "
          "read every tick — rules added while it was off are seen when it comes back",
          nones == (True, True), repr(nones))
    rig.answer = {"198.51.100.34": "panel"}
    rig.tick()
    skipped = rig.tick()
    forced = rig.tick(_bl34.UFW_FORCED_READ)
    check("F ufw: ...and an unchanged file is still read every UFW_FORCED_READ seconds",
          (skipped, forced) == (False, True), repr((skipped, forced)))
    _set34(_bl34, "UFW_RULE_FILES", (rig.files[0], os.path.join(rig.files[0], "not-a-dir")))
    unreadable = (rig.tick(), rig.tick())
    check("F ufw: a stat that fails (other than a missing file) reads, never skips",
          unreadable == (True, True), repr(unreadable))
    _restore_one34(_bl34, "UFW_RULE_FILES")
    _set34(_bl34, "UFW_RULE_FILES", tuple(rig.files))


def _section_banwatch_caller34(rig):
    f2b, ufw = [], []
    _set34(_so34, "panel_fail2ban_banned_ips", lambda: (f2b.append(1), {"203.0.113.34"})[1])
    _set34(_so34, "ufw_blocked_ips", lambda: (ufw.append(1), {"198.51.100.34": "panel"})[1])
    _bl34._ufw_gate.update(key=None)
    state, raised = {"seen": None}, []
    for _ in range(3):
        rig.clock["t"] += 90
        try:
            _app34mod._ban_watch_tick(_p9, state)
        except (TypeError, ValueError, AttributeError, KeyError, RuntimeError, OSError) as e:
            raised.append(type(e).__name__)
    check("F ban-watch: three ticks read fail2ban three times (its bans come and go on their own "
          "clock) and UFW once, its rule files unchanged",
          (len(f2b), len(ufw), raised) == (3, 1, []), repr((len(f2b), len(ufw), raised)))
    line = _gate_line34()
    check("F report: the ban-gate line says the rule files were checked, so 'read 4m ago' does not "
          "read as a stalled watcher", "rule files unchanged, checked" in line, line)
    watch = _calls34(_fn34("app.py", "_f2b_ban_watch"))
    tick = _calls34(_fn34("app.py", "_ban_watch_tick"))
    check("F ban-watch: the 90 s loop runs _ban_watch_tick, whose UFW read goes through the gate",
          all(("_ban_watch_tick" in watch, "_banlist.watch_ufw" in tick, "so.ufw_blocked_ips" not in tick)),
          repr((sorted(watch), sorted(tick))))


def _gate_line34():
    """The debug report's ban-gate line, as printed."""
    lines = []
    _nw34._bangate_line(NS(add=lines.append, find=lambda *a, **k: None))
    return "".join(lines)


def _section_ufw_report34(rig):
    """The report's 'rule files unchanged' reason is printed only after a check that SKIPPED."""
    # A panel whose ufw has been inactive since boot: every read answers None, so the gate never
    # gets a key and every tick reads.
    _bl34._ufw_gate.update(key=None, read_at=float("-inf"), checked_at=float("-inf"), skipped=0,
                           last_skipped=False)
    rig.answer = None
    rig.tick()
    rig.tick()
    rig.tick()
    inactive = _gate_line34()
    rig.answer = {"198.51.100.34": "panel"}
    check("F report: a UFW read that answered None skipped nothing, so the line gives no 'rule files "
          "unchanged' reason for a set that was not read", "rule files unchanged" not in inactive,
          inactive)
    _set34(_bl34, "UFW_RULE_FILES", (rig.files[0], os.path.join(rig.files[0], "not-a-dir")))
    rig.tick()                                   # the stat fails; the read succeeds
    no_stat = _gate_line34()
    _restore_one34(_bl34, "UFW_RULE_FILES")
    _set34(_bl34, "UFW_RULE_FILES", tuple(rig.files))
    check("F report: ...nor does a check whose stat failed and which therefore READ",
          "rule files unchanged" not in no_stat, no_stat)


class _LoopStop34(Exception):
    """Raised by the fake sleep once the ban-watch loop has run its ticks."""


def _ban_loop34(readings, whitelist=None, ufw_raises=False, record_raises=0):
    """Run app._f2b_ban_watch, the real 90 s loop, for one tick per reading; the new bans it recorded.

    `whitelist[i]` is tick i's security_whitelist (a hand-edited non-list makes set_whitelist
    raise AFTER the tick decided), `ufw_raises` makes the UFW read raise, `record_raises` makes that
    many calls of the recorder that were handed a new ban raise after it saw (and sent) them.
    """
    whitelist = whitelist or [[] for _ in readings]
    tick, recorded, left = {"i": 0}, [], {"n": record_raises}

    def _record(app, new_bans, unbans):
        recorded.append(tuple(new_bans))
        if new_bans and left["n"]:
            left["n"] -= 1
            raise RuntimeError("database is locked")

    def _ufw():
        if ufw_raises:
            raise RuntimeError("ufw-status helper call raised")
        return {}

    def _sleep(_s):
        tick["i"] += 1
        if tick["i"] >= len(readings):
            raise _LoopStop34()
    _set34(_so34, "panel_fail2ban_banned_ips", lambda: set(readings[tick["i"]]))
    _set34(_so34, "ufw_blocked_ips", _ufw)
    _set34(_app34mod, "_f2b_record_events", _record)
    _set34(_app34mod, "load_config", lambda: {"security_whitelist": whitelist[tick["i"]]})
    _set34(_app34mod, "time", NS(sleep=_sleep, monotonic=_time34.monotonic, time=_time34.time))
    _bl34._ufw_gate.update(key=None)
    loop = getattr(_app34mod, "_f2b_ban_watch", None)
    try:
        if loop is None:
            return ["NO MODULE-LEVEL LOOP"]
        loop(_p9)
    except _LoopStop34:
        pass
    finally:
        for name in ("_f2b_record_events", "load_config", "time"):
            _restore_one34(_app34mod, name)
    return [b for b in recorded if b]


def _section_banwatch_loop34():
    a, b, c = "203.0.113.7", "203.0.113.8", "203.0.113.9"
    bans = _ban_loop34([{a}, {a, b}, {a, b}, {a, b}], whitelist=[[], 5, 5, 5])
    check("F ban-watch: a tick that raised AFTER deciding (a hand-edited security_whitelist that is "
          "not a list) keeps its decision: a new ban is announced ONCE, not on every tick of its hour",
          bans == [(b,)], repr(bans))
    bans = _ban_loop34([{a}, {a, c}, {a, c}], ufw_raises=True)
    check("F ban-watch: ...and when every tick raises from the first (the UFW read), the first is "
          "still adopted as the baseline, so a later ban is announced — once",
          bans == [(c,)], repr(bans))
    bans = _ban_loop34([{a}, {a, b}, {a, b}], record_raises=1)
    check("F ban-watch: ...and a recorder that raised partway (a locked database) does not send the "
          "same batch again on the next tick", bans == [(b,)], repr(bans))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# G: the console — one round trip a tick, and the two feeds still stitch byte-exact
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Sio34:
    """The console's socket room: the lines it was pushed, in order."""

    def __init__(self):
        self.lines = []

    def emit(self, event, payload, room=None, **_k):
        if event == "console_output":
            self.lines.extend(r["line"] for r in payload.get("rows") or [])


class _ConsoleRig34:
    """read_as_game_user on a REAL file: every command the console builds runs in bash.

    `lines` is what the file holds, line by line; `rounds` the host commands each tick made.
    """

    def __init__(self, path):
        self.path, self.calls, self.fail, self.rounds, self.outs = path, [], 0, [], []
        self.tamper = _as_is34      # rewrites the host's next reply, then is reset
        self.sio, self.sid = _Sio34(), -3401
        self.gs = NS(console_log=path, remote=NS(timezone=""), short_name="mcsrv34",
                     lgsm_name="mcserver")
        self.lines = []

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append(sh)
        if self.fail:
            self.fail -= 1
            return "", "SSH command timed out", -1
        out, err, rc = _bash34(_as_account34(user, sh, selfname))
        tamper, self.tamper = self.tamper, _as_is34
        out = tamper(out)
        self.outs.append(out)
        return out, err, rc

    def _write(self, lines, mode):
        with open(self.path, mode, encoding="utf-8", newline="") as fh:
            fh.write("".join(ln + "\n" for ln in lines))

    def add(self, lines):
        self.lines.extend(lines)
        self._write(lines, "a")

    def replace(self, lines):
        """Write the file afresh: the SAME inode (truncated), or a new one after rotate()."""
        self.lines = list(lines)
        self._write(lines, "w")

    def rotate(self, lines):
        """The start LinuxGSM does: mv the log to a dated name, then a NEW file (a new inode)."""
        os.replace(self.path, self.path + ".old")
        self.replace(lines)

    def tick(self):
        n = len(self.calls)
        _sf34._console_tick(_app34, self.sio, self.gs, self.sid)
        self.rounds.append(len(self.calls) - n)

    def window(self):
        """What the page's 30 s /api/console poll returns: the log's last 200 lines, as rows."""
        return [r["line"] for r in _sf34._read_console_window(self.gs.remote, self.gs, 200, "")[1]]


def _js_fn34(src, name):
    i = src.index("function %s(" % name)
    depth = 0
    for k in range(src.index("{", i), len(src)):
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        if depth == 0:
            return src[i:k + 1]
    return ""


def _stitch_py34(have, incoming):
    """server_detail.js's _newConsoleLines, line for line, for a host with no node."""
    def same(a, b):
        return a == b or a.strip() == b.strip()
    if not incoming or not have:
        return list(incoming)
    for k in range(len(incoming) - 1, -1, -1):
        n = min(len(have), k + 1)
        if same(incoming[k], have[-1]) and all(same(have[len(have) - n + i], incoming[k + 1 - n + i])
                                               for i in range(n)):
            return incoming[k + 1:]
    return list(incoming)


def _stitch34(have, incoming):
    """What the browser appends: server_detail.js's own _newConsoleLines, run by node when present."""
    node = _shutil34.which("node")
    if not node:
        return _stitch_py34(have, incoming)
    with open(os.path.join(_root, "static", "js", "server_detail.js"), encoding="utf-8") as fh:
        js = fh.read()
    prog = "\n".join(_js_fn34(js, n) for n in ("_sameLine", "_eqRange", "_newConsoleLines"))
    prog += ("\nconst d=JSON.parse(require('fs').readFileSync(0,'utf8'));"
             "process.stdout.write(JSON.stringify(_newConsoleLines(d[0], d[1])));")
    r = _sp34.run([node, "-e", prog], input=_json34.dumps([have, incoming]),  # nosec B603 - node on fixtures
                  capture_output=True, text=True, timeout=30, check=False)
    return _json34.loads(r.stdout or "null")


def _section_console34():
    path = os.path.join(_TMP34, "console", "mcserver-console.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rig = _ConsoleRig34(path)
    _set34(_core34, "read_as_game_user", rig)
    _set34(_sf34, "_host_timezone_cached", lambda *a, **k: "")
    _ps34._console_offsets.pop(rig.sid, None)
    _sf34._console_partial.pop(rig.sid, None)
    _sf34._console_feed.pop(rig.sid, None)
    rig.replace(["[03:30:%02d] old line %d" % (i, i) for i in range(40)])
    rig.tick()
    rig.add(["list", "[03:30:35] There are 0 of a max of 20 players online: "])
    rig.tick()
    pushed_first = list(rig.sio.lines)
    rig.tick()
    idle_reply, idle_feed = (rig.outs[-1:] or [""])[0], dict(_sf34._console_feed.get(rig.sid) or {})
    check("G console: an idle tick (the log unchanged) is a GOOD tick that moves no bytes: the host "
          "chose the same offset and read nothing, and the feed records no failure",
          all((idle_reply.split()[2:4] == [str(_ps34._console_offsets[rig.sid]["pos"]), "0"],
               "\n" not in idle_reply, idle_feed.get("streak") == 0, "last_fail" not in idle_feed)),
          repr((idle_reply[:60], idle_feed)))
    check("G console: first sight reads nothing; new output is pushed whole, a trailing space and "
          "all; an idle tick pushes nothing",
          all((pushed_first == rig.lines[-2:], rig.sio.lines == pushed_first)), repr(pushed_first))
    check("G console: every tick after first sight is ONE command on the host (stat and read "
          "together) — growing or idle", rig.rounds == [1, 1, 1], repr(rig.rounds))
    _section_console_rotation34(rig)
    _section_console_burst34(rig)
    _section_console_guards34(rig)
    _section_stitch34(rig)


def _section_console_rotation34(rig):
    boot = ["Unpacking io/netty/netty-codec-4.2.7.jar %03d to libraries/io/netty" % i
            for i in range(60)] + ["Starting net.minecraft.server.Main"]
    rig.sio.lines = []
    rig.rotate(boot)
    rig.tick()
    check("G console: a log rotated by LinuxGSM's start (a new inode, already longer than the old "
          "offset) is read from its FIRST byte, every line, in order — in one round trip",
          all((rig.sio.lines == boot, rig.rounds[-1] == 1)),
          "pushed %d of %d" % (len(rig.sio.lines), len(boot)))
    rig.sio.lines = []
    rig.rotate(["[03:40:00] Starting minecraft server version 26.3"])
    rig.tick()
    os.remove(rig.path)
    before = dict(_ps34._console_offsets[rig.sid])
    rig.tick()
    check("G console: a smaller rotated log is read from byte 0; a log briefly MISSING (between "
          "LinuxGSM's mv and touch) changes nothing",
          all((rig.sio.lines == rig.lines, _ps34._console_offsets[rig.sid] == before)),
          repr(rig.sio.lines))
    rig.replace(rig.lines)                      # LinuxGSM's touch: a new file
    rig.tick()
    rig.replace(["[05:00:00] after the truncate"])  # same inode, shorter
    rig.tick()
    check("G console: a log truncated in place (same inode, shorter) is read from byte 0",
          rig.sio.lines[-1:] == rig.lines, repr(rig.sio.lines[-3:]))


def _section_console_burst34(rig):
    rig.sio.lines = []
    burst = ["MODULE: ct_%05d.lua loaded" % i for i in range(3000)]
    rig.add(burst)
    for _ in range(8):
        rig.tick()
    check("G console: a burst bigger than one read drains over several ticks, complete, in order, "
          "no line cut at a read boundary", rig.sio.lines == burst,
          "pushed %d of %d" % (len(rig.sio.lines), len(burst)))
    rig.sio.lines = []
    rig.add(["[05:01:00] Done (4.2s)! For help, type \"help\""])
    rig.fail = 1
    rig.tick()
    mid = list(rig.sio.lines)
    rig.tick()
    check("G console: a read that never ran (a non-raising transport timed out) advances nothing "
          "and the next tick delivers it", all((mid == [], rig.sio.lines == rig.lines[-1:])),
          repr((mid, rig.sio.lines)))


def _unframe34(out):
    """A reply that ran and printed its stat line, but lost the byte range's closing frame."""
    return out[:-1] if out.endswith("E") else out + "x"


def _shift_start34(out):
    """A reply whose host read from one byte later than the offset it was handed."""
    head, nl, rest = out.partition("\n")
    f = head.split()
    return " ".join(f[:2] + [str(int(f[2]) + 1)] + f[3:]) + nl + rest if len(f) == 4 else out


def _section_console_guards34(rig):
    for name, tamper in (("lost its closing frame", _unframe34),
                         ("read from another start than the offset", _shift_start34)):
        rig.sio.lines = []
        line = "[05:02:00] after a reply that %s" % name
        rig.add([line])
        before = dict(_ps34._console_offsets[rig.sid])
        rig.tamper = tamper
        rig.tick()
        held = (list(rig.sio.lines), dict(_ps34._console_offsets[rig.sid]))
        rig.tick()
        check("G console: a reply that %s is not used — nothing pushed, the offset unmoved — and "
              "the next tick delivers the line once" % name,
              all((held == ([], before), rig.sio.lines == [line])), repr((held, before, rig.sio.lines)))


def _section_stitch34(rig):
    # The page's copy: everything before these five lines, then what the socket pushed.
    rig.sio.lines = []
    rig.add(["[06:00:%02d] chat line %d " % (i, i) for i in range(5)])
    rig.tick()
    have = list(rig.lines[:-5]) + list(rig.sio.lines)
    window = rig.window()
    check("G stitch: the 30 s poll's window is the file's own last lines, byte for byte",
          window == rig.lines[-len(window):], repr(window[-3:]))
    joined = _stitch34(have, window)
    check("G stitch: what the socket pushed equals those same lines byte for byte (trailing spaces "
          "kept), so the poll finds the overlap and appends nothing twice",
          all((rig.sio.lines == rig.lines[-5:], joined == [])), repr((rig.sio.lines[-2:], joined[:3])))
    rig.add(["[06:01:00] written between two ticks"])
    joined = _stitch34(have, rig.window())
    check("G stitch: a line the poll sees before the socket does is appended once, by the poll",
          joined == ["[06:01:00] written between two ticks"], repr(joined))
    cmd = _sf34._console_poll_cmd(rig.gs.console_log, 1, 2)
    calls = _calls34(_fn34("panel/routes/server_files.py", "_console_poll_read"))
    check("G console: the round trip still frames the bytes (B…E), and the script's name in the "
          "path goes through read_as_game_user's selfname check",
          all(("printf B" in cmd, "printf E" in cmd,
               "selfname=gs.lgsm_name" in calls.get("_sm.read_as_game_user", []))), cmd[:80])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# I: the debug report
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PFX34 = "Oct 03 05:%02d:01 livebox7731 sudo[%d]: "
_SUDO_LINES34 = [
    # sudo.ws 1.9.15, a game account's player poll (the batch) and the dashboard's map lookup
    "  ubuntu : PWD=/home/ubuntu/linuxgsm-panel ; USER=codsrv7731 ; COMMAND=/usr/bin/bash -c "
    "'q() { timeout 20 gamedig --type \"$1\" \"$2\" 2>/dev/null | jq -c \"$3\" 2>/dev/null; }; q cod "
    "192.0.2.5:28960 '{k:3, c:(.players|length), m:.maxplayers}' &'",
    "  ubuntu : PWD=/home/ubuntu ; USER=gmodsrv7731 ; COMMAND=/usr/bin/bash -c 'gamedig --type "
    "garrysmod 192.0.2.5:27015 2>/dev/null | jq -r '.map // \"\"' 2>/dev/null'",
    # sudo-rs spacing, the console's one round trip
    "ubuntu :  PWD=/home/ubuntu ; USER=mcsrv7731 ; COMMAND=/usr/bin/bash -c "
    "L=/home/mcsrv7731/log/console/mcserver-console.log; S=$(stat -c \\'%i %s\\' \"$L\" "
    "2>/dev/null) ... tail -c +$((P + 1)) \"$L\" ",
    "  ubuntu : PWD=/home/ubuntu ; USER=codsrv7731 ; COMMAND=/usr/bin/bash -c 'cat "
    "/home/codsrv7731/lgsm/config-lgsm/codserver/_default.cfg 2>/dev/null; echo'",
    "  ubuntu : PWD=/home/ubuntu ; USER=gmodsrv7731 ; COMMAND=/usr/bin/rm -f /home/gmodsrv7731/x7731",
    # an operator's own script in the panel terminal (TTY=), and the panel's sudo -n probe
    "  ubuntu : TTY=pts/3 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/local/bin/rotate-acme7731.sh --now",
    "  ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/true",
    "  ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/local/lib/linuxgsm-panel/panel-helper "
    "renice-users -1 codsrv7731",
    "  ubuntu : (command continued) {k:4, c:(.players|length)} acct7731",
    "pam_unix(sudo:session): session opened for user codsrv7731(uid=1502) by ubuntu(uid=1000)",
    "  ubuntu : a password is required ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/true",
]


def _section_report_classifier34():
    lines = [_PFX34 % (i, 2000 + i) + b for i, b in enumerate(_SUDO_LINES34)]
    kept, verbs, sessions = _lg34._split_priv(lines)
    check("I labels: the game-account reads are named by what they were, never 'other command'",
          all((verbs.get(_lg34.GAME_ACCOUNT) == {"gamedig players": 1, "gamedig map": 1,
                                                 "console poll": 1, "LinuxGSM config": 1, "rm": 1},
               "other command" not in verbs)), repr(verbs))
    check("I labels: root programs the panel runs are named; an operator's own script is 'other "
          "program as root'; the helper's verb is its verb",
          (verbs.get("true as root"), verbs.get("other program as root"), verbs.get("renice-users"))
          == (1, 1, 1), repr(verbs))
    check("I labels: a '(command continued)' line is part of the call, not a log line; a pam "
          "session is counted; a REFUSED sudo is kept",
          all((sessions == 1, len(kept) == 1, "a password is required" in "".join(kept))), repr(kept))
    line = _lg34._priv_line(verbs, sessions, "x") or ""
    check("I labels: the printed line carries no account, path, address or script name — fixed "
          "words only", not any(t in line for t in ("7731", "rotate", "192.0.2")), line)
    many = {"as a game account": {"gamedig players": 900, "console poll": 300}, "restart-flags": 171,
            "ufw-status": 119, "f2b-status-jail": 117, "renice-users": 86, "crontab-list": 3}
    shown = _lg34._priv_line(many, 0, "x") or ""
    check("I labels: the game-account work is ONE entry with its kinds nested, so it cannot push the "
          "helper's verbs out of the six shown",
          all(("crontab-list ×3" in shown, "…" not in shown,
               "as a game account ×1200 [gamedig players ×900, console poll ×300]" in shown)), shown)


_OWN34 = "Oct 03 08:00:00 h python3[1]: WARNING panel own line\n"
_SUDO34 = "Oct 03 08:00:01 h sudo[2]:   u : PWD=/x ; USER=root ; COMMAND=/usr/bin/true\n"


def _read_with34(run):
    """_src_journal.read with system_ops._debug_run answered by `run`; (result, argvs)."""
    calls = []

    def _recording(argv, timeout=5, cap=None):
        calls.append(list(argv))
        return run(argv)
    with _patched():
        _patch(_so34, "_debug_run", _recording)
        got = _sj34.read(5000, timeout=5)
    return got, calls


def _section_report_reads34():
    uid = os.getuid() if hasattr(os, "getuid") else -1
    got, calls = _read_with34(lambda argv: ((_SUDO34 if "SYSLOG_IDENTIFIER=sudo" in argv else _OWN34),
                                            "", 0))
    first = calls[0] if calls else []
    check("I journal: the report's read asks journald for the panel's OWN output by indexed fields — "
          "its user unit's stdout, its critical syslog lines, systemd's lines about it — so the line "
          "limit counts only those (not --grep, which on systemd 254+ walks the whole journal "
          "backwards; the window that bounds it, and the sparse terms, are part39's)",
          all(([t for t in ("--user", "_SYSTEMD_USER_UNIT=linuxgsm-panel.service", "_UID=%d" % uid,
                            "_TRANSPORT=stdout", "PRIORITY=2", "+", "USER_UNIT=linuxgsm-panel.service",
                            "--lines=+5000") if t not in first] == [],
               not set(first) & {"-u", "-g", "--grep", "PRIORITY=3", "PRIORITY=4", "PRIORITY=5"})),
          repr(first))
    second = calls[1] if len(calls) > 1 else []
    check("I journal: ...and the sudo lines are read APART, for the digest's count",
          all((got.get("filtered") is True, bool(got.get("sudo")), len(calls) == 2,
               "SYSLOG_IDENTIFIER=sudo" in second, got["lines"] == [_OWN34.strip()])),
          repr((got.get("filtered"), calls[1:])))
    fb, fb_calls = _read_with34(lambda argv: (("", "Failed to add match", 1)
                                              if "_TRANSPORT=stdout" in argv else (_OWN34 + _SUDO34, "", 0)))
    check("I journal: a journalctl that refuses the matches falls back to today's `--user -u` read "
          "(nothing lost; the sudo lines are then filtered after the read, as before)",
          all((fb.get("filtered") is False, fb.get("sudo") is None, len(fb["lines"]) == 2,
               (fb_calls[1:2] or [[]])[0][:4] == ["journalctl", "--user", "-u", "linuxgsm-panel"])),
          repr((fb.get("filtered"), fb_calls)))
    _section_report_helper_path34()
    _section_report_helper34()


def _section_report_helper_path34():
    verbs = []

    def _verb(verb, args=(), timeout=30, merge_stderr=True):
        verbs.append(list(args)[:1])
        if list(args)[:1] == ["panel-own"]:
            return "", "panel-helper: invalid argument", 2
        return _OWN34, "", 0
    with _patched():
        _patch(_so34, "_debug_run", lambda argv, timeout=5, cap=None: ("", "", 1))
        _patch(_so34, "_helper_present", lambda: True)
        _patch(_so34, "_run_verb", _verb)
        old = _sj34.read(5000, timeout=5)
    check("I journal: on a system install the helper is asked for its filtered source first, and a "
          "helper older than it (it refuses the name) falls back to the plain unit read",
          all((verbs == [["panel-own"], ["panel"]], old.get("source") == "helper",
               old.get("filtered") is False)), repr(verbs))


def _helper_argv34(src):
    try:
        return _helper.VERBS["journal"][1](_helper.validate("journal", [src, "5000"]))
    except ValueError as e:
        return "refused: %s" % e


def _section_report_helper34():
    drift = [(src, _helper_argv34(src), _priv34.tool_argv("journal", [src, "5000"]))
             for src in ("panel-own", "panel-sudo")]
    drift = [d for d in drift if d[1] != d[2] or "--grep" in d[2]]
    own = _priv34.journal_argv("panel-own", "5000")
    check("I journal: the helper accepts the two new sources and builds the same argv as the panel "
          "(fixed field matches, no caller text, no --grep)",
          all((not drift, "_SYSTEMD_UNIT=linuxgsm-panel.service" in own, "_PID=1" in own,
               "COREDUMP_UNIT=linuxgsm-panel.service" in own)), repr(drift))
    check("I journal: the plain unit read is unchanged (an older panel's request still works)",
          _priv34.journal_argv("panel", "400") == ["journalctl", "-u", "linuxgsm-panel", "--no-pager",
                                                    "-n", "400"], "")


def _report34(own, sudo):
    """A whole debug report whose journal reads answer `own` (the main read) and `sudo`."""
    def _run(argv, timeout=5, cap=None):
        if "SYSLOG_IDENTIFIER=sudo" in argv:
            return sudo, "", 0
        if "--user" in argv:
            return own, "", 0
        return ("yes\n", "", 0) if "timedatectl" in argv else ("", "", 1)
    app = _Flask34("p34-report")
    app.config.update(SECRET_KEY="p34r", SQLALCHEMY_TRACK_MODIFICATIONS=False,  # nosec B106 - test app
                      SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP34, "rep.db"))
    db.init_app(app)
    with _patched():
        _env(journal=own)
        _patch(_so34, "_debug_run", _run)
        with app.app_context():
            db.create_all()
            return _so34.generate_debug_report()["report"]


def _section_report_once34():
    # Distinct words, not numbers: the recent log folds lines that differ only in their digits.
    own = "\n".join(["Oct 03 08:%02d:00 livebox7731 python3[1]: panel line %s" % (i, chr(97 + i) * 3)
                     for i in range(20)]) + "\n"
    rep = _report34(own, "\n".join(_PFX34 % (i, 3000 + i) + b for i, b in enumerate(_SUDO_LINES34)))
    digest = rep.split("### Errors in the journal", 1)[-1].split("### Recent log", 1)[0]
    log = rep.split("### Recent log", 1)[-1]
    check("I report: the privileged calls are printed ONCE, in the digest, from the separate sudo "
          "read; the recent log only says they are left out and where they are counted",
          all(("Privileged calls**: " in digest, "renice-users ×1" in digest,
               "as a game account ×" in digest, "renice-users ×1" not in log,
               "counted under Errors in the journal" in log)), digest[:900])
    check("I report: the window is the panel's OWN lines, and the report names it so",
          all(("of the panel's own output" in digest, "panel line ttt" in log,
               "COMMAND=" not in log.split("```", 1)[-1])), digest[:400])


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _section_admin34():
    """The real administrator-group lookup, before anything stubs it."""
    got = {u: _mon34._admin_account(u) for u in ("root", "nobody", "nosuchacct34")}
    check("C batch: the administrator test reads the account's groups: root is one, nobody is not, "
          "and an account that cannot be looked up counts as one (never batched as)",
          got == {"root": True, "nobody": False, "nosuchacct34": True}, repr(got))
    _section_admin_groups34()


_GID34 = 4242034          # a gid no real group has: the fixture account's own group


def _admin_in34(group):
    """_admin_account for a fixture account whose own group is named `group`.

    Every other name and gid is looked up for real.
    """
    import grp as _grp34
    real_pw, real_gr = _pwd34.getpwnam, _grp34.getgrgid
    _set34(_pwd34, "getpwnam",
           lambda name: NS(pw_gid=_GID34) if name == "grpacct34" else real_pw(name))
    _set34(_grp34, "getgrgid",
           lambda gid: NS(gr_name=group) if gid == _GID34 else real_gr(gid))
    try:
        return _mon34._admin_account("grpacct34")
    finally:
        _restore_one34(_grp34, "getgrgid")
        _restore_one34(_pwd34, "getpwnam")


def _section_admin_groups34():
    root_doors = ("docker", "lxd", "lxc", "incus-admin", "libvirt", "disk")
    got = {g: _admin_in34(g) for g in root_doors + ("sudo", "games34")}
    check("C batch: an account in a group that is root by another door (docker, lxd/lxc, incus-admin, "
          "libvirt, disk) counts as an administrator too, and is never batched as; a plain game "
          "group does not", got == dict({g: True for g in root_doors + ("sudo",)}, games34=False),
          repr(got))


def _run_sections34():
    _section_admin34()
    _arm34()
    with _app34.app_context():
        _section_poll34()
        _section_batch_edges34()
        _section_unmapped34()
        _section_sampler34()
    _section_batch_shell34()
    _section_map_cache34()
    _section_playerlist34()
    _section_renice34()
    with _app34.app_context():
        _section_restart_flags34()
    _section_banwatch34()
    _section_console34()
    _section_report_classifier34()
    _section_report_reads34()
    _section_report_once34()
    check("ws4: nothing in this part reached a real SSH or local transport", _TRIP34 == [],
          repr(_TRIP34))


def _cleanup34():
    _restore34()
    for m, snap in _PSTATE34:
        m.clear()
        m.update(snap)
    for cache in (_cron34._game_map_cache, _cron34._lgsm_query_cache, _game34._playerlist_cache,
                  _mon34._restart_flags_read_at, _mon34._batch_failed_at):
        cache.clear()
    _ps34._console_offsets.pop(-3401, None)
    _sf34._console_partial.pop(-3401, None)
    _sf34._console_feed.pop(-3401, None)
    _shutil34.rmtree(_TMP34, ignore_errors=True)


try:
    _run_sections34()
except Exception as _e34:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _tb34
    check("ws4: the part ran to the end", False,
          "raised %s: %s\n%s" % (type(_e34).__name__, _e34, _tb34.format_exc()[-1500:]))
finally:
    _cleanup34()
