"""Part 41's sections A to T (clean host reboots); part41 runs them."""
import importlib.machinery as _mach41
import importlib.util as _ilu41
import json as _json41
import math as _math41
import sys
import time as _time41
from types import SimpleNamespace as NS

from unit.part01 import eq, skip
from panel.ops.ssh_manager import hosts as _hosts41
from unit.reboot41_fixtures import (
    AuditLog, GameServer, HR, _CLOCK41, _Flask41, _NOTES41,
    _ROOT41, _TMP41, _TRACE41, _all41, _app41, _audit41,
    _core41, _events41, _fresh41, _gs41, _lockfile41, _mon41,
    _notif41, _patch, _popen41, _ps41, _remote41, _rr41,
    _run41, _sa_text41, _shlex41, _sm41, _so41, _std_host41,
    _tf41, _uuid41, _write_exec41, check, db, os)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A. Reading a server: the probe, run for real against a stand-in host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _lines41(h, prefix):
    """The stand-in host's LinuxGSM/console log lines that start with `prefix`."""
    return [ln for ln in h.events() if ln.startswith(prefix)]


def _bodies41(title=None, key=None):
    """The bodies of the notifications sent, of one title and/or event key."""
    return [b for k, t, b in _NOTES41 if title in (None, t) and key in (None, k)]


def _noted41(fragment):
    """Whether any notification sent says `fragment`."""
    return any(fragment in b for _k, _t, b in _NOTES41)


def _actions41(action):
    """The audit actions written for `action`, in order."""
    return [a for a, _s, _d in _audit41(action)]


def _locks41(h, names):
    return {s: _lockfile41(h, s) for s in names}


def _probe_fixture41():
    _fresh41()
    r, h = _remote41("probe")
    h.add("codserver", "codserver", running=False, lock="monitoring", autostart=True, uid="aaaa1111")
    h.add("codserver", "codserver-2", running=True, lock="none", autostart=False, uid="bbbb2222")
    h.add("gmodserver", "gmodserver", running=True, lock="legacy", autostart=False, uid=None)
    h.add("gmodserver", "gmodserver-3", running=False, lock="none", autostart=False, uid=None)
    # Stray sessions on the stopped servers' own sockets whose names hold the server's: an
    # operator's `tmux -L <socket> new -s codserver-old`. LinuxGSM's check_status.sh matches the
    # session name exactly (grep -Ecx), so they are not the server.
    for sock, stray in ((h.sock("codserver"), "codserver-old"), (h.sock("gmodserver-3"), "gmodserver-3x")):
        with open(os.path.join(h.state, "tmux", sock), "w") as fh:
            fh.write(stray + "\n")
    with open(h.lock("codserver") + ".panel-reboot", "w") as fh:
        fh.write("x\n")
    h.setn("inflight", "codserver", 2)
    h.setn("maint", "codserver", 1)
    probes = [HR.probe_server(r, {"user": u, "selfname": s})
              for u, s in (("codserver", "codserver"), ("codserver", "codserver-2"),
                           ("gmodserver", "gmodserver"), ("gmodserver", "gmodserver-3"))]
    return r, h, probes


def _probe_checks41():
    r, h, (p1, p2, p3, p4) = _probe_fixture41()
    check("probe: an EXACT session name on the uid socket — codserver is stopped though a session "
          "codserver-old is on its socket, while codserver-2 (same account) runs",
          (p1["session"], p2["session"]) == (0, 1), repr((p1["session"], p2["session"])))
    check("probe: an EXACT session name on the legacy bare socket too — gmodserver-3x is not "
          "gmodserver-3", p4["session"] == 0, repr(p4))
    check("probe: the legacy socket (no uid file: the bare session name) is read too",
          p3["session"] == 1, repr(p3))
    check("probe: the lock and the aside file are told apart; legacy <s>.lock is its own word",
          (p1["lock"], p1["aside"], p2["lock"], p3["lock"]) == ("monitoring", "monitoring", "none", "legacy"),
          repr((p1["lock"], p1["aside"], p2["lock"], p3["lock"])))
    check("probe: LinuxGSM commands in flight, and the maintenance ones among them, are counted",
          (p1["inflight"], p1["maint"], p2["inflight"]) == (2, 1, 0), repr(p1))
    check("probe: the boot id, the machine id and the host's second of the minute come back",
          (p1["boot"], p1["mid"], p1["sec"]) == (h.boot, h.mid, int(_CLOCK41.time()) % 60), repr(p1))
    check("probe: the Autostart line is read the way the Autostart switch reads it",
          [HR.has_autostart_line(p1["cron"], "codserver", "codserver"),
           HR.has_autostart_line(p1["cron"], "codserver", "codserver-2"),
           HR.has_autostart_line(p3["cron"], "gmodserver", "gmodserver")] == [True, False, False],
          repr(p1["cron"]))
    unread = dict(HR._UNREAD)
    eq("probe: output without the probe's own PROBE_OK is unread, every field None — never 'stopped'",
       HR.parse_probe("SESSION=0\nLOCK=none\n"), unread)
    eq("probe: an empty answer (a tailscale or local timeout) is unread", HR.parse_probe(""), unread)
    eq("probe: an unsafe account name sends nothing and is unread",
       HR.probe_server(r, {"user": "x; id", "selfname": "codserver"}), unread)


def _transport_one41(auth, local):
    _fresh41()
    r, h, rows = _std_host41(auth=auth, local=local)
    h.down = True
    p = HR.probe_server(r, rows["gmod"])
    ident = _hosts41.host_boot_identity(r)
    census = HR.host_player_state(r)
    check("transport %s: a dead host's probe is unread (paramiko raises, the others return -1)"
          % auth, p == dict(HR._UNREAD), repr(p))
    check("transport %s: its boot identity is None, never a new boot" % auth, ident is None, repr(ident))
    check("transport %s: its census is 'unreachable', which never reboots" % auth,
          census["state"] == "unreachable", census["state"])
    code, body = HR.request_reboot(r, "now", None, "web")
    check("transport %s: Reboot now on it is refused, and nothing was stopped or rebooted" % auth,
          _all41(code == 409, body.get("error") == "unreachable",
                 not _events41(h, ("stop", "reboot", "disarm"))), repr((code, body)))


def _transport_checks41():
    """A host that does not answer, on each transport: unknown, never stopped or idle."""
    for auth, local in (("key", False), ("tailscale", False), ("local", True)):
        _transport_one41(auth, local)


def _pgrep_count41(me, selfname):
    pat = HR._cmd_pattern(selfname, HR._INFLIGHT_CMDS)
    return _run41(["bash", "-c", "pgrep -u %s -fc %s" % (_shlex41.quote(me), _shlex41.quote(pat))]).stdout.strip()


def _probe_pattern_checks41():
    """The LinuxGSM-command pattern, against the REAL pgrep and a real `/bin/bash ./<s> start`."""
    d = _tf41.mkdtemp(prefix="pat-", dir=_TMP41)
    # A name of this run's own: pgrep sees every process of this account, and a second suite
    # running at the same time (a mutation battery) runs this same check.
    name = "zq%sserver" % _uuid41.uuid4().hex[:8]
    _write_exec41(os.path.join(d, name), "#!/bin/bash\nsleep 30\n")
    me = _run41(["id", "-un"]).stdout.strip()
    before = _pgrep_count41(me, name)
    proc = _popen41(["./" + name, "start"], cwd=d)
    try:
        _time41.sleep(0.3)
        during = _pgrep_count41(me, name)
        other = _pgrep_count41(me, name[1:])
    finally:
        proc.kill()
        proc.wait()
    check("probe pattern: the shell asking is never counted — 0 with nothing running, though its "
          "own command line holds the pattern", before == "0", repr(before))
    check("probe pattern: a real `/bin/bash ./<s> start` is counted", during == "1", repr(during))
    check("probe pattern: ...and not as another script whose name is a suffix of it",
          other == "0", repr(other))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# B. Who brings each server back
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _classify_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    probes = HR._probe_rows(r, list(rows.values()))
    got = {k: HR.classify(g, probes[g.id]) for k, g in rows.items()}
    check("owner: running + Autostart line + lock -> LinuxGSM's monitor brings it back",
          (got["gmod"], got["fctr"]) == (("monitor", "autostart"), ("monitor", "autostart")), repr(got))
    check("owner: running without an Autostart line -> the panel brings it back",
          got["mc"] == ("panel", "no_autostart"), repr(got["mc"]))
    check("owner: ...or nobody, with the reboot_restore_no_autostart setting off",
          HR.classify(rows["mc"], probes[rows["mc"].id], no_autostart_restore=False)
          == ("none", "no_autostart_off"))
    check("owner: a stopped server is not in the plan at all (never stopped: that would delete its lock)",
          got["cod"] == (None, "stopped"), repr(got["cod"]))
    check("owner: a server whose state could not be read is not in the plan",
          HR.classify(rows["gmod"], dict(HR._UNREAD)) == (None, "unreadable"))
    rows["gmod"].stop_pending = True
    check("owner: a running server with a queued stop -> nobody: it stays stopped",
          HR.classify(rows["gmod"], probes[rows["gmod"].id]) == ("none", "stop_pending"))
    rows["gmod"].stop_pending = False
    p = dict(probes[rows["gmod"].id], lock="none")
    check("owner: Autostart without a lock is not the monitor's (it would never start it)",
          HR.classify(rows["gmod"], p)[0] == "panel")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# C. The gate every entry point goes through
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gate_busy41():
    _fresh41()
    r, h, rows = _std_host41()
    h.players.update({"gmodserver": 3, "mcserver": 0, "fctrserver": 0})
    before = _locks41(h, h.servers)
    code, body = HR.request_reboot(r, None, None, "web")
    check("gate: a request with no mode while players are on answers 409 needs_choice",
          _all41(code == 409, body.get("error") == "players_online", body.get("needs_choice") is True,
                 body.get("choices") == ["when_empty", "now"],
                 (body.get("players") or {}).get("busy")
                 == [{"id": rows["gmod"].id, "name": "gmodserver", "players": 3}]),
          repr((code, body)))
    check("gate: ...and nothing was stopped, moved, written or rebooted",
          _all41(not _events41(h, ("stop", "disarm", "reboot")), not HR.plan_rows(r.id),
                 _locks41(h, h.servers) == before, not HR.job_of(r.id)), repr(_events41(h)))
    return r, h


def _gate_checks41():
    r, h = _gate_busy41()
    h.players.update({"gmodserver": 0, "fctrserver": None})
    code, body = HR.request_reboot(r, None, None, "web")
    check("gate: a count that cannot be read is NOT an empty server: 409 too, naming it",
          _all41(code == 409, body.get("error") == "players_online",
                 [u["name"] for u in (body.get("players") or {}).get("unknown", ())] == ["fctrserver"]),
          repr((code, body)))
    check("gate: ...and still nothing touched", not _events41(h, ("stop", "disarm", "reboot")))
    eq("gate: parse_mode — the older bodies and the new one",
       [HR.parse_mode(b) for b in ({}, {"mode": "now"}, {"mode": "force"}, {"force": True},
                                   {"when_empty": True}, {"when_empty": "true"}, {"when_empty": 1},
                                   {"when_empty": False}, {"when_empty": "false"}, {"when_empty": 0},
                                   {"mode": "wait"})],
       [(None, None), ("now", None), ("now", None), ("now", None), ("when_empty", None),
        ("when_empty", None), ("when_empty", None), (None, None), (None, None), (None, None),
        ("when_empty", None)])
    check("gate: an unknown mode or a when_empty that is not a boolean is an error, never a guess",
          all(HR.parse_mode(b)[1] for b in ({"mode": "later"}, {"when_empty": "maybe"},
                                             {"when_empty": 2})))


def _pass41():
    """One restore-worker pass, reading the rows afresh as the worker's own context would."""
    db.session.expire_all()
    out = HR.run_restore_pass(_app41)
    db.session.expire_all()
    return out


def _wpass41():
    """One 'reboot when empty' pass, reading the rows afresh as the loop's own context would."""
    db.session.expire_all()
    HR.wait_pass(_app41)
    db.session.expire_all()


def _restore_until41(rid, passes=30, step=15.0, between=None):
    """Run the restore worker's pass until the host has no plan rows left (or `passes` run out)."""
    for n in range(passes):
        if between is not None:
            between(n)
        _pass41()
        if not HR.plan_rows(rid):
            return n + 1
        _CLOCK41.sleep(step)
    return None


def _order41(events, first, then):
    """Every `first` event comes before every `then` event (and both happened)."""
    a = [i for i, e in enumerate(events) if e in first]
    b = [i for i, e in enumerate(events) if e in then]
    return _all41(bool(a), bool(b)) and max(a) < min(b)


def _trace41():
    """Every event of the run, a notification's prefixed with 'notify:'."""
    return [("notify:" + e if hh == "notify" else e) for hh, e in _TRACE41]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# D. Reboot now, on a remote: the whole plan, in order, and the lock files after
# ════════════════════════════════════════════════════════════════════════════════════════════════
_AUTO41 = ("gmodserver", "fctrserver")


def _asides41(h):
    return [f for u in _AUTO41 for f in os.listdir(os.path.join(h.home(u), "lgsm", "lock"))
            if f.endswith(".panel-reboot")]


def _now_locks41(auth, h, before):
    check("now (%s): the Autostart servers' monitoring locks are THE SAME FILES after the reboot "
          "was sent (content, inode, mtime): moved aside for the stop, put back before the reboot" % auth,
          _locks41(h, _AUTO41) == {s: before[s] for s in _AUTO41}, repr(_locks41(h, h.servers)))
    check("now (%s): no aside file is left behind" % auth, not _asides41(h))
    check("now (%s): the stopped server's state is untouched (still no lock)" % auth,
          (_lockfile41(h, "codserver"), before["codserver"]) == (None, None))
    check("now (%s): the server without Autostart lost its lock to the stop: the panel starts it" % auth,
          _lockfile41(h, "mcserver") is None)


def _now_order41(auth):
    rebooting = "notify:host_reboot:Rebooting vps"
    order = [e for e in _trace41() if e in ("disarm", "stop", "rearm", "reboot", rebooting)]
    check("now (%s): disarm, then stop, then the 'Rebooting' notice, then the locks back, then the "
          "reboot — nothing between the last two" % auth,
          _all41(_order41(order, {"disarm"}, {"stop"}), _order41(order, {"stop"}, {rebooting}),
                 _order41(order, {rebooting}, {"rearm"}), order[-2:] == ["rearm", "reboot"]),
          repr(order))


def _now_rows41(auth, r, rows):
    recs = {k: _rr41(g.id) for k, g in rows.items()}
    planned = {k: (v["owner"], v["stop"], bool(v["sent"]), v["restore"]) for k, v in recs.items() if v}
    check("now (%s): the plan is in the database before the reboot: who brings each back, how it "
          "stopped, and that the reboot was sent" % auth,
          planned == {"gmod": ("monitor", "stopped", True, "pending"),
                      "fctr": ("monitor", "stopped", True, "pending"),
                      "mc": ("panel", "stopped", True, "pending")}, repr(recs))
    audit = _audit41("remote_reboot")
    check("now (%s): one audit row says what happened before the reboot was sent" % auth,
          _all41([(a, s) for a, s, _d in audit] == [("remote_reboot", True)],
                 "gmodserver: stopped, back by Autostart" in (audit[0][2] if audit else "")),
          repr(_audit41()))
    check("now (%s): the planned servers' 'went offline' alerts are held for the whole plan" % auth,
          [_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [float("inf")] * 3)
    check("now (%s): a remote's reboot does not wait on the panel's own notification queue" % auth,
          "notify:flush" not in _trace41())
    check("now (%s): the job is now just waiting for the host: phase rebooting" % auth,
          (HR.job_of(r.id) or {}).get("phase") == "rebooting")


def _now_flow_checks41(auth):
    _fresh41()
    r, h, rows = _std_host41(auth=auth)
    h.players.update({"gmodserver": 0, "mcserver": 0, "fctrserver": None})
    before = _locks41(h, _AUTO41 + ("codserver",))
    code, body = HR.request_reboot(r, "now", None, "web")
    check("now (%s): 202, and the reboot command was sent once" % auth,
          _all41(code == 202, body.get("success") is True, _trace41().count("reboot") == 1),
          repr((code, body, _trace41())))
    stops = _lines41(h, "stop ")
    check("now (%s): every RUNNING server got LinuxGSM's graceful stop; the stopped one none" % auth,
          sorted(s.split()[1] for s in stops) == ["fctrserver", "gmodserver", "mcserver"], repr(stops))
    _now_locks41(auth, h, before)
    _now_order41(auth)
    _now_rows41(auth, r, rows)
    _restore_flow_checks41(auth, r, h, rows)


def _monitor_cron41(h, started):
    """Stand in for LinuxGSM's */5 monitor, about 5 min after boot: it restarts what has its lock."""
    def _tick(n):
        if n != 12:
            return
        for s in ("gmodserver", "fctrserver", "mcserver"):
            if _lockfile41(h, s) is not None and not h.running(s):
                h.run(s, True)
                started[s] = True
    return _tick


def _restore_flow_checks41(auth, r, h, rows):
    """The host reboots; the monitor restarts its own; the panel starts the rest."""
    sent = (_rr41(rows["gmod"].id) or {}).get("sent") or 0
    h.reboot_now()
    booted = h.booted_at
    _CLOCK41.sleep(120)
    monitor_started = {}
    passes = _restore_until41(r.id, between=_monitor_cron41(h, monitor_started))
    # Rounded UP, as "within" needs: the boot (from the host's own uptime) and the last confirmation.
    within = (_math41.ceil(booted - sent), _math41.ceil(_math41.ceil(_CLOCK41.time() - sent) / 60.0))
    starts = _lines41(h, "start ")
    check("restore (%s): the host is back and every plan row resolved" % auth, passes is not None,
          repr([_rr41(g.id) for g in rows.values()]))
    check("restore (%s): the panel started exactly the server without Autostart — never one "
          "LinuxGSM's monitor brings back" % auth,
          [s.split()[1] for s in starts] == ["mcserver"], repr(starts))
    check("restore (%s): ...and wrote LinuxGSM's -starting.lock before it, so a monitor run that "
          "overlaps backs off" % auth, starts == ["start mcserver starting_lock=1"], repr(starts))
    check("restore (%s): the Autostart servers came back by the monitor alone" % auth,
          sorted(monitor_started) == ["fctrserver", "gmodserver"], repr(monitor_started))
    back = _bodies41("Host reboot", "host_reboot")
    check("restore (%s): ONE summary: when the host's new boot started, and 3/3 running again within "
          "the time to the last one confirmed, 2 by Autostart and 1 by the panel" % auth,
          back == ["vps rebooted: its new boot started within %d s of the reboot being sent. 3/3 running "
                   "again within %d min of the reboot being sent (2 by Autostart, 1 started by the panel)."
                   % within], repr((within, _NOTES41)))
    check("restore (%s): the rows are cleared and the outcome audited" % auth,
          _all41(not HR.plan_rows(r.id),
                 [(a, s) for a, s, _d in _audit41("remote_reboot_restore")] == [("remote_reboot_restore", True)]))
    check("restore (%s): the alerts get the monitor's 3 minutes of grace from now, not for ever" % auth,
          [_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [_CLOCK41.time()] * 3,
          repr({k: _ps41._expected_offline.get(g.id) for k, g in rows.items()}))
    check("restore (%s): the job is gone" % auth, HR.job_of(r.id) is None)


def _stop_calls41():
    """Record every run_as_game_user call (and pass it through): (action, selfname, timeout)."""
    calls = []
    real = _core41.run_as_game_user

    def _rec(server, user, action, timeout=30, selfname=None, **kw):
        calls.append((action, selfname, timeout))
        return real(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _rec)
    return calls


# ════════════════════════════════════════════════════════════════════════════════════════════════
# E. The stop: its budget, and a stop LinuxGSM refuses
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _stop_checks41():
    _fresh41()
    r, h = _remote41("budget")
    h.add("sdtdserver", "sdtdserver", running=True, autostart=True)
    h.add("gmodserver", "gmodserver", running=True, autostart=True)
    rows = {"sdtd": _gs41(r, "sdtdserver", "sdtd", 26900), "gmod": _gs41(r, "gmodserver", "gmod", 27015)}
    h.flag("refuse_stop", "gmodserver")
    before = _lockfile41(h, "gmodserver")
    calls = _stop_calls41()
    HR.request_reboot(r, "now", None, "web")
    budgets = {s: t for a, s, t in calls if a == "stop"}
    check("stop budget: 600 s for the telnet stopmodes (7 Days to Die), 180 s for the rest — never "
          "the panel's usual 60 s, which cut a graceful stop off mid-save",
          (budgets.get("sdtdserver"), budgets.get("gmodserver")) == (600, 180), repr(calls))
    rec = _rr41(rows["gmod"].id) or {}
    check("stop refused (stoponlyifnoplayers: exit 0, still running): recorded as still_running, by "
          "the session and not the exit code, and its owner is unchanged",
          (rec.get("stop"), rec.get("owner")) == ("still_running", "monitor"), repr(rec))
    check("stop refused: ...its lock is back where it was, so the monitor restores it after the "
          "shutdown ends it", _lockfile41(h, "gmodserver") == before)
    check("stop refused: ...and it is not stopped a second time by the re-scan",
          _lines41(h, "stop gmodserver") == ["stop gmodserver starting_lock=0"], repr(h.events()))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# F. Refusals before anything is touched
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _untouched41(h, before):
    return _all41(not _events41(h, ("stop", "disarm", "reboot", "rearm")),
                  _locks41(h, h.servers) == before)


def _refusal41(name, setup, error, local=False, also=None):
    """Reboot now on a host `setup` made busy: refused with `error`, and nothing touched."""
    _fresh41()
    r, h, _rows = _std_host41(local=local)
    setup(r, h)
    before = _locks41(h, h.servers)
    code, body = HR.request_reboot(r, "now", None, "web")
    check("refused before anything is touched: %s — no lock moved, no stop, no reboot" % name,
          _all41(code == 409, body.get("error") == error, _untouched41(h, before),
                 also is None or also(body)), repr((code, body)))


def _no_escalation41(_r, _h):
    _patch(_so41, "_can_escalate", lambda: False)


def _refusal_checks41():
    _refusal41("an install in flight",
               lambda r, h: _gs41(r, "rustserver", "rust", 28015, status="installing", installed=False),
               "blocked", also=lambda b: b.get("choices") == ["when_empty"])
    _refusal41("dpkg's lock held", lambda r, h: setattr(h, "dpkg_held", True), "blocked")
    _refusal41("LinuxGSM maintenance", lambda r, h: h.setn("maint", "gmodserver", 1), "blocked")
    _refusal41("a remote with sudo off", lambda r, h: setattr(h, "sudo_ok", False), "preflight",
               also=lambda b: "sudo" in b.get("message", ""))
    _refusal41("the panel host without escalation", _no_escalation41, "preflight", local=True)
    _patch(_so41, "_can_escalate", lambda: True)
    _late_refusal41()


def _late_refusal41():
    """A job that finds the host blocked by the time it runs (a delay, then a backup starts)."""
    _fresh41()
    r, h, _rows = _std_host41()
    before = _locks41(h, h.servers)
    real_census = HR.host_player_state

    def _late_block(remote, probes=None):
        c = real_census(remote, probes)
        if HR.job_of(remote.id):
            c["state"], c["blockers"] = "blocked", [HR._blocker("backup", "gmodserver")]
        return c
    _patch(HR, "host_player_state", _late_block)
    code, _body = HR.request_reboot(r, "now", None, "web", delay=30)
    check("refused at the job: work that started during the delay ends it with nothing touched, an "
          "audit row that says so, and a notice",
          _all41(code == 202, _untouched41(h, before),
                 [(a, s) for a, s, _d in _audit41("remote_reboot")] == [("remote_reboot", False)],
                 _noted41("was not rebooted")), repr((_audit41(), _NOTES41)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# G. The window: the locks go back only when no monitor run can read them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _window_checks41():
    eq("window: second 5 and second 45 are outside it, 20 inside; a LinuxGSM command in flight "
       "keeps it shut; an unread second is shut",
       [HR._window_open([{"sec": s, "inflight": n}], HR.ARM_WINDOW)
        for s, n in ((5, 0), (45, 0), (20, 0), (20, 1), (None, 0), (20, None))],
       [False, False, True, False, False, False])
    _fresh41()
    r, h, _rows = _std_host41()
    h.setn("inflight", "gmodserver", 1)        # a scheduled update started and never ends
    real_census = HR.host_player_state

    def _quiet_census(remote, probes=None):
        h.setn("maint", "gmodserver", 0)
        return real_census(remote, probes)
    _patch(HR, "host_player_state", _quiet_census)
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("window: a LinuxGSM command in flight for 120 s — no reboot is sent",
          _all41("reboot" not in _events41(h), _CLOCK41.time() - t0 >= 120), repr(_events41(h)))
    check("window: ...the plan is rolled back: the locks are back, the panel-owned server is started "
          "again, and the operator is told why",
          _all41(None not in _locks41(h, _AUTO41).values(),
                 "start mcserver starting_lock=1" in h.events(),
                 _noted41("did not happen (a LinuxGSM command was running")),
          repr((h.events(), _NOTES41)))
    check("window: ...and the rows are gone", not HR.plan_rows(r.id))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# H. A reboot the host refuses, and a host that comes back on the same boot
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _refused_reboot_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.reboot_rc = 1
    before = _locks41(h, _AUTO41)
    HR.request_reboot(r, "now", None, "web")
    check("reboot refused (rc 1): rolled back at once — the Autostart servers' locks are the same "
          "files, so LinuxGSM's monitor restarts them", _locks41(h, _AUTO41) == before)
    check("reboot refused: ...the server without Autostart gets a SAFE START now",
          "start mcserver starting_lock=1" in h.events(), repr(h.events()))
    check("reboot refused: ...nothing it did not stop is started, and the monitor's are left to it",
          [ln.split()[1] for ln in _lines41(h, "start ")] == ["mcserver"], repr(h.events()))
    did_not = [b for b in _bodies41(key="host_reboot") if "did not happen" in b]
    check("reboot refused: ...ONE notification, with the host's refusal in it",
          _all41(len(did_not) == 1, "refused the reboot" in "".join(did_not)), repr(_NOTES41))
    check("reboot refused: ...audited as a rollback, and the job and the rows are gone",
          _all41(_actions41("remote_reboot_rollback") == ["remote_reboot_rollback"],
                 not HR.plan_rows(r.id), HR.job_of(r.id) is None))


def _send_answer41(answer):
    def _rp(_server, verb, _args=(), **_kw):
        if verb != "reboot-delayed":
            return "", "unexpected verb %s" % verb, 9
        if isinstance(answer, Exception):
            raise answer
        return answer
    return _rp


def _started41(exc):
    """`exc` marked as the paramiko transport marks a failure once its exec was under way."""
    exc.command_started = True
    return exc


def _send_reboot_checks41():
    """The reboot command's answer: a refusal is knowable, though a reboot's success is not."""
    _fresh41()
    r, _h, _rows = _std_host41()
    got = []
    for answer in (("", "sudo: a password is required\n", 1), ("", "SSH command timed out", -1),
                   ("", "", 0), _started41(ConnectionError("Command failed: dropped")),
                   ConnectionRefusedError(111, "Connection refused"),
                   _core41.HostKeyMismatch("the host key changed")):
        _patch(_core41, "run_privileged", _send_answer41(answer))
        got.append(HR.send_reboot(r))
    eq("send: a positive rc is the host refusing (sudo, an old helper) and says why; a connection "
       "that drops once the command is under way (-1, paramiko's marked ConnectionError) is what a reboot looks "
       "like, and 0 is sent; a connection that never opened sent nothing and says so",
       got, ["the host refused the reboot: sudo: a password is required", None, None, None,
             "the panel could not connect to send the reboot ([Errno 111] Connection refused)",
             "the panel could not connect to send the reboot (the host key changed)"])


def _plan_with_sent41(sent=True, mid=None, owner_map=None):
    """A host with plan rows written as a job would leave them, without running the job."""
    _fresh41()
    r, h, rows = _std_host41()
    now = _CLOCK41.time()
    for k, owner in (owner_map or {"gmod": "monitor", "mc": "panel"}).items():
        rec = {"v": 1, "plan": "p", "boot": h.boot, "mid": mid or h.mid, "owner": owner,
               "lock": "monitoring", "aside": None, "at": now, "sent": (now if sent else None),
               "by": "admin", "origin": "web", "mode": "now", "stop": "stopped", "restore": "pending",
               "attempts": 0, "boot_seen": None}
        rows[k].reboot_restore = _json41.dumps(rec)
    db.session.commit()
    h.run("gmodserver", False)
    h.run("mcserver", False)
    os.remove(h.lock("mcserver"))
    return r, h, rows


def _same_boot_unsent41():
    r, h, _rows = _plan_with_sent41(sent=False)
    _pass41()
    _restore_until41(r.id)
    check("same boot, never sent, no job (the panel restarted mid-plan): rolled back — the panel "
          "starts its own, the monitor's lock is left for the monitor",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], not HR.plan_rows(r.id),
                 _noted41("panel restarted before the reboot was sent")), repr((h.events(), _NOTES41)))


def _same_boot_checks41():
    _same_boot_unsent41()
    r, h, _rows = _plan_with_sent41()
    _pass41()
    check("same boot, sent a moment ago: wait — it may be shutting down right now",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start ")))
    h.sysstate = "stopping"
    _CLOCK41.sleep(300 + 5)                     # the design's 5 min, not the module's constant
    _pass41()
    check("same boot, sent 5 min ago, but the host says it is stopping: still waiting",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start ")))
    h.sysstate = "running"
    _restore_until41(r.id)
    check("same boot, 5 min after it was sent, running: the reboot did not happen — rolled back",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 _noted41("still on the same boot")), repr(_NOTES41))
    r, h, _rows = _plan_with_sent41()
    h.down = True
    _CLOCK41.sleep(700)                         # past 5 min (did not happen) and 10 (late notice)
    _pass41()
    _pass41()
    check("a host that does not answer is never taken for a new boot: nothing started, the plan "
          "kept, and ONE 'not back yet' notice",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start "),
                 [t for _k, t, _b in _NOTES41] == ["Host not back yet"]), repr(_NOTES41))


def _stale_checks41():
    r, h, _rows = _plan_with_sent41(mid="f" * 32)
    h.reboot_now()
    _CLOCK41.sleep(200)
    _pass41()
    check("another machine at the address (machine id differs): the plan is dropped, nothing started",
          _all41(not HR.plan_rows(r.id), not _lines41(h, "start "), _noted41("different machine")),
          repr(_NOTES41))
    _stale_bounds41()


# The design's limits as literals: a check that sleeps HR.STALE_SENT + 10 moves with the constant
# it is meant to pin, and passed with the constant at 10**9.
_DAY41 = 86400


def _stale_bounds41():
    r, h, _rows = _plan_with_sent41()
    _CLOCK41.sleep(23 * 3600)
    _restore_until41(r.id)
    check("a same-boot plan sent 23 h ago is still a reboot that did not happen: rolled back (the "
          "panel's server started again), not dropped",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 _noted41("still on the same boot")), repr((h.events(), _NOTES41)))
    r, h, _rows = _plan_with_sent41()
    _CLOCK41.sleep(_DAY41 + 10)
    _pass41()
    check("a same-boot plan sent more than a day ago (a restored database): dropped, nothing started",
          _all41(not HR.plan_rows(r.id), not _lines41(h, "start ")), repr((h.events(), _NOTES41)))
    r, h, _rows = _plan_with_sent41()
    h.down = True
    _CLOCK41.sleep(6 * _DAY41)
    _pass41()
    check("a plan for a host silent for 6 days is kept: it may still come back",
          _all41(len(HR.plan_rows(r.id)) == 2, not _noted41("has not answered for a week")))
    _CLOCK41.sleep(_DAY41 + 10)
    _pass41()
    check("a plan for a host silent for a week: dropped with a notice, nothing started",
          _all41(not HR.plan_rows(r.id), _noted41("has not answered for a week"),
                 not _lines41(h, "start ")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# I. SAFE START
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _safe_start_gates41(r, h, g):
    _CLOCK41.t = 1791000000.0 + 45                           # second 45: outside the window
    out = HR.safe_start(r, g)
    check("safe start: outside seconds 5-40 it waits, and starts nothing",
          _all41(out[0] == "wait", not _lines41(h, "start ")), repr(out))
    _CLOCK41.t = 1791000000.0 + 20
    h.setn("inflight", "mcserver", 1)
    out = HR.safe_start(r, g)
    check("safe start: with a LinuxGSM command in flight for it, it waits", out[0] == "wait", repr(out))
    h.setn("inflight", "mcserver", 0)


def _safe_start_checks41():
    _fresh41()
    r, h = _remote41("ss")
    h.add("mcserver", "mcserver", running=False, lock="none", autostart=False)
    g = _gs41(r, "mcserver", "mc", 25565, status="offline")
    _safe_start_gates41(r, h, g)
    out = HR.safe_start(r, g)
    check("safe start: inside the window: -starting.lock first, then LinuxGSM's start",
          _all41(out == ("started", ""), h.events()[-1:] == ["start mcserver starting_lock=1"]),
          repr((out, h.events())))
    out = HR.safe_start(r, g)
    check("safe start: a server that is already running is not started twice",
          _all41(out == ("running", ""), len(_lines41(h, "start ")) == 1))
    h.run("mcserver", False)
    h.flag("already", "mcserver")                           # LinuxGSM says so, with no session the panel saw
    out = HR.safe_start(r, g)
    h.flag("already", "mcserver", on=False)
    check("safe start: LinuxGSM's 'already running' (exit 2) is 'running' — something else started it, "
          "so the summary must not say the panel did", out == ("running", ""), repr(out))
    h.flag("fail_start", "mcserver")
    out = HR.safe_start(r, g)
    check("safe start: a start that fails says why, in LinuxGSM's words",
          _all41(out[0] == "failed", "Unable to start" in out[1]), repr(out))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# J. Wait for everyone to leave
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WAITER41 = NS(id=None, username="admin")


def _wait_entry41(rid):
    with _ps41._rwe_lock:
        return dict(_ps41._reboot_when_empty.get(rid) or {}) or None


def _wait_arm_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    h.players.update({"gmodserver": 2})
    t0 = _CLOCK41.time()
    code, body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    w = _wait_entry41(r.id) or {}
    check("wait: armed — 200 pending, it gives up 24 h from now, and nothing was touched",
          _all41(code == 200, body.get("pending") is True, w.get("expires") == t0 + 24 * 3600,
                 (w.get("by"), w.get("boot")) == ("admin", h.boot),
                 not _events41(h, ("stop", "disarm", "reboot"))), repr((code, body, w)))
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: arming it again changes nothing and writes no second audit row",
          _all41((_wait_entry41(r.id) or {}).get("since") == w.get("since"),
                 _actions41("reboot_when_empty_arm") == ["reboot_when_empty_arm"]))
    _wpass41()
    w = _wait_entry41(r.id) or {}
    check("wait: someone on — it keeps waiting, and records who it is waiting on",
          _all41((w.get("waiting_on") or {}).get("busy") == [{"name": "gmodserver", "players": 2}],
                 "reboot" not in _events41(h)), repr(w))
    return r, h, rows


def _wait_checks41():
    r, h, rows = _wait_arm_checks41()
    # The pop is the COMMIT POINT: a cancel while the census runs means no reboot.
    h.players.update({"gmodserver": 0})
    real_census = HR.host_player_state

    def _cancel_mid(remote, probes=None):
        c = real_census(remote, probes)
        HR.cancel(remote, _WAITER41)
        return c
    _patch(HR, "host_player_state", _cancel_mid)
    _wpass41()
    _patch(HR, "host_player_state", real_census)
    check("wait: cancelled while the census ran — it is not rebooted, though the host was empty",
          _all41(_wait_entry41(r.id) is None, "reboot" not in _events41(h), not _events41(h, ("stop",))))
    _wait_fire_checks41(r, h, rows)


def _wait_fire_checks41(r, h, rows):
    """Armed again; now empty: it fires — the clean reboot, as the operator who armed it."""
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    check("wait: empty — it fires the clean reboot (stops, then reboots), and is no longer pending",
          _all41(_wait_entry41(r.id) is None, "reboot" in _events41(h),
                 sorted(ln.split()[1] for ln in _lines41(h, "stop ")) == ["fctrserver", "gmodserver", "mcserver"]),
          repr(h.events()))
    fire = AuditLog.query.filter_by(action="reboot_when_empty_fire").all()
    check("wait: the fire is audited under whoever armed it, and the auto_reboot notice goes out",
          _all41([(a.username, a.success) for a in fire] == [("admin", True)],
                 bool(_bodies41(key="auto_reboot"))), repr((_audit41(), _NOTES41)))
    check("wait: the reboot it fired ran in the 'when_empty' mode: no in-game countdown",
          _all41(not _lines41(h, "say "), (_rr41(rows["gmod"].id) or {}).get("mode") == "when_empty"))


def _wait_expiry41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 1, "fctrserver": None})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    _CLOCK41.sleep(24 * 3600 + 1)
    _wpass41()
    gave = "".join(_bodies41("Gave up waiting to reboot"))
    check("wait: after 24 h it gives up — dropped, audited, and the notice names what was still on",
          _all41(_wait_entry41(r.id) is None, len(_bodies41("Gave up waiting to reboot")) == 1,
                 "gmodserver (1 player)" in gave, "fctrserver (count unknown)" in gave,
                 _actions41("reboot_when_empty_expire") == ["reboot_when_empty_expire"]),
          repr(_NOTES41))


def _wait_reminder41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"fctrserver": None})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    for _i in range(40):
        _wpass41()
        _CLOCK41.sleep(60)
    rem = _bodies41("Reboot still waiting")
    check("wait: a count unread for 30 min gets ONE reminder naming the server",
          _all41(len(rem) == 1, "fctrserver" in "".join(rem), _wait_entry41(r.id) is not None),
          repr(_NOTES41))


def _wait_outside41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 1})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.reboot_now()
    _wpass41()
    check("wait: the host rebooted outside the panel — the wait is dropped, with an audit row",
          _all41(_wait_entry41(r.id) is None,
                 _actions41("reboot_when_empty_drop") == ["reboot_when_empty_drop"]))


def _wait_unreachable41():
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.down = True
    _wpass41()
    check("wait: a host that does not answer stays queued and is not rebooted",
          _all41(_wait_entry41(r.id) is not None, "reboot" not in _events41(h)))
    with _ps41._rwe_lock:
        _ps41._reboot_when_empty[987654] = {"by": "x", "since": 1.0}
    _wpass41()
    check("wait: a host that no longer exists is dequeued", _wait_entry41(987654) is None)


def _wait_edges41():
    _wait_expiry41()
    _wait_reminder41()
    _wait_outside41()
    _wait_unreachable41()
    _fresh41()
    r, _h, _rows = _std_host41()
    _patch(HR, "wait_max_hours", lambda: 0)
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: with the limit at 0 it never expires", (_wait_entry41(r.id) or {}).get("expires", 1) is None)


def _bounce_stubs41(seen):
    """Empty for the census; once the stops have begun, fctr reads 1 player right before ITS stop."""
    real_run = _core41.run_as_game_user

    def _run(server, user, action, timeout=30, selfname=None, **kw):
        seen["stopping"] = seen["stopping"] or action == "stop"
        return real_run(server, user, action, timeout=timeout, selfname=selfname, **kw)

    def _slots(gs, allow_console=False, primary=None):
        if gs.short_name == "fctrserver" and seen["stopping"]:
            seen["n"] += 1
            return (1, 16, None)
        return (0, 16, None)
    _patch(_core41, "run_as_game_user", _run)
    _patch(_mon41, "_server_slots", _slots)
    _patch(HR, "STOP_WORKERS", 1)               # one account at a time: a fixed order


def _bounce_checks41():
    """A player joins in the moment between the census and their server's stop."""
    _fresh41()
    r, h, _rows = _std_host41()
    seen = {"n": 0, "stopping": False}
    _bounce_stubs41(seen)
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    t_arm = _CLOCK41.time()
    _wpass41()
    w = _wait_entry41(r.id) or {}
    check("bounce: no reboot, and the server a player just joined was never stopped",
          _all41("reboot" not in _events41(h), seen["n"] >= 1, not _lines41(h, "stop fctrserver")),
          repr(h.events()))
    check("bounce: the servers already stopped are rolled back (locks back, the panel's started again)",
          _all41(None not in _locks41(h, _AUTO41).values(),
                 not _lines41(h, "stop mcserver") or "start mcserver starting_lock=1" in h.events(),
                 not HR.plan_rows(r.id)), repr(h.events()))
    check("bounce: back to waiting, not before 10 min from now, one bounce counted",
          _all41(w.get("bounces") == 1, w.get("not_before", 0) >= t_arm + 600), repr(w))
    check("bounce: no 'did not happen' notice for it — it is still waiting",
          not _noted41("did not happen"), repr(_NOTES41))
    _bounce_again41(r, seen)


def _bounce_again41(r, seen):
    _wpass41()
    check("bounce: inside the back-off it does not look again",
          (_wait_entry41(r.id) or {}).get("bounces") == 1)
    for _i in range(2):
        _CLOCK41.sleep(600 + 1)
        seen["stopping"] = False
        _wpass41()
    check("bounce: after the third, ONE notice that players keep joining; it keeps waiting",
          _all41((_wait_entry41(r.id) or {}).get("bounces") == 3,
                 len(_bodies41("Host reboot still waiting")) == 1), repr(_NOTES41))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# K. The in-game warning before a forced reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _stamp_stops41(stamps):
    real_stop = _core41.run_as_game_user

    def _stop_at(server, user, action, timeout=30, selfname=None, **kw):
        stamps.setdefault(action, _CLOCK41.time())
        return real_stop(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _stop_at)


def _countdown_warned41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 3, "fctrserver": 2})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    says = _lines41(h, "say ")
    check("countdown: players on a game that can show a message are warned at 60, 30 and 10 s",
          _all41([ln.split(" in ")[1].split(" seconds")[0] for ln in says] == ["60", "30", "10"],
                 all(ln.startswith("say gmodserver say Server restarting in") for ln in says)), repr(says))
    check("countdown: a game with no console message (Factorio) is not sent anything",
          not [ln for ln in says if "fctrserver" in ln])
    check("countdown: the first stop comes a full minute after the first warning",
          stamps.get("stop", 0) - t0 >= 60, repr((stamps, t0)))
    first_stop = min(i for i, ln in enumerate(h.events()) if ln.startswith("stop "))
    check("countdown: every warning comes before any stop", h.events().index(says[-1]) < first_stop)


def _countdown_cancelled41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 3})
    real_say = _sm41.game.moderate

    def _say_then_cancel(server, user, game_type, action, **kw):
        out = real_say(server, user, game_type, action, **kw)
        HR.cancel(r, NS(id=None, username="ops"))
        return out
    _patch(_sm41.game, "moderate", _say_then_cancel)
    code, _body = HR.request_reboot(r, "now", None, "web")
    _patch(_sm41.game, "moderate", real_say)
    says = _lines41(h, "say ")
    check("countdown: cancelled during it — the players are told, nothing is stopped or moved, and "
          "the operator is told nothing had been stopped",
          _all41(code == 202, len(says) == 2, "cancelled" in "".join(says[-1:]),
                 not _events41(h, ("stop", "disarm", "reboot")), not HR.plan_rows(r.id),
                 _noted41("cancelled by ops; nothing had been stopped")), repr((says, _NOTES41)))


def _countdown_checks41():
    _countdown_warned41()
    _countdown_cancelled41()
    _fresh41()
    r, h, _rows = _std_host41()
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("countdown: nobody on — no warning and no minute's wait",
          _all41(not _lines41(h, "say "), _CLOCK41.time() - t0 < 60 + 120))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# L. The panel's own alerts while a plan holds a server or a host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _down_sweeps41(r, gs, n=3):
    """`n` monitor sweeps that find `gs` down after it was up: the alerts they sent."""
    ms = _ps41._monitor_state
    ms["servers"][gs.id] = True
    ms["server_misses"].pop(gs.id, None)
    del _NOTES41[:]
    for _i in range(n):
        ms["servers"][gs.id] = _mon41._server_transition(r, gs, False, ms["servers"][gs.id], False)
    return [k for k, _t, _b in _NOTES41]


def _host_cycle41(r):
    """A host that goes down for three sweeps and comes back: the alerts that sent."""
    ms = _ps41._monitor_state
    del _NOTES41[:]
    ms["remotes"][r.id] = True
    ms["remote_misses"].pop(r.id, None)
    for up in (False, False, False, True):
        _mon41._record_host_reachability(r, up)
    return [k for k, _t, _b in _NOTES41]


def _server_alert_checks41(r, gs):
    _ps41._expected_offline[gs.id] = float("inf")
    held = _down_sweeps41(r, gs)
    _ps41._expected_offline.pop(gs.id, None)
    paged = _down_sweeps41(r, gs)
    check("alerts: a server a plan stopped never pages 'went offline unexpectedly' (control: one "
          "that is not held does)", (held, paged) == ([], ["server_down"]), repr((held, paged)))
    _ps41._expected_offline[gs.id] = _CLOCK41.time()
    _CLOCK41.sleep(170)
    grace = _down_sweeps41(r, gs)
    _CLOCK41.sleep(20)
    after = _down_sweeps41(r, gs)
    check("alerts: the 3 minutes of grace after a row clears are honoured, and end",
          (grace, after) == ([], ["server_down"]), repr((grace, after)))


def _empty_alert_checks41(gs):
    gs.notify_when_empty = True
    gs.reboot_restore = _json41.dumps({"v": 1})
    db.session.commit()
    del _NOTES41[:]
    _mon41._notify_if_emptied(gs, 0)
    kept = _all41(bool(db.session.get(GameServer, gs.id).notify_when_empty), not _NOTES41)
    gs.reboot_restore = None
    db.session.commit()
    _mon41._notify_if_emptied(gs, 0)
    check("alerts: 'notify when empty' is NOT consumed by a server the reboot emptied (control: an "
          "ordinary 0 fires it once)",
          _all41(kept, [k for k, _t, _b in _NOTES41] == ["server_empty"],
                 not db.session.get(GameServer, gs.id).notify_when_empty), repr(_NOTES41))


def _host_alert_checks41(r):
    now = _CLOCK41.time()
    _ps41._reboot_awaiting[r.id] = {"sent": now, "back": None}
    during = _host_cycle41(r)
    _ps41._reboot_awaiting[r.id] = {"sent": now - 400, "back": now - 100}
    just_back = _host_cycle41(r)
    _ps41._reboot_awaiting[r.id] = {"sent": now - 900, "back": now - 400}
    later = _host_cycle41(r)
    _ps41._reboot_awaiting.pop(r.id, None)
    with _ps41._hr_lock:
        _ps41._host_reboots[r.id] = {"phase": "rebooting", "sent": now - 60}
    bare = _host_cycle41(r)
    with _ps41._hr_lock:
        _ps41._host_reboots.pop(r.id, None)
    plain = _host_cycle41(r)
    pages = ["remote_unreachable", "remote_recovered"]
    check("alerts: a host the panel rebooted pages neither 'unreachable' nor 'back online' while it "
          "is down, nor for 5 min after it is seen back", (during, just_back) == ([], []),
          repr((during, just_back)))
    check("alerts: ...after that grace, and for a host nobody rebooted, both page as before",
          (later, plain) == (pages, pages), repr((later, plain)))
    check("alerts: an idle host's reboot (no plan rows) is muted by its job for 15 min",
          bare == [], repr(bare))


def _suppression_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    _patch(_mon41, "time", _CLOCK41)
    _patch(_mon41, "_lgsm_maintenance_running", lambda remote, g: False)
    _patch(_notif41, "alerts_muted", lambda g: False)
    _server_alert_checks41(r, rows["gmod"])
    _empty_alert_checks41(rows["gmod"])
    _host_alert_checks41(r)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# M. While a host is being rebooted, nothing else touches its servers
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.routes import admin_notifications as _AN41  # noqa: E402
from panel.routes import host_local as _HL41  # noqa: E402
from panel.routes import manage_servers as _MSR41  # noqa: E402
from panel.routes import panel_backup as _PB41  # noqa: E402
from panel.routes import remote_bootstrap as _RB41  # noqa: E402
from panel.routes import remote_vps as _RV41  # noqa: E402
from panel.routes import server_detail as _SD41  # noqa: E402
from panel.routes import _shared as _SH41  # noqa: E402
import panel.security.auth as _auth41  # noqa: E402

_rapp41 = _Flask41("unit_part41_routes")
# nosemgrep: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING -- a throwaway app this test builds
_rapp41.config.update(SECRET_KEY="unit-part41-routes",  # nosec B106 - this part's throwaway app
                      LOGIN_DISABLED=True, TESTING=True, SQLALCHEMY_TRACK_MODIFICATIONS=False,
                      SQLALCHEMY_DATABASE_URI=_app41.config["SQLALCHEMY_DATABASE_URI"])
db.init_app(_rapp41)
_RV41.register(_rapp41)
_PB41._register_panel_host_os(_rapp41)
_HL41._register_panel_update(_rapp41)
_RB41.register(_rapp41)
_SD41._register_schedules(_rapp41)
_MSR41._register_install(_rapp41)
_AN41._register_panel_settings(_rapp41)
_rapp41.logger.disabled = True
_ADMIN41 = NS(id=None, username="admin", is_superadmin=True, is_authenticated=True)
_ADMIN41._get_current_object = lambda: _ADMIN41
_XHR41 = {"X-Requested-With": "XMLHttpRequest"}


def _as_admin41():
    for mod in (_auth41, _RV41, _PB41, _HL41, _RB41, _SD41, _MSR41):
        _patch(mod, "current_user", _ADMIN41)


def _busy41(rid, phase="stopping"):
    with _ps41._hr_lock:
        _ps41._host_reboots[rid] = {"phase": phase, "sent": None if phase != "rebooting" else 1.0,
                                    "plan": "x", "servers": []}


def _record41(calls, name, ret):
    def _call(*_a, **_k):
        calls.append(name)
        return ret
    return _call


def _gate_stubs41(calls):
    _as_admin41()
    _patch(_SD41, "set_autostart", _record41(calls, "set_autostart", (True, "")))
    _patch(_SD41, "_bg_power_action", _record41(calls, "power", None))
    _patch(_SD41, "_noop_power_refusal", lambda gs, remote, action: None)
    _patch(_RV41, "remote_os_update_start", _record41(calls, "os-update", (True, "ok")))
    _patch(_RV41, "remote_os_run_updates", _record41(calls, "run-updates", (True, "ok")))
    _patch(_so41, "panel_self_update", _record41(calls, "self-update", (True, "ok")))
    _patch(_so41, "os_run_update", _record41(calls, "os-run", (True, "ok")))
    _patch(_RB41, "_begin_bootstrap", _record41(calls, "bootstrap", (True, "")))
    _patch(_RB41, "_refuse_on_panel_host", lambda remote, what: None)
    _patch(_MSR41, "_queue_install_job", _record41(calls, "install", True))
    _patch(_MSR41, "_game_type_refusal", lambda game_type: None)   # the game list is not this part's


def _said41(resp):
    return (resp.status_code, "being rebooted" in ((resp.get_json() or {}).get("message") or ""))


def _gate_posts41(c, r, gs, failed):
    """Every refusable action on the host, through its real route: (status, said why) each."""
    return {
        "autostart": _said41(c.post("/api/server/%d/autostart" % gs.id, json={"enabled": False})),
        "os update": _said41(c.post("/api/remote/%d/os-update/start" % r.id)),
        "run updates": _said41(c.post("/api/remote/%d/run-updates" % r.id)),
        "bootstrap": _said41(c.post("/api/remote/%d/bootstrap" % r.id, json={})),
        "self-update": _said41(c.post("/api/panel/update")),
        "panel os update": _said41(c.post("/api/server-management/os-update-run")),
        "retry install": _said41(c.post("/servers/%d/retry-install" % failed.id, headers=_XHR41)),
        "install": _said41(c.post("/servers/add", data={"remote_id": r.id, "game_type": "gmod",
                                                         "server_name": "newgmod", "port": "27016"},
                                  headers=_XHR41)),
    }


def _gate_route_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    local, _lh = _remote41("panel", local=True)
    calls = []
    _gate_stubs41(calls)
    _busy41(r.id)
    _busy41(local.id)
    c = _rapp41.test_client()
    failed = _gs41(r, "rustserver", "rust", 28015, status="failed", installed=False)
    results = _gate_posts41(c, r, rows["gmod"], failed)
    action = _SD41._run_action(_app41, rows["gmod"], r, "start", None)
    refused = [k for k, v in results.items() if v != ((400, True) if "install" in k else (409, True))]
    check("gates: while a host's servers are being stopped, a start, an Autostart change, an OS "
          "update, a bootstrap, an install, a retry and the panel's self-update are all refused, "
          "each saying why",
          _all41(action[0] is False, "being rebooted" in action[1], refused == [], calls == []),
          repr((action, results, calls)))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    del calls[:]
    results = {"autostart": c.post("/api/server/%d/autostart" % rows["gmod"].id, json={"enabled": True}).status_code,
               "os update": c.post("/api/remote/%d/os-update/start" % r.id).status_code,
               "self-update": c.post("/api/panel/update").status_code}
    check("gates: ...and allowed again once it is not (control)",
          _all41(results == {"autostart": 200, "os update": 200, "self-update": 200},
                 calls == ["set_autostart", "os-update", "self-update"]), repr((results, calls)))
    _exclude_checks41(c, r, rows, calls)


def _exclude_checks41(c, r, rows, calls):
    """After the reboot is sent, an operator's own action wins: the row leaves the plan."""
    _busy41(r.id, phase="rebooting")
    for g in (rows["gmod"], rows["mc"]):
        g.reboot_restore = _json41.dumps({"v": 1, "owner": "panel", "restore": "pending"})
    db.session.commit()
    del calls[:]
    ok, _msg = _SD41._run_action(_app41, rows["gmod"], r, "stop", None)
    c.post("/api/server/%d/autostart" % rows["mc"].id, json={"enabled": True})
    db.session.expire_all()
    check("exclude: after the reboot is sent, an operator's Stop and Autostart change run, and take "
          "those servers out of the restore (audited)",
          _all41(ok, calls == ["power", "set_autostart"],
                 [db.session.get(GameServer, rows[k].id).reboot_restore for k in ("gmod", "mc")] == [None, None],
                 _actions41("remote_reboot_exclude") == ["remote_reboot_exclude"] * 2),
          repr((calls, _audit41())))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()


def _sweeps41(seen):
    _SH41._run_due_restarts(_app41)
    _SH41._run_pending_backups(_app41)
    _SH41._run_due_game_backups(_app41)
    return seen


def _sweep_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    seen = []
    _patch(_SH41, "_settle_queued_action", lambda app, gs: seen.append(("restart", gs.short_name)))
    _patch(_SH41, "_back_up_queued", lambda app, gs: seen.append(("queued", gs.short_name)))
    _patch(_SH41, "_back_up_if_due", lambda app, target: seen.append(("due", target[2])))
    _patch(_SH41, "_backups_blocked_by_config", lambda app, what: False)
    for g in rows.values():
        g.restart_pending = True
        g.backup_pending = True
    rows["gmod"].reboot_restore = _json41.dumps({"v": 1})
    db.session.commit()
    _busy41(r.id)
    check("sweeps: while the host's servers are being stopped, the queued-restart and both backup "
          "sweeps leave every one of them alone", _sweeps41(seen) == [], repr(seen))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    want = {(k, u) for k in ("restart", "queued", "due") for u in ("mcserver", "codserver", "fctrserver")}
    check("sweeps: ...after it, only the server the restore still holds is skipped",
          set(_sweeps41(seen)) == want, repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# N. The rest of the ways a reboot is asked for: the API route, and the bots (which may not)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _api_route_checks41():
    _fresh41()
    _r, h, _rows = _std_host41(local=True)
    h.players.update({"gmodserver": 2})
    _as_admin41()
    c = _rapp41.test_client()
    resp = c.post("/api/server-management/reboot", json={"delay": 30})
    check("api: the panel host's reboot route goes through the same gate — players on and no mode "
          "is a 409 with the choices, and nothing touched",
          _all41(resp.status_code == 409, (resp.get_json() or {}).get("needs_choice") is True,
                 not _events41(h, ("stop", "disarm", "reboot"))), repr(resp.get_json()))
    resp = c.post("/api/server-management/reboot", json={"mode": "later"})
    check("api: an unknown mode is a 400", resp.status_code == 400)
    t0 = _CLOCK41.time()
    resp = c.post("/api/server-management/reboot", json={"delay": 30, "mode": "now"})
    check("api: mode now with a delay: 202, the delay waited out by the job before it read the host, "
          "then the clean reboot",
          _all41(resp.status_code == 202, _CLOCK41.time() - t0 >= 30, "reboot" in _events41(h)),
          repr(resp.get_json()))
    _fresh41()
    _as_admin41()
    plain = []
    _patch(_so41, "server_reboot", lambda delay: (plain.append(delay), (True, "Server will reboot"))[1])
    _patch(_PB41, "log_action", lambda *a, **k: None)
    resp = c.post("/api/server-management/reboot", json={"delay": 7})
    check("api: with no local host row it reboots as it always did",
          _all41(resp.status_code == 200, plain == [7]), repr((resp.get_json(), plain)))


def _bot_checks41():
    from panel.services.bots import commands as _cmds41, discord as _dc41, telegram as _tg41
    asked = []
    for name in ("request_reboot", "start_clean_reboot", "arm_wait"):
        _patch(HR, name, _record41(asked, name, None))
    replies = []
    _patch(_tg41, "_tg_reply", lambda token, chat_id, text: replies.append(text))
    _patch(_dc41, "_dc_reply", lambda token, channel, text: replies.append(text))
    _tg41._handle_telegram_command(_app41, "t", "c", "/reboot vps now", sender=1)
    _dc41._handle_discord_command(_app41, "t", "c", "!reboot vps now", sender=1)
    check("bots: there is no reboot command — /reboot and !reboot are unknown commands and ask the "
          "reboot code nothing",
          _all41(asked == [], len(replies) == 2, all("Unknown command 'reboot'" in t for t in replies)),
          repr((asked, replies)))
    check("bots: ...nor is one offered in Telegram's command menu or open to everyone",
          _all41("reboot" not in [c for c, _d in _notif41.TG_COMMANDS], "reboot" not in _cmds41.OPEN_COMMANDS))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# O. The panel's own host: through the helper, or as a per-user install without it
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _helper_flow_checks41():
    ev = _trace41()
    order = [e for e in ev if e in ("helper:stop", "rearm", "reboot", "notify:flush", "notify:host_reboot:Rebooting Panel Server")]
    check("panel host (helper): the stops go through the helper's lgsm-command",
          ev.count("helper:stop") == 3, repr(ev))
    check("panel host (helper): the 'Rebooting' notice is FLUSHED to its channels before the locks "
          "go back and the reboot is sent — the panel goes down with the host",
          _all41(_order41(order, {"notify:host_reboot:Rebooting Panel Server"}, {"notify:flush"}),
                 _order41(order, {"notify:flush"}, {"rearm"}), order[-1:] == ["reboot"]), repr(order))


def _restart_marks41(rows):
    """The host rebooted and took the panel with it: memory is gone; resume reads the rows."""
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    _ps41._expected_offline.clear()
    HR.resume_reboot_state(_app41)
    check("panel host: at startup, before the monitor's first pass, every planned server's alerts "
          "are held again from the rows",
          _all41([_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [float("inf")] * 3,
                 rows["cod"].id not in _ps41._expected_offline))


def _panel_host_checks41():
    _fresh41()
    r, h, rows = _std_host41(local=True)
    _patch(_core41, "helper_present", lambda recheck=False: True)
    HR.request_reboot(r, "now", None, "web")
    _helper_flow_checks41()
    h.reboot_now()
    _restart_marks41(rows)
    _CLOCK41.sleep(90)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    argv = getattr(h, "helper_argv", [])
    action = argv[argv.index("lgsm-command") + 3] if "lgsm-command" in argv else None
    check("panel host (helper): after the boot the panel starts exactly its own, through the helper",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], action == "start"),
          repr((h.events(), argv)))


def _per_user_one41(unit, scope_ok):
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    h.user_scope_ok = scope_ok
    _patch(_core41, "_USER_UNIT", unit)
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    boot = _CLOCK41.time()
    _CLOCK41.sleep(70)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    at = [t for s_, t in h.timed("start") if s_ == "mcserver"]
    return h, boot, at


def _per_user_checks41():
    unit = os.path.join(_TMP41, "linuxgsm-panel.service")
    open(unit, "w").close()
    h, _boot, _at = _per_user_one41(unit, True)
    check("per-user panel host: the restore asks the user manager again and starts the "
          "server in a scope of its own, out of the panel's cgroup",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 any("mcserver" in c and "start" in c for c in h.scoped)), repr((h.events(), h.scoped)))
    h, boot, at = _per_user_one41(unit, False)
    check("per-user panel host: with no user manager to ask yet, the start waits (up to 2 min "
          "after the boot) rather than land in the panel's cgroup; then it starts anyway",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], not h.scoped,
                 bool(at) and at[0] - boot >= 120), repr((h.events(), at, boot)))
    _core41._USER_SCOPE.update(ok=None, at=0.0)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# P. A restore that does not fully work, and a lock left aside by a reboot from outside
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restore_failure_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    h.flag("fail_start", "mcserver")
    _CLOCK41.sleep(90)
    _restore_until41(r.id, passes=80, between=lambda n: h.run("gmodserver", True) if n == 10 else None)
    summary = "".join(_bodies41("Host reboot"))
    check("restore failures: the panel tries its own start three times, then gives up",
          len(_lines41(h, "start mcserver")) == 3, repr(h.events()))
    check("restore failures: ONE summary, naming each server that did not come back and why — the "
          "panel's start failure in LinuxGSM's words, and the Autostart server the monitor never "
          "restarted (after 12 min)",
          _all41(len(_bodies41("Host reboot")) == 1, "1/3 running again" in summary,
                 "mcserver didn't come back: FAIL: Unable to start mcserver" in summary,
                 "fctrserver didn't come back: LinuxGSM's monitor has not brought it back" in summary),
          repr(_NOTES41))
    check("restore failures: a server reported as not back is recorded down, so the monitor does not "
          "page 'went offline' about it as well",
          [_ps41._monitor_state["servers"].get(rows[k].id) for k in ("mc", "fctr")] == [False, False])
    check("restore failures: audited as a restore that did not fully succeed",
          [(a, ok) for a, ok, _d in _audit41("remote_reboot_restore")] == [("remote_reboot_restore", False)])
    _outside_reboot_checks41()


def _outside_reboot_checks41():
    """A reboot from outside hit between the move aside and the move back."""
    _r, h, _rows = _plan_with_sent41(owner_map={"gmod": "monitor"})
    os.rename(h.lock("gmodserver"), h.lock("gmodserver") + ".panel-reboot")
    h.reboot_now()
    _CLOCK41.sleep(90)
    _pass41()
    check("lock left aside by an outside reboot: put back after the boot, the panel starts nothing",
          _all41(_lockfile41(h, "gmodserver") is not None,
                 not os.path.exists(h.lock("gmodserver") + ".panel-reboot"), not _lines41(h, "start ")),
          repr(h.events()))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Q. Cancelling, and the plan's own preview and status
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cancel_stop_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    real = _core41.run_as_game_user

    def _cancel_at_stop(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if action == "stop":
            HR.cancel(r, NS(id=None, username="ops"))
        return out
    _patch(_core41, "run_as_game_user", _cancel_at_stop)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    _patch(_core41, "run_as_game_user", real)
    check("cancel during the stops: the stop under way finishes, the rest are not stopped, no "
          "reboot, and what was stopped is brought back",
          _all41(len(_lines41(h, "stop ")) == 1, "reboot" not in _events41(h),
                 _lockfile41(h, "gmodserver") is not None, not HR.plan_rows(r.id),
                 _noted41("did not happen (cancelled by ops)")), repr((h.events(), _NOTES41)))
    with _ps41._hr_lock:
        _ps41._host_reboots[r.id] = {"phase": "arming", "sent": _CLOCK41.time()}
    code, body = HR.cancel(r, None)
    check("cancel after the reboot was sent: refused, saying so",
          _all41(code == 409, "reboot has been sent" in body["message"]), repr(body))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()


def _cancel_checks41():
    _cancel_stop_checks41()
    _fresh41()
    r, h, _rows = _std_host41()
    real_sleep = _CLOCK41.sleep

    def _sleep_then_cancel(sec):
        real_sleep(sec)
        if HR.job_of(r.id):
            HR.cancel(r, NS(id=None, username="ops"))
    _patch(_CLOCK41, "sleep", _sleep_then_cancel)
    code, _body = HR.request_reboot(r, "now", None, "web", delay=60)
    _patch(_CLOCK41, "sleep", real_sleep)
    check("cancel during the delay: nothing is touched, and the operator is told so",
          _all41(code == 202, not _events41(h, ("stop", "disarm", "reboot")),
                 _noted41("nothing had been stopped yet")), repr(_NOTES41))


def _preview_checks41():
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    pv = {sv["name"]: sv for sv in HR.preview(r)}
    check("preview: says per server who brings it back, without touching anything",
          _all41([pv[n]["owner"] for n in ("gmodserver", "mcserver", "codserver")] == ["monitor", "panel", None],
                 "Autostart about 5 min" in pv["gmodserver"]["text"], "stays stopped" in pv["codserver"]["text"],
                 not _events41(h, ("stop", "disarm", "reboot", "rearm"))), repr(pv))
    _patch(_so41, "panel_starts_at_boot", lambda: False)
    check("preview: on the panel host, when the panel does not start at boot, it says the servers "
          "the PANEL starts would stay down", HR.preflight_warning(r, list(pv.values())) == HR.PANEL_WONT_RETURN)
    code, body = HR.request_reboot(r, "now", None, "web")
    check("preview: ...and the 202 carries the same warning (a warning, not a refusal)",
          (code, body.get("warning")) == (202, HR.PANEL_WONT_RETURN), repr(body))
    db.session.expire_all()
    st = HR.status(r)
    job = st["job"] or {}
    check("status: the job, the rows and nothing secret — what the Power card polls",
          _all41(job.get("phase") == "rebooting", "cancel" not in job,
                 {x["name"] for x in st["rows"]} == {"gmodserver", "mcserver", "fctrserver"}), repr(st))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# R. Startup, the database column, the notification flush and the boot identity
# ════════════════════════════════════════════════════════════════════════════════════════════════
_REAL_FLUSH41 = _notif41.flush


def _startup_rows41():
    from datetime import timedelta
    from panel.core.clock import utcnow
    hosts = {n: _remote41(n)[0] for n in ("alpha", "beta", "gamma", "delta")}
    now = utcnow()
    for name, actions, ago in (("alpha", ["reboot_when_empty_arm"], 2),
                               ("beta", ["reboot_when_empty_arm", "reboot_when_empty_cancel"], 2),
                               ("gamma", ["reboot_when_empty_arm", "remote_reboot"], 2),
                               ("delta", ["reboot_when_empty_arm"], 72)):
        for i, a in enumerate(actions):
            db.session.add(AuditLog(action=a, username="alice", remote_id=hosts[name].id, target=name,
                                    timestamp=now - timedelta(hours=ago) + timedelta(minutes=i)))
    db.session.commit()


def _startup_checks41():
    _fresh41()
    _startup_rows41()
    HR.announce_dropped_waits(_app41)
    drops = [(a.target, a.username) for a in AuditLog.query.filter_by(action="reboot_when_empty_drop")]
    told = _bodies41("Reboot wait cancelled")
    check("startup: a wait the restart dropped is announced — only a host whose newest wait row is "
          "the arm itself, within the wait's own limit",
          _all41(drops == [("alpha", "alice")], len(told) == 1, "alpha" in "".join(told)),
          repr((drops, _NOTES41)))
    HR.announce_dropped_waits(_app41)
    check("startup: ...and only once (the drop row it wrote is now the newest)",
          AuditLog.query.filter_by(action="reboot_when_empty_drop").count() == 1)
    _startup_wiring41()


def _startup_wiring41():
    """app.py's start: the holds go in before the monitor thread exists, and both loops are supervised."""
    with open(os.path.join(_ROOT41, "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    main = src[src.index('if __name__ == "__main__":'):]
    at = {k: main.find(k) for k in ("_host_reboot.resume_reboot_state(app)",
                                     "_host_reboot.announce_dropped_waits(app)",
                                     'target=lambda: _monitor_watch(app), name="monitor"',
                                     '_supervise("host-reboot", lambda: _host_reboot.host_reboot_worker(app))',
                                     '_supervise("reboot-when-empty", '
                                     'lambda: _host_reboot.reboot_when_empty_watch(app))')}
    order = sorted(at, key=at.get)
    check("startup: app.py puts the reboot holds in place (and announces dropped waits) BEFORE it "
          "starts the monitor thread, and runs both reboot loops under the supervisor",
          _all41(-1 not in at.values(),
                 at["_host_reboot.resume_reboot_state(app)"] < at['target=lambda: _monitor_watch(app), name="monitor"']),
          repr(order))


def _columns41():
    return [row[1] for row in db.session.execute(_sa_text41("PRAGMA table_info(game_server)"))]


def _migration_checks41():
    from panel.db.models import _run_light_migrations
    mig = _Flask41("unit_part41_mig")
    mig.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP41, "upgrade.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    db.init_app(mig)
    with mig.app_context():
        db.create_all()
        db.session.execute(_sa_text41("ALTER TABLE game_server DROP COLUMN reboot_restore"))
        db.session.commit()
        before = _columns41()
        _run_light_migrations()
        after = _columns41()
        db.session.remove()
    check("migration: a database from before this change gains game_server.reboot_restore at startup",
          ("reboot_restore" in before, "reboot_restore" in after) == (False, True), repr(after))


def _flush_checks41():
    q, lock, sender = _notif41._alert_queue, _notif41._alert_lock, _notif41._alert_sender
    with lock:
        busy_before = sender[0]
        sender[0] = True
    t0 = _time41.monotonic()
    waited = _REAL_FLUSH41(timeout=0.3)
    with lock:
        sender[0] = busy_before
    check("flush: it waits for the sender to stand down, and says so when it did not in time",
          _all41(waited is False, _time41.monotonic() - t0 >= 0.3))
    check("flush: an empty queue with no sender is flushed at once",
          _all41(q.empty(), _REAL_FLUSH41(timeout=0) is True))


def _flush_identity_checks41():
    _flush_checks41()
    _fresh41()
    r, h = _remote41("ident")
    good = _hosts41.host_boot_identity(r)
    check("boot identity: boot id, machine id, uptime, the host's clock and systemd's state",
          good == {"boot": h.boot, "mid": h.mid, "uptime": h.uptime, "now": int(_CLOCK41.time()),
                   "state": "running"}, repr(good))
    h.boot = "not-a-boot-id"
    h._write_ids()
    check("boot identity: anything but a real boot id is None — never a new boot",
          _hosts41.host_boot_identity(r) is None)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# S. The helper runs LinuxGSM as ./<script>, so LinuxGSM's own guards see it
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _helper41():
    spec = _ilu41.spec_from_loader("panel_helper_p41", _mach41.SourceFileLoader(
        "panel_helper_p41", os.path.join(_ROOT41, "tools", "panel-helper")))
    helper = _ilu41.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper._drop_to = lambda pw_, own_groups=False: True       # not root here: nothing to drop
    return helper


def _helper_checks41():
    import pwd as _pwd41
    helper = _helper41()
    home = _tf41.mkdtemp(prefix="p3home-", dir=_TMP41)
    out = os.path.join(_TMP41, "p3-guard.out")
    # LinuxGSM's own guard (command_monitor.sh): pgrep -fcx "/bin/bash ./<s> start". A name of
    # this run's own, as in the probe-pattern check.
    name = "zq%sserver" % _uuid41.uuid4().hex[:8]
    _write_exec41(os.path.join(home, name),
                  '#!/bin/bash\npgrep -u "$(id -un)" -fcx "/bin/bash ./%s start" > %s\n'
                  % (name, _shlex41.quote(out)))
    os.symlink("/bin/true", os.path.join(home, "escape"))
    pw = _pwd41.getpwuid(os.getuid())
    rc = helper._lgsm_child(pw, home, name, "start", "", False)
    with open(out) as fh:
        seen = fh.read().strip()
    os.remove(out)
    rc_escape = helper._lgsm_child(pw, home, "escape", "start", "", False)
    check("helper: a LinuxGSM start it runs is `/bin/bash ./<s> start` — exactly what LinuxGSM's "
          "monitor looks for before it starts a second copy", (rc, seen) == (0, "1"), repr((rc, seen)))
    check("helper: ...and a script that is a symlink out of the home directory is still refused",
          _all41(rc_escape == 1, not os.path.exists(out)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# T. "Are game servers running?" — the bootstrap's probe and install.sh's, with the real pgrep
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TMUX_NAME41 = ("import ctypes, time; ctypes.CDLL(None).prctl(15, b'tmux: server', 0, 0, 0); "
                "time.sleep(30)")
_STUBS41 = ('ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }; info() { :; }; sleep() { :; }; '
            'reboot() { echo REBOOTING; }; sudo() { "$@"; }; UPG_SUDO=""\n')


def _install_block41(txt, start, end):
    i = txt.index(start)
    return txt[i:txt.index(end, i) + len(end)]


def _install_blocks41():
    """install.sh's game_sessions_running and its two reboot spots, the marker file pointed at ours."""
    with open(os.path.join(_ROOT41, "install.sh"), encoding="utf-8") as fh:
        txt = fh.read()
    marker = os.path.join(_TMP41, "reboot-required")
    open(marker, "w").close()
    fn = _install_block41(txt, "game_sessions_running() {", "\n}\n")
    blocks = [_install_block41(txt, '                if [[ ! -f /var/run/reboot-required ]]; then\n'
                                    '                    ok "System updated', "\n                fi\n"),
              _install_block41(txt, 'if [[ "${PANEL_NO_UPGRADE:-0}" != "1" ]] && [[ "${PANEL_NO_REBOOT:-0}" != "1" ]]; then\n'
                                    '    RB_SUDO=""', "\nfi\n")]
    return [_STUBS41 + fn + b.replace("/var/run/reboot-required", marker) for b in blocks]


def _run_blocks41(blocks):
    return [_run41(["bash", "-c", b]).stdout for b in blocks]


def _session_probe_checks41():
    probe = _hosts41.GAME_SESSIONS_PROBE
    blocks = _install_blocks41()
    pre = _run41(["bash", "-c", probe]).stdout.strip()
    idle = _run_blocks41(blocks)
    proc = _popen41([sys.executable, "-c", _TMUX_NAME41])
    try:
        _time41.sleep(0.4)
        named = _run41(["pgrep", "-x", "tmux: server"]).stdout.split()
        busy_probe = _run41(["bash", "-c", probe]).stdout.strip()
        busy = _run_blocks41(blocks)
    finally:
        proc.kill()
        proc.wait()
    if str(proc.pid) not in named:
        skip("game-session probe: a process named 'tmux: server'", "prctl(PR_SET_NAME) did not take here")
        return
    check("game-session probe: with LinuxGSM's tmux server running (its process is named "
          "'tmux: server'), the bootstrap's probe answers YES — `pgrep -x tmux` answered NO",
          busy_probe == "YES", repr(busy_probe))
    check("install.sh: with it running, neither reboot spot reboots, and both say why",
          all("REBOOTING" not in o and "game servers" in o for o in busy), repr(busy))
    if pre == "NO" and all("REBOOTING" in o for o in idle):
        check("install.sh: ...while an idle host that needs one is still rebooted (control)", True)
    else:
        skip("install.sh: the idle control", "this machine runs a tmux or screen session of its own")


def _bootstrap_run_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    got = []
    _patch(_SH41, "remote_bootstrap_vps",
           lambda remote, progress=None, **kw: (got.append(kw.get("do_reboot", True)), (True, "done", ""))[1])
    job = {"status": "running", "log": []}
    _SH41._BootstrapRun(_app41, r.id, job)._bootstrap({})
    for g in rows.values():
        g.status = "offline"
    db.session.commit()
    _SH41._BootstrapRun(_app41, r.id, job)._bootstrap({})
    check("bootstrap: a host where a server the panel manages was last seen online is bootstrapped "
          "with do_reboot=False (so it is never rebooted), and one with none online as asked",
          got == [False, True], repr(got))



