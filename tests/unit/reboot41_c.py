"""Part 41's sections AE to AH (clean host reboots): what the monitor and the notices say after one.

Each runs the REAL monitor sweep against the stand-in hosts (reboot41_b._mon_stubs41) and the real
restore, so the alert a server pages, or does not, is the one the panel would send.
"""
import re as _re41

from unit.reboot41_fixtures import (
    HR, GameServer, _CLOCK41, _NOTES41, _all41, _app41, _fresh41, _gs41, _kind41, _mon41, _patch,
    _ps41, _remote41, _rr41, _std_host41, check, db)
from unit.reboot41_a import (
    _SD41, _bodies41, _gate_stubs41, _monitor_cron41, _pass41, _plan_with_sent41, _restore_until41)
from unit.reboot41_b import (
    _T41, _mon_stubs41, _plan_with_sweeps41, _said41, _server_pages41, _sweep41, _sweeps_after41)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AE. The marks the power buttons leave for the monitor
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _marks41(gs_id):
    """(the window's ts is set, the window is a Stop's) for one server."""
    at = _ps41._expected_offline.get(gs_id)
    return at is not None, at is not None and _ps41._expected_stop.get(gs_id) == at


def _power_marks_checks41():
    """Stop, Restart and Start through server_detail._run_action (web, bots, bulk, palette)."""
    _fresh41()
    r, _h, rows = _std_host41()
    calls = []
    _gate_stubs41(calls)
    got = {}
    for action in ("stop", "start", "restart"):
        ok, _msg = _SD41._run_action(_app41, rows["gmod"], r, action, None)
        got[action] = (ok, _marks41(rows["gmod"].id))
    check("power buttons: a Stop is marked as a Stop (meant to stay down), a Start ends that window, "
          "and a Restart is marked as one the server comes back from — not as a Stop",
          got == {"stop": (True, (True, True)), "start": (True, (False, False)),
                  "restart": (True, (True, False))}, repr((got, calls)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AF. After the plan: the summary's word is held to by the monitor's own port check
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restart_panel41():
    """The panel restarts: every in-memory map is gone, and resume_reboot_state reads the rows back."""
    for m in _ps41._monitor_state.values():
        m.clear()
    for m in (_ps41._expected_offline, _ps41._expected_stop, _ps41._reboot_awaiting):
        m.clear()
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    HR.resume_reboot_state(_app41)


def _shut_port41(port):
    """From now on the monitor's port scan never finds `port` open, whatever runs."""
    probe = _mon41._probe_host

    def _scan(remote, read_flags=True):
        rid, found = probe(remote, read_flags)
        if found.get("ports") is not None:
            found = dict(found, ports=set(found["ports"]) - {port})
        return rid, found
    _patch(_mon41, "_probe_host", _scan)


def _rebooted41(restart=False):
    """The standard host up and recorded up, rebooted by a plan (the panel restarted mid-plan or not)."""
    _fresh41()
    r, h, rows = _std_host41()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    HR.request_reboot(r, "now", None, "web")
    if restart:
        _restart_panel41()
    del _NOTES41[:]
    return r, h, rows


def _port_never_opens41(restart):
    """The reboot brings gmod's session back (so the summary counts it), but its port never opens."""
    r, h, rows = _rebooted41(restart)
    _shut_port41(rows["gmod"].port)
    done = _plan_with_sweeps41(r, h)
    summary = "".join(_bodies41("Host reboot"))
    _sweeps_after41()
    return done, summary, _server_pages41()


def _port_never_opens_checks41():
    plain, restarted = _port_never_opens41(False), _port_never_opens41(True)
    check("alerts (real sweeps): a server the summary counts as running again (its session is back) "
          "whose port never opens pages 'went offline unexpectedly' once the plan's window ends, once "
          "— also when the panel restarted mid-plan and first saw it down",
          _all41(*[done is not None and "3/3 running again" in summary
                   and pages == [("server_down", "gmodserver")]
                   for done, summary, pages in (plain, restarted)]), repr((plain, restarted)))


def _finish_crash_checks41():
    """The summary says a server is running again; it crashes a minute later and stays down."""
    r, h, _rows = _rebooted41()
    done = _plan_with_sweeps41(r, h)
    _CLOCK41.sleep(60)
    h.run("fctrserver", False)
    _sweeps_after41(10)
    check("alerts (real sweeps): a crash a minute after the summary said 'running again' pages 'went "
          "offline unexpectedly', once — the plan's last window delays it, never swallows it",
          _all41(done is not None, _server_pages41() == [("server_down", "fctrserver")]),
          repr((done, _NOTES41)))


def _excluded_crash_checks41():
    """After the reboot is sent, the operator starts a held server themselves; it crashes 2 min later."""
    r, h, rows = _rebooted41()
    _gate_stubs41([])
    h.reboot_now()
    db.session.expire_all()                   # the job wrote the plan rows in its own session
    mc = db.session.get(GameServer, rows["mc"].id)
    held = HR.rr(mc) is not None
    ok, _msg = _SD41._run_action(_app41, mc, r, "start", None)
    h.run("mcserver", True)                   # what the stubbed-out start would have done
    _sweeps_after41(1)
    _CLOCK41.sleep(60)
    h.run("mcserver", False)
    _sweeps_after41(8)
    check("alerts (real sweeps): a server the operator started out of a reboot's plan that crashes "
          "inside the window its exclusion leaves pages 'went offline unexpectedly' once that window "
          "ends — the window delays it, never swallows it",
          _all41(held, ok, _rr41(mc.id) is None, _server_pages41() == [("server_down", "mcserver")]),
          repr((held, ok, _NOTES41)))


def _rolled_back41():
    """A refused reboot rolled back: Autostart servers left to LinuxGSM's monitor (lock back, down)."""
    _fresh41()
    r, h, rows = _std_host41()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    h.reboot_rc = 1
    HR.request_reboot(r, "now", None, "web")
    _restore_until41(r.id)
    del _NOTES41[:]
    return r, h


def _rollback_hold_checks41():
    """A rollback's Autostart server comes back by LinuxGSM's */5 monitor, minutes after the summary."""
    r, h = _rolled_back41()
    finished = (HR._last_result.get(r.id) or {}).get("at") or _CLOCK41.time()
    downs = {}
    for minute in range(1, 21):
        _CLOCK41.sleep(max(0.0, finished + 60 * minute - _CLOCK41.time()))
        if minute == 6:
            h.run("gmodserver", True)            # LinuxGSM's monitor, a run and a boot later
        _sweep41()
        for _k, s in _server_pages41():
            downs.setdefault(s, minute)
    check("alerts (real sweeps): after a rollback, an Autostart server LinuxGSM's monitor brings back "
          "6 min later pages nothing; one it never brings back pages 'went offline unexpectedly' "
          "once, only after the monitor has had NOT_BACK_AFTER to bring it back",
          _all41(not h.running("fctrserver"), _server_pages41() == [("server_down", "fctrserver")],
                 downs.get("fctrserver", 0) * 60 >= HR.NOT_BACK_AFTER + _mon41._EXPECT_OFFLINE_WINDOW),
          repr((downs, _NOTES41)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AG. A running server the plan could not read
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _unread_host41(with_plan_row):
    """A host where mcserver runs but its session cannot be read; fctrserver (Autostart) reads normally."""
    _fresh41()
    r, h = _remote41("vps")
    h.add("mcserver", "mcserver", running=True, lock="monitoring", autostart=False)
    rows = {"mc": _gs41(r, "mcserver", "mc", 25565)}
    if with_plan_row:
        h.add("fctrserver", "fctrserver", running=True, lock="monitoring", autostart=True)
        rows["fctr"] = _gs41(r, "fctrserver", "fctr", 34197)
    real = HR.probe_server
    _patch(HR, "probe_server", lambda remote, ident: dict(real(remote, ident), session=None)
           if (ident["selfname"] if isinstance(ident, dict) else ident.lgsm_name) == "mcserver"
           else real(remote, ident))
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    return r, h, rows


def _unread_idle_checks41():
    """No plan rows: the notices say what is known, and the server that never returns pages once."""
    r, h, rows = _unread_host41(False)
    HR.request_reboot(r, "now", None, "web")
    marked = (_ps41._expected_offline.get(rows["mc"].id) or 0) - _mon41._REBOOT_EXPECT_OFFLINE_EXTRA
    h.reboot_now()
    _CLOCK41.sleep(30)
    _pass41()
    first = None
    for _i in range(12):
        _CLOCK41.sleep(60)
        _sweep41()
        if first is None and _server_pages41():
            first = _CLOCK41.time() - marked
    check("unreadable server, nothing else running: the notices say none was FOUND running and name "
          "the one that could not be read — not 'no game servers were running'",
          _all41(_bodies41("Rebooting vps") == ["No running game server was found, so none were stopped. "
                                                "1 server could not be read, so the panel did not stop it."],
                 any(b.endswith("(no running game server was found before it). 1 server could not be "
                                "read, so the panel did not stop or start it.")
                     for b in _bodies41("Host reboot"))), repr(_NOTES41))
    check("alerts (real sweeps): ...and that server, which never comes back, pages 'went offline "
          "unexpectedly' once, only after the reboot's mark (5 min more than a restart's window) ends",
          _all41(_server_pages41() == [("server_down", "mcserver")], first is not None,
                 (first or 0) >= _mon41._REBOOT_EXPECT_OFFLINE_EXTRA + _mon41._EXPECT_OFFLINE_WINDOW),
          repr((first, _server_pages41())))


def _unread_plan_checks41():
    r, h, _rows = _unread_host41(True)
    HR.request_reboot(r, "now", None, "web")
    _plan_with_sweeps41(r, h, between=lambda n: h.run("fctrserver", True) if n == 12 else None)
    said = _bodies41("Rebooting vps") + _bodies41("Host reboot")
    check("unreadable server beside a planned one: the 'Rebooting' notice and the summary each name it",
          _all41(len(said) == 2, said[0].endswith(" 1 server could not be read, so the panel did not "
                                                  "stop it."),
                 said[1].endswith(" 1 server could not be read, so the panel did not stop or start it.")),
          repr(said))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AH. The notices' words and numbers
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WITHIN41 = _re41.compile(r"(new boot started|running again) within (\d+) (s|min)")


def _claims41(text):
    """{'new boot started' | 'running again': the seconds the text claims, as the bound it states}."""
    return {m.group(1): int(m.group(2)) * (60 if m.group(3) == "min" else 1)
            for m in _WITHIN41.finditer(text)}


def _slow_starts41(h, secs, ran):
    """Every LinuxGSM start on this host takes `secs` of the clock (it blocks until the game is up)."""
    orig = h.bash

    def bash(user, script):
        out = orig(user, script)
        if _kind41(script) == "start":
            _CLOCK41.sleep(secs)
            ran.append(_CLOCK41.time())
        return out
    h.bash = bash


def _two_hosts41(b_servers):
    """Two hosts rebooted: vpsa (the panel's start takes 40 s of clock) and vpsb (booted at +30 s)."""
    _fresh41()
    ra, ha = _remote41("vpsa")
    ha.add("mcserver", "mcserver", running=True, lock="monitoring", autostart=False)
    mca = _gs41(ra, "mcserver", "mc", 25565)
    rb, hb = _remote41("vpsb")
    gmb = None
    if b_servers:
        hb.add("gmodserver", "gmodserver", running=True, lock="monitoring", autostart=False)
        gmb = _gs41(rb, "gmodserver", "gmod", 27015)
    ran = []
    _slow_starts41(ha, 40, ran)
    HR.request_reboot(ra, "now", None, "web")
    HR.request_reboot(rb, "now", None, "web")
    sent = {"vpsa": (_rr41(mca.id) or {}).get("sent"),
            "vpsb": ((_rr41(gmb.id) if gmb else HR.job_of(rb.id)) or {}).get("sent")}
    _CLOCK41.sleep(max(0.0, sent["vpsb"] + 30 - _CLOCK41.time()))
    hb.reboot_now()
    ha.reboot_now()
    booted_b = hb.booted_at
    _CLOCK41.sleep(60)
    for _n in range(30):
        _pass41()
        if not HR.plan_rows(ra.id) and not HR.plan_rows(rb.id) and HR.job_of(rb.id) is None:
            break
        _CLOCK41.sleep(15)
    said = {b.split(" ")[0]: _claims41(b) for b in _bodies41("Host reboot")}
    return said, sent, booted_b, ran


def _summary_clock_checks41():
    said, sent, booted_b, ran = _two_hosts41(True)
    started = ran[-1] - sent["vpsa"] if ran else None
    a_back = said.get("vpsa", {}).get("running again", 0)
    b_boot = said.get("vpsb", {}).get("new boot started", 0)
    check("summary: 'running again within N' is never less than when the panel's own start (40 s of "
          "clock) returned — measured when it returned, not at the start of the tick",
          _all41(started is not None, started <= a_back < started + 60), repr((said, started)))
    check("summary: ...and a second host whose new boot is first seen in that same tick, after the "
          "start, is not said to have booted sooner than it did",
          _all41(booted_b - sent["vpsb"] <= b_boot < booted_b - sent["vpsb"] + 60), repr((said, sent, booted_b)))
    said, sent, booted_b, ran = _two_hosts41(False)
    b_boot = said.get("vpsb", {}).get("new boot started", 0)
    check("summary: ...nor an idle host checked in that tick (its report has no servers to count)",
          _all41(bool(ran), booted_b - sent["vpsb"] <= b_boot < booted_b - sent["vpsb"] + 60),
          repr((said, sent, booted_b)))


def _late_text41(owner_map):
    """The 'Host not back yet' body for a plan whose rows have these owners."""
    _r, h, _rows = _plan_with_sent41(owner_map=owner_map)
    h.down = True
    _CLOCK41.sleep(700)
    _pass41()
    return _bodies41("Host not back yet")


def _late_notice_checks41():
    many = _late_text41({"gmod": "monitor", "mc": "panel", "fctr": "none"})
    one = _late_text41({"gmod": "monitor", "fctr": "none"})
    none_back = _late_text41({"fctr": "none"})
    check("'not back yet': it counts only the servers that come back (not one that stays stopped), with "
          "the verb agreeing, and says nothing of servers when none come back",
          (many, one, none_back) == (["vps hasn't come back after 11 min; its 2 servers come back when it does."],
                                     ["vps hasn't come back after 11 min; its 1 server comes back when it does."],
                                     ["vps hasn't come back after 11 min."]), repr((many, one, none_back)))


def _already_running_checks41():
    """A server the panel restores that something else started first (the user's own @reboot)."""
    _fresh41()
    r, h, rows = _std_host41()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    HR.request_reboot(r, "now", None, "web")
    cron = _monitor_cron41(h, {})

    def _between(n):
        if n == 0:
            h.run("mcserver", True)
        cron(n)
    _plan_with_sweeps41(r, h, between=_between)
    summary = "".join(_bodies41("Host reboot"))
    rollback = _said41([("mc", "running", False), ("gmod", "autostart", False)], _T41 + 60, rollback_=True,
                       reason="cancelled by ops", sent=None)
    check("summary: a server found already running when the panel went to start it is counted as that, "
          "not as 'started by the panel' — after a reboot and after a rollback",
          _all41("3/3 running again" in summary,
                 "(2 by Autostart, 0 started by the panel, 1 found already running)" in summary,
                 rollback.startswith("Reboot of vps-test did not happen (cancelled by ops): 2 servers "
                                     "coming back. 0 started by the panel, 1 by Autostart within 5 min, "
                                     "1 found already running.")), repr((summary, rollback)))
