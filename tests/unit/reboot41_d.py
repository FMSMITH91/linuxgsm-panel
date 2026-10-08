"""Part 41's section AI (clean host reboots): review 1008's reboot findings; part41 runs them.

Each runs the real job, restore worker and monitor sweep against the stand-in hosts, as AE-AH do.
"""
from unit.reboot41_fixtures import (
    HR, _CLOCK41, _NOTES41, _all41, _audit41, _core41, _fresh41, _mon41, _patch, _std_host41,
    check)
from unit.reboot41_a import _WAITER41, _bodies41, _pass41, _trace41, _wait_entry41, _wpass41
from unit.reboot41_b import _server_pages41, _sweep41
from unit.reboot41_c import _unread_host41


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AI. What a reboot's edges say: the hold on unplanned servers, the Power card's mark, an unread
#     count in the stop phase, a wait over an earlier plan's rows
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _rbhold_slow_return_checks41():
    """An unreadable server (no plan row) on a host that takes 10 min to come back, then Autostart."""
    r, h, rows = _unread_host41(False)
    HR.request_reboot(r, "now", None, "web")
    h.down = True
    for _i in range(10):                       # 600 s down: past the 480 s the plan's mark held
        _CLOCK41.sleep(60)
        _pass41()
        _sweep41()
    h.reboot_now()
    h.down = False
    for i in range(10):
        _CLOCK41.sleep(60)
        _pass41()
        if i == 3:
            h.run("mcserver", True)           # LinuxGSM's */5 monitor starts it after the boot
        _sweep41()
    check("reboot hold (real sweeps): a server the plan could not read, back on Autostart a few "
          "minutes after a slow host returns, does not page 'went offline unexpectedly' -- its hold "
          "runs from the new boot, not from the plan",
          _server_pages41() == [], repr((_server_pages41(), rows["mc"].id)))


def _rbhold_bare_ok_checks41():
    """The Power card's last outcome after a reboot with no plan rows: ok said, not guessed."""
    r, h, _rows = _unread_host41(False)
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    _CLOCK41.sleep(30)
    _pass41()
    back = dict(HR._last_result.get(r.id) or {})
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "mcserver", "fctrserver"):
        h.run(s_, False)
    HR.request_reboot(r, "now", None, "web")
    h.down = True
    _CLOCK41.sleep(700)
    _pass41()
    _CLOCK41.sleep(86400)
    _pass41()
    gone = dict(HR._last_result.get(r.id) or {})
    check("Power card mark: a reboot that happened is ok even when its text says an unread server "
          "'did not' get stopped; a host gone a day is not ok",
          _all41(back.get("ok") is True, "did not stop or start" in (back.get("text") or ""),
                 gone.get("ok") is False, "not come back after a day" in (gone.get("text") or "")),
          repr((back, gone)))


def _rbhold_unread_slots_stubs41(seen):
    """Empty for the census; once the stops have begun, fctr's count cannot be read."""
    real_run = _core41.run_as_game_user

    def _run(server, user, action, timeout=30, selfname=None, **kw):
        seen["stopping"] = seen["stopping"] or action == "stop"
        return real_run(server, user, action, timeout=timeout, selfname=selfname, **kw)

    def _slots(gs, allow_console=False, primary=None):
        if gs.short_name == "fctrserver" and seen["stopping"]:
            seen["n"] += 1
            return (None, None, None)
        return (0, 16, None)
    _patch(_core41, "run_as_game_user", _run)
    _patch(_mon41, "_server_slots", _slots)
    _patch(HR, "STOP_WORKERS", 1)


def _rbhold_unread_count_checks41():
    """A player count that cannot be read just before a server's stop, three times over."""
    _fresh41()
    r, _h, _rows = _std_host41()
    seen = {"n": 0, "stopping": False}
    _rbhold_unread_slots_stubs41(seen)
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    t_arm = _CLOCK41.time()
    _wpass41()
    w = _wait_entry41(r.id) or {}
    for _i in range(2):
        _CLOCK41.sleep(600 + 1)
        seen["stopping"] = False
        _wpass41()
    w3 = _wait_entry41(r.id) or {}
    said = [d for _a, _s, d in _audit41("reboot_when_empty_arm")]
    check("unread count in the stop phase: no reboot, back to waiting with the back-off, but no "
          "bounce counted, the audit row says the count could not be read (not 'a player joined'), "
          "and three of them send no 'Players keep joining' notice",
          _all41(seen["n"] >= 3, "reboot" not in _trace41(), not w.get("bounces"),
                 w.get("not_before", 0) >= t_arm + 600, not w3.get("bounces"),
                 any("a player count could not be read" in (d or "") for d in said),
                 not any("a player joined" in (d or "") for d in said),
                 not _bodies41("Host reboot still waiting")),
          repr((w, w3, said, _NOTES41)))


def _rbhold_wait_over_rows_checks41():
    """A wait whose host still has an earlier plan's rows pending does not fire over them."""
    _fresh41()
    r, _h, rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real = HR.plan_rows
    _patch(HR, "plan_rows", lambda rid: [rows["gmod"]] if rid == r.id else real(rid))
    _wpass41()
    held = (HR.job_of(r.id), "reboot" in _trace41(), bool(_wait_entry41(r.id)))
    _patch(HR, "plan_rows", real)
    _wpass41()
    check("wait over an earlier plan's rows: it does not fire while they are pending (request_reboot's "
          "conflict check), and fires once they are gone",
          _all41(held == (None, False, True), "reboot" in _trace41()), repr(held))
