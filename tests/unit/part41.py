"""Part 41 of the unit suite: clean host reboots (panel/services/host_reboot.py).

Every reboot the panel makes stops the host's running game servers gracefully first, reboots, and
brings back exactly the servers that were running. The invariant under test: every managed
server's LinuxGSM `-monitoring.lock` is in the same state after the reboot as before it, and each
server has exactly one starter (LinuxGSM's monitor for an Autostart server, the panel for one
without, nobody for a stopped one).

HOW IT RUNS. Nothing here reaches a host. Each test host is a DIRECTORY standing in for one: a
home per game account with LinuxGSM's `lgsm/lock` and `lgsm/data/<s>.uid`, a stand-in LinuxGSM
script that does what LinuxGSM's stop and start do to the lock files and the tmux session, and a
state directory the stand-in `tmux`, `pgrep`, `crontab`, `date` and `id` read. The panel's own
transports are replaced at their lowest layer (_core._run_via_paramiko, _run_via_ssh_cli,
_run_local, _exec_local_argv), so every command host_reboot builds goes through the REAL
shell_as_game_user / run_as_game_user / run_privileged code, and every shell script it builds is
RUN, by bash, against that directory (its /home, /proc and /etc paths pointed into it). A down
host fails the way each transport really fails: paramiko raises, the tailscale and local
transports return ("", "...timed out", -1).

The clock host_reboot reads is this part's own (sleeps advance it, nothing waits), and the second
of the minute every stand-in reports is that clock's. The job runs in line (host_reboot._spawn),
so nothing is left running. Notifications are recorded, never sent.

Two checks use REAL processes: the probe's LinuxGSM-command pattern is matched by the real pgrep
against a real `/bin/bash ./<s> start` process (and must not count the shell that asks), and the
bootstrap / install.sh "game servers running?" probe is run by the real pgrep against a process
named "tmux: server".
"""
import shutil as _shutil41

from unit.part20 import _patched
from unit.reboot41_fixtures import (
    _TMP41, _ctx41, _pstate_snap41, _std_patches41, check, db)
from unit.reboot41_a import (
    _api_route_checks41, _bootstrap_run_checks41, _bot_checks41, _bounce_checks41, _cancel_checks41, _classify_checks41,
    _countdown_checks41, _flush_identity_checks41, _gate_checks41, _gate_route_checks41, _helper_checks41, _migration_checks41,
    _now_flow_checks41, _panel_host_checks41, _per_user_checks41, _preview_checks41, _probe_checks41, _probe_pattern_checks41,
    _refusal_checks41, _refused_reboot_checks41, _restore_failure_checks41, _safe_start_checks41, _same_boot_checks41, _send_reboot_checks41,
    _session_probe_checks41, _stale_checks41, _startup_checks41, _stop_checks41, _suppression_checks41, _sweep_checks41,
    _transport_checks41, _wait_checks41, _wait_edges41, _window_checks41)
from unit.reboot41_b import (
    _apt_checks41, _arm_race_checks41, _back_to_waiting_restart41, _bare_job_checks41, _bare_silent_checks41,
    _bounce_cancel_checks41, _busy_at_job_restart41, _census_cancel_checks41, _connect_fail_checks41, _debug_report_checks41,
    _disarm_fail_checks41, _failed_row_back_checks41, _fire_race41, _fired_wait_cancel_checks41, _idle_tick_checks41,
    _inflight_panel_owned_checks41, _job_numbers_checks41, _kept_down_checks41, _kept_down_unscanned_checks41, _leftover_checks41,
    _local_warning_text_checks41, _lock_order_checks41, _none_rollback_checks41, _none_stopped_rollback_checks41,
    _own_account_checks41, _page_checks41, _refused_wait_checks41, _rescan_budget_checks41, _rescan_cancel_checks41,
    _rescan_checks41, _restart_mid_plan_checks41, _settings_checks41, _stop_pending_checks41, _summary_reason_checks41,
    _summary_time_checks41, _unknown_warning_checks41, _warning_text_checks41, _window_job_checks41)
from unit.reboot41_c import (
    _already_running_checks41, _excluded_crash_checks41, _finish_crash_checks41, _late_notice_checks41,
    _port_never_opens_checks41,
    _power_marks_checks41, _rollback_hold_checks41, _summary_clock_checks41, _unread_idle_checks41,
    _unread_plan_checks41)
from unit.reboot41_d import (
    _rbhold_bare_ok_checks41, _rbhold_slow_return_checks41, _rbhold_unread_count_checks41,
    _rbhold_wait_over_rows_checks41)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# Run everything under one set of stubs, and put the world back afterwards.
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SECTIONS41 = [
    ("probe", _probe_checks41), ("transports", _transport_checks41),
    ("probe pattern", _probe_pattern_checks41), ("owners", _classify_checks41),
    ("gate", _gate_checks41),
    ("now over tailscale", lambda: _now_flow_checks41("tailscale")),
    ("now over paramiko", lambda: _now_flow_checks41("key")),
    ("stop", _stop_checks41), ("refusals", _refusal_checks41), ("window", _window_checks41),
    ("refused reboot", _refused_reboot_checks41), ("send", _send_reboot_checks41),
    ("same boot", _same_boot_checks41),
    ("stale plans", _stale_checks41), ("safe start", _safe_start_checks41),
    ("wait", _wait_checks41), ("wait edges", _wait_edges41), ("bounce", _bounce_checks41),
    ("countdown", _countdown_checks41), ("alerts", _suppression_checks41),
    ("gates", _gate_route_checks41), ("sweeps", _sweep_checks41), ("api route", _api_route_checks41),
    ("bots", _bot_checks41), ("panel host", _panel_host_checks41), ("per-user", _per_user_checks41),
    ("restore failures", _restore_failure_checks41), ("cancel", _cancel_checks41),
    ("preview", _preview_checks41), ("startup", _startup_checks41), ("migration", _migration_checks41),
    ("flush and identity", _flush_identity_checks41), ("helper", _helper_checks41),
    ("session probe", _session_probe_checks41), ("bootstrap run", _bootstrap_run_checks41),
    ("re-scan", _rescan_checks41), ("leftover lock", _leftover_checks41),
    ("queued stop", _stop_pending_checks41), ("idle host", _bare_job_checks41),
    ("idle host silent", _bare_silent_checks41),
    ("disarm fails", _disarm_fail_checks41), ("settings", _settings_checks41),
    ("page", _page_checks41), ("debug report", _debug_report_checks41),
    ("apt probe", _apt_checks41), ("cancel in the re-scan", _rescan_cancel_checks41),
    ("cancel a fired wait", _fired_wait_cancel_checks41), ("wait hand-over", _fire_race41),
    ("restart after a wait went back", _back_to_waiting_restart41),
    ("restart after a busy job", _busy_at_job_restart41),
    ("wait refused at its job", _refused_wait_checks41), ("wait armed in a race", _arm_race_checks41),
    ("window at the job", _window_job_checks41),
    ("in flight on a panel-started server", _inflight_panel_owned_checks41),
    ("rollback of an unstopped server", _none_rollback_checks41),
    ("rollback of a stopped no-restore server", _none_stopped_rollback_checks41),
    ("warning an unknown count", _unknown_warning_checks41), ("warning text", _warning_text_checks41),
    ("warning text on the panel host", _local_warning_text_checks41),
    ("re-scan budget", _rescan_budget_checks41), ("send's connection", _connect_fail_checks41),
    ("the panel's own account", _own_account_checks41), ("cancel at the census", _census_cancel_checks41),
    ("bounce and cancel", _bounce_cancel_checks41), ("cancel's lock order", _lock_order_checks41),
    ("job numbers", _job_numbers_checks41), ("idle tick after the restore", _idle_tick_checks41),
    ("panel restart mid-plan: no 'back online'", _restart_mid_plan_checks41),
    ("kept down through a plan: no 'went offline'", _kept_down_checks41),
    ("kept down, never scanned in the plan", _kept_down_unscanned_checks41),
    ("a server reported not back, back later", _failed_row_back_checks41),
    ("summary times", _summary_time_checks41), ("summary reasons", _summary_reason_checks41),
    ("power buttons' marks", _power_marks_checks41),
    ("a restored server whose port never opens", _port_never_opens_checks41),
    ("a crash just after the summary", _finish_crash_checks41),
    ("a crash after an operator's start mid-reboot", _excluded_crash_checks41),
    ("a rollback's Autostart servers", _rollback_hold_checks41),
    ("an unreadable server, nothing else", _unread_idle_checks41),
    ("an unreadable server beside a planned one", _unread_plan_checks41),
    ("summary clock", _summary_clock_checks41), ("'not back yet' text", _late_notice_checks41),
    ("already running", _already_running_checks41),
    ("an unread server back late after a slow boot", _rbhold_slow_return_checks41),
    ("the Power card's mark after an idle reboot", _rbhold_bare_ok_checks41),
    ("an unread count in the stop phase", _rbhold_unread_count_checks41),
    ("a wait over an earlier plan's rows", _rbhold_wait_over_rows_checks41),
]


def _run_sections41():
    """Every section under the stubs: a section that crashes is a FAILED check, never a skip."""
    import traceback
    for name, fn in _SECTIONS41:
        with _patched():
            _std_patches41()
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - reported by name below
                check("part41 section %r ran to its end" % name, False,
                      "%s: %s" % (type(exc).__name__, traceback.format_exc()[-1500:]))


try:
    _run_sections41()
finally:
    db.session.rollback()
    db.session.remove()
    _ctx41.pop()
    for _m41, _s41 in _pstate_snap41:
        _m41.clear()
        _m41.update(_s41)
    _shutil41.rmtree(_TMP41, ignore_errors=True)
